//! Container lifecycle manager.
//!
//! Tracks all containers, handles creation/start/stop/destroy requests,
//! and monitors pidfds for container exit events.

use sandbox::container::Container;
use sandbox::error::{Error, Result};
use sandbox::protocol::{
    ContainerInfo, ContainerSpec, Request, Response,
};
use std::collections::HashMap;

/// Manages the lifecycle of all containers.
pub struct ContainerManager {
    containers: HashMap<String, Container>,
}

impl ContainerManager {
    pub fn new() -> Self {
        Self {
            containers: HashMap::new(),
        }
    }

    /// Handle a request and return a response.
    pub fn handle_request(&mut self, request: Request) -> Response {
        match request {
            Request::Create(spec) => self.handle_create(spec),
            Request::Run(spec) => self.handle_run(spec),
            Request::Start { name, command } => self.handle_start(&name, command),
            Request::Stop {
                name,
                timeout_secs,
            } => self.handle_stop(&name, timeout_secs),
            Request::Destroy { name } => self.handle_destroy(&name),
            Request::List => self.handle_list(),
            Request::Exec { name, command } => self.handle_exec(&name, command),
            Request::Shutdown => {
                tracing::info!("shutdown requested");
                // Clean up all containers
                let names: Vec<String> = self.containers.keys().cloned().collect();
                for name in names {
                    let _ = self.handle_destroy(&name);
                }
                Response::Ok
            }
        }
    }

    fn handle_create(&mut self, spec: ContainerSpec) -> Response {
        let name = spec.name.clone();

        if self.containers.contains_key(&name) {
            return Response::Error {
                message: format!("container {name} already exists"),
            };
        }

        let container = Container::new(spec);
        self.containers.insert(name.clone(), container);

        Response::Created { name }
    }

    fn handle_run(&mut self, spec: ContainerSpec) -> Response {
        let name = spec.name.clone();

        if self.containers.contains_key(&name) {
            return Response::Error {
                message: format!("container {name} already exists"),
            };
        }

        let mut container = Container::new(spec);

        match container.start() {
            Ok(()) => {
                let pid = container.pid.unwrap_or(0) as u32;
                self.containers.insert(name.clone(), container);
                Response::Started { name, pid }
            }
            Err(e) => Response::Error {
                message: format!("failed to start container: {e}"),
            },
        }
    }

    fn handle_start(&mut self, name: &str, command: Option<Vec<String>>) -> Response {
        let container = match self.containers.get_mut(name) {
            Some(c) => c,
            None => {
                return Response::Error {
                    message: format!("container {name} not found"),
                }
            }
        };

        if let Some(cmd) = command {
            container.spec.command = cmd;
        }

        match container.start() {
            Ok(()) => {
                let pid = container.pid.unwrap_or(0) as u32;
                Response::Started {
                    name: name.to_string(),
                    pid,
                }
            }
            Err(e) => Response::Error {
                message: format!("failed to start container: {e}"),
            },
        }
    }

    fn handle_stop(&mut self, name: &str, timeout_secs: u32) -> Response {
        let container = match self.containers.get_mut(name) {
            Some(c) => c,
            None => {
                return Response::Error {
                    message: format!("container {name} not found"),
                }
            }
        };

        match container.stop(timeout_secs) {
            Ok(exit_code) => Response::Stopped {
                name: name.to_string(),
                exit_code,
            },
            Err(e) => Response::Error {
                message: format!("failed to stop container: {e}"),
            },
        }
    }

    fn handle_destroy(&mut self, name: &str) -> Response {
        let mut container = match self.containers.remove(name) {
            Some(c) => c,
            None => {
                return Response::Error {
                    message: format!("container {name} not found"),
                }
            }
        };

        match container.destroy() {
            Ok(()) => Response::Destroyed {
                name: name.to_string(),
            },
            Err(e) => {
                // Put it back if destroy failed
                self.containers.insert(name.to_string(), container);
                Response::Error {
                    message: format!("failed to destroy container: {e}"),
                }
            }
        }
    }

    fn handle_list(&self) -> Response {
        let list: Vec<ContainerInfo> = self
            .containers
            .values()
            .map(|c| ContainerInfo {
                name: c.spec.name.clone(),
                state: c.state.current().clone(),
                pid: c.pid.map(|p| p as u32),
            })
            .collect();

        Response::ContainerList(list)
    }

    fn handle_exec(&mut self, name: &str, command: Vec<String>) -> Response {
        let container = match self.containers.get(name) {
            Some(c) => c,
            None => {
                return Response::Error {
                    message: format!("container {name} not found"),
                }
            }
        };

        if !container.state.is_running() {
            return Response::Error {
                message: format!("container {name} is not running"),
            };
        }

        let pid = match container.pid {
            Some(p) => p,
            None => {
                return Response::Error {
                    message: "container has no PID".to_string(),
                }
            }
        };

        // Exec into the container's namespaces
        match exec_in_container(pid, &command) {
            Ok(child_pid) => Response::ExecStarted {
                pid: child_pid as u32,
            },
            Err(e) => Response::Error {
                message: format!("exec failed: {e}"),
            },
        }
    }
}

/// Execute a command inside an existing container's namespaces.
/// This works like `nsenter` — fork, setns into all namespaces, then exec.
fn exec_in_container(container_pid: libc::pid_t, command: &[String]) -> Result<libc::pid_t> {
    let namespaces = ["pid", "mnt", "net", "uts", "ipc", "user"];

    // Open all namespace fds first
    let mut ns_fds: Vec<(String, std::fs::File)> = Vec::new();
    for ns in &namespaces {
        let path = format!("/proc/{container_pid}/ns/{ns}");
        match std::fs::File::open(&path) {
            Ok(f) => ns_fds.push((ns.to_string(), f)),
            Err(e) => {
                tracing::warn!("failed to open {path}: {e}");
            }
        }
    }

    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(Error::Other(format!(
            "fork failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    if child == 0 {
        // Child: enter namespaces and exec
        for (ns_name, ns_fd) in &ns_fds {
            let flags = match ns_name.as_str() {
                "pid" => nix::sched::CloneFlags::CLONE_NEWPID,
                "mnt" => nix::sched::CloneFlags::CLONE_NEWNS,
                "net" => nix::sched::CloneFlags::CLONE_NEWNET,
                "uts" => nix::sched::CloneFlags::CLONE_NEWUTS,
                "ipc" => nix::sched::CloneFlags::CLONE_NEWIPC,
                "user" => nix::sched::CloneFlags::CLONE_NEWUSER,
                _ => continue,
            };

            if let Err(e) = nix::sched::setns(ns_fd, flags) {
                eprintln!("setns({ns_name}) failed: {e}");
                std::process::exit(1);
            }
        }

        // Change root to the container's root
        if let Err(e) = nix::unistd::chroot("/") {
            eprintln!("chroot failed: {e}");
            std::process::exit(1);
        }
        let _ = std::env::set_current_dir("/");

        // Exec
        if command.is_empty() {
            std::process::exit(1);
        }

        let c_prog = std::ffi::CString::new(command[0].as_str()).unwrap();
        let c_args: Vec<std::ffi::CString> = command
            .iter()
            .map(|a| std::ffi::CString::new(a.as_str()).unwrap())
            .collect();
        let c_ptrs: Vec<*const libc::c_char> = c_args
            .iter()
            .map(|a| a.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        unsafe {
            libc::execvp(c_prog.as_ptr(), c_ptrs.as_ptr());
        }
        eprintln!("exec failed: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }

    Ok(child)
}
