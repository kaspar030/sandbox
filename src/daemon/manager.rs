//! Container lifecycle manager.
//!
//! Tracks all containers, handles creation/start/stop/destroy requests,
//! and monitors pidfds for container exit events.

use sandbox::container::Container;
use sandbox::error::{Error, Result};
use sandbox::namespace::user;
use sandbox::protocol::{ContainerInfo, ContainerSpec, ImageInfo, PoolInfo, Request, Response};
use sandbox::storage::{self, StorageManager};
use sandbox::sys::idmap;
use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;

const MOUNTS_DIR: &str = "/run/sandbox/mounts";

/// Result of handling a request — includes the response and optionally
/// a PTY master fd to send to the client via SCM_RIGHTS.
pub struct HandleResult {
    pub response: Response,
    pub pty_master: Option<OwnedFd>,
}

impl HandleResult {
    fn response_only(response: Response) -> Self {
        Self {
            response,
            pty_master: None,
        }
    }

    fn with_pty(response: Response, pty_master: Option<OwnedFd>) -> Self {
        Self {
            response,
            pty_master,
        }
    }
}

/// Manages the lifecycle of all containers.
pub struct ContainerManager {
    containers: HashMap<String, Container>,
    storage: Arc<StorageManager>,
}

impl ContainerManager {
    pub fn new(storage: Arc<StorageManager>) -> Self {
        Self {
            containers: HashMap::new(),
            storage,
        }
    }

    /// Take the pidfd out of a container for async monitoring.
    pub fn take_pidfd(&mut self, name: &str) -> Option<OwnedFd> {
        self.containers.get_mut(name)?.pidfd.take()
    }

    /// Handle a container exit: reap the child, update state, clean up resources.
    pub fn handle_container_exit(&mut self, name: &str) {
        let container = match self.containers.get_mut(name) {
            Some(c) => c,
            None => return,
        };

        if !container.state.is_running() {
            return;
        }

        let mut status = 0i32;
        if let Some(pid) = container.pid {
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        }

        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            1
        };

        let _ = container.state.stop(exit_code);
        let is_ephemeral = container.ephemeral;
        tracing::info!("container {name} exited with code {exit_code}");

        // Clean up cgroup
        if let Some(ref cgroup) = container.cgroup {
            let _ = cgroup.destroy();
        }
        container.cgroup = None;

        // Auto-remove ephemeral containers
        if is_ephemeral {
            if let Some(mut c) = self.containers.remove(name) {
                // Clean up storage (rootfs copy)
                if let (Some(pool_name), Some(_)) = (&c.pool_name, &c.rootfs_path) {
                    if let Some(pool) = self.storage.pool(pool_name) {
                        let _ = storage::container_fs::destroy_container_rootfs(pool, name);
                    }
                }
                let _ = c.destroy();
            }
            tracing::info!("ephemeral container {name} auto-removed");
        }
    }

    /// Handle a request and return a response + optional PTY fd.
    pub fn handle_request(&mut self, request: Request) -> HandleResult {
        match request {
            Request::Create(spec) => self.handle_create(spec),
            Request::Run(spec) => self.handle_run(spec),
            Request::Start { name, command } => self.handle_start(&name, command),
            Request::Stop { name, timeout_secs } => self.handle_stop(&name, timeout_secs),
            Request::Destroy { name } => self.handle_destroy(&name),
            Request::List => self.handle_list(),
            Request::Exec { name, command } => self.handle_exec(&name, command),
            Request::ImageImport { name, source, pool } => {
                self.handle_image_import(&name, &source, pool.as_deref())
            }
            Request::ImageList { pool } => self.handle_image_list(pool.as_deref()),
            Request::ImageRemove { name, pool } => self.handle_image_remove(&name, pool.as_deref()),
            Request::PoolList => self.handle_pool_list(),
            Request::Shutdown => {
                tracing::info!("shutdown requested");
                let names: Vec<String> = self.containers.keys().cloned().collect();
                for name in names {
                    let _ = self.handle_destroy(&name);
                }
                HandleResult::response_only(Response::Ok)
            }
        }
    }

    /// Prepare a container's rootfs: copy from image, set up idmapped mount.
    fn prepare_container_rootfs(&self, container: &mut Container) -> Result<()> {
        let pool = self.storage.resolve_pool(container.spec.pool.as_deref())?;
        let pool_name = pool.name.clone();

        // Create container rootfs from image (cp -a / snapshot)
        let rootfs_path = storage::container_fs::create_container_rootfs(
            pool,
            &container.spec.image,
            &container.spec.name,
        )?;

        // Resolve UID/GID mappings if not provided
        if container.spec.uid_mappings.is_empty() || container.spec.gid_mappings.is_empty() {
            let (uid_maps, gid_maps) = user::build_id_mappings()?;
            if container.spec.uid_mappings.is_empty() {
                container.spec.uid_mappings = uid_maps;
            }
            if container.spec.gid_mappings.is_empty() {
                container.spec.gid_mappings = gid_maps;
            }
        }

        // Set up idmapped mount
        let mount_target = PathBuf::from(MOUNTS_DIR).join(&container.spec.name);
        std::fs::create_dir_all(&mount_target).map_err(|e| {
            Error::Other(format!(
                "failed to create mount point {}: {e}",
                mount_target.display()
            ))
        })?;

        idmap::setup_idmapped_mount(
            &rootfs_path,
            &mount_target,
            &container.spec.uid_mappings,
            &container.spec.gid_mappings,
        )?;

        container.rootfs_path = Some(rootfs_path);
        container.idmap_mount = Some(mount_target);
        container.pool_name = Some(pool_name);

        Ok(())
    }

    fn handle_create(&mut self, spec: ContainerSpec) -> HandleResult {
        let name = spec.name.clone();

        if self.containers.contains_key(&name) {
            return HandleResult::response_only(Response::Error {
                message: format!("container {name} already exists"),
            });
        }

        let mut container = Container::new(spec);

        // Prepare rootfs (copy image + idmap mount)
        if let Err(e) = self.prepare_container_rootfs(&mut container) {
            return HandleResult::response_only(Response::Error {
                message: format!("failed to prepare rootfs: {e}"),
            });
        }

        self.containers.insert(name.clone(), container);
        HandleResult::response_only(Response::Created { name })
    }

    fn handle_run(&mut self, spec: ContainerSpec) -> HandleResult {
        let name = spec.name.clone();

        if self.containers.contains_key(&name) {
            return HandleResult::response_only(Response::Error {
                message: format!("container {name} already exists"),
            });
        }

        let mut container = Container::new(spec);
        container.ephemeral = true;

        // Prepare rootfs (copy image + idmap mount)
        if let Err(e) = self.prepare_container_rootfs(&mut container) {
            return HandleResult::response_only(Response::Error {
                message: format!("failed to prepare rootfs: {e}"),
            });
        }

        match container.start() {
            Ok(()) => {
                let pid = container.pid.unwrap_or(0) as u32;
                let pty_master = container.take_pty_master();
                self.containers.insert(name.clone(), container);
                HandleResult::with_pty(Response::Started { name, pid }, pty_master)
            }
            Err(e) => {
                // Clean up on failure
                let _ = container.destroy();
                if let Some(pool_name) = &container.pool_name {
                    if let Some(pool) = self.storage.pool(pool_name) {
                        let _ = storage::container_fs::destroy_container_rootfs(
                            pool,
                            &container.spec.name,
                        );
                    }
                }
                HandleResult::response_only(Response::Error {
                    message: format!("failed to start container: {e}"),
                })
            }
        }
    }

    fn handle_start(&mut self, name: &str, command: Option<Vec<String>>) -> HandleResult {
        let container = match self.containers.get_mut(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                })
            }
        };

        if let Some(cmd) = command {
            container.spec.command = cmd;
        }

        match container.start() {
            Ok(()) => {
                let pid = container.pid.unwrap_or(0) as u32;
                let pty_master = container.take_pty_master();
                HandleResult::with_pty(
                    Response::Started {
                        name: name.to_string(),
                        pid,
                    },
                    pty_master,
                )
            }
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("failed to start container: {e}"),
            }),
        }
    }

    fn handle_stop(&mut self, name: &str, timeout_secs: u32) -> HandleResult {
        let container = match self.containers.get_mut(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                })
            }
        };

        match container.stop(timeout_secs) {
            Ok(exit_code) => HandleResult::response_only(Response::Stopped {
                name: name.to_string(),
                exit_code,
            }),
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("failed to stop container: {e}"),
            }),
        }
    }

    fn handle_destroy(&mut self, name: &str) -> HandleResult {
        let mut container = match self.containers.remove(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                })
            }
        };

        // Clean up storage (rootfs copy)
        if let Some(ref pool_name) = container.pool_name {
            if let Some(pool) = self.storage.pool(pool_name) {
                let _ = storage::container_fs::destroy_container_rootfs(pool, name);
            }
        }

        match container.destroy() {
            Ok(()) => HandleResult::response_only(Response::Destroyed {
                name: name.to_string(),
            }),
            Err(e) => {
                self.containers.insert(name.to_string(), container);
                HandleResult::response_only(Response::Error {
                    message: format!("failed to destroy container: {e}"),
                })
            }
        }
    }

    fn handle_list(&self) -> HandleResult {
        let list: Vec<ContainerInfo> = self
            .containers
            .values()
            .map(|c| ContainerInfo {
                name: c.spec.name.clone(),
                state: c.state.current().clone(),
                pid: c.pid.map(|p| p as u32),
            })
            .collect();

        HandleResult::response_only(Response::ContainerList(list))
    }

    fn handle_exec(&mut self, name: &str, command: Vec<String>) -> HandleResult {
        let container = match self.containers.get(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                })
            }
        };

        if !container.state.is_running() {
            return HandleResult::response_only(Response::Error {
                message: format!("container {name} is not running"),
            });
        }

        let pid = match container.pid {
            Some(p) => p,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: "container has no PID".to_string(),
                })
            }
        };

        match exec_in_container(pid, &command) {
            Ok(child_pid) => HandleResult::response_only(Response::ExecStarted {
                pid: child_pid as u32,
            }),
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("exec failed: {e}"),
            }),
        }
    }

    // -- Image handlers --

    fn handle_image_import(&self, name: &str, source: &str, pool: Option<&str>) -> HandleResult {
        let pool = match self.storage.resolve_pool(pool) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                })
            }
        };

        match storage::image::import(pool, name, std::path::Path::new(source)) {
            Ok(()) => HandleResult::response_only(Response::ImageImported {
                name: name.to_string(),
            }),
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("image import failed: {e}"),
            }),
        }
    }

    fn handle_image_list(&self, pool: Option<&str>) -> HandleResult {
        let pool = match self.storage.resolve_pool(pool) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                })
            }
        };

        match storage::image::list_images(pool) {
            Ok(images) => {
                let infos: Vec<ImageInfo> = images
                    .into_iter()
                    .map(|i| ImageInfo {
                        name: i.name,
                        pool: i.pool,
                        size_bytes: i.size_bytes,
                    })
                    .collect();
                HandleResult::response_only(Response::ImageList(infos))
            }
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("failed to list images: {e}"),
            }),
        }
    }

    fn handle_image_remove(&self, name: &str, pool: Option<&str>) -> HandleResult {
        let pool = match self.storage.resolve_pool(pool) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                })
            }
        };

        match storage::image::remove_image(pool, name) {
            Ok(()) => HandleResult::response_only(Response::ImageRemoved {
                name: name.to_string(),
            }),
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("image remove failed: {e}"),
            }),
        }
    }

    fn handle_pool_list(&self) -> HandleResult {
        let pools: Vec<PoolInfo> = self
            .storage
            .list_pools()
            .into_iter()
            .map(|p| PoolInfo {
                name: p.name.clone(),
                fs_type: p.fs_type.to_string(),
                supports_snapshots: p.fs_type.supports_snapshots(),
            })
            .collect();

        HandleResult::response_only(Response::PoolList(pools))
    }
}

/// Execute a command inside an existing container's namespaces.
fn exec_in_container(container_pid: libc::pid_t, command: &[String]) -> Result<libc::pid_t> {
    let namespaces = ["pid", "mnt", "net", "uts", "ipc", "user"];

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

        if let Err(e) = nix::unistd::chroot("/") {
            eprintln!("chroot failed: {e}");
            std::process::exit(1);
        }
        let _ = std::env::set_current_dir("/");

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
