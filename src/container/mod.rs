//! Container lifecycle management.
//!
//! A Container encapsulates all the state needed to create, run, and stop
//! a Linux container using namespaces, cgroups, and security features.

pub mod builder;
pub mod init;
pub mod state;

use crate::cgroup::Cgroup;
use crate::error::{Error, Result};
use crate::namespace;
use crate::namespace::NamespaceConfig;
use crate::protocol::{ContainerSpec, NetworkMode};
use crate::rootfs::pivot::setup_rootfs;
use crate::security::{capabilities, seccomp};
use crate::sys::clone3::{self, CloneResult};
use crate::sys::eventfd::EventFd;

use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;

/// A running or stopped container.
pub struct Container {
    /// Container specification.
    pub spec: ContainerSpec,
    /// Current state.
    pub state: state::State,
    /// PID of the container's init process (in the host PID namespace).
    pub pid: Option<libc::pid_t>,
    /// Pidfd for monitoring the container process.
    pub pidfd: Option<OwnedFd>,
    /// Cgroup for resource limits.
    pub cgroup: Option<Cgroup>,
}

impl Container {
    /// Create a new container from a spec (does not start it).
    pub fn new(spec: ContainerSpec) -> Self {
        Self {
            spec,
            state: state::State::new(),
            pid: None,
            pidfd: None,
            cgroup: None,
        }
    }

    /// Start the container.
    ///
    /// This performs the full container creation sequence:
    /// 1. Create cgroup and apply limits
    /// 2. Create eventfd for synchronization
    /// 3. clone3 with namespace flags + CLONE_PIDFD + CLONE_INTO_CGROUP
    /// 4. Parent: write uid/gid maps, set up network, signal child
    /// 5. Child: pivot_root, mount filesystems, apply security, exec
    pub fn start(&mut self) -> Result<()> {
        if !self.state.is_created() {
            return Err(Error::InvalidState {
                name: self.spec.name.clone(),
                state: format!("{:?}", self.state.current()),
                operation: "start".to_string(),
            });
        }

        // 1. Create cgroup and apply limits
        let cgroup = Cgroup::create(&self.spec.name)?;
        cgroup.apply_limits(&self.spec.cgroup)?;
        let cgroup_fd = cgroup.open_fd()?;

        // 2. Create eventfd for parent-child sync
        let sync_fd = EventFd::new()?;

        // 3. Compute namespace flags
        let ns_config = NamespaceConfig::from_network_mode(&self.spec.network);
        let ns_flags = ns_config.to_flags();

        // 4. clone3
        let clone_result = clone3::clone3_with_pidfd(
            ns_flags.bits(),
            Some(cgroup_fd.as_raw_fd()),
        )?;

        match clone_result {
            Some(CloneResult { child_pid, pidfd }) => {
                // === PARENT ===
                self.parent_setup(child_pid, &sync_fd, &ns_config)?;
                self.pid = Some(child_pid);
                self.pidfd = Some(pidfd);
                self.cgroup = Some(cgroup);
                self.state.start().map_err(|e| Error::Other(e.to_string()))?;
                Ok(())
            }
            None => {
                // === CHILD ===
                // This function never returns — it either execs or exits
                self.child_setup(&sync_fd);
            }
        }
    }

    /// Parent-side setup after clone3.
    fn parent_setup(
        &self,
        child_pid: libc::pid_t,
        sync_fd: &EventFd,
        ns_config: &NamespaceConfig,
    ) -> Result<()> {
        // Write UID/GID mappings (required for user namespace)
        if ns_config.user {
            namespace::user::setup_user_namespace(
                child_pid,
                &self.spec.uid_mappings,
                &self.spec.gid_mappings,
            )?;
        }

        // Set up networking
        if ns_config.network {
            namespace::network::setup_network(&self.spec.network, child_pid)?;
        }

        // Signal child to proceed
        sync_fd.signal()?;

        Ok(())
    }

    /// Child-side setup after clone3. Never returns.
    fn child_setup(&self, sync_fd: &EventFd) -> ! {
        let result = self.child_setup_inner(sync_fd);
        if let Err(e) = result {
            eprintln!("sandbox: child setup failed: {e}");
            std::process::exit(1);
        }
        // If we get here, exec didn't happen (shouldn't be reachable)
        std::process::exit(1);
    }

    fn child_setup_inner(&self, sync_fd: &EventFd) -> Result<()> {
        // Wait for parent to finish uid_map / network setup
        sync_fd.wait()?;

        // Make mounts private
        namespace::mount::make_mounts_private()?;

        // Set hostname
        if let Some(ref hostname) = self.spec.hostname {
            namespace::uts::set_hostname(hostname)?;
        }

        // Set up rootfs (mounts /dev, /proc, /sys, bind mounts, pivot_root)
        let rootfs = PathBuf::from(&self.spec.rootfs);
        setup_rootfs(&rootfs, &self.spec.bind_mounts)?;

        // Apply seccomp filter
        seccomp::apply_seccomp(&self.spec.seccomp)?;

        // Drop capabilities (must be after seccomp to avoid blocking prctl)
        capabilities::drop_capabilities(&self.spec.capabilities)?;

        // Exec the command
        if self.spec.use_init {
            // Run mini-init as PID 1
            init::run_init(&self.spec.command);
        } else {
            // Direct exec
            exec_command(&self.spec.command)?;
        }

        Ok(())
    }

    /// Send a signal to the container's init process.
    pub fn signal(&self, sig: libc::c_int) -> Result<()> {
        if let Some(pid) = self.pid {
            let ret = unsafe { libc::kill(pid, sig) };
            if ret != 0 {
                return Err(Error::Kill(nix::Error::last()));
            }
        }
        Ok(())
    }

    /// Stop the container (SIGTERM, then SIGKILL after timeout).
    pub fn stop(&mut self, timeout_secs: u32) -> Result<i32> {
        if !self.state.is_running() {
            return Err(Error::InvalidState {
                name: self.spec.name.clone(),
                state: format!("{:?}", self.state.current()),
                operation: "stop".to_string(),
            });
        }

        // Send SIGTERM
        self.signal(libc::SIGTERM)?;

        // Wait for exit with timeout
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs as u64);

        loop {
            let mut status: i32 = 0;
            let ret = unsafe {
                libc::waitpid(
                    self.pid.unwrap_or(0),
                    &mut status,
                    libc::WNOHANG,
                )
            };

            if ret > 0 {
                let exit_code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else if libc::WIFSIGNALED(status) {
                    128 + libc::WTERMSIG(status)
                } else {
                    1
                };
                self.state.stop(exit_code).map_err(|e| Error::Other(e.to_string()))?;
                return Ok(exit_code);
            }

            if start.elapsed() > timeout {
                // Force kill
                self.signal(libc::SIGKILL)?;
                // Wait indefinitely for SIGKILL
                let ret = unsafe { libc::waitpid(self.pid.unwrap_or(0), &mut status, 0) };
                let exit_code = if ret > 0 {
                    if libc::WIFEXITED(status) {
                        libc::WEXITSTATUS(status)
                    } else {
                        137 // 128 + SIGKILL(9)
                    }
                } else {
                    137
                };
                self.state.stop(exit_code).map_err(|e| Error::Other(e.to_string()))?;
                return Ok(exit_code);
            }

            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// Destroy the container, cleaning up all resources.
    pub fn destroy(&mut self) -> Result<()> {
        // If still running, stop it
        if self.state.is_running() {
            let _ = self.stop(5);
        }

        // Clean up network
        if let Some(pid) = self.pid {
            if !matches!(self.spec.network, NetworkMode::Host) {
                let _ = crate::net::cleanup_container_network(pid);
            }
        }

        // Destroy cgroup
        if let Some(ref cgroup) = self.cgroup {
            let _ = cgroup.destroy();
        }

        self.pid = None;
        self.pidfd = None;
        self.cgroup = None;

        Ok(())
    }
}

/// Exec a command (replaces the current process).
fn exec_command(command: &[String]) -> Result<()> {
    if command.is_empty() {
        return Err(Error::Other("no command specified".to_string()));
    }

    let c_program = std::ffi::CString::new(command[0].as_str())
        .map_err(|e| Error::Other(format!("invalid command: {e}")))?;

    let c_args: Vec<std::ffi::CString> = command
        .iter()
        .map(|a| {
            std::ffi::CString::new(a.as_str())
                .map_err(|e| Error::Other(format!("invalid argument: {e}")))
        })
        .collect::<Result<Vec<_>>>()?;

    let c_arg_ptrs: Vec<*const libc::c_char> = c_args
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    unsafe {
        libc::execvp(c_program.as_ptr(), c_arg_ptrs.as_ptr());
    }

    // execvp only returns on error
    Err(Error::Exec(std::io::Error::last_os_error()))
}
