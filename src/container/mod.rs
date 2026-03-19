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
use crate::sys::pty;

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

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
    /// PTY master fd (for interactive containers). The daemon passes this
    /// to the CLI client via SCM_RIGHTS after the container starts.
    pub pty_master: Option<OwnedFd>,
    /// If true, the container is automatically removed from the daemon
    /// registry when it exits. Set for containers created via `run`.
    pub ephemeral: bool,
    /// Path to the idmapped mount for this container (under /run/sandbox/mounts/).
    /// Set by the daemon before start(). Cleaned up on destroy().
    pub idmap_mount: Option<std::path::PathBuf>,
    /// Path to the container's rootfs copy (under storage/<pool>/fs/<name>/).
    /// Set by the daemon before start(). Cleaned up on destroy().
    pub rootfs_path: Option<std::path::PathBuf>,
    /// Storage pool name this container uses.
    pub pool_name: Option<String>,
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
            pty_master: None,
            ephemeral: false,
            idmap_mount: None,
            rootfs_path: None,
            pool_name: None,
        }
    }

    /// Reconstruct a container from persisted state after daemon restart.
    /// The container is in Created state — process, cgroup, and idmap mount
    /// are gone, but the rootfs on disk is intact.
    pub fn from_recovered(
        spec: ContainerSpec,
        rootfs_path: Option<std::path::PathBuf>,
        pool_name: Option<String>,
        ephemeral: bool,
    ) -> Self {
        Self {
            spec,
            state: state::State::new(),
            pid: None,
            pidfd: None,
            cgroup: None,
            pty_master: None,
            ephemeral,
            idmap_mount: None,
            rootfs_path,
            pool_name,
        }
    }

    /// Start the container.
    ///
    /// This performs the full container creation sequence:
    /// 1. Create cgroup and apply limits
    /// 2. Allocate PTY (if interactive)
    /// 3. Create eventfd for synchronization
    /// 4. clone3 with namespace flags + CLONE_PIDFD + CLONE_INTO_CGROUP
    /// 5. Parent: write uid/gid maps, set up network, signal child, close slave
    /// 6. Child: set up PTY slave, pivot_root, mount, apply security, exec
    #[tracing::instrument(skip_all, level = "debug")]
    pub fn start(&mut self) -> Result<()> {
        if !self.state.is_created() {
            return Err(Error::InvalidState {
                name: self.spec.name.clone(),
                state: format!("{:?}", self.state.current()),
                operation: "start".to_string(),
            });
        }

        // UID/GID mappings and idmap mount must be set up by the daemon
        // (via prepare_container_rootfs) before calling start().

        // 1. Create cgroup and apply limits
        let cgroup = Cgroup::create(&self.spec.name)?;
        cgroup.apply_limits(&self.spec.cgroup)?;
        let cgroup_fd = cgroup.open_fd()?;

        // 2. Allocate PTY if interactive (not detached)
        let pty_fds = if !self.spec.detach {
            Some(pty::allocate_pty()?)
        } else {
            None
        };

        // 3. Create eventfd for parent-child sync (parent signals child)
        let sync_fd = EventFd::new()?;

        // 4. Create pipe for child to report setup result back to parent.
        // Write end has O_CLOEXEC: on successful exec(), the write end closes
        // and the parent reads EOF (0 bytes = success). On setup failure, the
        // child writes an error message before exiting.
        let (result_read, result_write) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(|e| Error::Io(e.into()))?;
        let result_write_raw = result_write.as_raw_fd();

        // 5. Compute namespace flags
        let ns_config = NamespaceConfig::from_network_mode(&self.spec.network);
        let ns_flags = ns_config.to_flags();

        // Store raw fd values for the child to use after clone3.
        let master_raw = pty_fds.as_ref().map(|(m, _)| m.as_raw_fd()).unwrap_or(-1);
        let slave_raw = pty_fds.as_ref().map(|(_, s)| s.as_raw_fd()).unwrap_or(-1);

        // 6. clone3
        let clone_result = clone3::clone3_with_pidfd(ns_flags.bits(), Some(cgroup_fd.as_raw_fd()))?;

        match clone_result {
            Some(CloneResult { child_pid, pidfd }) => {
                // === PARENT ===
                // Close the slave fd in the parent — only the child uses it
                if let Some((master, slave)) = pty_fds {
                    drop(slave); // close slave in parent
                    self.pty_master = Some(master);
                }
                // Close write end of result pipe in parent
                drop(result_write);

                // Do parent setup (uid_map, network, signal child)
                self.parent_setup(child_pid, &sync_fd, &ns_config)?;

                // Wait for child to report setup result.
                // EOF (0 bytes) = success (exec closed the O_CLOEXEC write end).
                // Non-empty read = error message from child.
                let mut err_buf = [0u8; 4096];
                let n = nix::unistd::read(&result_read, &mut err_buf).unwrap_or(0) as isize;

                if n > 0 {
                    // Child reported an error
                    let msg = String::from_utf8_lossy(&err_buf[..n as usize]);
                    // Clean up: child already exited or will exit
                    let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(child_pid), None);
                    cgroup.destroy().ok();
                    return Err(Error::Other(format!("container setup failed: {msg}")));
                }

                // n == 0: EOF, exec succeeded
                self.pid = Some(child_pid);
                self.pidfd = Some(pidfd);
                self.cgroup = Some(cgroup);
                self.state
                    .start()
                    .map_err(|e| Error::Other(e.to_string()))?;
                Ok(())
            }
            None => {
                // === CHILD ===
                // Close read end of result pipe
                drop(result_read);
                // This function never returns — it either execs or exits
                self.child_setup(&sync_fd, slave_raw, master_raw, result_write_raw);
            }
        }
    }

    /// Take the PTY master fd out of the container (transfers ownership).
    /// Called by the daemon to send it to the client via SCM_RIGHTS.
    pub fn take_pty_master(&mut self) -> Option<OwnedFd> {
        self.pty_master.take()
    }

    /// Parent-side setup after clone3.
    #[tracing::instrument(skip_all, level = "debug")]
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
    ///
    /// `result_pipe_fd` is the write end of a pipe (O_CLOEXEC). On successful
    /// setup, exec() closes it automatically (parent reads EOF = success).
    /// On failure, we write the error message to it before exiting.
    fn child_setup(
        &self,
        sync_fd: &EventFd,
        slave_raw: i32,
        master_raw: i32,
        result_pipe_fd: i32,
    ) -> ! {
        // SAFETY: result_pipe_fd is a valid fd from pipe2, and we own it in the child.
        let pipe_fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(result_pipe_fd) };
        let result = self.child_setup_inner(sync_fd, slave_raw, master_raw, result_pipe_fd);
        if let Err(e) = result {
            // Report error to parent via the result pipe
            let msg = format!("{e}");
            let _ = nix::unistd::write(pipe_fd, msg.as_bytes());
            let _ = nix::unistd::close(result_pipe_fd);
            std::process::exit(1);
        }
        // If we get here, exec didn't happen (shouldn't be reachable)
        let _ = nix::unistd::write(pipe_fd, b"exec returned unexpectedly");
        let _ = nix::unistd::close(result_pipe_fd);
        std::process::exit(1);
    }

    fn child_setup_inner(
        &self,
        sync_fd: &EventFd,
        slave_raw: i32,
        master_raw: i32,
        result_pipe_fd: i32,
    ) -> Result<()> {
        // Die if the daemon (our parent) crashes — ensures no orphan containers
        nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL)
            .map_err(|e| Error::Other(format!("set_pdeathsig failed: {e}")))?;

        // Wait for parent to finish uid_map / gid_map / network setup
        sync_fd.wait()?;

        // Become container uid 0 / gid 0. After clone3(CLONE_NEWUSER), the
        // child inherits kuid 0 from the root daemon, but the uid_map maps
        // container uid 0 to a subordinate host uid (e.g., 100000). Since
        // kuid 0 is not in the mapped range, the child appears as uid 65534
        // (overflow). setresuid/setresgid adopts container uid/gid 0, which
        // maps correctly through the uid_map. This is what runc, crun, LXC,
        // and systemd-nspawn all do.
        nix::unistd::setresgid(
            nix::unistd::Gid::from_raw(0),
            nix::unistd::Gid::from_raw(0),
            nix::unistd::Gid::from_raw(0),
        )
        .map_err(|e| Error::Other(format!("setresgid(0,0,0) failed: {e}")))?;
        nix::unistd::setresuid(
            nix::unistd::Uid::from_raw(0),
            nix::unistd::Uid::from_raw(0),
            nix::unistd::Uid::from_raw(0),
        )
        .map_err(|e| Error::Other(format!("setresuid(0,0,0) failed: {e}")))?;

        // Make mounts private
        namespace::mount::make_mounts_private()?;

        // Set hostname (fall back to container name if not explicitly set)
        let hostname = self.spec.hostname.as_deref().unwrap_or(&self.spec.name);
        namespace::uts::set_hostname(hostname)?;

        // Set up rootfs (mounts /dev, /proc, /sys, bind mounts, pivot_root).
        // The rootfs path is the idmapped mount point set up by the daemon,
        // or falls back to the container rootfs path.
        let rootfs = self
            .idmap_mount
            .as_ref()
            .or(self.rootfs_path.as_ref())
            .ok_or_else(|| Error::Other("no rootfs path configured".to_string()))?
            .clone();
        setup_rootfs(&rootfs, &self.spec.bind_mounts)?;

        // Set up PTY slave as controlling terminal and stdio.
        // Must be after pivot_root (rootfs setup) so that setsid() doesn't
        // interfere with mount operations.
        if slave_raw >= 0 {
            let slave_owned = unsafe { OwnedFd::from_raw_fd(slave_raw) };
            pty::setup_slave_pty(&slave_owned, master_raw)?;
            // Don't drop slave_owned — setup_slave_pty already closed the raw fd
            std::mem::forget(slave_owned);
        }

        // Set environment variables.
        // Clear inherited env from daemon, then apply image + user env.
        // SAFETY: we're in a forked child process — single-threaded.
        for (k, _) in std::env::vars() {
            unsafe { std::env::remove_var(&k) };
        }
        if self.spec.env.is_empty() {
            // Sensible fallback if no env is configured
            unsafe {
                std::env::set_var(
                    "PATH",
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                )
            };
            unsafe { std::env::set_var("HOME", "/root") };
            unsafe { std::env::set_var("TERM", "xterm") };
        } else {
            for var in &self.spec.env {
                if let Some((k, v)) = var.split_once('=') {
                    unsafe { std::env::set_var(k, v) };
                }
            }
        }

        // Set working directory (after pivot_root so container paths work)
        if !self.spec.working_dir.is_empty() && self.spec.working_dir != "/" {
            let _ = std::env::set_current_dir(&self.spec.working_dir);
        }

        // Apply seccomp filter
        seccomp::apply_seccomp(&self.spec.seccomp)?;

        // Drop capabilities (must be after seccomp to avoid blocking prctl)
        capabilities::drop_capabilities(&self.spec.capabilities)?;

        // Close result pipe to signal success to parent. For exec_command,
        // O_CLOEXEC would handle this, but run_init never execs (it forks
        // instead), so the pipe must be closed explicitly before entering init.
        let _ = nix::unistd::close(result_pipe_fd);

        // Merge entrypoint + command for exec
        let exec_args = if self.spec.entrypoint.is_empty() {
            self.spec.command.clone()
        } else {
            [self.spec.entrypoint.clone(), self.spec.command.clone()].concat()
        };

        // Exec the command
        if self.spec.use_init {
            init::run_init(&exec_args);
        } else {
            exec_command(&exec_args)?;
        }

        Ok(())
    }

    /// Send a signal to the container's init process.
    pub fn signal(&self, sig: libc::c_int) -> Result<()> {
        if let Some(pid) = self.pid {
            let signal = nix::sys::signal::Signal::try_from(sig)
                .map_err(|e| Error::Kill(nix::Error::from(e)))?;
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), signal).map_err(Error::Kill)?;
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

        use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};

        let pid = nix::unistd::Pid::from_raw(self.pid.unwrap_or(0));

        loop {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, code)) => {
                    self.state
                        .stop(code)
                        .map_err(|e| Error::Other(e.to_string()))?;
                    return Ok(code);
                }
                Ok(WaitStatus::Signaled(_, sig, _)) => {
                    let exit_code = 128 + sig as i32;
                    self.state
                        .stop(exit_code)
                        .map_err(|e| Error::Other(e.to_string()))?;
                    return Ok(exit_code);
                }
                Ok(WaitStatus::StillAlive) => {}
                Ok(_) => {}
                Err(_) => {}
            }

            if start.elapsed() > timeout {
                // Force kill
                self.signal(libc::SIGKILL)?;
                // Wait indefinitely for SIGKILL
                let exit_code = match waitpid(pid, None) {
                    Ok(WaitStatus::Exited(_, code)) => code,
                    Ok(WaitStatus::Signaled(_, _, _)) => 137,
                    _ => 137,
                };
                self.state
                    .stop(exit_code)
                    .map_err(|e| Error::Other(e.to_string()))?;
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

        // Unmount idmapped mount
        if let Some(ref mount) = self.idmap_mount {
            let _ = nix::mount::umount2(mount, nix::mount::MntFlags::MNT_DETACH);
            let _ = std::fs::remove_dir(mount);
        }

        self.pid = None;
        self.pidfd = None;
        self.cgroup = None;
        self.pty_master = None;
        self.idmap_mount = None;

        // Note: rootfs_path cleanup (rm -rf the container copy) is handled
        // by the daemon via storage::container_fs::destroy_container_rootfs()

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

    // nix::unistd::execvp only returns on error (Ok is Infallible)
    nix::unistd::execvp(&c_program, &c_args).map_err(Error::Exec)?;

    unreachable!()
}
