//! clone3() syscall wrapper with CLONE_PIDFD and CLONE_INTO_CGROUP support.
//!
//! Linux 5.7+ is required for CLONE_INTO_CGROUP.
//! The clone3 syscall is not wrapped by libc/nix, so we call it directly.

use crate::error::{Error, Result};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

// clone3 flags (from linux/sched.h)
pub const CLONE_NEWNS: u64 = 0x00020000;
pub const CLONE_NEWUTS: u64 = 0x04000000;
pub const CLONE_NEWIPC: u64 = 0x08000000;
pub const CLONE_NEWUSER: u64 = 0x10000000;
pub const CLONE_NEWPID: u64 = 0x20000000;
pub const CLONE_NEWNET: u64 = 0x40000000;
pub const CLONE_NEWCGROUP: u64 = 0x02000000;
pub const CLONE_PIDFD: u64 = 0x00001000;
pub const CLONE_INTO_CGROUP: u64 = 0x200000000;

/// clone_args structure for clone3(2).
/// Must match the kernel's struct clone_args exactly.
#[repr(C)]
#[derive(Default)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,       // pointer to pidfd output (when CLONE_PIDFD)
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,      // cgroup fd (when CLONE_INTO_CGROUP)
}

/// Result of a successful clone3 call in the parent.
pub struct CloneResult {
    /// PID of the child process.
    pub child_pid: libc::pid_t,
    /// File descriptor for the child process (pidfd).
    pub pidfd: OwnedFd,
}

/// Perform a clone3 syscall to create a new process in the specified namespaces.
///
/// # Arguments
/// * `namespace_flags` - Combination of CLONE_NEW* flags
/// * `cgroup_fd` - Optional cgroup fd for CLONE_INTO_CGROUP
///
/// # Returns
/// * `Ok(Some(CloneResult))` in the parent
/// * `Ok(None)` in the child
///
/// # Safety
/// This is inherently unsafe as it creates a new process. The caller must
/// ensure proper synchronization between parent and child (e.g., via eventfd).
pub fn clone3_with_pidfd(
    namespace_flags: u64,
    cgroup_fd: Option<RawFd>,
) -> Result<Option<CloneResult>> {
    let mut pidfd_out: RawFd = -1;

    let mut args = CloneArgs {
        flags: namespace_flags | CLONE_PIDFD,
        pidfd: &mut pidfd_out as *mut RawFd as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..Default::default()
    };

    if let Some(fd) = cgroup_fd {
        args.flags |= CLONE_INTO_CGROUP;
        args.cgroup = fd as u64;
    }

    let ret = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &args as *const CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };

    if ret < 0 {
        return Err(Error::Clone3(std::io::Error::last_os_error()));
    }

    if ret == 0 {
        // Child process
        Ok(None)
    } else {
        // Parent process
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_out) };
        Ok(Some(CloneResult {
            child_pid: ret as libc::pid_t,
            pidfd,
        }))
    }
}

/// Build namespace flags from configuration.
pub struct NamespaceFlags {
    flags: u64,
}

impl NamespaceFlags {
    pub fn new() -> Self {
        Self { flags: 0 }
    }

    pub fn pid(mut self) -> Self {
        self.flags |= CLONE_NEWPID;
        self
    }

    pub fn mount(mut self) -> Self {
        self.flags |= CLONE_NEWNS;
        self
    }

    pub fn network(mut self) -> Self {
        self.flags |= CLONE_NEWNET;
        self
    }

    pub fn uts(mut self) -> Self {
        self.flags |= CLONE_NEWUTS;
        self
    }

    pub fn user(mut self) -> Self {
        self.flags |= CLONE_NEWUSER;
        self
    }

    pub fn ipc(mut self) -> Self {
        self.flags |= CLONE_NEWIPC;
        self
    }

    pub fn cgroup(mut self) -> Self {
        self.flags |= CLONE_NEWCGROUP;
        self
    }

    pub fn bits(&self) -> u64 {
        self.flags
    }
}

impl Default for NamespaceFlags {
    fn default() -> Self {
        Self::new()
    }
}
