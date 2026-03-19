//! Eventfd wrapper for parent <-> child synchronization.
//!
//! We use a single eventfd to synchronize clone3:
//! 1. Parent creates eventfd before clone3
//! 2. Child inherits the fd and blocks reading it
//! 3. Parent sets up uid_map, gid_map, networking
//! 4. Parent writes to eventfd to unblock child
//! 5. Child proceeds with namespace setup (pivot_root, seccomp, etc.)

use crate::error::{Error, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// A synchronization primitive using Linux eventfd.
///
/// Used for parent-child coordination after clone3.
/// The child blocks on `wait()` until the parent calls `signal()`.
pub struct EventFd {
    fd: OwnedFd,
}

#[allow(dead_code)]
impl EventFd {
    /// Create a new eventfd with initial value 0.
    pub fn new() -> Result<Self> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        if fd < 0 {
            return Err(Error::EventFd(std::io::Error::last_os_error()));
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Create an EventFd from a raw file descriptor.
    ///
    /// # Safety
    /// The fd must be a valid eventfd file descriptor.
    pub unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        }
    }

    /// Signal the eventfd (unblock the waiter).
    /// Writes the value 1.
    pub fn signal(&self) -> Result<()> {
        let val: u64 = 1;
        let ret = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                &val as *const u64 as *const libc::c_void,
                8,
            )
        };
        if ret < 0 {
            return Err(Error::EventFd(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Wait (block) until the eventfd is signaled.
    /// Reads and consumes the counter.
    pub fn wait(&self) -> Result<()> {
        let mut val: u64 = 0;
        let ret = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                &mut val as *mut u64 as *mut libc::c_void,
                8,
            )
        };
        if ret < 0 {
            return Err(Error::EventFd(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Get the raw file descriptor (for passing across clone3).
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Duplicate the file descriptor without CLOEXEC so it survives exec.
    /// Returns a new raw fd that the child should use.
    pub fn dup_for_child(&self) -> Result<RawFd> {
        let new_fd = unsafe { libc::dup(self.fd.as_raw_fd()) };
        if new_fd < 0 {
            return Err(Error::EventFd(std::io::Error::last_os_error()));
        }
        // Remove CLOEXEC on the dup'd fd so it survives across exec
        let flags = unsafe { libc::fcntl(new_fd, libc::F_GETFD) };
        if flags < 0 {
            unsafe { libc::close(new_fd) };
            return Err(Error::EventFd(std::io::Error::last_os_error()));
        }
        let ret = unsafe { libc::fcntl(new_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
        if ret < 0 {
            unsafe { libc::close(new_fd) };
            return Err(Error::EventFd(std::io::Error::last_os_error()));
        }
        Ok(new_fd)
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
