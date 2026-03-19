//! Eventfd wrapper for parent <-> child synchronization.
//!
//! We use eventfds to synchronize clone3:
//! 1. Parent creates eventfd before clone3
//! 2. Child inherits the fd and blocks reading it
//! 3. Parent sets up uid_map, gid_map, networking
//! 4. Parent writes to eventfd to unblock child
//! 5. Child proceeds with namespace setup (pivot_root, seccomp, etc.)

use crate::error::{Error, Result};
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::eventfd::EfdFlags;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

/// A synchronization primitive using Linux eventfd.
///
/// Used for parent-child coordination after clone3.
/// The child blocks on `wait()` until the parent calls `signal()`.
pub struct EventFd {
    fd: OwnedFd,
}

impl EventFd {
    /// Create a new eventfd with initial value 0.
    pub fn new() -> Result<Self> {
        #[allow(deprecated)] // eventfd() returns OwnedFd; EventFd struct doesn't transfer ownership
        let fd = nix::sys::eventfd::eventfd(0, EfdFlags::EFD_CLOEXEC).map_err(Error::EventFd)?;
        Ok(Self { fd })
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
        nix::unistd::write(&self.fd, &val.to_ne_bytes()).map_err(Error::EventFd)?;
        Ok(())
    }

    /// Wait (block) until the eventfd is signaled.
    /// Reads and consumes the counter.
    pub fn wait(&self) -> Result<()> {
        let mut buf = [0u8; 8];
        nix::unistd::read(&self.fd, &mut buf).map_err(Error::EventFd)?;
        Ok(())
    }

    /// Duplicate the file descriptor without CLOEXEC so it survives exec.
    /// Returns a new raw fd that the child should use.
    pub fn dup_for_child(&self) -> Result<RawFd> {
        let new_fd = nix::unistd::dup(&self.fd).map_err(Error::EventFd)?;
        // Remove CLOEXEC on the dup'd fd so it survives across exec.
        // On error, new_fd drops and closes automatically.
        let flags = fcntl(&new_fd, FcntlArg::F_GETFD).map_err(Error::EventFd)?;
        let mut fd_flags = FdFlag::from_bits_truncate(flags);
        fd_flags.remove(FdFlag::FD_CLOEXEC);
        fcntl(&new_fd, FcntlArg::F_SETFD(fd_flags)).map_err(Error::EventFd)?;
        // Transfer ownership: caller is responsible for closing
        Ok(new_fd.into_raw_fd())
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
