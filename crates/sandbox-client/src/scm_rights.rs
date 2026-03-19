//! SCM_RIGHTS — receiving file descriptors over Unix domain sockets.

use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
use std::io::IoSliceMut;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Receive a file descriptor from a Unix domain socket via SCM_RIGHTS.
pub fn recv_fd(socket: &impl AsRawFd) -> crate::Result<OwnedFd> {
    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg_buf = nix::cmsg_space!([RawFd; 1]);

    let msg = recvmsg::<()>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::empty(),
    )
    .map_err(|e| crate::Error::Other(format!("recvmsg SCM_RIGHTS failed: {e}")))?;

    let cmsgs = msg
        .cmsgs()
        .map_err(|e| crate::Error::Other(format!("cmsgs truncated: {e}")))?;

    for cmsg in cmsgs {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if let Some(&fd) = fds.first() {
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }

    Err(crate::Error::Other(
        "no file descriptor received via SCM_RIGHTS".to_string(),
    ))
}
