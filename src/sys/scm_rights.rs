//! SCM_RIGHTS — passing file descriptors over Unix domain sockets.
//!
//! Used to transfer the PTY master fd from the daemon to the CLI client
//! after a container is started.

use crate::error::{Error, Result};
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Send a file descriptor over a Unix domain socket using SCM_RIGHTS.
///
/// A single byte is sent as the message payload (required by the protocol —
/// sendmsg must send at least 1 byte of data alongside ancillary data).
pub fn send_fd(socket: &impl AsRawFd, fd: &impl AsRawFd) -> Result<()> {
    let fds = [fd.as_raw_fd()];
    let cmsg = ControlMessage::ScmRights(&fds);
    let iov = [IoSlice::new(&[0u8])]; // 1 byte of payload

    sendmsg::<()>(socket.as_raw_fd(), &iov, &[cmsg], MsgFlags::empty(), None)
        .map_err(|e| Error::Other(format!("sendmsg SCM_RIGHTS failed: {e}")))?;

    Ok(())
}

/// Receive a file descriptor from a Unix domain socket via SCM_RIGHTS.
///
/// Returns the received fd as an OwnedFd.
pub fn recv_fd(socket: &impl AsRawFd) -> Result<OwnedFd> {
    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg_buf = nix::cmsg_space!([RawFd; 1]);

    let msg = recvmsg::<()>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::empty(),
    )
    .map_err(|e| Error::Other(format!("recvmsg SCM_RIGHTS failed: {e}")))?;

    // Extract the fd from the control message
    let cmsgs = msg
        .cmsgs()
        .map_err(|e| Error::Other(format!("cmsgs truncated: {e}")))?;

    for cmsg in cmsgs {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if let Some(&fd) = fds.first() {
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }

    Err(Error::Other(
        "no file descriptor received via SCM_RIGHTS".to_string(),
    ))
}
