//! PTY allocation and child-side setup.
//!
//! Allocates a master/slave PTY pair. The master fd stays with the daemon
//! (and is passed to the CLI client via SCM_RIGHTS). The slave fd is
//! set up as stdin/stdout/stderr in the container child process.

use crate::error::{Error, Result};
use nix::pty::{openpty, OpenptyResult, Winsize};

use nix::unistd::{dup2_stderr, dup2_stdin, dup2_stdout, setsid};
use std::os::fd::{AsRawFd, OwnedFd};

// ioctl wrappers via nix macros — these generate type-safe functions
nix::ioctl_write_int_bad!(tiocsctty, libc::TIOCSCTTY);
nix::ioctl_write_ptr_bad!(tiocswinsz, libc::TIOCSWINSZ, libc::winsize);
nix::ioctl_read_bad!(tiocgwinsz, libc::TIOCGWINSZ, libc::winsize);

/// Allocate a new PTY master/slave pair.
///
/// Returns (master, slave). The master fd has CLOEXEC set by default.
pub fn allocate_pty() -> Result<(OwnedFd, OwnedFd)> {
    let OpenptyResult { master, slave } = openpty(None, None)
        .map_err(|e| Error::Other(format!("openpty failed: {e}")))?;
    Ok((master, slave))
}

/// Allocate a PTY with a specific initial window size.
pub fn allocate_pty_with_size(rows: u16, cols: u16) -> Result<(OwnedFd, OwnedFd)> {
    let ws = Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let OpenptyResult { master, slave } = openpty(Some(&ws), None)
        .map_err(|e| Error::Other(format!("openpty failed: {e}")))?;
    Ok((master, slave))
}

/// Set up the slave PTY as the controlling terminal and redirect stdio.
///
/// Must be called in the child process after clone3, before exec.
/// The sequence is:
/// 1. setsid() — become session leader (required for TIOCSCTTY)
/// 2. TIOCSCTTY — make the slave PTY the controlling terminal
/// 3. dup2 slave → stdin/stdout/stderr
/// 4. Close the original slave fd (and master fd if leaked)
pub fn setup_slave_pty(slave_fd: &OwnedFd, master_fd_raw: i32) -> Result<()> {
    // 1. Create a new session (detach from parent's controlling terminal)
    setsid().map_err(|e| Error::Other(format!("setsid failed: {e}")))?;

    // 2. Set the slave PTY as the controlling terminal
    unsafe {
        tiocsctty(slave_fd.as_raw_fd(), 0)
            .map_err(|e| Error::Other(format!("TIOCSCTTY failed: {e}")))?;
    }

    // 3. Redirect stdin/stdout/stderr to the slave PTY
    dup2_stdin(slave_fd).map_err(|e| Error::Other(format!("dup2_stdin failed: {e}")))?;
    dup2_stdout(slave_fd).map_err(|e| Error::Other(format!("dup2_stdout failed: {e}")))?;
    dup2_stderr(slave_fd).map_err(|e| Error::Other(format!("dup2_stderr failed: {e}")))?;

    // 4. Close the original fds (if they're not already 0, 1, or 2)
    let slave_raw = slave_fd.as_raw_fd();
    if slave_raw > 2 {
        // Don't close via OwnedFd drop — we've already dup2'd it.
        // Just close the raw fd directly.
        unsafe { libc::close(slave_raw) };
    }
    if master_fd_raw >= 0 {
        unsafe { libc::close(master_fd_raw) };
    }

    Ok(())
}

/// Get the current terminal window size.
pub fn get_window_size(fd: &impl AsRawFd) -> Result<Winsize> {
    let mut ws = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        tiocgwinsz(fd.as_raw_fd(), &mut ws)
            .map_err(|e| Error::Other(format!("TIOCGWINSZ failed: {e}")))?;
    }
    Ok(ws)
}

/// Set the terminal window size on a PTY master fd.
pub fn set_window_size(fd: &impl AsRawFd, ws: &Winsize) -> Result<()> {
    unsafe {
        tiocswinsz(fd.as_raw_fd(), ws)
            .map_err(|e| Error::Other(format!("TIOCSWINSZ failed: {e}")))?;
    }
    Ok(())
}
