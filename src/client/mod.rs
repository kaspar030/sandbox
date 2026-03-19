//! CLI client — connects to the daemon over a Unix socket.
//!
//! Supports interactive sessions by receiving a PTY master fd
//! via SCM_RIGHTS and proxying I/O between the local terminal
//! and the container's PTY.

use sandbox::error::{Error, Result};
use sandbox::protocol::{self, Request, Response};
use sandbox::sys::scm_rights;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

const DEFAULT_SOCKET_PATH: &str = "/run/sandbox/sandbox.sock";

/// Client for communicating with the sandbox daemon.
pub struct Client {
    stream: UnixStream,
}

impl Client {
    /// Connect to the daemon.
    pub fn connect(socket_path: Option<&str>) -> Result<Self> {
        let path = socket_path.unwrap_or(DEFAULT_SOCKET_PATH);

        if !Path::new(path).exists() {
            return Err(Error::DaemonNotRunning(path.into()));
        }

        let stream = UnixStream::connect(path).map_err(Error::Connection)?;
        // Set a reasonable timeout for the initial request/response
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .map_err(Error::Connection)?;

        Ok(Self { stream })
    }

    /// Send a request and receive a response.
    pub fn request(&mut self, req: &Request) -> Result<Response> {
        protocol::write_message(&mut self.stream, req)?;
        protocol::read_message(&mut self.stream)
    }

    /// Send a request, receive a response, and if a PTY fd follows,
    /// enter an interactive session proxying I/O.
    ///
    /// Returns the response and the exit code (if interactive).
    pub fn request_interactive(&mut self, req: &Request) -> Result<(Response, Option<i32>)> {
        protocol::write_message(&mut self.stream, req)?;
        let response: Response = protocol::read_message(&mut self.stream)?;

        // Check if this response type implies a PTY fd follows
        let expects_pty = matches!(
            response,
            Response::Started { .. } | Response::ExecStarted { .. }
        );

        if expects_pty {
            // Remove read timeout for the interactive session
            self.stream
                .set_read_timeout(None)
                .map_err(Error::Connection)?;

            // Receive the PTY master fd via SCM_RIGHTS
            match scm_rights::recv_fd(&self.stream) {
                Ok(pty_master) => {
                    // Run the interactive session (blocks until PTY EOF)
                    let _ = interactive_session(pty_master)?;

                    // Read the exit code from the daemon (sent after container/exec exits)
                    let exit_msg: Response = protocol::read_message(&mut self.stream)?;
                    let exit_code = match exit_msg {
                        Response::ContainerExited { exit_code } => exit_code,
                        Response::ExecExited { exit_code } => exit_code,
                        _ => 0,
                    };
                    return Ok((response, Some(exit_code)));
                }
                Err(e) => {
                    tracing::warn!("no PTY fd received (detached mode?): {e}");
                    // Container started but no PTY — detached mode
                    return Ok((response, None));
                }
            }
        }

        Ok((response, None))
    }
}

/// Run an interactive session, proxying between the local terminal and
/// a PTY master fd received from the daemon.
///
/// 1. Save terminal state
/// 2. Put stdin in raw mode
/// 3. Spawn two threads: stdin → PTY, PTY → stdout
/// 4. Wait for PTY EOF (container exited)
/// 5. Restore terminal
fn interactive_session(pty_master: OwnedFd) -> Result<i32> {
    use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr, SetArg};

    let stdin_fd = std::io::stdin();
    let is_tty = nix::unistd::isatty(std::io::stdin().as_fd()).unwrap_or(false);

    // Save original terminal settings
    let original_termios = if is_tty {
        Some(tcgetattr(&stdin_fd).map_err(|e| Error::Other(format!("tcgetattr failed: {e}")))?)
    } else {
        None
    };

    // Guard to restore terminal on exit (including panic)
    let _guard = TerminalGuard {
        original: original_termios.clone(),
    };

    // Put stdin in raw mode
    if let Some(ref orig) = original_termios {
        let mut raw = orig.clone();
        cfmakeraw(&mut raw);
        tcsetattr(&stdin_fd, SetArg::TCSANOW, &raw)
            .map_err(|e| Error::Other(format!("tcsetattr raw failed: {e}")))?;
    }

    // Forward current terminal size to the PTY
    if is_tty {
        if let Ok(ws) = sandbox::sys::pty::get_window_size(&stdin_fd) {
            let _ = sandbox::sys::pty::set_window_size(&pty_master, &ws);
        }
    }

    let master_raw = pty_master.as_raw_fd();

    // Thread 1: stdin → PTY master (forward keystrokes to container)
    let _stdin_handle = std::thread::spawn(move || {
        // SAFETY: master_raw is a valid fd kept alive by pty_master in the main thread.
        let master_fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(master_raw) };
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if nix::unistd::write(master_fd, &buf[..n]).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });

    // Thread 2 (main thread): PTY master → stdout (display container output)
    let mut stdout = std::io::stdout().lock();
    let mut buf = [0u8; 4096];
    loop {
        match nix::unistd::read(&pty_master, &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stdout.write_all(&buf[..n]).is_err() {
                    break;
                }
                if stdout.flush().is_err() {
                    break;
                }
            }
        }
    }

    // The stdin thread will exit when its read returns an error
    // (because the master fd was closed or stdin was closed).
    // Don't join it — it may be blocked on stdin read.
    // The TerminalGuard will restore the terminal on drop.

    // Return 0 as exit code (we don't have the actual exit code here —
    // the daemon tracks that via pidfd). In a full implementation, the
    // daemon would send the exit code after the container exits.
    Ok(0)
}

/// RAII guard that restores the terminal state on drop.
struct TerminalGuard {
    original: Option<nix::sys::termios::Termios>,
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if let Some(ref orig) = self.original {
            let stdin = std::io::stdin();
            let _ = nix::sys::termios::tcsetattr(&stdin, nix::sys::termios::SetArg::TCSANOW, orig);
        }
    }
}
