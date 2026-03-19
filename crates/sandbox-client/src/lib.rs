//! Client library for the sandbox container manager.
//!
//! Provides a synchronous API for communicating with the sandbox daemon
//! over a Unix domain socket.
//!
//! # Example
//!
//! ```no_run
//! use sandbox_client::Client;
//! use sandbox_proto::{Request, Response};
//!
//! let mut client = Client::connect(None).unwrap();
//! let resp = client.request(&Request::List).unwrap();
//! match resp {
//!     Response::ContainerList(containers) => {
//!         for c in containers {
//!             println!("{}: {:?}", c.name, c.state);
//!         }
//!     }
//!     _ => {}
//! }
//! ```

pub use sandbox_proto;

use sandbox_proto::{Request, Response};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

mod scm_rights;

const DEFAULT_SOCKET_PATH: &str = "/run/sandbox/sandbox.sock";

/// Error type for client operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("daemon not running (socket not found: {0})")]
    DaemonNotRunning(String),
    #[error("connection error: {0}")]
    Connection(std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(sandbox_proto::Error),
    #[error("{0}")]
    Other(String),
}

impl From<sandbox_proto::Error> for Error {
    fn from(e: sandbox_proto::Error) -> Self {
        Error::Protocol(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Client for communicating with the sandbox daemon.
pub struct Client {
    stream: UnixStream,
}

impl Client {
    /// Connect to the daemon.
    ///
    /// If `socket_path` is None, uses the default path `/run/sandbox/sandbox.sock`.
    pub fn connect(socket_path: Option<&str>) -> Result<Self> {
        let path = socket_path.unwrap_or(DEFAULT_SOCKET_PATH);

        if !Path::new(path).exists() {
            return Err(Error::DaemonNotRunning(path.into()));
        }

        let stream = UnixStream::connect(path).map_err(Error::Connection)?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .map_err(Error::Connection)?;

        Ok(Self { stream })
    }

    /// Send a request and receive a response.
    ///
    /// Use this for non-interactive operations (list, stop, destroy, image ops).
    pub fn request(&mut self, req: &Request) -> Result<Response> {
        sandbox_proto::write_message(&mut self.stream, req)?;
        Ok(sandbox_proto::read_message(&mut self.stream)?)
    }

    /// Send a request and receive a response + optional PTY fd.
    ///
    /// For interactive operations (run, exec), the daemon sends a PTY master fd
    /// via SCM_RIGHTS after the response. The caller is responsible for handling
    /// the PTY I/O (e.g., proxying to a terminal).
    ///
    /// After the PTY session ends (fd EOF), call [`read_exit_code`] to get the
    /// container/exec exit code.
    pub fn request_with_fd(&mut self, req: &Request) -> Result<(Response, Option<OwnedFd>)> {
        sandbox_proto::write_message(&mut self.stream, req)?;
        let response: Response = sandbox_proto::read_message(&mut self.stream)?;

        let expects_pty = matches!(
            response,
            Response::Started { .. } | Response::ExecStarted { .. }
        );

        if expects_pty {
            // Remove read timeout for the interactive session
            self.stream
                .set_read_timeout(None)
                .map_err(Error::Connection)?;

            match scm_rights::recv_fd(&self.stream) {
                Ok(pty_fd) => Ok((response, Some(pty_fd))),
                Err(e) => {
                    // No PTY fd — detached mode
                    tracing::warn!("no PTY fd received (detached mode?): {e}");
                    Ok((response, None))
                }
            }
        } else {
            Ok((response, None))
        }
    }

    /// Read the trailing exit code message after an interactive session ends.
    ///
    /// Call this after the PTY fd from [`request_with_fd`] reaches EOF.
    /// Returns `ContainerExited` or `ExecExited` response.
    pub fn read_exit_code(&mut self) -> Result<Response> {
        Ok(sandbox_proto::read_message(&mut self.stream)?)
    }
}
