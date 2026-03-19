//! CLI client — connects to the daemon over a Unix socket.

use sandbox::error::{Error, Result};
use sandbox::protocol::{self, Request, Response};
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
        // Set a reasonable timeout
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
}
