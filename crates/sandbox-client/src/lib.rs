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

    // -- Convenience methods --

    /// Add a bind mount to a running container.
    pub fn mount_add(
        &mut self,
        container: &str,
        source: &str,
        target: &str,
        readonly: bool,
    ) -> Result<Response> {
        self.request(&Request::MountAdd {
            name: container.to_string(),
            source: source.to_string(),
            target: target.to_string(),
            readonly,
        })
    }

    /// Remove a bind mount from a running container.
    pub fn mount_remove(&mut self, container: &str, target: &str) -> Result<Response> {
        self.request(&Request::MountRemove {
            name: container.to_string(),
            target: target.to_string(),
        })
    }

    /// List bind mounts for a container.
    pub fn mount_list(&mut self, container: &str) -> Result<Vec<sandbox_proto::MountInfo>> {
        let resp = self.request(&Request::MountList {
            name: container.to_string(),
        })?;
        match resp {
            Response::MountList(mounts) => Ok(mounts),
            Response::Error { message } => Err(Error::Other(message)),
            _ => Err(Error::Other("unexpected response".to_string())),
        }
    }

    /// Snapshot a container's rootfs into a reusable image.
    pub fn snapshot(
        &mut self,
        container: &str,
        image_name: &str,
        force: bool,
        update: bool,
    ) -> Result<Response> {
        self.request(&Request::Snapshot {
            name: container.to_string(),
            image_name: image_name.to_string(),
            force,
            update,
        })
    }

    /// Inspect an image (detailed info).
    pub fn image_inspect(
        &mut self,
        name: &str,
        pool: Option<&str>,
    ) -> Result<sandbox_proto::ImageDetail> {
        let resp = self.request(&Request::ImageInspect {
            name: name.to_string(),
            pool: pool.map(|s| s.to_string()),
        })?;
        match resp {
            Response::ImageInspect(detail) => Ok(detail),
            Response::Error { message } => Err(Error::Other(message)),
            _ => Err(Error::Other("unexpected response".to_string())),
        }
    }

    // -- Volume convenience methods --

    /// Create a named volume.
    pub fn volume_create(&mut self, name: &str, pool: Option<&str>) -> Result<Response> {
        self.request(&Request::VolumeCreate {
            name: name.to_string(),
            pool: pool.map(|s| s.to_string()),
            volume_type: sandbox_proto::VolumeType::Filesystem,
            size: None,
            format: None,
        })
    }

    /// Remove a named volume.
    pub fn volume_remove(&mut self, name: &str, pool: Option<&str>) -> Result<Response> {
        self.request(&Request::VolumeRemove {
            name: name.to_string(),
            pool: pool.map(|s| s.to_string()),
        })
    }

    /// List named volumes.
    pub fn volume_list(&mut self, pool: Option<&str>) -> Result<Vec<sandbox_proto::VolumeInfo>> {
        let resp = self.request(&Request::VolumeList {
            pool: pool.map(|s| s.to_string()),
        })?;
        match resp {
            Response::VolumeList(volumes) => Ok(volumes),
            Response::Error { message } => Err(Error::Other(message)),
            _ => Err(Error::Other("unexpected response".to_string())),
        }
    }

    /// Attach a volume to a running container.
    pub fn volume_attach(
        &mut self,
        container: &str,
        volume_name: &str,
        target: &str,
        readonly: bool,
    ) -> Result<Response> {
        self.request(&Request::VolumeAttach {
            container: container.to_string(),
            volume_name: volume_name.to_string(),
            target: target.to_string(),
            readonly,
        })
    }

    /// Detach a volume from a running container.
    pub fn volume_detach(&mut self, container: &str, target: &str) -> Result<Response> {
        self.request(&Request::VolumeDetach {
            container: container.to_string(),
            target: target.to_string(),
        })
    }

    /// Mount a block device inside a container (daemon-assisted).
    pub fn mount_block(
        &mut self,
        container: &str,
        device: &str,
        target: &str,
        fs_type: &str,
        options: Option<&str>,
    ) -> Result<Response> {
        self.request(&Request::MountBlock {
            container: container.to_string(),
            device: device.to_string(),
            target: target.to_string(),
            fs_type: fs_type.to_string(),
            options: options.map(|s| s.to_string()),
        })
    }
}
