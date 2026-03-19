//! Daemon — manages container lifecycles and serves client requests.
//!
//! Uses smol for async I/O:
//! - Unix socket listener for client connections
//! - Async<OwnedFd> on pidfds for container exit detection
//! - SCM_RIGHTS for passing PTY fds to clients

pub mod manager;

use sandbox::error::{Error, Result};
use sandbox::protocol::{self, Request, Response};
use sandbox::storage::StorageManager;
use sandbox::sys::scm_rights;

use async_io::Async;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;

const DEFAULT_SOCKET_PATH: &str = "/run/sandbox/sandbox.sock";
const DEFAULT_DATA_DIR: &str = "/var/lib/sandbox";
const MOUNTS_DIR: &str = "/run/sandbox/mounts";

/// Start the daemon, listening on the given socket path.
pub fn run_daemon(socket_path: Option<&str>, foreground: bool, data_dir: Option<&str>) -> Result<()> {
    let socket_path = socket_path.unwrap_or(DEFAULT_SOCKET_PATH);
    let data_dir = data_dir.unwrap_or(DEFAULT_DATA_DIR);

    // Ensure directories exist
    if let Some(parent) = Path::new(socket_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir_all(MOUNTS_DIR)?;

    // Initialize storage manager
    let storage = StorageManager::init(Path::new(data_dir))?;
    let storage = Arc::new(storage);

    // Remove stale socket
    let _ = std::fs::remove_file(socket_path);

    // Bind the listener (std, then wrap in Async)
    let listener = UnixListener::bind(socket_path).map_err(Error::Connection)?;
    let listener = Async::new(listener).map_err(Error::Connection)?;

    tracing::info!("sandbox daemon listening on {socket_path}");

    if !foreground {
        tracing::info!("running in foreground");
    }

    let mgr = Arc::new(smol::lock::Mutex::new(manager::ContainerManager::new(
        Arc::clone(&storage),
    )));

    smol::block_on(async {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let mgr = Arc::clone(&mgr);
                    smol::spawn(async move {
                        if let Err(e) = handle_client(stream, mgr).await {
                            tracing::error!("client error: {e}");
                        }
                    })
                    .detach();
                }
                Err(e) => {
                    tracing::error!("accept error: {e}");
                }
            }
        }
    })
}

/// Handle a single client connection.
async fn handle_client(
    mut stream: Async<std::os::unix::net::UnixStream>,
    mgr: Arc<smol::lock::Mutex<manager::ContainerManager>>,
) -> Result<()> {
    // Read the request
    let request: Request = read_async_message(&mut stream).await?;

    tracing::debug!("received request: {request:?}");

    // Process request
    let result = {
        let mut mgr = mgr.lock().await;
        mgr.handle_request(request)
    };

    // Send response
    write_async_message(&mut stream, &result.response).await?;

    // If we have a PTY master fd, send it via SCM_RIGHTS
    if let Some(ref pty_master) = result.pty_master {
        let socket_ref = stream.get_ref();
        scm_rights::send_fd(socket_ref, pty_master)
            .map_err(|e| {
                tracing::error!("failed to send PTY fd via SCM_RIGHTS: {e}");
                e
            })?;
        tracing::debug!("sent PTY master fd to client");
    }

    // If a container was started, spawn a background task to monitor its
    // pidfd. When the pidfd becomes readable (child exited), we reap the
    // child and update the container state. This uses smol's async epoll
    // integration — no polling threads, no busy-waiting.
    if let Response::Started { ref name, .. } = result.response {
        let name = name.clone();
        let mgr = Arc::clone(&mgr);
        smol::spawn(async move {
            // Take the pidfd out of the container (so we can await it
            // without holding the manager lock).
            let pidfd = {
                let mut m = mgr.lock().await;
                m.take_pidfd(&name)
            };
            if let Some(pidfd) = pidfd {
                if let Ok(async_fd) = Async::new(pidfd) {
                    // Block until the child exits (pidfd becomes readable)
                    let _ = async_fd.readable().await;
                }
                // Reap the child and update container state
                let mut m = mgr.lock().await;
                m.handle_container_exit(&name);
            }
        })
        .detach();
    }

    Ok(())
}

/// Read a length-prefixed postcard message from an async stream.
async fn read_async_message<T: for<'a> serde::Deserialize<'a>>(
    stream: &mut Async<std::os::unix::net::UnixStream>,
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(Error::Connection)?;
    let len = u32::from_le_bytes(len_buf) as usize;

    if len > 16 * 1024 * 1024 {
        return Err(Error::Protocol(format!("message too large: {len} bytes")));
    }

    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(Error::Connection)?;

    postcard::from_bytes(&payload).map_err(|e| Error::Protocol(e.to_string()))
}

/// Write a length-prefixed postcard message to an async stream.
async fn write_async_message<T: serde::Serialize>(
    stream: &mut Async<std::os::unix::net::UnixStream>,
    msg: &T,
) -> Result<()> {
    let data = protocol::encode_message(msg)?;
    stream
        .write_all(&data)
        .await
        .map_err(Error::Connection)?;
    stream.flush().await.map_err(Error::Connection)?;
    Ok(())
}
