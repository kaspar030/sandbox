//! Daemon — manages container lifecycles and serves client requests.
//!
//! Uses smol for async I/O:
//! - Unix socket listener for client connections
//! - Async<OwnedFd> on pidfds for container exit detection
//! - SCM_RIGHTS for passing PTY fds to clients
//! - Signal handler for graceful SIGTERM/SIGINT shutdown

pub mod manager;
pub mod persist;

use sandbox::error::{Error, Result};
use sandbox::protocol::{self, Request, Response};
use sandbox::storage::StorageManager;
use sandbox::sys::scm_rights;

use async_io::Async;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook_async_std::Signals;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::stream::StreamExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_SOCKET_PATH: &str = "/run/sandbox/sandbox.sock";
const DEFAULT_DATA_DIR: &str = "/var/lib/sandbox";
const MOUNTS_DIR: &str = "/run/sandbox/mounts";

/// Default timeout for graceful container shutdown (seconds).
const SHUTDOWN_TIMEOUT: u64 = 10;

/// Start the daemon, listening on the given socket path.
pub fn run_daemon(
    socket_path: Option<&str>,
    foreground: bool,
    data_dir: Option<&str>,
) -> Result<()> {
    let socket_path = socket_path.unwrap_or(DEFAULT_SOCKET_PATH);
    let data_dir = data_dir.unwrap_or(DEFAULT_DATA_DIR);

    // Ensure directories exist
    if let Some(parent) = Path::new(socket_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir_all(MOUNTS_DIR)?;
    persist::ensure_state_dir().map_err(Error::Io)?;

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

    let mut mgr = manager::ContainerManager::new(Arc::clone(&storage));

    // Recover from previous crash: clean up leftover containers, cgroups, mounts
    mgr.recover_from_crash();

    let mgr = Arc::new(smol::lock::Mutex::new(mgr));

    smol::block_on(async {
        // Register signal handlers for graceful shutdown
        let mut signals =
            Signals::new([SIGTERM, SIGINT]).expect("failed to register signal handlers");

        // Shutdown channel: signal handler or Request::Shutdown sends on this
        let (shutdown_tx, shutdown_rx) = smol::channel::bounded::<()>(1);

        // Spawn signal watcher
        let shutdown_tx_sig = shutdown_tx.clone();
        smol::spawn(async move {
            if signals.next().await.is_some() {
                tracing::info!("received shutdown signal");
                let _ = shutdown_tx_sig.send(()).await;
            }
        })
        .detach();

        // Spawn a task that watches shutdown_requested (set by Request::Shutdown)
        let shutdown_tx_req = shutdown_tx.clone();
        let mgr_watch = Arc::clone(&mgr);
        smol::spawn(async move {
            loop {
                smol::Timer::after(Duration::from_millis(100)).await;
                if mgr_watch.lock().await.shutdown_requested {
                    let _ = shutdown_tx_req.send(()).await;
                    break;
                }
            }
        })
        .detach();

        // Accept loop: race accept() vs shutdown signal
        loop {
            let accept_result =
                smol::future::race(async { Some(listener.accept().await) }, async {
                    let _ = shutdown_rx.recv().await;
                    None
                })
                .await;

            match accept_result {
                Some(Ok((stream, _addr))) => {
                    let mgr = Arc::clone(&mgr);
                    smol::spawn(async move {
                        if let Err(e) = handle_client(stream, mgr).await {
                            tracing::error!("client error: {e}");
                        }
                    })
                    .detach();
                }
                Some(Err(e)) => {
                    tracing::error!("accept error: {e}");
                }
                None => {
                    // Shutdown signal received
                    break;
                }
            }
        }

        // === Graceful shutdown ===
        graceful_shutdown(&mgr).await;
    });

    // Clean up socket file
    let _ = std::fs::remove_file(socket_path);
    tracing::info!("daemon stopped");

    Ok(())
}

/// Graceful shutdown: SIGTERM all containers → wait → SIGKILL survivors → cleanup.
async fn graceful_shutdown(mgr: &Arc<smol::lock::Mutex<manager::ContainerManager>>) {
    // Collect running containers and their PIDs
    let running: Vec<(String, i32)> = {
        let m = mgr.lock().await;
        m.running_containers()
    };

    if running.is_empty() {
        tracing::info!("no running containers, shutting down");
        return;
    }

    tracing::info!(
        "shutting down: sending SIGTERM to {} container(s)",
        running.len()
    );

    // Send SIGTERM to all running containers
    for (name, pid) in &running {
        let pid = nix::unistd::Pid::from_raw(*pid);
        if let Err(e) = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM) {
            tracing::warn!("failed to SIGTERM container {name}: {e}");
        }
    }

    // Wait for containers to exit (with timeout)
    let deadline = smol::Timer::after(Duration::from_secs(SHUTDOWN_TIMEOUT));
    let mut remaining = running.clone();

    // Poll for container exits
    let poll_result = smol::future::race(
        async {
            loop {
                smol::Timer::after(Duration::from_millis(100)).await;
                remaining.retain(|(_, pid)| {
                    nix::sys::signal::kill(nix::unistd::Pid::from_raw(*pid), None).is_ok()
                });
                if remaining.is_empty() {
                    return true; // all exited
                }
            }
        },
        async {
            deadline.await;
            false // timeout
        },
    )
    .await;

    if !poll_result && !remaining.is_empty() {
        tracing::warn!(
            "timeout: sending SIGKILL to {} remaining container(s)",
            remaining.len()
        );
        for (name, pid) in &remaining {
            let pid = nix::unistd::Pid::from_raw(*pid);
            if let Err(e) = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL) {
                tracing::warn!("failed to SIGKILL container {name}: {e}");
            }
        }
        // Brief wait for SIGKILL to take effect
        smol::Timer::after(Duration::from_millis(500)).await;
    }

    // Reap all containers and clean up
    {
        let mut m = mgr.lock().await;
        for (name, _) in &running {
            m.handle_container_exit(name);
        }
    }

    // Wait for pending background cleanups (deferred rootfs deletions)
    let cleanup_deadline = smol::Timer::after(Duration::from_secs(5));
    let cleanup_done = smol::future::race(
        async {
            loop {
                smol::Timer::after(Duration::from_millis(100)).await;
                if mgr.lock().await.pending_cleanup_count() == 0 {
                    return true;
                }
            }
        },
        async {
            cleanup_deadline.await;
            false
        },
    )
    .await;

    if !cleanup_done {
        tracing::warn!("background cleanups still running, exiting anyway");
    }
}

/// Handle a single client connection.
async fn handle_client(
    mut stream: Async<std::os::unix::net::UnixStream>,
    mgr: Arc<smol::lock::Mutex<manager::ContainerManager>>,
) -> Result<()> {
    // Read the request
    let request: Request = read_async_message(&mut stream).await?;

    tracing::debug!("received request: {request:?}");

    // Handle Stop specially: send SIGTERM under mutex, wait async, then reap
    if let Request::Stop {
        ref name,
        timeout_secs,
    } = request
    {
        return handle_stop_async(&mut stream, &mgr, name, timeout_secs).await;
    }

    // Process request (holds mutex briefly for non-blocking operations)
    let result = {
        let mut mgr = mgr.lock().await;
        mgr.handle_request(request)
    };

    // Send response
    write_async_message(&mut stream, &result.response).await?;

    // If we have a PTY master fd, send it via SCM_RIGHTS
    if let Some(ref pty_master) = result.pty_master {
        let socket_ref = stream.get_ref();
        scm_rights::send_fd(socket_ref, pty_master).map_err(|e| {
            tracing::error!("failed to send PTY fd via SCM_RIGHTS: {e}");
            e
        })?;
        tracing::debug!("sent PTY master fd to client");
    }

    // Interactive container start: monitor pidfd and send exit code to client
    if let Response::Started { ref name, .. } = result.response {
        let name = name.clone();
        let has_pty = result.pty_master.is_some();
        let mgr_clone = Arc::clone(&mgr);

        // Take the pidfd out of the container
        let pidfd = {
            let mut m = mgr.lock().await;
            m.take_pidfd(&name)
        };

        if let Some(pidfd) = pidfd {
            if has_pty {
                // Interactive mode: keep connection alive, send exit code after container exits
                let exit_code = await_pidfd_and_reap(pidfd, &name, mgr_clone).await;
                let _ = write_async_message(&mut stream, &Response::ContainerExited { exit_code })
                    .await;
            } else {
                // Detached mode: monitor in background
                smol::spawn(async move {
                    let _ = await_pidfd_and_reap(pidfd, &name, mgr_clone).await;
                })
                .detach();
            }
        }
    }

    // Interactive exec: monitor exec pidfd and send exit code to client
    if let Response::ExecStarted { pid } = result.response {
        if let Some(exec_pidfd) = result.exec_pidfd {
            let has_pty = result.pty_master.is_some();
            if has_pty {
                // Interactive exec: keep connection alive, send exit code
                let exit_code = await_exec_pidfd(exec_pidfd, pid as i32).await;
                let _ = write_async_message(&mut stream, &Response::ExecExited { exit_code }).await;
            } else {
                // Detached exec: just reap in background
                smol::spawn(async move {
                    let _ = await_exec_pidfd(exec_pidfd, pid as i32).await;
                })
                .detach();
            }
        }
    }

    Ok(())
}

/// Async container stop: send SIGTERM outside the blocking mutex path,
/// wait for the container to exit asynchronously, then reap.
async fn handle_stop_async(
    stream: &mut Async<std::os::unix::net::UnixStream>,
    mgr: &Arc<smol::lock::Mutex<manager::ContainerManager>>,
    name: &str,
    timeout_secs: u32,
) -> Result<()> {
    // Send SIGTERM and get pidfd (brief mutex hold)
    let (pid, pidfd) = {
        let mut m = mgr.lock().await;
        match m.initiate_stop(name) {
            Ok(result) => result,
            Err(resp) => {
                write_async_message(stream, &resp).await?;
                return Ok(());
            }
        }
    };

    // Wait for the container to exit asynchronously (no mutex held)
    let exited = if let Some(pidfd) = pidfd {
        if let Ok(async_fd) = Async::new(pidfd) {
            let timeout = smol::Timer::after(Duration::from_secs(timeout_secs as u64));
            smol::future::race(
                async {
                    let _ = async_fd.readable().await;
                    true
                },
                async {
                    timeout.await;
                    false
                },
            )
            .await
        } else {
            false
        }
    } else {
        false
    };

    // If timeout, send SIGKILL
    if !exited {
        let nix_pid = nix::unistd::Pid::from_raw(pid);
        let _ = nix::sys::signal::kill(nix_pid, nix::sys::signal::Signal::SIGKILL);
        // Brief wait for SIGKILL to take effect
        smol::Timer::after(Duration::from_millis(200)).await;
    }

    // Reap and update state (brief mutex hold)
    let exit_code = {
        let mut m = mgr.lock().await;
        m.handle_container_exit(name)
    };

    write_async_message(
        stream,
        &Response::Stopped {
            name: name.to_string(),
            exit_code,
        },
    )
    .await?;

    Ok(())
}

/// Wait for a container pidfd to become readable (child exited), then reap
/// and update state. Returns the exit code.
async fn await_pidfd_and_reap(
    pidfd: std::os::fd::OwnedFd,
    name: &str,
    mgr: Arc<smol::lock::Mutex<manager::ContainerManager>>,
) -> i32 {
    if let Ok(async_fd) = Async::new(pidfd) {
        let _ = async_fd.readable().await;
    }
    let mut m = mgr.lock().await;
    m.handle_container_exit(name)
}

/// Wait for an exec child pidfd to become readable, then reap it.
/// Returns the exit code.
async fn await_exec_pidfd(pidfd: std::os::fd::OwnedFd, child_pid: i32) -> i32 {
    if let Ok(async_fd) = Async::new(pidfd) {
        let _ = async_fd.readable().await;
    }
    // Reap the specific exec child
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    match waitpid(
        nix::unistd::Pid::from_raw(child_pid),
        Some(WaitPidFlag::WNOHANG),
    ) {
        Ok(WaitStatus::Exited(_, code)) => code,
        Ok(WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
        _ => 1,
    }
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
    stream.write_all(&data).await.map_err(Error::Connection)?;
    stream.flush().await.map_err(Error::Connection)?;
    Ok(())
}
