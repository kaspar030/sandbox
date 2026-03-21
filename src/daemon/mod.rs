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
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const DEFAULT_SOCKET_PATH: &str = "/run/sandbox/sandbox.sock";
const DEFAULT_DATA_DIR: &str = "/var/lib/sandbox";

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

    // Derive paths from data_dir and socket_path
    let mounts_dir = Path::new(socket_path)
        .parent()
        .unwrap_or(Path::new("/run/sandbox"))
        .join("mounts");
    let state_dir = Path::new(data_dir).join("state");

    // Ensure directories exist
    if let Some(parent) = Path::new(socket_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir_all(&mounts_dir)?;

    // Initialize storage manager BEFORE creating the state dir.
    // On ZFS, StorageManager::init may create ZFS datasets that mount
    // over the data_dir, so any directories created beforehand would be
    // hidden. The state dir must be created after storage init.
    let storage = StorageManager::init(Path::new(data_dir))?;
    let storage = Arc::new(storage);

    persist::ensure_state_dir(&state_dir).map_err(Error::Io)?;

    // Remove stale socket
    let _ = std::fs::remove_file(socket_path);

    // Bind the listener (std, then wrap in Async)
    let listener = UnixListener::bind(socket_path).map_err(Error::Connection)?;
    let listener = Async::new(listener).map_err(Error::Connection)?;

    tracing::info!("sandbox daemon listening on {socket_path}");

    if !foreground {
        tracing::info!("running in foreground");
    }

    let mut mgr = manager::ContainerManager::new(
        Arc::clone(&storage),
        Path::new(data_dir),
        Path::new(socket_path),
    );

    // Load persisted networks and create the default network
    mgr.init_networks();

    // Recover from previous crash: clean up leftover containers, cgroups, mounts
    mgr.recover_from_crash();
    let containers_to_restart = mgr.containers_to_restart();

    let shutting_down = Arc::clone(&mgr.shutting_down);
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

        // Spawn a task that watches shutting_down (set by Request::Shutdown)
        let shutdown_tx_req = shutdown_tx.clone();
        let shutting_down_watch = Arc::clone(&shutting_down);
        smol::spawn(async move {
            loop {
                smol::Timer::after(Duration::from_millis(100)).await;
                if shutting_down_watch.load(Ordering::Relaxed) {
                    let _ = shutdown_tx_req.send(()).await;
                    break;
                }
            }
        })
        .detach();

        // Auto-restart recovered containers that have a restart policy
        for name in containers_to_restart {
            let mgr_restart = Arc::clone(&mgr);
            let shutting_down_restart = Arc::clone(&shutting_down);
            let name_clone = name.clone();
            smol::spawn(async move {
                // Brief delay to let the daemon fully initialize
                smol::Timer::after(Duration::from_secs(1)).await;

                let restart_result = {
                    let mut m = mgr_restart.lock().await;
                    m.restart_container(&name_clone)
                };

                match restart_result {
                    Ok(pidfd) => {
                        tracing::info!("auto-restarted recovered container {name_clone}");
                        await_pidfd_and_reap(
                            pidfd,
                            &name_clone,
                            Arc::clone(&mgr_restart),
                            shutting_down_restart,
                        )
                        .await;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "failed to auto-restart recovered container {name_clone}: {e}"
                        );
                    }
                }
            })
            .detach();
        }

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
                    let shutting_down = Arc::clone(&shutting_down);
                    smol::spawn(async move {
                        if let Err(e) = handle_client(stream, mgr, shutting_down).await {
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
    // Collect running containers and their PIDs, and set the shutting_down flag
    // so that await_pidfd_and_reap tasks don't attempt to restart containers.
    let running: Vec<(String, i32)> = {
        let m = mgr.lock().await;
        m.shutting_down.store(true, Ordering::Relaxed);
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

    // Kill all processes in each container's cgroup, then send SIGTERM to PID 1
    for (name, pid) in &running {
        // cgroup.kill ensures ALL processes (including exec'd) are killed
        let cgroup_kill = format!("/sys/fs/cgroup/sandbox/{name}/cgroup.kill");
        let _ = std::fs::write(&cgroup_kill, "1");
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
    shutting_down: Arc<AtomicBool>,
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

    // If we have a PTY master fd, send it via SCM_RIGHTS.
    // Don't fail the connection if the client disconnected (e.g., non-interactive
    // `start` command that just prints "Started" and exits). The pidfd monitoring
    // must still be set up even if the PTY send fails.
    if let Some(ref pty_master) = result.pty_master {
        let socket_ref = stream.get_ref();
        if let Err(e) = scm_rights::send_fd(socket_ref, pty_master) {
            tracing::debug!("PTY fd send failed (client may have disconnected): {e}");
        } else {
            tracing::debug!("sent PTY master fd to client");
        }
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
                let exit_code =
                    await_pidfd_and_reap(pidfd, &name, mgr_clone, Arc::clone(&shutting_down)).await;
                let _ = write_async_message(&mut stream, &Response::ContainerExited { exit_code })
                    .await;
            } else {
                // Detached mode: monitor in background
                let shutting_down = Arc::clone(&shutting_down);
                smol::spawn(async move {
                    let _ = await_pidfd_and_reap(pidfd, &name, mgr_clone, shutting_down).await;
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
    // Note: manually_stopped is already set in initiate_stop(), so
    // the restart policy won't trigger for user-initiated stops.
    let result = {
        let mut m = mgr.lock().await;
        m.handle_container_exit(name)
    };

    write_async_message(
        stream,
        &Response::Stopped {
            name: name.to_string(),
            exit_code: result.exit_code,
        },
    )
    .await?;

    Ok(())
}

/// Wait for a container pidfd to become readable (child exited), then reap
/// and update state. If the container has a restart policy, restart it
/// with exponential backoff and continue monitoring.
/// Returns the final exit code (when the container is not restarted).
async fn await_pidfd_and_reap(
    pidfd: std::os::fd::OwnedFd,
    name: &str,
    mgr: Arc<smol::lock::Mutex<manager::ContainerManager>>,
    shutting_down: Arc<AtomicBool>,
) -> i32 {
    let mut current_pidfd = pidfd;
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(30);
    let healthy_threshold = Duration::from_secs(10);

    loop {
        let start_time = std::time::Instant::now();

        // Wait for the container to exit
        if let Ok(async_fd) = Async::new(current_pidfd) {
            let _ = async_fd.readable().await;
        }

        // Reap and check restart policy
        let result = {
            let mut m = mgr.lock().await;
            m.handle_container_exit(name)
        };

        // Don't restart if the daemon is shutting down
        if !result.should_restart || shutting_down.load(Ordering::Relaxed) {
            return result.exit_code;
        }

        // Reset backoff if the container ran for a healthy duration
        let run_duration = start_time.elapsed();
        if run_duration > healthy_threshold {
            backoff = Duration::from_secs(1);
        }

        tracing::info!(
            "restarting container {name} in {:.1}s (backoff)",
            backoff.as_secs_f64()
        );
        smol::Timer::after(backoff).await;

        // Increase backoff for next crash (cap at max)
        backoff = std::cmp::min(backoff * 2, max_backoff);

        // Check if the container state changed during the backoff
        {
            let m = mgr.lock().await;
            if let Some(c) = m.get_container(name) {
                if c.manually_stopped {
                    tracing::info!(
                        "container {name} was stopped during restart backoff, aborting restart"
                    );
                    return result.exit_code;
                }
                if c.state.is_running() {
                    // User manually started it — another task is monitoring
                    tracing::info!(
                        "container {name} was manually started during restart backoff, aborting restart"
                    );
                    return result.exit_code;
                }
            } else {
                // Container was destroyed during backoff
                return result.exit_code;
            }
        }

        // Restart the container and get new pidfd
        let new_pidfd = {
            let mut m = mgr.lock().await;
            m.restart_container(name)
        };

        match new_pidfd {
            Ok(pidfd) => {
                current_pidfd = pidfd;
                // Continue the loop to monitor the new process
            }
            Err(e) => {
                tracing::error!("failed to restart container {name}: {e}");
                return result.exit_code;
            }
        }
    }
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
