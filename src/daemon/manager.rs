//! Container lifecycle manager.
//!
//! Tracks all containers, handles creation/start/stop/destroy requests,
//! and monitors pidfds for container exit events.

use super::persist;
use sandbox::container::Container;
use sandbox::error::{Error, Result};
use sandbox::namespace::user;
use sandbox::protocol::{ContainerInfo, ContainerSpec, ImageInfo, PoolInfo, Request, Response};
use sandbox::storage::fs_detect::FsType;
use sandbox::storage::{self, StorageManager};
use sandbox::sys::idmap;
use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const MOUNTS_DIR: &str = "/run/sandbox/mounts";

/// Result of handling a request — includes the response and optionally
/// a PTY master fd to send to the client via SCM_RIGHTS.
pub struct HandleResult {
    pub response: Response,
    pub pty_master: Option<OwnedFd>,
    /// Pidfd for an exec child (for monitoring + exit code delivery).
    pub exec_pidfd: Option<OwnedFd>,
}

impl HandleResult {
    fn response_only(response: Response) -> Self {
        Self {
            response,
            pty_master: None,
            exec_pidfd: None,
        }
    }

    fn with_pty(response: Response, pty_master: Option<OwnedFd>) -> Self {
        Self {
            response,
            pty_master,
            exec_pidfd: None,
        }
    }
}

/// Manages the lifecycle of all containers.
pub struct ContainerManager {
    containers: HashMap<String, Container>,
    storage: Arc<StorageManager>,
    /// Number of background rootfs deletions currently in flight.
    pending_cleanups: Arc<AtomicUsize>,
    /// Set to true when a shutdown request has been received.
    pub shutdown_requested: bool,
}

impl ContainerManager {
    pub fn new(storage: Arc<StorageManager>) -> Self {
        Self {
            containers: HashMap::new(),
            storage,
            pending_cleanups: Arc::new(AtomicUsize::new(0)),
            shutdown_requested: false,
        }
    }

    /// Recover from a previous daemon crash. Loads persisted state files,
    /// kills any surviving containers (PDEATHSIG should have handled this,
    /// but be defensive), cleans up transient resources (cgroups, mounts),
    /// and re-registers non-ephemeral containers as Created.
    pub fn recover_from_crash(&mut self) {
        let records = persist::load_all_states();
        if records.is_empty() {
            return;
        }

        tracing::info!(
            "found {} persisted container state(s), recovering",
            records.len()
        );

        // Collect names for orphan scan before consuming records
        let known_names: std::collections::HashSet<String> =
            records.iter().map(|(n, _)| n.clone()).collect();

        for (name, record) in records {
            // Kill the container process if it somehow survived
            if record.pid > 0 {
                let pid = nix::unistd::Pid::from_raw(record.pid);
                if nix::sys::signal::kill(pid, None).is_ok() {
                    tracing::info!(
                        "killing orphaned container process {name} (pid {})",
                        record.pid
                    );
                    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
                    // Poll until the process dies (can't waitpid — not our child after restart)
                    for _ in 0..20 {
                        if nix::sys::signal::kill(pid, None).is_err() {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            }

            // Clean up cgroup (transient, re-created on start)
            if record.cgroup_path.exists() {
                tracing::debug!("removing leftover cgroup {}", record.cgroup_path.display());
                let _ = std::fs::remove_dir(&record.cgroup_path);
            }

            // Unmount and remove idmapped mount (transient, re-created on start)
            if let Some(ref mount_path) = record.idmap_mount {
                if mount_path.exists() {
                    tracing::debug!("unmounting leftover idmap mount {}", mount_path.display());
                    let _ = nix::mount::umount2(mount_path, nix::mount::MntFlags::MNT_DETACH);
                    let _ = std::fs::remove_dir(mount_path);
                }
            }

            if record.ephemeral {
                // Ephemeral: delete rootfs, remove state file, don't re-register
                if let Some(ref rootfs_path) = record.rootfs_path {
                    if let Some(ref pool_name) = record.pool_name {
                        if let Some(pool) = self.storage.pool(pool_name) {
                            let fs_type = pool.fs_type.clone();
                            self.spawn_deferred_cleanup(rootfs_path.clone(), fs_type, name.clone());
                        }
                    }
                }
                persist::remove_state(&name);
                tracing::info!("cleaned up ephemeral container {name}");
            } else {
                // Non-ephemeral: keep rootfs, re-register as Created
                let rootfs_exists = record.rootfs_path.as_ref().is_some_and(|p| p.exists());

                if rootfs_exists {
                    let container = Container::from_recovered(
                        record.spec,
                        record.rootfs_path,
                        record.pool_name,
                        false,
                    );
                    // Update state file to Created
                    Self::persist_container(&name, &container);
                    self.containers.insert(name.clone(), container);
                    tracing::info!("recovered container {name} as Created");
                } else {
                    // Rootfs gone — nothing to recover
                    persist::remove_state(&name);
                    tracing::warn!("container {name} rootfs missing, removed state");
                }
            }
        }

        // Scan for orphaned cgroups not in any state file
        let cgroup_parent = std::path::Path::new("/sys/fs/cgroup/sandbox");
        if let Ok(entries) = std::fs::read_dir(cgroup_parent) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !known_names.contains(name.as_ref())
                    && !self.containers.contains_key(name.as_ref())
                    && entry.path().is_dir()
                {
                    tracing::debug!("removing orphaned cgroup /sys/fs/cgroup/sandbox/{name}");
                    let _ = std::fs::remove_dir(entry.path());
                }
            }
        }

        // Scan for orphaned mounts
        let mounts_dir = std::path::Path::new(MOUNTS_DIR);
        if let Ok(entries) = std::fs::read_dir(mounts_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !known_names.contains(name.as_ref())
                    && !self.containers.contains_key(name.as_ref())
                    && entry.path().is_dir()
                {
                    tracing::debug!("unmounting orphaned mount {}", entry.path().display());
                    let _ = nix::mount::umount2(&entry.path(), nix::mount::MntFlags::MNT_DETACH);
                    let _ = std::fs::remove_dir(entry.path());
                }
            }
        }

        // Scan for stale .cleanup-* directories and orphaned container rootfs in all pools
        for pool in self.storage.list_pools() {
            let fs_dir = pool.path.join("fs");
            if let Ok(entries) = std::fs::read_dir(&fs_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with(".cleanup-") {
                        tracing::debug!("finishing stale cleanup {}", entry.path().display());
                        let fs_type = pool.fs_type.clone();
                        self.spawn_deferred_cleanup(entry.path(), fs_type, name_str.to_string());
                    } else if !self.containers.contains_key(name_str.as_ref())
                        && !known_names.contains(name_str.as_ref())
                    {
                        // Orphaned container rootfs (e.g., ephemeral container
                        // whose daemon crashed before cleanup)
                        tracing::info!("cleaning up orphaned container rootfs: {name_str}");
                        // Unmount any stale idmap mount
                        let mount_path = std::path::Path::new(MOUNTS_DIR).join(name_str.as_ref());
                        if mount_path.exists() {
                            let _ =
                                nix::mount::umount2(&mount_path, nix::mount::MntFlags::MNT_DETACH);
                            let _ = std::fs::remove_dir(&mount_path);
                        }
                        let fs_type = pool.fs_type.clone();
                        self.spawn_deferred_cleanup(entry.path(), fs_type, name_str.to_string());
                    }
                }
            }
        }
    }

    /// Number of background rootfs deletions currently in flight.
    pub fn pending_cleanup_count(&self) -> usize {
        self.pending_cleanups.load(Ordering::Relaxed)
    }

    /// Spawn a background task to destroy a container's rootfs.
    ///
    /// The container rootfs is first renamed to a `.cleanup-*` path (instant
    /// metadata operation) so the original path is immediately available for
    /// reuse. The blocking `subvolume delete` / `rm -rf` then runs on smol's
    /// thread pool against the renamed path.
    fn spawn_deferred_cleanup(&self, container_path: PathBuf, fs_type: FsType, name: String) {
        // Rename to a unique cleanup path — instant metadata operation that
        // frees the original path for immediate reuse by the next container.
        let cleanup_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let cleanup_path = container_path
            .parent()
            .expect("container path must have parent")
            .join(format!(".cleanup-{name}-{cleanup_id}"));

        if let Err(e) = std::fs::rename(&container_path, &cleanup_path) {
            tracing::warn!("rename for deferred cleanup of '{name}' failed: {e}");
            return;
        }
        tracing::debug!(
            "renamed '{name}' rootfs to {} for deferred cleanup",
            cleanup_path.display()
        );

        let pending = Arc::clone(&self.pending_cleanups);
        pending.fetch_add(1, Ordering::Relaxed);
        smol::spawn(async move {
            let path_display = cleanup_path.display().to_string();
            let result = smol::unblock(move || {
                storage::container_fs::destroy_container_rootfs_by_path(cleanup_path, fs_type)
            })
            .await;
            if let Err(e) = result {
                tracing::warn!("deferred rootfs cleanup for '{name}' ({path_display}) failed: {e}");
            } else {
                tracing::debug!("deferred rootfs cleanup for '{name}' complete");
            }
            pending.fetch_sub(1, Ordering::Relaxed);
        })
        .detach();
    }

    /// Take the pidfd out of a container for async monitoring.
    pub fn take_pidfd(&mut self, name: &str) -> Option<OwnedFd> {
        self.containers.get_mut(name)?.pidfd.take()
    }

    /// Get all running containers as (name, pid) pairs.
    pub fn running_containers(&self) -> Vec<(String, i32)> {
        self.containers
            .iter()
            .filter(|(_, c)| c.state.is_running())
            .filter_map(|(name, c)| c.pid.map(|pid| (name.clone(), pid)))
            .collect()
    }

    /// Initiate an async stop: send SIGTERM and return pid + pidfd.
    /// Returns Err(Response) if the container doesn't exist or isn't running.
    pub fn initiate_stop(
        &mut self,
        name: &str,
    ) -> std::result::Result<(i32, Option<OwnedFd>), Response> {
        let container = match self.containers.get_mut(name) {
            Some(c) => c,
            None => {
                return Err(Response::Error {
                    message: format!("container {name} not found"),
                });
            }
        };

        if !container.state.is_running() {
            return Err(Response::Error {
                message: format!("container {name} is not running"),
            });
        }

        let pid = container.pid.unwrap_or(0);

        // Send SIGTERM
        if let Err(e) = container.signal(libc::SIGTERM) {
            return Err(Response::Error {
                message: format!("failed to signal container: {e}"),
            });
        }

        // Take pidfd for async monitoring
        let pidfd = container.pidfd.take();

        Ok((pid, pidfd))
    }

    /// Persist a non-ephemeral container's state to disk.
    fn persist_container(name: &str, container: &Container) {
        if container.ephemeral {
            return;
        }
        let record = persist::ContainerRecord {
            spec: container.spec.clone(),
            state: container.state.current().clone(),
            pid: container.pid.unwrap_or(0),
            cgroup_path: PathBuf::from("/sys/fs/cgroup/sandbox").join(name),
            idmap_mount: container.idmap_mount.clone(),
            rootfs_path: container.rootfs_path.clone(),
            pool_name: container.pool_name.clone(),
            ephemeral: container.ephemeral,
        };
        if let Err(e) = persist::save_state(name, &record) {
            tracing::warn!("failed to persist state for {name}: {e}");
        }
    }

    /// Handle a container exit: reap the child, update state, clean up resources.
    #[tracing::instrument(skip_all, level = "debug", fields(name = name))]
    pub fn handle_container_exit(&mut self, name: &str) -> i32 {
        let container = match self.containers.get_mut(name) {
            Some(c) => c,
            None => return 1,
        };

        if !container.state.is_running() {
            return 1;
        }

        let exit_code = if let Some(pid) = container.pid {
            use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
            match waitpid(nix::unistd::Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, code)) => code,
                Ok(WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
                _ => 1,
            }
        } else {
            1
        };

        let _ = container.state.stop(exit_code);
        let is_ephemeral = container.ephemeral;
        tracing::info!("container {name} exited with code {exit_code}");

        // Persist updated state (Stopped) for non-ephemeral containers
        if !is_ephemeral {
            if let Err(e) = persist::update_state(
                name,
                sandbox::protocol::ContainerState::Stopped { exit_code },
            ) {
                tracing::warn!("failed to persist exit state for {name}: {e}");
            }
        }

        // Clean up cgroup
        if let Some(ref cgroup) = container.cgroup {
            let _ = cgroup.destroy();
        }
        container.cgroup = None;

        // Auto-remove ephemeral containers
        if is_ephemeral {
            if let Some(mut c) = self.containers.remove(name) {
                // Defer rootfs deletion to a background task so we release
                // the manager mutex quickly.
                if let Some(pool_name) = &c.pool_name {
                    if let Some(pool) = self.storage.pool(pool_name) {
                        let container_path = pool.container_path(name);
                        let fs_type = pool.fs_type.clone();
                        self.spawn_deferred_cleanup(container_path, fs_type, name.to_string());
                    }
                }
                let _ = c.destroy();
            }
            tracing::info!("ephemeral container {name} auto-removed");
        }

        exit_code
    }

    /// Handle a request and return a response + optional PTY fd.
    pub fn handle_request(&mut self, request: Request) -> HandleResult {
        match request {
            Request::Create(spec) => self.handle_create(spec),
            Request::Run(spec) => self.handle_run(spec),
            Request::Start { name, command } => self.handle_start(&name, command),
            Request::Stop { .. } => {
                // Stop is handled asynchronously in handle_client via handle_stop_async.
                // This branch should not be reached.
                HandleResult::response_only(Response::Error {
                    message: "internal error: Stop should be handled async".to_string(),
                })
            }
            Request::Destroy { name } => self.handle_destroy(&name),
            Request::List => self.handle_list(),
            Request::Exec {
                name,
                command,
                detach,
            } => self.handle_exec(&name, command, detach),
            Request::ImageImport { name, source, pool } => {
                self.handle_image_import(&name, &source, pool.as_deref())
            }
            Request::ImagePull {
                reference,
                name,
                pool,
            } => self.handle_image_pull(&reference, name.as_deref(), pool.as_deref()),
            Request::ImageList { pool } => self.handle_image_list(pool.as_deref()),
            Request::ImageRemove { name, pool } => self.handle_image_remove(&name, pool.as_deref()),
            Request::MountAdd {
                name,
                source,
                target,
                readonly,
            } => self.handle_mount_add(&name, &source, &target, readonly),
            Request::MountRemove { name, target } => self.handle_mount_remove(&name, &target),
            Request::MountList { name } => self.handle_mount_list(&name),
            Request::PoolList => self.handle_pool_list(),
            Request::Shutdown => {
                tracing::info!("shutdown requested");
                let names: Vec<String> = self.containers.keys().cloned().collect();
                for name in names {
                    let _ = self.handle_destroy(&name);
                }
                let pending = self.pending_cleanup_count();
                if pending > 0 {
                    tracing::info!(
                        "shutdown: {pending} background rootfs cleanup(s) still in progress"
                    );
                }
                self.shutdown_requested = true;
                HandleResult::response_only(Response::Ok)
            }
        }
    }

    /// Prepare a container's rootfs: copy from image, set up idmapped mount.
    #[tracing::instrument(skip_all, level = "debug")]
    fn prepare_container_rootfs(&self, container: &mut Container) -> Result<()> {
        let pool = self.storage.resolve_pool(container.spec.pool.as_deref())?;
        let pool_name = pool.name.clone();

        // Create container rootfs from image (cp -a / snapshot)
        let rootfs_path = storage::container_fs::create_container_rootfs(
            pool,
            &container.spec.image,
            &container.spec.name,
        )?;

        container.rootfs_path = Some(rootfs_path);
        container.pool_name = Some(pool_name);

        // Set up idmapped mount on top of the new rootfs
        Self::ensure_idmap_mount(container)?;

        Ok(())
    }

    /// Ensure the idmapped mount is set up for a container.
    ///
    /// Called during create (after rootfs copy) and on start if the mount
    /// was cleaned up (e.g., after daemon restart recovery).
    #[tracing::instrument(skip_all, level = "debug")]
    fn ensure_idmap_mount(container: &mut Container) -> Result<()> {
        // Skip if already mounted
        if container.idmap_mount.is_some() {
            return Ok(());
        }

        let rootfs_path = container
            .rootfs_path
            .as_ref()
            .ok_or_else(|| Error::Other("no rootfs path configured".to_string()))?;

        // Resolve UID/GID mappings if not provided
        if container.spec.uid_mappings.is_empty() || container.spec.gid_mappings.is_empty() {
            let (uid_maps, gid_maps) = user::build_id_mappings()?;
            if container.spec.uid_mappings.is_empty() {
                container.spec.uid_mappings = uid_maps;
            }
            if container.spec.gid_mappings.is_empty() {
                container.spec.gid_mappings = gid_maps;
            }
        }

        let mount_target = PathBuf::from(MOUNTS_DIR).join(&container.spec.name);
        std::fs::create_dir_all(&mount_target).map_err(|e| {
            Error::Other(format!(
                "failed to create mount point {}: {e}",
                mount_target.display()
            ))
        })?;

        idmap::setup_idmapped_mount(
            rootfs_path,
            &mount_target,
            &container.spec.uid_mappings,
            &container.spec.gid_mappings,
        )?;

        container.idmap_mount = Some(mount_target);
        Ok(())
    }

    /// Apply image config (entrypoint, cmd, env, working_dir) to a ContainerSpec.
    /// Image defaults are used only if the user didn't provide overrides.
    #[tracing::instrument(skip_all, level = "debug")]
    fn apply_image_config(&self, spec: &mut ContainerSpec) {
        let pool = match self.storage.resolve_pool(spec.pool.as_deref()) {
            Ok(p) => p,
            Err(_) => return,
        };
        if let Some(meta) = storage::layers::load_image_meta(pool, &spec.image) {
            // Entrypoint: use image default if user didn't override
            if spec.entrypoint.is_empty() {
                spec.entrypoint = meta.config.entrypoint;
            }
            // Command: use image default only if user didn't provide any command
            // (default is ["/bin/sh"] from ContainerSpec::default — check if unchanged)
            if spec.command == vec!["/bin/sh".to_string()] && !meta.config.cmd.is_empty() {
                spec.command = meta.config.cmd;
            }
            // Env: merge image env with user env (user overrides image)
            if spec.env.is_empty() {
                spec.env = meta.config.env;
            }
            // Working dir: use image default if user didn't set one
            if spec.working_dir == "/" && !meta.config.working_dir.is_empty() {
                spec.working_dir = meta.config.working_dir;
            }
        }
    }

    fn handle_create(&mut self, mut spec: ContainerSpec) -> HandleResult {
        let name = spec.name.clone();

        if self.containers.contains_key(&name) {
            return HandleResult::response_only(Response::Error {
                message: format!("container {name} already exists"),
            });
        }

        self.apply_image_config(&mut spec);
        let mut container = Container::new(spec);

        // Prepare rootfs (copy image + idmap mount)
        if let Err(e) = self.prepare_container_rootfs(&mut container) {
            return HandleResult::response_only(Response::Error {
                message: format!("failed to prepare rootfs: {e}"),
            });
        }

        self.containers.insert(name.clone(), container);
        HandleResult::response_only(Response::Created { name })
    }

    #[tracing::instrument(skip_all, level = "debug", fields(name = %spec.name))]
    fn handle_run(&mut self, mut spec: ContainerSpec) -> HandleResult {
        let name = spec.name.clone();

        if self.containers.contains_key(&name) {
            return HandleResult::response_only(Response::Error {
                message: format!("container {name} already exists"),
            });
        }

        self.apply_image_config(&mut spec);
        let mut container = Container::new(spec);
        container.ephemeral = true;

        // Prepare rootfs (copy image + idmap mount)
        if let Err(e) = self.prepare_container_rootfs(&mut container) {
            return HandleResult::response_only(Response::Error {
                message: format!("failed to prepare rootfs: {e}"),
            });
        }

        match container.start() {
            Ok(()) => {
                let pid = container.pid.unwrap_or(0) as u32;
                let pty_master = container.take_pty_master();
                Self::persist_container(&name, &container);
                self.containers.insert(name.clone(), container);
                HandleResult::with_pty(Response::Started { name, pid }, pty_master)
            }
            Err(e) => {
                // Clean up on failure — defer rootfs deletion.
                let _ = container.destroy();
                if let Some(pool_name) = &container.pool_name {
                    if let Some(pool) = self.storage.pool(pool_name) {
                        let container_path = pool.container_path(&container.spec.name);
                        let fs_type = pool.fs_type.clone();
                        self.spawn_deferred_cleanup(
                            container_path,
                            fs_type,
                            container.spec.name.clone(),
                        );
                    }
                }
                HandleResult::response_only(Response::Error {
                    message: format!("failed to start container: {e}"),
                })
            }
        }
    }

    fn handle_start(&mut self, name: &str, command: Option<Vec<String>>) -> HandleResult {
        let container = match self.containers.get_mut(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                });
            }
        };

        if let Some(cmd) = command {
            container.spec.command = cmd;
        }

        // Re-create idmap mount if needed (e.g., after daemon restart recovery)
        if container.idmap_mount.is_none() {
            if let Err(e) = Self::ensure_idmap_mount(container) {
                return HandleResult::response_only(Response::Error {
                    message: format!("failed to set up idmap mount: {e}"),
                });
            }
        }

        match container.start() {
            Ok(()) => {
                let pid = container.pid.unwrap_or(0) as u32;
                let pty_master = container.take_pty_master();
                Self::persist_container(name, container);
                HandleResult::with_pty(
                    Response::Started {
                        name: name.to_string(),
                        pid,
                    },
                    pty_master,
                )
            }
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("failed to start container: {e}"),
            }),
        }
    }

    fn handle_mount_add(
        &mut self,
        name: &str,
        source: &str,
        target: &str,
        readonly: bool,
    ) -> HandleResult {
        let container = match self.containers.get_mut(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                });
            }
        };

        if !container.state.is_running() {
            return HandleResult::response_only(Response::Error {
                message: format!("container {name} is not running"),
            });
        }

        let pid = match container.pid {
            Some(p) => p,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: "container has no PID".to_string(),
                });
            }
        };

        let source_path = std::path::Path::new(source);
        if !source_path.exists() {
            return HandleResult::response_only(Response::Error {
                message: format!("source path does not exist: {source}"),
            });
        }

        // Perform the hot bind mount
        if let Err(e) = sandbox::sys::hot_mount::hot_bind_mount(pid, source_path, target, readonly)
        {
            return HandleResult::response_only(Response::Error {
                message: format!("mount failed: {e}"),
            });
        }

        // Add to bind_mounts so it persists across restart
        container
            .spec
            .bind_mounts
            .push(sandbox::protocol::BindMount {
                source: source.to_string(),
                target: target.to_string(),
                readonly,
            });

        // Persist updated state
        Self::persist_container(name, container);

        HandleResult::response_only(Response::MountAdded {
            target: target.to_string(),
        })
    }

    fn handle_mount_remove(&mut self, name: &str, target: &str) -> HandleResult {
        let container = match self.containers.get_mut(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                });
            }
        };

        if !container.state.is_running() {
            return HandleResult::response_only(Response::Error {
                message: format!("container {name} is not running"),
            });
        }

        let pid = match container.pid {
            Some(p) => p,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: "container has no PID".to_string(),
                });
            }
        };

        // Check mount exists in bind_mounts
        let idx = container
            .spec
            .bind_mounts
            .iter()
            .position(|m| m.target == target);
        if idx.is_none() {
            return HandleResult::response_only(Response::Error {
                message: format!("no bind mount at {target}"),
            });
        }

        // Perform the hot unmount
        if let Err(e) = sandbox::sys::hot_mount::hot_unmount(pid, target) {
            return HandleResult::response_only(Response::Error {
                message: format!("unmount failed: {e}"),
            });
        }

        // Remove from bind_mounts
        container.spec.bind_mounts.remove(idx.unwrap());

        // Persist updated state
        Self::persist_container(name, container);

        HandleResult::response_only(Response::MountRemoved {
            target: target.to_string(),
        })
    }

    fn handle_mount_list(&self, name: &str) -> HandleResult {
        let container = match self.containers.get(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                });
            }
        };

        let mounts: Vec<sandbox::protocol::MountInfo> = container
            .spec
            .bind_mounts
            .iter()
            .map(|m| sandbox::protocol::MountInfo {
                source: m.source.clone(),
                target: m.target.clone(),
                readonly: m.readonly,
            })
            .collect();

        HandleResult::response_only(Response::MountList(mounts))
    }

    fn handle_destroy(&mut self, name: &str) -> HandleResult {
        let mut container = match self.containers.remove(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                });
            }
        };

        // Defer rootfs deletion to a background task.
        if let Some(ref pool_name) = container.pool_name {
            if let Some(pool) = self.storage.pool(pool_name) {
                let container_path = pool.container_path(name);
                let fs_type = pool.fs_type.clone();
                self.spawn_deferred_cleanup(container_path, fs_type, name.to_string());
            }
        }

        match container.destroy() {
            Ok(()) => {
                persist::remove_state(name);
                HandleResult::response_only(Response::Destroyed {
                    name: name.to_string(),
                })
            }
            Err(e) => {
                self.containers.insert(name.to_string(), container);
                HandleResult::response_only(Response::Error {
                    message: format!("failed to destroy container: {e}"),
                })
            }
        }
    }

    fn handle_list(&self) -> HandleResult {
        let list: Vec<ContainerInfo> = self
            .containers
            .values()
            .map(|c| ContainerInfo {
                name: c.spec.name.clone(),
                state: c.state.current().clone(),
                pid: c.pid.map(|p| p as u32),
            })
            .collect();

        HandleResult::response_only(Response::ContainerList(list))
    }

    fn handle_exec(&mut self, name: &str, command: Vec<String>, detach: bool) -> HandleResult {
        let container = match self.containers.get(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                });
            }
        };

        if !container.state.is_running() {
            return HandleResult::response_only(Response::Error {
                message: format!("container {name} is not running"),
            });
        }

        let pid = match container.pid {
            Some(p) => p,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: "container has no PID".to_string(),
                });
            }
        };

        match exec_in_container(pid, name, &command, detach) {
            Ok(result) => {
                let response = Response::ExecStarted {
                    pid: result.pid as u32,
                };
                HandleResult {
                    response,
                    pty_master: result.pty_master,
                    exec_pidfd: Some(result.pidfd),
                }
            }
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("exec failed: {e}"),
            }),
        }
    }

    // -- Image handlers --

    fn handle_image_pull(
        &self,
        reference: &str,
        name: Option<&str>,
        pool: Option<&str>,
    ) -> HandleResult {
        let pool = match self.storage.resolve_pool(pool) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        // Parse the reference
        let parsed_ref = match storage::oci::Reference::parse(reference) {
            Ok(r) => r,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("invalid reference: {e}"),
                });
            }
        };

        let image_name = name
            .map(|n| n.to_string())
            .unwrap_or_else(|| parsed_ref.base_name());

        // Pull: authenticate, fetch manifest + config, download uncached layers.
        // We don't know chain IDs before fetching the config (need diff_ids),
        // so we download all layers and let layers.rs skip cached ones during extraction.
        let pull_result =
            match storage::oci::pull_image(&parsed_ref, &std::collections::HashSet::new()) {
                Ok(r) => r,
                Err(e) => {
                    return HandleResult::response_only(Response::Error {
                        message: format!("pull failed: {e}"),
                    });
                }
            };

        // Now we have the config with diff_ids — compute chain IDs and check cache
        let diff_ids = pull_result
            .config
            .rootfs
            .as_ref()
            .map(|r| r.diff_ids.clone())
            .unwrap_or_default();
        let chain_ids = storage::layers::compute_chain_ids(&diff_ids);
        let num_cached = storage::layers::find_cached_layers(pool, &chain_ids).len();

        if num_cached == chain_ids.len() {
            tracing::info!("all {} layers cached", chain_ids.len());
        } else if num_cached > 0 {
            tracing::info!("{} of {} layers cached", num_cached, chain_ids.len());
        }

        // Create image from pulled layers
        match storage::layers::create_image_from_pull(pool, &pull_result, &image_name) {
            Ok(()) => HandleResult::response_only(Response::ImagePulled { name: image_name }),
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("image creation failed: {e}"),
            }),
        }
    }

    fn handle_image_import(&self, name: &str, source: &str, pool: Option<&str>) -> HandleResult {
        let pool = match self.storage.resolve_pool(pool) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        match storage::image::import(pool, name, std::path::Path::new(source)) {
            Ok(()) => HandleResult::response_only(Response::ImageImported {
                name: name.to_string(),
            }),
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("image import failed: {e}"),
            }),
        }
    }

    fn handle_image_list(&self, pool: Option<&str>) -> HandleResult {
        let pool = match self.storage.resolve_pool(pool) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        match storage::image::list_images(pool) {
            Ok(images) => {
                let infos: Vec<ImageInfo> = images
                    .into_iter()
                    .map(|i| ImageInfo {
                        name: i.name,
                        pool: i.pool,
                        size_bytes: i.size_bytes,
                    })
                    .collect();
                HandleResult::response_only(Response::ImageList(infos))
            }
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("failed to list images: {e}"),
            }),
        }
    }

    fn handle_image_remove(&self, name: &str, pool: Option<&str>) -> HandleResult {
        let pool = match self.storage.resolve_pool(pool) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        // Clean up layer references (if this was a pulled image)
        if let Err(e) = storage::layers::remove_image_layers(pool, name) {
            tracing::warn!("layer cleanup for {name}: {e}");
        }

        match storage::image::remove_image(pool, name) {
            Ok(()) => HandleResult::response_only(Response::ImageRemoved {
                name: name.to_string(),
            }),
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("image remove failed: {e}"),
            }),
        }
    }

    fn handle_pool_list(&self) -> HandleResult {
        let pools: Vec<PoolInfo> = self
            .storage
            .list_pools()
            .into_iter()
            .map(|p| PoolInfo {
                name: p.name.clone(),
                fs_type: p.fs_type.to_string(),
                supports_snapshots: p.fs_type.supports_snapshots(),
            })
            .collect();

        HandleResult::response_only(Response::PoolList(pools))
    }
}

/// Result of exec_in_container.
struct ExecResult {
    pid: libc::pid_t,
    pidfd: OwnedFd,
    pty_master: Option<OwnedFd>,
}

/// Execute a command inside an existing container's namespaces.
///
/// Forks a child that joins the container's namespaces, optionally sets up
/// a PTY for interactive use, writes itself into the container's cgroup, and
/// execs the command. Returns a pidfd for monitoring + optional PTY master.
fn exec_in_container(
    container_pid: libc::pid_t,
    container_name: &str,
    command: &[String],
    detach: bool,
) -> Result<ExecResult> {
    use std::os::fd::FromRawFd;

    let namespaces = ["pid", "mnt", "net", "uts", "ipc", "user"];

    let mut ns_fds: Vec<(String, std::fs::File)> = Vec::new();
    for ns in &namespaces {
        let path = format!("/proc/{container_pid}/ns/{ns}");
        match std::fs::File::open(&path) {
            Ok(f) => ns_fds.push((ns.to_string(), f)),
            Err(e) => {
                tracing::warn!("failed to open {path}: {e}");
            }
        }
    }

    // Allocate PTY for interactive mode
    let pty = if !detach {
        Some(sandbox::sys::pty::allocate_pty()?)
    } else {
        None
    };

    // Cgroup path for the container
    let cgroup_procs = format!("/sys/fs/cgroup/sandbox/{container_name}/cgroup.procs");

    match unsafe { nix::unistd::fork() } {
        Err(e) => {
            return Err(Error::Other(format!("fork failed: {e}")));
        }
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            let child_pid = child.as_raw();

            // Close slave end in parent
            if let Some((master, _slave)) = pty {
                // Open pidfd for the child
                let pidfd_raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0) };
                if pidfd_raw < 0 {
                    return Err(Error::Other(format!(
                        "pidfd_open failed: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw as i32) };

                return Ok(ExecResult {
                    pid: child_pid,
                    pidfd,
                    pty_master: Some(master),
                });
            } else {
                // Detached mode — no PTY
                let pidfd_raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0) };
                if pidfd_raw < 0 {
                    return Err(Error::Other(format!(
                        "pidfd_open failed: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw as i32) };

                return Ok(ExecResult {
                    pid: child_pid,
                    pidfd,
                    pty_master: None,
                });
            }
        }
        Ok(nix::unistd::ForkResult::Child) => {}
    }

    // === CHILD ===
    {
        // Die if daemon dies
        let _ = nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL);

        // Join the container's cgroup (must happen before setns into mnt namespace,
        // since the host cgroupfs is not visible inside the container)
        if let Err(e) = std::fs::write(&cgroup_procs, format!("{}", std::process::id())) {
            eprintln!("failed to join cgroup: {e}");
            // Non-fatal — continue without cgroup membership
        }

        // Join the container's namespaces
        for (ns_name, ns_fd) in &ns_fds {
            let flags = match ns_name.as_str() {
                "pid" => nix::sched::CloneFlags::CLONE_NEWPID,
                "mnt" => nix::sched::CloneFlags::CLONE_NEWNS,
                "net" => nix::sched::CloneFlags::CLONE_NEWNET,
                "uts" => nix::sched::CloneFlags::CLONE_NEWUTS,
                "ipc" => nix::sched::CloneFlags::CLONE_NEWIPC,
                "user" => nix::sched::CloneFlags::CLONE_NEWUSER,
                _ => continue,
            };

            if let Err(e) = nix::sched::setns(ns_fd, flags) {
                eprintln!("setns({ns_name}) failed: {e}");
                std::process::exit(1);
            }
        }

        if let Err(e) = nix::unistd::chroot("/") {
            eprintln!("chroot failed: {e}");
            std::process::exit(1);
        }
        let _ = std::env::set_current_dir("/");

        // Set up PTY slave as stdin/stdout/stderr
        if let Some((_master, slave)) = pty {
            // Drop master in child
            drop(_master);
            if let Err(e) = sandbox::sys::pty::setup_slave_pty(&slave, -1) {
                eprintln!("pty setup failed: {e}");
                std::process::exit(1);
            }
        }

        if command.is_empty() {
            std::process::exit(1);
        }

        let c_prog = std::ffi::CString::new(command[0].as_str()).unwrap();
        let c_args: Vec<std::ffi::CString> = command
            .iter()
            .map(|a| std::ffi::CString::new(a.as_str()).unwrap())
            .collect();

        let err = nix::unistd::execvp(&c_prog, &c_args).unwrap_err();
        eprintln!("exec failed: {err}");
        std::process::exit(1);
    }
}
