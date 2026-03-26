//! Container lifecycle manager.
//!
//! Tracks all containers, handles creation/start/stop/destroy requests,
//! and monitors pidfds for container exit events.

use super::persist;
use sandbox::container::Container;
use sandbox::error::{Error, Result};
use sandbox::namespace::user;
use sandbox::protocol::{
    ContainerDetail, ContainerInfo, ContainerSpec, PoolInfo, Request, Response,
};
use sandbox::storage::fs_detect::FsType;
use sandbox::storage::{self, StorageManager};
use sandbox::sys::idmap;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;

/// Result of handling a container exit.
pub struct ExitResult {
    pub exit_code: i32,
    /// If true, the container should be restarted by the async layer.
    pub should_restart: bool,
}
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Parse a subnet string like "10.1.0.0/24" into (addr, prefix_len).
fn parse_subnet(s: &str) -> std::result::Result<(Ipv4Addr, u8), String> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("invalid subnet: {s} (expected x.x.x.x/prefix)"));
    }
    let addr: Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| format!("invalid IP in subnet: {}", parts[0]))?;
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| format!("invalid prefix in subnet: {}", parts[1]))?;
    Ok((addr, prefix))
}

/// Result of handling a request — includes the response and optionally
/// a PTY master fd to send to the client via SCM_RIGHTS.
pub struct HandleResult {
    pub response: Response,
    pub pty_master: Option<OwnedFd>,
    /// Pidfd for an exec child (for monitoring + exit code delivery).
    pub exec_pidfd: Option<OwnedFd>,
    /// Pipe fds for piped exec mode: (stdout_read, stderr_read).
    pub pipe_fds: Option<(OwnedFd, OwnedFd)>,
}

impl HandleResult {
    fn response_only(response: Response) -> Self {
        Self {
            response,
            pty_master: None,
            exec_pidfd: None,
            pipe_fds: None,
        }
    }

    fn with_pty(response: Response, pty_master: Option<OwnedFd>) -> Self {
        Self {
            response,
            pty_master,
            exec_pidfd: None,
            pipe_fds: None,
        }
    }
}

/// Configuration for a named network.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct NetworkConfig {
    name: String,
    bridge: String,
    subnet: std::net::Ipv4Addr,
    gateway: std::net::Ipv4Addr,
    prefix_len: u8,
}

/// State of an active stack.
struct StackState {
    name: String,
    bridge: String,
    #[allow(dead_code)]
    network_name: String,
    containers: Vec<String>,
    volumes: Vec<String>,
    /// Sender to signal the DNS responder to shut down.
    dns_shutdown: Option<smol::channel::Sender<()>>,
}

/// Manages the lifecycle of all containers.
pub struct ContainerManager {
    containers: HashMap<String, Container>,
    storage: Arc<StorageManager>,
    /// Number of background rootfs deletions currently in flight.
    pending_cleanups: Arc<AtomicUsize>,
    /// Set to true when a shutdown request has been received.
    pub shutting_down: Arc<AtomicBool>,
    /// IP allocators per bridge name.
    ipam: HashMap<String, sandbox::net::ipam::IpAllocator>,
    /// Whether nftables (nft) is available on this system.
    nft_available: bool,
    /// Published host ports: host_port → container name.
    published_ports: HashMap<u16, String>,
    /// Bridge reference counts: bridge_name → number of containers using it.
    bridge_refcounts: HashMap<String, u32>,
    /// Named networks: network_name → NetworkConfig.
    networks: HashMap<String, NetworkConfig>,
    /// Next subnet index for auto-allocation (10.0.N.0/24).
    next_subnet_idx: u8,
    /// Active stacks: stack_name → StackState.
    stacks: HashMap<String, StackState>,
    /// Derived paths.
    state_dir: PathBuf,
    ipam_dir: PathBuf,
    mounts_dir: PathBuf,
}

impl ContainerManager {
    pub fn new(
        storage: Arc<StorageManager>,
        data_dir: &std::path::Path,
        socket_path: &std::path::Path,
    ) -> Self {
        let nft_available = sandbox::net::nat::nft_available();
        if !nft_available {
            tracing::warn!("nftables (nft) not found — bridged networking will not work");
        }
        let state_dir = data_dir.join("state");
        let ipam_dir = data_dir.join("ipam");
        let mounts_dir = socket_path
            .parent()
            .unwrap_or(std::path::Path::new("/run/sandbox"))
            .join("mounts");
        Self {
            containers: HashMap::new(),
            storage,
            pending_cleanups: Arc::new(AtomicUsize::new(0)),
            shutting_down: Arc::new(AtomicBool::new(false)),
            ipam: HashMap::new(),
            nft_available,
            published_ports: HashMap::new(),
            bridge_refcounts: HashMap::new(),
            networks: HashMap::new(),
            next_subnet_idx: 0,
            stacks: HashMap::new(),
            state_dir,
            ipam_dir,
            mounts_dir,
        }
    }

    /// Load persisted network configs and create the "default" network if needed.
    pub fn init_networks(&mut self) {
        self.load_network_configs();

        // Ensure the "default" network exists (backward compat with --network bridged)
        if !self.networks.contains_key("default") {
            let config = NetworkConfig {
                name: "default".to_string(),
                bridge: "sbr0".to_string(),
                subnet: std::net::Ipv4Addr::new(10, 0, 0, 0),
                gateway: std::net::Ipv4Addr::new(10, 0, 0, 1),
                prefix_len: 24,
            };
            self.networks.insert("default".to_string(), config);
            // Don't persist the default network — it's always auto-created
        }

        // Set next_subnet_idx based on existing networks
        for config in self.networks.values() {
            let octets = config.subnet.octets();
            if octets[0] == 10 && octets[1] == 0 {
                let idx = octets[2];
                if idx >= self.next_subnet_idx {
                    self.next_subnet_idx = idx.wrapping_add(1);
                }
            }
        }
    }

    /// Recover from a previous daemon crash. Loads persisted state files,
    /// kills any surviving containers (PDEATHSIG should have handled this,
    /// but be defensive), cleans up transient resources (cgroups, mounts),
    /// and re-registers non-ephemeral containers as Created.
    pub fn recover_from_crash(&mut self) {
        // Clean up stale NAT rules from previous run
        sandbox::net::nat::cleanup_nat();

        let records = persist::load_all_states(&self.state_dir);
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

            // Also kill any orphaned processes remaining in the container's
            // cgroup. This handles the case where the persisted PID was 0
            // (e.g., state saved after stop) but processes survived.
            let procs_path = record.cgroup_path.join("cgroup.procs");
            if let Ok(content) = std::fs::read_to_string(&procs_path) {
                for line in content.lines() {
                    if let Ok(pid) = line.trim().parse::<i32>() {
                        if pid > 0 {
                            tracing::info!(
                                "killing orphaned process in cgroup for {name} (pid {pid})"
                            );
                            let pid = nix::unistd::Pid::from_raw(pid);
                            let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
                        }
                    }
                }
            }

            // Clean up idmapped mounts that propagated to the host from
            // this container's bind mounts (must happen before cgroup/idmap
            // cleanup since propagated mounts may reference the container's
            // mount namespace resources)
            Self::cleanup_propagated_mounts(&record.spec.bind_mounts);

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
                persist::remove_state(&self.state_dir, &name);
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
                        record.manually_stopped,
                    );
                    // Update state file to Created
                    Self::persist_container(&self.state_dir, &name, &container);
                    self.containers.insert(name.clone(), container);
                    tracing::info!("recovered container {name} as Created");
                } else {
                    // Rootfs gone — nothing to recover
                    persist::remove_state(&self.state_dir, &name);
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
        let mounts_dir = &self.mounts_dir;
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
                        let mount_path = self.mounts_dir.join(name_str.as_ref());
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

    /// Get a reference to a container by name.
    pub fn get_container(&self, name: &str) -> Option<&Container> {
        self.containers.get(name)
    }

    /// Get names of recovered containers that should be auto-restarted.
    /// These are non-ephemeral containers with a restart policy that allows
    /// restart and that are currently in Created state (after recovery).
    pub fn containers_to_restart(&self) -> Vec<String> {
        self.containers
            .iter()
            .filter(|(_, c)| {
                c.state.is_created()
                    && !c.ephemeral
                    && c.spec.restart_policy.should_restart(0, c.manually_stopped)
            })
            .map(|(name, _)| name.clone())
            .collect()
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
    #[allow(clippy::result_large_err)]
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

        // Mark as manually stopped (inhibits UnlessStopped restart).
        // Set this even if the container is stopped (between restart cycles)
        // to prevent the restart loop from re-starting it.
        container.manually_stopped = true;
        Self::persist_container(&self.state_dir, name, container);

        if !container.state.is_running() {
            return Err(Response::Error {
                message: format!("container {name} is not running"),
            });
        }

        let pid = container.pid.unwrap_or(0);

        // Kill all processes in the cgroup (belt-and-suspenders: ensures exec'd
        // processes die even if they somehow escaped the PID namespace)
        let cgroup_kill_path = format!("/sys/fs/cgroup/sandbox/{name}/cgroup.kill");
        let _ = std::fs::write(&cgroup_kill_path, "1");

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
    /// Populate block volume state from resolved block volumes.
    ///
    /// Heuristic: if the target path starts with "/dev/", expose as raw device.
    /// Otherwise, if the volume is formatted, auto-mount the filesystem.
    fn populate_block_volumes(
        &self,
        container: &mut Container,
        block_vols: &[(String, String, sandbox::protocol::VolumeMount)],
    ) {
        for (vol_name, host_device, vol_mount) in block_vols {
            let meta = {
                let pool = match self.storage.resolve_pool(container.spec.pool.as_deref()) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                storage::volume::load_block_meta(pool, vol_name).ok()
            };
            let is_dev_target = vol_mount.target.starts_with("/dev/");
            let (container_device, container_mount) = if is_dev_target {
                // Explicitly a device path — always expose as raw device node
                (Some(vol_mount.target.clone()), None)
            } else if let Some(ref m) = meta {
                if m.format.is_some() {
                    // Formatted + non-/dev/ target: auto-mount filesystem
                    (m.format.clone(), Some(vol_mount.target.clone()))
                } else {
                    // Raw + non-/dev/ target: expose as device (user probably meant /dev/)
                    (Some(vol_mount.target.clone()), None)
                }
            } else {
                (Some(vol_mount.target.clone()), None)
            };
            container
                .block_volumes
                .push(sandbox::protocol::BlockVolumeState {
                    volume_name: vol_name.clone(),
                    host_device: host_device.clone(),
                    container_device,
                    container_mount,
                    host_mount: None,
                    loop_file: meta.and_then(|m| m.loop_file),
                });
        }
    }

    /// Clean up block volume resources: unmount host-side mounts, detach loop devices.
    fn cleanup_block_volumes(block_volumes: &mut Vec<sandbox::protocol::BlockVolumeState>) {
        for bv in block_volumes.iter() {
            if let Some(ref host_mount) = bv.host_mount {
                let _ = sandbox::sys::hot_mount::host_unmount(std::path::Path::new(host_mount));
            }
            if let Some(ref loop_file) = bv.loop_file {
                if let Ok(Some(dev)) = storage::volume::find_loop_for_file(loop_file) {
                    let _ = std::process::Command::new("losetup")
                        .args(["-d", &dev])
                        .output();
                }
            }
        }
        block_volumes.clear();
    }

    /// Clean up idmapped mounts that propagated from a container's bind mounts
    /// to the host mount namespace. These appear as idmapped submounts under
    /// the bind mount source paths on the host.
    fn cleanup_propagated_mounts(_bind_mounts: &[sandbox::protocol::BindMount]) {
        // TODO: implement propagated mount cleanup once mountinfo module is ready
    }

    fn persist_container(state_dir: &std::path::Path, name: &str, container: &Container) {
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
            manually_stopped: container.manually_stopped,
            block_volumes: container.block_volumes.clone(),
        };
        if let Err(e) = persist::save_state(state_dir, name, &record) {
            tracing::warn!("failed to persist state for {name}: {e}");
        }
    }

    /// Set up bridged networking for a container spec.
    ///
    /// Allocates an IP from IPAM if not specified, validates port mappings,
    /// sets up NAT masquerade + port forwarding, and adds resolv.conf bind mount.
    /// Resolve volume mounts. Filesystem volumes → bind mounts.
    /// Block volumes → returned for device setup during container start.
    fn resolve_volumes(
        &self,
        spec: &mut ContainerSpec,
    ) -> Result<Vec<(String, String, sandbox::protocol::VolumeMount)>> {
        if spec.volumes.is_empty() {
            return Ok(Vec::new());
        }
        let pool = self.storage.resolve_pool(spec.pool.as_deref())?;
        let mut block_vols = Vec::new();
        for vol in &spec.volumes {
            if vol.volume_type == sandbox::protocol::VolumeType::Block
                || storage::volume::is_block_volume(pool, &vol.name)
            {
                let device = storage::volume::get_block_device_path(pool, &vol.name)?;
                block_vols.push((vol.name.clone(), device, vol.clone()));
            } else {
                let vol_path = storage::volume::volume_path(pool, &vol.name);
                if !vol_path.is_dir() {
                    return Err(Error::Other(format!(
                        "volume '{}' not found (create it with: sandbox volume create {})",
                        vol.name, vol.name
                    )));
                }
                spec.bind_mounts.push(sandbox::protocol::BindMount {
                    source: vol_path.to_string_lossy().to_string(),
                    target: vol.target.clone(),
                    readonly: vol.readonly,
                });
            }
        }
        Ok(block_vols)
    }

    fn setup_bridged_networking(&mut self, spec: &mut ContainerSpec) -> Result<()> {
        // Resolve Named networks to Bridged
        if let sandbox::protocol::NetworkMode::Named { name } = &spec.network {
            let net = self.networks.get(name).ok_or_else(|| {
                Error::Other(format!(
                    "network '{name}' not found (create it with: sandbox network create {name})"
                ))
            })?;
            spec.network = sandbox::protocol::NetworkMode::Bridged {
                bridge: net.bridge.clone(),
                address: None,
                gateway: Some(net.gateway),
                prefix_len: net.prefix_len,
            };
        }

        let (bridge, address, gateway, prefix_len) = match &spec.network {
            sandbox::protocol::NetworkMode::Bridged {
                bridge,
                address,
                gateway,
                prefix_len,
            } => (bridge.clone(), *address, *gateway, *prefix_len),
            _ => return Ok(()),
        };

        // Check nft availability
        if !self.nft_available {
            return Err(Error::Other(
                "bridged networking requires nftables (nft) — not found on this system".to_string(),
            ));
        }

        // Get or create IPAM for this bridge
        let ipam_dir = self.ipam_dir.clone();
        let allocator = self.ipam.entry(bridge.clone()).or_insert_with(|| {
            sandbox::net::ipam::IpAllocator::load(&bridge, &ipam_dir).unwrap_or_else(|| {
                let subnet = std::net::Ipv4Addr::new(10, 0, 0, 0);
                sandbox::net::ipam::IpAllocator::new(subnet, prefix_len, &bridge, &ipam_dir)
            })
        });

        // Allocate or register IP
        let container_ip = if let Some(ip) = address {
            allocator.register(ip, &spec.name)?;
            ip
        } else {
            allocator.allocate(&spec.name)?
        };

        let gw = gateway.unwrap_or_else(|| allocator.gateway());

        // Update the spec with the resolved IP and gateway
        spec.network = sandbox::protocol::NetworkMode::Bridged {
            bridge: bridge.clone(),
            address: Some(container_ip),
            gateway: Some(gw),
            prefix_len,
        };

        // Set up NAT masquerade (idempotent — deletes and recreates table)
        let subnet_str = allocator.subnet_str();
        sandbox::net::nat::setup_masquerade(&bridge, &subnet_str)?;

        // Track bridge refcount
        *self.bridge_refcounts.entry(bridge.clone()).or_insert(0) += 1;

        // Validate and set up port forwarding
        for pm in &spec.publish {
            if let Some(existing) = self.published_ports.get(&pm.host_port) {
                return Err(Error::Other(format!(
                    "host port {} already in use by container '{existing}'",
                    pm.host_port
                )));
            }
            sandbox::net::nat::add_port_forward(
                &pm.protocol.to_string(),
                pm.host_port,
                container_ip,
                pm.container_port,
            )?;
            self.published_ports.insert(pm.host_port, spec.name.clone());
        }

        // Auto-add /etc/resolv.conf bind mount (read-only) so DNS works.
        // We copy the host's resolv.conf to a file under the runtime dir
        // instead of bind-mounting it directly, because on many systems
        // /etc/resolv.conf is a symlink to /run/... which is on tmpfs
        // and fails idmap mount_setattr.
        if !spec
            .bind_mounts
            .iter()
            .any(|m| m.target == "/etc/resolv.conf")
        {
            let resolv_copy = self
                .mounts_dir
                .parent()
                .unwrap_or(&self.mounts_dir)
                .join(format!("resolv-{}.conf", spec.name));
            if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
                let _ = std::fs::write(&resolv_copy, contents);
                spec.bind_mounts.push(sandbox::protocol::BindMount {
                    source: resolv_copy.to_string_lossy().to_string(),
                    target: "/etc/resolv.conf".to_string(),
                    readonly: true,
                });
            }
        }

        Ok(())
    }

    /// Clean up bridged networking for a container.
    fn cleanup_bridged_networking(&mut self, spec: &ContainerSpec) {
        let bridge = match &spec.network {
            sandbox::protocol::NetworkMode::Bridged { bridge, .. } => bridge.clone(),
            _ => return,
        };

        // Release IP
        if let Some(allocator) = self.ipam.get_mut(&bridge) {
            allocator.release(&spec.name);
        }

        // Remove port forwarding rules
        for pm in &spec.publish {
            let _ = sandbox::net::nat::remove_port_forward(&pm.protocol.to_string(), pm.host_port);
            self.published_ports.remove(&pm.host_port);
        }

        // Decrement bridge refcount
        if let Some(count) = self.bridge_refcounts.get_mut(&bridge) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                // Last container on this bridge — clean up
                self.bridge_refcounts.remove(&bridge);
                let _ = sandbox::net::bridge::delete_bridge(&bridge);
                sandbox::net::nat::cleanup_nat();
                if let Some(allocator) = self.ipam.remove(&bridge) {
                    allocator.remove_state();
                }
                tracing::info!("bridge {bridge} removed (last container left)");
            }
        }
    }

    /// Validate that --publish is only used with bridged networking.
    fn validate_publish(spec: &ContainerSpec) -> Result<()> {
        if !spec.publish.is_empty()
            && !matches!(
                spec.network,
                sandbox::protocol::NetworkMode::Bridged { .. }
                    | sandbox::protocol::NetworkMode::Named { .. }
            )
        {
            return Err(Error::Other(
                "--publish requires a network (bridged or named)".to_string(),
            ));
        }
        Ok(())
    }

    /// Handle a container exit: reap the child, update state, clean up resources.
    /// Returns the exit code and whether the container should be restarted.
    #[tracing::instrument(skip_all, level = "debug", fields(name = name))]
    pub fn handle_container_exit(&mut self, name: &str) -> ExitResult {
        let container = match self.containers.get_mut(name) {
            Some(c) => c,
            None => {
                return ExitResult {
                    exit_code: 1,
                    should_restart: false,
                };
            }
        };

        if !container.state.is_running() {
            return ExitResult {
                exit_code: 1,
                should_restart: false,
            };
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
        let manually_stopped = container.manually_stopped;
        let restart_policy = container.spec.restart_policy.clone();

        tracing::info!("container {name} exited with code {exit_code}");

        // Check if we should restart
        let should_restart =
            !is_ephemeral && restart_policy.should_restart(exit_code, manually_stopped);

        // Persist updated state (Stopped) for non-ephemeral containers
        if !is_ephemeral {
            Self::persist_container(&self.state_dir, name, container);
        }

        // Clean up block volume mounts and loop devices
        Self::cleanup_block_volumes(&mut container.block_volumes);

        // Clean up idmapped mounts that propagated to the host
        Self::cleanup_propagated_mounts(&container.spec.bind_mounts);

        // Clean up cgroup
        if let Some(ref cgroup) = container.cgroup {
            let _ = cgroup.destroy();
        }
        container.cgroup = None;
        container.pid = None;

        // Auto-remove ephemeral containers
        if is_ephemeral {
            // Clean up networking before removing the container
            if let Some(c) = self.containers.get(name) {
                self.cleanup_bridged_networking(&c.spec.clone());
            }
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

        ExitResult {
            exit_code,
            should_restart,
        }
    }

    /// Restart a stopped container. Resets state to Created and starts it.
    /// Returns the new pidfd on success.
    pub fn restart_container(&mut self, name: &str) -> std::result::Result<OwnedFd, String> {
        let container = match self.containers.get_mut(name) {
            Some(c) => c,
            None => return Err(format!("container {name} not found")),
        };

        // Reset state: Stopped → Created (skip if already Created, e.g., after recovery)
        if container.state.is_stopped() {
            if let Err(e) = container.state.reset() {
                return Err(format!("cannot restart {name}: {e}"));
            }
        } else if !container.state.is_created() {
            return Err(format!(
                "cannot restart {name}: not in Stopped or Created state"
            ));
        }

        // Clear the manually_stopped flag for the new lifecycle
        container.manually_stopped = false;

        // Re-create idmap mount if needed
        if container.idmap_mount.is_none() {
            if let Err(e) = Self::ensure_idmap_mount(container, &self.mounts_dir) {
                return Err(format!("idmap mount for {name}: {e}"));
            }
        }

        // Start the container
        match container.start() {
            Ok(()) => {
                let pid = container.pid.unwrap_or(0);
                tracing::info!("restarted container {name} (PID {pid})");
                Self::persist_container(&self.state_dir, name, container);

                // Take the pidfd so the async layer can monitor it
                container
                    .pidfd
                    .take()
                    .ok_or_else(|| format!("no pidfd for restarted {name}"))
            }
            Err(e) => Err(format!("restart {name}: {e}")),
        }
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
            Request::Snapshot {
                name,
                image_name,
                force,
                update,
            } => self.handle_snapshot(&name, &image_name, force, update),
            Request::List => self.handle_list(),
            Request::Inspect { name } => self.handle_inspect(&name),
            Request::Exec {
                name,
                command,
                detach,
                user,
                env,
                piped,
            } => self.handle_exec(&name, command, detach, piped, user, env),
            Request::ImageImport { name, source, pool } => {
                self.handle_image_import(&name, &source, pool.as_deref())
            }
            Request::ImagePull {
                reference,
                name,
                pool,
            } => self.handle_image_pull(&reference, name.as_deref(), pool.as_deref()),
            Request::ImageList {
                pool,
                show_size,
                show_exclusive,
                show_layers,
            } => self.handle_image_list(pool.as_deref(), show_size, show_exclusive, show_layers),
            Request::ImageInspect { name, pool } => {
                self.handle_image_inspect(&name, pool.as_deref())
            }
            Request::ImageRemove { name, pool } => self.handle_image_remove(&name, pool.as_deref()),
            Request::MountAdd {
                name,
                source,
                target,
                readonly,
            } => self.handle_mount_add(&name, &source, &target, readonly),
            Request::MountRemove { name, target } => self.handle_mount_remove(&name, &target),
            Request::MountList { name } => self.handle_mount_list(&name),
            Request::VolumeCreate {
                name,
                pool,
                volume_type,
                size,
                format,
            } => self.handle_volume_create(&name, pool.as_deref(), volume_type, size, format),
            Request::VolumeRemove { name, pool } => {
                self.handle_volume_remove(&name, pool.as_deref())
            }
            Request::VolumeList { pool } => self.handle_volume_list(pool.as_deref()),
            Request::VolumeAttach {
                container,
                volume_name,
                target,
                readonly,
            } => self.handle_volume_attach(&container, &volume_name, &target, readonly),
            Request::VolumeDetach { container, target } => {
                self.handle_volume_detach(&container, &target)
            }
            Request::MountBlock {
                container,
                device,
                target,
                fs_type,
                options,
            } => {
                self.handle_mount_block(&container, &device, &target, &fs_type, options.as_deref())
            }
            Request::UpdateContainer { name, update } => {
                self.handle_update_container(&name, update)
            }
            Request::StackUp(def) => self.handle_stack_up(def),
            Request::StackDown { name } => self.handle_stack_down(&name),
            Request::StackPs { name } => self.handle_stack_ps(&name),
            Request::StackList => self.handle_stack_list(),
            Request::NetworkCreate { name, subnet } => {
                self.handle_network_create(&name, subnet.as_deref())
            }
            Request::NetworkRemove { name } => self.handle_network_remove(&name),
            Request::NetworkList => self.handle_network_list(),
            Request::PoolList => self.handle_pool_list(),
            Request::Shutdown => {
                tracing::info!("shutdown requested");
                // Don't destroy containers — graceful_shutdown() will handle
                // running containers, and non-running containers should survive
                // for recovery on next daemon start.
                self.shutting_down.store(true, Ordering::Relaxed);
                HandleResult::response_only(Response::Ok)
            }
            Request::SnapshotContainer {
                name,
                snapshot_name,
                exclude_volumes,
            } => self.handle_snapshot_container(&name, snapshot_name, exclude_volumes),
            Request::RestoreContainer {
                name,
                snapshot_name,
            } => self.handle_restore_container(&name, &snapshot_name),
            Request::ListContainerSnapshots { name, show_size } => {
                self.handle_list_container_snapshots(&name, show_size)
            }
            Request::DeleteContainerSnapshot {
                name,
                snapshot_name,
            } => self.handle_delete_container_snapshot(&name, &snapshot_name),
            Request::StackSnapshot {
                stack_name,
                snapshot_name,
                exclude_volumes,
            } => self.handle_stack_snapshot(&stack_name, snapshot_name, exclude_volumes),
            Request::StackRestore {
                stack_name,
                snapshot_name,
            } => self.handle_stack_restore(&stack_name, &snapshot_name),
            Request::StackSnapshots {
                stack_name,
                show_size,
            } => self.handle_stack_snapshots(&stack_name, show_size),
            Request::CloneContainer {
                source,
                name,
                overrides,
            } => self.handle_clone_container(source, &name, overrides),
            Request::RenameContainer { name, new_name } => {
                self.handle_rename_container(&name, &new_name)
            }
            Request::EnableSession => {
                // Handled at the connection level in handle_client, not here.
                HandleResult::response_only(Response::SessionEnabled)
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
        Self::ensure_idmap_mount(container, &self.mounts_dir)?;

        Ok(())
    }

    fn ensure_idmap_mount(container: &mut Container, mounts_dir: &std::path::Path) -> Result<()> {
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

        let mount_target = mounts_dir.join(&container.spec.name);
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
            if spec.command.is_empty() && !meta.config.cmd.is_empty() {
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
            // User: use image default if CLI didn't set one
            if spec.user.is_none() {
                spec.user = meta.config.user;
            }
        }
    }

    /// If no command or entrypoint is set and init is not explicitly enabled,
    /// enable init implicitly so the container runs in idle mode (PID 1 waits
    /// for `exec` sessions). This is the default for `create` without a command.
    fn apply_implicit_init(spec: &mut ContainerSpec) {
        if spec.command.is_empty() && spec.entrypoint.is_empty() && !spec.use_init {
            spec.use_init = true;
        }
    }

    fn handle_create(&mut self, mut spec: ContainerSpec) -> HandleResult {
        let name = spec.name.clone();

        if self.containers.contains_key(&name) {
            return HandleResult::response_only(Response::Error {
                message: format!("container {name} already exists"),
            });
        }

        // Apply implicit init BEFORE image config — if the user didn't provide
        // a command or entrypoint, enable init (idle mode). apply_image_config
        // may later fill in the image's CMD, but init is already set.
        Self::apply_implicit_init(&mut spec);
        self.apply_image_config(&mut spec);

        // Validate and set up bridged networking
        if let Err(e) = Self::validate_publish(&spec) {
            return HandleResult::response_only(Response::Error {
                message: format!("{e}"),
            });
        }
        if let Err(e) = self.setup_bridged_networking(&mut spec) {
            return HandleResult::response_only(Response::Error {
                message: format!("network setup failed: {e}"),
            });
        }

        // Resolve volumes (block volumes returned for device setup during start)
        let block_vols = match self.resolve_volumes(&mut spec) {
            Ok(bv) => bv,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        let mut container = Container::new(spec);
        self.populate_block_volumes(&mut container, &block_vols);

        // Prepare rootfs (copy image + idmap mount)
        if let Err(e) = self.prepare_container_rootfs(&mut container) {
            return HandleResult::response_only(Response::Error {
                message: format!("failed to prepare rootfs: {e}"),
            });
        }

        self.containers.insert(name.clone(), container);
        HandleResult::response_only(Response::Created { name })
    }

    fn handle_clone_container(
        &mut self,
        source: sandbox::protocol::CloneSource,
        new_name: &str,
        overrides: sandbox::protocol::ContainerOverrides,
    ) -> HandleResult {
        if self.containers.contains_key(new_name) {
            return HandleResult::response_only(Response::Error {
                message: format!("container {new_name} already exists"),
            });
        }

        // Resolve source spec and rootfs path
        let (mut spec, source_rootfs) = match &source {
            sandbox::protocol::CloneSource::Container(src_name) => {
                let src = match self.containers.get(src_name.as_str()) {
                    Some(c) => c,
                    None => {
                        return HandleResult::response_only(Response::Error {
                            message: format!("source container '{src_name}' not found"),
                        });
                    }
                };
                let rootfs = match &src.rootfs_path {
                    Some(p) => p.clone(),
                    None => {
                        return HandleResult::response_only(Response::Error {
                            message: format!("source container '{src_name}' has no rootfs"),
                        });
                    }
                };
                (src.spec.clone(), rootfs)
            }
            sandbox::protocol::CloneSource::Snapshot(container_name, snapshot_name) => {
                // Find the source container to resolve the pool
                let src = match self.containers.get(container_name.as_str()) {
                    Some(c) => c,
                    None => {
                        return HandleResult::response_only(Response::Error {
                            message: format!("source container '{container_name}' not found"),
                        });
                    }
                };
                let pool = match self.storage.resolve_pool(src.spec.pool.as_deref()) {
                    Ok(p) => p,
                    Err(e) => {
                        return HandleResult::response_only(Response::Error {
                            message: format!("{e}"),
                        });
                    }
                };
                let manifest =
                    match storage::snapshot::read_manifest(pool, container_name, snapshot_name) {
                        Ok(m) => m,
                        Err(e) => {
                            return HandleResult::response_only(Response::Error {
                                message: format!("failed to read snapshot manifest: {e}"),
                            });
                        }
                    };
                let rootfs =
                    storage::snapshot::snapshot_rootfs_path(pool, container_name, snapshot_name);
                if !rootfs.exists() {
                    return HandleResult::response_only(Response::Error {
                        message: format!(
                            "snapshot rootfs not found for '{container_name}:{snapshot_name}'"
                        ),
                    });
                }
                (manifest.spec, rootfs)
            }
        };

        // Set new name
        spec.name = new_name.to_string();

        // Clear bridged network address — the clone gets its own
        if let sandbox::protocol::NetworkMode::Bridged {
            ref mut address, ..
        } = spec.network
        {
            *address = None;
        }

        // Apply overrides
        if !overrides.env.is_empty() {
            spec.env = overrides.env;
        }
        if let Some(hostname) = overrides.hostname {
            spec.hostname = Some(hostname);
        }
        if let Some(command) = overrides.command {
            spec.command = command;
        }
        if let Some(entrypoint) = overrides.entrypoint {
            spec.entrypoint = entrypoint;
        }
        if let Some(user) = overrides.user {
            spec.user = Some(user);
        }
        if let Some(working_dir) = overrides.working_dir {
            spec.working_dir = working_dir;
        }
        if let Some(restart_policy) = overrides.restart_policy {
            spec.restart_policy = restart_policy;
        }
        if let Some(use_init) = overrides.use_init {
            spec.use_init = use_init;
        }
        if !overrides.volumes.is_empty() {
            spec.volumes = overrides.volumes;
        }
        if !overrides.bind_mounts.is_empty() {
            spec.bind_mounts = overrides.bind_mounts;
        }

        // Re-apply implicit init after overrides may have changed command/entrypoint
        Self::apply_implicit_init(&mut spec);

        // Skip apply_image_config — the source spec already has it baked in

        // Validate and set up bridged networking
        if let Err(e) = Self::validate_publish(&spec) {
            return HandleResult::response_only(Response::Error {
                message: format!("{e}"),
            });
        }
        if let Err(e) = self.setup_bridged_networking(&mut spec) {
            return HandleResult::response_only(Response::Error {
                message: format!("network setup failed: {e}"),
            });
        }

        // Resolve volumes
        let block_vols = match self.resolve_volumes(&mut spec) {
            Ok(bv) => bv,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        // Clone rootfs
        let pool = match self.storage.resolve_pool(spec.pool.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };
        let pool_name = pool.name.clone();
        let rootfs_path =
            match storage::container_fs::clone_container_rootfs(pool, &source_rootfs, new_name) {
                Ok(p) => p,
                Err(e) => {
                    return HandleResult::response_only(Response::Error {
                        message: format!("failed to clone rootfs: {e}"),
                    });
                }
            };

        let mut container = Container::new(spec);
        self.populate_block_volumes(&mut container, &block_vols);
        container.rootfs_path = Some(rootfs_path);
        container.pool_name = Some(pool_name);

        // Set up idmapped mount
        if let Err(e) = Self::ensure_idmap_mount(&mut container, &self.mounts_dir) {
            return HandleResult::response_only(Response::Error {
                message: format!("failed to set up idmap mount: {e}"),
            });
        }

        let name = new_name.to_string();
        self.containers.insert(name.clone(), container);
        HandleResult::response_only(Response::Created { name })
    }

    fn handle_rename_container(&mut self, name: &str, new_name: &str) -> HandleResult {
        // Validate
        if !self.containers.contains_key(name) {
            return HandleResult::response_only(Response::Error {
                message: format!("container '{name}' not found"),
            });
        }
        if self.containers.contains_key(new_name) {
            return HandleResult::response_only(Response::Error {
                message: format!("container '{new_name}' already exists"),
            });
        }
        if self.containers[name].state.is_running() {
            return HandleResult::response_only(Response::Error {
                message: format!("container '{name}' is running — stop it before renaming"),
            });
        }

        let pool = match self
            .storage
            .resolve_pool(self.containers[name].spec.pool.as_deref())
        {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        // Rename rootfs: <pool>/fs/<old> -> <pool>/fs/<new>
        let old_rootfs = pool.container_path(name);
        let new_rootfs = pool.container_path(new_name);
        if old_rootfs.exists() {
            if let Err(e) = std::fs::rename(&old_rootfs, &new_rootfs) {
                return HandleResult::response_only(Response::Error {
                    message: format!(
                        "failed to rename rootfs {} -> {}: {e}",
                        old_rootfs.display(),
                        new_rootfs.display()
                    ),
                });
            }
        }

        // Rename snapshots dir: <pool>/snapshots/<old> -> <pool>/snapshots/<new>
        let old_snaps = pool.path.join("snapshots").join(name);
        let new_snaps = pool.path.join("snapshots").join(new_name);
        if old_snaps.exists() {
            if let Err(e) = std::fs::rename(&old_snaps, &new_snaps) {
                tracing::warn!("failed to rename snapshots dir: {e}");
            } else {
                // Update container name in snapshot manifests
                if let Ok(entries) = std::fs::read_dir(&new_snaps) {
                    for entry in entries.flatten() {
                        let manifest_path = entry.path().join("manifest.json");
                        if manifest_path.exists() {
                            if let Ok(json) = std::fs::read_to_string(&manifest_path) {
                                if let Ok(mut manifest) = serde_json::from_str::<
                                    storage::snapshot::SnapshotManifest,
                                >(&json)
                                {
                                    manifest.container = new_name.to_string();
                                    manifest.spec.name = new_name.to_string();
                                    if let Ok(updated) = serde_json::to_string_pretty(&manifest) {
                                        let _ = std::fs::write(&manifest_path, updated);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Clean up old idmap mount
        let mut container = self.containers.remove(name).unwrap();
        if let Some(ref mount_path) = container.idmap_mount {
            let _ = nix::mount::umount2(mount_path, nix::mount::MntFlags::MNT_DETACH);
            let _ = std::fs::remove_dir(mount_path);
        }
        container.idmap_mount = None;

        // Update container state
        container.spec.name = new_name.to_string();
        if old_rootfs.exists() || new_rootfs.exists() {
            container.rootfs_path = Some(new_rootfs);
        }

        // Remove old persistence file, save new one
        persist::remove_state(&self.state_dir, name);
        Self::persist_container(&self.state_dir, new_name, &container);

        self.containers.insert(new_name.to_string(), container);

        HandleResult::response_only(Response::ContainerRenamed {
            old_name: name.to_string(),
            new_name: new_name.to_string(),
        })
    }

    fn handle_update_container(
        &mut self,
        name: &str,
        update: sandbox::protocol::ContainerUpdate,
    ) -> HandleResult {
        let container = match self.containers.get_mut(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                });
            }
        };

        let is_running = container.state.is_running();

        // -- Cgroup limits --
        if let Some(policy) = update.restart_policy {
            container.spec.restart_policy = policy;
        }
        if let Some(mem) = update.memory_max {
            container.spec.cgroup.memory_max = Some(mem);
        }
        if let Some(cpu) = update.cpu_max {
            container.spec.cgroup.cpu_max = Some(cpu);
        }
        if let Some(pids) = update.pids_max {
            container.spec.cgroup.pids_max = Some(pids);
        }

        // -- Environment --
        // Order: clear → remove → set
        if update.env_clear {
            container.spec.env.clear();
        }
        for key in &update.env_remove {
            container
                .spec
                .env
                .retain(|e| !e.starts_with(&format!("{key}=")));
        }
        for kv in &update.env_set {
            if let Some(key) = kv.split('=').next() {
                // Remove existing value for this key, then add new
                container
                    .spec
                    .env
                    .retain(|e| !e.starts_with(&format!("{key}=")));
            }
            container.spec.env.push(kv.clone());
        }

        // -- Command / Entrypoint --
        if let Some(cmd) = update.command {
            container.spec.command = cmd;
        }
        if let Some(ep) = update.entrypoint {
            container.spec.entrypoint = ep;
        }

        // Implicit init: if command+entrypoint are now empty, enable init (idle mode)
        Self::apply_implicit_init(&mut container.spec);

        // -- Container identity --
        if let Some(u) = update.user {
            container.spec.user = u;
        }
        if let Some(h) = update.hostname {
            container.spec.hostname = h;
        }
        if let Some(wd) = update.working_dir {
            container.spec.working_dir = wd;
        }

        // -- Init --
        if let Some(init) = update.use_init {
            container.spec.use_init = init;
        }

        // -- Security --
        if let Some(seccomp) = update.seccomp {
            container.spec.seccomp = seccomp;
        }
        for cap in &update.cap_add {
            if !container.spec.capabilities.keep.contains(cap) {
                container.spec.capabilities.keep.push(cap.clone());
            }
        }
        for cap in &update.cap_drop {
            container.spec.capabilities.keep.retain(|c| c != cap);
        }
        if let Some(nnp) = update.no_new_privs {
            container.spec.no_new_privs = nnp;
        }

        // -- Bind mounts --
        if let Some(new_binds) = &update.bind_mounts {
            if is_running {
                let pid = container.pid.unwrap_or(0);
                // Remove mounts no longer in the new list
                let old_targets: Vec<String> = container
                    .spec
                    .bind_mounts
                    .iter()
                    .map(|m| m.target.clone())
                    .collect();
                for target in &old_targets {
                    if !new_binds.iter().any(|b| b.target == *target) {
                        if let Err(e) = sandbox::sys::hot_mount::hot_unmount(pid, target) {
                            tracing::warn!("failed to unmount {target}: {e}");
                        }
                    }
                }
                // Add new mounts
                for bind in new_binds {
                    if !container
                        .spec
                        .bind_mounts
                        .iter()
                        .any(|b| b.target == bind.target)
                    {
                        let source_path = std::path::Path::new(&bind.source);
                        if let Err(e) = sandbox::sys::hot_mount::hot_bind_mount(
                            pid,
                            source_path,
                            &bind.target,
                            bind.readonly,
                        ) {
                            tracing::warn!("failed to mount {}: {e}", bind.target);
                        }
                    }
                }
            }
            container.spec.bind_mounts = new_binds.clone();
        }

        // -- Volumes --
        if let Some(new_vols) = &update.volumes {
            if is_running {
                let pid = container.pid.unwrap_or(0);
                // Unmount removed volumes
                let old_targets: Vec<String> = container
                    .spec
                    .volumes
                    .iter()
                    .filter(|v| v.volume_type == sandbox::protocol::VolumeType::Filesystem)
                    .map(|v| v.target.clone())
                    .collect();
                for target in &old_targets {
                    if !new_vols.iter().any(|v| v.target == *target) {
                        if let Err(e) = sandbox::sys::hot_mount::hot_unmount(pid, target) {
                            tracing::warn!("failed to unmount volume at {target}: {e}");
                        }
                    }
                }
                // Mount new volumes
                if let Ok(pool) = self.storage.resolve_pool(container.spec.pool.as_deref()) {
                    for vol in new_vols {
                        if !container
                            .spec
                            .volumes
                            .iter()
                            .any(|v| v.target == vol.target)
                        {
                            let vol_path = storage::volume::volume_path(pool, &vol.name);
                            if let Err(e) = sandbox::sys::hot_mount::hot_bind_mount(
                                pid,
                                &vol_path,
                                &vol.target,
                                vol.readonly,
                            ) {
                                tracing::warn!("failed to mount volume {}: {e}", vol.target);
                            }
                        }
                    }
                }
            }
            container.spec.volumes = new_vols.clone();
        }

        // -- Publish ports --
        // Always update the spec. Port forwarding rules are set up at container
        // start and cleaned up at stop, so changes take effect on next restart.
        if let Some(new_publish) = &update.publish {
            container.spec.publish = new_publish.clone();
        }

        // If running, apply cgroup changes live
        if is_running {
            let cgroup_path = PathBuf::from("/sys/fs/cgroup/sandbox").join(name);
            if let Some(mem) = update.memory_max {
                if let Err(e) = sandbox::cgroup::memory::set_memory_max(&cgroup_path, mem) {
                    tracing::warn!("failed to apply live memory limit for {name}: {e}");
                }
            }
            if let Some((quota, period)) = update.cpu_max {
                if let Err(e) = sandbox::cgroup::cpu::set_cpu_max(&cgroup_path, quota, period) {
                    tracing::warn!("failed to apply live cpu limit for {name}: {e}");
                }
            }
            if let Some(pids) = update.pids_max {
                if let Err(e) = sandbox::cgroup::pids::set_pids_max(&cgroup_path, pids) {
                    tracing::warn!("failed to apply live pids limit for {name}: {e}");
                }
            }
        }

        // Persist the updated spec
        Self::persist_container(&self.state_dir, name, container);

        HandleResult::response_only(Response::ContainerUpdated {
            name: name.to_string(),
        })
    }

    // -- Snapshot / Restore --

    fn handle_snapshot_container(
        &self,
        name: &str,
        snapshot_name: Option<String>,
        exclude_volumes: bool,
    ) -> HandleResult {
        let container = match self.containers.get(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                });
            }
        };

        let pool = match self.storage.resolve_pool(container.spec.pool.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        let snap_name = snapshot_name.unwrap_or_else(storage::snapshot::generate_snapshot_name);

        // Snapshot rootfs
        if let Err(e) = storage::snapshot::snapshot_rootfs(pool, name, &snap_name) {
            return HandleResult::response_only(Response::Error {
                message: format!("rootfs snapshot failed: {e}"),
            });
        }

        // Snapshot volumes (filesystem type only)
        let mut snapped_volumes = Vec::new();
        if !exclude_volumes {
            for vol_mount in &container.spec.volumes {
                if vol_mount.volume_type == sandbox::protocol::VolumeType::Filesystem {
                    if let Err(e) =
                        storage::snapshot::snapshot_volume(pool, &vol_mount.name, name, &snap_name)
                    {
                        tracing::warn!("failed to snapshot volume '{}': {e}", vol_mount.name);
                    } else {
                        snapped_volumes.push(vol_mount.name.clone());
                    }
                }
            }
        }

        // Write manifest
        let manifest = storage::snapshot::SnapshotManifest {
            name: snap_name.clone(),
            timestamp: format!(
                "{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            ),
            container: name.to_string(),
            spec: container.spec.clone(),
            volumes: snapped_volumes,
            pool: pool.name.clone(),
        };

        if let Err(e) = storage::snapshot::write_manifest(pool, name, &snap_name, &manifest) {
            tracing::warn!("failed to write snapshot manifest: {e}");
        }

        HandleResult::response_only(Response::ContainerSnapshotted {
            name: name.to_string(),
            snapshot_name: snap_name,
        })
    }

    fn handle_restore_container(&mut self, name: &str, snapshot_name: &str) -> HandleResult {
        let container = match self.containers.get(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                });
            }
        };

        // Must be stopped
        if container.state.is_running() {
            return HandleResult::response_only(Response::Error {
                message: format!("container {name} is running — stop it before restoring"),
            });
        }

        let pool = match self.storage.resolve_pool(container.spec.pool.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        // Read manifest
        let manifest = match storage::snapshot::read_manifest(pool, name, snapshot_name) {
            Ok(m) => m,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("failed to read snapshot manifest: {e}"),
                });
            }
        };

        // Restore rootfs
        if let Err(e) = storage::snapshot::restore_rootfs(pool, name, snapshot_name) {
            return HandleResult::response_only(Response::Error {
                message: format!("rootfs restore failed: {e}"),
            });
        }

        // Restore volumes
        for vol_name in &manifest.volumes {
            if let Err(e) = storage::snapshot::restore_volume(pool, vol_name, name, snapshot_name) {
                tracing::warn!("failed to restore volume '{vol_name}': {e}");
            }
        }

        // Clean up old idmap mount and restore spec from manifest
        let container = self.containers.get_mut(name).unwrap();

        // Unmount and remove old idmap mount point
        if let Some(ref mount_path) = container.idmap_mount {
            let _ = nix::mount::umount2(mount_path, nix::mount::MntFlags::MNT_DETACH);
            let _ = std::fs::remove_dir(mount_path);
        }
        container.idmap_mount = None;

        container.spec = manifest.spec;
        Self::persist_container(&self.state_dir, name, container);

        HandleResult::response_only(Response::ContainerRestored {
            name: name.to_string(),
            snapshot_name: snapshot_name.to_string(),
        })
    }

    fn handle_list_container_snapshots(&self, name: &str, show_size: bool) -> HandleResult {
        let container = match self.containers.get(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                });
            }
        };

        let pool = match self.storage.resolve_pool(container.spec.pool.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        let snap_names = match storage::snapshot::list_snapshots(pool, name) {
            Ok(names) => names,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("failed to list snapshots: {e}"),
                });
            }
        };

        let mut snapshots = Vec::new();
        for sn in snap_names {
            let manifest = storage::snapshot::read_manifest(pool, name, &sn);
            let size_bytes = if show_size {
                storage::snapshot::snapshot_size(pool, name, &sn).ok()
            } else {
                None
            };
            snapshots.push(sandbox::protocol::SnapshotInfo {
                name: sn.clone(),
                timestamp: manifest
                    .as_ref()
                    .map(|m| m.timestamp.clone())
                    .unwrap_or_default(),
                container: name.to_string(),
                includes_volumes: manifest.as_ref().is_ok_and(|m| !m.volumes.is_empty()),
                size_bytes,
            });
        }

        HandleResult::response_only(Response::ContainerSnapshotList { snapshots })
    }

    fn handle_delete_container_snapshot(&self, name: &str, snapshot_name: &str) -> HandleResult {
        let container = match self.containers.get(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                });
            }
        };

        let pool = match self.storage.resolve_pool(container.spec.pool.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        if let Err(e) = storage::snapshot::delete_snapshot(pool, name, snapshot_name) {
            return HandleResult::response_only(Response::Error {
                message: format!("{e}"),
            });
        }

        HandleResult::response_only(Response::ContainerSnapshotDeleted {
            name: name.to_string(),
            snapshot_name: snapshot_name.to_string(),
        })
    }

    fn handle_stack_snapshot(
        &self,
        stack_name: &str,
        snapshot_name: Option<String>,
        exclude_volumes: bool,
    ) -> HandleResult {
        // Find all containers belonging to this stack
        let stack_containers: Vec<String> = self
            .containers
            .iter()
            .filter(|(_, c)| c.spec.name.starts_with(&format!("{stack_name}-")))
            .map(|(name, _)| name.clone())
            .collect();

        if stack_containers.is_empty() {
            return HandleResult::response_only(Response::Error {
                message: format!("no containers found for stack '{stack_name}'"),
            });
        }

        let snap_name = snapshot_name.unwrap_or_else(storage::snapshot::generate_snapshot_name);

        // Snapshot each container
        for container_name in &stack_containers {
            let container = self.containers.get(container_name).unwrap();
            let pool = match self.storage.resolve_pool(container.spec.pool.as_deref()) {
                Ok(p) => p,
                Err(e) => {
                    return HandleResult::response_only(Response::Error {
                        message: format!("pool error for {container_name}: {e}"),
                    });
                }
            };

            // Snapshot rootfs
            if let Err(e) = storage::snapshot::snapshot_rootfs(pool, container_name, &snap_name) {
                return HandleResult::response_only(Response::Error {
                    message: format!("rootfs snapshot failed for {container_name}: {e}"),
                });
            }

            // Snapshot volumes
            if !exclude_volumes {
                for vol_mount in &container.spec.volumes {
                    if vol_mount.volume_type == sandbox::protocol::VolumeType::Filesystem {
                        if let Err(e) = storage::snapshot::snapshot_volume(
                            pool,
                            &vol_mount.name,
                            container_name,
                            &snap_name,
                        ) {
                            tracing::warn!(
                                "failed to snapshot volume '{}' for {container_name}: {e}",
                                vol_mount.name
                            );
                        }
                    }
                }
            }

            // Write per-container manifest
            let snapped_vols: Vec<String> = if exclude_volumes {
                Vec::new()
            } else {
                container
                    .spec
                    .volumes
                    .iter()
                    .filter(|v| v.volume_type == sandbox::protocol::VolumeType::Filesystem)
                    .map(|v| v.name.clone())
                    .collect()
            };

            let manifest = storage::snapshot::SnapshotManifest {
                name: snap_name.clone(),
                timestamp: format!(
                    "{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                ),
                container: container_name.clone(),
                spec: container.spec.clone(),
                volumes: snapped_vols,
                pool: pool.name.clone(),
            };

            if let Err(e) =
                storage::snapshot::write_manifest(pool, container_name, &snap_name, &manifest)
            {
                tracing::warn!("failed to write manifest for {container_name}: {e}");
            }
        }

        HandleResult::response_only(Response::StackSnapshotted {
            stack_name: stack_name.to_string(),
            snapshot_name: snap_name,
        })
    }

    fn handle_stack_restore(&mut self, stack_name: &str, snapshot_name: &str) -> HandleResult {
        // Find all stack containers
        let stack_containers: Vec<String> = self
            .containers
            .iter()
            .filter(|(_, c)| c.spec.name.starts_with(&format!("{stack_name}-")))
            .map(|(name, _)| name.clone())
            .collect();

        if stack_containers.is_empty() {
            return HandleResult::response_only(Response::Error {
                message: format!("no containers found for stack '{stack_name}'"),
            });
        }

        // All must be stopped
        for container_name in &stack_containers {
            let container = self.containers.get(container_name).unwrap();
            if container.state.is_running() {
                return HandleResult::response_only(Response::Error {
                    message: format!(
                        "container {container_name} is running — stop the stack before restoring"
                    ),
                });
            }
        }

        // Restore each container
        for container_name in &stack_containers {
            let result = self.handle_restore_container(container_name, snapshot_name);
            if let Response::Error { message } = &result.response {
                return HandleResult::response_only(Response::Error {
                    message: format!("failed to restore {container_name}: {message}"),
                });
            }
        }

        HandleResult::response_only(Response::StackRestored {
            stack_name: stack_name.to_string(),
            snapshot_name: snapshot_name.to_string(),
        })
    }

    fn handle_stack_snapshots(&self, stack_name: &str, show_size: bool) -> HandleResult {
        // Find one container from the stack to determine the pool
        let container = match self
            .containers
            .iter()
            .find(|(_, c)| c.spec.name.starts_with(&format!("{stack_name}-")))
        {
            Some((_, c)) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("no containers found for stack '{stack_name}'"),
                });
            }
        };

        let pool = match self.storage.resolve_pool(container.spec.pool.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        // Collect unique snapshot names across all stack containers
        let mut all_snaps = std::collections::BTreeSet::new();
        for (cname, c) in &self.containers {
            if c.spec.name.starts_with(&format!("{stack_name}-")) {
                if let Ok(names) = storage::snapshot::list_snapshots(pool, cname) {
                    for n in names {
                        all_snaps.insert(n);
                    }
                }
            }
        }

        let stack_containers: Vec<String> = self
            .containers
            .iter()
            .filter(|(_, c)| c.spec.name.starts_with(&format!("{stack_name}-")))
            .map(|(name, _)| name.clone())
            .collect();

        let snapshots = all_snaps
            .into_iter()
            .map(|sn| {
                let size_bytes = if show_size {
                    // Sum sizes across all stack containers for this snapshot
                    let mut total = 0u64;
                    for cname in &stack_containers {
                        if let Ok(s) = storage::snapshot::snapshot_size(pool, cname, &sn) {
                            total += s;
                        }
                    }
                    Some(total)
                } else {
                    None
                };
                sandbox::protocol::StackSnapshotInfo {
                    name: sn,
                    timestamp: String::new(),
                    containers: stack_containers.clone(),
                    includes_volumes: true,
                    size_bytes,
                }
            })
            .collect();

        HandleResult::response_only(Response::StackSnapshotList { snapshots })
    }

    #[tracing::instrument(skip_all, level = "debug", fields(name = %spec.name))]
    fn handle_run(&mut self, mut spec: ContainerSpec) -> HandleResult {
        let name = spec.name.clone();

        if self.containers.contains_key(&name) {
            return HandleResult::response_only(Response::Error {
                message: format!("container {name} already exists"),
            });
        }

        Self::apply_implicit_init(&mut spec);
        self.apply_image_config(&mut spec);

        // Validate and set up bridged networking (IPAM, NAT, port forwarding)
        if let Err(e) = Self::validate_publish(&spec) {
            return HandleResult::response_only(Response::Error {
                message: format!("{e}"),
            });
        }
        if let Err(e) = self.setup_bridged_networking(&mut spec) {
            return HandleResult::response_only(Response::Error {
                message: format!("network setup failed: {e}"),
            });
        }

        // Resolve volumes (block volumes returned for device setup during start)
        let block_vols = match self.resolve_volumes(&mut spec) {
            Ok(bv) => bv,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        let mut container = Container::new(spec);
        container.ephemeral = true;
        self.populate_block_volumes(&mut container, &block_vols);

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
                Self::persist_container(&self.state_dir, &name, &container);
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

        // Allow re-starting a stopped container
        if container.state.is_stopped() {
            let _ = container.state.reset();
            container.manually_stopped = false;
        }

        if let Some(cmd) = command {
            container.spec.command = cmd;
        }

        // Re-create idmap mount if needed (e.g., after daemon restart recovery)
        if container.idmap_mount.is_none() {
            if let Err(e) = Self::ensure_idmap_mount(container, &self.mounts_dir) {
                return HandleResult::response_only(Response::Error {
                    message: format!("failed to set up idmap mount: {e}"),
                });
            }
        }

        match container.start() {
            Ok(()) => {
                let pid = container.pid.unwrap_or(0) as u32;
                let pty_master = container.take_pty_master();
                Self::persist_container(&self.state_dir, name, container);
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

        let source_path = std::path::Path::new(source);
        if !source_path.exists() {
            return HandleResult::response_only(Response::Error {
                message: format!("source path does not exist: {source}"),
            });
        }

        // If running, perform the hot bind mount immediately
        if container.state.is_running() {
            let pid = match container.pid {
                Some(p) => p,
                None => {
                    return HandleResult::response_only(Response::Error {
                        message: "container has no PID".to_string(),
                    });
                }
            };
            if let Err(e) =
                sandbox::sys::hot_mount::hot_bind_mount(pid, source_path, target, readonly)
            {
                return HandleResult::response_only(Response::Error {
                    message: format!("mount failed: {e}"),
                });
            }
        }

        // Add to bind_mounts (takes effect on next start if stopped)
        container
            .spec
            .bind_mounts
            .push(sandbox::protocol::BindMount {
                source: source.to_string(),
                target: target.to_string(),
                readonly,
            });

        // Persist updated state
        Self::persist_container(&self.state_dir, name, container);

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

        // If running, perform the hot unmount in the container's namespaces
        if container.state.is_running() {
            let pid = match container.pid {
                Some(p) => p,
                None => {
                    return HandleResult::response_only(Response::Error {
                        message: "container has no PID".to_string(),
                    });
                }
            };
            if let Err(e) = sandbox::sys::hot_mount::hot_unmount(pid, target) {
                return HandleResult::response_only(Response::Error {
                    message: format!("unmount failed: {e}"),
                });
            }
        }

        // Remove from bind_mounts (takes effect on next start if stopped)
        container.spec.bind_mounts.remove(idx.unwrap());

        // Persist updated state
        Self::persist_container(&self.state_dir, name, container);

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

    fn handle_mount_block(
        &mut self,
        container_name: &str,
        device: &str,
        target: &str,
        fs_type: &str,
        options: Option<&str>,
    ) -> HandleResult {
        let container = match self.containers.get(container_name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {container_name} not found"),
                });
            }
        };
        if !container.state.is_running() {
            return HandleResult::response_only(Response::Error {
                message: format!("container {container_name} is not running"),
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

        // Find host device path from tracked block volumes
        let host_device = container
            .block_volumes
            .iter()
            .find(|bv| bv.container_device.as_deref() == Some(device))
            .map(|bv| bv.host_device.clone());
        let host_device = match host_device {
            Some(d) => d,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!(
                        "block device '{device}' not found in container \
                         (attach it with --volume name:{device})"
                    ),
                });
            }
        };

        let mount_dir = PathBuf::from("/run/sandbox/block-mounts")
            .join(container_name)
            .join(target.trim_start_matches('/'));

        if let Err(e) = sandbox::sys::hot_mount::hot_block_mount(
            pid,
            &host_device,
            target,
            fs_type,
            options,
            &mount_dir,
        ) {
            return HandleResult::response_only(Response::Error {
                message: format!("block mount failed: {e}"),
            });
        }

        // Update tracked state
        let container = self.containers.get_mut(container_name).unwrap();
        if let Some(bv) = container
            .block_volumes
            .iter_mut()
            .find(|bv| bv.container_device.as_deref() == Some(device))
        {
            bv.container_mount = Some(target.to_string());
            bv.host_mount = Some(mount_dir.to_string_lossy().to_string());
        }
        Self::persist_container(&self.state_dir, container_name, container);

        HandleResult::response_only(Response::BlockMounted {
            target: target.to_string(),
        })
    }

    fn handle_snapshot(
        &self,
        name: &str,
        image_name: &str,
        force: bool,
        update: bool,
    ) -> HandleResult {
        let container = match self.containers.get(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                });
            }
        };

        let pool = match self.storage.resolve_pool(container.spec.pool.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        // Safety check: non-CoW filesystem + running container
        if container.state.is_running() && !pool.fs_type.supports_snapshots() && !force {
            return HandleResult::response_only(Response::Error {
                message: format!(
                    "container {name} is running on non-CoW filesystem ({}); \
                     snapshot may be inconsistent. Use --force to override.",
                    pool.fs_type
                ),
            });
        }

        let container_rootfs = match &container.rootfs_path {
            Some(p) => p.clone(),
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} has no rootfs"),
                });
            }
        };

        // Check if this is an update to an existing image
        let existing_meta = storage::layers::load_image_meta(pool, image_name);

        if existing_meta.is_some() && !update {
            return HandleResult::response_only(Response::Error {
                message: format!("image '{image_name}' already exists (use --update to overwrite)"),
            });
        }

        // Create or update layer metadata
        let image_meta = if let Some(ref existing) = existing_meta {
            // Update: add a new layer on top of the existing image
            match storage::layers::update_snapshot_layer(
                pool,
                name,
                image_name,
                &container_rootfs,
                existing,
            ) {
                Ok(meta) => meta,
                Err(e) => {
                    return HandleResult::response_only(Response::Error {
                        message: format!("snapshot layer creation failed: {e}"),
                    });
                }
            }
        } else {
            // First snapshot: create initial layer, continuing chain from source image if possible
            let source_meta = storage::layers::load_image_meta(pool, &container.spec.image);
            match storage::layers::create_snapshot_layer(
                pool,
                name,
                image_name,
                &container_rootfs,
                source_meta.as_ref(),
            ) {
                Ok(meta) => meta,
                Err(e) => {
                    return HandleResult::response_only(Response::Error {
                        message: format!("snapshot layer creation failed: {e}"),
                    });
                }
            }
        };

        // Snapshot the container rootfs as the image (create or replace)
        if let Err(e) =
            storage::container_fs::snapshot_container_to_image(pool, name, image_name, update)
        {
            return HandleResult::response_only(Response::Error {
                message: format!("snapshot failed: {e}"),
            });
        }

        // Write image metadata
        if let Err(e) = storage::layers::write_image_meta_pub(pool, image_name, &image_meta) {
            tracing::warn!("failed to write image metadata: {e}");
        }

        HandleResult::response_only(Response::Snapshotted {
            image_name: image_name.to_string(),
        })
    }

    fn handle_stack_up(&mut self, def: sandbox::protocol::StackDefinition) -> HandleResult {
        if self.stacks.contains_key(&def.name) {
            return HandleResult::response_only(Response::Error {
                message: format!("stack '{}' already running", def.name),
            });
        }

        let stack_name = def.name.clone();

        // Create or reference a named network for the stack
        let network_name = if !def.network.subnet.is_empty() || def.network.bridge.is_empty() {
            // Auto-create a network for this stack
            let net_name = format!("stack-{stack_name}");
            let subnet = if def.network.subnet.is_empty() {
                None
            } else {
                Some(def.network.subnet.as_str())
            };
            let result = self.handle_network_create(&net_name, subnet);
            if let Response::Error { message } = &result.response {
                // Might already exist from a previous run
                if !message.contains("already exists") {
                    return result;
                }
            }
            net_name
        } else {
            // Use existing named network
            def.network.bridge.clone()
        };

        let bridge_name = self
            .networks
            .get(&network_name)
            .map(|n| n.bridge.clone())
            .unwrap_or_else(|| {
                let mut b = format!("sbr-{stack_name}");
                b.truncate(15);
                b
            });

        // Create volumes (prefixed with stack name)
        let mut volume_names: Vec<String> = Vec::new();
        for vol in &def.volumes {
            let prefixed = format!("{stack_name}-{vol}");
            if let Err(e) = self.handle_volume_create_inner(&prefixed, None) {
                // Clean up already-created volumes
                for v in &volume_names {
                    let _ = self.handle_volume_remove_inner(v, None);
                }
                return HandleResult::response_only(Response::Error {
                    message: format!("failed to create volume {prefixed}: {e}"),
                });
            }
            volume_names.push(prefixed);
        }

        // Create containers
        let mut container_names = Vec::new();
        for svc in &def.containers {
            let container_name = format!("{stack_name}-{}", svc.name);

            // Build ContainerSpec
            let mut spec = sandbox::protocol::ContainerSpec {
                name: container_name.clone(),
                image: svc.image.clone(),
                command: if svc.command.is_empty() {
                    vec!["/bin/sh".to_string()]
                } else {
                    svc.command.clone()
                },
                entrypoint: svc.entrypoint.clone(),
                env: svc.env.clone(),
                working_dir: if svc.working_dir.is_empty() {
                    "/".to_string()
                } else {
                    svc.working_dir.clone()
                },
                hostname: if svc.hostname.is_empty() {
                    None
                } else {
                    Some(svc.hostname.clone())
                },
                network: sandbox::protocol::NetworkMode::Named {
                    name: network_name.clone(),
                },
                cgroup: sandbox::protocol::CgroupSpec {
                    memory_max: if svc.memory.is_empty() {
                        None
                    } else {
                        sandbox::stack::parse_memory_size(&svc.memory).ok()
                    },
                    cpu_max: if svc.cpus.is_empty() {
                        None
                    } else {
                        sandbox::stack::parse_cpu_limit(&svc.cpus).ok()
                    },
                    pids_max: svc.pids,
                    ..Default::default()
                },
                use_init: svc.init,
                detach: true, // stacks run detached
                restart_policy: {
                    // Per-service restart overrides stack-level, which overrides default
                    let restart_str = if svc.restart.is_empty() {
                        if def.restart.is_empty() {
                            "unless-stopped"
                        } else {
                            &def.restart
                        }
                    } else {
                        &svc.restart
                    };
                    sandbox::protocol::RestartPolicy::parse(restart_str)
                        .unwrap_or(sandbox::protocol::RestartPolicy::UnlessStopped)
                },
                no_new_privs: !svc.allow_new_privs,
                ..Default::default()
            };

            // Resolve volume mounts (prefix volume names with stack name)
            for v in &svc.volumes {
                let parts: Vec<&str> = v.splitn(3, ':').collect();
                if parts.len() >= 2 {
                    let vol_name = format!("{stack_name}-{}", parts[0]);
                    let target = parts[1].to_string();
                    let readonly = parts.get(2).is_some_and(|&s| s == "ro");
                    spec.volumes.push(sandbox::protocol::VolumeMount {
                        name: vol_name,
                        target,
                        readonly,
                        volume_type: sandbox::protocol::VolumeType::default(),
                    });
                }
            }

            // Parse bind mounts
            for b in &svc.bind {
                if let Ok((source, target, readonly)) = sandbox::stack::parse_bind_spec(b) {
                    spec.bind_mounts.push(sandbox::protocol::BindMount {
                        source,
                        target,
                        readonly,
                    });
                }
            }

            // Parse port mappings
            for p in &svc.publish {
                if let Ok(pm) = sandbox::stack::parse_port_spec(p) {
                    spec.publish.push(pm);
                }
            }

            // Apply image config
            self.apply_image_config(&mut spec);

            // Validate and set up networking
            if let Err(e) = Self::validate_publish(&spec) {
                self.cleanup_stack_partial(&container_names, &volume_names, &bridge_name);
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
            if let Err(e) = self.setup_bridged_networking(&mut spec) {
                self.cleanup_stack_partial(&container_names, &volume_names, &bridge_name);
                return HandleResult::response_only(Response::Error {
                    message: format!("network setup for {}: {e}", svc.name),
                });
            }

            // Resolve volumes (block volumes not supported in stacks yet)
            let _block_vols = match self.resolve_volumes(&mut spec) {
                Ok(bv) => bv,
                Err(e) => {
                    self.cleanup_stack_partial(&container_names, &volume_names, &bridge_name);
                    return HandleResult::response_only(Response::Error {
                        message: format!("volume setup for {}: {e}", svc.name),
                    });
                }
            };

            // Create + start the container
            let mut container = Container::new(spec);
            container.ephemeral = false; // stack containers are non-ephemeral

            if let Err(e) = self.prepare_container_rootfs(&mut container) {
                self.cleanup_stack_partial(&container_names, &volume_names, &bridge_name);
                return HandleResult::response_only(Response::Error {
                    message: format!("rootfs for {}: {e}", svc.name),
                });
            }

            match container.start() {
                Ok(()) => {
                    Self::persist_container(&self.state_dir, &container_name, &container);
                    self.containers.insert(container_name.clone(), container);
                    container_names.push(container_name);
                }
                Err(e) => {
                    let _ = container.destroy();
                    self.cleanup_stack_partial(&container_names, &volume_names, &bridge_name);
                    return HandleResult::response_only(Response::Error {
                        message: format!("start {}: {e}", svc.name),
                    });
                }
            }
        }

        // Build DNS name→IP map for inter-container resolution
        let mut dns_names: HashMap<String, std::net::Ipv4Addr> = HashMap::new();
        for svc in &def.containers {
            let container_name = format!("{stack_name}-{}", svc.name);
            if let Some(container) = self.containers.get(&container_name)
                && let sandbox::protocol::NetworkMode::Bridged {
                    address: Some(ip), ..
                } = &container.spec.network
            {
                dns_names.insert(svc.name.clone(), *ip);
                dns_names.insert(container_name.clone(), *ip);
            }
        }

        // Start DNS responder on the gateway IP
        let dns_shutdown = if let Some(net_config) = self.networks.get(&network_name) {
            let gateway = net_config.gateway;
            let listen_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(gateway), 53);
            let upstream = sandbox::net::dns::parse_upstream_dns().unwrap_or_else(|| {
                std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                    53,
                )
            });

            let (tx, rx) = smol::channel::bounded::<()>(1);
            smol::spawn(sandbox::net::dns::run_dns_responder(
                listen_addr,
                dns_names,
                upstream,
                rx,
            ))
            .detach();

            // Write resolv.conf pointing to the gateway for each container
            for cname in &container_names {
                if let Some(container) = self.containers.get(cname) {
                    if let Some(pid) = container.pid {
                        let resolv_content = format!("nameserver {gateway}\n");
                        let resolv_path = self
                            .mounts_dir
                            .parent()
                            .unwrap_or(&self.mounts_dir)
                            .join(format!("resolv-{}.conf", cname));
                        let _ = std::fs::write(&resolv_path, resolv_content);
                        // Hot-mount the generated resolv.conf into the container
                        let _ = sandbox::sys::hot_mount::hot_bind_mount(
                            pid,
                            &resolv_path,
                            "/etc/resolv.conf",
                            false,
                        );
                    }
                }
            }

            Some(tx)
        } else {
            None
        };

        // Track the stack
        self.stacks.insert(
            stack_name.clone(),
            StackState {
                name: stack_name.clone(),
                bridge: bridge_name,
                network_name: network_name.clone(),
                containers: container_names.clone(),
                volumes: volume_names,
                dns_shutdown,
            },
        );

        tracing::info!(
            "stack '{}' up: {} container(s)",
            stack_name,
            container_names.len()
        );

        HandleResult::response_only(Response::StackUp {
            name: stack_name,
            containers: container_names,
        })
    }

    fn handle_stack_down(&mut self, name: &str) -> HandleResult {
        let stack = match self.stacks.remove(name) {
            Some(s) => s,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("stack '{name}' not found"),
                });
            }
        };

        // Stop the DNS responder
        if let Some(tx) = stack.dns_shutdown {
            let _ = tx.try_send(());
        }

        // Clean up generated resolv.conf files
        for cname in &stack.containers {
            let resolv_path = self
                .mounts_dir
                .parent()
                .unwrap_or(&self.mounts_dir)
                .join(format!("resolv-{cname}.conf"));
            let _ = std::fs::remove_file(resolv_path);
        }

        // Stop and destroy all containers
        for cname in &stack.containers {
            if let Some(container) = self.containers.get(cname) {
                if container.state.is_running() {
                    if let Some(pid) = container.pid {
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(pid),
                            nix::sys::signal::Signal::SIGTERM,
                        );
                    }
                }
            }
        }

        // Brief wait for SIGTERM
        std::thread::sleep(std::time::Duration::from_millis(500));

        for cname in &stack.containers {
            self.handle_container_exit(cname);
            if let Some(mut c) = self.containers.remove(cname) {
                self.cleanup_bridged_networking(&c.spec.clone());
                persist::remove_state(&self.state_dir, cname);
                let _ = c.destroy();
                // Defer rootfs cleanup
                if let Some(pool_name) = &c.pool_name {
                    if let Some(pool) = self.storage.pool(pool_name) {
                        let container_path = pool.container_path(cname);
                        let fs_type = pool.fs_type.clone();
                        self.spawn_deferred_cleanup(container_path, fs_type, cname.clone());
                    }
                }
            }
        }

        // Remove volumes
        for vol in &stack.volumes {
            let _ = self.handle_volume_remove_inner(vol, None);
        }

        // Remove the stack's network (if it was auto-created)
        let net_name = format!("stack-{name}");
        if self.networks.contains_key(&net_name) {
            let _ = self.handle_network_remove(&net_name);
        }

        tracing::info!("stack '{}' down", name);

        HandleResult::response_only(Response::StackDown {
            name: name.to_string(),
        })
    }

    fn handle_stack_ps(&self, name: &str) -> HandleResult {
        let stack = match self.stacks.get(name) {
            Some(s) => s,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("stack '{name}' not found"),
                });
            }
        };

        let infos: Vec<sandbox::protocol::ContainerInfo> = stack
            .containers
            .iter()
            .filter_map(|cname| {
                self.containers
                    .get(cname)
                    .map(|c| sandbox::protocol::ContainerInfo {
                        name: cname.clone(),
                        state: c.state.current().clone(),
                        pid: c.pid.map(|p| p as u32),
                    })
            })
            .collect();

        HandleResult::response_only(Response::StackPs(infos))
    }

    fn handle_stack_list(&self) -> HandleResult {
        let stacks: Vec<sandbox::protocol::StackInfo> = self
            .stacks
            .values()
            .map(|s| sandbox::protocol::StackInfo {
                name: s.name.clone(),
                containers: s.containers.clone(),
                bridge: s.bridge.clone(),
            })
            .collect();
        HandleResult::response_only(Response::StackList(stacks))
    }

    /// Clean up a partially created stack (on error during stack up).
    fn cleanup_stack_partial(&mut self, containers: &[String], volumes: &[String], _bridge: &str) {
        for cname in containers {
            if let Some(mut c) = self.containers.remove(cname) {
                self.cleanup_bridged_networking(&c.spec.clone());
                persist::remove_state(&self.state_dir, cname);
                let _ = c.destroy();
            }
        }
        for vol in volumes {
            let _ = self.handle_volume_remove_inner(vol, None);
        }
    }

    fn handle_network_create(&mut self, name: &str, subnet: Option<&str>) -> HandleResult {
        if self.networks.contains_key(name) {
            return HandleResult::response_only(Response::Error {
                message: format!("network '{name}' already exists"),
            });
        }

        if !self.nft_available {
            return HandleResult::response_only(Response::Error {
                message: "bridged networking requires nftables (nft)".to_string(),
            });
        }

        // Parse or auto-allocate subnet
        let (subnet_addr, prefix_len) = if let Some(s) = subnet {
            match parse_subnet(s) {
                Ok(v) => v,
                Err(e) => {
                    return HandleResult::response_only(Response::Error { message: e });
                }
            }
        } else {
            let idx = self.next_subnet_idx;
            self.next_subnet_idx = self.next_subnet_idx.wrapping_add(1);
            (std::net::Ipv4Addr::new(10, 0, idx, 0), 24u8)
        };

        let gateway = std::net::Ipv4Addr::from(u32::from(subnet_addr) + 1);

        // Bridge name (truncate to 15 chars)
        let mut bridge = format!("sbr-{name}");
        bridge.truncate(15);

        // Create bridge + NAT
        if let Err(e) = sandbox::net::bridge::ensure_bridge(&bridge, gateway, prefix_len) {
            return HandleResult::response_only(Response::Error {
                message: format!("bridge creation failed: {e}"),
            });
        }

        let subnet_str = format!("{subnet_addr}/{prefix_len}");
        if let Err(e) = sandbox::net::nat::setup_masquerade(&bridge, &subnet_str) {
            return HandleResult::response_only(Response::Error {
                message: format!("NAT setup failed: {e}"),
            });
        }

        // Create IPAM for this network
        let allocator =
            sandbox::net::ipam::IpAllocator::new(subnet_addr, prefix_len, &bridge, &self.ipam_dir);
        let _ = allocator.save();
        self.ipam.insert(bridge.clone(), allocator);
        *self.bridge_refcounts.entry(bridge.clone()).or_insert(0) += 0; // just register

        // Persist network config
        let config = NetworkConfig {
            name: name.to_string(),
            bridge: bridge.clone(),
            subnet: subnet_addr,
            gateway,
            prefix_len,
        };
        self.save_network_config(&config);
        self.networks.insert(name.to_string(), config);

        tracing::info!("created network '{name}' (bridge: {bridge}, subnet: {subnet_str})");

        HandleResult::response_only(Response::NetworkCreated {
            name: name.to_string(),
        })
    }

    fn handle_network_remove(&mut self, name: &str) -> HandleResult {
        let config = match self.networks.get(name) {
            Some(c) => c.clone(),
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("network '{name}' not found"),
                });
            }
        };

        // Check if any containers are using this network's bridge
        let in_use = self.containers.values().any(|c| {
            matches!(&c.spec.network, sandbox::protocol::NetworkMode::Bridged { bridge, .. } if bridge == &config.bridge)
        });
        if in_use {
            return HandleResult::response_only(Response::Error {
                message: format!("network '{name}' is in use by containers"),
            });
        }

        // Clean up bridge + NAT + IPAM
        let _ = sandbox::net::bridge::delete_bridge(&config.bridge);
        sandbox::net::nat::cleanup_nat();
        self.ipam.remove(&config.bridge);
        self.bridge_refcounts.remove(&config.bridge);
        self.networks.remove(name);
        self.remove_network_config(name);

        tracing::info!("removed network '{name}'");

        HandleResult::response_only(Response::NetworkRemoved {
            name: name.to_string(),
        })
    }

    fn handle_network_list(&self) -> HandleResult {
        let infos: Vec<sandbox::protocol::NetworkInfo> = self
            .networks
            .values()
            .map(|n| {
                let containers = self
                    .containers
                    .values()
                    .filter(|c| {
                        matches!(&c.spec.network, sandbox::protocol::NetworkMode::Bridged { bridge, .. } if bridge == &n.bridge)
                    })
                    .count() as u32;
                sandbox::protocol::NetworkInfo {
                    name: n.name.clone(),
                    bridge: n.bridge.clone(),
                    subnet: format!("{}/{}", n.subnet, n.prefix_len),
                    gateway: n.gateway.to_string(),
                    containers,
                }
            })
            .collect();
        HandleResult::response_only(Response::NetworkList(infos))
    }

    fn save_network_config(&self, config: &NetworkConfig) {
        let dir = self
            .state_dir
            .parent()
            .unwrap_or(&self.state_dir)
            .join("networks");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("{}.json", config.name));
        if let Ok(json) = serde_json::to_string(config) {
            let _ = std::fs::write(path, json);
        }
    }

    fn remove_network_config(&self, name: &str) {
        let dir = self
            .state_dir
            .parent()
            .unwrap_or(&self.state_dir)
            .join("networks");
        let _ = std::fs::remove_file(dir.join(format!("{name}.json")));
    }

    fn load_network_configs(&mut self) {
        let dir = self
            .state_dir
            .parent()
            .unwrap_or(&self.state_dir)
            .join("networks");
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if let Ok(json) = std::fs::read_to_string(entry.path()) {
                    if let Ok(config) = serde_json::from_str::<NetworkConfig>(&json) {
                        self.networks.insert(config.name.clone(), config);
                    }
                }
            }
        }
    }

    /// Internal volume create (doesn't produce HandleResult).
    fn handle_volume_create_inner(&self, name: &str, pool: Option<&str>) -> Result<()> {
        let pool = self.storage.resolve_pool(pool)?;
        storage::volume::ensure_volumes_dir(pool)?;
        storage::volume::create_volume(pool, name)
    }

    /// Internal volume remove (doesn't produce HandleResult).
    fn handle_volume_remove_inner(&self, name: &str, pool: Option<&str>) -> Result<()> {
        let pool = match self.storage.resolve_pool(pool) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };
        let _ = storage::volume::remove_volume(pool, name);
        Ok(())
    }

    fn handle_volume_create(
        &self,
        name: &str,
        pool: Option<&str>,
        volume_type: sandbox::protocol::VolumeType,
        size: Option<u64>,
        format: Option<String>,
    ) -> HandleResult {
        let pool = match self.storage.resolve_pool(pool) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };
        if let Err(e) = storage::volume::ensure_volumes_dir(pool) {
            return HandleResult::response_only(Response::Error {
                message: format!("{e}"),
            });
        }
        let result = match volume_type {
            sandbox::protocol::VolumeType::Filesystem => storage::volume::create_volume(pool, name),
            sandbox::protocol::VolumeType::Block => {
                let sz = size.unwrap_or(1024 * 1024 * 1024);
                storage::volume::create_block_volume(pool, name, sz, format.as_deref())
            }
        };
        match result {
            Ok(()) => HandleResult::response_only(Response::VolumeCreated {
                name: name.to_string(),
            }),
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("{e}"),
            }),
        }
    }

    fn handle_volume_remove(&self, name: &str, pool: Option<&str>) -> HandleResult {
        let pool = match self.storage.resolve_pool(pool) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        // Check if any container is using this volume
        for (cname, container) in &self.containers {
            if container.spec.volumes.iter().any(|v| v.name == name) {
                return HandleResult::response_only(Response::Error {
                    message: format!("volume '{name}' is in use by container '{cname}'"),
                });
            }
        }

        let result = if storage::volume::is_block_volume(pool, name) {
            storage::volume::remove_block_volume(pool, name)
        } else {
            storage::volume::remove_volume(pool, name)
        };
        match result {
            Ok(()) => HandleResult::response_only(Response::VolumeRemoved {
                name: name.to_string(),
            }),
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("{e}"),
            }),
        }
    }

    fn handle_volume_list(&self, pool: Option<&str>) -> HandleResult {
        let pool = match self.storage.resolve_pool(pool) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        match storage::volume::list_volumes(pool) {
            Ok(volumes) => HandleResult::response_only(Response::VolumeList(volumes)),
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("{e}"),
            }),
        }
    }

    fn handle_volume_attach(
        &mut self,
        container_name: &str,
        volume_name: &str,
        target: &str,
        readonly: bool,
    ) -> HandleResult {
        // Resolve the volume path
        let container = match self.containers.get(container_name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {container_name} not found"),
                });
            }
        };

        if !container.state.is_running() {
            return HandleResult::response_only(Response::Error {
                message: format!("container {container_name} is not running"),
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

        let pool = match self.storage.resolve_pool(container.spec.pool.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        let vol_path = storage::volume::volume_path(pool, volume_name);
        if !vol_path.is_dir() {
            return HandleResult::response_only(Response::Error {
                message: format!("volume '{volume_name}' not found"),
            });
        }

        // Mount via hot_bind_mount
        if let Err(e) = sandbox::sys::hot_mount::hot_bind_mount(pid, &vol_path, target, readonly) {
            return HandleResult::response_only(Response::Error {
                message: format!("volume attach failed: {e}"),
            });
        }

        // Track the volume mount
        let container = self.containers.get_mut(container_name).unwrap();
        container.spec.volumes.push(sandbox::protocol::VolumeMount {
            name: volume_name.to_string(),
            target: target.to_string(),
            readonly,
            volume_type: sandbox::protocol::VolumeType::default(),
        });
        Self::persist_container(&self.state_dir, container_name, container);

        HandleResult::response_only(Response::VolumeAttached {
            target: target.to_string(),
        })
    }

    fn handle_volume_detach(&mut self, container_name: &str, target: &str) -> HandleResult {
        let container = match self.containers.get(container_name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {container_name} not found"),
                });
            }
        };

        if !container.state.is_running() {
            return HandleResult::response_only(Response::Error {
                message: format!("container {container_name} is not running"),
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

        // Check volume exists in spec
        if !container.spec.volumes.iter().any(|v| v.target == target) {
            return HandleResult::response_only(Response::Error {
                message: format!("no volume mounted at {target}"),
            });
        }

        // Unmount
        if let Err(e) = sandbox::sys::hot_mount::hot_unmount(pid, target) {
            return HandleResult::response_only(Response::Error {
                message: format!("volume detach failed: {e}"),
            });
        }

        // Remove from tracking
        let container = self.containers.get_mut(container_name).unwrap();
        container.spec.volumes.retain(|v| v.target != target);
        Self::persist_container(&self.state_dir, container_name, container);

        HandleResult::response_only(Response::VolumeDetached {
            target: target.to_string(),
        })
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

        // Clean up networking
        self.cleanup_bridged_networking(&container.spec.clone());

        // Clean up block volume mounts and loop devices
        Self::cleanup_block_volumes(&mut container.block_volumes);

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
                persist::remove_state(&self.state_dir, name);
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

    fn handle_inspect(&self, name: &str) -> HandleResult {
        let container = match self.containers.get(name) {
            Some(c) => c,
            None => {
                return HandleResult::response_only(Response::Error {
                    message: format!("container {name} not found"),
                });
            }
        };

        let detail = ContainerDetail {
            name: container.spec.name.clone(),
            image: container.spec.image.clone(),
            pool: container
                .pool_name
                .clone()
                .or_else(|| container.spec.pool.clone())
                .unwrap_or_else(|| "main".to_string()),
            state: container.state.current().clone(),
            pid: container.pid.map(|p| p as u32),
            ephemeral: container.ephemeral,
            user: container.spec.user.clone(),
            command: container.spec.command.clone(),
            entrypoint: container.spec.entrypoint.clone(),
            env: container.spec.env.clone(),
            working_dir: container.spec.working_dir.clone(),
            hostname: container.spec.hostname.clone(),
            use_init: container.spec.use_init,
            network: container.spec.network.clone(),
            bind_mounts: container.spec.bind_mounts.clone(),
            volumes: container.spec.volumes.clone(),
            publish: container.spec.publish.clone(),
            cgroup: container.spec.cgroup.clone(),
            seccomp: container.spec.seccomp.clone(),
            restart_policy: container.spec.restart_policy.clone(),
            no_new_privs: container.spec.no_new_privs,
            rootfs_path: container
                .rootfs_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            cgroup_path: format!("/sys/fs/cgroup/sandbox/{name}"),
        };

        HandleResult::response_only(Response::ContainerInspect(Box::new(detail)))
    }

    fn handle_exec(
        &mut self,
        name: &str,
        command: Vec<String>,
        detach: bool,
        piped: bool,
        user: Option<sandbox::protocol::ExecUser>,
        exec_env: Vec<String>,
    ) -> HandleResult {
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

        // Merge: container env is the base, per-exec env overrides per-key
        let env = merge_env(&container.spec.env, &exec_env);
        match exec_in_container(pid, name, &command, detach, piped, user, &env) {
            Ok(result) => {
                if result.pipe_fds.is_some() {
                    HandleResult {
                        response: Response::ExecStartedPiped {
                            pid: result.pid as u32,
                        },
                        pty_master: None,
                        exec_pidfd: Some(result.pidfd),
                        pipe_fds: result.pipe_fds,
                    }
                } else {
                    HandleResult {
                        response: Response::ExecStarted {
                            pid: result.pid as u32,
                        },
                        pty_master: result.pty_master,
                        exec_pidfd: Some(result.pidfd),
                        pipe_fds: None,
                    }
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

    fn handle_image_list(
        &self,
        pool: Option<&str>,
        show_size: bool,
        show_exclusive: bool,
        show_layers: bool,
    ) -> HandleResult {
        let pool = match self.storage.resolve_pool(pool) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        match storage::image::list_images(pool, show_size, show_exclusive, show_layers) {
            Ok(images) => HandleResult::response_only(Response::ImageList(images)),
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("failed to list images: {e}"),
            }),
        }
    }

    fn handle_image_inspect(&self, name: &str, pool: Option<&str>) -> HandleResult {
        let pool = match self.storage.resolve_pool(pool) {
            Ok(p) => p,
            Err(e) => {
                return HandleResult::response_only(Response::Error {
                    message: format!("{e}"),
                });
            }
        };

        match storage::image::inspect_image(pool, name) {
            Ok(detail) => HandleResult::response_only(Response::ImageInspect(detail)),
            Err(e) => HandleResult::response_only(Response::Error {
                message: format!("inspect failed: {e}"),
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
    /// Pipe fds for piped mode: (stdout_read, stderr_read).
    pipe_fds: Option<(OwnedFd, OwnedFd)>,
}

/// Merge container env (base) with per-exec env (overrides).
///
/// For keys present in both, the exec value wins. Exec env can also add new keys.
fn merge_env(container_env: &[String], exec_env: &[String]) -> Vec<String> {
    if exec_env.is_empty() {
        return container_env.to_vec();
    }
    // Build a map from container env, preserving order
    let mut map: Vec<(String, String)> = Vec::new();
    for var in container_env {
        if let Some((k, v)) = var.split_once('=') {
            map.push((k.to_string(), v.to_string()));
        }
    }
    // Override or append from exec env
    for var in exec_env {
        if let Some((k, v)) = var.split_once('=') {
            if let Some(entry) = map.iter_mut().find(|(key, _)| key == k) {
                entry.1 = v.to_string();
            } else {
                map.push((k.to_string(), v.to_string()));
            }
        }
    }
    map.into_iter().map(|(k, v)| format!("{k}={v}")).collect()
}

/// Execute a command inside an existing container's namespaces.
///
/// Forks a child that joins the container's namespaces, optionally sets up
/// a PTY for interactive use, writes itself into the container's cgroup, and
/// execs the command. Returns a pidfd for monitoring + optional PTY master.
/// PID of the exec grandchild, used by the intermediate child to forward signals.
static EXEC_GRANDCHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Signal handler for the intermediate exec child: forward signals to grandchild.
extern "C" fn exec_forward_signal(sig: libc::c_int) {
    let pid = EXEC_GRANDCHILD_PID.load(std::sync::atomic::Ordering::SeqCst);
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

fn exec_in_container(
    container_pid: libc::pid_t,
    container_name: &str,
    command: &[String],
    detach: bool,
    piped: bool,
    user: Option<sandbox::protocol::ExecUser>,
    env: &[String],
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

    // Allocate PTY for interactive mode, or pipes for piped mode
    let pty = if !detach && !piped {
        Some(sandbox::sys::pty::allocate_pty()?)
    } else {
        None
    };

    // Create pipes for piped mode (stdout + stderr)
    let pipes = if piped && !detach {
        let stdout_pipe =
            nix::unistd::pipe().map_err(|e| Error::Other(format!("stdout pipe failed: {e}")))?;
        let stderr_pipe =
            nix::unistd::pipe().map_err(|e| Error::Other(format!("stderr pipe failed: {e}")))?;
        Some((stdout_pipe, stderr_pipe))
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

            // Open pidfd for the child
            let pidfd_raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0) };
            if pidfd_raw < 0 {
                return Err(Error::Other(format!(
                    "pidfd_open failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw as i32) };

            if let Some((master, _slave)) = pty {
                // PTY mode: return master fd
                return Ok(ExecResult {
                    pid: child_pid,
                    pidfd,
                    pty_master: Some(master),
                    pipe_fds: None,
                });
            } else if let Some(((stdout_r, stdout_w), (stderr_r, stderr_w))) = pipes {
                // Piped mode: close write ends in parent, return read ends
                drop(stdout_w);
                drop(stderr_w);
                return Ok(ExecResult {
                    pid: child_pid,
                    pidfd,
                    pty_master: None,
                    pipe_fds: Some((stdout_r, stderr_r)),
                });
            } else {
                // Detached mode
                return Ok(ExecResult {
                    pid: child_pid,
                    pidfd,
                    pty_master: None,
                    pipe_fds: None,
                });
            }
        }
        Ok(nix::unistd::ForkResult::Child) => {}
    }

    // === CHILD (intermediate) ===
    //
    // This process joins the container's namespaces (including PID), then
    // forks again. The grandchild is truly in the container's PID namespace
    // (setns(CLONE_NEWPID) only takes effect for children). The intermediate
    // child waits for the grandchild and proxies its exit code.
    {
        // Die if daemon dies
        let _ = nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL);

        // Join the container's cgroup (must happen before setns into mnt namespace,
        // since the host cgroupfs is not visible inside the container)
        if let Err(e) = std::fs::write(&cgroup_procs, format!("{}", std::process::id())) {
            eprintln!("failed to join cgroup: {e}");
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
        // Drop all namespace fds before forking — grandchild doesn't need them
        drop(ns_fds);

        // Fork again: the grandchild will be in the container's PID namespace.
        // setns(CLONE_NEWPID) only affects children, not the caller itself.
        match unsafe { nix::unistd::fork() } {
            Err(e) => {
                eprintln!("double-fork failed: {e}");
                std::process::exit(1);
            }
            Ok(nix::unistd::ForkResult::Parent { child }) => {
                // Intermediate child: close PTY fds, wait for grandchild, exit
                drop(pty);
                // Forward signals to grandchild so that SIGTERM from daemon reaches it
                let grandchild_pid = child.as_raw();
                unsafe {
                    EXEC_GRANDCHILD_PID.store(grandchild_pid, std::sync::atomic::Ordering::SeqCst);
                    for &sig in &[libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
                        libc::signal(sig, exec_forward_signal as *const () as libc::sighandler_t);
                    }
                }
                loop {
                    match nix::sys::wait::waitpid(child, None) {
                        Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => {
                            std::process::exit(code);
                        }
                        Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => {
                            std::process::exit(128 + sig as i32);
                        }
                        Err(nix::errno::Errno::EINTR) => continue,
                        _ => std::process::exit(1),
                    }
                }
            }
            Ok(nix::unistd::ForkResult::Child) => {
                // Grandchild: actually in the container's PID namespace.
                // Fall through to exec setup below.
            }
        }

        // === GRANDCHILD (in container PID namespace) ===

        if let Err(e) = nix::unistd::chroot("/") {
            eprintln!("chroot failed: {e}");
            std::process::exit(1);
        }
        let _ = std::env::set_current_dir("/");

        // Become a session leader so that bash job control (setpgid) works.
        let _ = nix::unistd::setsid();

        // Switch to target user (default: container root)
        let (uid, gid) = match &user {
            Some(u) => (u.uid, u.gid),
            None => (0, 0),
        };

        // Set supplementary groups from /etc/group (after chroot so we read container's file).
        {
            let mut sup_gids: Vec<nix::unistd::Gid> = vec![nix::unistd::Gid::from_raw(gid)];
            if let Some(pw) = sandbox::sys::passwd::lookup_uid(uid) {
                if pw.gid != gid {
                    sup_gids.push(nix::unistd::Gid::from_raw(pw.gid));
                }
                for g in sandbox::sys::passwd::lookup_supplementary_groups(&pw.name) {
                    let gid_val = nix::unistd::Gid::from_raw(g);
                    if !sup_gids.contains(&gid_val) {
                        sup_gids.push(gid_val);
                    }
                }
            }
            let _ = nix::unistd::setgroups(&sup_gids);
        }

        if let Err(e) = nix::unistd::setresgid(gid.into(), gid.into(), gid.into()) {
            eprintln!("setresgid({gid}) failed: {e}");
            std::process::exit(1);
        }
        if let Err(e) = nix::unistd::setresuid(uid.into(), uid.into(), uid.into()) {
            eprintln!("setresuid({uid}) failed: {e}");
            std::process::exit(1);
        }

        // Clear daemon environment and apply container's env
        unsafe { nix::env::clearenv() }.ok();
        if env.is_empty() {
            unsafe {
                std::env::set_var(
                    "PATH",
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                )
            };
        } else {
            for var in env {
                if let Some((k, v)) = var.split_once('=') {
                    unsafe { std::env::set_var(k, v) };
                }
            }
        }

        // Set HOME, USER from /etc/passwd based on the target uid.
        if std::env::var("HOME").is_err() || std::env::var("USER").is_err() {
            if let Some(pw) = sandbox::sys::passwd::lookup_uid(uid) {
                if std::env::var("HOME").is_err() {
                    unsafe { std::env::set_var("HOME", &pw.home) };
                }
                if std::env::var("USER").is_err() {
                    unsafe { std::env::set_var("USER", &pw.name) };
                }
            } else if std::env::var("HOME").is_err() {
                unsafe { std::env::set_var("HOME", "/") };
            }
        }

        // Set HOSTNAME from the container's UTS namespace
        if std::env::var("HOSTNAME").is_err() {
            if let Ok(hn) = nix::unistd::gethostname() {
                if let Some(hn) = hn.to_str() {
                    unsafe { std::env::set_var("HOSTNAME", hn) };
                }
            }
        }

        // Ensure TERM is set for interactive sessions
        if std::env::var("TERM").is_err() {
            unsafe { std::env::set_var("TERM", "xterm") };
        }

        // Set up PTY slave as stdin/stdout/stderr
        if let Some((_master, slave)) = pty {
            drop(_master);
            if let Err(e) = sandbox::sys::pty::setup_slave_pty(&slave, -1) {
                eprintln!("pty setup failed: {e}");
                std::process::exit(1);
            }
        } else if let Some(((_stdout_r, stdout_w), (_stderr_r, stderr_w))) = pipes {
            // Piped mode: close read ends, dup write ends to stdout/stderr
            // stdin from /dev/null
            use std::os::fd::AsRawFd;
            drop(_stdout_r);
            drop(_stderr_r);
            if let Ok(devnull) = std::fs::File::open("/dev/null") {
                unsafe { libc::dup2(devnull.as_raw_fd(), libc::STDIN_FILENO) };
            }
            unsafe {
                libc::dup2(stdout_w.as_raw_fd(), libc::STDOUT_FILENO);
                libc::dup2(stderr_w.as_raw_fd(), libc::STDERR_FILENO);
            }
            // Close original fds (now duped)
            drop(stdout_w);
            drop(stderr_w);
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
