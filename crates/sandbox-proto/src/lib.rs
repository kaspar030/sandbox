//! Wire protocol types for daemon <-> client communication.
//!
//! Messages are length-prefixed: `[u32 LE length][postcard bytes]`.
//! For interactive sessions (run/exec), after the initial Response,
//! the daemon sends a PTY master fd via SCM_RIGHTS.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

// -- Error type for protocol operations --

/// Protocol error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

// -- Types --

/// Container specification for creation.
///
/// All fields except `name` and `image` have `#[serde(default)]` to ensure
/// backward compatibility — old persisted state files that are missing
/// newer fields (e.g., `volumes`, `publish`) will deserialize successfully
/// with default values instead of failing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSpec {
    pub name: String,
    /// Image name (resolved by the daemon from the storage pool).
    pub image: String,
    /// Storage pool name (default: "main").
    #[serde(default)]
    pub pool: Option<String>,
    /// Entrypoint from image config or --entrypoint override.
    /// Combined with command at exec time: exec(entrypoint + command).
    #[serde(default)]
    pub entrypoint: Vec<String>,
    #[serde(default)]
    pub command: Vec<String>,
    /// Environment variables: ["KEY=VALUE", ...].
    #[serde(default)]
    pub env: Vec<String>,
    /// Working directory inside the container.
    #[serde(default = "default_working_dir")]
    pub working_dir: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub uid_mappings: Vec<IdMapping>,
    #[serde(default)]
    pub gid_mappings: Vec<IdMapping>,
    #[serde(default)]
    pub cgroup: CgroupSpec,
    #[serde(default)]
    pub network: NetworkMode,
    #[serde(default)]
    pub seccomp: SeccompMode,
    #[serde(default)]
    pub capabilities: CapabilitySpec,
    #[serde(default)]
    pub bind_mounts: Vec<BindMount>,
    /// Named volume mounts.
    #[serde(default)]
    pub volumes: Vec<VolumeMount>,
    /// Port mappings for bridged networking (host_port:container_port/proto).
    #[serde(default)]
    pub publish: Vec<PortMapping>,
    #[serde(default)]
    pub use_init: bool,
    /// If true, run detached (no PTY, no interactive I/O).
    /// If false (default), allocate a PTY and send master fd to client.
    #[serde(default)]
    pub detach: bool,
    /// User to run as (e.g., "1000", "1000:1000", "nobody").
    /// Resolved from image config if not set by CLI. Default: root (uid 0).
    #[serde(default)]
    pub user: Option<String>,
    /// Restart policy. Default: No (for backward compatibility with old specs).
    /// CLI `create` defaults to UnlessStopped; `run` always uses No.
    #[serde(default)]
    pub restart_policy: RestartPolicy,
    /// Prevent gaining privileges via exec (PR_SET_NO_NEW_PRIVS).
    /// Default: true (secure). Set to false to allow sudo/su inside the container.
    #[serde(default = "default_true")]
    pub no_new_privs: bool,
}

fn default_true() -> bool {
    true
}

fn default_working_dir() -> String {
    "/".to_string()
}

impl Default for ContainerSpec {
    fn default() -> Self {
        Self {
            name: String::new(),
            image: String::new(),
            pool: None,
            entrypoint: Vec::new(),
            command: Vec::new(),
            env: Vec::new(),
            working_dir: "/".to_string(),
            hostname: None,
            uid_mappings: Vec::new(),
            gid_mappings: Vec::new(),
            cgroup: CgroupSpec::default(),
            network: NetworkMode::Host,
            seccomp: SeccompMode::Default,
            capabilities: CapabilitySpec::default(),
            bind_mounts: Vec::new(),
            volumes: Vec::new(),
            publish: Vec::new(),
            use_init: false,
            detach: false,
            user: None,
            restart_policy: RestartPolicy::No,
            no_new_privs: true,
        }
    }
}

/// Information about a stored image (for list view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    pub name: String,
    pub pool: String,
    pub size_bytes: Option<u64>,
    pub exclusive_bytes: Option<u64>,
    pub layer_count: u32,
    pub source: String,
    pub layers: Vec<LayerSummary>,
}

/// Summary of a layer (for list --layers view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerSummary {
    pub chain_id: String,
    pub size_bytes: Option<u64>,
    pub shared_with: Vec<String>,
}

/// Detailed image information (for inspect view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageDetail {
    pub name: String,
    pub pool: String,
    pub size_bytes: u64,
    pub source: String,
    pub reference: String,
    pub config: ImageConfigDetail,
    pub layers: Vec<LayerDetailInfo>,
}

/// Layer detail for inspect view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerDetailInfo {
    pub chain_id: String,
    pub diff_id: String,
    pub size_bytes: u64,
    pub shared_with: Vec<String>,
}

/// Image config for inspect view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageConfigDetail {
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub working_dir: String,
    #[serde(default)]
    pub user: Option<String>,
}

/// Information about a storage pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolInfo {
    pub name: String,
    pub fs_type: String,
    pub supports_snapshots: bool,
}

/// UID/GID mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdMapping {
    pub container_id: u32,
    pub host_id: u32,
    pub count: u32,
}

/// Cgroup resource limits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CgroupSpec {
    /// Memory limit in bytes (memory.max).
    pub memory_max: Option<u64>,
    /// Memory high watermark in bytes (memory.high).
    pub memory_high: Option<u64>,
    /// CPU max: (quota_us, period_us). E.g. (50000, 100000) = 50%.
    pub cpu_max: Option<(u64, u64)>,
    /// CPU weight (1-10000, default 100).
    pub cpu_weight: Option<u32>,
    /// Maximum number of processes (pids.max).
    pub pids_max: Option<u32>,
}

/// Network configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum NetworkMode {
    /// Share the host network namespace (fastest, no isolation).
    #[default]
    Host,
    /// Create isolated network namespace with veth + bridge.
    /// Used internally after resolving a named network.
    Bridged {
        bridge: String,
        /// Container IP — auto-allocated by IPAM if None.
        address: Option<Ipv4Addr>,
        /// Gateway IP — auto-assigned (bridge IP) if None.
        gateway: Option<Ipv4Addr>,
        prefix_len: u8,
    },
    /// Use a named network (resolved to Bridged by the daemon).
    /// "default" is the default bridged network (10.0.0.0/24).
    Named { name: String },
    /// Isolated network namespace, no configuration (user sets up manually).
    None,
}

/// Information about a named network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub name: String,
    pub bridge: String,
    pub subnet: String,
    pub gateway: String,
    pub containers: u32,
}

/// Port mapping for bridged networking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: PortProtocol,
}

/// Protocol for port mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortProtocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for PortProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortProtocol::Tcp => write!(f, "tcp"),
            PortProtocol::Udp => write!(f, "udp"),
        }
    }
}

/// Seccomp profile selection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeccompMode {
    /// Deny-by-default allowlist of common syscalls.
    #[default]
    Default,
    /// No seccomp filtering.
    Disabled,
}

/// Capability configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySpec {
    /// Capabilities to keep (everything else is dropped).
    pub keep: Vec<String>,
}

impl Default for CapabilitySpec {
    fn default() -> Self {
        // Match Docker's default capability set.
        Self {
            keep: vec![
                "CAP_CHOWN".to_string(),
                "CAP_DAC_OVERRIDE".to_string(),
                "CAP_FSETID".to_string(),
                "CAP_FOWNER".to_string(),
                "CAP_MKNOD".to_string(),
                "CAP_NET_RAW".to_string(),
                "CAP_SETGID".to_string(),
                "CAP_SETUID".to_string(),
                "CAP_SETFCAP".to_string(),
                "CAP_SETPCAP".to_string(),
                "CAP_NET_BIND_SERVICE".to_string(),
                "CAP_SYS_CHROOT".to_string(),
                "CAP_KILL".to_string(),
                "CAP_AUDIT_WRITE".to_string(),
            ],
        }
    }
}

/// Bind mount specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindMount {
    pub source: String,
    pub target: String,
    pub readonly: bool,
}

/// Volume type: filesystem (directory) or block device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum VolumeType {
    #[default]
    Filesystem,
    Block,
}

/// Named volume mount specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMount {
    pub name: String,
    pub target: String,
    pub readonly: bool,
    #[serde(default)]
    pub volume_type: VolumeType,
}

/// Information about a named volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub name: String,
    pub pool: String,
    #[serde(default)]
    pub volume_type: VolumeType,
    #[serde(default)]
    pub size: Option<u64>,
}

/// Metadata for a block volume (stored as sidecar JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockVolumeMeta {
    pub size: u64,
    pub format: Option<String>,
    pub backing: String,
    pub loop_file: Option<String>,
    pub zvol_dataset: Option<String>,
}

/// Runtime state of a block volume attached to a container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockVolumeState {
    pub volume_name: String,
    pub host_device: String,
    pub container_device: Option<String>,
    pub container_mount: Option<String>,
    pub host_mount: Option<String>,
    pub loop_file: Option<String>,
}

/// User identity for exec commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecUser {
    pub uid: u32,
    pub gid: u32,
}

/// Container state as reported by the daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContainerState {
    Created,
    Running,
    Stopped { exit_code: i32 },
}

/// Info about a container snapshot (for listing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotInfo {
    pub name: String,
    pub timestamp: String,
    pub container: String,
    pub includes_volumes: bool,
}

/// Info about a stack snapshot (for listing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackSnapshotInfo {
    pub name: String,
    pub timestamp: String,
    pub containers: Vec<String>,
    pub includes_volumes: bool,
}

/// Partial update for a container's configuration.
///
/// All fields are optional — only specified (Some) fields are applied.
/// Used by the `update` command to modify a container's spec.
/// Cgroup changes are applied live on running containers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerUpdate {
    // -- Cgroup limits --
    /// New restart policy.
    pub restart_policy: Option<RestartPolicy>,
    /// New memory limit in bytes (memory.max).
    pub memory_max: Option<u64>,
    /// New CPU limit as (quota_us, period_us).
    pub cpu_max: Option<(u64, u64)>,
    /// New PID limit.
    pub pids_max: Option<u32>,

    // -- Environment --
    /// Environment variables to set/override (KEY=VALUE).
    #[serde(default)]
    pub env_set: Vec<String>,
    /// Environment variable keys to remove.
    #[serde(default)]
    pub env_remove: Vec<String>,
    /// If true, clear all env vars before applying env_set.
    #[serde(default)]
    pub env_clear: bool,

    // -- Command / Entrypoint --
    /// New command. Some(vec![]) = clear, None = no change.
    pub command: Option<Vec<String>>,
    /// New entrypoint. Some(vec![]) = clear, None = no change.
    pub entrypoint: Option<Vec<String>>,

    // -- Container identity --
    /// New user (UID, UID:GID, etc.). Some(Some("1000")) = set, Some(None) = clear.
    pub user: Option<Option<String>>,
    /// New hostname. Some(Some("host")) = set, Some(None) = clear.
    pub hostname: Option<Option<String>>,
    /// New working directory.
    pub working_dir: Option<String>,

    // -- Init --
    /// Enable/disable init. Some(true) = enable, Some(false) = disable.
    pub use_init: Option<bool>,

    // -- Security --
    /// New seccomp mode.
    pub seccomp: Option<SeccompMode>,
    /// Capabilities to add.
    #[serde(default)]
    pub cap_add: Vec<String>,
    /// Capabilities to drop.
    #[serde(default)]
    pub cap_drop: Vec<String>,
    /// Set no_new_privs. Some(true) = enable, Some(false) = disable (allow sudo).
    pub no_new_privs: Option<bool>,
}

impl ContainerUpdate {
    /// Returns true if no fields are set (no updates to apply).
    pub fn is_empty(&self) -> bool {
        self.restart_policy.is_none()
            && self.memory_max.is_none()
            && self.cpu_max.is_none()
            && self.pids_max.is_none()
            && self.env_set.is_empty()
            && self.env_remove.is_empty()
            && !self.env_clear
            && self.command.is_none()
            && self.entrypoint.is_none()
            && self.user.is_none()
            && self.hostname.is_none()
            && self.working_dir.is_none()
            && self.use_init.is_none()
            && self.seccomp.is_none()
            && self.cap_add.is_empty()
            && self.cap_drop.is_empty()
            && self.no_new_privs.is_none()
    }
}

/// Restart policy for containers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    /// Never restart (default for ephemeral `run` containers).
    #[default]
    No,
    /// Always restart regardless of exit code.
    Always,
    /// Restart only on non-zero exit code.
    OnFailure,
    /// Restart unless explicitly stopped by the user.
    /// Default for non-ephemeral `create` containers and stack services.
    UnlessStopped,
}

impl std::fmt::Display for RestartPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::No => write!(f, "no"),
            Self::Always => write!(f, "always"),
            Self::OnFailure => write!(f, "on-failure"),
            Self::UnlessStopped => write!(f, "unless-stopped"),
        }
    }
}

impl RestartPolicy {
    /// Parse from a string (Docker-compatible values).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "no" | "" => Some(Self::No),
            "always" => Some(Self::Always),
            "on-failure" => Some(Self::OnFailure),
            "unless-stopped" => Some(Self::UnlessStopped),
            _ => None,
        }
    }

    /// Whether this policy can trigger a restart for the given exit code.
    pub fn should_restart(&self, exit_code: i32, manually_stopped: bool) -> bool {
        match self {
            Self::No => false,
            Self::Always => true,
            Self::OnFailure => exit_code != 0,
            Self::UnlessStopped => !manually_stopped,
        }
    }
}

/// Information about a container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub name: String,
    pub state: ContainerState,
    pub pid: Option<u32>,
}

/// Detailed container information (for inspect view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerDetail {
    pub name: String,
    pub image: String,
    pub pool: String,
    pub state: ContainerState,
    pub pid: Option<u32>,
    pub ephemeral: bool,
    pub user: Option<String>,
    pub command: Vec<String>,
    pub entrypoint: Vec<String>,
    pub env: Vec<String>,
    pub working_dir: String,
    pub hostname: Option<String>,
    pub use_init: bool,
    pub network: NetworkMode,
    pub bind_mounts: Vec<BindMount>,
    pub volumes: Vec<VolumeMount>,
    pub publish: Vec<PortMapping>,
    pub cgroup: CgroupSpec,
    pub seccomp: SeccompMode,
    pub restart_policy: RestartPolicy,
    #[serde(default = "default_true")]
    pub no_new_privs: bool,
    pub rootfs_path: Option<String>,
    pub cgroup_path: String,
}

// -- Wire protocol messages --

/// Request from CLI client to daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Create and start a container (combined).
    Run(ContainerSpec),
    /// Create a container without starting.
    Create(ContainerSpec),
    /// Start a previously created container.
    Start {
        name: String,
        command: Option<Vec<String>>,
    },
    /// Stop a running container.
    Stop { name: String, timeout_secs: u32 },
    /// Destroy a container (cleanup all resources).
    Destroy { name: String },
    /// List all containers.
    List,
    /// Inspect a container (detailed info).
    Inspect { name: String },
    /// Execute a command in a running container's namespaces.
    Exec {
        name: String,
        command: Vec<String>,
        /// If true, run without PTY (fire-and-forget). Default: false (interactive).
        detach: bool,
        /// Run as a specific user (default: container root, uid 0).
        user: Option<ExecUser>,
        /// Per-exec environment variables (merged on top of container env).
        #[serde(default)]
        env: Vec<String>,
        /// If true, use pipes for stdout/stderr instead of a PTY.
        /// Client receives two fds (stdout, stderr) via SCM_RIGHTS.
        #[serde(default)]
        piped: bool,
    },
    /// Import an image from a path (directory or tar.gz).
    ImageImport {
        name: String,
        source: String,
        pool: Option<String>,
    },
    /// Pull an image from an OCI registry.
    ImagePull {
        /// OCI reference, e.g. "alpine:latest", "docker.io/library/ubuntu:22.04"
        reference: String,
        /// Local image name override (defaults to repo basename).
        name: Option<String>,
        pool: Option<String>,
    },
    /// List images.
    ImageList {
        pool: Option<String>,
        show_size: bool,
        show_exclusive: bool,
        show_layers: bool,
    },
    /// Inspect an image (detailed info).
    ImageInspect { name: String, pool: Option<String> },
    /// Remove an image.
    ImageRemove { name: String, pool: Option<String> },
    /// Add a bind mount to a running container.
    MountAdd {
        name: String,
        source: String,
        target: String,
        readonly: bool,
    },
    /// Remove a bind mount from a running container.
    MountRemove { name: String, target: String },
    /// List bind mounts for a container.
    MountList { name: String },
    /// Snapshot a container's rootfs into a reusable image.
    Snapshot {
        name: String,
        image_name: String,
        /// Skip non-CoW running container safety check.
        force: bool,
        /// Overwrite existing image, adding a new layer on CoW filesystems.
        update: bool,
    },
    /// Create a named volume.
    VolumeCreate {
        name: String,
        pool: Option<String>,
        #[serde(default)]
        volume_type: VolumeType,
        #[serde(default)]
        size: Option<u64>,
        #[serde(default)]
        format: Option<String>,
    },
    /// Remove a named volume.
    VolumeRemove { name: String, pool: Option<String> },
    /// List named volumes.
    VolumeList { pool: Option<String> },
    /// Attach a volume to a running container.
    VolumeAttach {
        container: String,
        volume_name: String,
        target: String,
        readonly: bool,
    },
    /// Detach a volume from a running container.
    VolumeDetach { container: String, target: String },
    /// Mount a block device inside a container (daemon-assisted).
    MountBlock {
        container: String,
        device: String,
        target: String,
        fs_type: String,
        #[serde(default)]
        options: Option<String>,
    },
    /// Create a named network.
    NetworkCreate {
        name: String,
        subnet: Option<String>,
    },
    /// Remove a named network.
    NetworkRemove { name: String },
    /// List named networks.
    NetworkList,
    /// List storage pools.
    PoolList,
    /// Bring up a stack (create network + volumes + containers).
    StackUp(StackDefinition),
    /// Tear down a stack.
    StackDown { name: String },
    /// List containers in a stack.
    StackPs { name: String },
    /// List all stacks.
    StackList,
    /// Update a container's configuration (must be stopped or created).
    UpdateContainer {
        name: String,
        update: ContainerUpdate,
    },
    /// Snapshot a container (rootfs + config + optionally volumes).
    SnapshotContainer {
        name: String,
        snapshot_name: Option<String>,
        #[serde(default)]
        exclude_volumes: bool,
    },
    /// Restore a container from a snapshot.
    RestoreContainer { name: String, snapshot_name: String },
    /// List snapshots for a container.
    ListContainerSnapshots { name: String },
    /// Delete a container snapshot.
    DeleteContainerSnapshot { name: String, snapshot_name: String },
    /// Snapshot all containers in a stack.
    StackSnapshot {
        stack_name: String,
        snapshot_name: Option<String>,
        #[serde(default)]
        exclude_volumes: bool,
    },
    /// Restore a stack from a snapshot.
    StackRestore {
        stack_name: String,
        snapshot_name: String,
    },
    /// List snapshots for a stack.
    StackSnapshots { stack_name: String },
    /// Shut down the daemon.
    Shutdown,
    /// Enable session mode: keep the connection alive for multiple requests.
    /// After receiving SessionEnabled, the client can send further requests
    /// on the same connection without reconnecting.
    EnableSession,
}

/// Stack definition — describes a group of containers, network, and volumes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackDefinition {
    pub name: String,
    #[serde(default)]
    pub network: StackNetwork,
    #[serde(default)]
    pub volumes: Vec<String>,
    pub containers: Vec<StackContainer>,
    /// Default restart policy for all containers in this stack.
    /// Per-service `restart` overrides this. Defaults to "unless-stopped".
    #[serde(default)]
    pub restart: String,
}

/// Network configuration for a stack.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StackNetwork {
    /// Subnet (e.g., "10.1.0.0/24"). Auto-allocated if empty.
    #[serde(default)]
    pub subnet: String,
    /// Bridge name. Auto-generated if empty.
    #[serde(default)]
    pub bridge: String,
}

/// Container definition within a stack.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StackContainer {
    pub name: String,
    pub image: String,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub entrypoint: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub working_dir: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub bind: Vec<String>,
    #[serde(default)]
    pub publish: Vec<String>,
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub init: bool,
    #[serde(default)]
    pub restart: String,
    /// CPU limit (e.g., "2.0")
    #[serde(default)]
    pub cpus: String,
    /// Memory limit (e.g., "512M")
    #[serde(default)]
    pub memory: String,
    /// PID limit
    #[serde(default)]
    pub pids: Option<u32>,
    /// Allow privilege escalation (sudo/su). Default: false (secure).
    #[serde(default)]
    pub allow_new_privs: bool,
}

/// Information about a running stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackInfo {
    pub name: String,
    pub containers: Vec<String>,
    pub bridge: String,
}

/// Information about a bind mount.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    pub source: String,
    pub target: String,
    pub readonly: bool,
}

/// Response from daemon to CLI client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    /// Operation succeeded.
    Ok,
    /// Container created successfully.
    Created { name: String },
    /// Container started. For interactive sessions, a PTY fd follows via SCM_RIGHTS.
    Started { name: String, pid: u32 },
    /// Container stopped.
    Stopped { name: String, exit_code: i32 },
    /// Container list.
    ContainerList(Vec<ContainerInfo>),
    /// Container detail (inspect).
    ContainerInspect(Box<ContainerDetail>),
    /// Container was destroyed.
    Destroyed { name: String },
    /// Exec started (PTY mode). PTY fd follows via SCM_RIGHTS.
    ExecStarted { pid: u32 },
    /// Exec started (piped mode). Two fds (stdout, stderr) follow via SCM_RIGHTS.
    ExecStartedPiped { pid: u32 },
    /// Image imported successfully.
    ImageImported { name: String },
    /// Image pulled from registry.
    ImagePulled { name: String },
    /// Image list.
    ImageList(Vec<ImageInfo>),
    /// Image detail (inspect).
    ImageInspect(ImageDetail),
    /// Image removed.
    ImageRemoved { name: String },
    /// Volume created.
    VolumeCreated { name: String },
    /// Volume removed.
    VolumeRemoved { name: String },
    /// Volume list.
    VolumeList(Vec<VolumeInfo>),
    /// Volume attached to container.
    VolumeAttached { target: String },
    /// Volume detached from container.
    VolumeDetached { target: String },
    /// Block device mounted inside container.
    BlockMounted { target: String },
    /// Network created.
    NetworkCreated { name: String },
    /// Network removed.
    NetworkRemoved { name: String },
    /// Network list.
    NetworkList(Vec<NetworkInfo>),
    /// Stack brought up.
    StackUp {
        name: String,
        containers: Vec<String>,
    },
    /// Stack torn down.
    StackDown { name: String },
    /// Containers in a stack.
    StackPs(Vec<ContainerInfo>),
    /// List of all stacks.
    StackList(Vec<StackInfo>),
    /// Pool list.
    PoolList(Vec<PoolInfo>),
    /// Container exited (sent after PTY EOF on interactive run).
    ContainerExited { exit_code: i32 },
    /// Exec child exited (sent after PTY EOF on interactive exec).
    ExecExited { exit_code: i32 },
    /// Mount added to container.
    MountAdded { target: String },
    /// Mount removed from container.
    MountRemoved { target: String },
    /// Mount list for a container.
    MountList(Vec<MountInfo>),
    /// Container rootfs snapshotted as image.
    Snapshotted { image_name: String },
    /// Container configuration updated.
    ContainerUpdated { name: String },
    /// Session mode enabled — connection will accept multiple requests.
    SessionEnabled,
    /// Container snapshotted (rootfs + config + volumes).
    ContainerSnapshotted { name: String, snapshot_name: String },
    /// Container restored from snapshot.
    ContainerRestored { name: String, snapshot_name: String },
    /// List of container snapshots.
    ContainerSnapshotList { snapshots: Vec<SnapshotInfo> },
    /// Container snapshot deleted.
    ContainerSnapshotDeleted { name: String, snapshot_name: String },
    /// Stack snapshotted.
    StackSnapshotted {
        stack_name: String,
        snapshot_name: String,
    },
    /// Stack restored from snapshot.
    StackRestored {
        stack_name: String,
        snapshot_name: String,
    },
    /// List of stack snapshots.
    StackSnapshotList { snapshots: Vec<StackSnapshotInfo> },
    /// Error response.
    Error { message: String },
}

// -- Encoding / decoding --

/// Encode a message with a u32 LE length prefix.
pub fn encode_message<T: Serialize>(msg: &T) -> Result<Vec<u8>> {
    let payload = postcard::to_allocvec(msg).map_err(|e| Error::Protocol(e.to_string()))?;
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Decode a length-prefixed message. Returns the message and remaining bytes.
pub fn decode_message<'a, T: Deserialize<'a>>(buf: &'a [u8]) -> Result<(T, &'a [u8])> {
    if buf.len() < 4 {
        return Err(Error::Protocol(
            "buffer too short for length prefix".to_string(),
        ));
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let rest = &buf[4..];
    if rest.len() < len {
        return Err(Error::Protocol(format!(
            "expected {} bytes, got {}",
            len,
            rest.len()
        )));
    }
    let msg = postcard::from_bytes(&rest[..len]).map_err(|e| Error::Protocol(e.to_string()))?;
    Ok((msg, &rest[len..]))
}

/// Read a complete length-prefixed message from a reader.
pub fn read_message<T: for<'a> Deserialize<'a>>(reader: &mut impl std::io::Read) -> Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;

    if len > 16 * 1024 * 1024 {
        return Err(Error::Protocol(format!("message too large: {} bytes", len)));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    postcard::from_bytes(&payload).map_err(|e| Error::Protocol(e.to_string()))
}

/// Write a length-prefixed message to a writer.
pub fn write_message<T: Serialize>(writer: &mut impl std::io::Write, msg: &T) -> Result<()> {
    let data = encode_message(msg)?;
    writer.write_all(&data)?;
    writer.flush()?;
    Ok(())
}
