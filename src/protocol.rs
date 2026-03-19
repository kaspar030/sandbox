//! Wire protocol types for daemon <-> client communication.
//!
//! Messages are length-prefixed: `[u32 LE length][postcard bytes]`.
//! For interactive sessions (run/exec), after the initial Response,
//! the daemon sends a PTY master fd via SCM_RIGHTS.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Container specification for creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSpec {
    pub name: String,
    pub rootfs: String,
    pub command: Vec<String>,
    pub hostname: Option<String>,
    pub uid_mappings: Vec<IdMapping>,
    pub gid_mappings: Vec<IdMapping>,
    pub cgroup: CgroupSpec,
    pub network: NetworkMode,
    pub seccomp: SeccompMode,
    pub capabilities: CapabilitySpec,
    pub bind_mounts: Vec<BindMount>,
    pub use_init: bool,
}

impl Default for ContainerSpec {
    fn default() -> Self {
        Self {
            name: String::new(),
            rootfs: String::new(),
            command: vec!["/bin/sh".to_string()],
            hostname: None,
            uid_mappings: vec![IdMapping {
                container_id: 0,
                host_id: 1000,
                count: 1,
            }],
            gid_mappings: vec![IdMapping {
                container_id: 0,
                host_id: 1000,
                count: 1,
            }],
            cgroup: CgroupSpec::default(),
            network: NetworkMode::Host,
            seccomp: SeccompMode::Default,
            capabilities: CapabilitySpec::default(),
            bind_mounts: Vec::new(),
            use_init: false,
        }
    }
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMode {
    /// Share the host network namespace (fastest, no isolation).
    Host,
    /// Create isolated network namespace with veth + bridge.
    Bridged {
        bridge: String,
        address: Ipv4Addr,
        gateway: Ipv4Addr,
        prefix_len: u8,
    },
    /// Isolated network namespace, no configuration (user sets up manually).
    None,
}

/// Seccomp profile selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SeccompMode {
    /// Deny-by-default allowlist of common syscalls.
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
        Self { keep: Vec::new() }
    }
}

/// Bind mount specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindMount {
    pub source: String,
    pub target: String,
    pub readonly: bool,
}

/// Container state as reported by the daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContainerState {
    Created,
    Running,
    Stopped { exit_code: i32 },
}

/// Information about a container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub name: String,
    pub state: ContainerState,
    pub pid: Option<u32>,
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
    /// Execute a command in a running container's namespaces.
    Exec { name: String, command: Vec<String> },
    /// Shut down the daemon.
    Shutdown,
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
    /// Container was destroyed.
    Destroyed { name: String },
    /// Exec started. PTY fd follows via SCM_RIGHTS.
    ExecStarted { pid: u32 },
    /// Error response.
    Error { message: String },
}

/// Encode a message with a u32 LE length prefix.
pub fn encode_message<T: Serialize>(msg: &T) -> crate::error::Result<Vec<u8>> {
    let payload =
        postcard::to_allocvec(msg).map_err(|e| crate::error::Error::Protocol(e.to_string()))?;
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Decode a length-prefixed message. Returns the message and remaining bytes.
pub fn decode_message<'a, T: Deserialize<'a>>(buf: &'a [u8]) -> crate::error::Result<(T, &'a [u8])> {
    if buf.len() < 4 {
        return Err(crate::error::Error::Protocol(
            "buffer too short for length prefix".to_string(),
        ));
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let rest = &buf[4..];
    if rest.len() < len {
        return Err(crate::error::Error::Protocol(format!(
            "expected {} bytes, got {}",
            len,
            rest.len()
        )));
    }
    let msg = postcard::from_bytes(&rest[..len])
        .map_err(|e| crate::error::Error::Protocol(e.to_string()))?;
    Ok((msg, &rest[len..]))
}

/// Read a complete length-prefixed message from a reader.
pub fn read_message<T: for<'a> Deserialize<'a>>(
    reader: &mut impl std::io::Read,
) -> crate::error::Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;

    // Sanity check: reject messages larger than 16 MiB
    if len > 16 * 1024 * 1024 {
        return Err(crate::error::Error::Protocol(format!(
            "message too large: {} bytes",
            len
        )));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    postcard::from_bytes(&payload).map_err(|e| crate::error::Error::Protocol(e.to_string()))
}

/// Write a length-prefixed message to a writer.
pub fn write_message<T: Serialize>(
    writer: &mut impl std::io::Write,
    msg: &T,
) -> crate::error::Result<()> {
    let data = encode_message(msg)?;
    writer.write_all(&data)?;
    writer.flush()?;
    Ok(())
}
