use std::path::PathBuf;

/// All errors that can occur in sandbox operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // -- Syscall / OS errors --
    #[error("clone3 failed: {0}")]
    Clone3(std::io::Error),

    #[error("eventfd failed: {0}")]
    EventFd(nix::Error),

    #[error("mount failed on {path}: {source}")]
    Mount {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("pivot_root failed: {0}")]
    PivotRoot(std::io::Error),

    #[error("sethostname failed: {0}")]
    SetHostname(nix::Error),

    #[error("setns failed for {ns}: {source}")]
    SetNs { ns: String, source: nix::Error },

    #[error("unshare failed: {0}")]
    Unshare(nix::Error),

    #[error("waitid failed: {0}")]
    WaitId(nix::Error),

    #[error("kill failed: {0}")]
    Kill(nix::Error),

    #[error("exec failed: {0}")]
    Exec(nix::Error),

    #[error("prctl failed: {0}")]
    Prctl(nix::Error),

    #[error("ioctl failed: {0}")]
    Ioctl(nix::Error),

    // -- Namespace errors --
    #[error("failed to write uid_map: {0}")]
    UidMap(std::io::Error),

    #[error("failed to write gid_map: {0}")]
    GidMap(std::io::Error),

    #[error("failed to write deny setgroups: {0}")]
    SetGroups(std::io::Error),

    // -- Cgroup errors --
    #[error("cgroup operation failed on {path}: {source}")]
    Cgroup {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("cgroup v2 not available at /sys/fs/cgroup")]
    CgroupV2NotAvailable,

    // -- Network errors --
    #[error("netlink error: {0}")]
    Netlink(std::io::Error),

    #[error("network setup failed: {0}")]
    NetworkSetup(String),

    // -- Rootfs errors --
    #[error("rootfs path does not exist: {0}")]
    RootfsNotFound(PathBuf),

    #[error("rootfs setup failed: {0}")]
    RootfsSetup(String),

    // -- Security errors --
    #[error("seccomp filter failed: {0}")]
    Seccomp(String),

    #[error("capability operation failed: {0}")]
    Capability(String),

    // -- Container errors --
    #[error("container {0} not found")]
    ContainerNotFound(String),

    #[error("container {name} is in invalid state {state} for operation {operation}")]
    InvalidState {
        name: String,
        state: String,
        operation: String,
    },

    #[error("container name {0} is already in use")]
    NameConflict(String),

    // -- Daemon / protocol errors --
    #[error("daemon not running (socket not found at {0})")]
    DaemonNotRunning(PathBuf),

    #[error("daemon already running")]
    DaemonAlreadyRunning,

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("connection error: {0}")]
    Connection(std::io::Error),

    // -- General --
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
