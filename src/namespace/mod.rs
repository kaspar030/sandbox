//! Linux namespace setup.
//!
//! Each module handles configuration for one namespace type.
//! The parent configures user namespace mappings and network before
//! signaling the child. The child then configures everything else.

pub mod ipc;
pub mod mount;
pub mod network;
pub mod pid;
pub mod subid;
pub mod user;
pub mod uts;

use crate::protocol::NetworkMode;
use crate::sys::clone3::NamespaceFlags;

/// Configuration for which namespaces to create.
#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    pub pid: bool,
    pub mount: bool,
    pub network: bool,
    pub uts: bool,
    pub user: bool,
    pub ipc: bool,
    pub cgroup: bool,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            pid: true,
            mount: true,
            network: true,
            uts: true,
            user: true,
            ipc: true,
            cgroup: true,
        }
    }
}

impl NamespaceConfig {
    /// Create namespace config based on network mode.
    /// When using host networking, CLONE_NEWNET is omitted.
    pub fn from_network_mode(network: &NetworkMode) -> Self {
        let mut config = Self::default();
        if matches!(network, NetworkMode::Host) {
            config.network = false;
        }
        config
    }

    /// Convert to clone3 namespace flags.
    pub fn to_flags(&self) -> NamespaceFlags {
        let mut flags = NamespaceFlags::new();
        if self.pid {
            flags = flags.pid();
        }
        if self.mount {
            flags = flags.mount();
        }
        if self.network {
            flags = flags.network();
        }
        if self.uts {
            flags = flags.uts();
        }
        if self.user {
            flags = flags.user();
        }
        if self.ipc {
            flags = flags.ipc();
        }
        if self.cgroup {
            flags = flags.cgroup();
        }
        flags
    }
}
