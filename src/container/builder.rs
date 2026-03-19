//! Builder pattern for constructing container specifications.

use crate::protocol::{
    BindMount, CapabilitySpec, CgroupSpec, ContainerSpec, IdMapping, NetworkMode, SeccompMode,
};
use std::net::Ipv4Addr;

/// Builder for constructing a `ContainerSpec`.
#[derive(Debug)]
pub struct ContainerBuilder {
    spec: ContainerSpec,
}

impl ContainerBuilder {
    pub fn new(name: impl Into<String>, rootfs: impl Into<String>) -> Self {
        let mut spec = ContainerSpec::default();
        spec.name = name.into();
        spec.rootfs = rootfs.into();
        Self { spec }
    }

    pub fn command(mut self, cmd: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.spec.command = cmd.into_iter().map(|s| s.into()).collect();
        self
    }

    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.spec.hostname = Some(hostname.into());
        self
    }

    pub fn uid_map(mut self, container_id: u32, host_id: u32, count: u32) -> Self {
        self.spec.uid_mappings.push(IdMapping {
            container_id,
            host_id,
            count,
        });
        self
    }

    pub fn gid_map(mut self, container_id: u32, host_id: u32, count: u32) -> Self {
        self.spec.gid_mappings.push(IdMapping {
            container_id,
            host_id,
            count,
        });
        self
    }

    /// Replace all UID mappings.
    pub fn uid_mappings(mut self, mappings: Vec<IdMapping>) -> Self {
        self.spec.uid_mappings = mappings;
        self
    }

    /// Replace all GID mappings.
    pub fn gid_mappings(mut self, mappings: Vec<IdMapping>) -> Self {
        self.spec.gid_mappings = mappings;
        self
    }

    pub fn memory_max(mut self, bytes: u64) -> Self {
        self.spec.cgroup.memory_max = Some(bytes);
        self
    }

    pub fn memory_high(mut self, bytes: u64) -> Self {
        self.spec.cgroup.memory_high = Some(bytes);
        self
    }

    pub fn cpu_max(mut self, quota_us: u64, period_us: u64) -> Self {
        self.spec.cgroup.cpu_max = Some((quota_us, period_us));
        self
    }

    pub fn cpu_weight(mut self, weight: u32) -> Self {
        self.spec.cgroup.cpu_weight = Some(weight);
        self
    }

    pub fn pids_max(mut self, max: u32) -> Self {
        self.spec.cgroup.pids_max = Some(max);
        self
    }

    pub fn cgroup(mut self, cgroup: CgroupSpec) -> Self {
        self.spec.cgroup = cgroup;
        self
    }

    pub fn network_host(mut self) -> Self {
        self.spec.network = NetworkMode::Host;
        self
    }

    pub fn network_bridged(
        mut self,
        bridge: impl Into<String>,
        address: Ipv4Addr,
        gateway: Ipv4Addr,
        prefix_len: u8,
    ) -> Self {
        self.spec.network = NetworkMode::Bridged {
            bridge: bridge.into(),
            address,
            gateway,
            prefix_len,
        };
        self
    }

    pub fn network_none(mut self) -> Self {
        self.spec.network = NetworkMode::None;
        self
    }

    pub fn seccomp(mut self, mode: SeccompMode) -> Self {
        self.spec.seccomp = mode;
        self
    }

    pub fn seccomp_disabled(mut self) -> Self {
        self.spec.seccomp = SeccompMode::Disabled;
        self
    }

    /// Keep only these capabilities, drop everything else.
    pub fn keep_capabilities(mut self, caps: Vec<String>) -> Self {
        self.spec.capabilities = CapabilitySpec { keep: caps };
        self
    }

    pub fn bind_mount(
        mut self,
        source: impl Into<String>,
        target: impl Into<String>,
        readonly: bool,
    ) -> Self {
        self.spec.bind_mounts.push(BindMount {
            source: source.into(),
            target: target.into(),
            readonly,
        });
        self
    }

    pub fn use_init(mut self, enabled: bool) -> Self {
        self.spec.use_init = enabled;
        self
    }

    pub fn detach(mut self, detach: bool) -> Self {
        self.spec.detach = detach;
        self
    }

    pub fn build(self) -> ContainerSpec {
        self.spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let spec = ContainerBuilder::new("test", "/rootfs").build();
        assert_eq!(spec.name, "test");
        assert_eq!(spec.rootfs, "/rootfs");
        assert_eq!(spec.command, vec!["/bin/sh"]);
        assert!(spec.hostname.is_none());
        assert!(!spec.use_init);
        assert!(matches!(spec.network, NetworkMode::Host));
        assert!(matches!(spec.seccomp, SeccompMode::Default));
        assert!(spec.capabilities.keep.is_empty());
    }

    #[test]
    fn test_builder_full() {
        let spec = ContainerBuilder::new("mybox", "/path/to/rootfs")
            .command(["echo", "hello"])
            .hostname("testhost")
            .memory_max(128 * 1024 * 1024)
            .pids_max(64)
            .network_host()
            .seccomp_disabled()
            .keep_capabilities(vec!["CAP_NET_BIND_SERVICE".to_string()])
            .bind_mount("/tmp/data", "/data", true)
            .use_init(true)
            .build();

        assert_eq!(spec.name, "mybox");
        assert_eq!(spec.command, vec!["echo", "hello"]);
        assert_eq!(spec.hostname.as_deref(), Some("testhost"));
        assert_eq!(spec.cgroup.memory_max, Some(128 * 1024 * 1024));
        assert_eq!(spec.cgroup.pids_max, Some(64));
        assert!(spec.use_init);
        assert_eq!(spec.bind_mounts.len(), 1);
        assert!(spec.bind_mounts[0].readonly);
    }
}
