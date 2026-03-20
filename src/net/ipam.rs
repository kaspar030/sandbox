//! Simple IP address management (IPAM) for bridged networking.
//!
//! Sequential allocator for a subnet. Tracks allocated IPs per bridge.
//! State is persisted to disk for daemon restart recovery.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

const IPAM_DIR: &str = "/var/lib/sandbox/ipam";

/// IP address allocator for a bridge subnet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAllocator {
    /// Subnet base address (e.g., 10.0.0.0).
    subnet: u32,
    /// Prefix length (e.g., 24).
    prefix_len: u8,
    /// Gateway IP (first usable, assigned to the bridge).
    gateway: u32,
    /// Allocated IPs: IP → container name.
    allocated: HashMap<u32, String>,
    /// Next offset to try (starts at 2: .1 is gateway).
    next_offset: u32,
    /// Bridge name (for persistence path).
    bridge_name: String,
}

impl IpAllocator {
    /// Create a new allocator for a subnet.
    ///
    /// Gateway is the first usable IP (subnet + 1).
    /// Container IPs start from subnet + 2.
    pub fn new(subnet: Ipv4Addr, prefix_len: u8, bridge_name: &str) -> Self {
        let subnet_u32 = u32::from(subnet);
        Self {
            subnet: subnet_u32,
            prefix_len,
            gateway: subnet_u32 + 1,
            allocated: HashMap::new(),
            next_offset: 2,
            bridge_name: bridge_name.to_string(),
        }
    }

    /// Gateway IP address (assigned to the bridge).
    pub fn gateway(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.gateway)
    }

    /// Subnet as "x.x.x.x/prefix" string.
    pub fn subnet_str(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.subnet), self.prefix_len)
    }

    /// Maximum number of usable IPs (excluding network + broadcast + gateway).
    fn max_hosts(&self) -> u32 {
        let total = 1u32 << (32 - self.prefix_len);
        total.saturating_sub(3) // network addr + broadcast + gateway
    }

    /// Allocate an IP for a container.
    pub fn allocate(&mut self, container_name: &str) -> Result<Ipv4Addr> {
        let max = self.max_hosts();
        if self.allocated.len() as u32 >= max {
            return Err(Error::Other(format!(
                "subnet {}/{} exhausted ({} IPs allocated)",
                Ipv4Addr::from(self.subnet),
                self.prefix_len,
                self.allocated.len()
            )));
        }

        // Warn at 90% capacity
        if self.allocated.len() as u32 >= max * 9 / 10 {
            tracing::warn!(
                "subnet {}/{}: {} of {} IPs allocated (90%+ usage)",
                Ipv4Addr::from(self.subnet),
                self.prefix_len,
                self.allocated.len(),
                max
            );
        }

        // Find next available IP
        let broadcast = self.subnet | ((1u32 << (32 - self.prefix_len)) - 1);
        for _ in 0..max + 3 {
            let ip = self.subnet + self.next_offset;
            self.next_offset += 1;

            // Wrap around
            if ip >= broadcast {
                self.next_offset = 2;
                continue;
            }

            // Skip gateway
            if ip == self.gateway {
                continue;
            }

            // Skip already allocated
            if self.allocated.contains_key(&ip) {
                continue;
            }

            self.allocated.insert(ip, container_name.to_string());
            let _ = self.save();
            return Ok(Ipv4Addr::from(ip));
        }

        Err(Error::Other("IPAM: no available IPs".to_string()))
    }

    /// Register a manually specified IP (from --ip flag).
    /// Returns error if the IP is already allocated or out of subnet.
    pub fn register(&mut self, ip: Ipv4Addr, container_name: &str) -> Result<()> {
        let ip_u32 = u32::from(ip);
        let mask = !((1u32 << (32 - self.prefix_len)) - 1);

        if ip_u32 & mask != self.subnet {
            return Err(Error::Other(format!(
                "IP {ip} is not in subnet {}/{}",
                Ipv4Addr::from(self.subnet),
                self.prefix_len
            )));
        }

        if ip_u32 == self.gateway {
            return Err(Error::Other(format!("IP {ip} is the gateway address")));
        }

        if let Some(existing) = self.allocated.get(&ip_u32) {
            return Err(Error::Other(format!(
                "IP {ip} already allocated to container '{existing}'"
            )));
        }

        self.allocated.insert(ip_u32, container_name.to_string());
        let _ = self.save();
        Ok(())
    }

    /// Release a container's IP.
    pub fn release(&mut self, container_name: &str) {
        self.allocated.retain(|_, name| name != container_name);
        let _ = self.save();
    }

    /// Number of containers using this allocator.
    pub fn container_count(&self) -> usize {
        self.allocated.len()
    }

    /// Persistence path.
    fn state_path(&self) -> PathBuf {
        Path::new(IPAM_DIR).join(format!("{}.json", self.bridge_name))
    }

    /// Save state to disk.
    pub fn save(&self) -> Result<()> {
        let _ = std::fs::create_dir_all(IPAM_DIR);
        let json = serde_json::to_string(self)
            .map_err(|e| Error::Other(format!("IPAM serialize: {e}")))?;
        std::fs::write(self.state_path(), json).map_err(|e| Error::Other(format!("IPAM save: {e}")))
    }

    /// Load state from disk (if exists).
    pub fn load(bridge_name: &str) -> Option<Self> {
        let path = Path::new(IPAM_DIR).join(format!("{bridge_name}.json"));
        let json = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&json).ok()
    }

    /// Remove persisted state.
    pub fn remove_state(&self) {
        let _ = std::fs::remove_file(self.state_path());
    }
}
