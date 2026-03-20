//! Bridge interface management.

use crate::error::{Error, Result};
use crate::net::netlink::NetlinkSocket;
use std::net::Ipv4Addr;

/// Ensure a bridge interface exists with an IP address.
///
/// Idempotent: if the bridge already exists, just returns.
/// If created, assigns the gateway IP and brings it up.
/// Also enables ip_forward for the first bridge.
pub fn ensure_bridge(name: &str, gateway: Ipv4Addr, prefix_len: u8) -> Result<()> {
    let mut sock = NetlinkSocket::new()?;

    // Check if bridge already exists
    if sock.get_link_index(name).is_ok() {
        return Ok(());
    }

    // Create the bridge
    sock.create_bridge(name)?;

    // Assign gateway IP to the bridge
    let idx = sock.get_link_index(name)?;
    sock.add_address(idx, gateway, prefix_len)?;

    // Bring it up
    sock.set_link_up(idx)?;

    // Enable IP forwarding (required for NAT)
    enable_ip_forward()?;

    tracing::info!("bridge {name} created with IP {gateway}/{prefix_len}");
    Ok(())
}

/// Add an interface to a bridge.
pub fn add_to_bridge(bridge_name: &str, iface_name: &str) -> Result<()> {
    let mut sock = NetlinkSocket::new()?;
    sock.set_master(iface_name, bridge_name)
}

/// Remove (delete) a bridge interface.
pub fn delete_bridge(name: &str) -> Result<()> {
    let mut sock = NetlinkSocket::new()?;
    sock.delete_link(name)
}

/// Enable IPv4 packet forwarding.
fn enable_ip_forward() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .map_err(|e| Error::Other(format!("failed to enable ip_forward: {e}")))
}
