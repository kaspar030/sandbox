//! Bridge interface management.

use crate::error::Result;
use crate::net::netlink::NetlinkSocket;

/// Ensure a bridge interface exists (create if it doesn't).
pub fn ensure_bridge(name: &str) -> Result<()> {
    let mut sock = NetlinkSocket::new()?;

    // Check if bridge already exists
    if sock.get_link_index(name).is_ok() {
        return Ok(());
    }

    // Create the bridge
    sock.create_bridge(name)?;

    // Bring it up
    let idx = sock.get_link_index(name)?;
    sock.set_link_up(idx)?;

    Ok(())
}

/// Add an interface to a bridge.
pub fn add_to_bridge(bridge_name: &str, iface_name: &str) -> Result<()> {
    let mut sock = NetlinkSocket::new()?;
    sock.set_master(iface_name, bridge_name)
}

/// Remove (delete) a bridge interface.
#[allow(dead_code)]
pub fn delete_bridge(name: &str) -> Result<()> {
    let mut sock = NetlinkSocket::new()?;
    sock.delete_link(name)
}
