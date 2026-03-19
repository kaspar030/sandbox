//! Networking support using raw netlink sockets.
//!
//! Provides veth pair creation, bridge management, and interface configuration
//! without shelling out to `ip` or depending on an async netlink library.

pub mod bridge;
pub mod netlink;
pub mod veth;

use crate::error::Result;
use std::net::Ipv4Addr;

/// Set up the full network stack for a container with bridged networking.
///
/// Called from the parent after clone3:
/// 1. Create veth pair (host-side and container-side)
/// 2. Move container-side veth into the container's network namespace
/// 3. Attach host-side veth to the bridge
/// 4. Configure IP address on the container-side interface
/// 5. Bring up interfaces
pub fn setup_container_network(
    child_pid: libc::pid_t,
    bridge_name: &str,
    address: Ipv4Addr,
    gateway: Ipv4Addr,
    prefix_len: u8,
) -> Result<()> {
    let host_veth = format!("veth_{child_pid}_h");
    let container_veth = format!("veth_{child_pid}_c");

    // Create veth pair
    veth::create_veth_pair(&host_veth, &container_veth)?;

    // Move container-side veth into the container's network namespace
    veth::move_to_netns(&container_veth, child_pid)?;

    // Ensure bridge exists
    bridge::ensure_bridge(bridge_name)?;

    // Attach host-side veth to bridge
    bridge::add_to_bridge(bridge_name, &host_veth)?;

    // Bring up host-side veth
    veth::set_link_up(&host_veth)?;

    // Configure the container-side interface (done via nsenter or netlink
    // into the child's namespace). We do this from the parent by specifying
    // the target netns pid.
    veth::configure_in_netns(child_pid, "eth0", address, prefix_len, gateway)?;

    Ok(())
}

/// Bring up the loopback interface inside the current network namespace.
#[allow(dead_code)]
pub fn bring_up_loopback() -> Result<()> {
    let mut sock = netlink::NetlinkSocket::new()?;
    let lo_index = sock.get_link_index("lo")?;
    sock.set_link_up(lo_index)?;
    Ok(())
}

/// Clean up network resources for a container.
pub fn cleanup_container_network(child_pid: libc::pid_t) -> Result<()> {
    let host_veth = format!("veth_{child_pid}_h");

    // Deleting one end of a veth pair automatically deletes the other
    if let Err(e) = veth::delete_link(&host_veth) {
        tracing::warn!("failed to delete veth {host_veth}: {e}");
    }

    Ok(())
}
