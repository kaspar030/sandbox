//! Veth pair management.

use crate::error::{Error, Result};
use crate::net::netlink::NetlinkSocket;

/// Create a veth pair with the given names.
pub fn create_veth_pair(name: &str, peer_name: &str) -> Result<()> {
    let mut sock = NetlinkSocket::new()?;
    sock.create_veth(name, peer_name)
}

/// Move a network interface to another network namespace.
pub fn move_to_netns(name: &str, pid: libc::pid_t) -> Result<()> {
    let mut sock = NetlinkSocket::new()?;
    sock.set_link_netns(name, pid)
}

/// Set a network interface up.
pub fn set_link_up(name: &str) -> Result<()> {
    let mut sock = NetlinkSocket::new()?;
    sock.set_link_up_by_name(name)
}

/// Delete a network interface.
pub fn delete_link(name: &str) -> Result<()> {
    let mut sock = NetlinkSocket::new()?;
    sock.delete_link(name)
}

/// Configure an interface inside a container's network namespace.
/// This opens a netlink socket inside the target namespace via /proc/<pid>/ns/net.
pub fn configure_in_netns(
    pid: libc::pid_t,
    iface_name: &str,
    addr: std::net::Ipv4Addr,
    prefix_len: u8,
    gateway: std::net::Ipv4Addr,
) -> Result<()> {
    // We need to enter the child's network namespace to configure the interface.
    // We do this by opening /proc/<pid>/ns/net and using setns.
    let ns_path = format!("/proc/{pid}/ns/net");
    let ns_fd = std::fs::File::open(&ns_path)
        .map_err(|e| Error::NetworkSetup(format!("failed to open {ns_path}: {e}")))?;

    // Save our current netns
    let my_ns = std::fs::File::open("/proc/self/ns/net")
        .map_err(|e| Error::NetworkSetup(format!("failed to open own netns: {e}")))?;

    // Enter child's network namespace
    nix::sched::setns(&ns_fd, nix::sched::CloneFlags::CLONE_NEWNET)
        .map_err(|e| Error::SetNs {
            ns: "net".to_string(),
            source: e,
        })?;

    // Now we're in the child's netns — configure the interface
    let result = (|| -> Result<()> {
        let mut sock = NetlinkSocket::new()?;

        // The moved interface may have a different name in the new ns.
        // Rename it to the desired name.
        // Actually, the interface keeps its name. We need to find it.
        // After moving into the netns, the interface index may differ.
        let idx = sock.get_link_index(iface_name).or_else(|_| {
            // Try the original name — the interface might not have been renamed yet
            // The interface we moved was the container-side veth
            // We should look for the veth name pattern
            Err(Error::NetworkSetup(format!(
                "interface {iface_name} not found in container netns"
            )))
        })?;

        // Add IP address
        sock.add_address(idx, addr, prefix_len)?;

        // Bring up the interface
        sock.set_link_up(idx)?;

        // Bring up loopback
        if let Ok(lo_idx) = sock.get_link_index("lo") {
            sock.set_link_up(lo_idx)?;
        }

        // Add default route
        sock.add_default_route(gateway, idx)?;

        Ok(())
    })();

    // Restore our network namespace
    nix::sched::setns(&my_ns, nix::sched::CloneFlags::CLONE_NEWNET)
        .map_err(|e| Error::SetNs {
            ns: "net (restore)".to_string(),
            source: e,
        })?;

    result
}
