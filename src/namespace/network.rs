//! Network namespace setup.
//!
//! For `NetworkMode::Host`, no network namespace is created (CLONE_NEWNET omitted).
//! For `NetworkMode::Bridged`, we create a veth pair and bridge via raw netlink.
//! For `NetworkMode::None`, the namespace is created but left unconfigured.

use crate::error::{Error, Result};
use crate::protocol::NetworkMode;

/// Set up networking for a container based on the network mode.
/// Called from the parent after clone3.
pub fn setup_network(mode: &NetworkMode, child_pid: libc::pid_t) -> Result<()> {
    match mode {
        NetworkMode::Host => {
            // Nothing to do — CLONE_NEWNET was not set
            Ok(())
        }
        NetworkMode::Bridged {
            bridge,
            address,
            gateway,
            prefix_len,
        } => {
            // Set up veth pair + bridge using raw netlink
            crate::net::setup_container_network(
                child_pid,
                bridge,
                *address,
                *gateway,
                *prefix_len,
            )
        }
        NetworkMode::None => {
            // Network namespace was created but leave it unconfigured.
            // The loopback interface is down by default.
            Ok(())
        }
    }
}

/// Bring up the loopback interface inside the container.
/// Called from the child after entering the network namespace.
#[allow(dead_code)]
pub fn setup_loopback() -> Result<()> {
    crate::net::bring_up_loopback().map_err(|e| Error::NetworkSetup(format!("loopback: {e}")))
}
