//! NAT management via nftables (shells out to `nft`).
//!
//! Sets up masquerade for outbound traffic from bridge subnets and
//! DNAT rules for port forwarding.

use crate::error::{Error, Result};
use std::net::Ipv4Addr;
use std::process::Command;

const NFT_TABLE: &str = "sandbox_nat";

/// Check if the `nft` binary is available.
pub fn nft_available() -> bool {
    Command::new("nft")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Set up the sandbox NAT table with masquerade for a bridge subnet.
///
/// Idempotent: deletes existing table first, then recreates.
pub fn setup_masquerade(bridge: &str, subnet: &str) -> Result<()> {
    // Delete existing table (ignore errors if it doesn't exist)
    let _ = run_nft(&["delete", "table", "ip", NFT_TABLE]);

    // Create table
    run_nft(&["add", "table", "ip", NFT_TABLE])?;

    // Create postrouting chain for masquerade
    run_nft(&[
        "add",
        "chain",
        "ip",
        NFT_TABLE,
        "postrouting",
        "{ type nat hook postrouting priority 100 ; }",
    ])?;

    // Create prerouting chain for DNAT (port forwarding)
    run_nft(&[
        "add",
        "chain",
        "ip",
        NFT_TABLE,
        "prerouting",
        "{ type nat hook prerouting priority -100 ; }",
    ])?;

    // Add masquerade rule: traffic from the subnet going out any interface
    // except the bridge itself gets masqueraded (NAT'd to the host's IP).
    let rule = format!("oifname != \"{bridge}\" ip saddr {subnet} masquerade");
    run_nft(&["add", "rule", "ip", NFT_TABLE, "postrouting", &rule])?;

    tracing::info!("NAT masquerade configured for {subnet} on bridge {bridge}");
    Ok(())
}

/// Add a DNAT port forwarding rule.
///
/// Forwards `host_port` on the host to `container_ip:container_port`.
pub fn add_port_forward(
    protocol: &str,
    host_port: u16,
    container_ip: Ipv4Addr,
    container_port: u16,
) -> Result<()> {
    let rule = format!("{protocol} dport {host_port} dnat to {container_ip}:{container_port}");
    run_nft(&["add", "rule", "ip", NFT_TABLE, "prerouting", &rule])?;
    tracing::info!("port forward: {protocol}/{host_port} → {container_ip}:{container_port}");
    Ok(())
}

/// Remove all DNAT rules for a specific host port.
///
/// Lists rules in the prerouting chain, finds the one matching the port,
/// and deletes it by handle.
pub fn remove_port_forward(protocol: &str, host_port: u16) -> Result<()> {
    // List rules with handles
    let output = Command::new("nft")
        .args(["-a", "list", "chain", "ip", NFT_TABLE, "prerouting"])
        .output()
        .map_err(|e| Error::Other(format!("nft list: {e}")))?;

    if !output.status.success() {
        return Ok(()); // table/chain doesn't exist
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let pattern = format!("{protocol} dport {host_port}");

    for line in stdout.lines() {
        if line.contains(&pattern) {
            // Extract handle number: "... # handle N"
            if let Some(handle) = line.rsplit("# handle ").next() {
                if let Ok(handle_num) = handle.trim().parse::<u32>() {
                    let _ = run_nft(&[
                        "delete",
                        "rule",
                        "ip",
                        NFT_TABLE,
                        "prerouting",
                        "handle",
                        &handle_num.to_string(),
                    ]);
                }
            }
        }
    }

    Ok(())
}

/// Clean up the entire sandbox NAT table.
pub fn cleanup_nat() {
    let _ = run_nft(&["delete", "table", "ip", NFT_TABLE]);
    tracing::debug!("NAT table cleaned up");
}

/// Run an nft command.
fn run_nft(args: &[&str]) -> Result<()> {
    let output = Command::new("nft")
        .args(args)
        .output()
        .map_err(|e| Error::Other(format!("failed to run nft: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Other(format!(
            "nft {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }

    Ok(())
}
