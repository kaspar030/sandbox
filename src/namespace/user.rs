//! User namespace — UID/GID mapping.
//!
//! After clone3 with CLONE_NEWUSER, the parent must write uid_map and gid_map
//! for the child process. The child waits (via eventfd) until this is done.

use crate::error::{Error, Result};
use crate::namespace::subid;
use crate::protocol::IdMapping;
use std::fs;

/// Write UID mappings for a child process.
/// Must be called from the parent after clone3, before signaling the child.
pub fn write_uid_map(child_pid: libc::pid_t, mappings: &[IdMapping]) -> Result<()> {
    let path = format!("/proc/{child_pid}/uid_map");
    let content = mappings_to_string(mappings);
    fs::write(&path, &content).map_err(Error::UidMap)?;
    Ok(())
}

/// Write GID mappings for a child process.
/// Must be called from the parent after writing "deny" to setgroups.
pub fn write_gid_map(child_pid: libc::pid_t, mappings: &[IdMapping]) -> Result<()> {
    let path = format!("/proc/{child_pid}/gid_map");
    let content = mappings_to_string(mappings);
    fs::write(&path, &content).map_err(Error::GidMap)?;
    Ok(())
}

/// Configure /proc/<pid>/setgroups for the user namespace.
///
/// When the daemon runs as root (euid 0), we write "allow" so that
/// setgroups() works inside the container (needed by apt, pip, etc.).
/// When unprivileged, we must write "deny" before writing gid_map.
fn configure_setgroups(child_pid: libc::pid_t) -> Result<()> {
    let path = format!("/proc/{child_pid}/setgroups");
    let value = if nix::unistd::geteuid().is_root() {
        "allow"
    } else {
        "deny"
    };
    fs::write(&path, value).map_err(Error::SetGroups)?;
    Ok(())
}

/// Set up all user namespace mappings for a child process.
/// This is the main entry point called from the parent.
pub fn setup_user_namespace(
    child_pid: libc::pid_t,
    uid_mappings: &[IdMapping],
    gid_mappings: &[IdMapping],
) -> Result<()> {
    // Order matters: configure setgroups, then write gid_map, then uid_map.
    // (gid_map before uid_map avoids needing CAP_SETGID in some cases.)
    configure_setgroups(child_pid)?;
    write_gid_map(child_pid, gid_mappings)?;
    write_uid_map(child_pid, uid_mappings)?;
    Ok(())
}

/// Build UID/GID mappings based on the daemon's current context.
///
/// When running as root: reads /etc/subuid and /etc/subgid for subordinate
/// ranges. Container uid 0 maps to the first subordinate uid (e.g., 100000).
/// Falls back to `0 0 1` (container root = host root) if no subid ranges found.
///
/// When running as non-root: maps container uid 0 to the current uid,
/// plus any subordinate ranges from /etc/subuid.
pub fn build_id_mappings() -> Result<(Vec<IdMapping>, Vec<IdMapping>)> {
    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getgid().as_raw();
    let username = subid::current_username().unwrap_or_else(|| uid.to_string());

    let uid_ranges = subid::read_subuid(&username, uid);
    let gid_ranges = subid::read_subgid(&username, gid);

    let uid_mappings = build_mappings_from_ranges(uid, &uid_ranges);
    let gid_mappings = build_mappings_from_ranges(gid, &gid_ranges);

    if uid_ranges.is_empty() {
        tracing::warn!(
            "no subordinate UID ranges found for {username} (uid {uid}) in /etc/subuid; \
             container will use a single-UID mapping"
        );
    }

    Ok((uid_mappings, gid_mappings))
}

/// Build ID mappings from subordinate ranges.
///
/// If subordinate ranges exist, container uid 0 maps to the first
/// subordinate range (fully within that range). If no ranges exist,
/// fall back to mapping container 0 to the daemon's own uid.
fn build_mappings_from_ranges(own_id: u32, ranges: &[subid::SubIdRange]) -> Vec<IdMapping> {
    if ranges.is_empty() {
        // No subordinate ranges — map container 0 to our own uid
        return vec![IdMapping {
            container_id: 0,
            host_id: own_id,
            count: 1,
        }];
    }

    // Use the first (and typically only) subordinate range.
    // Map container uid 0..count to host uid start..start+count.
    let range = &ranges[0];
    vec![IdMapping {
        container_id: 0,
        host_id: range.start,
        count: range.count,
    }]
}

/// Convert ID mappings to the kernel format: "container_id host_id count\n"
fn mappings_to_string(mappings: &[IdMapping]) -> String {
    let mut s = String::new();
    for m in mappings {
        s.push_str(&format!("{} {} {}\n", m.container_id, m.host_id, m.count));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mappings_to_string() {
        let mappings = vec![
            IdMapping {
                container_id: 0,
                host_id: 1000,
                count: 1,
            },
            IdMapping {
                container_id: 1,
                host_id: 100000,
                count: 65536,
            },
        ];
        let s = mappings_to_string(&mappings);
        assert_eq!(s, "0 1000 1\n1 100000 65536\n");
    }

    #[test]
    fn test_single_mapping() {
        let mappings = vec![IdMapping {
            container_id: 0,
            host_id: 1000,
            count: 1,
        }];
        let s = mappings_to_string(&mappings);
        assert_eq!(s, "0 1000 1\n");
    }
}
