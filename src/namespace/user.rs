//! User namespace — UID/GID mapping.
//!
//! After clone3 with CLONE_NEWUSER, the parent must write uid_map and gid_map
//! for the child process. The child waits (via eventfd) until this is done.

use crate::error::{Error, Result};
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

/// Write "deny" to /proc/<pid>/setgroups.
/// This is required before writing gid_map in a user namespace.
pub fn deny_setgroups(child_pid: libc::pid_t) -> Result<()> {
    let path = format!("/proc/{child_pid}/setgroups");
    fs::write(&path, "deny").map_err(Error::SetGroups)?;
    Ok(())
}

/// Set up all user namespace mappings for a child process.
/// This is the main entry point called from the parent.
pub fn setup_user_namespace(
    child_pid: libc::pid_t,
    uid_mappings: &[IdMapping],
    gid_mappings: &[IdMapping],
) -> Result<()> {
    // Order matters: deny setgroups, then write gid_map, then uid_map.
    // (gid_map before uid_map avoids needing CAP_SETGID in some cases.)
    deny_setgroups(child_pid)?;
    write_gid_map(child_pid, gid_mappings)?;
    write_uid_map(child_pid, uid_mappings)?;
    Ok(())
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
