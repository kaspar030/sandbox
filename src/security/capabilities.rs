//! Linux capability management.
//!
//! By default, all capabilities are dropped. The user can opt in to specific
//! capabilities via the CapabilitySpec.
//!
//! We use prctl() directly via nix rather than the `caps` crate.

use crate::error::{Error, Result};
use crate::protocol::CapabilitySpec;

/// All known Linux capabilities (as of kernel 6.x).
/// These are the values used with prctl and capset.
const ALL_CAPS: &[(u32, &str)] = &[
    (0, "CAP_CHOWN"),
    (1, "CAP_DAC_OVERRIDE"),
    (2, "CAP_DAC_READ_SEARCH"),
    (3, "CAP_FOWNER"),
    (4, "CAP_FSETID"),
    (5, "CAP_KILL"),
    (6, "CAP_SETGID"),
    (7, "CAP_SETUID"),
    (8, "CAP_SETPCAP"),
    (9, "CAP_LINUX_IMMUTABLE"),
    (10, "CAP_NET_BIND_SERVICE"),
    (11, "CAP_NET_BROADCAST"),
    (12, "CAP_NET_ADMIN"),
    (13, "CAP_NET_RAW"),
    (14, "CAP_IPC_LOCK"),
    (15, "CAP_IPC_OWNER"),
    (16, "CAP_SYS_MODULE"),
    (17, "CAP_SYS_RAWIO"),
    (18, "CAP_SYS_CHROOT"),
    (19, "CAP_SYS_PTRACE"),
    (20, "CAP_SYS_PACCT"),
    (21, "CAP_SYS_ADMIN"),
    (22, "CAP_SYS_BOOT"),
    (23, "CAP_SYS_NICE"),
    (24, "CAP_SYS_RESOURCE"),
    (25, "CAP_SYS_TIME"),
    (26, "CAP_SYS_TTY_CONFIG"),
    (27, "CAP_MKNOD"),
    (28, "CAP_LEASE"),
    (29, "CAP_AUDIT_WRITE"),
    (30, "CAP_AUDIT_CONTROL"),
    (31, "CAP_SETFCAP"),
    (32, "CAP_MAC_OVERRIDE"),
    (33, "CAP_MAC_ADMIN"),
    (34, "CAP_SYSLOG"),
    (35, "CAP_WAKE_ALARM"),
    (36, "CAP_BLOCK_SUSPEND"),
    (37, "CAP_AUDIT_READ"),
    (38, "CAP_PERFMON"),
    (39, "CAP_BPF"),
    (40, "CAP_CHECKPOINT_RESTORE"),
];

/// Resolve a capability name (e.g., "CAP_NET_BIND_SERVICE") to its number.
pub fn resolve_capability(name: &str) -> Option<u32> {
    let upper = name.to_uppercase();
    let lookup = if upper.starts_with("CAP_") {
        upper
    } else {
        format!("CAP_{upper}")
    };
    ALL_CAPS.iter().find(|(_, n)| *n == lookup).map(|(v, _)| *v)
}

/// Drop all capabilities except those specified in the keep list.
///
/// This must be called in the child process after all other setup.
/// We use prctl to:
/// 1. Set PR_SET_NO_NEW_PRIVS (prevent regaining caps via exec)
/// 2. Drop capabilities from the bounding set
/// 3. Clear inheritable, permitted, and effective sets (keeping only what's needed)
pub fn drop_capabilities(spec: &CapabilitySpec) -> Result<()> {
    // Resolve capability names to numbers
    let keep_set: Vec<u32> = spec
        .keep
        .iter()
        .filter_map(|name| {
            let cap = resolve_capability(name);
            if cap.is_none() {
                tracing::warn!("unknown capability: {name}, ignoring");
            }
            cap
        })
        .collect();

    // Set no_new_privs first — this prevents gaining capabilities through exec
    nix::sys::prctl::set_no_new_privs().map_err(Error::Prctl)?;

    // Drop capabilities from the bounding set
    for &(cap_num, _) in ALL_CAPS {
        if !keep_set.contains(&cap_num) {
            // Clear ambient capabilities (ignore errors — might not be supported)
            let _ = unsafe { libc::prctl(libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, 0) };

            let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap_num as u64, 0, 0, 0) };
            if ret != 0 {
                let err = nix::Error::last();
                // EINVAL means the capability doesn't exist on this kernel — skip it
                if err != nix::Error::EINVAL {
                    return Err(Error::Prctl(err));
                }
            }
        }
    }

    // Now use capset to clear the inheritable, permitted, and effective sets
    // except for capabilities we want to keep
    let mut inheritable_low: u32 = 0;
    let mut inheritable_high: u32 = 0;
    let mut permitted_low: u32 = 0;
    let mut permitted_high: u32 = 0;
    let mut effective_low: u32 = 0;
    let mut effective_high: u32 = 0;

    for &cap in &keep_set {
        if cap < 32 {
            inheritable_low |= 1 << cap;
            permitted_low |= 1 << cap;
            effective_low |= 1 << cap;
        } else {
            let bit = cap - 32;
            inheritable_high |= 1 << bit;
            permitted_high |= 1 << bit;
            effective_high |= 1 << bit;
        }
    }

    // Linux capability version 3 (supports caps 0-63)
    let header = CapUserHeader {
        version: 0x20080522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,              // current process
    };

    let data = [
        CapUserData {
            effective: effective_low,
            permitted: permitted_low,
            inheritable: inheritable_low,
        },
        CapUserData {
            effective: effective_high,
            permitted: permitted_high,
            inheritable: inheritable_high,
        },
    ];

    let ret = unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) };
    if ret != 0 {
        return Err(Error::Capability(format!(
            "capset failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_capability() {
        assert_eq!(resolve_capability("CAP_NET_BIND_SERVICE"), Some(10));
        assert_eq!(resolve_capability("NET_BIND_SERVICE"), Some(10));
        assert_eq!(resolve_capability("cap_sys_admin"), Some(21));
        assert_eq!(resolve_capability("NONEXISTENT"), None);
    }

    #[test]
    fn test_all_caps_ordered() {
        for (i, &(num, _)) in ALL_CAPS.iter().enumerate() {
            assert_eq!(num, i as u32, "capabilities should be in order");
        }
    }
}
