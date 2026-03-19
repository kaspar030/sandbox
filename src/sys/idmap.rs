//! Idmapped mount support via the new mount API (open_tree, mount_setattr, move_mount).
//!
//! Used to apply a UID/GID shift to a mount so that on-disk uid 0 appears
//! as uid 100000 (or whatever the subordinate range is) without modifying
//! on-disk ownership.
//!
//! The idmap is described by a user namespace: we create a throwaway userns
//! with the desired uid_map/gid_map, pass its fd to mount_setattr, and then
//! destroy the userns. The kernel copies the mapping data — the userns can
//! be discarded after mount_setattr returns.

use crate::error::{Error, Result};
use crate::namespace::user;
use crate::protocol::IdMapping;
use crate::sys::clone3;
use crate::sys::mount_api;
use std::os::fd::OwnedFd;
use std::path::Path;

/// Create a user namespace with specific UID/GID mappings, solely for use
/// as an idmap descriptor in mount_setattr().
///
/// Implementation: clone3(CLONE_NEWUSER | CLONE_PIDFD) creates a throwaway
/// child that pause()s. Parent writes uid_map/gid_map, opens
/// /proc/<pid>/ns/user, kills the child. The returned fd keeps the namespace
/// alive via kernel refcounting. This is the approach used by Incus and crun.
pub fn create_idmap_userns(
    uid_mappings: &[IdMapping],
    gid_mappings: &[IdMapping],
) -> Result<OwnedFd> {
    // clone3 with CLONE_NEWUSER only — no other namespaces, no cgroup
    let clone_result = clone3::clone3_with_pidfd(clone3::CLONE_NEWUSER, None)?;

    match clone_result {
        None => {
            // === CHILD ===
            let _ = nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL);
            loop {
                nix::unistd::pause();
            }
        }
        Some(clone3::CloneResult {
            child_pid,
            pidfd: _,
        }) => {
            // === PARENT ===
            let setup_result = (|| -> Result<OwnedFd> {
                user::setup_user_namespace(child_pid, uid_mappings, gid_mappings)?;

                let ns_path = format!("/proc/{child_pid}/ns/user");
                let ns_fd = std::fs::File::open(&ns_path)
                    .map_err(|e| Error::Other(format!("failed to open {ns_path}: {e}")))?;

                Ok(OwnedFd::from(ns_fd))
            })();

            // Kill the child regardless of success/failure
            let child = nix::unistd::Pid::from_raw(child_pid);
            let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(child, None);

            setup_result
        }
    }
}

/// High-level: set up an idmapped mount of source at target.
///
/// 1. Creates a throwaway user namespace with the desired mapping
/// 2. Clones the source mount tree (open_tree)
/// 3. Applies the idmap (mount_setattr)
/// 4. Attaches at the target path (move_mount)
///
/// The target directory must already exist.
#[tracing::instrument(skip_all, level = "debug")]
pub fn setup_idmapped_mount(
    source: &Path,
    target: &Path,
    uid_mappings: &[IdMapping],
    gid_mappings: &[IdMapping],
) -> Result<()> {
    let userns_fd = create_idmap_userns(uid_mappings, gid_mappings)?;
    let tree_fd = mount_api::open_tree(source, true)?;
    mount_api::set_idmap(&tree_fd, &userns_fd)?;
    drop(userns_fd);
    mount_api::move_mount(&tree_fd, target)?;
    Ok(())
}
