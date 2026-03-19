//! Hot bind mount support — add/remove bind mounts to running containers.
//!
//! Uses /proc/<pid>/root/ to access the container's filesystem and the
//! new mount API (open_tree + move_mount) to inject mounts without needing
//! fork + setns.

use crate::error::{Error, Result};
use crate::sys::mount_api;
use std::path::{Path, PathBuf};

/// Resolve a target path inside a running container via procfs.
fn container_path(container_pid: i32, target: &str) -> PathBuf {
    PathBuf::from(format!("/proc/{container_pid}/root")).join(target.trim_start_matches('/'))
}

/// Add a bind mount to a running container.
///
/// Uses open_tree(OPEN_TREE_CLONE) to create a detached mount clone of the
/// source, then move_mount() to attach it at /proc/<pid>/root/<target>,
/// which places it inside the container's mount namespace.
pub fn hot_bind_mount(
    container_pid: i32,
    source: &Path,
    target: &str,
    readonly: bool,
) -> Result<()> {
    let tree_fd = mount_api::open_tree(source, true)?;

    if readonly {
        mount_api::set_readonly(&tree_fd)?;
    }

    let container_target = container_path(container_pid, target);

    // Create mount point — file or directory depending on source type
    if source.is_file() {
        if let Some(parent) = container_target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Other(format!("mkdir -p {}: {e}", parent.display())))?;
        }
        if !container_target.exists() {
            std::fs::File::create(&container_target)
                .map_err(|e| Error::Other(format!("touch {}: {e}", container_target.display())))?;
        }
    } else {
        std::fs::create_dir_all(&container_target)
            .map_err(|e| Error::Other(format!("mkdir -p {}: {e}", container_target.display())))?;
    }

    mount_api::move_mount(&tree_fd, &container_target)
}

/// Remove a bind mount from a running container.
pub fn hot_unmount(container_pid: i32, target: &str) -> Result<()> {
    let container_target = container_path(container_pid, target);

    nix::mount::umount2(&container_target, nix::mount::MntFlags::MNT_DETACH)
        .map_err(|e| Error::Other(format!("umount {}: {e}", container_target.display())))
}
