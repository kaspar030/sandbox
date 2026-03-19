//! Container rootfs management — create from image, destroy.
//!
//! Containers never mount the image directory directly. Instead, a copy
//! (or CoW snapshot on btrfs/bcachefs) is created under the pool's fs/ directory.

use crate::error::{Error, Result};
use crate::storage::StoragePool;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Create a container rootfs from an image.
///
/// Currently uses `cp -a` for all filesystems. Future: use btrfs/bcachefs
/// snapshots when the pool supports them.
pub fn create_container_rootfs(
    pool: &StoragePool,
    image_name: &str,
    container_name: &str,
) -> Result<PathBuf> {
    let image_path = pool.image_path(image_name);
    if !image_path.is_dir() {
        return Err(Error::Other(format!(
            "image '{image_name}' not found in pool '{}'",
            pool.name
        )));
    }

    let container_path = pool.container_path(container_name);
    if container_path.exists() {
        return Err(Error::Other(format!(
            "container rootfs for '{container_name}' already exists in pool '{}'",
            pool.name
        )));
    }

    // TODO: When pool.fs_type.supports_snapshots(), use:
    //   btrfs subvolume snapshot <image_path> <container_path>
    //   bcachefs subvolume snapshot ...
    // For now: always cp -a

    let status = Command::new("cp")
        .args(["-a", "--reflink=auto", "--"])
        .arg(&image_path)
        .arg(&container_path)
        .status()
        .map_err(|e| Error::Other(format!("failed to run cp: {e}")))?;

    if !status.success() {
        let _ = fs::remove_dir_all(&container_path);
        return Err(Error::Other(format!(
            "cp failed with exit code {:?}",
            status.code()
        )));
    }

    Ok(container_path)
}

/// Destroy a container's rootfs.
///
/// Currently uses rm -rf. Future: btrfs subvolume delete when applicable.
pub fn destroy_container_rootfs(pool: &StoragePool, container_name: &str) -> Result<()> {
    let container_path = pool.container_path(container_name);
    if !container_path.exists() {
        return Ok(()); // Already gone
    }

    // TODO: When pool.fs_type.supports_snapshots(), use:
    //   btrfs subvolume delete <container_path>
    // For now: rm -rf

    fs::remove_dir_all(&container_path).map_err(|e| {
        Error::Other(format!(
            "failed to remove container rootfs '{}': {e}",
            container_path.display()
        ))
    })?;

    Ok(())
}
