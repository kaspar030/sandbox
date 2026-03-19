//! Container rootfs management — create from image, destroy.
//!
//! Containers never mount the image directory directly. Instead, a copy
//! (or CoW snapshot on btrfs/bcachefs) is created under the pool's fs/ directory.
//!
//! On btrfs/bcachefs, images are stored as subvolumes and container rootfs
//! creation uses instant O(1) CoW snapshots. On other filesystems, cp -a
//! with --reflink=auto is used (O(n) in file count but CoW at file level
//! when the filesystem supports reflinks).

use crate::error::{Error, Result};
use crate::storage::fs_detect::FsType;
use crate::storage::StoragePool;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Create a container rootfs from an image.
///
/// On btrfs/bcachefs: creates an instant CoW snapshot of the image subvolume.
/// On other filesystems: copies with cp -a --reflink=auto.
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

    match pool.fs_type {
        FsType::Btrfs => {
            btrfs_snapshot(&image_path, &container_path)?;
            tracing::info!(
                "created btrfs snapshot for container '{container_name}' from image '{image_name}'"
            );
        }
        FsType::Bcachefs => {
            bcachefs_snapshot(&image_path, &container_path)?;
            tracing::info!(
                "created bcachefs snapshot for container '{container_name}' from image '{image_name}'"
            );
        }
        _ => {
            cp_reflink(&image_path, &container_path)?;
        }
    }

    Ok(container_path)
}

/// Destroy a container's rootfs.
///
/// On btrfs/bcachefs: deletes the subvolume/snapshot.
/// On other filesystems: rm -rf.
pub fn destroy_container_rootfs(pool: &StoragePool, container_name: &str) -> Result<()> {
    let container_path = pool.container_path(container_name);
    destroy_container_rootfs_by_path(container_path, pool.fs_type.clone())
}

/// Destroy a container rootfs given its path and filesystem type.
///
/// Like [`destroy_container_rootfs`], but takes owned values so it can be
/// moved into a background task for deferred cleanup.
pub fn destroy_container_rootfs_by_path(container_path: PathBuf, fs_type: FsType) -> Result<()> {
    if !container_path.exists() {
        return Ok(());
    }

    match fs_type {
        FsType::Btrfs => btrfs_subvolume_delete(&container_path)?,
        FsType::Bcachefs => bcachefs_subvolume_delete(&container_path)?,
        _ => {
            fs::remove_dir_all(&container_path).map_err(|e| {
                Error::Other(format!(
                    "failed to remove container rootfs '{}': {e}",
                    container_path.display()
                ))
            })?;
        }
    }

    Ok(())
}

// -- Btrfs operations --

/// Create a btrfs subvolume at the given path.
pub fn btrfs_subvolume_create(path: &Path) -> Result<()> {
    run_cmd("btrfs", &["subvolume", "create", "--"], path)
}

/// Create a btrfs snapshot of source at dest.
fn btrfs_snapshot(source: &Path, dest: &Path) -> Result<()> {
    let status = Command::new("btrfs")
        .args(["subvolume", "snapshot", "--"])
        .arg(source)
        .arg(dest)
        .status()
        .map_err(|e| Error::Other(format!("failed to run btrfs: {e}")))?;

    if !status.success() {
        return Err(Error::Other(format!(
            "btrfs subvolume snapshot failed with exit code {:?}",
            status.code()
        )));
    }
    Ok(())
}

/// Delete a btrfs subvolume or snapshot.
pub fn btrfs_subvolume_delete(path: &Path) -> Result<()> {
    run_cmd("btrfs", &["subvolume", "delete", "--"], path)
}

// -- Bcachefs operations --

/// Create a bcachefs subvolume at the given path.
pub fn bcachefs_subvolume_create(path: &Path) -> Result<()> {
    run_cmd("bcachefs", &["subvolume", "create"], path)
}

/// Create a bcachefs snapshot of source at dest.
fn bcachefs_snapshot(source: &Path, dest: &Path) -> Result<()> {
    let status = Command::new("bcachefs")
        .args(["subvolume", "snapshot"])
        .arg(source)
        .arg(dest)
        .status()
        .map_err(|e| Error::Other(format!("failed to run bcachefs: {e}")))?;

    if !status.success() {
        return Err(Error::Other(format!(
            "bcachefs subvolume snapshot failed with exit code {:?}",
            status.code()
        )));
    }
    Ok(())
}

/// Delete a bcachefs subvolume or snapshot.
pub fn bcachefs_subvolume_delete(path: &Path) -> Result<()> {
    run_cmd("bcachefs", &["subvolume", "delete"], path)
}

// -- Fallback --

/// Copy with cp -a --reflink=auto (for non-snapshot filesystems).
fn cp_reflink(source: &Path, dest: &Path) -> Result<()> {
    let status = Command::new("cp")
        .args(["-a", "--reflink=auto", "--"])
        .arg(source)
        .arg(dest)
        .status()
        .map_err(|e| Error::Other(format!("failed to run cp: {e}")))?;

    if !status.success() {
        let _ = fs::remove_dir_all(dest);
        return Err(Error::Other(format!(
            "cp failed with exit code {:?}",
            status.code()
        )));
    }
    Ok(())
}

// -- Helpers --

/// Run a command with a single path argument appended.
fn run_cmd(program: &str, args: &[&str], path: &Path) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .arg(path)
        .status()
        .map_err(|e| Error::Other(format!("failed to run {program}: {e}")))?;

    if !status.success() {
        return Err(Error::Other(format!(
            "{program} {} failed with exit code {:?}",
            args.join(" "),
            status.code()
        )));
    }
    Ok(())
}

/// Check if the required snapshot tool is available for a filesystem type.
pub fn check_snapshot_tool(fs_type: &FsType) -> bool {
    match fs_type {
        FsType::Btrfs => which("btrfs"),
        FsType::Bcachefs => which("bcachefs"),
        _ => true, // no tool needed for cp -a
    }
}

/// Check if a command exists in PATH.
fn which(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}
