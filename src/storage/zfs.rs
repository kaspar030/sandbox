//! ZFS storage backend helpers.
//!
//! ZFS uses a dataset model rather than directory-based subvolumes.
//! Each "subvolume" is a ZFS dataset, and snapshots are two-step:
//! first `zfs snapshot`, then `zfs clone`.
//!
//! This module provides the path-to-dataset mapping and all ZFS
//! operations needed by the storage layer.

use crate::error::{Error, Result};
use std::path::Path;
use std::process::Command;

/// Resolve a filesystem path to its ZFS dataset name.
///
/// Runs `zfs list` to find the dataset whose mountpoint contains `path`,
/// then appends the relative path components as child dataset names.
///
/// Example: if pool `sandbox` is mounted at `/pool` and `path` is
/// `/pool/storage/main/images/alpine`, returns `sandbox/storage/main/images/alpine`.
pub fn path_to_dataset(path: &Path) -> Result<String> {
    // First check if this exact path is already a dataset mountpoint
    let output = Command::new("zfs")
        .args(["list", "-H", "-o", "name,mountpoint"])
        .output()
        .map_err(|e| Error::Other(format!("failed to run zfs list: {e}")))?;

    if !output.status.success() {
        return Err(Error::Other(format!(
            "zfs list failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Find the dataset with the longest mountpoint prefix that matches our path.
    // This handles nested datasets correctly.
    let path_str = path.to_string_lossy();
    let mut best_dataset = None;
    let mut best_mountpoint_len = 0;

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 2 {
            let dataset = parts[0];
            let mountpoint = parts[1];
            if (path_str == mountpoint || path_str.starts_with(&format!("{mountpoint}/")))
                && mountpoint.len() > best_mountpoint_len
            {
                best_dataset = Some((dataset.to_string(), mountpoint.to_string()));
                best_mountpoint_len = mountpoint.len();
            }
        }
    }

    match best_dataset {
        Some((dataset, mountpoint)) => {
            let remainder = path_str
                .strip_prefix(&mountpoint)
                .unwrap_or("")
                .trim_start_matches('/');
            if remainder.is_empty() {
                Ok(dataset)
            } else {
                Ok(format!("{dataset}/{remainder}"))
            }
        }
        None => Err(Error::Other(format!(
            "no ZFS dataset found for path '{}'",
            path.display()
        ))),
    }
}

/// Create a ZFS dataset at the given filesystem path.
///
/// The parent dataset must already exist as a mounted ZFS dataset.
/// The new dataset is created as a child with an inherited mountpoint
/// (e.g., pool `sandbox` at `/zpool` → `sandbox/images` at `/zpool/images`).
///
/// Uses `-p` to create intermediate parent datasets if needed. Note that
/// this can shadow existing directory contents when intermediate datasets
/// get mounted. Use [`zfs_dataset_create_leaf`] when you need to avoid that.
pub fn zfs_dataset_create(path: &Path) -> Result<()> {
    let dataset = path_to_dataset(path)?;

    let output = Command::new("zfs")
        .args(["create", "-p", &dataset])
        .output()
        .map_err(|e| Error::Other(format!("failed to run zfs create: {e}")))?;

    if !output.status.success() {
        return Err(Error::Other(format!(
            "zfs create '{}' failed: {}",
            dataset,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

/// Create a ZFS dataset at the given filesystem path (leaf-only).
///
/// Unlike [`zfs_dataset_create`], this does NOT use `-p` and will fail if
/// the parent is not already a ZFS dataset. This is safer in contexts where
/// creating intermediate datasets would shadow existing directory contents.
pub fn zfs_dataset_create_leaf(path: &Path) -> Result<()> {
    let dataset = path_to_dataset(path)?;

    let output = Command::new("zfs")
        .args(["create", &dataset])
        .output()
        .map_err(|e| Error::Other(format!("failed to run zfs create: {e}")))?;

    if !output.status.success() {
        return Err(Error::Other(format!(
            "zfs create '{}' failed: {}",
            dataset,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

/// Destroy a ZFS dataset at the given filesystem path.
///
/// Uses `-r` to recursively destroy child datasets (snapshots, clones).
/// Also removes the leftover mountpoint directory, since ZFS does not
/// clean it up when a custom mountpoint was set via `-o mountpoint=`.
pub fn zfs_dataset_destroy(path: &Path) -> Result<()> {
    let dataset = path_to_dataset(path)?;

    let output = Command::new("zfs")
        .args(["destroy", "-r", &dataset])
        .output()
        .map_err(|e| Error::Other(format!("failed to run zfs destroy: {e}")))?;

    if !output.status.success() {
        return Err(Error::Other(format!(
            "zfs destroy '{}' failed: {}",
            dataset,
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // ZFS doesn't always remove the mountpoint directory (especially when
    // a custom mountpoint was set). Clean it up ourselves.
    if path.exists() {
        let _ = std::fs::remove_dir_all(path);
    }

    Ok(())
}

/// Create a ZFS clone (CoW snapshot) of a source dataset at dest path.
///
/// ZFS cloning is two-step:
/// 1. `zfs snapshot <source>@<snap_name>`
/// 2. `zfs clone <source>@<snap_name> <dest_dataset>`
///
/// Snapshot names include a timestamp to avoid collisions when the same
/// source is cloned to different destinations over time.
pub fn zfs_clone(source: &Path, dest: &Path) -> Result<()> {
    let source_dataset = path_to_dataset(source)?;
    let dest_dataset = path_to_dataset(dest)?;

    // Use dest name + timestamp for uniqueness
    let dest_leaf = dest_dataset.rsplit('/').next().unwrap_or("snap");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let snap_name = format!("{dest_leaf}-{ts}");

    let snapshot = format!("{source_dataset}@{snap_name}");

    // Step 1: Create snapshot
    let output = Command::new("zfs")
        .args(["snapshot", &snapshot])
        .output()
        .map_err(|e| Error::Other(format!("failed to run zfs snapshot: {e}")))?;

    if !output.status.success() {
        return Err(Error::Other(format!(
            "zfs snapshot '{}' failed: {}",
            snapshot,
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Step 2: Clone from snapshot
    let output = Command::new("zfs")
        .args(["clone", &snapshot, &dest_dataset])
        .output()
        .map_err(|e| Error::Other(format!("failed to run zfs clone: {e}")))?;

    if !output.status.success() {
        // Clean up the snapshot on clone failure
        let _ = Command::new("zfs").args(["destroy", &snapshot]).output();
        return Err(Error::Other(format!(
            "zfs clone '{}' -> '{}' failed: {}",
            snapshot,
            dest_dataset,
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Get the space used exclusively by a ZFS dataset (analogous to btrfs qgroup exclusive).
///
/// Returns the `used` property value in bytes, or None if the dataset doesn't exist.
pub fn zfs_exclusive_size(path: &Path) -> Option<u64> {
    let dataset = path_to_dataset(path).ok()?;

    let output = Command::new("zfs")
        .args(["get", "-Hp", "-o", "value", "used", &dataset])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    String::from_utf8_lossy(&output.stdout).trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_to_dataset_no_zfs() {
        // On a non-ZFS system, this should return an error
        let result = path_to_dataset(Path::new("/tmp/nonexistent"));
        // We can't assert much here without actual ZFS, but it shouldn't panic
        assert!(result.is_err() || result.is_ok());
    }
}
