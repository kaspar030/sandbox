//! Container and volume checkpoint snapshots.
//!
//! Snapshots capture a container's rootfs (and optionally its volumes) as
//! CoW snapshots on btrfs/bcachefs/zfs, or as cp -a copies on other filesystems.
//!
//! Layout:
//!   <pool>/snapshots/<container>/<snap-name>/rootfs/       — rootfs snapshot
//!   <pool>/snapshots/<container>/<snap-name>/vol-<name>/   — volume snapshot
//!   <pool>/snapshots/<container>/<snap-name>/manifest.json — snapshot metadata

use crate::error::{Error, Result};
use crate::storage::StoragePool;
use crate::storage::container_fs::{bcachefs_subvolume_delete, btrfs_subvolume_delete};
use crate::storage::fs_detect::FsType;
use crate::storage::volume;
use crate::storage::zfs;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Snapshot manifest — metadata stored alongside the filesystem snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotManifest {
    /// Snapshot name.
    pub name: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Container name.
    pub container: String,
    /// Full container spec at snapshot time.
    pub spec: sandbox_proto::ContainerSpec,
    /// Volume names included in this snapshot.
    pub volumes: Vec<String>,
    /// Pool name.
    pub pool: String,
}

// -- Directory helpers --

/// Root directory for all snapshots in a pool.
fn snapshots_dir(pool: &StoragePool) -> PathBuf {
    pool.path.join("snapshots")
}

/// Directory for a specific container's snapshots.
fn container_snapshots_dir(pool: &StoragePool, container_name: &str) -> PathBuf {
    snapshots_dir(pool).join(container_name)
}

/// Directory for a specific snapshot.
fn snapshot_dir(pool: &StoragePool, container_name: &str, snapshot_name: &str) -> PathBuf {
    container_snapshots_dir(pool, container_name).join(snapshot_name)
}

/// Path to the rootfs snapshot within a snapshot directory.
fn snapshot_rootfs_path(pool: &StoragePool, container_name: &str, snapshot_name: &str) -> PathBuf {
    snapshot_dir(pool, container_name, snapshot_name).join("rootfs")
}

/// Path to a volume snapshot within a snapshot directory.
fn snapshot_volume_path(
    pool: &StoragePool,
    container_name: &str,
    snapshot_name: &str,
    volume_name: &str,
) -> PathBuf {
    snapshot_dir(pool, container_name, snapshot_name).join(format!("vol-{volume_name}"))
}

/// Path to the manifest file within a snapshot directory.
fn manifest_path(pool: &StoragePool, container_name: &str, snapshot_name: &str) -> PathBuf {
    snapshot_dir(pool, container_name, snapshot_name).join("manifest.json")
}

// -- Ensure directories --

/// Ensure the snapshots directory structure exists for a container.
fn ensure_snapshot_dirs(
    pool: &StoragePool,
    container_name: &str,
    snapshot_name: &str,
) -> Result<()> {
    let dir = snapshot_dir(pool, container_name, snapshot_name);
    // On ZFS, snapshot dirs are regular directories (not datasets).
    // The actual snapshots (rootfs, volumes) inside are created as datasets/clones.
    fs::create_dir_all(&dir).map_err(|e| {
        Error::Other(format!(
            "failed to create snapshot directory {}: {e}",
            dir.display()
        ))
    })
}

// -- Snapshot operations --

/// Create a CoW snapshot of a source path to a destination path.
fn cow_snapshot(pool: &StoragePool, source: &Path, dest: &Path) -> Result<()> {
    match pool.fs_type {
        FsType::Btrfs => {
            let status = Command::new("btrfs")
                .args(["subvolume", "snapshot", "--"])
                .arg(source)
                .arg(dest)
                .status()
                .map_err(|e| Error::Other(format!("failed to run btrfs: {e}")))?;
            if !status.success() {
                return Err(Error::Other(format!(
                    "btrfs subvolume snapshot failed: {:?}",
                    status.code()
                )));
            }
            Ok(())
        }
        FsType::Bcachefs => {
            let status = Command::new("bcachefs")
                .args(["subvolume", "snapshot"])
                .arg(source)
                .arg(dest)
                .status()
                .map_err(|e| Error::Other(format!("failed to run bcachefs: {e}")))?;
            if !status.success() {
                return Err(Error::Other(format!(
                    "bcachefs subvolume snapshot failed: {:?}",
                    status.code()
                )));
            }
            Ok(())
        }
        FsType::Zfs => zfs::zfs_clone(source, dest),
        _ => {
            // Fallback: cp -a --reflink=auto
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
    }
}

/// Delete a subvolume/dataset/directory (per filesystem type).
fn cow_delete(pool: &StoragePool, path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    match pool.fs_type {
        FsType::Btrfs => btrfs_subvolume_delete(path),
        FsType::Bcachefs => bcachefs_subvolume_delete(path),
        FsType::Zfs => zfs::zfs_dataset_destroy(path),
        _ => fs::remove_dir_all(path)
            .map_err(|e| Error::Other(format!("failed to remove {}: {e}", path.display()))),
    }
}

// -- Public API --

/// Snapshot a container's rootfs.
pub fn snapshot_rootfs(
    pool: &StoragePool,
    container_name: &str,
    snapshot_name: &str,
) -> Result<()> {
    let source = pool.container_path(container_name);
    if !source.is_dir() {
        return Err(Error::Other(format!(
            "container rootfs '{}' not found",
            source.display()
        )));
    }

    ensure_snapshot_dirs(pool, container_name, snapshot_name)?;
    let dest = snapshot_rootfs_path(pool, container_name, snapshot_name);
    if dest.exists() {
        return Err(Error::Other(format!(
            "snapshot '{snapshot_name}' already exists for container '{container_name}'"
        )));
    }

    cow_snapshot(pool, &source, &dest)?;
    tracing::info!("snapshotted rootfs of '{container_name}' as '{snapshot_name}'");
    Ok(())
}

/// Snapshot a named volume.
pub fn snapshot_volume(
    pool: &StoragePool,
    volume_name: &str,
    container_name: &str,
    snapshot_name: &str,
) -> Result<()> {
    let source = volume::volume_path(pool, volume_name);
    if !source.is_dir() {
        return Err(Error::Other(format!(
            "volume '{}' not found at {}",
            volume_name,
            source.display()
        )));
    }

    ensure_snapshot_dirs(pool, container_name, snapshot_name)?;
    let dest = snapshot_volume_path(pool, container_name, snapshot_name, volume_name);
    if dest.exists() {
        return Err(Error::Other(format!(
            "volume snapshot '{volume_name}' already exists in snapshot '{snapshot_name}'"
        )));
    }

    cow_snapshot(pool, &source, &dest)?;
    tracing::info!("snapshotted volume '{volume_name}' in snapshot '{snapshot_name}'");
    Ok(())
}

/// Restore a container's rootfs from a snapshot.
///
/// Deletes the current rootfs and replaces it with a writable clone of the snapshot.
pub fn restore_rootfs(pool: &StoragePool, container_name: &str, snapshot_name: &str) -> Result<()> {
    let current = pool.container_path(container_name);
    let saved = snapshot_rootfs_path(pool, container_name, snapshot_name);

    if !saved.exists() {
        return Err(Error::Other(format!(
            "snapshot rootfs not found: {}",
            saved.display()
        )));
    }

    // Delete current rootfs
    if current.exists() {
        cow_delete(pool, &current)?;
    }

    // Clone the snapshot back to the container path
    cow_snapshot(pool, &saved, &current)?;
    tracing::info!("restored rootfs of '{container_name}' from snapshot '{snapshot_name}'");
    Ok(())
}

/// Restore a named volume from a snapshot.
pub fn restore_volume(
    pool: &StoragePool,
    volume_name: &str,
    container_name: &str,
    snapshot_name: &str,
) -> Result<()> {
    let current = volume::volume_path(pool, volume_name);
    let saved = snapshot_volume_path(pool, container_name, snapshot_name, volume_name);

    if !saved.exists() {
        return Err(Error::Other(format!(
            "volume snapshot '{volume_name}' not found in snapshot '{snapshot_name}'"
        )));
    }

    // Delete current volume
    if current.exists() {
        cow_delete(pool, &current)?;
    }

    // Clone the snapshot back
    cow_snapshot(pool, &saved, &current)?;
    tracing::info!("restored volume '{volume_name}' from snapshot '{snapshot_name}'");
    Ok(())
}

/// Delete a snapshot (rootfs + volumes + manifest).
pub fn delete_snapshot(
    pool: &StoragePool,
    container_name: &str,
    snapshot_name: &str,
) -> Result<()> {
    let dir = snapshot_dir(pool, container_name, snapshot_name);
    if !dir.exists() {
        return Err(Error::Other(format!(
            "snapshot '{snapshot_name}' not found for container '{container_name}'"
        )));
    }

    // Read manifest to find volume snapshots
    if let Ok(manifest) = read_manifest(pool, container_name, snapshot_name) {
        for vol in &manifest.volumes {
            let vol_path = snapshot_volume_path(pool, container_name, snapshot_name, vol);
            if vol_path.exists() {
                cow_delete(pool, &vol_path)?;
            }
        }
    }

    // Delete rootfs snapshot
    let rootfs = snapshot_rootfs_path(pool, container_name, snapshot_name);
    if rootfs.exists() {
        cow_delete(pool, &rootfs)?;
    }

    // Remove the snapshot directory
    fs::remove_dir_all(&dir).map_err(|e| {
        Error::Other(format!(
            "failed to remove snapshot directory {}: {e}",
            dir.display()
        ))
    })?;

    tracing::info!("deleted snapshot '{snapshot_name}' for container '{container_name}'");
    Ok(())
}

/// List all snapshots for a container.
pub fn list_snapshots(pool: &StoragePool, container_name: &str) -> Result<Vec<String>> {
    let dir = container_snapshots_dir(pool, container_name);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut names = Vec::new();
    for entry in fs::read_dir(&dir)
        .map_err(|e| Error::Other(format!("failed to read {}: {e}", dir.display())))?
    {
        let entry = entry.map_err(|e| Error::Other(format!("readdir error: {e}")))?;
        if entry.path().is_dir() {
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
    }
    names.sort();
    Ok(names)
}

/// Calculate the total size of a snapshot directory (rootfs + volumes + manifest).
pub fn snapshot_size(
    pool: &StoragePool,
    container_name: &str,
    snapshot_name: &str,
) -> std::io::Result<u64> {
    let dir = snapshot_dir(pool, container_name, snapshot_name);
    dir_size(&dir)
}

/// Calculate the total size of a directory tree (recursive).
fn dir_size(path: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_dir() {
                total += dir_size(&entry.path())?;
            } else {
                total += meta.len();
            }
        }
    }
    Ok(total)
}

/// Write a snapshot manifest.
pub fn write_manifest(
    pool: &StoragePool,
    container_name: &str,
    snapshot_name: &str,
    manifest: &SnapshotManifest,
) -> Result<()> {
    let path = manifest_path(pool, container_name, snapshot_name);
    let json = serde_json::to_string_pretty(manifest)
        .map_err(|e| Error::Other(format!("failed to serialize manifest: {e}")))?;
    fs::write(&path, json)
        .map_err(|e| Error::Other(format!("failed to write manifest {}: {e}", path.display())))
}

/// Read a snapshot manifest.
pub fn read_manifest(
    pool: &StoragePool,
    container_name: &str,
    snapshot_name: &str,
) -> Result<SnapshotManifest> {
    let path = manifest_path(pool, container_name, snapshot_name);
    let json = fs::read_to_string(&path)
        .map_err(|e| Error::Other(format!("failed to read manifest {}: {e}", path.display())))?;
    serde_json::from_str(&json).map_err(|e| Error::Other(format!("failed to parse manifest: {e}")))
}

/// Generate a snapshot name from the current timestamp.
pub fn generate_snapshot_name() -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("snap-{ts}")
}

/// Snapshot multiple ZFS datasets atomically in a single command.
///
/// Takes a list of (source_path, snapshot_suffix) pairs.
/// Executes: `zfs snapshot pool/ds1@suffix pool/ds2@suffix ...`
pub fn snapshot_multiple_zfs(sources: &[(PathBuf, String)], snapshot_suffix: &str) -> Result<()> {
    if sources.is_empty() {
        return Ok(());
    }

    let mut snap_args: Vec<String> = Vec::new();
    for (path, _) in sources {
        let dataset = zfs::path_to_dataset(path)?;
        snap_args.push(format!("{dataset}@{snapshot_suffix}"));
    }

    let mut cmd = Command::new("zfs");
    cmd.arg("snapshot");
    for arg in &snap_args {
        cmd.arg(arg);
    }

    let output = cmd
        .output()
        .map_err(|e| Error::Other(format!("failed to run zfs snapshot: {e}")))?;

    if !output.status.success() {
        return Err(Error::Other(format!(
            "zfs snapshot (atomic) failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    tracing::info!(
        "created {} atomic ZFS snapshots with suffix '{snapshot_suffix}'",
        snap_args.len()
    );
    Ok(())
}
