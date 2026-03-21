//! Named volume management.
//!
//! Volumes are persistent filesystems stored in `<pool>/volumes/<name>/`.
//! On btrfs/bcachefs, they are subvolumes. On ZFS, they are datasets.
//! On ext4/xfs, plain directories.

use crate::error::{Error, Result};
use crate::storage::StoragePool;
use crate::storage::container_fs;
use crate::storage::fs_detect::FsType;
use crate::storage::zfs;
use sandbox_proto::VolumeInfo;
use std::fs;

/// Create a named volume.
pub fn create_volume(pool: &StoragePool, name: &str) -> Result<()> {
    validate_name(name)?;
    let path = volume_path(pool, name);

    if path.exists() {
        return Err(Error::Other(format!("volume '{name}' already exists")));
    }

    match pool.fs_type {
        FsType::Btrfs => container_fs::btrfs_subvolume_create(&path)?,
        FsType::Bcachefs => container_fs::bcachefs_subvolume_create(&path)?,
        FsType::Zfs => zfs::zfs_dataset_create_leaf(&path)?,
        _ => {
            fs::create_dir_all(&path)
                .map_err(|e| Error::Other(format!("mkdir {}: {e}", path.display())))?;
        }
    }

    tracing::info!("created volume '{name}'");
    Ok(())
}

/// Remove a named volume.
pub fn remove_volume(pool: &StoragePool, name: &str) -> Result<()> {
    let path = volume_path(pool, name);

    if !path.exists() {
        return Err(Error::Other(format!("volume '{name}' not found")));
    }

    match pool.fs_type {
        FsType::Btrfs => container_fs::btrfs_subvolume_delete(&path)?,
        FsType::Bcachefs => container_fs::bcachefs_subvolume_delete(&path)?,
        FsType::Zfs => zfs::zfs_dataset_destroy(&path)?,
        _ => {
            fs::remove_dir_all(&path)
                .map_err(|e| Error::Other(format!("rm {}: {e}", path.display())))?;
        }
    }

    tracing::info!("removed volume '{name}'");
    Ok(())
}

/// List all volumes in a pool.
pub fn list_volumes(pool: &StoragePool) -> Result<Vec<VolumeInfo>> {
    let dir = volumes_dir(pool);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut volumes = Vec::new();
    for entry in
        fs::read_dir(&dir).map_err(|e| Error::Other(format!("readdir {}: {e}", dir.display())))?
    {
        let entry = entry.map_err(|e| Error::Other(format!("readdir: {e}")))?;
        if entry.path().is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            volumes.push(VolumeInfo {
                name,
                pool: pool.name.clone(),
            });
        }
    }

    volumes.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(volumes)
}

/// Get the path to a volume's data directory.
pub fn volume_path(pool: &StoragePool, name: &str) -> std::path::PathBuf {
    volumes_dir(pool).join(name)
}

/// Get the volumes directory for a pool.
fn volumes_dir(pool: &StoragePool) -> std::path::PathBuf {
    pool.path.join("volumes")
}

/// Ensure the volumes directory exists.
///
/// On ZFS, creates a dataset so that child datasets (one per volume)
/// can be created under it.
pub fn ensure_volumes_dir(pool: &StoragePool) -> Result<()> {
    let dir = volumes_dir(pool);
    if dir.exists() {
        return Ok(());
    }
    match pool.fs_type {
        FsType::Zfs => zfs::zfs_dataset_create_leaf(&dir),
        _ => fs::create_dir_all(&dir)
            .map_err(|e| Error::Other(format!("mkdir {}: {e}", dir.display()))),
    }
}

/// Validate a volume name.
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::Other("volume name cannot be empty".into()));
    }
    if name.starts_with('.') || name.starts_with('-') {
        return Err(Error::Other(format!(
            "volume name cannot start with '.' or '-': {name}"
        )));
    }
    if name.contains('/') || name.contains('\0') {
        return Err(Error::Other(format!(
            "volume name cannot contain '/' or null: {name}"
        )));
    }
    Ok(())
}
