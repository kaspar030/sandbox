//! Image management — import, list, remove.
//!
//! An image is a rootfs directory stored under a storage pool's images/ directory.
//! Images can be imported from directories or .tar.gz archives.
//! Images are never mounted directly by containers — a copy/snapshot is made first.
//!
//! On btrfs/bcachefs pools, images are stored as subvolumes so that container
//! rootfs creation can use instant CoW snapshots.

use crate::error::{Error, Result};
use crate::storage::StoragePool;
use crate::storage::container_fs;
use crate::storage::fs_detect::FsType;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Information about a stored image.
#[derive(Debug, Clone)]
pub struct ImageInfo {
    pub name: String,
    pub pool: String,
    pub size_bytes: u64,
}

/// Import an image from a directory.
///
/// On btrfs/bcachefs: creates a subvolume, then copies contents into it.
/// On other filesystems: cp -a.
fn import_from_dir(pool: &StoragePool, name: &str, source: &Path) -> Result<()> {
    if !source.is_dir() {
        return Err(Error::Other(format!(
            "source is not a directory: {}",
            source.display()
        )));
    }

    let target = pool.image_path(name);
    if target.exists() {
        return Err(Error::Other(format!(
            "image '{name}' already exists in pool '{}'",
            pool.name
        )));
    }

    match pool.fs_type {
        FsType::Btrfs => {
            // Create subvolume, then copy contents into it
            container_fs::btrfs_subvolume_create(&target)?;
            let status = Command::new("cp")
                .args(["-a", "--reflink=auto", "-T", "--"])
                .arg(source)
                .arg(&target)
                .status()
                .map_err(|e| Error::Other(format!("failed to run cp: {e}")))?;
            if !status.success() {
                let _ = container_fs::btrfs_subvolume_delete(&target);
                return Err(Error::Other(format!(
                    "cp into btrfs subvolume failed with exit code {:?}",
                    status.code()
                )));
            }
        }
        FsType::Bcachefs => {
            container_fs::bcachefs_subvolume_create(&target)?;
            let status = Command::new("cp")
                .args(["-a", "--reflink=auto", "-T", "--"])
                .arg(source)
                .arg(&target)
                .status()
                .map_err(|e| Error::Other(format!("failed to run cp: {e}")))?;
            if !status.success() {
                let _ = container_fs::bcachefs_subvolume_delete(&target);
                return Err(Error::Other(format!(
                    "cp into bcachefs subvolume failed with exit code {:?}",
                    status.code()
                )));
            }
        }
        _ => {
            // Regular cp -a
            let status = Command::new("cp")
                .args(["-a", "--"])
                .arg(source)
                .arg(&target)
                .status()
                .map_err(|e| Error::Other(format!("failed to run cp: {e}")))?;
            if !status.success() {
                let _ = fs::remove_dir_all(&target);
                return Err(Error::Other(format!(
                    "cp failed with exit code {:?}",
                    status.code()
                )));
            }
        }
    }

    Ok(())
}

/// Import an image from a .tar.gz archive.
///
/// On btrfs/bcachefs: creates a subvolume, then extracts into it.
/// On other filesystems: creates a directory, then extracts.
fn import_from_tar(pool: &StoragePool, name: &str, source: &Path) -> Result<()> {
    if !source.is_file() {
        return Err(Error::Other(format!(
            "source is not a file: {}",
            source.display()
        )));
    }

    let target = pool.image_path(name);
    if target.exists() {
        return Err(Error::Other(format!(
            "image '{name}' already exists in pool '{}'",
            pool.name
        )));
    }

    // Create the target as a subvolume (btrfs/bcachefs) or directory (other)
    match pool.fs_type {
        FsType::Btrfs => container_fs::btrfs_subvolume_create(&target)?,
        FsType::Bcachefs => container_fs::bcachefs_subvolume_create(&target)?,
        _ => {
            fs::create_dir_all(&target)
                .map_err(|e| Error::Other(format!("failed to create {}: {e}", target.display())))?;
        }
    }

    // Determine tar flags based on file extension
    let tar_flag = if let Some(name) = source.file_name().and_then(|n| n.to_str()) {
        if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
            "xzf"
        } else if name.ends_with(".tar.xz") {
            "xJf"
        } else if name.ends_with(".tar.bz2") {
            "xjf"
        } else {
            "xf"
        }
    } else {
        "xf"
    };

    let status = Command::new("tar")
        .arg(tar_flag)
        .arg(source)
        .arg("-C")
        .arg(&target)
        .args(["--same-owner"])
        .status()
        .map_err(|e| Error::Other(format!("failed to run tar: {e}")))?;

    if !status.success() {
        // Clean up on failure
        match pool.fs_type {
            FsType::Btrfs => {
                let _ = container_fs::btrfs_subvolume_delete(&target);
            }
            FsType::Bcachefs => {
                let _ = container_fs::bcachefs_subvolume_delete(&target);
            }
            _ => {
                let _ = fs::remove_dir_all(&target);
            }
        }
        return Err(Error::Other(format!(
            "tar extraction failed with exit code {:?}",
            status.code()
        )));
    }

    Ok(())
}

/// Import an image from a directory or .tar.gz, auto-detecting the type.
pub fn import(pool: &StoragePool, name: &str, source: &Path) -> Result<()> {
    validate_image_name(name)?;

    if source.is_dir() {
        import_from_dir(pool, name, source)
    } else if is_tar_archive(source) {
        import_from_tar(pool, name, source)
    } else {
        Err(Error::Other(format!(
            "source must be a directory or .tar.gz file: {}",
            source.display()
        )))
    }
}

/// List all images in a pool.
pub fn list_images(pool: &StoragePool) -> Result<Vec<ImageInfo>> {
    let images_dir = pool.images_dir();
    if !images_dir.exists() {
        return Ok(Vec::new());
    }

    let mut images = Vec::new();
    for entry in fs::read_dir(&images_dir)
        .map_err(|e| Error::Other(format!("failed to read {}: {e}", images_dir.display())))?
    {
        let entry = entry.map_err(|e| Error::Other(format!("readdir error: {e}")))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let name = entry.file_name().to_str().unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }

        let size_bytes = dir_size(&path).unwrap_or(0);

        images.push(ImageInfo {
            name,
            pool: pool.name.clone(),
            size_bytes,
        });
    }

    images.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(images)
}

/// Remove an image.
///
/// On btrfs/bcachefs: uses subvolume delete.
/// On other filesystems: rm -rf.
pub fn remove_image(pool: &StoragePool, name: &str) -> Result<()> {
    let path = pool.image_path(name);
    if !path.exists() {
        return Err(Error::Other(format!(
            "image '{name}' not found in pool '{}'",
            pool.name
        )));
    }

    match pool.fs_type {
        FsType::Btrfs => container_fs::btrfs_subvolume_delete(&path)?,
        FsType::Bcachefs => container_fs::bcachefs_subvolume_delete(&path)?,
        _ => {
            fs::remove_dir_all(&path)
                .map_err(|e| Error::Other(format!("failed to remove image '{name}': {e}")))?;
        }
    }

    Ok(())
}

/// Check if an image exists in a pool.
pub fn image_exists(pool: &StoragePool, name: &str) -> bool {
    pool.image_path(name).is_dir()
}

/// Validate an image name (alphanumeric, hyphens, underscores).
fn validate_image_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::Other("image name cannot be empty".to_string()));
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(Error::Other(format!(
            "invalid image name '{name}': only alphanumeric, hyphens, underscores, and dots allowed"
        )));
    }
    Ok(())
}

/// Check if a file looks like a tar archive (by extension).
fn is_tar_archive(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.ends_with(".tar.gz")
        || name.ends_with(".tgz")
        || name.ends_with(".tar.xz")
        || name.ends_with(".tar.bz2")
        || name.ends_with(".tar")
}

/// Calculate the total size of a directory tree.
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
