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

use crate::storage::layers;
use sandbox_proto::{ImageConfigDetail, ImageDetail, ImageInfo, LayerDetailInfo, LayerSummary};

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
pub fn list_images(
    pool: &StoragePool,
    show_size: bool,
    show_exclusive: bool,
    show_layers: bool,
) -> Result<Vec<ImageInfo>> {
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

        // Load image metadata (if available)
        let meta = layers::load_image_meta(pool, &name);

        let layer_count = meta.as_ref().map(|m| m.chain_ids.len() as u32).unwrap_or(0);

        let source = meta
            .as_ref()
            .map(|m| match &m.source {
                layers::ImageSource::OciPull => "oci-pull".to_string(),
                layers::ImageSource::Import => "import".to_string(),
                layers::ImageSource::Snapshot { .. } => "snapshot".to_string(),
            })
            .unwrap_or_else(|| "import".to_string());

        let size_bytes = if show_size {
            Some(dir_size(&path).unwrap_or(0))
        } else {
            None
        };

        let exclusive_bytes = if show_exclusive {
            btrfs_exclusive_size(&path)
        } else {
            None
        };

        let layer_summaries = if show_layers {
            build_layer_summaries(pool, &meta, &name, show_size)
        } else {
            Vec::new()
        };

        images.push(ImageInfo {
            name,
            pool: pool.name.clone(),
            size_bytes,
            exclusive_bytes,
            layer_count,
            source,
            layers: layer_summaries,
        });
    }

    images.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(images)
}

/// Inspect an image — detailed info including layer details.
pub fn inspect_image(pool: &StoragePool, name: &str) -> Result<ImageDetail> {
    let path = pool.image_path(name);
    if !path.is_dir() {
        return Err(Error::Other(format!("image '{name}' not found")));
    }

    let meta = layers::load_image_meta(pool, name);
    let size_bytes = dir_size(&path).unwrap_or(0);

    let source = meta
        .as_ref()
        .map(|m| match &m.source {
            layers::ImageSource::OciPull => "oci-pull".to_string(),
            layers::ImageSource::Import => "import".to_string(),
            layers::ImageSource::Snapshot { container } => {
                format!("snapshot (container: {container})")
            }
        })
        .unwrap_or_else(|| "import".to_string());

    let reference = meta
        .as_ref()
        .map(|m| m.reference.clone())
        .unwrap_or_default();

    let config = meta
        .as_ref()
        .map(|m| ImageConfigDetail {
            entrypoint: m.config.entrypoint.clone(),
            cmd: m.config.cmd.clone(),
            env: m.config.env.clone(),
            working_dir: m.config.working_dir.clone(),
            user: m.config.user.clone(),
        })
        .unwrap_or_else(|| ImageConfigDetail {
            entrypoint: Vec::new(),
            cmd: Vec::new(),
            env: Vec::new(),
            working_dir: "/".to_string(),
            user: None,
        });

    let layer_details = if let Some(ref m) = meta {
        build_layer_details(pool, m, name)
    } else {
        Vec::new()
    };

    Ok(ImageDetail {
        name: name.to_string(),
        pool: pool.name.clone(),
        size_bytes,
        source,
        reference,
        config,
        layers: layer_details,
    })
}

/// Build layer summaries for list --layers view.
fn build_layer_summaries(
    pool: &StoragePool,
    meta: &Option<layers::ImageMeta>,
    image_name: &str,
    show_size: bool,
) -> Vec<LayerSummary> {
    let meta = match meta {
        Some(m) => m,
        None => return Vec::new(),
    };

    meta.chain_ids
        .iter()
        .map(|chain_id| {
            let size_bytes = if show_size {
                let layer_path = pool
                    .path
                    .join("layers")
                    .join(layers::safe_name_pub(chain_id));
                if layer_path.is_dir() {
                    Some(dir_size(&layer_path).unwrap_or(0))
                } else {
                    None
                }
            } else {
                None
            };

            let shared_with = layers::layer_shared_with(pool, chain_id, image_name);

            LayerSummary {
                chain_id: chain_id.clone(),
                size_bytes,
                shared_with,
            }
        })
        .collect()
}

/// Build layer details for inspect view.
fn build_layer_details(
    pool: &StoragePool,
    meta: &layers::ImageMeta,
    image_name: &str,
) -> Vec<LayerDetailInfo> {
    meta.chain_ids
        .iter()
        .enumerate()
        .map(|(i, chain_id)| {
            let diff_id = meta
                .diff_ids
                .get(i)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());

            let layer_path = pool
                .path
                .join("layers")
                .join(layers::safe_name_pub(chain_id));
            let size_bytes = if layer_path.is_dir() {
                dir_size(&layer_path).unwrap_or(0)
            } else {
                0
            };

            let shared_with = layers::layer_shared_with(pool, chain_id, image_name);

            LayerDetailInfo {
                chain_id: chain_id.clone(),
                diff_id,
                size_bytes,
                shared_with,
            }
        })
        .collect()
}

/// Get exclusive size of a btrfs subvolume using qgroup.
/// Returns None if not btrfs or quotas not enabled.
fn btrfs_exclusive_size(path: &Path) -> Option<u64> {
    let output = Command::new("btrfs")
        .args(["qgroup", "show", "--raw", "-f", "--"])
        .arg(path)
        .output()
        .ok()?;

    if !output.status.success() {
        return None; // quotas not enabled or not btrfs
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse the last data line: "0/NNN    <rfer>    <excl>"
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("0/") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                return parts[2].parse().ok();
            }
        }
    }

    None
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
