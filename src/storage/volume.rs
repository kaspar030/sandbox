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

/// List all volumes in a pool (both filesystem and block).
pub fn list_volumes(pool: &StoragePool) -> Result<Vec<VolumeInfo>> {
    let dir = volumes_dir(pool);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut volumes = Vec::new();
    let mut block_names: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Detect block volumes from .block.json sidecar files
    for entry in
        fs::read_dir(&dir).map_err(|e| Error::Other(format!("readdir {}: {e}", dir.display())))?
    {
        let entry = entry.map_err(|e| Error::Other(format!("readdir: {e}")))?;
        let file_name = entry.file_name().to_string_lossy().to_string();
        if let Some(name) = file_name.strip_suffix(".block.json") {
            if let Ok(meta) = load_block_meta(pool, name) {
                block_names.insert(name.to_string());
                volumes.push(VolumeInfo {
                    name: name.to_string(),
                    pool: pool.name.clone(),
                    volume_type: sandbox_proto::VolumeType::Block,
                    size: Some(meta.size),
                });
            }
        }
    }

    // List directory-based (filesystem) volumes, excluding block volume names
    for entry in
        fs::read_dir(&dir).map_err(|e| Error::Other(format!("readdir {}: {e}", dir.display())))?
    {
        let entry = entry.map_err(|e| Error::Other(format!("readdir: {e}")))?;
        if entry.path().is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !block_names.contains(&name) {
                volumes.push(VolumeInfo {
                    name,
                    pool: pool.name.clone(),
                    volume_type: sandbox_proto::VolumeType::Filesystem,
                    size: None,
                });
            }
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

// -- Block volume support --

fn block_meta_path(pool: &StoragePool, name: &str) -> std::path::PathBuf {
    volumes_dir(pool).join(format!("{name}.block.json"))
}

fn block_img_path(pool: &StoragePool, name: &str) -> std::path::PathBuf {
    volumes_dir(pool).join(format!("{name}.img"))
}

pub fn load_block_meta(pool: &StoragePool, name: &str) -> Result<sandbox_proto::BlockVolumeMeta> {
    let path = block_meta_path(pool, name);
    let json = fs::read_to_string(&path)
        .map_err(|e| Error::Other(format!("read {}: {e}", path.display())))?;
    serde_json::from_str(&json).map_err(|e| Error::Other(format!("parse {}: {e}", path.display())))
}

fn save_block_meta(
    pool: &StoragePool,
    name: &str,
    meta: &sandbox_proto::BlockVolumeMeta,
) -> Result<()> {
    let path = block_meta_path(pool, name);
    let json = serde_json::to_string_pretty(meta)
        .map_err(|e| Error::Other(format!("serialize block meta: {e}")))?;
    fs::write(&path, json).map_err(|e| Error::Other(format!("write {}: {e}", path.display())))
}

pub fn is_block_volume(pool: &StoragePool, name: &str) -> bool {
    block_meta_path(pool, name).exists()
}

/// Create a block volume (ZFS zvol or loop-backed sparse file).
pub fn create_block_volume(
    pool: &StoragePool,
    name: &str,
    size: u64,
    format: Option<&str>,
) -> Result<()> {
    validate_name(name)?;
    ensure_volumes_dir(pool)?;
    if block_meta_path(pool, name).exists() || volume_path(pool, name).exists() {
        return Err(Error::Other(format!("volume '{name}' already exists")));
    }

    let meta = match pool.fs_type {
        FsType::Zfs => create_block_zvol(pool, name, size)?,
        _ => create_block_loop(pool, name, size)?,
    };

    if let Some(fstype) = format {
        let device = get_device_from_meta(&meta)?;
        run_mkfs(&device, fstype)?;
        // Flush filesystem metadata to the backing file before detaching
        let _ = std::process::Command::new("sync").output();
        release_device_from_meta(&meta);
        let mut meta = meta;
        meta.format = Some(fstype.to_string());
        save_block_meta(pool, name, &meta)?;
    } else {
        save_block_meta(pool, name, &meta)?;
    }

    tracing::info!("created block volume '{name}' ({size} bytes)");
    Ok(())
}

fn create_block_zvol(
    pool: &StoragePool,
    name: &str,
    size: u64,
) -> Result<sandbox_proto::BlockVolumeMeta> {
    let dataset = zfs::path_to_dataset(&volumes_dir(pool).join(name))?;
    let output = std::process::Command::new("zfs")
        .args(["create", "-s", "-V", &size.to_string(), &dataset])
        .output()
        .map_err(|e| Error::Other(format!("zfs create -V failed: {e}")))?;
    if !output.status.success() {
        return Err(Error::Other(format!(
            "zfs create -V failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let _ = std::process::Command::new("udevadm").arg("settle").output();
    Ok(sandbox_proto::BlockVolumeMeta {
        size,
        format: None,
        backing: "zvol".to_string(),
        loop_file: None,
        zvol_dataset: Some(dataset),
    })
}

fn create_block_loop(
    pool: &StoragePool,
    name: &str,
    size: u64,
) -> Result<sandbox_proto::BlockVolumeMeta> {
    let img_path = block_img_path(pool, name);
    fs::File::create(&img_path)
        .map_err(|e| Error::Other(format!("create {}: {e}", img_path.display())))?;
    if matches!(pool.fs_type, FsType::Btrfs | FsType::Bcachefs) {
        let _ = std::process::Command::new("chattr")
            .args(["+C", &img_path.to_string_lossy()])
            .output();
    }
    let output = std::process::Command::new("truncate")
        .args(["-s", &size.to_string()])
        .arg(&img_path)
        .output()
        .map_err(|e| Error::Other(format!("truncate failed: {e}")))?;
    if !output.status.success() {
        let _ = fs::remove_file(&img_path);
        return Err(Error::Other(format!(
            "truncate failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(sandbox_proto::BlockVolumeMeta {
        size,
        format: None,
        backing: "loop".to_string(),
        loop_file: Some(img_path.to_string_lossy().to_string()),
        zvol_dataset: None,
    })
}

fn run_mkfs(device: &str, fstype: &str) -> Result<()> {
    let prog = format!("mkfs.{fstype}");
    let output = std::process::Command::new(&prog)
        .args(["-F", device])
        .output()
        .map_err(|e| Error::Other(format!("{prog} failed: {e}")))?;
    if !output.status.success() {
        return Err(Error::Other(format!(
            "{prog} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

pub fn get_block_device_path(pool: &StoragePool, name: &str) -> Result<String> {
    let meta = load_block_meta(pool, name)?;
    get_device_from_meta(&meta)
}

fn get_device_from_meta(meta: &sandbox_proto::BlockVolumeMeta) -> Result<String> {
    match meta.backing.as_str() {
        "zvol" => {
            let dataset = meta
                .zvol_dataset
                .as_ref()
                .ok_or_else(|| Error::Other("zvol metadata missing dataset".into()))?;
            let dev = format!("/dev/zvol/{dataset}");
            if !std::path::Path::new(&dev).exists() {
                return Err(Error::Other(format!("zvol device not found: {dev}")));
            }
            Ok(dev)
        }
        "loop" => {
            let img = meta
                .loop_file
                .as_ref()
                .ok_or_else(|| Error::Other("loop metadata missing file path".into()))?;
            if let Some(dev) = find_loop_device(img)? {
                return Ok(dev);
            }
            attach_loop_device(img)
        }
        other => Err(Error::Other(format!("unknown block backing: {other}"))),
    }
}

pub fn release_block_device(pool: &StoragePool, name: &str) {
    if let Ok(meta) = load_block_meta(pool, name) {
        release_device_from_meta(&meta);
    }
}

fn release_device_from_meta(meta: &sandbox_proto::BlockVolumeMeta) {
    if meta.backing == "loop" {
        if let Some(ref img) = meta.loop_file {
            if let Ok(Some(dev)) = find_loop_device(img) {
                let _ = detach_loop_device(&dev);
            }
        }
    }
}

pub fn remove_block_volume(pool: &StoragePool, name: &str) -> Result<()> {
    let meta = load_block_meta(pool, name)?;
    release_device_from_meta(&meta);
    match meta.backing.as_str() {
        "zvol" => {
            if let Some(ref dataset) = meta.zvol_dataset {
                let output = std::process::Command::new("zfs")
                    .args(["destroy", "-r", dataset])
                    .output()
                    .map_err(|e| Error::Other(format!("zfs destroy failed: {e}")))?;
                if !output.status.success() {
                    return Err(Error::Other(format!(
                        "zfs destroy failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )));
                }
            }
        }
        "loop" => {
            if let Some(ref img) = meta.loop_file {
                let _ = fs::remove_file(img);
            }
        }
        _ => {}
    }
    let _ = fs::remove_file(block_meta_path(pool, name));
    tracing::info!("removed block volume '{name}'");
    Ok(())
}

pub fn find_loop_for_file(img_path: &str) -> Result<Option<String>> {
    find_loop_device(img_path)
}

fn find_loop_device(img_path: &str) -> Result<Option<String>> {
    let output = std::process::Command::new("losetup")
        .args(["-j", img_path])
        .output()
        .map_err(|e| Error::Other(format!("losetup -j failed: {e}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Some(line) = stdout.lines().next() {
        if let Some(dev) = line.split(':').next() {
            let dev = dev.trim();
            if !dev.is_empty() {
                return Ok(Some(dev.to_string()));
            }
        }
    }
    Ok(None)
}

fn attach_loop_device(img_path: &str) -> Result<String> {
    let output = std::process::Command::new("losetup")
        .args(["--find", "--show", img_path])
        .output()
        .map_err(|e| Error::Other(format!("losetup --find failed: {e}")))?;
    if !output.status.success() {
        return Err(Error::Other(format!(
            "losetup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let dev = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if dev.is_empty() {
        return Err(Error::Other("losetup returned empty device".into()));
    }
    Ok(dev)
}

fn detach_loop_device(dev: &str) -> Result<()> {
    let output = std::process::Command::new("losetup")
        .args(["-d", dev])
        .output()
        .map_err(|e| Error::Other(format!("losetup -d failed: {e}")))?;
    if !output.status.success() {
        return Err(Error::Other(format!(
            "losetup -d failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
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
