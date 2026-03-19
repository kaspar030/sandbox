//! Layer-based storage with chain ID caching and reference counting.
//!
//! Each layer subvolume (or directory on non-CoW fs) represents the accumulated
//! rootfs after extracting layers 1..N. The key is the OCI chain ID:
//!
//!   chainID(L1) = diffID(L1)
//!   chainID(L1, L2) = sha256(chainID(L1) + " " + diffID(L2))
//!
//! Images reference their final chain ID. When two images share layers,
//! they share the same chain ID subvolumes.

use crate::error::{Error, Result};
use crate::storage::container_fs;
use crate::storage::fs_detect::FsType;
use crate::storage::oci::{ImageConfig, PullResult};
use crate::storage::unpack;
use crate::storage::StoragePool;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Metadata about a cached layer (stored in `layers/<chain_id>/layer_meta.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerMeta {
    pub chain_id: String,
    pub diff_id: String,
    pub parent_chain_id: Option<String>,
    /// Image names that reference this layer.
    pub images: Vec<String>,
}

/// Metadata about a pulled image (stored in `image_meta/<name>.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMeta {
    pub reference: String,
    pub manifest_digest: Option<String>,
    pub config: ImageConfigMeta,
    /// Chain IDs in order (one per layer).
    pub chain_ids: Vec<String>,
    /// The final chain ID — snapshot this to create a container rootfs.
    pub final_chain_id: String,
    /// Raw layer diff_ids (for future re-pull optimization).
    pub diff_ids: Vec<String>,
}

/// Subset of image config we persist.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImageConfigMeta {
    #[serde(default)]
    pub entrypoint: Vec<String>,
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub working_dir: String,
}

impl ImageConfigMeta {
    pub fn from_oci_config(config: &ImageConfig) -> Self {
        let cc = config.config.as_ref();
        Self {
            entrypoint: cc.and_then(|c| c.entrypoint.clone()).unwrap_or_default(),
            cmd: cc.and_then(|c| c.cmd.clone()).unwrap_or_default(),
            env: cc.and_then(|c| c.env.clone()).unwrap_or_default(),
            working_dir: cc
                .and_then(|c| c.working_dir.clone())
                .unwrap_or_else(|| "/".to_string()),
        }
    }
}

// --- Paths ---

fn layers_dir(pool: &StoragePool) -> PathBuf {
    pool.path.join("layers")
}

fn layer_path(pool: &StoragePool, chain_id: &str) -> PathBuf {
    layers_dir(pool).join(safe_name(chain_id))
}

fn layer_meta_path(pool: &StoragePool, chain_id: &str) -> PathBuf {
    layer_path(pool, chain_id).join("layer_meta.json")
}

fn image_meta_dir(pool: &StoragePool) -> PathBuf {
    pool.path.join("image_meta")
}

fn image_meta_path(pool: &StoragePool, image_name: &str) -> PathBuf {
    image_meta_dir(pool).join(format!("{}.json", safe_name(image_name)))
}

/// Sanitize a digest or reference for use as a directory/file name.
fn safe_name(s: &str) -> String {
    s.replace(':', "_").replace('/', "_")
}

// --- Chain ID computation ---

/// Compute OCI chain IDs from diff_ids.
///
/// chainID(L1) = diffID(L1)
/// chainID(L1..Ln) = sha256(chainID(L1..Ln-1) + " " + diffID(Ln))
pub fn compute_chain_ids(diff_ids: &[String]) -> Vec<String> {
    let mut chain_ids = Vec::with_capacity(diff_ids.len());
    for (i, diff_id) in diff_ids.iter().enumerate() {
        if i == 0 {
            chain_ids.push(diff_id.clone());
        } else {
            let parent = &chain_ids[i - 1];
            let mut hasher = Sha256::new();
            hasher.update(format!("{parent} {diff_id}").as_bytes());
            let hash = hex::encode(hasher.finalize());
            chain_ids.push(format!("sha256:{hash}"));
        }
    }
    chain_ids
}

/// Check which chain IDs already exist in the layer store.
/// Returns the set of layer indices that are cached (0-based).
pub fn find_cached_layers(pool: &StoragePool, chain_ids: &[String]) -> HashSet<usize> {
    let mut cached = HashSet::new();
    for (i, chain_id) in chain_ids.iter().enumerate() {
        if layer_path(pool, chain_id).is_dir() {
            cached.insert(i);
        } else {
            // Once we hit a missing layer, all subsequent must be rebuilt
            break;
        }
    }
    cached
}

// --- Layer extraction ---

/// Ensure pool directories exist.
pub fn ensure_dirs(pool: &StoragePool) -> Result<()> {
    fs::create_dir_all(layers_dir(pool))
        .map_err(|e| Error::Other(format!("create layers dir: {e}")))?;
    fs::create_dir_all(image_meta_dir(pool))
        .map_err(|e| Error::Other(format!("create image_meta dir: {e}")))?;
    Ok(())
}

/// Extract layers and build the chain of snapshots.
///
/// `pull_result` contains downloaded blobs and config. `diff_ids` come from the
/// image config's rootfs.diff_ids. `chain_ids` are precomputed.
///
/// For each uncached layer:
/// 1. If first layer (or first uncached): create subvolume from scratch or snapshot parent
/// 2. Extract the tar blob into the subvolume
/// 3. Write layer_meta.json
pub fn extract_layers(
    pool: &StoragePool,
    pull_result: &PullResult,
    diff_ids: &[String],
    chain_ids: &[String],
    image_name: &str,
) -> Result<()> {
    ensure_dirs(pool)?;

    // Build a map of downloaded blobs by index
    let blob_map: std::collections::HashMap<usize, &[u8]> = pull_result
        .layers
        .iter()
        .map(|(idx, blob)| (*idx, blob.as_slice()))
        .collect();

    for (i, chain_id) in chain_ids.iter().enumerate() {
        let target = layer_path(pool, chain_id);

        if target.is_dir() {
            // Already cached — just add our image to the refcount
            add_image_ref(pool, chain_id, image_name)?;
            tracing::debug!("layer {i} cached: {chain_id}");
            continue;
        }

        let blob = blob_map
            .get(&i)
            .ok_or_else(|| Error::Other(format!("missing blob for layer {i} ({chain_id})")))?;

        if i == 0 {
            // First layer: create new subvolume/directory
            create_layer_subvolume(pool, &target)?;
        } else {
            // Snapshot the parent layer
            let parent_chain_id = &chain_ids[i - 1];
            let parent_path = layer_path(pool, parent_chain_id);
            snapshot_layer(pool, &parent_path, &target)?;
        }

        // Extract the layer tar into the subvolume
        tracing::info!(
            "extracting layer {}/{}: {}",
            i + 1,
            chain_ids.len(),
            chain_id
        );
        if let Err(e) = unpack::unpack_layer(blob, &target) {
            // Clean up on failure
            delete_layer_subvolume(pool, &target);
            return Err(e);
        }

        // Write layer metadata
        let parent = if i > 0 {
            Some(chain_ids[i - 1].clone())
        } else {
            None
        };
        let meta = LayerMeta {
            chain_id: chain_id.clone(),
            diff_id: diff_ids[i].clone(),
            parent_chain_id: parent,
            images: vec![image_name.to_string()],
        };
        write_layer_meta(pool, chain_id, &meta)?;
    }

    Ok(())
}

/// Create the final image from the pulled data.
///
/// 1. Extract layers into chain ID subvolumes
/// 2. Snapshot the final chain ID as the image rootfs
/// 3. Write image metadata
pub fn create_image_from_pull(
    pool: &StoragePool,
    pull_result: &PullResult,
    image_name: &str,
) -> Result<()> {
    // Get diff_ids from the image config
    let diff_ids = pull_result
        .config
        .rootfs
        .as_ref()
        .map(|r| r.diff_ids.clone())
        .unwrap_or_default();

    if diff_ids.is_empty() {
        return Err(Error::Other(
            "image config has no rootfs diff_ids".to_string(),
        ));
    }

    if diff_ids.len() != pull_result.manifest.layers.len() {
        return Err(Error::Other(format!(
            "diff_ids count ({}) doesn't match layer count ({})",
            diff_ids.len(),
            pull_result.manifest.layers.len()
        )));
    }

    let chain_ids = compute_chain_ids(&diff_ids);
    let final_chain_id = chain_ids.last().unwrap().clone();

    // Extract layers (skips cached ones)
    extract_layers(pool, pull_result, &diff_ids, &chain_ids, image_name)?;

    // Snapshot the final chain ID subvolume as the image
    let image_path = pool.image_path(image_name);
    if image_path.exists() {
        // Image already exists — remove old one first
        match pool.fs_type {
            FsType::Btrfs => {
                let _ = container_fs::btrfs_subvolume_delete(&image_path);
            }
            FsType::Bcachefs => {
                let _ = container_fs::bcachefs_subvolume_delete(&image_path);
            }
            _ => {
                let _ = fs::remove_dir_all(&image_path);
            }
        }
    }

    let final_layer_path = layer_path(pool, &final_chain_id);
    snapshot_layer(pool, &final_layer_path, &image_path)?;
    tracing::info!("created image {image_name} from {}", pull_result.reference);

    // Write image metadata
    let meta = ImageMeta {
        reference: pull_result.reference.to_string(),
        manifest_digest: None, // TODO: capture from manifest response
        config: ImageConfigMeta::from_oci_config(&pull_result.config),
        chain_ids: chain_ids.clone(),
        final_chain_id,
        diff_ids,
    };
    write_image_meta(pool, image_name, &meta)?;

    Ok(())
}

/// Load image metadata (if it exists).
pub fn load_image_meta(pool: &StoragePool, image_name: &str) -> Option<ImageMeta> {
    let path = image_meta_path(pool, image_name);
    let json = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&json).ok()
}

/// Remove an image and decrement layer refcounts.
pub fn remove_image_layers(pool: &StoragePool, image_name: &str) -> Result<()> {
    let meta = match load_image_meta(pool, image_name) {
        Some(m) => m,
        None => return Ok(()), // No layer metadata — legacy flat image
    };

    // Remove image ref from all layers (reverse order for leaf-first cleanup)
    for chain_id in meta.chain_ids.iter().rev() {
        remove_image_ref(pool, chain_id, image_name)?;

        // If no more images reference this layer, delete it
        if let Some(layer_meta) = load_layer_meta(pool, chain_id) {
            if layer_meta.images.is_empty() {
                let target = layer_path(pool, chain_id);
                tracing::debug!("removing unreferenced layer {chain_id}");
                delete_layer_subvolume(pool, &target);
            }
        }
    }

    // Remove image metadata
    let _ = fs::remove_file(image_meta_path(pool, image_name));

    Ok(())
}

// --- Layer subvolume operations ---

fn create_layer_subvolume(pool: &StoragePool, path: &Path) -> Result<()> {
    match pool.fs_type {
        FsType::Btrfs => container_fs::btrfs_subvolume_create(path),
        FsType::Bcachefs => container_fs::bcachefs_subvolume_create(path),
        _ => fs::create_dir_all(path)
            .map_err(|e| Error::Other(format!("mkdir {}: {e}", path.display()))),
    }
}

fn snapshot_layer(pool: &StoragePool, source: &Path, dest: &Path) -> Result<()> {
    match pool.fs_type {
        FsType::Btrfs => {
            let output = std::process::Command::new("btrfs")
                .args(["subvolume", "snapshot", "--"])
                .arg(source)
                .arg(dest)
                .output()
                .map_err(|e| Error::Other(format!("btrfs snapshot: {e}")))?;
            if !output.status.success() {
                return Err(Error::Other(format!(
                    "btrfs snapshot failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
            Ok(())
        }
        FsType::Bcachefs => {
            let output = std::process::Command::new("bcachefs")
                .args(["subvolume", "snapshot"])
                .arg(source)
                .arg(dest)
                .output()
                .map_err(|e| Error::Other(format!("bcachefs snapshot: {e}")))?;
            if !output.status.success() {
                return Err(Error::Other(format!(
                    "bcachefs snapshot failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
            Ok(())
        }
        _ => {
            // cp -a --reflink=auto
            let output = std::process::Command::new("cp")
                .args(["-a", "--reflink=auto", "--"])
                .arg(source)
                .arg(dest)
                .output()
                .map_err(|e| Error::Other(format!("cp: {e}")))?;
            if !output.status.success() {
                return Err(Error::Other(format!(
                    "cp failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
            Ok(())
        }
    }
}

fn delete_layer_subvolume(pool: &StoragePool, path: &Path) {
    match pool.fs_type {
        FsType::Btrfs => {
            let _ = container_fs::btrfs_subvolume_delete(path);
        }
        FsType::Bcachefs => {
            let _ = container_fs::bcachefs_subvolume_delete(path);
        }
        _ => {
            let _ = fs::remove_dir_all(path);
        }
    }
}

// --- Metadata I/O ---

fn write_layer_meta(pool: &StoragePool, chain_id: &str, meta: &LayerMeta) -> Result<()> {
    let path = layer_meta_path(pool, chain_id);
    let json = serde_json::to_string(meta)
        .map_err(|e| Error::Other(format!("serialize layer meta: {e}")))?;
    fs::write(&path, json).map_err(|e| Error::Other(format!("write layer meta: {e}")))
}

fn load_layer_meta(pool: &StoragePool, chain_id: &str) -> Option<LayerMeta> {
    let path = layer_meta_path(pool, chain_id);
    let json = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&json).ok()
}

fn write_image_meta(pool: &StoragePool, image_name: &str, meta: &ImageMeta) -> Result<()> {
    let path = image_meta_path(pool, image_name);
    let json = serde_json::to_string_pretty(meta)
        .map_err(|e| Error::Other(format!("serialize image meta: {e}")))?;
    let mut f =
        fs::File::create(&path).map_err(|e| Error::Other(format!("create image meta: {e}")))?;
    f.write_all(json.as_bytes())
        .map_err(|e| Error::Other(format!("write image meta: {e}")))?;
    Ok(())
}

fn add_image_ref(pool: &StoragePool, chain_id: &str, image_name: &str) -> Result<()> {
    if let Some(mut meta) = load_layer_meta(pool, chain_id) {
        if !meta.images.contains(&image_name.to_string()) {
            meta.images.push(image_name.to_string());
            write_layer_meta(pool, chain_id, &meta)?;
        }
    }
    Ok(())
}

fn remove_image_ref(pool: &StoragePool, chain_id: &str, image_name: &str) -> Result<()> {
    if let Some(mut meta) = load_layer_meta(pool, chain_id) {
        meta.images.retain(|n| n != image_name);
        write_layer_meta(pool, chain_id, &meta)?;
    }
    Ok(())
}
