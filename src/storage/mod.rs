//! Storage pool management.
//!
//! Layout:
//!   /var/lib/sandbox/storage/<pool>/images/<name>/       — rootfs images
//!   /var/lib/sandbox/storage/<pool>/fs/<container>/      — per-container rootfs (copy/snapshot)
//!   /var/lib/sandbox/storage/<pool>/layers/<chain_id>/   — cached OCI layer subvolumes
//!   /var/lib/sandbox/storage/<pool>/image_meta/<name>.json — image metadata (config, chain IDs)
//!
//! The default pool is "main". Additional pools can be created by mounting
//! a filesystem (btrfs, bcachefs, etc.) at storage/<name>/.

pub mod container_fs;
pub mod fs_detect;
pub mod image;
pub mod layers;
pub mod oci;
pub mod unpack;

use crate::error::{Error, Result};
use fs_detect::FsType;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// A storage pool — a named directory under /var/lib/sandbox/storage/.
#[derive(Debug)]
pub struct StoragePool {
    /// Pool name (e.g., "main", "fast-nvme").
    pub name: String,
    /// Full path to the pool directory.
    pub path: PathBuf,
    /// Detected filesystem type.
    pub fs_type: FsType,
}

impl StoragePool {
    /// Path to the images directory within this pool.
    pub fn images_dir(&self) -> PathBuf {
        self.path.join("images")
    }

    /// Path to the container rootfs directory within this pool.
    pub fn fs_dir(&self) -> PathBuf {
        self.path.join("fs")
    }

    /// Path to a specific image's rootfs.
    pub fn image_path(&self, image_name: &str) -> PathBuf {
        self.images_dir().join(image_name)
    }

    /// Path to a specific container's rootfs.
    pub fn container_path(&self, container_name: &str) -> PathBuf {
        self.fs_dir().join(container_name)
    }
}

/// Manages all storage pools.
#[derive(Debug)]
pub struct StorageManager {
    /// Base directory (e.g., /var/lib/sandbox).
    base_dir: PathBuf,
    /// All discovered pools, keyed by name.
    pools: HashMap<String, StoragePool>,
}

impl StorageManager {
    /// Initialize the storage manager.
    ///
    /// Creates the default "main" pool if it doesn't exist.
    /// Discovers any additional pools under storage/.
    /// Verifies that all pools are on idmap-capable filesystems.
    pub fn init(base_dir: &Path) -> Result<Self> {
        let storage_dir = base_dir.join("storage");
        let main_dir = storage_dir.join("main");

        // Create the default pool directory structure
        fs::create_dir_all(main_dir.join("images")).map_err(|e| {
            Error::Other(format!(
                "failed to create {}: {e}",
                main_dir.join("images").display()
            ))
        })?;
        fs::create_dir_all(main_dir.join("fs")).map_err(|e| {
            Error::Other(format!(
                "failed to create {}: {e}",
                main_dir.join("fs").display()
            ))
        })?;

        let mut pools = HashMap::new();

        // Discover all pool directories
        if storage_dir.exists() {
            for entry in fs::read_dir(&storage_dir).map_err(|e| {
                Error::Other(format!("failed to read {}: {e}", storage_dir.display()))
            })? {
                let entry = entry.map_err(|e| Error::Other(format!("readdir error: {e}")))?;
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }

                let name = entry.file_name().to_str().unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }

                // Ensure images/ and fs/ subdirs exist
                let _ = fs::create_dir_all(path.join("images"));
                let _ = fs::create_dir_all(path.join("fs"));

                let fs_type = fs_detect::detect_filesystem(&path)?;

                if !fs_type.supports_idmap() {
                    tracing::warn!(
                        "storage pool '{name}' is on {} which may not support idmapped mounts",
                        fs_type
                    );
                }

                if fs_type.supports_snapshots() && !container_fs::check_snapshot_tool(&fs_type) {
                    tracing::warn!(
                        "storage pool '{name}' is on {} but snapshot tool not found — \
                         falling back to cp -a for container rootfs",
                        fs_type
                    );
                }

                tracing::info!(
                    "storage pool '{name}' on {} (snapshots: {}, idmap: {})",
                    fs_type,
                    fs_type.supports_snapshots(),
                    fs_type.supports_idmap(),
                );

                pools.insert(
                    name.clone(),
                    StoragePool {
                        name,
                        path,
                        fs_type,
                    },
                );
            }
        }

        if !pools.contains_key("main") {
            return Err(Error::Other(
                "default storage pool 'main' not found or not on an idmap-capable filesystem"
                    .to_string(),
            ));
        }

        Ok(Self {
            base_dir: base_dir.to_path_buf(),
            pools,
        })
    }

    /// Get the default pool ("main").
    pub fn default_pool(&self) -> &StoragePool {
        self.pools.get("main").expect("main pool must exist")
    }

    /// Get a pool by name.
    pub fn pool(&self, name: &str) -> Option<&StoragePool> {
        self.pools.get(name)
    }

    /// Resolve pool name: use the given name or fall back to "main".
    pub fn resolve_pool(&self, name: Option<&str>) -> Result<&StoragePool> {
        let pool_name = name.unwrap_or("main");
        self.pools
            .get(pool_name)
            .ok_or_else(|| Error::Other(format!("storage pool '{pool_name}' not found")))
    }

    /// List all pools.
    pub fn list_pools(&self) -> Vec<&StoragePool> {
        let mut pools: Vec<_> = self.pools.values().collect();
        pools.sort_by_key(|p| &p.name);
        pools
    }

    /// Get the base directory.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}
