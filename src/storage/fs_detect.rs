//! Filesystem type detection via statfs(2).

use crate::error::{Error, Result};
use std::path::Path;

// Filesystem magic numbers (from linux/magic.h and kernel sources)
const BTRFS_SUPER_MAGIC: i64 = 0x9123683E;
const BCACHEFS_SUPER_MAGIC: i64 = 0xCA451A4E_u32 as i64;
const EXT4_SUPER_MAGIC: i64 = 0xEF53;
const XFS_SUPER_MAGIC: i64 = 0x58465342;
const TMPFS_MAGIC: i64 = 0x01021994;

/// Known filesystem types relevant to container operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsType {
    Btrfs,
    Bcachefs,
    Ext4,
    Xfs,
    Tmpfs,
    Other(i64),
}

impl FsType {
    /// Can this filesystem create CoW snapshots?
    pub fn supports_snapshots(&self) -> bool {
        matches!(self, FsType::Btrfs | FsType::Bcachefs)
    }

    /// Does this filesystem support idmapped mounts (FS_ALLOW_IDMAP)?
    /// Verified from kernel source for each filesystem.
    pub fn supports_idmap(&self) -> bool {
        matches!(
            self,
            FsType::Btrfs | FsType::Bcachefs | FsType::Ext4 | FsType::Xfs | FsType::Tmpfs
        )
    }

    /// Human-readable name.
    pub fn name(&self) -> &str {
        match self {
            FsType::Btrfs => "btrfs",
            FsType::Bcachefs => "bcachefs",
            FsType::Ext4 => "ext4",
            FsType::Xfs => "xfs",
            FsType::Tmpfs => "tmpfs",
            FsType::Other(_) => "unknown",
        }
    }
}

impl std::fmt::Display for FsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FsType::Other(magic) => write!(f, "unknown(0x{magic:X})"),
            _ => write!(f, "{}", self.name()),
        }
    }
}

/// Detect the filesystem type of the given path.
pub fn detect_filesystem(path: &Path) -> Result<FsType> {
    let stat = nix::sys::statfs::statfs(path)
        .map_err(|e| Error::Other(format!("statfs({}) failed: {e}", path.display())))?;

    let magic = stat.filesystem_type().0 as i64;

    Ok(match magic {
        BTRFS_SUPER_MAGIC => FsType::Btrfs,
        BCACHEFS_SUPER_MAGIC => FsType::Bcachefs,
        EXT4_SUPER_MAGIC => FsType::Ext4,
        XFS_SUPER_MAGIC => FsType::Xfs,
        TMPFS_MAGIC => FsType::Tmpfs,
        other => FsType::Other(other),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fs_type_properties() {
        assert!(FsType::Btrfs.supports_snapshots());
        assert!(FsType::Bcachefs.supports_snapshots());
        assert!(!FsType::Ext4.supports_snapshots());
        assert!(!FsType::Xfs.supports_snapshots());

        assert!(FsType::Btrfs.supports_idmap());
        assert!(FsType::Bcachefs.supports_idmap());
        assert!(FsType::Ext4.supports_idmap());
        assert!(FsType::Xfs.supports_idmap());
        assert!(FsType::Tmpfs.supports_idmap());
        assert!(!FsType::Other(0x1234).supports_idmap());
    }

    #[test]
    fn test_detect_tmp() {
        // /tmp is often tmpfs
        let result = detect_filesystem(Path::new("/tmp"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", FsType::Btrfs), "btrfs");
        assert_eq!(format!("{}", FsType::Other(0xABCD)), "unknown(0xABCD)");
    }
}
