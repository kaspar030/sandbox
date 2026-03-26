//! Parse `/proc/self/mountinfo` and find propagated mounts.
//!
//! When the daemon creates idmapped bind mounts inside a container via
//! `hot_bind_mount()`, mount propagation can cause those mounts to appear
//! on the host. This module provides tools to find and clean up such
//! propagated mounts.
//!
//! A propagated mount is identified as an idmapped mount whose mount point
//! is a strict subdirectory of a bind mount source path. For example, if
//! a container has bind mount `/home/user/project → /app` and also
//! `/home/user/other → /app/other`, the latter may propagate to the host
//! as an idmapped mount at `/home/user/project/other`.

use crate::protocol::BindMount;
use std::path::{Path, PathBuf};

/// A parsed entry from `/proc/self/mountinfo`.
#[derive(Debug)]
struct MountEntry {
    /// Mount point (field 5) — where this mount is attached.
    mount_point: PathBuf,
    /// Per-mount options (field 6) — e.g. "rw,relatime,idmapped".
    options: String,
}

/// Parse mountinfo content into a list of mount entries.
///
/// Format (from `proc(5)`):
/// ```text
/// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
/// ```
/// Fields: mount_id parent_id major:minor root mount_point options optional_fields - fs_type source super_options
fn parse_mountinfo_content(content: &str) -> Vec<MountEntry> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Minimum fields: mount_id parent_id dev root mount_point options - fs_type source super_options
        if fields.len() < 7 {
            continue;
        }
        // field 5 (0-indexed) = mount_point, field 6 = options
        let mount_point = PathBuf::from(fields[4]);
        let options = fields[5].to_string();
        entries.push(MountEntry {
            mount_point,
            options,
        });
    }
    entries
}

/// Parse `/proc/self/mountinfo` into a list of mount entries.
fn parse_mountinfo() -> Vec<MountEntry> {
    match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(content) => parse_mountinfo_content(&content),
        Err(e) => {
            tracing::warn!("failed to read /proc/self/mountinfo: {e}");
            Vec::new()
        }
    }
}

/// Find idmapped mounts whose mount point is a strict subdirectory of any
/// bind mount source path. Returns mount points sorted deepest-first.
fn find_propagated_in_entries(entries: &[MountEntry], sources: &[PathBuf]) -> Vec<PathBuf> {
    let mut propagated: Vec<PathBuf> = Vec::new();

    for entry in entries {
        // Only consider idmapped mounts
        if !entry.options.contains("idmapped") {
            continue;
        }

        // Check if this mount point is a strict subdirectory of any bind
        // mount source
        for source in sources {
            if entry.mount_point.starts_with(source) && entry.mount_point != *source {
                propagated.push(entry.mount_point.clone());
                break;
            }
        }
    }

    // Sort deepest-first for correct unmount ordering (child before parent)
    propagated.sort_by(|a, b| {
        let a_depth = a.components().count();
        let b_depth = b.components().count();
        b_depth.cmp(&a_depth)
    });

    propagated
}

/// Find idmapped mounts on the host that were propagated from container
/// bind mounts.
///
/// For each bind mount source path, finds idmapped mounts whose mount point
/// is a strict subdirectory of that source. Returns the mount points sorted
/// deepest-first so they can be unmounted in the correct order.
pub fn find_propagated_mounts(bind_mounts: &[BindMount]) -> Vec<PathBuf> {
    let entries = parse_mountinfo();

    // Canonicalize bind mount source paths (resolve symlinks, normalize)
    let sources: Vec<PathBuf> = bind_mounts
        .iter()
        .filter_map(|bm| {
            let p = Path::new(&bm.source);
            p.canonicalize().ok().or_else(|| Some(p.to_path_buf()))
        })
        .collect();

    find_propagated_in_entries(&entries, &sources)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bm(source: &str, target: &str) -> BindMount {
        BindMount {
            source: source.to_string(),
            target: target.to_string(),
            readonly: false,
        }
    }

    #[test]
    fn test_find_propagated_empty() {
        let result = find_propagated_mounts(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_mountinfo_content() {
        let content = "\
67 1 259:3 / / rw,relatime shared:1 - bcachefs /dev/nvme0n1p2 rw,
536 47 259:3 /storage/fs/dev /run/sandbox/mounts/dev rw,relatime,idmapped shared:1 - bcachefs /dev/nvme0n1p2 rw,
1028 67 259:3 /src/other /home/user/project/other rw,relatime,idmapped shared:1 - bcachefs /dev/nvme0n1p2 rw,
1029 67 259:3 /src/deep /home/user/project/a/b rw,relatime,idmapped shared:1 - bcachefs /dev/nvme0n1p2 rw,
";
        let entries = parse_mountinfo_content(content);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].mount_point, PathBuf::from("/"));
        assert_eq!(entries[0].options, "rw,relatime");
        assert_eq!(
            entries[1].mount_point,
            PathBuf::from("/run/sandbox/mounts/dev")
        );
        assert!(entries[1].options.contains("idmapped"));
    }

    #[test]
    fn test_find_propagated_matches_strict_subdirs() {
        let content = "\
67 1 259:3 / / rw,relatime shared:1 - bcachefs /dev/nvme0n1p2 rw,
1028 67 259:3 /src/other /home/user/project/other rw,relatime,idmapped shared:1 - bcachefs /dev/nvme0n1p2 rw,
1029 67 259:3 /src/deep /home/user/project/a/b rw,relatime,idmapped shared:1 - bcachefs /dev/nvme0n1p2 rw,
";
        let entries = parse_mountinfo_content(content);
        let sources = vec![PathBuf::from("/home/user/project")];
        let result = find_propagated_in_entries(&entries, &sources);

        assert_eq!(result.len(), 2);
        // Deepest first
        assert_eq!(result[0], PathBuf::from("/home/user/project/a/b"));
        assert_eq!(result[1], PathBuf::from("/home/user/project/other"));
    }

    #[test]
    fn test_find_propagated_ignores_non_idmapped() {
        let content = "\
67 1 259:3 / / rw,relatime shared:1 - bcachefs /dev/nvme0n1p2 rw,
100 67 259:3 /src/sub /home/user/project/sub rw,relatime shared:1 - bcachefs /dev/nvme0n1p2 rw,
";
        let entries = parse_mountinfo_content(content);
        let sources = vec![PathBuf::from("/home/user/project")];
        let result = find_propagated_in_entries(&entries, &sources);

        assert!(result.is_empty());
    }

    #[test]
    fn test_find_propagated_ignores_exact_match() {
        // A mount AT the source path is the source itself, not propagated
        let content = "\
536 47 259:3 /storage/fs/dev /home/user/project rw,relatime,idmapped shared:1 - bcachefs /dev/nvme0n1p2 rw,
";
        let entries = parse_mountinfo_content(content);
        let sources = vec![PathBuf::from("/home/user/project")];
        let result = find_propagated_in_entries(&entries, &sources);

        assert!(result.is_empty());
    }

    #[test]
    fn test_find_propagated_ignores_unrelated_paths() {
        let content = "\
1028 67 259:3 /src/other /somewhere/else/other rw,relatime,idmapped shared:1 - bcachefs /dev/nvme0n1p2 rw,
";
        let entries = parse_mountinfo_content(content);
        let sources = vec![PathBuf::from("/home/user/project")];
        let result = find_propagated_in_entries(&entries, &sources);

        assert!(result.is_empty());
    }

    #[test]
    fn test_find_propagated_multiple_sources() {
        let content = "\
1028 67 259:3 /x /home/a/sub rw,relatime,idmapped shared:1 - bcachefs /dev/nvme0n1p2 rw,
1029 67 259:3 /y /home/b/sub rw,relatime,idmapped shared:1 - bcachefs /dev/nvme0n1p2 rw,
";
        let entries = parse_mountinfo_content(content);
        let sources = vec![PathBuf::from("/home/a"), PathBuf::from("/home/b")];
        let result = find_propagated_in_entries(&entries, &sources);

        assert_eq!(result.len(), 2);
        assert!(result.contains(&PathBuf::from("/home/a/sub")));
        assert!(result.contains(&PathBuf::from("/home/b/sub")));
    }

    #[test]
    fn test_deepest_first_ordering() {
        let content = "\
1 67 259:3 /x /mnt/a rw,relatime,idmapped shared:1 - bcachefs /dev/nvme0n1p2 rw,
2 67 259:3 /y /mnt/a/b/c rw,relatime,idmapped shared:1 - bcachefs /dev/nvme0n1p2 rw,
3 67 259:3 /z /mnt/a/b rw,relatime,idmapped shared:1 - bcachefs /dev/nvme0n1p2 rw,
";
        let entries = parse_mountinfo_content(content);
        let sources = vec![PathBuf::from("/mnt")];
        let result = find_propagated_in_entries(&entries, &sources);

        assert_eq!(result.len(), 3);
        assert_eq!(result[0], PathBuf::from("/mnt/a/b/c"));
        assert_eq!(result[1], PathBuf::from("/mnt/a/b"));
        assert_eq!(result[2], PathBuf::from("/mnt/a"));
    }
}
