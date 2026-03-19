//! Streaming tar extraction with compression detection and OCI whiteout handling.

use crate::error::{Error, Result};
use std::fs;
use std::io::Read;
use std::path::Path;

/// Detect compression format from magic bytes and unpack a tar layer into `target`.
///
/// Handles:
/// - gzip (0x1f 0x8b)
/// - zstd (0x28 0xb5 0x2f 0xfd)
/// - raw tar (0x75 0x73 0x74 0x61 0x72 at offset 257, or just try raw)
///
/// OCI whiteout semantics:
/// - `.wh.<name>` → delete `<name>` in the same directory
/// - `.wh..wh..opq` → opaque whiteout: delete all existing entries in that directory
pub fn unpack_layer(blob: &[u8], target: &Path) -> Result<()> {
    if blob.len() < 4 {
        return Err(Error::Other("layer blob too small".to_string()));
    }

    // Detect compression
    if blob.starts_with(&[0x1f, 0x8b]) {
        // gzip
        let decoder = flate2::read::GzDecoder::new(blob);
        extract_tar(decoder, target)
    } else if blob.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        // zstd
        let decoder = zstd::Decoder::new(blob)
            .map_err(|e| Error::Other(format!("zstd decode error: {e}")))?;
        extract_tar(decoder, target)
    } else {
        // Assume raw tar
        extract_tar(blob, target)
    }
}

/// Extract a tar archive from a reader into `target`, handling OCI whiteouts.
fn extract_tar<R: Read>(reader: R, target: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    archive.set_overwrite(true);
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(true);
    // Don't unpack absolute paths outside target
    archive.set_unpack_xattrs(true);

    for entry in archive
        .entries()
        .map_err(|e| Error::Other(format!("tar entries error: {e}")))?
    {
        let mut entry = entry.map_err(|e| Error::Other(format!("tar entry error: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| Error::Other(format!("tar path error: {e}")))?
            .into_owned();

        // Get the filename component
        let file_name = match path.file_name() {
            Some(n) => n.to_string_lossy().to_string(),
            None => {
                // Directory entry like "./" — just extract normally
                entry
                    .unpack_in(target)
                    .map_err(|e| Error::Other(format!("tar unpack error: {e}")))?;
                continue;
            }
        };

        if file_name == ".wh..wh..opq" {
            // Opaque whiteout: delete all existing entries in this directory
            let parent = path.parent().unwrap_or(Path::new(""));
            let abs_parent = target.join(parent);
            if abs_parent.is_dir() {
                for child in fs::read_dir(&abs_parent)
                    .map_err(|e| Error::Other(format!("readdir error: {e}")))?
                    .flatten()
                {
                    let child_path = child.path();
                    if child_path.is_dir() {
                        let _ = fs::remove_dir_all(&child_path);
                    } else {
                        let _ = fs::remove_file(&child_path);
                    }
                }
            }
        } else if let Some(deleted_name) = file_name.strip_prefix(".wh.") {
            // File whiteout: delete the named file/dir
            let parent = path.parent().unwrap_or(Path::new(""));
            let to_delete = target.join(parent).join(deleted_name);
            if to_delete.is_dir() {
                let _ = fs::remove_dir_all(&to_delete);
            } else {
                let _ = fs::remove_file(&to_delete);
            }
        } else {
            // Normal file/dir/symlink — extract
            entry.unpack_in(target).map_err(|e| {
                Error::Other(format!("tar unpack error for {}: {e}", path.display()))
            })?;
        }
    }

    Ok(())
}
