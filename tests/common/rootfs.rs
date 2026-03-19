//! Test rootfs management.
//!
//! Downloads a static busybox binary, creates a minimal rootfs directory,
//! and provides per-test temporary rootfs clones.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;

const BUSYBOX_URL: &str = "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox";

static INIT_ROOTFS: Once = Once::new();

/// Get the path to the cached base rootfs directory.
/// Downloads busybox on first call, then reuses the cache.
fn base_rootfs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-rootfs")
}

/// Ensure the base rootfs exists (download busybox if needed).
pub fn ensure_base_rootfs() -> PathBuf {
    let dir = base_rootfs_dir();

    INIT_ROOTFS.call_once(|| {
        if dir.join("bin").join("busybox").exists() {
            return; // Already cached
        }

        eprintln!("Downloading busybox for test rootfs...");

        // Create directory structure
        for subdir in &[
            "bin", "sbin", "usr/bin", "usr/sbin", "proc", "sys", "dev", "tmp", "etc", "root",
            "var", "var/tmp", "run",
        ] {
            fs::create_dir_all(dir.join(subdir)).expect("failed to create rootfs dir");
        }

        // Download busybox
        let busybox_path = dir.join("bin").join("busybox");
        download_busybox(&busybox_path);

        // Make it executable
        let mut perms = fs::metadata(&busybox_path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        fs::set_permissions(&busybox_path, perms).unwrap();

        // Create symlinks for all applets
        create_busybox_symlinks(&dir, &busybox_path);

        // Create minimal /etc files
        fs::write(
            dir.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n",
        )
        .unwrap();
        fs::write(dir.join("etc/group"), "root:x:0:\nnogroup:x:65534:\n").unwrap();
        fs::write(dir.join("etc/hostname"), "sandbox-test\n").unwrap();
        fs::write(dir.join("etc/hosts"), "127.0.0.1 localhost\n").unwrap();
        fs::write(dir.join("etc/resolv.conf"), "nameserver 8.8.8.8\n").unwrap();

        eprintln!("Test rootfs ready at {}", dir.display());
    });

    dir
}

/// Download busybox binary.
fn download_busybox(target: &Path) {
    // Try using ureq (already a dev-dependency)
    match download_with_ureq(target) {
        Ok(()) => return,
        Err(e) => {
            eprintln!("ureq download failed: {e}, trying curl...");
        }
    }

    let status = Command::new("curl")
        .args(["-fsSL", "-o", target.to_str().unwrap(), BUSYBOX_URL])
        .status()
        .expect("failed to run curl");

    if !status.success() {
        panic!("failed to download busybox from {BUSYBOX_URL}");
    }
}

fn download_with_ureq(target: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;
    let resp = ureq::get(BUSYBOX_URL).call()?;
    let mut data = Vec::new();
    resp.into_reader().read_to_end(&mut data)?;
    fs::write(target, &data)?;
    Ok(())
}

/// Create busybox symlinks for all applets.
fn create_busybox_symlinks(rootfs: &Path, busybox: &Path) {
    let output = Command::new(busybox)
        .arg("--list-full")
        .output()
        .expect("failed to list busybox applets");

    let applets = String::from_utf8_lossy(&output.stdout);
    for line in applets.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let target = rootfs.join(line.trim_start_matches('/'));
        if target.exists() {
            continue;
        }

        // Ensure parent directory exists
        if let Some(parent) = target.parent() {
            let _ = fs::create_dir_all(parent);
        }

        // Create symlink to /bin/busybox
        let _ = symlink("/bin/busybox", &target);
    }
}

/// A temporary rootfs directory that is cleaned up on drop.
/// Each test gets its own independent copy of the rootfs.
pub struct TempRootfs {
    dir: tempfile::TempDir,
}

impl TempRootfs {
    /// Create a new temporary rootfs by copying the base rootfs.
    pub fn new() -> Self {
        let base = ensure_base_rootfs();
        let dir = tempfile::TempDir::new().expect("failed to create tempdir");

        // Copy the base rootfs into the tempdir
        copy_dir_recursive(&base, dir.path()).expect("failed to copy rootfs");

        Self { dir }
    }

    /// Get the path to the rootfs directory.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Write a file inside the rootfs.
    #[allow(dead_code)]
    pub fn write_file(&self, relative_path: &str, content: &str) {
        let path = self.dir.path().join(relative_path.trim_start_matches('/'));
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&path, content).unwrap_or_else(|e| {
            panic!("failed to write {}: {e}", path.display());
        });
    }

    /// Read a file from inside the rootfs.
    #[allow(dead_code)]
    pub fn read_file(&self, relative_path: &str) -> Option<String> {
        let path = self.dir.path().join(relative_path.trim_start_matches('/'));
        fs::read_to_string(&path).ok()
    }

    /// Create a directory inside the rootfs.
    #[allow(dead_code)]
    pub fn mkdir(&self, relative_path: &str) {
        let path = self.dir.path().join(relative_path.trim_start_matches('/'));
        fs::create_dir_all(&path).unwrap();
    }
}

/// Recursively copy a directory.
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if file_type.is_symlink() {
            let link_target = fs::read_link(&src_path)?;
            let _ = symlink(&link_target, &dst_path);
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}
