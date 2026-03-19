//! Root filesystem setup and pivot_root.
//!
//! The sequence is:
//! 1. Bind-mount the rootfs onto itself (required for pivot_root)
//! 2. Set up /dev, /proc, /sys inside the new root
//! 3. Set up user bind mounts
//! 4. pivot_root to the new root
//! 5. Unmount and remove the old root

use crate::error::{Error, Result};
use crate::namespace::mount::{setup_bind_mounts, setup_dev, setup_sys};
use crate::namespace::pid::mount_proc;
use crate::protocol::BindMount;
use nix::mount::MsFlags;
use std::path::Path;

/// Perform the full rootfs setup and pivot_root.
///
/// This must be called from the child process after namespaces are configured
/// and the parent has signaled via eventfd.
pub fn setup_rootfs(rootfs: &Path, bind_mounts: &[BindMount]) -> Result<()> {
    // Verify rootfs exists
    if !rootfs.exists() {
        return Err(Error::RootfsNotFound(rootfs.to_path_buf()));
    }

    // Bind-mount rootfs onto itself (required for pivot_root)
    nix::mount::mount(
        Some(rootfs),
        rootfs,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| Error::Mount {
        path: rootfs.to_path_buf(),
        source: std::io::Error::from_raw_os_error(e as i32),
    })?;

    // Set up special filesystems inside the new root
    setup_dev(rootfs)?;
    mount_proc(rootfs)?;
    setup_sys(rootfs)?;

    // Set up user bind mounts
    setup_bind_mounts(rootfs, bind_mounts)?;

    // Create the old_root directory for pivot_root
    let old_root = rootfs.join("old_root");
    std::fs::create_dir_all(&old_root).map_err(|e| Error::Mount {
        path: old_root.clone(),
        source: e,
    })?;

    // pivot_root: swap root filesystem
    nix::unistd::pivot_root(rootfs, &old_root).map_err(|e| {
        Error::PivotRoot(std::io::Error::from_raw_os_error(e as i32))
    })?;

    // Change to new root
    std::env::set_current_dir("/").map_err(Error::PivotRoot)?;

    // Unmount old root (lazily, in case things are still using it)
    nix::mount::umount2("/old_root", nix::mount::MntFlags::MNT_DETACH)
        .map_err(|e| Error::Mount {
            path: "/old_root".into(),
            source: std::io::Error::from_raw_os_error(e as i32),
        })?;

    // Remove old_root directory
    std::fs::remove_dir("/old_root").map_err(|e| Error::Mount {
        path: "/old_root".into(),
        source: e,
    })?;

    Ok(())
}
