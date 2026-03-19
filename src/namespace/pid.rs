//! PID namespace setup.
//!
//! After clone3 with CLONE_NEWPID, the child is PID 1 in the new namespace.
//! We need to mount a new /proc so that tools like `ps` see the container's
//! process tree instead of the host's.

use crate::error::{Error, Result};
use std::path::Path;

/// Mount /proc inside the container.
/// This must be called after pivot_root from within the mount namespace.
pub fn mount_proc(new_root: &Path) -> Result<()> {
    let proc_path = new_root.join("proc");

    // Ensure the mount point exists
    std::fs::create_dir_all(&proc_path).map_err(|e| Error::Mount {
        path: proc_path.clone(),
        source: e,
    })?;

    // Mount proc filesystem
    nix::mount::mount(
        Some("proc"),
        &proc_path,
        Some("proc"),
        nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV | nix::mount::MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|e| Error::Mount {
        path: proc_path,
        source: std::io::Error::from_raw_os_error(e as i32),
    })?;

    Ok(())
}
