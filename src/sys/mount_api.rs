//! New mount API wrappers: open_tree(2), move_mount(2), mount_setattr(2).
//!
//! These syscalls are not wrapped by libc or nix, so we call them directly.
//! Used by idmap.rs for idmapped mounts and hot_mount.rs for runtime bind mounts.

use crate::error::{Error, Result};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

// Syscall numbers (x86_64)
const SYS_OPEN_TREE: i64 = 428;
const SYS_MOVE_MOUNT: i64 = 429;
const SYS_MOUNT_SETATTR: i64 = 442;

// open_tree flags
const OPEN_TREE_CLONE: u32 = 1;
const OPEN_TREE_CLOEXEC: u32 = libc::O_CLOEXEC as u32;

// move_mount flags
const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x00000004;

// mount_setattr constants
pub const MOUNT_ATTR_IDMAP: u64 = 0x00100000;
pub const MOUNT_ATTR_RDONLY: u64 = 0x00000001;
pub const AT_RECURSIVE: u32 = 0x8000;

/// Struct for mount_setattr(2).
#[repr(C)]
pub struct MountAttr {
    pub attr_set: u64,
    pub attr_clr: u64,
    pub propagation: u64,
    pub userns_fd: u64,
}

/// Create a detached clone of a mount subtree.
///
/// Returns a file descriptor representing the cloned mount tree.
/// The mount is detached — not visible in any mount namespace until
/// move_mount() is called.
pub fn open_tree(path: &Path, recursive: bool) -> Result<OwnedFd> {
    let c_path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| Error::Other(format!("invalid path: {e}")))?;

    let mut flags = OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC;
    if recursive {
        flags |= AT_RECURSIVE;
    }

    let fd = unsafe { libc::syscall(SYS_OPEN_TREE, libc::AT_FDCWD, c_path.as_ptr(), flags) };

    if fd < 0 {
        return Err(Error::Other(format!(
            "open_tree({}) failed: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }

    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Attach a detached mount at a target path.
///
/// The target directory must already exist.
pub fn move_mount(mount_fd: &OwnedFd, target: &Path) -> Result<()> {
    let c_target = CString::new(target.as_os_str().as_encoded_bytes())
        .map_err(|e| Error::Other(format!("invalid target path: {e}")))?;

    let ret = unsafe {
        libc::syscall(
            SYS_MOVE_MOUNT,
            mount_fd.as_raw_fd(),
            b"\0".as_ptr(),
            libc::AT_FDCWD,
            c_target.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    };

    if ret < 0 {
        return Err(Error::Other(format!(
            "move_mount({}) failed: {}",
            target.display(),
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Apply attributes to a detached mount via mount_setattr(2).
///
/// `attr` describes the attributes to set/clear. Common uses:
/// - `MOUNT_ATTR_IDMAP` with `userns_fd` for idmapped mounts
/// - `MOUNT_ATTR_RDONLY` for read-only mounts
pub fn mount_setattr(mount_fd: &OwnedFd, attr: &MountAttr, recursive: bool) -> Result<()> {
    let flags = if recursive {
        libc::AT_EMPTY_PATH | AT_RECURSIVE as i32
    } else {
        libc::AT_EMPTY_PATH
    };

    let ret = unsafe {
        libc::syscall(
            SYS_MOUNT_SETATTR,
            mount_fd.as_raw_fd(),
            b"\0".as_ptr(),
            flags,
            attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };

    if ret < 0 {
        return Err(Error::Other(format!(
            "mount_setattr failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Set a detached mount to read-only.
pub fn set_readonly(mount_fd: &OwnedFd) -> Result<()> {
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    mount_setattr(mount_fd, &attr, true)
}

/// Apply an idmap to a detached mount using a user namespace fd.
pub fn set_idmap(mount_fd: &OwnedFd, userns_fd: &OwnedFd) -> Result<()> {
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_IDMAP,
        attr_clr: 0,
        propagation: 0,
        userns_fd: userns_fd.as_raw_fd() as u64,
    };
    mount_setattr(mount_fd, &attr, true)
}
