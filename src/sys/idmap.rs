//! Idmapped mount support via open_tree(2), mount_setattr(2), move_mount(2).
//!
//! These syscalls are not wrapped by libc or nix, so we call them directly.
//! Used to apply a UID/GID shift to a mount so that on-disk uid 0 appears
//! as uid 100000 (or whatever the subordinate range is) without modifying
//! on-disk ownership.
//!
//! The idmap is described by a user namespace: we create a throwaway userns
//! with the desired uid_map/gid_map, pass its fd to mount_setattr, and then
//! destroy the userns. The kernel copies the mapping data — the userns can
//! be discarded after mount_setattr returns.

use crate::error::{Error, Result};
use crate::namespace::user;
use crate::protocol::IdMapping;
use crate::sys::clone3;
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
const MOUNT_ATTR_IDMAP: u64 = 0x00100000;
const AT_RECURSIVE: u32 = 0x8000;

/// Struct for mount_setattr(2).
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
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

/// Apply an idmap to a detached mount.
///
/// `mount_fd` is the detached mount from open_tree().
/// `userns_fd` is a user namespace whose uid_map/gid_map describe the
/// desired UID/GID shift. The kernel copies the mapping data — the userns
/// can be discarded after this call returns.
pub fn mount_setattr_idmap(mount_fd: &OwnedFd, userns_fd: &OwnedFd) -> Result<()> {
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_IDMAP,
        attr_clr: 0,
        propagation: 0,
        userns_fd: userns_fd.as_raw_fd() as u64,
    };

    let ret = unsafe {
        libc::syscall(
            SYS_MOUNT_SETATTR,
            mount_fd.as_raw_fd(),
            b"\0".as_ptr(), // empty path — operate on the fd itself
            libc::AT_EMPTY_PATH | AT_RECURSIVE as i32,
            &attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };

    if ret < 0 {
        return Err(Error::Other(format!(
            "mount_setattr(MOUNT_ATTR_IDMAP) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
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
            b"\0".as_ptr(), // empty from_path — use the fd
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

/// Create a user namespace with specific UID/GID mappings, solely for use
/// as an idmap descriptor in mount_setattr().
///
/// Implementation: clone3(CLONE_NEWUSER | CLONE_PIDFD) creates a throwaway
/// child that pause()s. Parent writes uid_map/gid_map, opens
/// /proc/<pid>/ns/user, kills the child. The returned fd keeps the namespace
/// alive via kernel refcounting. This is the approach used by Incus and crun.
pub fn create_idmap_userns(
    uid_mappings: &[IdMapping],
    gid_mappings: &[IdMapping],
) -> Result<OwnedFd> {
    // clone3 with CLONE_NEWUSER only — no other namespaces, no cgroup
    let clone_result = clone3::clone3_with_pidfd(clone3::CLONE_NEWUSER, None)?;

    match clone_result {
        None => {
            // === CHILD ===
            // Set parent-death signal so we're killed if parent dies
            let _ = nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL);
            // Just sleep until killed — we're only here so the parent can
            // open our /proc/<pid>/ns/user
            loop {
                nix::unistd::pause();
            }
        }
        Some(clone3::CloneResult {
            child_pid,
            pidfd: _,
        }) => {
            // === PARENT ===
            // Write uid_map and gid_map for the child's user namespace
            let setup_result = (|| -> Result<OwnedFd> {
                user::setup_user_namespace(child_pid, uid_mappings, gid_mappings)?;

                // Open the user namespace fd
                let ns_path = format!("/proc/{child_pid}/ns/user");
                let ns_fd = std::fs::File::open(&ns_path)
                    .map_err(|e| Error::Other(format!("failed to open {ns_path}: {e}")))?;

                Ok(OwnedFd::from(ns_fd))
            })();

            // Kill the child regardless of success/failure
            let child = nix::unistd::Pid::from_raw(child_pid);
            let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(child, None);

            setup_result
        }
    }
}

/// High-level: set up an idmapped mount of source at target.
///
/// 1. Creates a throwaway user namespace with the desired mapping
/// 2. Clones the source mount tree (open_tree)
/// 3. Applies the idmap (mount_setattr)
/// 4. Attaches at the target path (move_mount)
///
/// The target directory must already exist.
pub fn setup_idmapped_mount(
    source: &Path,
    target: &Path,
    uid_mappings: &[IdMapping],
    gid_mappings: &[IdMapping],
) -> Result<()> {
    // 1. Create the idmap user namespace
    let userns_fd = create_idmap_userns(uid_mappings, gid_mappings)?;

    // 2. Clone the source mount tree
    let tree_fd = open_tree(source, true)?;

    // 3. Apply the idmap — kernel copies the mapping data
    mount_setattr_idmap(&tree_fd, &userns_fd)?;

    // 4. userns no longer needed — kernel has copied the mapping
    drop(userns_fd);

    // 5. Attach the idmapped mount at the target
    move_mount(&tree_fd, target)?;

    Ok(())
}
