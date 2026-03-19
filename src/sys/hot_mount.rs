//! Hot bind mount support — add/remove bind mounts to running containers.
//!
//! Uses fork + setns(CLONE_NEWNS) + open_tree/move_mount to inject mounts
//! into a running container's mount namespace from the host.

use crate::error::{Error, Result};
use crate::sys::mount_api;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;

/// Add a bind mount to a running container.
///
/// 1. open_tree(source, OPEN_TREE_CLONE) — clone source mount in host ns
/// 2. If readonly: mount_setattr(MOUNT_ATTR_RDONLY)
/// 3. Fork helper that:
///    a. setns(container_pid, CLONE_NEWNS) — enter container mount ns
///    b. mkdir -p target inside the container
///    c. move_mount(tree_fd, target) — attach the mount
pub fn hot_bind_mount(
    container_pid: i32,
    source: &Path,
    target: &str,
    readonly: bool,
) -> Result<()> {
    // Clone the source mount tree in the host mount namespace
    let tree_fd = mount_api::open_tree(source, true)?;

    // Apply readonly if requested
    if readonly {
        mount_api::set_readonly(&tree_fd)?;
    }

    // Fork a helper to enter the container's mount namespace
    let tree_raw = tree_fd.as_raw_fd();
    let target = target.to_string();

    match unsafe { nix::unistd::fork() } {
        Err(e) => return Err(Error::Other(format!("fork failed: {e}"))),
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            // Parent: wait for helper
            drop(tree_fd); // child inherited the fd
            use nix::sys::wait::{waitpid, WaitStatus};
            match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, 0)) => Ok(()),
                Ok(WaitStatus::Exited(_, code)) => Err(Error::Other(format!(
                    "hot mount helper exited with code {code}"
                ))),
                Ok(status) => Err(Error::Other(format!(
                    "hot mount helper unexpected status: {status:?}"
                ))),
                Err(e) => Err(Error::Other(format!("waitpid failed: {e}"))),
            }
        }
        Ok(nix::unistd::ForkResult::Child) => {
            // Child: enter container mount namespace and perform the mount
            let _ = nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL);

            // Open and enter the container's mount namespace
            let mnt_ns = format!("/proc/{container_pid}/ns/mnt");
            let ns_fd = match std::fs::File::open(&mnt_ns) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("hot_mount: open {mnt_ns}: {e}");
                    std::process::exit(1);
                }
            };
            if let Err(e) = nix::sched::setns(&ns_fd, nix::sched::CloneFlags::CLONE_NEWNS) {
                eprintln!("hot_mount: setns(CLONE_NEWNS): {e}");
                std::process::exit(1);
            }

            // Create the target directory if it doesn't exist
            let target_path = Path::new(&target);
            if let Some(parent) = target_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            // Create the target itself (could be a file or directory mount point)
            if !target_path.exists() {
                let _ = std::fs::create_dir_all(target_path);
            }

            // Reconstruct the OwnedFd from the raw fd inherited across fork
            let tree_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(tree_raw) };

            // Attach the mount
            if let Err(e) = mount_api::move_mount(&tree_fd, target_path) {
                eprintln!("hot_mount: move_mount: {e}");
                std::process::exit(1);
            }

            std::process::exit(0);
        }
    }
}

/// Remove a bind mount from a running container.
///
/// Forks a helper that enters the container's mount namespace and unmounts
/// the target path.
pub fn hot_unmount(container_pid: i32, target: &str) -> Result<()> {
    let target = target.to_string();

    match unsafe { nix::unistd::fork() } {
        Err(e) => return Err(Error::Other(format!("fork failed: {e}"))),
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            use nix::sys::wait::{waitpid, WaitStatus};
            match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, 0)) => Ok(()),
                Ok(WaitStatus::Exited(_, code)) => Err(Error::Other(format!(
                    "hot unmount helper exited with code {code}"
                ))),
                Ok(status) => Err(Error::Other(format!(
                    "hot unmount helper unexpected status: {status:?}"
                ))),
                Err(e) => Err(Error::Other(format!("waitpid failed: {e}"))),
            }
        }
        Ok(nix::unistd::ForkResult::Child) => {
            let _ = nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL);

            let mnt_ns = format!("/proc/{container_pid}/ns/mnt");
            let ns_fd = match std::fs::File::open(&mnt_ns) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("hot_unmount: open {mnt_ns}: {e}");
                    std::process::exit(1);
                }
            };
            if let Err(e) = nix::sched::setns(&ns_fd, nix::sched::CloneFlags::CLONE_NEWNS) {
                eprintln!("hot_unmount: setns(CLONE_NEWNS): {e}");
                std::process::exit(1);
            }

            let target_path = Path::new(&target);
            if let Err(e) = nix::mount::umount2(target_path, nix::mount::MntFlags::MNT_DETACH) {
                eprintln!("hot_unmount: umount2: {e}");
                std::process::exit(1);
            }

            std::process::exit(0);
        }
    }
}
