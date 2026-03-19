//! Hot bind mount support — add/remove bind mounts to running containers.
//!
//! Approach (Variant A from testing):
//! 1. Parent: open_tree(source) in host ns — creates detached mount clone
//! 2. Parent: if readonly, set_readonly(tree_fd)
//! 3. Fork helper that inherits tree_fd:
//!    a. setns(CLONE_NEWUSER) — enter container's user namespace
//!    b. setns(CLONE_NEWNS) — enter container's mount namespace
//!    c. chroot("/") + chdir("/") — now / is the container's rootfs
//!    d. mkdir -p <target>
//!    e. move_mount(tree_fd, <target>) — attach the detached mount
//!
//! This works because open_tree creates an "unowned" detached mount that
//! can be moved into a different mount namespace via move_mount, even from
//! a different user namespace context.

use crate::error::{Error, Result};
use crate::sys::mount_api;
use std::os::fd::AsRawFd;
use std::path::Path;

/// Add a bind mount to a running container.
pub fn hot_bind_mount(
    container_pid: i32,
    source: &Path,
    target: &str,
    readonly: bool,
) -> Result<()> {
    // Step 1: Clone the source mount in the host namespace
    let tree_fd = mount_api::open_tree(source, true)?;

    // Step 2: Set readonly if requested
    if readonly {
        mount_api::set_readonly(&tree_fd)?;
    }

    // Step 3: Fork helper to enter container namespaces and attach the mount
    let tree_raw = tree_fd.as_raw_fd();
    let is_file = source.is_file();
    let target = target.to_string();

    match unsafe { nix::unistd::fork() } {
        Err(e) => Err(Error::Other(format!("fork failed: {e}"))),
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            drop(tree_fd); // child inherited the fd
            match nix::sys::wait::waitpid(child, None) {
                Ok(nix::sys::wait::WaitStatus::Exited(_, 0)) => Ok(()),
                Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => Err(Error::Other(format!(
                    "hot mount helper exited with code {code}"
                ))),
                Ok(status) => Err(Error::Other(format!(
                    "hot mount helper unexpected status: {status:?}"
                ))),
                Err(e) => Err(Error::Other(format!("waitpid failed: {e}"))),
            }
        }
        Ok(nix::unistd::ForkResult::Child) => {
            let _ = nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL);
            child_do_mount(container_pid, tree_raw, &target, is_file);
        }
    }
}

/// Remove a bind mount from a running container.
pub fn hot_unmount(container_pid: i32, target: &str) -> Result<()> {
    let target = target.to_string();

    match unsafe { nix::unistd::fork() } {
        Err(e) => Err(Error::Other(format!("fork failed: {e}"))),
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            match nix::sys::wait::waitpid(child, None) {
                Ok(nix::sys::wait::WaitStatus::Exited(_, 0)) => Ok(()),
                Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => Err(Error::Other(format!(
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
            child_do_unmount(container_pid, &target);
        }
    }
}

/// Enter the container's user + mount namespaces, chroot into container root.
fn enter_container_ns(container_pid: i32) -> bool {
    // setns(CLONE_NEWUSER)
    let user_ns = format!("/proc/{container_pid}/ns/user");
    let ns_fd = match std::fs::File::open(&user_ns) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("hot_mount: open {user_ns}: {e}");
            return false;
        }
    };
    if let Err(e) = nix::sched::setns(&ns_fd, nix::sched::CloneFlags::CLONE_NEWUSER) {
        eprintln!("hot_mount: setns(CLONE_NEWUSER): {e}");
        return false;
    }
    drop(ns_fd);

    // setns(CLONE_NEWNS)
    let mnt_ns = format!("/proc/{container_pid}/ns/mnt");
    let ns_fd = match std::fs::File::open(&mnt_ns) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("hot_mount: open {mnt_ns}: {e}");
            return false;
        }
    };
    if let Err(e) = nix::sched::setns(&ns_fd, nix::sched::CloneFlags::CLONE_NEWNS) {
        eprintln!("hot_mount: setns(CLONE_NEWNS): {e}");
        return false;
    }
    drop(ns_fd);

    // Become container root. After setns(CLONE_NEWUSER), the process is uid 65534
    // (overflow/nobody) because host uid 0 is not mapped in the container's user
    // namespace. setresuid/setresgid to 0 makes us container root with full
    // capabilities — this is what nsenter does internally.
    if let Err(e) = nix::unistd::setresgid(0.into(), 0.into(), 0.into()) {
        eprintln!("hot_mount: setresgid(0,0,0): {e}");
        return false;
    }
    if let Err(e) = nix::unistd::setresuid(0.into(), 0.into(), 0.into()) {
        eprintln!("hot_mount: setresuid(0,0,0): {e}");
        return false;
    }

    // chroot + chdir into the container's root
    if let Err(e) = nix::unistd::chroot("/") {
        eprintln!("hot_mount: chroot(/): {e}");
        return false;
    }
    if let Err(e) = std::env::set_current_dir("/") {
        eprintln!("hot_mount: chdir(/): {e}");
        return false;
    }

    true
}

/// Child process: enter container ns, mkdir target, move_mount.
fn child_do_mount(container_pid: i32, tree_raw: i32, target: &str, is_file: bool) -> ! {
    if !enter_container_ns(container_pid) {
        std::process::exit(1);
    }

    // Create mount point
    let target_path = Path::new(target);
    if is_file {
        if let Some(parent) = target_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("hot_mount: mkdir -p {}: {e}", parent.display());
                std::process::exit(1);
            }
        }
        if !target_path.exists() {
            if let Err(e) = std::fs::File::create(target_path) {
                eprintln!("hot_mount: touch {target}: {e}");
                std::process::exit(1);
            }
        }
    } else if let Err(e) = std::fs::create_dir_all(target_path) {
        eprintln!("hot_mount: mkdir -p {target}: {e}");
        std::process::exit(1);
    }

    // Reconstruct OwnedFd from inherited raw fd
    let tree_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(tree_raw) };

    if let Err(e) = mount_api::move_mount(&tree_fd, target_path) {
        eprintln!("hot_mount: move_mount: {e}");
        std::process::exit(1);
    }

    std::process::exit(0);
}

/// Child process: enter container ns, umount target.
fn child_do_unmount(container_pid: i32, target: &str) -> ! {
    if !enter_container_ns(container_pid) {
        std::process::exit(1);
    }

    let target_path = Path::new(target);
    if let Err(e) = nix::mount::umount2(target_path, nix::mount::MntFlags::MNT_DETACH) {
        eprintln!("hot_unmount: umount {target}: {e}");
        std::process::exit(1);
    }

    std::process::exit(0);
}

use std::os::fd::FromRawFd;
