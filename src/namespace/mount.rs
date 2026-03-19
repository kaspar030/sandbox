//! Mount namespace setup.
//!
//! Handles bind mounts, special filesystem mounts, and making the
//! rootfs mount private so mounts don't propagate to the host.

use crate::error::{Error, Result};
use crate::protocol::BindMount;
use nix::mount::MsFlags;
use std::path::Path;

/// Make all mounts private (prevent propagation to/from host).
/// This must be called early in the child, before any other mounts.
pub fn make_mounts_private() -> Result<()> {
    nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| Error::Mount {
        path: "/".into(),
        source: std::io::Error::from_raw_os_error(e as i32),
    })?;

    Ok(())
}

/// Set up bind mounts from host into the container rootfs.
pub fn setup_bind_mounts(rootfs: &Path, bind_mounts: &[BindMount]) -> Result<()> {
    for bm in bind_mounts {
        let target = rootfs.join(bm.target.trim_start_matches('/'));

        // Create target directory if it doesn't exist
        if Path::new(&bm.source).is_dir() {
            std::fs::create_dir_all(&target).map_err(|e| Error::Mount {
                path: target.clone(),
                source: e,
            })?;
        } else {
            // For file bind mounts, ensure parent dir exists and create the file
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| Error::Mount {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
            }
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&target)
                .map_err(|e| Error::Mount {
                    path: target.clone(),
                    source: e,
                })?;
        }

        // Bind mount
        nix::mount::mount(
            Some(bm.source.as_str()),
            &target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| Error::Mount {
            path: target.clone(),
            source: std::io::Error::from_raw_os_error(e as i32),
        })?;

        // If readonly, remount with MS_RDONLY
        if bm.readonly {
            nix::mount::mount(
                None::<&str>,
                &target,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC,
                None::<&str>,
            )
            .map_err(|e| Error::Mount {
                path: target,
                source: std::io::Error::from_raw_os_error(e as i32),
            })?;
        }
    }

    Ok(())
}

/// Device nodes to bind-mount from the host into the container's /dev.
const HOST_DEV_NODES: &[&str] = &[
    "null", "zero", "full", "random", "urandom", "tty",
];

/// Mount /dev with minimal device nodes.
///
/// Bind-mounts device nodes directly from host `/dev/<name>` paths.
/// This runs before `pivot_root`, so host paths are still accessible.
/// The bind-mount preserves the source superblock (host devtmpfs, no
/// `SB_I_NODEV`), so the devices remain functional inside the user
/// namespace.
pub fn setup_dev(rootfs: &Path) -> Result<()> {
    let dev_path = rootfs.join("dev");
    std::fs::create_dir_all(&dev_path).map_err(|e| Error::Mount {
        path: dev_path.clone(),
        source: e,
    })?;

    // Mount tmpfs on /dev for a clean device directory
    nix::mount::mount(
        Some("tmpfs"),
        &dev_path,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME,
        Some("mode=755,size=65536k"),
    )
    .map_err(|e| Error::Mount {
        path: dev_path.clone(),
        source: std::io::Error::from_raw_os_error(e as i32),
    })?;

    // Bind-mount each device node from the host
    for name in HOST_DEV_NODES {
        let dev_node = dev_path.join(name);
        let host_path = format!("/dev/{name}");

        // Create empty file as bind-mount target
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&dev_node)
            .map_err(|e| Error::Mount {
                path: dev_node.clone(),
                source: e,
            })?;

        nix::mount::mount(
            Some(host_path.as_str()),
            &dev_node,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| Error::Mount {
            path: dev_node,
            source: std::io::Error::from_raw_os_error(e as i32),
        })?;
    }

    // Create /dev/pts + devpts mount (non-fatal — may fail in some userns configs)
    let pts_path = dev_path.join("pts");
    std::fs::create_dir_all(&pts_path).map_err(|e| Error::Mount {
        path: pts_path.clone(),
        source: e,
    })?;

    match nix::mount::mount(
        Some("devpts"),
        &pts_path,
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=620"),
    ) {
        Ok(()) => {
            let _ = std::os::unix::fs::symlink("pts/ptmx", dev_path.join("ptmx"));
        }
        Err(e) => {
            tracing::warn!("devpts mount failed: {e}");
        }
    }

    // Create /dev/shm (non-fatal)
    let shm_path = dev_path.join("shm");
    std::fs::create_dir_all(&shm_path).map_err(|e| Error::Mount {
        path: shm_path.clone(),
        source: e,
    })?;

    if let Err(e) = nix::mount::mount(
        Some("tmpfs"),
        &shm_path,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("mode=1777,size=65536k"),
    ) {
        tracing::warn!("shm tmpfs mount failed: {e}");
    }

    // Symlinks
    let symlinks = [
        ("/proc/self/fd", "fd"),
        ("/proc/self/fd/0", "stdin"),
        ("/proc/self/fd/1", "stdout"),
        ("/proc/self/fd/2", "stderr"),
    ];
    for (target, name) in &symlinks {
        let link = dev_path.join(name);
        match std::os::unix::fs::symlink(target, &link) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                tracing::warn!("symlink /dev/{name}: {e}");
            }
        }
    }

    Ok(())
}

/// Mount /sys inside the container (read-only).
pub fn setup_sys(rootfs: &Path) -> Result<()> {
    let sys_path = rootfs.join("sys");
    std::fs::create_dir_all(&sys_path).map_err(|e| Error::Mount {
        path: sys_path.clone(),
        source: e,
    })?;

    nix::mount::mount(
        Some("sysfs"),
        &sys_path,
        Some("sysfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .map_err(|e| Error::Mount {
        path: sys_path,
        source: std::io::Error::from_raw_os_error(e as i32),
    })?;

    Ok(())
}
