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
/// namespace even though the target tmpfs has `SB_I_NODEV`.
pub fn setup_dev(rootfs: &Path) -> Result<()> {
    let dev_path = rootfs.join("dev");
    std::fs::create_dir_all(&dev_path).map_err(|e| Error::Mount {
        path: dev_path.clone(),
        source: e,
    })?;

    // Mount tmpfs on /dev
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

    // Bind-mount each device node from the host.
    // Source is the host's /dev/<name> (on devtmpfs, init user namespace).
    // Target is <rootfs>/dev/<name> (on our tmpfs).
    // The bind mount preserves the source superblock, so the device works
    // despite the target tmpfs having SB_I_NODEV.
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

        // Use raw libc::mount to avoid any nix path conversion overhead
        let c_src = std::ffi::CString::new(host_path.as_str())
            .map_err(|e| Error::Other(format!("invalid device path: {e}")))?;
        let c_dst = std::ffi::CString::new(dev_node.as_os_str().as_encoded_bytes())
            .map_err(|e| Error::Other(format!("invalid device path: {e}")))?;

        let ret = unsafe {
            libc::mount(
                c_src.as_ptr(),
                c_dst.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            // Non-fatal: log and skip this device
            tracing::warn!(
                "bind-mount {host_path} -> {}: {} (errno {})",
                dev_node.display(),
                err,
                err.raw_os_error().unwrap_or(0)
            );
        }
    }

    // Create /dev/pts — use newinstance for user namespace compatibility.
    // Non-fatal if it fails (some user namespace configs block devpts).
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
            // Create /dev/ptmx symlink to /dev/pts/ptmx
            let ptmx = dev_path.join("ptmx");
            let _ = std::os::unix::fs::symlink("pts/ptmx", &ptmx);
        }
        Err(e) => {
            tracing::warn!("devpts mount failed (expected in some user namespace configs): {e}");
        }
    }

    // Create /dev/shm
    let shm_path = dev_path.join("shm");
    std::fs::create_dir_all(&shm_path).map_err(|e| Error::Mount {
        path: shm_path.clone(),
        source: e,
    })?;

    nix::mount::mount(
        Some("tmpfs"),
        &shm_path,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("mode=1777,size=65536k"),
    )
    .map_err(|e| Error::Mount {
        path: shm_path,
        source: std::io::Error::from_raw_os_error(e as i32),
    })?;

    // Symlinks
    std::os::unix::fs::symlink("/proc/self/fd", dev_path.join("fd"))
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })
        .map_err(|e| Error::Mount {
            path: dev_path.join("fd"),
            source: e,
        })?;

    std::os::unix::fs::symlink("/proc/self/fd/0", dev_path.join("stdin"))
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })
        .map_err(|e| Error::Mount {
            path: dev_path.join("stdin"),
            source: e,
        })?;

    std::os::unix::fs::symlink("/proc/self/fd/1", dev_path.join("stdout"))
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })
        .map_err(|e| Error::Mount {
            path: dev_path.join("stdout"),
            source: e,
        })?;

    std::os::unix::fs::symlink("/proc/self/fd/2", dev_path.join("stderr"))
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })
        .map_err(|e| Error::Mount {
            path: dev_path.join("stderr"),
            source: e,
        })?;

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
