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

/// Mount /dev with minimal device nodes.
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

    // Create essential device nodes by bind-mounting from host
    let devices = [
        ("null", "null"),
        ("zero", "zero"),
        ("full", "full"),
        ("random", "random"),
        ("urandom", "urandom"),
        ("tty", "tty"),
    ];

    for (name, host_name) in &devices {
        let dev_node = dev_path.join(name);
        let host_dev = Path::new("/dev").join(host_name);

        // Create the file to mount onto
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&dev_node)
            .map_err(|e| Error::Mount {
                path: dev_node.clone(),
                source: e,
            })?;

        // Bind mount from host
        nix::mount::mount(
            Some(&host_dev),
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

    // Create /dev/pts
    let pts_path = dev_path.join("pts");
    std::fs::create_dir_all(&pts_path).map_err(|e| Error::Mount {
        path: pts_path.clone(),
        source: e,
    })?;

    nix::mount::mount(
        Some("devpts"),
        &pts_path,
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=620"),
    )
    .map_err(|e| Error::Mount {
        path: pts_path,
        source: std::io::Error::from_raw_os_error(e as i32),
    })?;

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
