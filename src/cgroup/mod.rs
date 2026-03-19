//! Cgroup v2 management.
//!
//! Creates cgroup directories under /sys/fs/cgroup and configures
//! resource limits. Uses CLONE_INTO_CGROUP for atomic cgroup assignment.

pub mod cpu;
pub mod memory;
pub mod pids;

use crate::error::{Error, Result};
use crate::protocol::CgroupSpec;
use std::fs;
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SANDBOX_CGROUP_PREFIX: &str = "sandbox";

/// Manages a cgroup for a container.
#[allow(dead_code)]
pub struct Cgroup {
    /// Full path to the cgroup directory.
    path: PathBuf,
    /// Name of the container.
    name: String,
}

#[allow(dead_code)]
impl Cgroup {
    /// Create a new cgroup for the given container.
    pub fn create(container_name: &str) -> Result<Self> {
        let path = Path::new(CGROUP_ROOT)
            .join(SANDBOX_CGROUP_PREFIX)
            .join(container_name);

        // Verify cgroup v2 is available
        if !Path::new(CGROUP_ROOT).join("cgroup.controllers").exists() {
            return Err(Error::CgroupV2NotAvailable);
        }

        // Create the sandbox parent cgroup if needed
        let parent = Path::new(CGROUP_ROOT).join(SANDBOX_CGROUP_PREFIX);
        if !parent.exists() {
            fs::create_dir_all(&parent).map_err(|e| Error::Cgroup {
                path: parent.clone(),
                source: e,
            })?;

            // Enable controllers in the parent
            enable_controllers(&parent)?;
        }

        // Create the container cgroup
        fs::create_dir_all(&path).map_err(|e| Error::Cgroup {
            path: path.clone(),
            source: e,
        })?;

        Ok(Self {
            path,
            name: container_name.to_string(),
        })
    }

    /// Apply resource limits from a CgroupSpec.
    pub fn apply_limits(&self, spec: &CgroupSpec) -> Result<()> {
        if let Some(max) = spec.memory_max {
            memory::set_memory_max(&self.path, max)?;
        }
        if let Some(high) = spec.memory_high {
            memory::set_memory_high(&self.path, high)?;
        }
        if let Some((quota, period)) = spec.cpu_max {
            cpu::set_cpu_max(&self.path, quota, period)?;
        }
        if let Some(weight) = spec.cpu_weight {
            cpu::set_cpu_weight(&self.path, weight)?;
        }
        if let Some(max) = spec.pids_max {
            pids::set_pids_max(&self.path, max)?;
        }
        Ok(())
    }

    /// Open the cgroup directory as an fd for CLONE_INTO_CGROUP.
    pub fn open_fd(&self) -> Result<OwnedFd> {
        let fd = unsafe {
            libc::open(
                std::ffi::CString::new(self.path.to_str().unwrap_or(""))
                    .map_err(|e| Error::Cgroup {
                        path: self.path.clone(),
                        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, e),
                    })?
                    .as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Error::Cgroup {
                path: self.path.clone(),
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Get the cgroup path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the container name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Destroy the cgroup directory.
    /// All processes must have exited first.
    pub fn destroy(&self) -> Result<()> {
        if self.path.exists() {
            fs::remove_dir(&self.path).map_err(|e| Error::Cgroup {
                path: self.path.clone(),
                source: e,
            })?;
        }
        Ok(())
    }
}

/// Enable controllers in a cgroup's subtree_control.
fn enable_controllers(path: &Path) -> Result<()> {
    let controllers_path = path.join("cgroup.subtree_control");

    // Try to enable the controllers we need
    for controller in &["+memory", "+cpu", "+pids"] {
        // Ignore errors — controller might not be available
        let _ = fs::write(&controllers_path, controller);
    }

    Ok(())
}

/// Write a value to a cgroup file.
pub(crate) fn write_cgroup_file(path: &Path, file: &str, value: &str) -> Result<()> {
    let file_path = path.join(file);
    fs::write(&file_path, value).map_err(|e| Error::Cgroup {
        path: file_path,
        source: e,
    })?;
    Ok(())
}
