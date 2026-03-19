//! Memory cgroup v2 controls.

use super::write_cgroup_file;
use crate::error::Result;
use std::path::Path;

/// Set memory.max (hard limit in bytes).
/// The kernel will OOM-kill processes exceeding this.
pub fn set_memory_max(cgroup_path: &Path, bytes: u64) -> Result<()> {
    write_cgroup_file(cgroup_path, "memory.max", &bytes.to_string())
}

/// Set memory.high (soft limit in bytes).
/// The kernel will throttle memory allocation above this.
pub fn set_memory_high(cgroup_path: &Path, bytes: u64) -> Result<()> {
    write_cgroup_file(cgroup_path, "memory.high", &bytes.to_string())
}
