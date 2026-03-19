//! PID count cgroup v2 controls.

use super::write_cgroup_file;
use crate::error::Result;
use std::path::Path;

/// Set pids.max (maximum number of processes in the cgroup).
/// Fork/clone will fail with EAGAIN when the limit is reached.
pub fn set_pids_max(cgroup_path: &Path, max: u32) -> Result<()> {
    write_cgroup_file(cgroup_path, "pids.max", &max.to_string())
}
