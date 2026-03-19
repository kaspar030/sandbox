//! CPU cgroup v2 controls.

use super::write_cgroup_file;
use crate::error::Result;
use std::path::Path;

/// Set cpu.max (quota and period in microseconds).
/// E.g., (50000, 100000) means 50% of one CPU.
/// "max 100000" means unlimited.
pub fn set_cpu_max(cgroup_path: &Path, quota_us: u64, period_us: u64) -> Result<()> {
    write_cgroup_file(cgroup_path, "cpu.max", &format!("{quota_us} {period_us}"))
}

/// Set cpu.weight (1-10000, default 100).
/// Higher values get more CPU time relative to other cgroups.
pub fn set_cpu_weight(cgroup_path: &Path, weight: u32) -> Result<()> {
    write_cgroup_file(cgroup_path, "cpu.weight", &weight.to_string())
}
