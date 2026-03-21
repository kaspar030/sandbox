//! Daemon state persistence.
//!
//! Persists container metadata to `<state_dir>/<name>.json` so the daemon can
//! clean up leftover resources after a crash or reboot. The state_dir is
//! derived from the daemon's --data-dir (typically `<data_dir>/state/`).
//!
//! Write points (2-3 per container lifetime):
//! 1. After container start succeeds
//! 2. On container exit (state -> Stopped)
//! 3. On container destroy (delete file)

use sandbox::protocol::{BlockVolumeState, ContainerSpec, ContainerState};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Serializable subset of container state — everything needed to clean up
/// after a crash. File descriptors (pidfd, pty_master) and in-memory structs
/// (Cgroup) are not persisted; they cannot survive a process restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRecord {
    pub spec: ContainerSpec,
    pub state: ContainerState,
    pub pid: i32,
    pub cgroup_path: PathBuf,
    pub idmap_mount: Option<PathBuf>,
    pub rootfs_path: Option<PathBuf>,
    pub pool_name: Option<String>,
    pub ephemeral: bool,
    #[serde(default)]
    pub manually_stopped: bool,
    /// Active block volume mounts (for cleanup on stop/crash).
    #[serde(default)]
    pub block_volumes: Vec<BlockVolumeState>,
}

/// Ensure the state directory exists.
pub fn ensure_state_dir(state_dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(state_dir)
}

/// Path to a container's state file.
fn state_path(state_dir: &Path, name: &str) -> PathBuf {
    state_dir.join(format!("{name}.json"))
}

/// Persist a container record to disk. Uses write-to-temp + rename for
/// atomicity. Calls fsync on the file before rename.
pub fn save_state(state_dir: &Path, name: &str, record: &ContainerRecord) -> std::io::Result<()> {
    let path = state_path(state_dir, name);
    let tmp_path = path.with_extension("json.tmp");

    let json = serde_json::to_string(record).map_err(std::io::Error::other)?;

    let mut f = fs::File::create(&tmp_path)?;
    f.write_all(json.as_bytes())?;
    f.sync_all()?;

    fs::rename(&tmp_path, &path)?;
    Ok(())
}

/// Remove a container's state file.
pub fn remove_state(state_dir: &Path, name: &str) {
    let _ = fs::remove_file(state_path(state_dir, name));
}

/// Load all persisted container records. Returns (name, record) pairs.
/// Skips files that fail to parse (logs a warning).
pub fn load_all_states(state_dir: &Path) -> Vec<(String, ContainerRecord)> {
    let entries = match fs::read_dir(state_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut records = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            match fs::read_to_string(&path) {
                Ok(json) => match serde_json::from_str::<ContainerRecord>(&json) {
                    Ok(record) => records.push((name, record)),
                    Err(e) => {
                        tracing::warn!("failed to parse state file {}: {e}", path.display());
                        let _ = fs::remove_file(&path);
                    }
                },
                Err(e) => {
                    tracing::warn!("failed to read state file {}: {e}", path.display());
                }
            }
        }
    }
    records
}
