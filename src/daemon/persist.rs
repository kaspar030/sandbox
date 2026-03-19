//! Daemon state persistence.
//!
//! Persists container metadata to `/var/lib/sandbox/state/<name>.json` so the
//! daemon can clean up leftover resources after a crash or reboot. Only
//! non-ephemeral containers are persisted; ephemeral containers are cleaned up
//! on exit anyway.
//!
//! Write points (2-3 per container lifetime):
//! 1. After container start succeeds
//! 2. On container exit (state -> Stopped)
//! 3. On container destroy (delete file)

use sandbox::protocol::{ContainerSpec, ContainerState};
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
}

/// Base directory for state files.
const STATE_DIR: &str = "/var/lib/sandbox/state";

/// Ensure the state directory exists.
pub fn ensure_state_dir() -> std::io::Result<()> {
    fs::create_dir_all(STATE_DIR)
}

/// Path to a container's state file.
fn state_path(name: &str) -> PathBuf {
    Path::new(STATE_DIR).join(format!("{name}.json"))
}

/// Persist a container record to disk. Uses write-to-temp + rename for
/// atomicity. Calls fsync on the file before rename.
pub fn save_state(name: &str, record: &ContainerRecord) -> std::io::Result<()> {
    let path = state_path(name);
    let tmp_path = path.with_extension("json.tmp");

    let json = serde_json::to_string(record).map_err(std::io::Error::other)?;

    let mut f = fs::File::create(&tmp_path)?;
    f.write_all(json.as_bytes())?;
    f.sync_all()?;

    fs::rename(&tmp_path, &path)?;
    Ok(())
}

/// Update only the state field of an existing record. Read-modify-write.
pub fn update_state(name: &str, new_state: ContainerState) -> std::io::Result<()> {
    let path = state_path(name);
    let json = fs::read_to_string(&path)?;
    let mut record: ContainerRecord = serde_json::from_str(&json)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    record.state = new_state;
    save_state(name, &record)
}

/// Remove a container's state file.
pub fn remove_state(name: &str) {
    let _ = fs::remove_file(state_path(name));
}

/// Load all persisted container records. Returns (name, record) pairs.
/// Skips files that fail to parse (logs a warning).
pub fn load_all_states() -> Vec<(String, ContainerRecord)> {
    let dir = Path::new(STATE_DIR);
    let entries = match fs::read_dir(dir) {
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
                        // Remove corrupt state file
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
