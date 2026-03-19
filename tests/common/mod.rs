//! Shared test infrastructure.
//!
//! Provides busybox download/caching, temporary rootfs creation,
//! privilege checking, and daemon lifecycle helpers.

pub mod rootfs;

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

/// Check if the current user has root privileges.
#[allow(dead_code)]
pub fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// Check if unprivileged user namespaces are available.
#[allow(dead_code)]
pub fn has_unprivileged_userns() -> bool {
    let path = "/proc/sys/kernel/unprivileged_userns_clone";
    if let Ok(content) = std::fs::read_to_string(path) {
        return content.trim() == "1";
    }
    // If the file doesn't exist, unprivileged userns might still be available
    // (some distros don't have this sysctl). Try to unshare to check.
    let result = Command::new("unshare")
        .args(["--user", "--", "true"])
        .output();
    matches!(result, Ok(output) if output.status.success())
}

/// Skip test if not running as root.
#[allow(dead_code)]
pub fn require_root() {
    if !is_root() {
        eprintln!("SKIP: test requires root privileges");
        return;
    }
}

/// Path to the sandbox binary (built by cargo).
#[allow(dead_code)]
pub fn sandbox_binary() -> PathBuf {
    // Find the binary in the target directory
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove 'deps'
    path.push("sandbox");
    path
}

/// A running daemon instance for testing.
#[allow(dead_code)]
pub struct TestDaemon {
    pub process: Child,
    pub socket_path: PathBuf,
    pub data_dir: PathBuf,
}

#[allow(dead_code)]
impl TestDaemon {
    /// Start a sandbox daemon on a temporary socket with a temporary data dir.
    pub fn start(socket_dir: &Path) -> Self {
        let socket_path = socket_dir.join("sandbox.sock");
        let data_dir = socket_dir.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();

        let binary = sandbox_binary();
        let process = Command::new(&binary)
            .args([
                "--socket",
                socket_path.to_str().unwrap(),
                "daemon",
                "start",
                "--foreground",
                "--data-dir",
                data_dir.to_str().unwrap(),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to start daemon at {:?}: {}", binary, e));

        let daemon = Self {
            process,
            socket_path: socket_path.clone(),
            data_dir,
        };

        // Wait for the socket to appear
        for _ in 0..50 {
            if socket_path.exists() {
                // Try to actually connect
                if UnixStream::connect(&socket_path).is_ok() {
                    return daemon;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        panic!("daemon did not start within 5 seconds");
    }

    /// Get the socket path as a string.
    pub fn socket(&self) -> &str {
        self.socket_path.to_str().unwrap()
    }

    /// Run a sandbox CLI command against this daemon.
    pub fn run_cli(&self, args: &[&str]) -> std::process::Output {
        let binary = sandbox_binary();
        Command::new(binary)
            .arg("--socket")
            .arg(self.socket())
            .args(args)
            .output()
            .expect("failed to run sandbox CLI")
    }

    /// Import a test image from a TempRootfs into the daemon's storage.
    pub fn import_image(&self, name: &str, rootfs: &rootfs::TempRootfs) {
        let output = self.run_cli(&["image", "import", name, rootfs.path().to_str().unwrap()]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "image import failed:\nstdout: {stdout}\nstderr: {stderr}"
        );
    }

    /// Run a sandbox CLI command and return stdout as a string.
    pub fn run_cli_ok(&self, args: &[&str]) -> String {
        let output = self.run_cli(args);
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            panic!(
                "sandbox CLI failed with args {:?}\nstdout: {}\nstderr: {}",
                args, stdout, stderr
            );
        }
        String::from_utf8_lossy(&output.stdout).to_string()
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        // Send shutdown
        let _ = self.run_cli(&["daemon", "stop"]);
        // Give it a moment to shut down
        std::thread::sleep(Duration::from_millis(200));
        // Force kill if still running
        let _ = self.process.kill();
        let _ = self.process.wait();
        // Clean up socket
        let _ = std::fs::remove_file(&self.socket_path);
    }
}
