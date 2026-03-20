//! TestContext: manages daemon lifecycle, client connections, and CLI execution.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

pub struct TestContext {
    pub sandbox_bin: PathBuf,
    pub workdir: PathBuf,
    pub data_dir: PathBuf,
    pub socket_path: PathBuf,
    daemon_child: Option<Child>,
    keep: bool,
}

impl TestContext {
    pub fn new(sandbox_bin: PathBuf, pool: &Path, keep: bool) -> Self {
        // Create a unique workdir under the pool
        let id: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let workdir = pool.join(format!("sandbox-e2e-{id}"));
        let data_dir = workdir.join("data");
        let socket_path = workdir.join("sandbox.sock");

        std::fs::create_dir_all(&data_dir).expect("failed to create workdir");

        Self {
            sandbox_bin,
            workdir,
            data_dir,
            socket_path,
            daemon_child: None,
            keep,
        }
    }

    /// Start the daemon process.
    pub fn start_daemon(&mut self) {
        let child = Command::new(&self.sandbox_bin)
            .args([
                "daemon",
                "start",
                "--socket",
                self.socket_path.to_str().unwrap(),
                "--data-dir",
                self.data_dir.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to start daemon");

        self.daemon_child = Some(child);

        // Wait for socket to appear
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.socket_path.exists() {
                // Brief extra wait for the daemon to be fully ready
                std::thread::sleep(Duration::from_millis(100));
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "daemon did not create socket at {} within 10s",
            self.socket_path.display()
        );
    }

    /// Stop the daemon gracefully.
    pub fn stop_daemon(&mut self) {
        // Try graceful shutdown via CLI
        let _ = self.cli(&["daemon", "stop"]);

        // Wait for the process to exit (up to 15 seconds for graceful shutdown)
        if let Some(child) = self.daemon_child.as_mut() {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {
                        if Instant::now() > deadline {
                            let _ = child.kill();
                            let _ = child.wait();
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(_) => break,
                }
            }
        }
        self.daemon_child = None;

        // Remove stale socket
        let _ = std::fs::remove_file(&self.socket_path);
    }

    /// Get a sandbox-client connected to this daemon.
    #[allow(dead_code)]
    pub fn client(&self) -> sandbox_client::Client {
        sandbox_client::Client::connect(Some(self.socket_path.to_str().unwrap()))
            .expect("failed to connect to daemon")
    }

    /// Run a sandbox CLI command, returning the full output.
    pub fn cli(&self, args: &[&str]) -> Output {
        Command::new(&self.sandbox_bin)
            .arg("--socket")
            .arg(self.socket_path.to_str().unwrap())
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("failed to run sandbox CLI: {e}"))
    }

    /// Run a sandbox CLI command and return stdout as a string.
    /// Panics with stderr if the command fails.
    pub fn cli_ok(&self, args: &[&str]) -> String {
        let output = self.cli(args);
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            panic!(
                "CLI command failed: sandbox {}\nstdout: {stdout}\nstderr: {stderr}",
                args.join(" ")
            );
        }
        String::from_utf8_lossy(&output.stdout).to_string()
    }

    /// Run a sandbox CLI command and return stderr.
    #[allow(dead_code)]
    pub fn cli_stderr(&self, args: &[&str]) -> String {
        let output = self.cli(args);
        String::from_utf8_lossy(&output.stderr).to_string()
    }

    /// Check if a CLI command succeeds.
    pub fn cli_succeeds(&self, args: &[&str]) -> bool {
        self.cli(args).status.success()
    }

    /// Check if a CLI command fails.
    pub fn cli_fails(&self, args: &[&str]) -> bool {
        !self.cli(args).status.success()
    }

    /// Ensure required images are available in the daemon.
    ///
    /// Uses a cache directory at `<pool>/cache/` to avoid re-pulling from
    /// the registry on every test run. Images are pulled to cache on first
    /// run, then imported from cache on subsequent runs.
    pub fn ensure_images(&self) {
        let cache_dir = self
            .workdir
            .parent()
            .unwrap_or(Path::new("/pool"))
            .join("cache");
        let _ = std::fs::create_dir_all(&cache_dir);

        let output = self.cli_ok(&["image", "list"]);

        for (name, reference) in &[("alpine", "alpine:latest"), ("ubuntu", "ubuntu:noble")] {
            if output.contains(name) {
                continue;
            }

            let cached_image = cache_dir.join(name);
            if cached_image.is_dir() {
                // Import from cache
                eprint!("  Importing {name} from cache...");
                self.cli_ok(&["image", "import", name, cached_image.to_str().unwrap()]);
                eprintln!("OK");
            } else {
                // Pull from registry, then cache it
                eprint!("  Pulling {reference}...");
                if name == &"ubuntu" {
                    self.cli_ok(&["image", "pull", reference, "--name", name]);
                } else {
                    self.cli_ok(&["image", "pull", reference]);
                }
                eprintln!("OK");

                // Cache the image by copying the storage pool's image dir
                let pool_image = self.data_dir.join("storage/main/images").join(name);
                if pool_image.is_dir() {
                    eprint!("  Caching {name}...");
                    let _ = Command::new("cp")
                        .args(["-a", "--reflink=auto", "--"])
                        .arg(&pool_image)
                        .arg(&cached_image)
                        .output();
                    eprintln!("OK");
                }
            }
        }
    }

    /// Restart the daemon (stop + start).
    #[allow(dead_code)]
    pub fn restart_daemon(&mut self) {
        self.stop_daemon();
        std::thread::sleep(Duration::from_millis(200));
        self.start_daemon();
    }

    /// Kill the daemon abruptly (simulates crash). Does NOT clean up
    /// containers or state — used for recovery tests.
    pub fn kill_daemon(&mut self) {
        if let Some(child) = self.daemon_child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.daemon_child = None;
        let _ = std::fs::remove_file(&self.socket_path);
    }

    /// Read daemon stderr (for debugging).
    #[allow(dead_code)]
    pub fn daemon_stderr(&mut self) -> String {
        if let Some(ref mut child) = self.daemon_child
            && let Some(ref mut stderr) = child.stderr
        {
            let mut buf = String::new();
            let _ = stderr.read_to_string(&mut buf);
            return buf;
        }
        String::new()
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        if self.keep {
            eprintln!(
                "\n  --keep: daemon still running, workdir preserved at {}",
                self.workdir.display()
            );
            eprintln!("  socket: {}", self.socket_path.display());
            // Detach daemon so it's not killed
            if self.daemon_child.is_some() {
                std::mem::forget(self.daemon_child.take());
            }
            return;
        }

        self.stop_daemon();

        // Clean up workdir
        if self.workdir.exists() {
            // Use btrfs subvolume delete for any subvolumes, then rm -rf
            let _ = Command::new("btrfs")
                .args(["subvolume", "delete", "--"])
                .arg(self.workdir.join("data"))
                .output();
            let _ = std::fs::remove_dir_all(&self.workdir);
        }
    }
}
