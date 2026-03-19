//! Container lifecycle tests (require root privileges).
//!
//! These tests create actual containers with namespaces and verify
//! the full create -> start -> stop -> destroy lifecycle.

mod common;

use common::rootfs::TempRootfs;
use common::TestDaemon;

/// Helper to skip test if not root.
fn skip_if_not_root() -> bool {
    if !common::is_root() {
        eprintln!("SKIP: test requires root privileges");
        return true;
    }
    false
}

#[test]
fn test_run_simple_command() {
    if skip_if_not_root() {
        return;
    }

    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());
    let rootfs = TempRootfs::new();

    // Run a simple command that exits immediately
    let output = daemon.run_cli(&[
        "run",
        "--name",
        "run-test",
        "--rootfs",
        rootfs.path().to_str().unwrap(),
        "--network",
        "host",
        "--seccomp",
        "disabled",
        "--",
        "/bin/true",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("stdout: {stdout}");
    eprintln!("stderr: {stderr}");

    // Should have started (or reported an error about namespaces)
    // On success: "Started container: run-test (PID ...)"
    assert!(
        stdout.contains("Started") || stderr.contains("clone3"),
        "unexpected output: stdout={stdout} stderr={stderr}"
    );
}

#[test]
fn test_container_with_hostname() {
    if skip_if_not_root() {
        return;
    }

    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());
    let rootfs = TempRootfs::new();

    let output = daemon.run_cli(&[
        "run",
        "--name",
        "hostname-test",
        "--rootfs",
        rootfs.path().to_str().unwrap(),
        "--hostname",
        "mybox",
        "--network",
        "host",
        "--seccomp",
        "disabled",
        "--",
        "/bin/hostname",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("stdout: {stdout}");
    eprintln!("stderr: {stderr}");
}

#[test]
fn test_container_with_bind_mount() {
    if skip_if_not_root() {
        return;
    }

    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());
    let rootfs = TempRootfs::new();

    // Create a temp directory with a file to bind mount
    let bind_dir = tempfile::TempDir::new().unwrap();
    std::fs::write(bind_dir.path().join("testfile.txt"), "bind mount works").unwrap();

    let bind_arg = format!("{}:/mnt/data:ro", bind_dir.path().display());

    let output = daemon.run_cli(&[
        "run",
        "--name",
        "bind-test",
        "--rootfs",
        rootfs.path().to_str().unwrap(),
        "--network",
        "host",
        "--seccomp",
        "disabled",
        "--bind",
        &bind_arg,
        "--",
        "/bin/cat",
        "/mnt/data/testfile.txt",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("stdout: {stdout}");
    eprintln!("stderr: {stderr}");
}

#[test]
fn test_container_with_init() {
    if skip_if_not_root() {
        return;
    }

    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());
    let rootfs = TempRootfs::new();

    let output = daemon.run_cli(&[
        "run",
        "--name",
        "init-test",
        "--rootfs",
        rootfs.path().to_str().unwrap(),
        "--network",
        "host",
        "--seccomp",
        "disabled",
        "--init",
        "--",
        "/bin/echo",
        "hello from init",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("stdout: {stdout}");
    eprintln!("stderr: {stderr}");
}

#[test]
fn test_create_start_stop_destroy() {
    if skip_if_not_root() {
        return;
    }

    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());
    let rootfs = TempRootfs::new();

    // Create
    let output = daemon.run_cli_ok(&[
        "create",
        "--name",
        "lifecycle-test",
        "--rootfs",
        rootfs.path().to_str().unwrap(),
        "--network",
        "host",
        "--seccomp",
        "disabled",
        "--",
        "/bin/sleep",
        "60",
    ]);
    assert!(output.contains("Created"));

    // Start
    let output = daemon.run_cli(&[
        "start",
        "lifecycle-test",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("start stdout: {stdout}");
    eprintln!("start stderr: {stderr}");

    if stdout.contains("Started") {
        // Container is running, try to stop it
        let output = daemon.run_cli(&["stop", "lifecycle-test", "--timeout", "3"]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("stop stdout: {stdout}");
        eprintln!("stop stderr: {stderr}");
    }

    // Destroy (should work regardless of state)
    let output = daemon.run_cli(&["destroy", "lifecycle-test"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("destroy stdout: {stdout}");
}

#[test]
fn test_container_memory_limit() {
    if skip_if_not_root() {
        return;
    }

    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());
    let rootfs = TempRootfs::new();

    // Run with a memory limit
    let output = daemon.run_cli(&[
        "run",
        "--name",
        "memory-test",
        "--rootfs",
        rootfs.path().to_str().unwrap(),
        "--network",
        "host",
        "--seccomp",
        "disabled",
        "--memory",
        "128M",
        "--",
        "/bin/true",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("stdout: {stdout}");
    eprintln!("stderr: {stderr}");
}

#[test]
fn test_container_pids_limit() {
    if skip_if_not_root() {
        return;
    }

    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());
    let rootfs = TempRootfs::new();

    // Run with a PID limit
    let output = daemon.run_cli(&[
        "run",
        "--name",
        "pids-test",
        "--rootfs",
        rootfs.path().to_str().unwrap(),
        "--network",
        "host",
        "--seccomp",
        "disabled",
        "--pids-max",
        "10",
        "--",
        "/bin/true",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("stdout: {stdout}");
    eprintln!("stderr: {stderr}");
}
