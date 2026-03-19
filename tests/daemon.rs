//! Daemon protocol and lifecycle tests.
//!
//! These tests verify the daemon starts, accepts connections,
//! handles the protocol correctly, and shuts down cleanly.

mod common;

use common::rootfs::TempRootfs;
use common::TestDaemon;


#[test]
fn test_daemon_starts_and_stops() {
    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());

    // Verify daemon is running by listing containers (should be empty)
    let output = daemon.run_cli_ok(&["list"]);
    assert!(
        output.contains("No containers"),
        "expected 'No containers', got: {output}"
    );

    // Stop daemon
    let output = daemon.run_cli(&["daemon", "stop"]);
    assert!(output.status.success(), "daemon stop failed");
}

#[test]
fn test_daemon_create_and_list() {
    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());
    let rootfs = TempRootfs::new();

    // Create a container (don't start it — that requires privileges)
    let output = daemon.run_cli(&[
        "create",
        "--name",
        "test-create",
        "--rootfs",
        rootfs.path().to_str().unwrap(),
        "--",
        "/bin/echo",
        "hello",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Created container: test-create"),
        "unexpected create output: {stdout}"
    );

    // List should show the container
    let output = daemon.run_cli_ok(&["list"]);
    assert!(
        output.contains("test-create"),
        "container not in list: {output}"
    );
    assert!(
        output.contains("Created"),
        "expected Created state: {output}"
    );
}

#[test]
fn test_daemon_create_duplicate_name() {
    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());
    let rootfs = TempRootfs::new();

    // Create first container
    daemon.run_cli_ok(&[
        "create",
        "--name",
        "dup-test",
        "--rootfs",
        rootfs.path().to_str().unwrap(),
        "--",
        "/bin/sh",
    ]);

    // Try to create another with the same name
    let output = daemon.run_cli(&[
        "create",
        "--name",
        "dup-test",
        "--rootfs",
        rootfs.path().to_str().unwrap(),
        "--",
        "/bin/sh",
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("already exists"),
        "expected 'already exists' error: {combined}"
    );
}

#[test]
fn test_daemon_destroy() {
    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());
    let rootfs = TempRootfs::new();

    // Create
    daemon.run_cli_ok(&[
        "create",
        "--name",
        "destroy-test",
        "--rootfs",
        rootfs.path().to_str().unwrap(),
        "--",
        "/bin/sh",
    ]);

    // Destroy
    let output = daemon.run_cli_ok(&["destroy", "destroy-test"]);
    assert!(
        output.contains("Destroyed"),
        "expected 'Destroyed': {output}"
    );

    // List should be empty
    let output = daemon.run_cli_ok(&["list"]);
    assert!(
        output.contains("No containers"),
        "expected no containers: {output}"
    );
}

#[test]
fn test_daemon_destroy_nonexistent() {
    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());

    let output = daemon.run_cli(&["destroy", "nonexistent"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("not found"),
        "expected 'not found': {combined}"
    );
}

#[test]
fn test_daemon_stop_nonexistent() {
    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());

    let output = daemon.run_cli(&["stop", "nonexistent"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("not found"),
        "expected 'not found': {combined}"
    );
}

#[test]
fn test_daemon_multiple_containers() {
    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());
    let rootfs = TempRootfs::new();

    // Create multiple containers
    for i in 0..5 {
        daemon.run_cli_ok(&[
            "create",
            "--name",
            &format!("multi-{i}"),
            "--rootfs",
            rootfs.path().to_str().unwrap(),
            "--",
            "/bin/sh",
        ]);
    }

    // List should show all 5
    let output = daemon.run_cli_ok(&["list"]);
    for i in 0..5 {
        assert!(
            output.contains(&format!("multi-{i}")),
            "missing multi-{i} in list: {output}"
        );
    }

    // Destroy all
    for i in 0..5 {
        daemon.run_cli_ok(&["destroy", &format!("multi-{i}")]);
    }

    let output = daemon.run_cli_ok(&["list"]);
    assert!(
        output.contains("No containers"),
        "expected no containers: {output}"
    );
}
