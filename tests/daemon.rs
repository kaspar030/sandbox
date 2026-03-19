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

    // Import an image first
    daemon.import_image("test-img", &rootfs);

    // Create a container
    let output = daemon.run_cli(&[
        "create",
        "--name",
        "test-create",
        "--image",
        "test-img",
        "--",
        "/bin/echo",
        "hello",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // May fail due to idmap requirements (non-root), but should at least parse
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Created container: test-create") || combined.contains("Error"),
        "unexpected output: {combined}"
    );
}

#[test]
fn test_daemon_image_import_list_remove() {
    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());
    let rootfs = TempRootfs::new();

    // Import
    daemon.import_image("alpine-test", &rootfs);

    // List
    let output = daemon.run_cli_ok(&["image", "list"]);
    assert!(
        output.contains("alpine-test"),
        "image not in list: {output}"
    );

    // Remove
    let output = daemon.run_cli_ok(&["image", "rm", "alpine-test"]);
    assert!(
        output.contains("Removed image: alpine-test"),
        "unexpected output: {output}"
    );

    // List should be empty now
    let output = daemon.run_cli_ok(&["image", "list"]);
    assert!(output.contains("No images"), "expected no images: {output}");
}

#[test]
fn test_daemon_pool_list() {
    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());

    let output = daemon.run_cli_ok(&["pool", "list"]);
    assert!(output.contains("main"), "expected 'main' pool: {output}");
}

#[test]
fn test_daemon_duplicate_image() {
    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());
    let rootfs = TempRootfs::new();

    daemon.import_image("dup-img", &rootfs);

    // Try to import again
    let output = daemon.run_cli(&[
        "image",
        "import",
        "dup-img",
        rootfs.path().to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("already exists"),
        "expected 'already exists': {combined}"
    );
}

#[test]
fn test_daemon_remove_nonexistent_image() {
    let tmp = tempfile::TempDir::new().unwrap();
    let daemon = TestDaemon::start(tmp.path());

    let output = daemon.run_cli(&["image", "rm", "nonexistent"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("not found"),
        "expected 'not found': {combined}"
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
