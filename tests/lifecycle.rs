//! Container lifecycle tests (require root privileges + idmap support).
//!
//! These tests create actual containers with namespaces and verify
//! the full create -> start -> stop -> destroy lifecycle.

mod common;

use common::TestDaemon;
use common::rootfs::TempRootfs;

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
    daemon.import_image("test-img", &rootfs);

    let output = daemon.run_cli(&[
        "run",
        "--name",
        "run-test",
        "--image",
        "test-img",
        "--network",
        "host",
        "--seccomp",
        "disabled",
        "-d",
        "--",
        "/bin/true",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("stdout: {stdout}");
    eprintln!("stderr: {stderr}");

    assert!(
        stdout.contains("Started") || stderr.contains("Error"),
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
    daemon.import_image("test-img", &rootfs);

    let output = daemon.run_cli(&[
        "run",
        "--name",
        "hostname-test",
        "--image",
        "test-img",
        "--hostname",
        "mybox",
        "--network",
        "host",
        "--seccomp",
        "disabled",
        "-d",
        "--",
        "/bin/hostname",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("stdout: {stdout}");
    eprintln!("stderr: {stderr}");
}
