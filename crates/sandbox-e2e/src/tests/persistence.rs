use crate::context::TestContext;

pub fn test_daemon_restart_recovery(ctx: &mut TestContext) -> Result<(), String> {
    let name = "persist-test";

    // Create and start a non-ephemeral container (state is persisted on start)
    let output = ctx.cli(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--init",
        "--restart",
        "no",
    ]);
    if !output.status.success() {
        return Err(format!(
            "create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let output = ctx.cli(&["start", name, "--", "sleep", "300"]);
    if !output.status.success() {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "start failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Verify it exists and is running
    let list = ctx.cli_ok(&["list"]);
    if !list.contains(name) {
        return Err(format!("container not in list after start. list: {list}"));
    }
    if !list.contains("Running") {
        return Err(format!("container not running after start. list: {list}"));
    }

    // Check state file exists
    let state_file = ctx.data_dir.join("state").join(format!("{name}.json"));
    if !state_file.exists() {
        return Err(format!("state file not found at {}", state_file.display()));
    }

    // Kill daemon abruptly (simulates crash — state files preserved)
    ctx.kill_daemon();
    std::thread::sleep(std::time::Duration::from_millis(200));
    ctx.start_daemon();
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Verify container is recovered as Created
    let list = ctx.cli_ok(&["list"]);
    if !list.contains(name) {
        return Err(format!(
            "container not recovered after daemon restart. list: {list}"
        ));
    }

    // Clean up
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Regression test: a container with unless-stopped that was manually stopped,
/// then started again, then the daemon restarts — the container must be
/// auto-restarted. Previously, manually_stopped was only cleared when the
/// container was in Stopped state, but after daemon recovery containers are
/// in Created state, so the flag was never cleared by handle_start().
pub fn test_manually_stopped_cleared_on_start(ctx: &mut TestContext) -> Result<(), String> {
    let name = "persist-manual-stop";

    // 1. Create with unless-stopped (default) and start
    if ctx.cli_fails(&["create", "--name", name, "--image", "alpine", "--init"]) {
        return Err("create failed".into());
    }
    if ctx.cli_fails(&["start", name, "--", "sleep", "300"]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("first start failed".into());
    }
    std::thread::sleep(std::time::Duration::from_millis(500));

    // 2. Manually stop → sets manually_stopped = true
    if ctx.cli_fails(&["stop", name]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("stop failed".into());
    }
    std::thread::sleep(std::time::Duration::from_millis(500));

    // 3. Start again → should clear manually_stopped
    if ctx.cli_fails(&["start", name, "--", "sleep", "300"]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("second start failed".into());
    }
    std::thread::sleep(std::time::Duration::from_millis(500));

    // 4. Graceful daemon restart (stop + start)
    ctx.restart_daemon();
    // Wait for auto-restart (1s delay + margin)
    std::thread::sleep(std::time::Duration::from_secs(3));

    // 5. Container should have been auto-restarted
    let list = ctx.cli_ok(&["list"]);
    if !list.contains(name) || !list.contains("Running") {
        let _ = ctx.cli(&["stop", "--timeout", "1", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "expected container to be auto-restarted after daemon restart, got: {list}"
        ));
    }

    let _ = ctx.cli(&["stop", "--timeout", "1", name]);
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

pub fn test_graceful_shutdown(ctx: &mut TestContext) -> Result<(), String> {
    let name = "shutdown-test";

    // Create a bind mount source
    let test_dir = ctx.workdir.join("shutdown-mount-src");
    std::fs::create_dir_all(&test_dir).unwrap();
    std::fs::write(test_dir.join("data"), "shutdown-test").unwrap();
    let src = test_dir.to_str().unwrap();
    let bind_spec = format!("{src}:/mnt/test");

    // Create a persistent container with a bind mount, then start it.
    // Using create+start (not run) so the container is non-ephemeral
    // and its state file persists across daemon shutdown for recovery.
    ctx.cli_ok(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--init",
        "--bind",
        &bind_spec,
        "--restart",
        "no",
        "--",
        "sleep",
        "300",
    ]);
    ctx.cli_ok(&["start", name]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Verify idmap mount exists
    let idmap_mount = ctx.workdir.join("mounts").join(name);
    if !idmap_mount.exists() {
        ctx.stop_daemon();
        ctx.start_daemon();
        return Err(format!(
            "idmap mount {} should exist while running",
            idmap_mount.display()
        ));
    }

    // Stop the daemon — should cleanly shut down and unmount everything
    let _ = ctx.cli(&["daemon", "stop"]);
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Verify idmap mount is cleaned up
    if idmap_mount.exists() {
        // Check if it's still a mount point (exists could mean empty dir)
        // The daemon should have removed the directory too.
        ctx.start_daemon();
        return Err(format!(
            "idmap mount {} should be cleaned up after daemon shutdown",
            idmap_mount.display()
        ));
    }

    // Restart daemon and verify container is recovered
    ctx.start_daemon();
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Container should be recovered as Created (not running)
    let list = ctx.cli_ok(&["list"]);
    if !list.contains(name) {
        return Err(format!(
            "container should be recovered after shutdown, list: {list}"
        ));
    }

    // Start the container again — idmap mount should be re-created
    ctx.cli_ok(&["start", name, "--", "sleep", "300"]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Verify bind mount works after recovery + restart
    let output = ctx.cli_ok(&["exec", name, "--", "cat", "/mnt/test/data"]);
    if !output.contains("shutdown-test") {
        let _ = ctx.cli(&["stop", "--timeout", "1", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected shutdown-test, got: {output}"));
    }

    let _ = ctx.cli(&["stop", "--timeout", "1", name]);
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}
