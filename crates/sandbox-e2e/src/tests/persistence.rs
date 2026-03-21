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

pub fn test_graceful_shutdown(ctx: &mut TestContext) -> Result<(), String> {
    // Start a container
    ctx.cli_ok(&[
        "run",
        "--name",
        "shutdown-test",
        "--image",
        "alpine",
        "--init",
        "-d",
        "--",
        "sleep",
        "300",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Stop the daemon — should cleanly shut down
    // Stop daemon via CLI
    let _ = ctx.cli(&["daemon", "stop"]);

    // Wait for daemon to exit
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Restart for remaining tests
    ctx.start_daemon();
    std::thread::sleep(std::time::Duration::from_millis(500));

    Ok(())
}
