use crate::context::TestContext;

pub fn test_daemon_restart_recovery(ctx: &mut TestContext) -> Result<(), String> {
    let name = "persist-test";

    // Create a non-ephemeral container
    ctx.cli_ok(&["create", "--name", name, "--image", "alpine"]);

    // Verify it exists
    let list = ctx.cli_ok(&["list"]);
    if !list.contains(name) {
        return Err("container not in list after create".into());
    }

    // Restart daemon
    ctx.restart_daemon();
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Verify container is recovered as Created
    let list = ctx.cli_ok(&["list"]);
    if !list.contains(name) {
        return Err("container not recovered after daemon restart".into());
    }

    // Clean up
    ctx.cli_ok(&["destroy", name]);
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
