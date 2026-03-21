use crate::context::TestContext;

/// Test that a container with --restart=always restarts after exit.
pub fn test_restart_always(ctx: &TestContext) -> Result<(), String> {
    let name = "restart-always";

    // Create with restart=always, start a process that exits quickly
    if ctx.cli_fails(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "always",
        "--init",
    ]) {
        return Err("create failed".into());
    }

    // Start with a command that exits after 1 second
    if ctx.cli_fails(&["start", name, "--", "sleep", "2"]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("start failed".into());
    }

    // Verify it's running
    let list = ctx.cli_ok(&["list"]);
    if !list.contains("Running") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected Running state, got: {list}"));
    }

    // Wait for it to exit and be restarted (2s for exit + up to 2s for restart backoff)
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Should be running again (restarted)
    let list = ctx.cli_ok(&["list"]);
    if !list.contains("Running") {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "expected container to be restarted (Running), got: {list}"
        ));
    }

    // Stop and destroy — the container restarts, so stop may need retries.
    // The stop sets manually_stopped which prevents further restarts,
    // but we need to wait for the restart loop to notice.
    for _ in 0..3 {
        let _ = ctx.cli(&["stop", "--timeout", "2", name]);
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test that a container with --restart=on-failure only restarts on non-zero exit.
pub fn test_restart_on_failure(ctx: &TestContext) -> Result<(), String> {
    let name = "restart-onfail";

    // Create with restart=on-failure
    if ctx.cli_fails(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "on-failure",
        "--init",
    ]) {
        return Err("create failed".into());
    }

    // Start with a command that exits successfully (exit 0)
    if ctx.cli_fails(&["start", name, "--", "/bin/true"]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("start failed".into());
    }

    // Wait for exit
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Should be stopped (exit 0, no restart)
    let inspect = ctx.cli_ok(&["inspect", name]);
    if !inspect.contains("Stopped (exit code 0)") {
        let _ = ctx.cli(&["stop", "--timeout", "1", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "expected Stopped (exit code 0) (no restart for exit 0), got: {inspect}"
        ));
    }

    // Now start with a command that runs for a bit then exits non-zero.
    // "sleep 3; exit 1" runs for 3 seconds, giving us a clear window
    // to observe the Running state after restart.
    if ctx.cli_fails(&["start", name, "--", "/bin/sh", "-c", "sleep 3; exit 1"]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("start with exit-1 command failed".into());
    }

    // Wait for the process to exit (3s) + restart backoff (1s) + margin (1s)
    // After restart, the container runs "sleep 3; exit 1" again.
    // At the 6s mark, the restarted container should be in its "sleep 3" phase.
    std::thread::sleep(std::time::Duration::from_secs(6));

    let list = ctx.cli_ok(&["list"]);
    if !list.contains("Running") {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "expected Running after non-zero exit restart, got: {list}"
        ));
    }

    for _ in 0..3 {
        let _ = ctx.cli(&["stop", "--timeout", "2", name]);
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test that --restart=unless-stopped does not restart after explicit stop.
pub fn test_restart_unless_stopped(ctx: &TestContext) -> Result<(), String> {
    let name = "restart-unless";

    // Create with unless-stopped (the default for create)
    if ctx.cli_fails(&["create", "--name", name, "--image", "alpine", "--init"]) {
        return Err("create failed".into());
    }

    // Start with a short-lived process
    if ctx.cli_fails(&["start", name, "--", "sleep", "2"]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("start failed".into());
    }

    // Stop it explicitly
    if ctx.cli_fails(&["stop", name]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("stop failed".into());
    }

    // Wait a bit
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Should NOT be restarted (manually stopped)
    let list = ctx.cli_ok(&["list"]);
    if list.contains("Running") {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "expected Stopped (manually stopped, no restart), got: {list}"
        ));
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test that --restart=no keeps container stopped after exit.
pub fn test_restart_no(ctx: &TestContext) -> Result<(), String> {
    let name = "restart-no";

    if ctx.cli_fails(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "no",
        "--init",
    ]) {
        return Err("create failed".into());
    }

    if ctx.cli_fails(&["start", name, "--", "sleep", "1"]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("start failed".into());
    }

    // Wait for exit
    std::thread::sleep(std::time::Duration::from_secs(4));

    // Should stay stopped — use inspect for this specific container
    let inspect = ctx.cli_ok(&["inspect", name]);
    if inspect.contains("State:      Running") {
        let _ = ctx.cli(&["stop", "--timeout", "1", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected Stopped (restart=no), got: {inspect}"));
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test that inspect shows the restart policy.
pub fn test_restart_inspect(ctx: &TestContext) -> Result<(), String> {
    let name = "restart-inspect";

    if ctx.cli_fails(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "always",
    ]) {
        return Err("create failed".into());
    }

    let output = ctx.cli_ok(&["inspect", name]);
    if !output.contains("always") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "expected 'always' in inspect output, got: {output}"
        ));
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}
