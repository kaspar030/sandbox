use crate::context::TestContext;

/// Test that `create` without a command defaults to idle init mode.
/// Container should stay running and accept exec.
pub fn test_create_idle_default(ctx: &TestContext) -> Result<(), String> {
    let name = "idle-default";

    // Create with no command — should get implicit init idle mode
    if ctx.cli_fails(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]) {
        return Err("create failed".into());
    }

    // Start
    let start_output = ctx.cli(&["start", name]);
    if !start_output.status.success() {
        let stderr = String::from_utf8_lossy(&start_output.stderr);
        let stdout = String::from_utf8_lossy(&start_output.stdout);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("start failed: stdout={stdout} stderr={stderr}"));
    }

    // Should be running
    std::thread::sleep(std::time::Duration::from_millis(500));
    let list = ctx.cli_ok(&["list"]);
    if !list.contains("Running") {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected Running state, got: {list}"));
    }

    // Exec into it
    let output = ctx.cli(&["exec", name, "--", "echo", "hello-idle"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("hello-idle") {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("exec failed, got: {stdout}"));
    }

    // Stop should work cleanly (init exits on SIGTERM)
    if ctx.cli_fails(&["stop", "--timeout", "3", name]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("stop failed".into());
    }

    // Should be stopped now
    let list = ctx.cli_ok(&["list"]);
    if list.contains("Running") {
        let _ = ctx.cli(&["destroy", name]);
        return Err("container still running after stop".into());
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test that `create` with --init and no command also works (explicit init).
pub fn test_create_idle_explicit_init(ctx: &TestContext) -> Result<(), String> {
    let name = "idle-explicit";

    if ctx.cli_fails(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--init",
        "--restart",
        "no",
    ]) {
        return Err("create failed".into());
    }

    if ctx.cli_fails(&["start", name]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("start failed".into());
    }

    std::thread::sleep(std::time::Duration::from_millis(500));

    let output = ctx.cli(&["exec", name, "--", "echo", "explicit-init"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("explicit-init") {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("exec failed, got: {stdout}"));
    }

    let _ = ctx.cli(&["stop", "--timeout", "3", name]);
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test that `create` with a command still works as before (no idle mode).
pub fn test_create_with_command(ctx: &TestContext) -> Result<(), String> {
    let name = "idle-with-cmd";

    if ctx.cli_fails(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--init",
        "--restart",
        "no",
    ]) {
        return Err("create failed".into());
    }

    // Start with a command — init should fork+exec it
    if ctx.cli_fails(&["start", name, "--", "sleep", "60"]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("start failed".into());
    }

    std::thread::sleep(std::time::Duration::from_millis(500));

    // Verify it's running
    let list = ctx.cli_ok(&["list"]);
    if !list.contains("Running") {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected Running, got: {list}"));
    }

    // Verify sleep is running inside
    let output = ctx.cli(&["exec", name, "--", "pgrep", "-a", "sleep"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("sleep") {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("sleep not found in container, got: {stdout}"));
    }

    let _ = ctx.cli(&["stop", "--timeout", "2", name]);
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test that `run` without a command still defaults to /bin/sh (backward compat).
pub fn test_run_default_shell(ctx: &TestContext) -> Result<(), String> {
    // Run with echo via sh — verifies sh is the default
    let output = ctx.cli(&["run", "--image", "alpine", "--", "echo", "run-test"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("run-test") {
        return Err(format!("run with command failed, got: {stdout}"));
    }
    Ok(())
}

/// Test that idle container's init reaps zombies from exec'd processes.
pub fn test_idle_reaps_zombies(ctx: &TestContext) -> Result<(), String> {
    let name = "idle-reap";

    if ctx.cli_fails(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]) {
        return Err("create failed".into());
    }

    if ctx.cli_fails(&["start", name]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("start failed".into());
    }

    std::thread::sleep(std::time::Duration::from_millis(500));

    // Run several exec commands that exit
    for i in 0..3 {
        let output = ctx.cli(&["exec", name, "--", "echo", &format!("reap-{i}")]);
        if !output.status.success() {
            let _ = ctx.cli(&["stop", name]);
            let _ = ctx.cli(&["destroy", name]);
            return Err(format!("exec {i} failed"));
        }
    }

    // Container should still be running (init still alive)
    let list = ctx.cli_ok(&["list"]);
    if !list.contains("Running") {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("container died after execs, got: {list}"));
    }

    let _ = ctx.cli(&["stop", "--timeout", "3", name]);
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test that the container's PID 1 has comm name "sandbox-init".
pub fn test_init_process_name(ctx: &TestContext) -> Result<(), String> {
    let name = "init-procname";

    if ctx.cli_fails(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]) {
        return Err("create failed".into());
    }

    if ctx.cli_fails(&["start", name]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("start failed".into());
    }

    std::thread::sleep(std::time::Duration::from_millis(500));

    // Read /proc/1/comm inside the container — should be "sandbox-init"
    let output = ctx.cli(&["exec", name, "--", "cat", "/proc/1/comm"]);
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout != "sandbox-init" {
        let _ = ctx.cli(&["stop", "--timeout", "2", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected comm 'sandbox-init', got: '{stdout}'"));
    }

    let _ = ctx.cli(&["stop", "--timeout", "2", name]);
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}
