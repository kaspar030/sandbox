use crate::context::TestContext;

/// Test updating the restart policy on a stopped container.
pub fn test_update_restart_policy(ctx: &TestContext) -> Result<(), String> {
    let name = "update-restart";

    // Create with default restart policy (unless-stopped)
    if ctx.cli_fails(&["create", "--name", name, "--image", "alpine"]) {
        return Err("create failed".into());
    }

    // Verify initial restart policy via inspect
    let inspect = ctx.cli_ok(&["inspect", name]);
    if !inspect.contains("unless-stopped") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "expected initial restart policy 'unless-stopped', got: {inspect}"
        ));
    }

    // Update restart policy to 'no'
    let output = ctx.cli_ok(&["update", name, "--restart", "no"]);
    if !output.contains("Updated container") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "expected 'Updated container' output, got: {output}"
        ));
    }

    // Verify updated restart policy
    let inspect = ctx.cli_ok(&["inspect", name]);
    if !inspect.contains("Restart:    no") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "expected updated restart policy 'no', got: {inspect}"
        ));
    }

    // Update to 'always'
    ctx.cli_ok(&["update", name, "--restart", "always"]);
    let inspect = ctx.cli_ok(&["inspect", name]);
    if !inspect.contains("Restart:    always") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected restart policy 'always', got: {inspect}"));
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test updating memory limit on a stopped container.
pub fn test_update_memory(ctx: &TestContext) -> Result<(), String> {
    let name = "update-memory";

    // Create without memory limit
    if ctx.cli_fails(&["create", "--name", name, "--image", "alpine"]) {
        return Err("create failed".into());
    }

    // Verify no memory limit initially
    let inspect = ctx.cli_ok(&["inspect", name]);
    // Should not have a "memory:" line in cgroup section
    if inspect.contains("memory:") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "expected no memory limit initially, got: {inspect}"
        ));
    }

    // Update memory to 256M
    ctx.cli_ok(&["update", name, "--memory", "256M"]);

    // Verify memory limit in inspect output
    let inspect = ctx.cli_ok(&["inspect", name]);
    if !inspect.contains("memory: 256.0M") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected memory: 256.0M, got: {inspect}"));
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test updating CPU limit on a stopped container.
pub fn test_update_cpus(ctx: &TestContext) -> Result<(), String> {
    let name = "update-cpus";

    if ctx.cli_fails(&["create", "--name", name, "--image", "alpine"]) {
        return Err("create failed".into());
    }

    // Update cpus to 1.5
    ctx.cli_ok(&["update", name, "--cpus", "1.5"]);

    let inspect = ctx.cli_ok(&["inspect", name]);
    if !inspect.contains("cpus:   1.5") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected cpus: 1.5, got: {inspect}"));
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test updating pids limit on a stopped container.
pub fn test_update_pids_max(ctx: &TestContext) -> Result<(), String> {
    let name = "update-pids";

    if ctx.cli_fails(&["create", "--name", name, "--image", "alpine"]) {
        return Err("create failed".into());
    }

    // Update pids-max to 64
    ctx.cli_ok(&["update", name, "--pids-max", "64"]);

    let inspect = ctx.cli_ok(&["inspect", name]);
    if !inspect.contains("pids:   64") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected pids: 64, got: {inspect}"));
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test that updating a running container applies live cgroup changes.
pub fn test_update_running(ctx: &TestContext) -> Result<(), String> {
    let name = "update-running";

    if ctx.cli_fails(&["create", "--name", name, "--image", "alpine", "--init"]) {
        return Err("create failed".into());
    }

    if ctx.cli_fails(&["start", "-d", name, "--", "sleep", "60"]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("start failed".into());
    }

    // Wait for it to be running
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Update memory limit on running container — should succeed
    let output = ctx.cli_ok(&["update", name, "--memory", "64M"]);
    if !output.contains("Updated container") {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "expected success updating running container, got: {output}"
        ));
    }

    // Update restart policy on running container — should also succeed
    ctx.cli_ok(&["update", name, "--restart", "always"]);

    // Verify via inspect
    let inspect = ctx.cli_ok(&["inspect", name]);
    if !inspect.contains("Restart:    always") {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "restart policy not updated on running container. inspect:\n{inspect}"
        ));
    }

    let _ = ctx.cli(&["stop", name]);
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test updating multiple settings at once.
pub fn test_update_multiple(ctx: &TestContext) -> Result<(), String> {
    let name = "update-multi";

    if ctx.cli_fails(&["create", "--name", name, "--image", "alpine"]) {
        return Err("create failed".into());
    }

    // Update restart + memory + cpus + pids-max all at once
    ctx.cli_ok(&[
        "update",
        name,
        "--restart",
        "on-failure",
        "--memory",
        "512M",
        "--cpus",
        "2.0",
        "--pids-max",
        "256",
    ]);

    let inspect = ctx.cli_ok(&["inspect", name]);
    let mut errors = Vec::new();
    if !inspect.contains("Restart:    on-failure") {
        errors.push("restart policy not updated");
    }
    if !inspect.contains("memory: 512.0M") {
        errors.push("memory not updated");
    }
    if !inspect.contains("cpus:   2.0") {
        errors.push("cpus not updated");
    }
    if !inspect.contains("pids:   256") {
        errors.push("pids not updated");
    }

    let _ = ctx.cli(&["destroy", name]);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "multiple update failures: {}. inspect output:\n{inspect}",
            errors.join(", ")
        ))
    }
}

/// Test that update persists across daemon restart.
pub fn test_update_persists(ctx: &mut TestContext) -> Result<(), String> {
    let name = "update-persist";

    if ctx.cli_fails(&["create", "--name", name, "--image", "alpine"]) {
        return Err("create failed".into());
    }

    // Update restart policy
    ctx.cli_ok(&["update", name, "--restart", "always", "--memory", "128M"]);

    // Verify before restart
    let inspect = ctx.cli_ok(&["inspect", name]);
    if !inspect.contains("Restart:    always") || !inspect.contains("memory: 128.0M") {
        let _ = ctx.cli(&["destroy", name]);
        return Err("update not applied before daemon restart".into());
    }

    // Restart daemon
    ctx.restart_daemon();

    // Verify after restart
    let inspect = ctx.cli_ok(&["inspect", name]);
    if !inspect.contains("Restart:    always") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "restart policy not persisted after daemon restart. inspect:\n{inspect}"
        ));
    }
    if !inspect.contains("memory: 128.0M") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "memory limit not persisted after daemon restart. inspect:\n{inspect}"
        ));
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}
