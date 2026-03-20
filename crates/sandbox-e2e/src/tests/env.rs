use crate::context::TestContext;

pub fn test_env_home_user(ctx: &TestContext) -> Result<(), String> {
    let output = ctx.cli_ok(&["run", "--image", "ubuntu", "--", "env"]);

    if !output.contains("HOME=/root") {
        return Err(format!("expected HOME=/root in env, got: {output}"));
    }
    if !output.contains("USER=root") {
        return Err(format!("expected USER=root in env, got: {output}"));
    }
    Ok(())
}

pub fn test_env_hostname(ctx: &TestContext) -> Result<(), String> {
    let name = "hostname-test";
    let output = ctx.cli_ok(&["run", "--name", name, "--image", "alpine", "--", "hostname"]);

    if !output.trim().contains(name) {
        return Err(format!(
            "expected hostname '{name}', got: {}",
            output.trim()
        ));
    }
    Ok(())
}

pub fn test_env_no_daemon_leak(ctx: &TestContext) -> Result<(), String> {
    let output = ctx.cli_ok(&["run", "--image", "alpine", "--", "env"]);

    if output.contains("SUDO_") {
        return Err("SUDO_* variables leaked from daemon".into());
    }
    if output.contains("MACHTYPE") {
        return Err("MACHTYPE leaked from daemon".into());
    }
    // PATH should be the image default, not the host's cargo/perl/gem paths
    for line in output.lines() {
        if line.starts_with("PATH=") && line.contains(".cargo") {
            return Err(format!("host PATH leaked: {line}"));
        }
    }
    Ok(())
}

/// Test that -e KEY=VALUE sets env vars on run.
pub fn test_env_run(ctx: &TestContext) -> Result<(), String> {
    let output = ctx.cli_ok(&[
        "run", "--image", "alpine", "-e", "FOO=bar", "-e", "BAZ=123", "--", "env",
    ]);

    if !output.contains("FOO=bar") {
        return Err(format!("expected FOO=bar in env, got: {output}"));
    }
    if !output.contains("BAZ=123") {
        return Err(format!("expected BAZ=123 in env, got: {output}"));
    }
    Ok(())
}

/// Test that -e KEY=VALUE on create persists and is visible via exec.
pub fn test_env_create_persist(ctx: &TestContext) -> Result<(), String> {
    let name = "env-persist-test";
    // Create with env, then start separately (daemon handles one request per connection)
    ctx.cli_ok(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "-e",
        "PERSIST=yes",
        "--",
        "sleep",
        "30",
    ]);
    // Start detached via run -d would create a new container, so use the
    // "start" command which backgrounds automatically.
    ctx.cli_ok(&["start", name]);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let output = ctx.cli_ok(&["exec", name, "--", "env"]);
    ctx.cli_ok(&["stop", name]);
    ctx.cli_ok(&["destroy", name]);

    if !output.contains("PERSIST=yes") {
        return Err(format!("expected PERSIST=yes in exec env, got: {output}"));
    }
    Ok(())
}

/// Test that exec -e sets local env and overrides container env.
pub fn test_env_exec_override(ctx: &TestContext) -> Result<(), String> {
    let name = "env-exec-override";
    ctx.cli_ok(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "-e",
        "COLOR=red",
        "-e",
        "SHAPE=circle",
        "--",
        "sleep",
        "30",
    ]);
    ctx.cli_ok(&["start", name]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Exec with override for COLOR and new var SIZE
    let output = ctx.cli_ok(&[
        "exec",
        name,
        "-e",
        "COLOR=blue",
        "-e",
        "SIZE=large",
        "--",
        "env",
    ]);
    ctx.cli_ok(&["stop", name]);
    ctx.cli_ok(&["destroy", name]);

    // COLOR should be overridden to blue
    if !output.contains("COLOR=blue") {
        return Err(format!("expected COLOR=blue (overridden), got: {output}"));
    }
    // Original COLOR=red should NOT be present
    if output.contains("COLOR=red") {
        return Err("COLOR=red should have been overridden by exec env".into());
    }
    // SHAPE should still be present from container env
    if !output.contains("SHAPE=circle") {
        return Err(format!(
            "expected SHAPE=circle from container env, got: {output}"
        ));
    }
    // SIZE should be present from exec env
    if !output.contains("SIZE=large") {
        return Err(format!("expected SIZE=large from exec env, got: {output}"));
    }
    Ok(())
}
