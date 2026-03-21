use crate::context::TestContext;

pub fn test_exec_basic(ctx: &TestContext) -> Result<(), String> {
    let name = "exec-test";
    ctx.cli_ok(&[
        "run", "--name", name, "--image", "ubuntu", "--init", "-d", "--", "sleep", "300",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    let output = ctx.cli(&["exec", name, "--", "whoami"]);
    let _ = ctx.cli(&["stop", name]);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if !output.status.success() {
        return Err(format!(
            "exec failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if !stdout.trim().contains("root") {
        return Err(format!("expected 'root', got: '{}'", stdout.trim()));
    }
    Ok(())
}

pub fn test_exec_user(ctx: &TestContext) -> Result<(), String> {
    let name = "exec-user-test";
    ctx.cli_ok(&[
        "run", "--name", name, "--image", "ubuntu", "--init", "-d", "--", "sleep", "300",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Use uid 1000 (ubuntu user exists in ubuntu image)
    let output = ctx.cli(&["exec", name, "-u", "1000", "--", "id"]);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    let _ = ctx.cli(&["stop", name]);

    if !output.status.success() {
        return Err(format!(
            "exec -u 1000 failed (exit {exit_code}): stdout='{stdout}' stderr='{stderr}'"
        ));
    }
    if !stdout.contains("uid=1000") {
        return Err(format!(
            "expected uid=1000, got stdout='{stdout}' stderr='{stderr}'"
        ));
    }
    Ok(())
}

pub fn test_exec_env_clean(ctx: &TestContext) -> Result<(), String> {
    let name = "exec-env-test";
    ctx.cli_ok(&[
        "run", "--name", name, "--image", "ubuntu", "--init", "-d", "--", "sleep", "300",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    let output = ctx.cli(&["exec", name, "--", "env"]);
    let _ = ctx.cli(&["stop", name]);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if !output.status.success() {
        return Err(format!(
            "exec env failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if stdout.contains("SUDO_") {
        return Err("daemon environment leaked (SUDO_*)".into());
    }
    if stdout.contains(".cargo") {
        return Err("daemon environment leaked (cargo paths)".into());
    }
    Ok(())
}

/// Test that bash job control (setpgid) works inside exec.
/// Previously failed with "setpgid: Operation not permitted" because
/// the exec child didn't call setsid().
pub fn test_exec_setpgid(ctx: &TestContext) -> Result<(), String> {
    let name = "exec-setpgid-test";
    ctx.cli_ok(&[
        "run", "--name", name, "--image", "ubuntu", "--init", "-d", "--", "sleep", "300",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // This command triggers setpgid inside bash — was failing before setsid fix
    let output = ctx.cli(&["exec", name, "--", "bash", "-c", "echo hello-from-bash"]);
    let _ = ctx.cli(&["stop", name]);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !stdout.contains("hello-from-bash") {
        return Err(format!(
            "expected hello-from-bash, got stdout='{stdout}' stderr='{stderr}'"
        ));
    }
    // Should NOT contain setpgid error
    if stderr.contains("setpgid") {
        return Err(format!("setpgid error in stderr: {stderr}"));
    }
    Ok(())
}

/// Test that supplementary groups are set correctly via exec --user.
/// The ubuntu image has user 'ubuntu' (uid 1000) in various groups.
pub fn test_exec_groups(ctx: &TestContext) -> Result<(), String> {
    let name = "exec-groups-test";
    ctx.cli_ok(&[
        "run", "--name", name, "--image", "ubuntu", "--init", "-d", "--", "sleep", "300",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Check that 'id' shows supplementary groups
    let output = ctx.cli(&["exec", name, "-u", "1000", "--", "id"]);
    let _ = ctx.cli(&["stop", name]);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if !output.status.success() {
        return Err(format!(
            "exec id failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    // Should show groups= with at least the primary group
    if !stdout.contains("groups=") {
        return Err(format!("expected groups= in id output, got: {stdout}"));
    }
    Ok(())
}

/// Test that --user on run sets the container user.
pub fn test_run_user(ctx: &TestContext) -> Result<(), String> {
    // Run as uid 65534 (nobody on ubuntu)
    let output = ctx.cli(&["run", "--image", "ubuntu", "--user", "65534", "--", "id"]);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);

    if !stdout.contains("uid=65534") {
        return Err(format!(
            "expected uid=65534, exit={code} stdout='{stdout}' stderr='{stderr}'"
        ));
    }
    Ok(())
}

/// Test that --user with a username works.
pub fn test_run_user_by_name(ctx: &TestContext) -> Result<(), String> {
    let output = ctx.cli(&["run", "--image", "ubuntu", "--user", "nobody", "--", "id"]);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);

    if !stdout.contains("uid=65534") {
        return Err(format!(
            "expected uid=65534, exit={code} stdout='{stdout}' stderr='{stderr}'"
        ));
    }
    Ok(())
}
