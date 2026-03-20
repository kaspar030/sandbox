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
