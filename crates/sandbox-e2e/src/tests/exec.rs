use crate::context::TestContext;

pub fn test_exec_basic(ctx: &TestContext) -> Result<(), String> {
    let name = "exec-test";
    ctx.cli_ok(&[
        "run", "--name", name, "--image", "ubuntu", "--init", "-d", "--", "sleep", "300",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    let output = ctx.cli_ok(&["exec", name, "--", "whoami"]);
    let _ = ctx.cli(&["stop", name]);

    if !output.trim().contains("root") {
        return Err(format!("expected 'root', got: {}", output.trim()));
    }
    Ok(())
}

pub fn test_exec_user(ctx: &TestContext) -> Result<(), String> {
    let name = "exec-user-test";
    ctx.cli_ok(&[
        "run", "--name", name, "--image", "ubuntu", "--init", "-d", "--", "sleep", "300",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    let output = ctx.cli_ok(&["exec", name, "-u", "65534", "--", "id"]);
    let _ = ctx.cli(&["stop", name]);

    if !output.contains("uid=65534") {
        return Err(format!("expected uid=65534, got: {output}"));
    }
    Ok(())
}

pub fn test_exec_env_clean(ctx: &TestContext) -> Result<(), String> {
    let name = "exec-env-test";
    ctx.cli_ok(&[
        "run", "--name", name, "--image", "ubuntu", "--init", "-d", "--", "sleep", "300",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    let output = ctx.cli_ok(&["exec", name, "--", "env"]);
    let _ = ctx.cli(&["stop", name]);

    if output.contains("SUDO_") {
        return Err("daemon environment leaked (SUDO_*)".into());
    }
    if output.contains(".cargo") {
        return Err("daemon environment leaked (cargo paths)".into());
    }
    Ok(())
}
