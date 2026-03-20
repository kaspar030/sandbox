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
