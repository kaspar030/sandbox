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

/// Test that exec'd processes die when the container is stopped.
pub fn test_exec_killed_on_stop(ctx: &TestContext) -> Result<(), String> {
    let name = "exec-kill-test";
    ctx.cli_ok(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--init",
        "--restart",
        "no",
        "--",
        "sleep",
        "300",
    ]);
    ctx.cli_ok(&["start", name]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Start a detached exec process
    let exec_output = ctx.cli(&["exec", "-d", name, "--", "sleep", "200"]);
    if !exec_output.status.success() {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "exec failed: {}",
            String::from_utf8_lossy(&exec_output.stderr)
        ));
    }

    // Read the exec PID from output ("Exec started (PID NNNN)")
    let exec_stdout = String::from_utf8_lossy(&exec_output.stdout);
    let exec_pid: Option<u32> = exec_stdout.lines().find_map(|l| {
        l.strip_prefix("Exec started (PID ")
            .and_then(|s| s.strip_suffix(')'))
            .and_then(|s| s.parse().ok())
    });

    std::thread::sleep(std::time::Duration::from_millis(200));

    // Stop the container
    let _ = ctx.cli(&["stop", name]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Verify exec process is dead (check /proc/<pid> on the host)
    if let Some(pid) = exec_pid {
        let proc_path = format!("/proc/{pid}");
        if std::path::Path::new(&proc_path).exists() {
            let _ = ctx.cli(&["destroy", name]);
            return Err(format!(
                "exec PID {pid} SURVIVED container stop (should have been killed)"
            ));
        }
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test piped exec: stdout and stderr are separate.
pub fn test_exec_piped_stdout_stderr(ctx: &TestContext) -> Result<(), String> {
    let name = "exec-piped";
    ctx.cli_ok(&[
        "run", "--name", name, "--image", "alpine", "--init", "-d", "--", "sleep", "300",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Run a command that writes to both stdout and stderr
    let output = ctx.cli(&[
        "exec",
        "-T",
        name,
        "--",
        "sh",
        "-c",
        "echo OUT; echo ERR >&2",
    ]);
    let _ = ctx.cli(&["stop", "--timeout", "2", name]);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !stdout.contains("OUT") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected 'OUT' on stdout, got: {stdout}"));
    }
    if !stderr.contains("ERR") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected 'ERR' on stderr, got: {stderr}"));
    }
    // Verify stdout does NOT contain ERR (they should be separate)
    if stdout.contains("ERR") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("stderr leaked into stdout: {stdout}"));
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test piped exec exit code propagation.
pub fn test_exec_piped_exit_code(ctx: &TestContext) -> Result<(), String> {
    let name = "exec-piped-exit";
    ctx.cli_ok(&[
        "run", "--name", name, "--image", "alpine", "--init", "-d", "--", "sleep", "300",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Run a command that exits with code 42
    let output = ctx.cli(&["exec", "-T", name, "--", "sh", "-c", "exit 42"]);
    let _ = ctx.cli(&["stop", "--timeout", "2", name]);

    let code = output.status.code().unwrap_or(-1);
    if code != 42 {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected exit code 42, got: {code}"));
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test that -T flag works explicitly (even when stdin is a tty).
pub fn test_exec_piped_explicit(ctx: &TestContext) -> Result<(), String> {
    let name = "exec-piped-explicit";
    ctx.cli_ok(&[
        "run", "--name", name, "--image", "alpine", "--init", "-d", "--", "sleep", "300",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // -T forces piped mode; just verify it works
    let output = ctx.cli(&["exec", "-T", name, "--", "echo", "piped-ok"]);
    let _ = ctx.cli(&["stop", "--timeout", "2", name]);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if !stdout.contains("piped-ok") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected 'piped-ok', got: {stdout}"));
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}
