use crate::context::TestContext;
use std::os::unix::fs::PermissionsExt;

/// Test that `sandbox edit` with EDITOR=true (no changes) reports no changes.
pub fn test_edit_noop(ctx: &TestContext) -> Result<(), String> {
    let name = "edit-noop";

    ctx.cli_ok(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);

    // EDITOR=true → no modifications to file → no changes
    let output = ctx.cli_with_env(&["edit", name], &[("EDITOR", "true")]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("No changes") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected 'No changes', got: {stdout}"));
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test editing restart_policy via sed.
pub fn test_edit_change_restart(ctx: &TestContext) -> Result<(), String> {
    let name = "edit-restart";

    ctx.cli_ok(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);

    // Verify initial
    let inspect = ctx.cli_ok(&["inspect", name]);
    if !inspect.contains("Restart:    no") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected initial restart 'no': {inspect}"));
    }

    // Edit: change restart_policy from 'no' to 'always'
    // Write a helper script since EDITOR is split on whitespace
    let script = "/tmp/sandbox-test-editor-restart.sh";
    std::fs::write(
        script,
        "#!/bin/sh\nsed -i 's/restart_policy: no/restart_policy: always/' \"$1\"\n",
    )
    .map_err(|e| format!("write script: {e}"))?;
    std::fs::set_permissions(script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .map_err(|e| format!("chmod: {e}"))?;
    let output = ctx.cli_with_env(&["edit", name], &[("EDITOR", script)]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("restart_policy") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected change summary, got: {stdout}"));
    }

    // Verify changed
    let inspect = ctx.cli_ok(&["inspect", name]);
    if !inspect.contains("Restart:    always") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected restart 'always': {inspect}"));
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test changing working_dir via edit.
pub fn test_edit_change_workdir(ctx: &TestContext) -> Result<(), String> {
    let name = "edit-workdir";

    ctx.cli_ok(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "no",
        "--workdir",
        "/",
        "-e",
        "EXISTING=yes",
    ]);

    // Edit: change working_dir from / to /app via sed
    let script = "/tmp/sandbox-test-editor-workdir.sh";
    std::fs::write(
        script,
        "#!/bin/sh\nsed -i 's|working_dir: \"/\"|working_dir: \"/app\"|' \"$1\"\n",
    )
    .map_err(|e| format!("write script: {e}"))?;
    std::fs::set_permissions(script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .map_err(|e| format!("chmod: {e}"))?;
    let output = ctx.cli_with_env(&["edit", name], &[("EDITOR", script)]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("working_dir") {
        let _ = ctx.cli(&["destroy", name]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "expected working_dir change summary, got stdout: {stdout}, stderr: {stderr}"
        ));
    }

    // Verify
    let inspect = ctx.cli_ok(&["inspect", name]);
    if !inspect.contains("WorkingDir: /app") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected WorkingDir: /app in inspect: {inspect}"));
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test adding a bind mount via edit on a stopped container.
pub fn test_edit_add_bind_mount(ctx: &TestContext) -> Result<(), String> {
    let name = "edit-bind";

    ctx.cli_ok(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);

    // Write an editor script that adds a bind mount
    let script = "/tmp/sandbox-test-editor-bind.sh";
    std::fs::write(
        script,
        concat!(
            "#!/bin/sh\n",
            "sed -i 's/^bind_mounts: \\[\\]/bind_mounts:\\n",
            "  - source: \"\\/tmp\"\\n",
            "    target: \"\\/mnt\"/' \"$1\"\n"
        ),
    )
    .map_err(|e| format!("write script: {e}"))?;
    std::fs::set_permissions(script, PermissionsExt::from_mode(0o755))
        .map_err(|e| format!("chmod: {e}"))?;
    let output = ctx.cli_with_env(&["edit", name], &[("EDITOR", script)]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("edit failed: stdout={stdout} stderr={stderr}"));
    }
    if !stdout.contains("bind_mounts") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "expected bind_mounts change summary, got: {stdout}"
        ));
    }

    // Verify via mount list
    let mounts = ctx.cli_ok(&["mount", "list", name]);
    if !mounts.contains("/tmp") || !mounts.contains("/mnt") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected bind mount in mount list: {mounts}"));
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}
