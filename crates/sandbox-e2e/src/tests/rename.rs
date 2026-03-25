use crate::context::TestContext;

/// Test basic rename: create a container, rename it, verify it works under new name.
pub fn test_rename_basic(ctx: &TestContext) -> Result<(), String> {
    let old = "rename-old";
    let new = "rename-new";

    ctx.cli_ok(&[
        "create",
        "--name",
        old,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);

    // Rename
    let output = ctx.cli_ok(&["rename", old, new]);
    if !output.contains("Renamed") {
        let _ = ctx.cli(&["destroy", old]);
        let _ = ctx.cli(&["destroy", new]);
        return Err(format!("expected 'Renamed' in output: {output}"));
    }

    // Old name should not exist
    if ctx.cli_succeeds(&["inspect", old]) {
        let _ = ctx.cli(&["destroy", old]);
        let _ = ctx.cli(&["destroy", new]);
        return Err("old container name should not exist after rename".into());
    }

    // New name should exist and be startable
    ctx.cli_ok(&["start", new]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    let out = ctx.cli(&["exec", "-T", new, "--", "echo", "hello"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.contains("hello") {
        let _ = ctx.cli(&["stop", new]);
        let _ = ctx.cli(&["destroy", new]);
        return Err(format!("exec on renamed container failed: {stdout}"));
    }

    let _ = ctx.cli(&["stop", "--timeout", "2", new]);
    let _ = ctx.cli(&["destroy", new]);
    Ok(())
}

/// Test rename preserves data: write a file, rename, start, verify file exists.
pub fn test_rename_preserves_data(ctx: &TestContext) -> Result<(), String> {
    let old = "rename-data-old";
    let new = "rename-data-new";

    ctx.cli_ok(&[
        "create",
        "--name",
        old,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);
    ctx.cli_ok(&["start", old]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Write a marker
    ctx.cli_ok(&[
        "exec",
        old,
        "--",
        "sh",
        "-c",
        "echo preserved > /rename-marker.txt",
    ]);

    // Stop and rename
    ctx.cli_ok(&["stop", "--timeout", "2", old]);
    ctx.cli_ok(&["rename", old, new]);

    // Start under new name, verify data
    ctx.cli_ok(&["start", new]);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let out = ctx.cli(&["exec", "-T", new, "--", "cat", "/rename-marker.txt"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.contains("preserved") {
        let _ = ctx.cli(&["stop", new]);
        let _ = ctx.cli(&["destroy", new]);
        return Err(format!("expected 'preserved' after rename, got: {stdout}"));
    }

    let _ = ctx.cli(&["stop", "--timeout", "2", new]);
    let _ = ctx.cli(&["destroy", new]);
    Ok(())
}

/// Test rename fails on running container.
pub fn test_rename_running_fails(ctx: &TestContext) -> Result<(), String> {
    let name = "rename-running";

    ctx.cli_ok(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);
    ctx.cli_ok(&["start", name]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Rename should fail
    if ctx.cli_succeeds(&["rename", name, "rename-running-new"]) {
        let _ = ctx.cli(&["stop", "rename-running-new"]);
        let _ = ctx.cli(&["destroy", "rename-running-new"]);
        return Err("rename should fail on a running container".into());
    }

    let _ = ctx.cli(&["stop", "--timeout", "2", name]);
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test rename updates snapshots: create, snapshot, rename, list snapshots under new name.
pub fn test_rename_with_snapshots(ctx: &TestContext) -> Result<(), String> {
    let old = "rename-snap-old";
    let new = "rename-snap-new";

    ctx.cli_ok(&[
        "create",
        "--name",
        old,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);

    // Create a snapshot
    ctx.cli_ok(&["snapshot", old, "v1"]);

    // Rename
    ctx.cli_ok(&["rename", old, new]);

    // Snapshots should be accessible under the new name
    let output = ctx.cli_ok(&["snapshots", new]);
    if !output.contains("v1") {
        let _ = ctx.cli(&["destroy", new]);
        return Err(format!(
            "expected 'v1' in snapshots of renamed container: {output}"
        ));
    }

    // Should be able to restore from the snapshot
    ctx.cli_ok(&["restore", new, "v1"]);

    let _ = ctx.cli(&["snapshot-rm", new, "v1"]);
    let _ = ctx.cli(&["destroy", new]);
    Ok(())
}
