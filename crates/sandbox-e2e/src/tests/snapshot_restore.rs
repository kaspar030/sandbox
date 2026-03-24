use crate::context::TestContext;

/// Test basic snapshot and restore: create container, write a file,
/// snapshot, modify file, restore, verify original content.
pub fn test_snapshot_and_restore(ctx: &TestContext) -> Result<(), String> {
    let name = "snap-basic";

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

    // Write a marker file
    ctx.cli_ok(&[
        "exec",
        name,
        "--",
        "sh",
        "-c",
        "echo original > /marker.txt",
    ]);

    // Snapshot
    let output = ctx.cli_ok(&["snapshot", name, "v1"]);
    if !output.contains("Snapshotted") {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("snapshot failed: {output}"));
    }

    // Modify the file
    ctx.cli_ok(&[
        "exec",
        name,
        "--",
        "sh",
        "-c",
        "echo modified > /marker.txt",
    ]);

    // Verify modified
    let out = ctx.cli(&["exec", "-T", name, "--", "cat", "/marker.txt"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.contains("modified") {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected 'modified', got: {stdout}"));
    }

    // Stop and restore
    ctx.cli_ok(&["stop", "--timeout", "3", name]);
    let output = ctx.cli_ok(&["restore", name, "v1"]);
    if !output.contains("Restored") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("restore failed: {output}"));
    }

    // Start and verify original content
    ctx.cli_ok(&["start", name]);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let out = ctx.cli(&["exec", "-T", name, "--", "cat", "/marker.txt"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.contains("original") {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected 'original' after restore, got: {stdout}"));
    }

    let _ = ctx.cli(&["stop", "--timeout", "2", name]);
    let _ = ctx.cli(&["snapshot-rm", name, "v1"]);
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test snapshot with volumes included.
pub fn test_snapshot_with_volumes(ctx: &TestContext) -> Result<(), String> {
    let name = "snap-vol";
    let vol = "snap-vol-data";

    ctx.cli_ok(&["volume", "create", vol]);
    ctx.cli_ok(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "no",
        "-v",
        &format!("{vol}:/data"),
    ]);
    ctx.cli_ok(&["start", name]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Write to volume
    ctx.cli_ok(&[
        "exec",
        name,
        "--",
        "sh",
        "-c",
        "echo voldata > /data/test.txt",
    ]);

    // Snapshot (includes volumes by default)
    ctx.cli_ok(&["snapshot", name, "v1"]);

    // Modify volume data
    ctx.cli_ok(&[
        "exec",
        name,
        "--",
        "sh",
        "-c",
        "echo changed > /data/test.txt",
    ]);

    // Stop and restore
    ctx.cli_ok(&["stop", "--timeout", "3", name]);
    ctx.cli_ok(&["restore", name, "v1"]);

    // Start and verify volume data restored
    ctx.cli_ok(&["start", name]);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let out = ctx.cli(&["exec", "-T", name, "--", "cat", "/data/test.txt"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.contains("voldata") {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        let _ = ctx.cli(&["volume", "rm", vol]);
        return Err(format!("expected 'voldata' after restore, got: {stdout}"));
    }

    let _ = ctx.cli(&["stop", "--timeout", "2", name]);
    let _ = ctx.cli(&["snapshot-rm", name, "v1"]);
    let _ = ctx.cli(&["destroy", name]);
    let _ = ctx.cli(&["volume", "rm", vol]);
    Ok(())
}

/// Test snapshot with --exclude-volumes.
pub fn test_snapshot_exclude_volumes(ctx: &TestContext) -> Result<(), String> {
    let name = "snap-excl";
    let vol = "snap-excl-data";

    ctx.cli_ok(&["volume", "create", vol]);
    ctx.cli_ok(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "no",
        "-v",
        &format!("{vol}:/data"),
    ]);
    ctx.cli_ok(&["start", name]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Write to volume
    ctx.cli_ok(&[
        "exec",
        name,
        "--",
        "sh",
        "-c",
        "echo original > /data/test.txt",
    ]);

    // Snapshot WITHOUT volumes
    ctx.cli_ok(&["snapshot", name, "v1", "--exclude-volumes"]);

    // Modify volume data
    ctx.cli_ok(&[
        "exec",
        name,
        "--",
        "sh",
        "-c",
        "echo modified > /data/test.txt",
    ]);

    // Stop and restore
    ctx.cli_ok(&["stop", "--timeout", "3", name]);
    ctx.cli_ok(&["restore", name, "v1"]);

    // Start — volume data should NOT be rolled back (was excluded)
    ctx.cli_ok(&["start", name]);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let out = ctx.cli(&["exec", "-T", name, "--", "cat", "/data/test.txt"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.contains("modified") {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        let _ = ctx.cli(&["volume", "rm", vol]);
        return Err(format!(
            "volume data should NOT be rolled back with --exclude-volumes, got: {stdout}"
        ));
    }

    let _ = ctx.cli(&["stop", "--timeout", "2", name]);
    let _ = ctx.cli(&["snapshot-rm", name, "v1"]);
    let _ = ctx.cli(&["destroy", name]);
    let _ = ctx.cli(&["volume", "rm", vol]);
    Ok(())
}

/// Test snapshot while container is running — should succeed.
pub fn test_snapshot_running_container(ctx: &TestContext) -> Result<(), String> {
    let name = "snap-running";

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

    // Snapshot while running — should work
    if ctx.cli_fails(&["snapshot", name, "v1"]) {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err("snapshot should succeed on running container".into());
    }

    let _ = ctx.cli(&["stop", "--timeout", "2", name]);
    let _ = ctx.cli(&["snapshot-rm", name, "v1"]);
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test restore on running container — should fail.
pub fn test_restore_requires_stopped(ctx: &TestContext) -> Result<(), String> {
    let name = "snap-restore-running";

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

    // Snapshot
    ctx.cli_ok(&["snapshot", name, "v1"]);

    // Try restore while running — should fail
    if ctx.cli_succeeds(&["restore", name, "v1"]) {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err("restore should fail on running container".into());
    }

    let _ = ctx.cli(&["stop", "--timeout", "2", name]);
    let _ = ctx.cli(&["snapshot-rm", name, "v1"]);
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test snapshot list and delete.
pub fn test_snapshot_list_and_delete(ctx: &TestContext) -> Result<(), String> {
    let name = "snap-list";

    ctx.cli_ok(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);

    // Create two snapshots
    ctx.cli_ok(&["snapshot", name, "first"]);
    ctx.cli_ok(&["snapshot", name, "second"]);

    // List — should contain both
    let output = ctx.cli_ok(&["snapshots", name]);
    if !output.contains("first") || !output.contains("second") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("expected 'first' and 'second' in list: {output}"));
    }

    // Delete one
    ctx.cli_ok(&["snapshot-rm", name, "first"]);

    // List — should only contain second
    let output = ctx.cli_ok(&["snapshots", name]);
    if output.contains("first") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("'first' should be deleted: {output}"));
    }
    if !output.contains("second") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("'second' should still exist: {output}"));
    }

    let _ = ctx.cli(&["snapshot-rm", name, "second"]);
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test auto-generated snapshot name.
pub fn test_snapshot_auto_name(ctx: &TestContext) -> Result<(), String> {
    let name = "snap-auto";

    ctx.cli_ok(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);

    // Snapshot without a name
    let output = ctx.cli_ok(&["snapshot", name]);
    if !output.contains("snap-") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!(
            "expected auto-generated name 'snap-*', got: {output}"
        ));
    }

    // List — should have one snapshot
    let list = ctx.cli_ok(&["snapshots", name]);
    if !list.contains("snap-") {
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("no auto-named snapshot in list: {list}"));
    }

    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}
