use crate::context::TestContext;

pub fn test_volume_create_list_remove(ctx: &TestContext) -> Result<(), String> {
    let name = "e2e-vol-test";

    // Create
    if ctx.cli_fails(&["volume", "create", name]) {
        return Err("volume create failed".into());
    }

    // List — should contain the volume
    let output = ctx.cli_ok(&["volume", "ls"]);
    if !output.contains(name) {
        let _ = ctx.cli(&["volume", "rm", name]);
        return Err(format!("volume not in list: {output}"));
    }

    // Remove
    if ctx.cli_fails(&["volume", "rm", name]) {
        return Err("volume rm failed".into());
    }

    // List — should be gone
    let output = ctx.cli_ok(&["volume", "ls"]);
    if output.contains(name) {
        return Err("volume still in list after rm".into());
    }

    Ok(())
}

pub fn test_volume_mount_write_read(ctx: &TestContext) -> Result<(), String> {
    let vol = "e2e-vol-rw";
    ctx.cli_ok(&["volume", "create", vol]);

    // Run container, write a file to the volume
    let vol_spec = format!("{vol}:/data");
    ctx.cli_ok(&[
        "run",
        "--image",
        "alpine",
        "--volume",
        &vol_spec,
        "--",
        "/bin/sh",
        "-c",
        "echo volume-content > /data/testfile",
    ]);

    // Run another container with the same volume, read the file
    let output = ctx.cli_ok(&[
        "run",
        "--image",
        "alpine",
        "--volume",
        &vol_spec,
        "--",
        "cat",
        "/data/testfile",
    ]);

    ctx.cli_ok(&["volume", "rm", vol]);

    if !output.contains("volume-content") {
        return Err(format!("expected volume-content, got: {output}"));
    }
    Ok(())
}

pub fn test_volume_attach_detach(ctx: &TestContext) -> Result<(), String> {
    let vol = "e2e-vol-attach";
    let container = "e2e-vol-attach-ctr";

    ctx.cli_ok(&["volume", "create", vol]);

    // Start a long-running container
    ctx.cli_ok(&[
        "run", "--name", container, "--image", "alpine", "--init", "-d", "--", "sleep", "300",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Write something to the volume from outside
    // (the volume is just a directory on the host — we can write to it directly)

    // Attach volume
    let spec = format!("{vol}:/mnt/attached");
    if ctx.cli_fails(&["volume", "attach", container, &spec]) {
        let _ = ctx.cli(&["stop", container]);
        let _ = ctx.cli(&["volume", "rm", vol]);
        return Err("volume attach failed".into());
    }

    // Write via exec
    let output = ctx.cli(&[
        "exec",
        container,
        "--",
        "/bin/sh",
        "-c",
        "echo attached-ok > /mnt/attached/marker && cat /mnt/attached/marker",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // Detach
    let _ = ctx.cli(&["volume", "detach", container, "/mnt/attached"]);
    let _ = ctx.cli(&["stop", container]);
    ctx.cli_ok(&["volume", "rm", vol]);

    if !stdout.contains("attached-ok") {
        return Err(format!("expected attached-ok, got: {stdout}"));
    }
    Ok(())
}

pub fn test_volume_remove_in_use(ctx: &TestContext) -> Result<(), String> {
    let vol = "e2e-vol-inuse";
    let container = "e2e-vol-inuse-ctr";

    ctx.cli_ok(&["volume", "create", vol]);

    // Start container with volume
    let vol_spec = format!("{vol}:/data");
    ctx.cli_ok(&[
        "run", "--name", container, "--image", "alpine", "--init", "-d", "--volume", &vol_spec,
        "--", "sleep", "300",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Try to remove — should fail (in use)
    if ctx.cli_succeeds(&["volume", "rm", vol]) {
        let _ = ctx.cli(&["stop", container]);
        return Err("volume rm should fail when in use".into());
    }

    // Stop container, then remove should succeed
    let _ = ctx.cli(&["stop", container]);
    ctx.cli_ok(&["volume", "rm", vol]);

    Ok(())
}
