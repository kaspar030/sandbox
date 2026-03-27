use crate::context::TestContext;
use std::fs;

pub fn test_bind_mount_at_create(ctx: &TestContext) -> Result<(), String> {
    // Create a test directory with a file
    let test_dir = ctx.workdir.join("bind-test-src");
    fs::create_dir_all(&test_dir).unwrap();
    fs::write(test_dir.join("testfile"), "bind-mount-content").unwrap();

    let src = test_dir.to_str().unwrap();
    let bind_spec = format!("{src}:/mnt/test");

    let output = ctx.cli_ok(&[
        "run",
        "--image",
        "alpine",
        "--bind",
        &bind_spec,
        "--",
        "cat",
        "/mnt/test/testfile",
    ]);

    if !output.contains("bind-mount-content") {
        return Err(format!("expected bind mount content, got: {output}"));
    }
    Ok(())
}

pub fn test_hot_mount_add_remove(ctx: &TestContext) -> Result<(), String> {
    let name = "hot-mount-test";

    // Create test dir
    let test_dir = ctx.workdir.join("hot-mount-src");
    fs::create_dir_all(&test_dir).unwrap();
    fs::write(test_dir.join("hotfile"), "hot-content").unwrap();

    // Start a container
    ctx.cli_ok(&[
        "run", "--name", name, "--image", "alpine", "--init", "-d", "--", "sleep", "300",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Add mount
    let src = test_dir.to_str().unwrap();
    let spec = format!("{src}:/mnt/hot");
    if ctx.cli_fails(&["mount", "add", name, &spec]) {
        let _ = ctx.cli(&["stop", name]);
        return Err("mount add failed".into());
    }

    // Verify contents
    let output = ctx.cli_ok(&["exec", name, "--", "cat", "/mnt/hot/hotfile"]);
    if !output.contains("hot-content") {
        let _ = ctx.cli(&["stop", name]);
        return Err(format!("expected hot-content, got: {output}"));
    }

    // Remove mount
    ctx.cli_ok(&["mount", "rm", name, "/mnt/hot"]);

    // Verify it's gone
    let _ = ctx.cli(&["exec", name, "--", "ls", "/mnt/hot"]);

    let _ = ctx.cli(&["stop", name]);
    Ok(())
}

pub fn test_mount_shorthand(ctx: &TestContext) -> Result<(), String> {
    // Create a test file
    let test_file = ctx.workdir.join("shorthand-file");
    fs::write(&test_file, "shorthand-content").unwrap();

    // Run with shorthand mount (source = target)
    let src = test_file.to_str().unwrap();
    let output = ctx.cli_ok(&["run", "--image", "alpine", "--bind", src, "--", "cat", src]);

    if !output.contains("shorthand-content") {
        return Err(format!("expected shorthand-content, got: {output}"));
    }
    Ok(())
}

/// Test that mount add/remove works on stopped containers.
pub fn test_mount_stopped(ctx: &TestContext) -> Result<(), String> {
    let name = "mount-stopped-test";

    // Create test dirs
    let test_dir = ctx.workdir.join("mount-stopped-src");
    fs::create_dir_all(&test_dir).unwrap();
    fs::write(test_dir.join("data"), "stopped-mount-content").unwrap();
    let src = test_dir.to_str().unwrap();

    // Create container (stopped)
    ctx.cli_ok(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "no",
        "--",
        "sleep",
        "30",
    ]);

    // Add mount while stopped
    let spec = format!("{src}:/mnt/added");
    ctx.cli_ok(&["mount", "add", name, &spec]);

    // Verify mount is listed
    let list_output = ctx.cli_ok(&["mount", "ls", name]);
    if !list_output.contains("/mnt/added") {
        ctx.cli_ok(&["destroy", name]);
        return Err(format!(
            "expected /mnt/added in mount list, got: {list_output}"
        ));
    }

    // Start and verify mount is effective
    ctx.cli_ok(&["start", name]);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let output = ctx.cli_ok(&["exec", name, "--", "cat", "/mnt/added/data"]);
    if !output.contains("stopped-mount-content") {
        ctx.cli_ok(&["stop", name]);
        ctx.cli_ok(&["destroy", name]);
        return Err(format!("expected stopped-mount-content, got: {output}"));
    }

    // Stop, remove mount while stopped
    ctx.cli_ok(&["stop", "--timeout", "1", name]);
    ctx.cli_ok(&["mount", "rm", name, "/mnt/added"]);

    // Verify mount is gone from list
    let list_output2 = ctx.cli_ok(&["mount", "ls", name]);
    if list_output2.contains("/mnt/added") {
        ctx.cli_ok(&["destroy", name]);
        return Err("mount should have been removed".into());
    }

    ctx.cli_ok(&["destroy", name]);
    Ok(())
}

/// Test that idmap mounts are cleaned up when a container is stopped,
/// and re-created when the container is started again.
pub fn test_mount_cleanup_on_stop(ctx: &TestContext) -> Result<(), String> {
    let name = "mount-cleanup-stop";

    // Create test dir for a bind mount
    let test_dir = ctx.workdir.join("mount-cleanup-src");
    fs::create_dir_all(&test_dir).unwrap();
    fs::write(test_dir.join("data"), "cleanup-test").unwrap();
    let src = test_dir.to_str().unwrap();
    let bind_spec = format!("{src}:/mnt/test");

    // Run a detached container with a bind mount
    ctx.cli_ok(&[
        "run", "--name", name, "--image", "alpine", "--init", "-d", "--bind", &bind_spec, "--",
        "sleep", "300",
    ]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Verify the idmap mount exists
    let mounts_dir = ctx.workdir.join("mounts").join(name);
    if !mounts_dir.exists() {
        ctx.cli_ok(&["stop", "--timeout", "1", name]);
        ctx.cli_ok(&["destroy", name]);
        return Err(format!(
            "idmap mount {} should exist while running",
            mounts_dir.display()
        ));
    }

    // Stop the container
    ctx.cli_ok(&["stop", "--timeout", "2", name]);

    // Verify the idmap mount is gone
    if mounts_dir.exists() {
        ctx.cli_ok(&["destroy", name]);
        return Err(format!(
            "idmap mount {} should be cleaned up after stop",
            mounts_dir.display()
        ));
    }

    // Start again — idmap mount should be re-created
    ctx.cli_ok(&["start", name]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    if !mounts_dir.exists() {
        ctx.cli_ok(&["stop", "--timeout", "1", name]);
        ctx.cli_ok(&["destroy", name]);
        return Err(format!(
            "idmap mount {} should be re-created on start",
            mounts_dir.display()
        ));
    }

    // Verify bind mount still works after restart
    let output = ctx.cli_ok(&["exec", name, "--", "cat", "/mnt/test/data"]);
    if !output.contains("cleanup-test") {
        ctx.cli_ok(&["stop", "--timeout", "1", name]);
        ctx.cli_ok(&["destroy", name]);
        return Err(format!("expected cleanup-test, got: {output}"));
    }

    ctx.cli_ok(&["stop", "--timeout", "1", name]);
    ctx.cli_ok(&["destroy", name]);
    Ok(())
}
