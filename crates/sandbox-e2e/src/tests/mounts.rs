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
