use crate::context::TestContext;

/// Test cloning from a running container: create container, write a file,
/// clone it, start the clone, verify the file exists.
pub fn test_clone_from_container(ctx: &TestContext) -> Result<(), String> {
    let src = "clone-src";
    let dst = "clone-dst";

    ctx.cli_ok(&[
        "create",
        "--name",
        src,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);
    ctx.cli_ok(&["start", src]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Write a marker file in the source container
    ctx.cli_ok(&[
        "exec",
        src,
        "--",
        "sh",
        "-c",
        "echo cloned > /clone-marker.txt",
    ]);

    // Clone from the running container
    let output = ctx.cli_ok(&["create", "--from", src, "--name", dst]);
    if !output.contains("Created") {
        let _ = ctx.cli(&["stop", src]);
        let _ = ctx.cli(&["destroy", src]);
        return Err(format!("clone failed: {output}"));
    }

    // Start the clone and verify the marker file
    ctx.cli_ok(&["start", dst]);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let out = ctx.cli(&["exec", "-T", dst, "--", "cat", "/clone-marker.txt"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.contains("cloned") {
        let _ = ctx.cli(&["stop", src]);
        let _ = ctx.cli(&["stop", dst]);
        let _ = ctx.cli(&["destroy", src]);
        let _ = ctx.cli(&["destroy", dst]);
        return Err(format!("expected 'cloned' in clone, got: {stdout}"));
    }

    let _ = ctx.cli(&["stop", "--timeout", "2", src]);
    let _ = ctx.cli(&["stop", "--timeout", "2", dst]);
    let _ = ctx.cli(&["destroy", src]);
    let _ = ctx.cli(&["destroy", dst]);
    Ok(())
}

/// Test cloning from a snapshot: create container, write a file, snapshot,
/// clone from snapshot, verify file exists in clone.
pub fn test_clone_from_snapshot(ctx: &TestContext) -> Result<(), String> {
    let src = "clone-snap-src";
    let dst = "clone-snap-dst";

    ctx.cli_ok(&[
        "create",
        "--name",
        src,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);
    ctx.cli_ok(&["start", src]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Write a marker file
    ctx.cli_ok(&[
        "exec",
        src,
        "--",
        "sh",
        "-c",
        "echo snapshot-clone > /snap-marker.txt",
    ]);

    // Snapshot
    ctx.cli_ok(&["snapshot", src, "v1"]);

    // Modify the file after snapshot (to prove clone gets snapshot state)
    ctx.cli_ok(&[
        "exec",
        src,
        "--",
        "sh",
        "-c",
        "echo modified > /snap-marker.txt",
    ]);

    // Clone from the snapshot
    let output = ctx.cli_ok(&[
        "create",
        "--from-snapshot",
        &format!("{src}:v1"),
        "--name",
        dst,
    ]);
    if !output.contains("Created") {
        let _ = ctx.cli(&["stop", src]);
        let _ = ctx.cli(&["destroy", src]);
        return Err(format!("clone from snapshot failed: {output}"));
    }

    // Start the clone and verify it has the snapshot's content, not the modified content
    ctx.cli_ok(&["start", dst]);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let out = ctx.cli(&["exec", "-T", dst, "--", "cat", "/snap-marker.txt"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.contains("snapshot-clone") {
        let _ = ctx.cli(&["stop", src]);
        let _ = ctx.cli(&["stop", dst]);
        let _ = ctx.cli(&["destroy", src]);
        let _ = ctx.cli(&["destroy", dst]);
        return Err(format!("expected 'snapshot-clone' in clone, got: {stdout}"));
    }

    let _ = ctx.cli(&["stop", "--timeout", "2", src]);
    let _ = ctx.cli(&["stop", "--timeout", "2", dst]);
    let _ = ctx.cli(&["snapshot-rm", src, "v1"]);
    let _ = ctx.cli(&["destroy", src]);
    let _ = ctx.cli(&["destroy", dst]);
    Ok(())
}

/// Test cloning with overrides: clone a container with a different hostname,
/// verify the override is applied.
pub fn test_clone_with_overrides(ctx: &TestContext) -> Result<(), String> {
    let src = "clone-override-src";
    let dst = "clone-override-dst";

    ctx.cli_ok(&[
        "create",
        "--name",
        src,
        "--image",
        "alpine",
        "--restart",
        "no",
        "--hostname",
        "original-host",
    ]);

    // Clone with hostname override
    let output = ctx.cli_ok(&[
        "create",
        "--from",
        src,
        "--name",
        dst,
        "--hostname",
        "cloned-host",
    ]);
    if !output.contains("Created") {
        let _ = ctx.cli(&["destroy", src]);
        return Err(format!("clone with overrides failed: {output}"));
    }

    // Start the clone and verify hostname
    ctx.cli_ok(&["start", dst]);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let out = ctx.cli(&["exec", "-T", dst, "--", "hostname"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.contains("cloned-host") {
        let _ = ctx.cli(&["stop", dst]);
        let _ = ctx.cli(&["destroy", src]);
        let _ = ctx.cli(&["destroy", dst]);
        return Err(format!("expected 'cloned-host', got: {stdout}"));
    }

    let _ = ctx.cli(&["stop", "--timeout", "2", dst]);
    let _ = ctx.cli(&["destroy", src]);
    let _ = ctx.cli(&["destroy", dst]);
    Ok(())
}

/// Test that cloning a container produces independent rootfs: modifying the
/// clone does not affect the source.
pub fn test_clone_independence(ctx: &TestContext) -> Result<(), String> {
    let src = "clone-indep-src";
    let dst = "clone-indep-dst";

    ctx.cli_ok(&[
        "create",
        "--name",
        src,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);
    ctx.cli_ok(&["start", src]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Write a file in source
    ctx.cli_ok(&["exec", src, "--", "sh", "-c", "echo source > /indep.txt"]);

    // Clone
    ctx.cli_ok(&["create", "--from", src, "--name", dst]);
    ctx.cli_ok(&["start", dst]);
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Modify the file in the clone
    ctx.cli_ok(&["exec", dst, "--", "sh", "-c", "echo clone > /indep.txt"]);

    // Verify source is unchanged
    let out = ctx.cli(&["exec", "-T", src, "--", "cat", "/indep.txt"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.contains("source") {
        let _ = ctx.cli(&["stop", src]);
        let _ = ctx.cli(&["stop", dst]);
        let _ = ctx.cli(&["destroy", src]);
        let _ = ctx.cli(&["destroy", dst]);
        return Err(format!(
            "source was modified by clone change, got: {stdout}"
        ));
    }

    let _ = ctx.cli(&["stop", "--timeout", "2", src]);
    let _ = ctx.cli(&["stop", "--timeout", "2", dst]);
    let _ = ctx.cli(&["destroy", src]);
    let _ = ctx.cli(&["destroy", dst]);
    Ok(())
}
