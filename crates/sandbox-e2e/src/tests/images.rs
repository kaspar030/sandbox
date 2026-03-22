use crate::context::TestContext;

pub fn test_image_list(ctx: &TestContext) -> Result<(), String> {
    let output = ctx.cli_ok(&["image", "list"]);
    if !output.contains("alpine") {
        return Err(format!("alpine not in image list: {output}"));
    }
    if !output.contains("ubuntu") {
        return Err(format!("ubuntu not in image list: {output}"));
    }
    Ok(())
}

pub fn test_image_inspect(ctx: &TestContext) -> Result<(), String> {
    let output = ctx.cli_ok(&["image", "inspect", "alpine"]);
    if !output.contains("Name: alpine") {
        return Err(format!("inspect output missing name: {output}"));
    }
    if !output.contains("Layers:") {
        return Err(format!("inspect output missing layers: {output}"));
    }
    Ok(())
}

/// Test creating an image from a container's rootfs via `image create --from`.
pub fn test_image_create_from(ctx: &TestContext) -> Result<(), String> {
    let container = "imgcreate-test";
    let image = "imgcreate-image";

    ctx.cli_ok(&[
        "create",
        "--name",
        container,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);
    ctx.cli_ok(&["image", "create", image, "--from", container]);

    // Verify image exists
    let list = ctx.cli_ok(&["image", "list"]);
    if !list.contains(image) {
        let _ = ctx.cli(&["destroy", container]);
        let _ = ctx.cli(&["image", "rm", image]);
        return Err(format!("{image} not in image list: {list}"));
    }

    // Clean up
    ctx.cli_ok(&["destroy", container]);
    ctx.cli_ok(&["image", "rm", image]);
    Ok(())
}

/// Test --update flag on `image create --from`.
pub fn test_image_create_update(ctx: &TestContext) -> Result<(), String> {
    let container = "imgcreate-update";
    let image = "imgcreate-update-img";

    ctx.cli_ok(&[
        "create",
        "--name",
        container,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);
    ctx.cli_ok(&["image", "create", image, "--from", container]);

    // Update should work
    ctx.cli_ok(&["image", "create", image, "--from", container, "--update"]);

    // Without --update should fail (already exists)
    if ctx.cli_succeeds(&["image", "create", image, "--from", container]) {
        let _ = ctx.cli(&["destroy", container]);
        let _ = ctx.cli(&["image", "rm", image]);
        return Err("image create without --update should fail when image exists".into());
    }

    ctx.cli_ok(&["destroy", container]);
    ctx.cli_ok(&["image", "rm", image]);
    Ok(())
}

/// Test that the deprecated `snapshot` alias still works.
pub fn test_snapshot_alias(ctx: &TestContext) -> Result<(), String> {
    let container = "snap-alias";
    let image = "snap-alias-img";

    ctx.cli_ok(&[
        "create",
        "--name",
        container,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);
    ctx.cli_ok(&["snapshot", container, image]);

    let list = ctx.cli_ok(&["image", "list"]);
    if !list.contains(image) {
        let _ = ctx.cli(&["destroy", container]);
        let _ = ctx.cli(&["image", "rm", image]);
        return Err(format!("{image} not in image list: {list}"));
    }

    ctx.cli_ok(&["destroy", container]);
    ctx.cli_ok(&["image", "rm", image]);
    Ok(())
}
