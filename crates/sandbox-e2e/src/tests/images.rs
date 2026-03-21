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

pub fn test_snapshot(ctx: &TestContext) -> Result<(), String> {
    let container = "snap-test";
    let image = "snap-image";

    // Create a container, make a change, snapshot it
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

pub fn test_snapshot_update(ctx: &TestContext) -> Result<(), String> {
    let container = "snap-update-test";
    let image = "snap-update-image";

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

    // Update should work
    ctx.cli_ok(&["snapshot", container, image, "--update"]);

    // Without --update should fail (already exists)
    if ctx.cli_succeeds(&["snapshot", container, image]) {
        let _ = ctx.cli(&["destroy", container]);
        let _ = ctx.cli(&["image", "rm", image]);
        return Err("snapshot without --update should fail when image exists".into());
    }

    ctx.cli_ok(&["destroy", container]);
    ctx.cli_ok(&["image", "rm", image]);
    Ok(())
}
