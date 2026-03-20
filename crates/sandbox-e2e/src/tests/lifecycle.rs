use crate::context::TestContext;

pub fn test_run_echo(ctx: &TestContext) -> Result<(), String> {
    let output = ctx.cli_ok(&["run", "--image", "alpine", "--", "echo", "hello"]);
    if !output.contains("hello") {
        return Err(format!("expected 'hello' in output, got: {output}"));
    }
    Ok(())
}

pub fn test_run_init(ctx: &TestContext) -> Result<(), String> {
    let output = ctx.cli_ok(&[
        "run",
        "--image",
        "alpine",
        "--init",
        "--",
        "/bin/sh",
        "-c",
        "echo init-test",
    ]);
    if !output.contains("init-test") {
        return Err(format!("expected 'init-test' in output, got: {output}"));
    }
    Ok(())
}

pub fn test_create_start_stop_destroy(ctx: &TestContext) -> Result<(), String> {
    let name = "lifecycle-test";

    // Create
    if ctx.cli_fails(&["create", "--name", name, "--image", "alpine"]) {
        return Err("create failed".into());
    }

    // List — should show as Created
    let list = ctx.cli_ok(&["list"]);
    if !list.contains(name) {
        return Err(format!("container not in list: {list}"));
    }

    // Start
    if ctx.cli_fails(&["start", name, "--", "sleep", "60"]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("start failed".into());
    }

    // Stop
    if ctx.cli_fails(&["stop", name]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("stop failed".into());
    }

    // Destroy
    if ctx.cli_fails(&["destroy", name]) {
        return Err("destroy failed".into());
    }

    // List — should be gone
    let list = ctx.cli_ok(&["list"]);
    if list.contains(name) {
        return Err("container still in list after destroy".into());
    }

    Ok(())
}

pub fn test_petname_auto(ctx: &TestContext) -> Result<(), String> {
    let output = ctx.cli_ok(&["run", "--image", "alpine", "--", "echo", "petname-ok"]);
    if !output.contains("petname-ok") {
        return Err(format!("expected 'petname-ok', got: {output}"));
    }
    Ok(())
}

pub fn test_list_containers(ctx: &TestContext) -> Result<(), String> {
    let name1 = "list-test-1";
    let name2 = "list-test-2";

    ctx.cli_ok(&["create", "--name", name1, "--image", "alpine"]);
    ctx.cli_ok(&["create", "--name", name2, "--image", "alpine"]);

    let list = ctx.cli_ok(&["list"]);
    let ok = list.contains(name1) && list.contains(name2);

    ctx.cli_ok(&["destroy", name1]);
    ctx.cli_ok(&["destroy", name2]);

    if !ok {
        return Err(format!("containers not in list: {list}"));
    }
    Ok(())
}
