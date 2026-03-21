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
    if ctx.cli_fails(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]) {
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

    // Stop (short timeout — sleep as PID 1 ignores SIGTERM)
    if ctx.cli_fails(&["stop", "--timeout", "1", name]) {
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

    ctx.cli_ok(&[
        "create",
        "--name",
        name1,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);
    ctx.cli_ok(&[
        "create",
        "--name",
        name2,
        "--image",
        "alpine",
        "--restart",
        "no",
    ]);

    let list = ctx.cli_ok(&["list"]);
    let ok = list.contains(name1) && list.contains(name2);

    ctx.cli_ok(&["destroy", name1]);
    ctx.cli_ok(&["destroy", name2]);

    if !ok {
        return Err(format!("containers not in list: {list}"));
    }
    Ok(())
}

pub fn test_inspect(ctx: &TestContext) -> Result<(), String> {
    let name = "inspect-test";
    let test_dir = ctx.workdir.join("inspect-bind-src");
    std::fs::create_dir_all(&test_dir).unwrap();
    let src = test_dir.to_str().unwrap();
    let bind_spec = format!("{src}:/mnt/data");

    ctx.cli_ok(&[
        "create",
        "--name",
        name,
        "--image",
        "alpine",
        "-e",
        "MYKEY=myval",
        "--bind",
        &bind_spec,
        "--restart",
        "no",
        "--",
        "sleep",
        "30",
    ]);

    // Human-readable inspect
    let output = ctx.cli_ok(&["inspect", name]);
    if !output.contains("Name:") || !output.contains(name) {
        ctx.cli_ok(&["destroy", name]);
        return Err(format!("missing Name field in inspect output: {output}"));
    }
    if !output.contains("Image:") || !output.contains("alpine") {
        ctx.cli_ok(&["destroy", name]);
        return Err(format!("missing Image field in inspect output: {output}"));
    }
    if !output.contains("MYKEY=myval") {
        ctx.cli_ok(&["destroy", name]);
        return Err(format!("missing env in inspect output: {output}"));
    }
    if !output.contains("/mnt/data") {
        ctx.cli_ok(&["destroy", name]);
        return Err(format!("missing bind mount in inspect output: {output}"));
    }

    // JSON inspect
    let json_output = ctx.cli_ok(&["inspect", "--json", name]);
    // Verify it parses as valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&json_output).map_err(|e| {
        ctx.cli_ok(&["destroy", name]);
        format!("invalid JSON from inspect --json: {e}\noutput: {json_output}")
    })?;

    // Check key fields in JSON
    if parsed["name"].as_str() != Some(name) {
        ctx.cli_ok(&["destroy", name]);
        return Err(format!("JSON name mismatch: {:?}", parsed["name"]));
    }
    if parsed["image"].as_str() != Some("alpine") {
        ctx.cli_ok(&["destroy", name]);
        return Err(format!("JSON image mismatch: {:?}", parsed["image"]));
    }

    ctx.cli_ok(&["destroy", name]);
    Ok(())
}
