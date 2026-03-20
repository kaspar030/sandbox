use crate::context::TestContext;
use std::fs;

pub fn test_stack_up_down(ctx: &TestContext) -> Result<(), String> {
    // Write a stack YAML file
    let stack_file = ctx.workdir.join("test-stack.yaml");
    fs::write(
        &stack_file,
        r#"
name: e2e-stack
containers:
  app1:
    image: alpine
    init: true
    command: ["sleep", "300"]
  app2:
    image: alpine
    init: true
    command: ["sleep", "300"]
"#,
    )
    .unwrap();

    // Stack up
    let output = ctx.cli(&["stack", "up", stack_file.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if !output.status.success() {
        return Err(format!(
            "stack up failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if !stdout.contains("e2e-stack") {
        return Err(format!("expected stack name in output: {stdout}"));
    }

    // Stack list
    let output = ctx.cli_ok(&["stack", "ls"]);
    if !output.contains("e2e-stack") {
        let _ = ctx.cli(&["stack", "down", "e2e-stack"]);
        return Err(format!("stack not in list: {output}"));
    }

    // Stack ps
    let output = ctx.cli_ok(&["stack", "ps", "e2e-stack"]);
    if !output.contains("e2e-stack-app1") || !output.contains("e2e-stack-app2") {
        let _ = ctx.cli(&["stack", "down", "e2e-stack"]);
        return Err(format!("containers not in stack ps: {output}"));
    }

    // Stack down
    let output = ctx.cli(&["stack", "down", "e2e-stack"]);
    if !output.status.success() {
        return Err(format!(
            "stack down failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Verify containers are gone
    let output = ctx.cli_ok(&["list"]);
    if output.contains("e2e-stack-app1") || output.contains("e2e-stack-app2") {
        return Err("containers still present after stack down".into());
    }

    Ok(())
}

pub fn test_stack_with_volumes(ctx: &TestContext) -> Result<(), String> {
    let stack_file = ctx.workdir.join("test-stack-vol.yaml");
    fs::write(
        &stack_file,
        r#"
name: e2e-stack-vol
volumes:
  - data
containers:
  writer:
    image: alpine
    init: true
    volumes:
      - data:/shared
    command: ["sh", "-c", "echo stack-vol-ok > /shared/marker && sleep 300"]
"#,
    )
    .unwrap();

    // Stack up
    let output = ctx.cli(&["stack", "up", stack_file.to_str().unwrap()]);
    if !output.status.success() {
        return Err(format!(
            "stack up failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }

    // Wait for writer to create the file
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Verify the volume data via exec
    let output = ctx.cli(&[
        "exec",
        "e2e-stack-vol-writer",
        "--",
        "cat",
        "/shared/marker",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // Clean up
    let _ = ctx.cli(&["stack", "down", "e2e-stack-vol"]);

    if !stdout.contains("stack-vol-ok") {
        return Err(format!("expected stack-vol-ok, got: {stdout}"));
    }

    Ok(())
}

pub fn test_stack_with_networking(ctx: &TestContext) -> Result<(), String> {
    let stack_file = ctx.workdir.join("test-stack-net.yaml");
    fs::write(
        &stack_file,
        r#"
name: e2e-stack-net
containers:
  nettest:
    image: alpine
    init: true
    command: ["sleep", "300"]
"#,
    )
    .unwrap();

    // Stack up
    let output = ctx.cli(&["stack", "up", stack_file.to_str().unwrap()]);
    if !output.status.success() {
        return Err(format!(
            "stack up failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }

    std::thread::sleep(std::time::Duration::from_millis(500));

    // Verify the container has a bridged IP
    let output = ctx.cli(&["exec", "e2e-stack-net-nettest", "--", "ifconfig"]);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let _ = ctx.cli(&["stack", "down", "e2e-stack-net"]);

    // Stack auto-creates a network with an auto-allocated subnet (10.0.N.0/24)
    if !stdout.contains("inet addr:10.") {
        return Err(format!("expected bridged IP (10.x.x.x), got: {stdout}"));
    }

    Ok(())
}
