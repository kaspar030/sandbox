use crate::context::TestContext;

pub fn test_network_create_list_remove(ctx: &TestContext) -> Result<(), String> {
    let name = "e2e-net-test";

    // Create
    if ctx.cli_fails(&["network", "create", name]) {
        return Err("network create failed".into());
    }

    // List
    let output = ctx.cli_ok(&["network", "ls"]);
    if !output.contains(name) {
        let _ = ctx.cli(&["network", "rm", name]);
        return Err(format!("network not in list: {output}"));
    }

    // Remove
    if ctx.cli_fails(&["network", "rm", name]) {
        return Err("network rm failed".into());
    }

    Ok(())
}

pub fn test_network_with_subnet(ctx: &TestContext) -> Result<(), String> {
    let name = "e2e-net-sub";

    // Create with explicit subnet
    if ctx.cli_fails(&["network", "create", name, "--subnet", "10.99.0.0/24"]) {
        return Err("network create with subnet failed".into());
    }

    // List should show the subnet
    let output = ctx.cli_ok(&["network", "ls"]);
    if !output.contains("10.99.0.0/24") {
        let _ = ctx.cli(&["network", "rm", name]);
        return Err(format!("subnet not in list: {output}"));
    }

    // Remove
    ctx.cli_ok(&["network", "rm", name]);
    Ok(())
}

pub fn test_container_on_named_network(ctx: &TestContext) -> Result<(), String> {
    let net = "e2e-net-run";

    // Create network
    ctx.cli_ok(&["network", "create", net, "--subnet", "10.88.0.0/24"]);

    // Run container on the network
    let output = ctx.cli(&[
        "run",
        "--network",
        net,
        "--image",
        "alpine",
        "--",
        "ifconfig",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // Clean up
    ctx.cli_ok(&["network", "rm", net]);

    if !output.status.success() {
        return Err(format!(
            "run on named network failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if !stdout.contains("10.88.0.") {
        return Err(format!("expected 10.88.0.x IP, got: {stdout}"));
    }

    Ok(())
}

pub fn test_default_network(ctx: &TestContext) -> Result<(), String> {
    // "default" network should always exist
    let output = ctx.cli_ok(&["network", "ls"]);
    if !output.contains("default") {
        return Err(format!("default network not in list: {output}"));
    }

    // --network default should work
    let output = ctx.cli(&[
        "run",
        "--network",
        "default",
        "--image",
        "alpine",
        "--",
        "ifconfig",
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if !output.status.success() {
        return Err(format!(
            "run on default network failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if !stdout.contains("10.0.0.") {
        return Err(format!("expected 10.0.0.x IP, got: {stdout}"));
    }

    Ok(())
}
