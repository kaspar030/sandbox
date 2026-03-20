use crate::context::TestContext;

pub fn test_bridged_auto_ip(ctx: &TestContext) -> Result<(), String> {
    // Use ifconfig (available in alpine) to check for assigned IP
    let output = ctx.cli(&[
        "run",
        "--network",
        "bridged",
        "--image",
        "alpine",
        "--",
        "ifconfig",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        return Err(format!("bridged run failed: {stderr}"));
    }

    if !stdout.contains("10.0.0.") {
        return Err(format!(
            "expected 10.0.0.x IP in ifconfig output, got: {stdout}"
        ));
    }

    Ok(())
}

pub fn test_publish_requires_bridged(ctx: &TestContext) -> Result<(), String> {
    let output = ctx.cli(&[
        "run",
        "--publish",
        "8080:80",
        "--image",
        "alpine",
        "--",
        "echo",
        "should-fail",
    ]);

    if output.status.success() {
        return Err("--publish without --network bridged should fail".into());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    if !combined.contains("bridged") {
        return Err(format!("error should mention 'bridged', got: {combined}"));
    }

    Ok(())
}

pub fn test_bridged_dns(ctx: &TestContext) -> Result<(), String> {
    let output = ctx.cli_ok(&[
        "run",
        "--network",
        "bridged",
        "--image",
        "alpine",
        "--",
        "cat",
        "/etc/resolv.conf",
    ]);

    if !output.contains("nameserver") {
        return Err(format!("expected nameserver in resolv.conf, got: {output}"));
    }

    Ok(())
}
