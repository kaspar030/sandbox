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

pub fn test_stack_dns_resolution(ctx: &TestContext) -> Result<(), String> {
    let stack_file = ctx.workdir.join("test-stack-dns.yaml");
    fs::write(
        &stack_file,
        r#"
name: e2e-dns
containers:
  server:
    image: alpine
    init: true
    command: ["sleep", "300"]
  client:
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

    std::thread::sleep(std::time::Duration::from_secs(1));

    // Verify DNS: client should be able to resolve "server" to an IP
    // Use nslookup/ping/getent - alpine has nslookup
    let output = ctx.cli(&["exec", "e2e-dns-client", "--", "nslookup", "server"]);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // Also check resolv.conf points to the gateway
    let resolv = ctx.cli(&["exec", "e2e-dns-client", "--", "cat", "/etc/resolv.conf"]);
    let resolv_content = String::from_utf8_lossy(&resolv.stdout).to_string();

    let _ = ctx.cli(&["stack", "down", "e2e-dns"]);

    // Verify resolv.conf points to a gateway (10.x.x.1)
    if !resolv_content.contains("nameserver 10.") {
        return Err(format!(
            "resolv.conf should point to gateway, got: {resolv_content}"
        ));
    }

    // Verify nslookup resolved "server" to an IP
    let combined = format!("{stdout}{stderr}");
    if !combined.contains("10.") {
        return Err(format!(
            "DNS resolution failed. nslookup output: {combined}"
        ));
    }

    Ok(())
}

pub fn test_stack_compose_format(ctx: &TestContext) -> Result<(), String> {
    let stack_file = ctx.workdir.join("test-compose.yaml");
    fs::write(
        &stack_file,
        r#"
name: e2e-compose
volumes:
  shared:
services:
  first:
    image: alpine
    init: true
    environment:
      MY_VAR: hello
    command: ["sh", "-c", "echo $MY_VAR > /data/result && sleep 300"]
    volumes:
      - shared:/data
  second:
    image: alpine
    init: true
    depends_on:
      - first
    command: ["sleep", "300"]
    volumes:
      - shared:/data
"#,
    )
    .unwrap();

    let output = ctx.cli(&["stack", "up", stack_file.to_str().unwrap()]);
    if !output.status.success() {
        return Err(format!(
            "compose stack up failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }

    std::thread::sleep(std::time::Duration::from_secs(1));

    let output = ctx.cli(&["exec", "e2e-compose-second", "--", "cat", "/data/result"]);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let _ = ctx.cli(&["stack", "down", "e2e-compose"]);

    if !stdout.contains("hello") {
        return Err(format!(
            "expected 'hello' from env var in shared volume, got: {stdout}"
        ));
    }

    Ok(())
}

pub fn test_stack_strict_parsing(ctx: &TestContext) -> Result<(), String> {
    let stack_file = ctx.workdir.join("test-strict.yaml");
    fs::write(
        &stack_file,
        r#"
name: e2e-strict
unknown_field: true
services:
  app:
    image: alpine
"#,
    )
    .unwrap();

    let output = ctx.cli(&["stack", "up", stack_file.to_str().unwrap()]);
    if output.status.success() {
        let _ = ctx.cli(&["stack", "down", "e2e-strict"]);
        return Err("stack up should fail with unknown field".into());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let combined = format!("{stdout}{stderr}");
    if !combined.to_lowercase().contains("unknown") {
        return Err(format!("error should mention 'unknown', got: {combined}"));
    }

    Ok(())
}

pub fn test_stack_check_valid(ctx: &TestContext) -> Result<(), String> {
    let file = ctx.workdir.join("check-valid.yaml");
    fs::write(
        &file,
        r#"
name: check-valid
services:
  app:
    image: alpine
    command: ["echo", "hello"]
    environment:
      FOO: bar
    ports:
      - "8080:80"
"#,
    )
    .unwrap();

    let output = ctx.cli(&["stack", "check", file.to_str().unwrap()]);
    if !output.status.success() {
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return Err(format!("check should pass: {combined}"));
    }
    Ok(())
}

pub fn test_stack_check_unsupported(ctx: &TestContext) -> Result<(), String> {
    let file = ctx.workdir.join("check-unsupported.yaml");
    fs::write(
        &file,
        r#"
name: check-bad
version: "3.8"
services:
  app:
    image: alpine
    healthcheck:
      test: ["CMD", "true"]
    restart: always
"#,
    )
    .unwrap();

    // Should fail (unknown field 'healthcheck')
    let output = ctx.cli(&["stack", "check", file.to_str().unwrap()]);
    if output.status.success() {
        return Err("check should fail with unsupported fields".into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if !stdout.contains("healthcheck") {
        return Err(format!(
            "should report 'healthcheck' as unknown, got: {stdout}"
        ));
    }

    Ok(())
}

pub fn test_stack_check_quiet(ctx: &TestContext) -> Result<(), String> {
    let file = ctx.workdir.join("check-quiet.yaml");
    fs::write(
        &file,
        r#"
name: check-quiet
services:
  app:
    image: alpine
"#,
    )
    .unwrap();

    let output = ctx.cli(&["stack", "check", file.to_str().unwrap(), "--quiet"]);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if !stdout.trim().is_empty() {
        return Err(format!("--quiet should produce no output, got: {stdout}"));
    }
    if !output.status.success() {
        return Err("check --quiet should succeed for valid file".into());
    }

    Ok(())
}
