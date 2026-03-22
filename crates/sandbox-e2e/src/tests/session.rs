use crate::context::TestContext;

/// Test session mode: multiple requests on one connection.
///
/// Uses the client library directly (not CLI) to enable session mode
/// and send multiple requests: create → start → exec → stop → destroy.
pub fn test_session_multi_request(ctx: &TestContext) -> Result<(), String> {
    let name = "session-multi";

    // Connect and enable session
    let mut client = ctx.client();
    client
        .enable_session()
        .map_err(|e| format!("enable_session failed: {e}"))?;

    // Create container
    let resp = client
        .request(&sandbox_proto::Request::Create(
            sandbox_proto::ContainerSpec {
                name: name.to_string(),
                image: "alpine".to_string(),
                restart_policy: sandbox_proto::RestartPolicy::No,
                use_init: true,
                ..Default::default()
            },
        ))
        .map_err(|e| format!("create failed: {e}"))?;
    if matches!(resp, sandbox_proto::Response::Error { .. }) {
        return Err(format!("create returned error: {resp:?}"));
    }

    // Start container (on same connection)
    let resp = client
        .request(&sandbox_proto::Request::Start {
            name: name.to_string(),
            command: None,
        })
        .map_err(|e| format!("start failed: {e}"))?;
    if matches!(resp, sandbox_proto::Response::Error { .. }) {
        return Err(format!("start returned error: {resp:?}"));
    }

    std::thread::sleep(std::time::Duration::from_millis(500));

    // List containers (on same connection)
    let resp = client
        .request(&sandbox_proto::Request::List)
        .map_err(|e| format!("list failed: {e}"))?;
    match resp {
        sandbox_proto::Response::ContainerList(list) => {
            if !list.iter().any(|c| c.name == name) {
                return Err(format!("container {name} not in list"));
            }
        }
        _ => return Err(format!("list returned unexpected: {resp:?}")),
    }

    // Exec (detached, on same connection)
    let resp = client
        .request(&sandbox_proto::Request::Exec {
            name: name.to_string(),
            command: vec!["echo".to_string(), "session-ok".to_string()],
            detach: true,
            user: None,
            env: Vec::new(),
            piped: false,
        })
        .map_err(|e| format!("exec failed: {e}"))?;
    if matches!(resp, sandbox_proto::Response::Error { .. }) {
        return Err(format!("exec returned error: {resp:?}"));
    }

    // Stop container (on same connection)
    let resp = client
        .request(&sandbox_proto::Request::Stop {
            name: name.to_string(),
            timeout_secs: 3,
        })
        .map_err(|e| format!("stop failed: {e}"))?;
    if matches!(resp, sandbox_proto::Response::Error { .. }) {
        return Err(format!("stop returned error: {resp:?}"));
    }

    // Destroy container (on same connection)
    let resp = client
        .request(&sandbox_proto::Request::Destroy {
            name: name.to_string(),
        })
        .map_err(|e| format!("destroy failed: {e}"))?;
    if matches!(resp, sandbox_proto::Response::Error { .. }) {
        return Err(format!("destroy returned error: {resp:?}"));
    }

    // Verify container is gone
    let resp = client
        .request(&sandbox_proto::Request::List)
        .map_err(|e| format!("final list failed: {e}"))?;
    match resp {
        sandbox_proto::Response::ContainerList(list) => {
            if list.iter().any(|c| c.name == name) {
                return Err(format!("container {name} still in list after destroy"));
            }
        }
        _ => return Err(format!("final list returned unexpected: {resp:?}")),
    }

    Ok(())
}

/// Test that single-shot mode still works (backward compat).
/// Each CLI command opens a new connection — no session needed.
pub fn test_session_single_shot_compat(ctx: &TestContext) -> Result<(), String> {
    let name = "session-compat";

    // Use CLI (each command = new connection, no session)
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

    if ctx.cli_fails(&["start", name]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("start failed".into());
    }

    std::thread::sleep(std::time::Duration::from_millis(500));

    let list = ctx.cli_ok(&["list"]);
    if !list.contains(name) {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("container not in list: {list}"));
    }

    let _ = ctx.cli(&["stop", "--timeout", "3", name]);
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}

/// Test that piped exec works within a session.
pub fn test_session_piped_exec(ctx: &TestContext) -> Result<(), String> {
    let name = "session-piped";

    // Create + start via CLI
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
    if ctx.cli_fails(&["start", name]) {
        let _ = ctx.cli(&["destroy", name]);
        return Err("start failed".into());
    }

    std::thread::sleep(std::time::Duration::from_millis(500));

    // Open session, do piped exec
    let mut client = ctx.client();
    client
        .enable_session()
        .map_err(|e| format!("enable_session failed: {e}"))?;

    let (resp, pipe_fds) = client
        .request_with_pipe_fds(&sandbox_proto::Request::Exec {
            name: name.to_string(),
            command: vec!["echo".to_string(), "piped-session".to_string()],
            detach: false,
            user: None,
            env: Vec::new(),
            piped: true,
        })
        .map_err(|e| format!("piped exec failed: {e}"))?;

    if matches!(resp, sandbox_proto::Response::Error { .. }) {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("piped exec error: {resp:?}"));
    }

    if let Some((stdout_fd, _stderr_fd)) = pipe_fds {
        use std::io::Read;
        let mut stdout_file = std::fs::File::from(stdout_fd);
        let mut output = String::new();
        stdout_file
            .read_to_string(&mut output)
            .map_err(|e| format!("read stdout: {e}"))?;
        if !output.contains("piped-session") {
            let _ = ctx.cli(&["stop", name]);
            let _ = ctx.cli(&["destroy", name]);
            return Err(format!("expected 'piped-session', got: {output}"));
        }
    } else {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err("no pipe fds received".into());
    }

    // Read exit code
    let exit_resp = client
        .read_exit_code()
        .map_err(|e| format!("read exit code: {e}"))?;
    match exit_resp {
        sandbox_proto::Response::ExecExited { exit_code } => {
            if exit_code != 0 {
                let _ = ctx.cli(&["stop", name]);
                let _ = ctx.cli(&["destroy", name]);
                return Err(format!("expected exit code 0, got: {exit_code}"));
            }
        }
        _ => {}
    }

    // Can still send more requests on the same session
    let resp = client
        .request(&sandbox_proto::Request::List)
        .map_err(|e| format!("list after exec failed: {e}"))?;
    if matches!(resp, sandbox_proto::Response::Error { .. }) {
        let _ = ctx.cli(&["stop", name]);
        let _ = ctx.cli(&["destroy", name]);
        return Err(format!("list after exec error: {resp:?}"));
    }

    let _ = ctx.cli(&["stop", "--timeout", "3", name]);
    let _ = ctx.cli(&["destroy", name]);
    Ok(())
}
