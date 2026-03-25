//! Protocol serialization/deserialization tests.
//!
//! These tests verify the postcard wire format is correct.

#[allow(dead_code)]
mod common;

use sandbox_proto::*;

#[test]
fn test_roundtrip_request_create() {
    let spec = ContainerSpec {
        name: "test".to_string(),
        image: "alpine".to_string(),
        pool: None,
        entrypoint: Vec::new(),
        command: vec!["/bin/sh".to_string()],
        env: vec!["PATH=/usr/bin".to_string()],
        working_dir: "/app".to_string(),
        hostname: Some("myhost".to_string()),
        uid_mappings: vec![IdMapping {
            container_id: 0,
            host_id: 1000,
            count: 1,
        }],
        gid_mappings: vec![IdMapping {
            container_id: 0,
            host_id: 1000,
            count: 1,
        }],
        cgroup: CgroupSpec {
            memory_max: Some(128 * 1024 * 1024),
            memory_high: None,
            cpu_max: Some((50000, 100000)),
            cpu_weight: None,
            pids_max: Some(64),
        },
        network: NetworkMode::Host,
        seccomp: SeccompMode::Default,
        capabilities: CapabilitySpec {
            keep: vec!["CAP_NET_BIND_SERVICE".to_string()],
        },
        bind_mounts: vec![BindMount {
            source: "/tmp".to_string(),
            target: "/mnt".to_string(),
            readonly: true,
        }],
        volumes: Vec::new(),
        publish: Vec::new(),
        use_init: false,
        detach: false,
        user: Some("1000:1000".to_string()),
        restart_policy: RestartPolicy::UnlessStopped,
        no_new_privs: true,
    };

    let req = Request::Create(spec);
    let encoded = encode_message(&req).unwrap();
    let (decoded, rest): (Request, &[u8]) = decode_message(&encoded).unwrap();
    assert!(rest.is_empty());

    match decoded {
        Request::Create(s) => {
            assert_eq!(s.name, "test");
            assert_eq!(s.image, "alpine");
            assert_eq!(s.hostname, Some("myhost".to_string()));
            assert_eq!(s.cgroup.memory_max, Some(128 * 1024 * 1024));
            assert_eq!(s.cgroup.pids_max, Some(64));
            assert!(matches!(s.network, NetworkMode::Host));
            assert_eq!(s.bind_mounts.len(), 1);
            assert!(s.bind_mounts[0].readonly);
        }
        _ => panic!("expected Create request"),
    }
}

#[test]
fn test_roundtrip_response_container_list() {
    let resp = Response::ContainerList(vec![
        ContainerInfo {
            name: "foo".to_string(),
            state: ContainerState::Running,
            pid: Some(1234),
        },
        ContainerInfo {
            name: "bar".to_string(),
            state: ContainerState::Stopped { exit_code: 0 },
            pid: None,
        },
    ]);

    let encoded = encode_message(&resp).unwrap();
    let (decoded, _): (Response, &[u8]) = decode_message(&encoded).unwrap();

    match decoded {
        Response::ContainerList(list) => {
            assert_eq!(list.len(), 2);
            assert_eq!(list[0].name, "foo");
            assert_eq!(list[0].pid, Some(1234));
            assert!(matches!(list[0].state, ContainerState::Running));
            assert_eq!(list[1].name, "bar");
            assert!(matches!(
                list[1].state,
                ContainerState::Stopped { exit_code: 0 }
            ));
        }
        _ => panic!("expected ContainerList response"),
    }
}

#[test]
fn test_roundtrip_all_request_variants() {
    let requests: Vec<Request> = vec![
        Request::Create(ContainerSpec::default()),
        Request::Run(ContainerSpec::default()),
        Request::Start {
            name: "foo".to_string(),
            command: Some(vec!["/bin/sh".to_string()]),
        },
        Request::Stop {
            name: "foo".to_string(),
            timeout_secs: 10,
        },
        Request::Destroy {
            name: "foo".to_string(),
        },
        Request::List,
        Request::Inspect {
            name: "foo".to_string(),
        },
        Request::Exec {
            name: "foo".to_string(),
            command: vec!["/bin/ls".to_string(), "-la".to_string()],
            detach: false,
            user: Some(sandbox_proto::ExecUser {
                uid: 1000,
                gid: 1000,
            }),
            env: vec!["FOO=bar".to_string()],
            piped: false,
        },
        Request::UpdateContainer {
            name: "foo".to_string(),
            update: ContainerUpdate {
                restart_policy: Some(RestartPolicy::Always),
                memory_max: Some(1024),
                ..Default::default()
            },
        },
        Request::SnapshotContainer {
            name: "foo".to_string(),
            snapshot_name: Some("v1".to_string()),
            exclude_volumes: false,
        },
        Request::RestoreContainer {
            name: "foo".to_string(),
            snapshot_name: "v1".to_string(),
        },
        Request::ListContainerSnapshots {
            name: "foo".to_string(),
            show_size: false,
        },
        Request::DeleteContainerSnapshot {
            name: "foo".to_string(),
            snapshot_name: "v1".to_string(),
        },
        Request::StackSnapshot {
            stack_name: "mystack".to_string(),
            snapshot_name: None,
            exclude_volumes: true,
        },
        Request::StackRestore {
            stack_name: "mystack".to_string(),
            snapshot_name: "v1".to_string(),
        },
        Request::StackSnapshots {
            stack_name: "mystack".to_string(),
            show_size: false,
        },
        Request::Shutdown,
        Request::EnableSession,
    ];

    for req in &requests {
        let encoded = encode_message(req).unwrap();
        let (_decoded, rest): (Request, &[u8]) = decode_message(&encoded).unwrap();
        assert!(rest.is_empty(), "leftover bytes after decode");
    }
}

#[test]
fn test_roundtrip_all_response_variants() {
    let responses: Vec<Response> = vec![
        Response::Ok,
        Response::Created {
            name: "test".to_string(),
        },
        Response::Started {
            name: "test".to_string(),
            pid: 42,
        },
        Response::Stopped {
            name: "test".to_string(),
            exit_code: 0,
        },
        Response::Destroyed {
            name: "test".to_string(),
        },
        Response::ExecStarted { pid: 123 },
        Response::ExecStartedPiped { pid: 456 },
        Response::Error {
            message: "something went wrong".to_string(),
        },
        Response::ContainerList(vec![]),
        Response::ContainerUpdated {
            name: "test".to_string(),
        },
        Response::SessionEnabled,
        Response::ContainerSnapshotted {
            name: "foo".to_string(),
            snapshot_name: "v1".to_string(),
        },
        Response::ContainerRestored {
            name: "foo".to_string(),
            snapshot_name: "v1".to_string(),
        },
        Response::ContainerSnapshotList {
            snapshots: vec![SnapshotInfo {
                name: "v1".to_string(),
                timestamp: "123".to_string(),
                container: "foo".to_string(),
                includes_volumes: true,
                size_bytes: Some(1024),
            }],
        },
        Response::ContainerSnapshotDeleted {
            name: "foo".to_string(),
            snapshot_name: "v1".to_string(),
        },
        Response::StackSnapshotted {
            stack_name: "mystack".to_string(),
            snapshot_name: "v1".to_string(),
        },
        Response::StackRestored {
            stack_name: "mystack".to_string(),
            snapshot_name: "v1".to_string(),
        },
        Response::StackSnapshotList {
            snapshots: vec![StackSnapshotInfo {
                name: "v1".to_string(),
                timestamp: "123".to_string(),
                containers: vec!["a".to_string()],
                includes_volumes: true,
                size_bytes: Some(2048),
            }],
        },
        Response::ContainerInspect(Box::new(ContainerDetail {
            name: "test".to_string(),
            image: "alpine".to_string(),
            pool: "main".to_string(),
            state: ContainerState::Running,
            pid: Some(42),
            ephemeral: false,
            user: Some("1000".to_string()),
            command: vec!["/bin/sh".to_string()],
            entrypoint: Vec::new(),
            env: vec!["FOO=bar".to_string()],
            working_dir: "/".to_string(),
            hostname: None,
            use_init: false,
            network: NetworkMode::Host,
            bind_mounts: Vec::new(),
            volumes: Vec::new(),
            publish: Vec::new(),
            cgroup: CgroupSpec::default(),
            seccomp: SeccompMode::Default,
            restart_policy: RestartPolicy::Always,
            no_new_privs: true,
            rootfs_path: Some("/pool/fs/test".to_string()),
            cgroup_path: "/sys/fs/cgroup/sandbox/test".to_string(),
        })),
    ];

    for resp in &responses {
        let encoded = encode_message(resp).unwrap();
        let (_decoded, rest): (Response, &[u8]) = decode_message(&encoded).unwrap();
        assert!(rest.is_empty());
    }
}

#[test]
fn test_read_write_message() {
    let req = Request::List;

    let mut buf = Vec::new();
    write_message(&mut buf, &req).unwrap();

    let mut cursor = std::io::Cursor::new(buf);
    let decoded: Request = read_message(&mut cursor).unwrap();

    assert!(matches!(decoded, Request::List));
}

#[test]
fn test_network_mode_bridged_roundtrip() {
    let spec = ContainerSpec {
        network: NetworkMode::Bridged {
            bridge: "sbr0".to_string(),
            address: Some("10.0.0.2".parse().unwrap()),
            gateway: Some("10.0.0.1".parse().unwrap()),
            prefix_len: 24,
        },
        ..Default::default()
    };

    let req = Request::Create(spec);
    let encoded = encode_message(&req).unwrap();
    let (decoded, _): (Request, &[u8]) = decode_message(&encoded).unwrap();

    match decoded {
        Request::Create(s) => match s.network {
            NetworkMode::Bridged {
                bridge,
                address,
                gateway,
                prefix_len,
            } => {
                assert_eq!(bridge, "sbr0");
                assert_eq!(
                    address,
                    Some("10.0.0.2".parse::<std::net::Ipv4Addr>().unwrap())
                );
                assert_eq!(
                    gateway,
                    Some("10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap())
                );
                assert_eq!(prefix_len, 24);
            }
            _ => panic!("expected Bridged network mode"),
        },
        _ => panic!("expected Create request"),
    }
}

#[test]
fn test_message_too_short() {
    let buf = [0u8; 2]; // Too short for length prefix
    let result: std::result::Result<(Request, &[u8]), _> = decode_message(&buf);
    assert!(result.is_err());
}

#[test]
fn test_message_truncated_payload() {
    // Write a length prefix claiming 100 bytes, but only provide 5
    let mut buf = Vec::new();
    buf.extend_from_slice(&100u32.to_le_bytes());
    buf.extend_from_slice(&[0u8; 5]);

    let result: std::result::Result<(Request, &[u8]), _> = decode_message(&buf);
    assert!(result.is_err());
}

/// Verify that a ContainerSpec JSON missing newer fields (volumes, publish, etc.)
/// deserializes successfully with defaults — backward compatibility for persisted state.
#[test]
fn test_container_spec_backward_compat() {
    // Minimal JSON that an old daemon version might have persisted
    // (missing: volumes, publish, entrypoint, env, working_dir)
    let old_json = r#"{
        "name": "test-container",
        "image": "alpine",
        "command": ["/bin/sh"],
        "hostname": null,
        "uid_mappings": [],
        "gid_mappings": [],
        "cgroup": {},
        "network": "Host",
        "seccomp": "Default",
        "capabilities": {"keep": []},
        "bind_mounts": [],
        "use_init": false,
        "detach": false
    }"#;

    let spec: ContainerSpec = serde_json::from_str(old_json)
        .expect("old ContainerSpec JSON should deserialize with defaults");

    assert_eq!(spec.name, "test-container");
    assert_eq!(spec.image, "alpine");
    // New fields should have their defaults
    assert!(spec.volumes.is_empty());
    assert!(spec.publish.is_empty());
    assert!(spec.entrypoint.is_empty());
    assert!(spec.env.is_empty());
    assert_eq!(spec.working_dir, "/");
    // restart_policy should default to No for old specs
    assert_eq!(spec.restart_policy, RestartPolicy::No);
}

/// Verify that a ContainerSpec JSON with no "command" field deserializes to empty vec.
#[test]
fn test_container_spec_no_command_defaults_empty() {
    let json = r#"{
        "name": "idle-test",
        "image": "alpine",
        "hostname": null,
        "uid_mappings": [],
        "gid_mappings": [],
        "cgroup": {},
        "network": "Host",
        "seccomp": "Default",
        "capabilities": {"keep": []},
        "bind_mounts": [],
        "use_init": true,
        "detach": false
    }"#;

    let spec: ContainerSpec =
        serde_json::from_str(json).expect("ContainerSpec without command should deserialize");

    assert_eq!(spec.name, "idle-test");
    assert!(spec.command.is_empty());
    assert!(spec.use_init);
}

/// Verify that RestartPolicy serializes/deserializes with kebab-case.
#[test]
fn test_restart_policy_serde() {
    let policies = vec![
        (RestartPolicy::No, "\"no\""),
        (RestartPolicy::Always, "\"always\""),
        (RestartPolicy::OnFailure, "\"on-failure\""),
        (RestartPolicy::UnlessStopped, "\"unless-stopped\""),
    ];

    for (policy, expected_json) in &policies {
        let json = serde_json::to_string(policy).unwrap();
        assert_eq!(&json, *expected_json, "serialize {policy}");
        let deserialized: RestartPolicy = serde_json::from_str(expected_json).unwrap();
        assert_eq!(&deserialized, policy, "deserialize {expected_json}");
    }
}

/// Verify that RestartPolicy::should_restart works correctly.
#[test]
fn test_restart_policy_should_restart() {
    // No: never restart
    assert!(!RestartPolicy::No.should_restart(0, false));
    assert!(!RestartPolicy::No.should_restart(1, false));

    // Always: always restart
    assert!(RestartPolicy::Always.should_restart(0, false));
    assert!(RestartPolicy::Always.should_restart(1, false));
    assert!(RestartPolicy::Always.should_restart(0, true));

    // OnFailure: only on non-zero exit
    assert!(!RestartPolicy::OnFailure.should_restart(0, false));
    assert!(RestartPolicy::OnFailure.should_restart(1, false));
    assert!(RestartPolicy::OnFailure.should_restart(137, false));

    // UnlessStopped: restart unless manually stopped
    assert!(RestartPolicy::UnlessStopped.should_restart(0, false));
    assert!(RestartPolicy::UnlessStopped.should_restart(1, false));
    assert!(!RestartPolicy::UnlessStopped.should_restart(0, true));
    assert!(!RestartPolicy::UnlessStopped.should_restart(1, true));
}

/// Verify that UpdateContainer request roundtrips correctly.
#[test]
fn test_roundtrip_update_container() {
    let req = Request::UpdateContainer {
        name: "mycontainer".to_string(),
        update: ContainerUpdate {
            restart_policy: Some(RestartPolicy::Always),
            memory_max: Some(256 * 1024 * 1024),
            cpu_max: Some((150_000, 100_000)),
            pids_max: Some(128),
            ..Default::default()
        },
    };

    let encoded = encode_message(&req).unwrap();
    let (decoded, rest): (Request, &[u8]) = decode_message(&encoded).unwrap();
    assert!(rest.is_empty());

    match decoded {
        Request::UpdateContainer { name, update } => {
            assert_eq!(name, "mycontainer");
            assert_eq!(update.restart_policy, Some(RestartPolicy::Always));
            assert_eq!(update.memory_max, Some(256 * 1024 * 1024));
            assert_eq!(update.cpu_max, Some((150_000, 100_000)));
            assert_eq!(update.pids_max, Some(128));
        }
        _ => panic!("expected UpdateContainer request"),
    }
}

/// Verify that ContainerUpdate with partial fields roundtrips correctly.
#[test]
fn test_roundtrip_update_container_partial() {
    let req = Request::UpdateContainer {
        name: "partial".to_string(),
        update: ContainerUpdate {
            restart_policy: Some(RestartPolicy::OnFailure),
            ..Default::default()
        },
    };

    let encoded = encode_message(&req).unwrap();
    let (decoded, rest): (Request, &[u8]) = decode_message(&encoded).unwrap();
    assert!(rest.is_empty());

    match decoded {
        Request::UpdateContainer { name, update } => {
            assert_eq!(name, "partial");
            assert_eq!(update.restart_policy, Some(RestartPolicy::OnFailure));
            assert!(update.memory_max.is_none());
            assert!(update.cpu_max.is_none());
            assert!(update.pids_max.is_none());
        }
        _ => panic!("expected UpdateContainer request"),
    }
}

/// Verify that ContainerUpdate with all new fields roundtrips correctly.
#[test]
fn test_roundtrip_update_container_full() {
    let req = Request::UpdateContainer {
        name: "full".to_string(),
        update: ContainerUpdate {
            restart_policy: Some(RestartPolicy::Always),
            memory_max: Some(1024),
            cpu_max: Some((50_000, 100_000)),
            pids_max: Some(64),
            env_set: vec!["FOO=bar".to_string(), "BAZ=qux".to_string()],
            env_remove: vec!["OLD_VAR".to_string()],
            env_clear: true,
            command: Some(vec!["/bin/zsh".to_string()]),
            entrypoint: Some(vec!["/entrypoint.sh".to_string()]),
            user: Some(Some("1000:1000".to_string())),
            hostname: Some(Some("myhost".to_string())),
            working_dir: Some("/app".to_string()),
            use_init: Some(true),
            seccomp: Some(SeccompMode::Disabled),
            cap_add: vec!["NET_RAW".to_string()],
            cap_drop: vec!["SYS_ADMIN".to_string()],
            no_new_privs: Some(false),
        },
    };

    let encoded = encode_message(&req).unwrap();
    let (decoded, rest): (Request, &[u8]) = decode_message(&encoded).unwrap();
    assert!(rest.is_empty());

    match decoded {
        Request::UpdateContainer { name, update } => {
            assert_eq!(name, "full");
            assert_eq!(update.env_set, vec!["FOO=bar", "BAZ=qux"]);
            assert_eq!(update.env_remove, vec!["OLD_VAR"]);
            assert!(update.env_clear);
            assert_eq!(update.command, Some(vec!["/bin/zsh".to_string()]));
            assert_eq!(update.entrypoint, Some(vec!["/entrypoint.sh".to_string()]));
            assert_eq!(update.user, Some(Some("1000:1000".to_string())));
            assert_eq!(update.hostname, Some(Some("myhost".to_string())));
            assert_eq!(update.working_dir, Some("/app".to_string()));
            assert_eq!(update.use_init, Some(true));
            assert_eq!(update.cap_add, vec!["NET_RAW"]);
            assert_eq!(update.cap_drop, vec!["SYS_ADMIN"]);
        }
        _ => panic!("expected UpdateContainer request"),
    }
}

/// Verify that an empty ContainerUpdate roundtrips with defaults.
#[test]
fn test_roundtrip_update_container_empty_defaults() {
    let req = Request::UpdateContainer {
        name: "empty".to_string(),
        update: ContainerUpdate::default(),
    };

    let encoded = encode_message(&req).unwrap();
    let (decoded, rest): (Request, &[u8]) = decode_message(&encoded).unwrap();
    assert!(rest.is_empty());

    match decoded {
        Request::UpdateContainer { name, update } => {
            assert_eq!(name, "empty");
            assert!(update.is_empty());
        }
        _ => panic!("expected UpdateContainer request"),
    }
}

/// Verify that ContainerUpdated response roundtrips correctly.
#[test]
fn test_roundtrip_container_updated_response() {
    let resp = Response::ContainerUpdated {
        name: "test".to_string(),
    };

    let encoded = encode_message(&resp).unwrap();
    let (decoded, rest): (Response, &[u8]) = decode_message(&encoded).unwrap();
    assert!(rest.is_empty());

    match decoded {
        Response::ContainerUpdated { name } => assert_eq!(name, "test"),
        _ => panic!("expected ContainerUpdated response"),
    }
}

/// Verify that an Exec request with env roundtrips correctly.
#[test]
fn test_exec_with_env_roundtrip() {
    let req = Request::Exec {
        name: "test".to_string(),
        command: vec!["/bin/env".to_string()],
        detach: false,
        user: None,
        env: vec!["FOO=bar".to_string(), "BAZ=qux".to_string()],
        piped: false,
    };

    let encoded = encode_message(&req).unwrap();
    let (decoded, rest): (Request, &[u8]) = decode_message(&encoded).unwrap();
    assert!(rest.is_empty());

    match decoded {
        Request::Exec {
            name, command, env, ..
        } => {
            assert_eq!(name, "test");
            assert_eq!(command, vec!["/bin/env"]);
            assert_eq!(env, vec!["FOO=bar", "BAZ=qux"]);
        }
        _ => panic!("expected Exec request"),
    }
}

/// Verify that a piped Exec request roundtrips correctly.
#[test]
fn test_exec_piped_roundtrip() {
    let req = Request::Exec {
        name: "piped-test".to_string(),
        command: vec!["make".to_string(), "build".to_string()],
        detach: false,
        user: None,
        env: Vec::new(),
        piped: true,
    };

    let encoded = encode_message(&req).unwrap();
    let (decoded, rest): (Request, &[u8]) = decode_message(&encoded).unwrap();
    assert!(rest.is_empty());

    match decoded {
        Request::Exec {
            name,
            piped,
            detach,
            ..
        } => {
            assert_eq!(name, "piped-test");
            assert!(piped);
            assert!(!detach);
        }
        _ => panic!("expected Exec request"),
    }
}

/// Verify that ExecStartedPiped response roundtrips correctly.
#[test]
fn test_exec_started_piped_roundtrip() {
    let resp = Response::ExecStartedPiped { pid: 42 };

    let encoded = encode_message(&resp).unwrap();
    let (decoded, rest): (Response, &[u8]) = decode_message(&encoded).unwrap();
    assert!(rest.is_empty());

    match decoded {
        Response::ExecStartedPiped { pid } => assert_eq!(pid, 42),
        _ => panic!("expected ExecStartedPiped response"),
    }
}

/// Verify that EnableSession request roundtrips correctly.
#[test]
fn test_roundtrip_enable_session() {
    let req = Request::EnableSession;
    let encoded = encode_message(&req).unwrap();
    let (decoded, rest): (Request, &[u8]) = decode_message(&encoded).unwrap();
    assert!(rest.is_empty());
    assert!(matches!(decoded, Request::EnableSession));
}

/// Verify that SessionEnabled response roundtrips correctly.
#[test]
fn test_roundtrip_session_enabled() {
    let resp = Response::SessionEnabled;
    let encoded = encode_message(&resp).unwrap();
    let (decoded, rest): (Response, &[u8]) = decode_message(&encoded).unwrap();
    assert!(rest.is_empty());
    assert!(matches!(decoded, Response::SessionEnabled));
}
