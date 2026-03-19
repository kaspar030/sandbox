//! Protocol serialization/deserialization tests.
//!
//! These tests verify the postcard wire format is correct.

mod common;

use sandbox::protocol::*;

#[test]
fn test_roundtrip_request_create() {
    let spec = ContainerSpec {
        name: "test".to_string(),
        rootfs: "/rootfs".to_string(),
        command: vec!["/bin/sh".to_string()],
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
        use_init: false,
    };

    let req = Request::Create(spec);
    let encoded = encode_message(&req).unwrap();
    let (decoded, rest): (Request, &[u8]) = decode_message(&encoded).unwrap();
    assert!(rest.is_empty());

    match decoded {
        Request::Create(s) => {
            assert_eq!(s.name, "test");
            assert_eq!(s.rootfs, "/rootfs");
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
        Request::Exec {
            name: "foo".to_string(),
            command: vec!["/bin/ls".to_string(), "-la".to_string()],
        },
        Request::Shutdown,
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
        Response::Error {
            message: "something went wrong".to_string(),
        },
        Response::ContainerList(vec![]),
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
            address: "10.0.0.2".parse().unwrap(),
            gateway: "10.0.0.1".parse().unwrap(),
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
                assert_eq!(address, "10.0.0.2".parse::<std::net::Ipv4Addr>().unwrap());
                assert_eq!(gateway, "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap());
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
    let result: Result<(Request, &[u8]), _> = decode_message(&buf);
    assert!(result.is_err());
}

#[test]
fn test_message_truncated_payload() {
    // Write a length prefix claiming 100 bytes, but only provide 5
    let mut buf = Vec::new();
    buf.extend_from_slice(&100u32.to_le_bytes());
    buf.extend_from_slice(&[0u8; 5]);

    let result: Result<(Request, &[u8]), _> = decode_message(&buf);
    assert!(result.is_err());
}
