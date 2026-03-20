//! Stack definition parsing and validation.
//!
//! A stack is a declarative grouping of containers, networks, and volumes
//! defined in a YAML file. This module parses the YAML and produces a
//! `StackDefinition` that the daemon can orchestrate.

use crate::error::{Error, Result};
use sandbox_proto::{StackContainer, StackDefinition, StackNetwork};
use serde::Deserialize;
use std::path::Path;

/// YAML format for a stack file. This mirrors `StackDefinition` but uses
/// a HashMap for containers (keyed by service name) which is more natural
/// in YAML.
#[derive(Debug, Deserialize)]
struct StackYaml {
    name: String,
    #[serde(default)]
    network: Option<StackNetworkYaml>,
    #[serde(default)]
    volumes: Vec<String>,
    containers: std::collections::HashMap<String, ContainerYaml>,
}

#[derive(Debug, Deserialize)]
struct StackNetworkYaml {
    #[serde(default)]
    subnet: Option<String>,
    #[serde(default)]
    bridge: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ContainerYaml {
    image: String,
    #[serde(default)]
    command: Option<Vec<String>>,
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    volumes: Vec<String>,
    #[serde(default)]
    bind: Vec<String>,
    #[serde(default)]
    publish: Vec<String>,
    #[serde(default)]
    init: bool,
}

/// Parse a stack YAML file into a `StackDefinition`.
pub fn parse_stack_file(path: &Path) -> Result<StackDefinition> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| Error::Other(format!("failed to read {}: {e}", path.display())))?;
    parse_stack_yaml(&contents)
}

/// Parse a stack YAML string into a `StackDefinition`.
pub fn parse_stack_yaml(yaml: &str) -> Result<StackDefinition> {
    let raw: StackYaml =
        serde_yaml::from_str(yaml).map_err(|e| Error::Other(format!("YAML parse error: {e}")))?;

    validate_stack_name(&raw.name)?;

    let network = match raw.network {
        Some(n) => StackNetwork {
            subnet: n.subnet.unwrap_or_default(),
            bridge: n.bridge.unwrap_or_default(),
        },
        None => StackNetwork::default(),
    };

    // Convert HashMap containers to Vec, sorted by name for deterministic order
    let mut containers: Vec<StackContainer> = raw
        .containers
        .into_iter()
        .map(|(name, c)| StackContainer {
            name,
            image: c.image,
            command: c.command.unwrap_or_default(),
            env: c.env,
            volumes: c.volumes,
            bind: c.bind,
            publish: c.publish,
            init: c.init,
        })
        .collect();
    containers.sort_by(|a, b| a.name.cmp(&b.name));

    if containers.is_empty() {
        return Err(Error::Other(
            "stack must define at least one container".to_string(),
        ));
    }

    Ok(StackDefinition {
        name: raw.name,
        network,
        volumes: raw.volumes,
        containers,
    })
}

/// Parse a bind mount spec from a stack YAML: "source:target" or "source:target:ro"
pub fn parse_bind_spec(spec: &str) -> Result<(String, String, bool)> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    match parts.len() {
        2 => Ok((parts[0].to_string(), parts[1].to_string(), false)),
        3 => Ok((parts[0].to_string(), parts[1].to_string(), parts[2] == "ro")),
        _ => Err(Error::Other(format!("invalid bind spec: {spec}"))),
    }
}

/// Parse a port mapping spec from a stack YAML: "hostPort:containerPort[/proto]"
pub fn parse_port_spec(spec: &str) -> Result<sandbox_proto::PortMapping> {
    let (ports, proto) = if let Some((p, pr)) = spec.rsplit_once('/') {
        let protocol = match pr {
            "tcp" => sandbox_proto::PortProtocol::Tcp,
            "udp" => sandbox_proto::PortProtocol::Udp,
            other => return Err(Error::Other(format!("unknown protocol: {other}"))),
        };
        (p, protocol)
    } else {
        (spec, sandbox_proto::PortProtocol::Tcp)
    };

    let (host, container) = ports
        .split_once(':')
        .ok_or_else(|| Error::Other(format!("invalid port spec: {spec}")))?;

    Ok(sandbox_proto::PortMapping {
        host_port: host
            .parse()
            .map_err(|_| Error::Other(format!("invalid host port: {host}")))?,
        container_port: container
            .parse()
            .map_err(|_| Error::Other(format!("invalid container port: {container}")))?,
        protocol: proto,
    })
}

fn validate_stack_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::Other("stack name cannot be empty".to_string()));
    }
    if name.contains('/') || name.contains('\0') || name.contains(' ') {
        return Err(Error::Other(format!("invalid stack name: {name}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_stack() {
        let yaml = r#"
name: myapp
volumes:
  - pgdata
containers:
  db:
    image: postgres
    init: true
    volumes:
      - pgdata:/var/lib/postgresql/data
    env:
      - POSTGRES_PASSWORD=secret
  web:
    image: nginx
    publish:
      - "8080:80"
"#;
        let stack = parse_stack_yaml(yaml).unwrap();
        assert_eq!(stack.name, "myapp");
        assert_eq!(stack.volumes, vec!["pgdata"]);
        assert_eq!(stack.containers.len(), 2);
        // Sorted by name
        assert_eq!(stack.containers[0].name, "db");
        assert_eq!(stack.containers[1].name, "web");
        assert!(stack.containers[0].init);
        assert!(!stack.containers[1].init);
    }

    #[test]
    fn test_parse_minimal_stack() {
        let yaml = r#"
name: minimal
containers:
  app:
    image: alpine
"#;
        let stack = parse_stack_yaml(yaml).unwrap();
        assert_eq!(stack.name, "minimal");
        assert_eq!(stack.containers.len(), 1);
    }

    #[test]
    fn test_parse_empty_containers() {
        let yaml = r#"
name: empty
containers: {}
"#;
        let result = parse_stack_yaml(yaml);
        assert!(result.is_err());
    }
}
