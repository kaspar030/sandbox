//! Stack definition parsing and validation.
//!
//! A stack is a declarative grouping of containers, networks, and volumes.
//! This module dispatches to format-specific parsers based on file extension.
//!
//! Supported formats:
//! - Docker Compose-compatible YAML (`.yaml`, `.yml`) — see `compose.rs`

pub mod compose;

use crate::error::{Error, Result};
use sandbox_proto::StackContainer;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

/// Parse a stack file, dispatching to the appropriate parser by extension.
///
/// Defaults to Docker Compose YAML format if the extension is unknown.
pub fn parse_stack_file(path: &Path) -> Result<sandbox_proto::StackDefinition> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| Error::Other(format!("failed to read {}: {e}", path.display())))?;

    match path.extension().and_then(|e| e.to_str()) {
        Some("yaml" | "yml") => compose::parse(&contents),
        // Future: Some("kdl") => kdl::parse(&contents),
        _ => compose::parse(&contents), // default to compose format
    }
}

/// Parse a bind mount spec: "source:target" or "source:target:ro"
pub fn parse_bind_spec(spec: &str) -> Result<(String, String, bool)> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    match parts.len() {
        2 => Ok((parts[0].to_string(), parts[1].to_string(), false)),
        3 => Ok((parts[0].to_string(), parts[1].to_string(), parts[2] == "ro")),
        _ => Err(Error::Other(format!("invalid bind spec: {spec}"))),
    }
}

/// Parse a port mapping spec: "hostPort:containerPort[/proto]"
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

/// Validate a stack name.
pub fn validate_stack_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::Other("stack name cannot be empty".to_string()));
    }
    if name.contains('/') || name.contains('\0') || name.contains(' ') {
        return Err(Error::Other(format!("invalid stack name: {name}")));
    }
    Ok(())
}

/// Topological sort of containers based on `depends_on`.
///
/// Returns containers in dependency order (dependencies first).
/// Errors on circular dependencies.
pub fn topological_sort(containers: Vec<StackContainer>) -> Result<Vec<StackContainer>> {
    let names: Vec<String> = containers.iter().map(|c| c.name.clone()).collect();
    let name_set: HashSet<&str> = names.iter().map(|s| s.as_str()).collect();

    // Validate that all depends_on targets exist
    for c in &containers {
        for dep in &c.depends_on {
            if !name_set.contains(dep.as_str()) {
                return Err(Error::Other(format!(
                    "service '{}' depends on '{}' which does not exist",
                    c.name, dep
                )));
            }
        }
    }

    // Build adjacency list and in-degree count (using owned strings)
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let mut dependents: HashMap<String, Vec<String>> = HashMap::new();

    for c in &containers {
        in_degree.entry(c.name.clone()).or_insert(0);
        for dep in &c.depends_on {
            *in_degree.entry(c.name.clone()).or_insert(0) += 1;
            dependents
                .entry(dep.clone())
                .or_default()
                .push(c.name.clone());
        }
    }

    // Kahn's algorithm
    let mut queue: VecDeque<String> = in_degree
        .iter()
        .filter(|(_, deg)| **deg == 0)
        .map(|(name, _)| name.clone())
        .collect();

    let mut order: Vec<String> = Vec::new();

    while let Some(name) = queue.pop_front() {
        order.push(name.clone());
        if let Some(deps) = dependents.get(&name) {
            for dep in deps {
                if let Some(deg) = in_degree.get_mut(dep) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(dep.clone());
                    }
                }
            }
        }
    }

    if order.len() != containers.len() {
        return Err(Error::Other(
            "circular dependency detected in depends_on".to_string(),
        ));
    }

    // Reorder containers according to topological order
    let container_map: HashMap<String, StackContainer> = containers
        .into_iter()
        .map(|c| (c.name.clone(), c))
        .collect();

    let result: Vec<StackContainer> = order
        .into_iter()
        .filter_map(|name| container_map.get(&name).cloned())
        .collect();

    Ok(result)
}

/// Parse a memory size string (e.g., "512M", "1G", "256k") to bytes.
pub fn parse_memory_size(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::Other("empty memory size".into()));
    }

    let (num_str, multiplier) = if let Some(n) = s.strip_suffix(['g', 'G']) {
        (n, 1024 * 1024 * 1024u64)
    } else if let Some(n) = s.strip_suffix(['m', 'M']) {
        (n, 1024 * 1024u64)
    } else if let Some(n) = s.strip_suffix(['k', 'K']) {
        (n, 1024u64)
    } else if let Some(n) = s.strip_suffix(['b', 'B']) {
        (n, 1u64)
    } else {
        (s, 1u64) // assume bytes
    };

    let num: f64 = num_str
        .parse()
        .map_err(|_| Error::Other(format!("invalid memory size: {s}")))?;
    Ok((num * multiplier as f64) as u64)
}

/// Parse a CPU limit string (e.g., "2.0") to (quota_us, period_us).
pub fn parse_cpu_limit(s: &str) -> Result<(u64, u64)> {
    let cpus: f64 = s
        .trim()
        .parse()
        .map_err(|_| Error::Other(format!("invalid CPU limit: {s}")))?;
    let period = 100_000u64; // 100ms
    let quota = (cpus * period as f64) as u64;
    Ok((quota, period))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topological_sort_simple() {
        let containers = vec![
            StackContainer {
                name: "web".into(),
                depends_on: vec!["db".into()],
                image: "nginx".into(),
                ..Default::default()
            },
            StackContainer {
                name: "db".into(),
                image: "postgres".into(),
                ..Default::default()
            },
        ];
        let sorted = topological_sort(containers).unwrap();
        assert_eq!(sorted[0].name, "db");
        assert_eq!(sorted[1].name, "web");
    }

    #[test]
    fn test_topological_sort_cycle() {
        let containers = vec![
            StackContainer {
                name: "a".into(),
                depends_on: vec!["b".into()],
                image: "x".into(),
                ..Default::default()
            },
            StackContainer {
                name: "b".into(),
                depends_on: vec!["a".into()],
                image: "x".into(),
                ..Default::default()
            },
        ];
        let result = topological_sort(containers);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("circular"));
    }

    #[test]
    fn test_parse_memory_size() {
        assert_eq!(parse_memory_size("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_memory_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_memory_size("256k").unwrap(), 256 * 1024);
        assert_eq!(parse_memory_size("1024").unwrap(), 1024);
    }

    #[test]
    fn test_parse_cpu_limit() {
        let (quota, period) = parse_cpu_limit("2.0").unwrap();
        assert_eq!(period, 100_000);
        assert_eq!(quota, 200_000);
    }
}
