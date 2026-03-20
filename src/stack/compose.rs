//! Docker Compose-compatible YAML parser for stack definitions.
//!
//! Accepts the Docker Compose format with aliases:
//! - `services:` alias for `containers:`
//! - `ports:` alias for `publish:`
//! - `environment:` alias for `env:` (map or list form)
//! - `depends_on:` as list or map (with conditions)
//! - Top-level `volumes:` as map or list
//! - Top-level `networks:` as map
//! - `version:` field accepted and warned
//!
//! Strict parsing: unknown fields are rejected with `#[serde(deny_unknown_fields)]`.

use crate::error::{Error, Result};
use sandbox_proto::{StackContainer, StackDefinition, StackNetwork};
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use std::collections::HashMap;
use std::fmt;

/// Parse a compose YAML string into a `StackDefinition`.
pub fn parse(yaml: &str) -> Result<StackDefinition> {
    let raw: StackYaml =
        serde_yaml::from_str(yaml).map_err(|e| Error::Other(format!("YAML parse error: {e}")))?;

    if raw.version.is_some() {
        tracing::warn!("'version' field in stack YAML is deprecated and ignored");
    }

    super::validate_stack_name(&raw.name)?;

    // Resolve network config
    let network = resolve_network(&raw)?;

    // Resolve volumes (top-level, for creating)
    let volumes = raw.volumes;

    // Convert containers HashMap to Vec, respecting depends_on ordering
    let mut containers: Vec<StackContainer> = raw
        .containers
        .into_iter()
        .map(|(name, c)| convert_container(name, c))
        .collect();

    // Sort by depends_on (topological) or by name as fallback
    let has_deps = containers.iter().any(|c| !c.depends_on.is_empty());
    if has_deps {
        containers = super::topological_sort(containers)?;
    } else {
        containers.sort_by(|a, b| a.name.cmp(&b.name));
    }

    if containers.is_empty() {
        return Err(Error::Other(
            "stack must define at least one container/service".to_string(),
        ));
    }

    Ok(StackDefinition {
        name: raw.name,
        network,
        volumes,
        containers,
    })
}

fn resolve_network(raw: &StackYaml) -> Result<StackNetwork> {
    // Top-level `networks:` map takes precedence
    if let Some(ref nets) = raw.networks {
        if nets.len() > 1 {
            tracing::warn!(
                "multiple networks defined; using first network (multi-network not yet supported)"
            );
        }
        if let Some((name, config)) = nets.iter().next() {
            return Ok(StackNetwork {
                subnet: config
                    .as_ref()
                    .and_then(|c| c.subnet.clone())
                    .unwrap_or_default(),
                bridge: name.clone(),
            });
        }
    }

    // Legacy single `network:` block
    if let Some(ref n) = raw.network {
        return Ok(StackNetwork {
            subnet: n.subnet.clone().unwrap_or_default(),
            bridge: n.bridge.clone().unwrap_or_default(),
        });
    }

    Ok(StackNetwork::default())
}

fn convert_container(name: String, c: ContainerYaml) -> StackContainer {
    // Split container volumes into named volumes and bind mounts
    let mut named_volumes = Vec::new();
    let mut bind_mounts = c.bind.clone();

    for v in &c.volumes {
        let source = v.split(':').next().unwrap_or(v);
        if source.starts_with('/') || source.starts_with('.') {
            // Bind mount (path-style source)
            bind_mounts.push(v.clone());
        } else {
            // Named volume
            named_volumes.push(v.clone());
        }
    }

    StackContainer {
        name,
        image: c.image,
        command: c.command.unwrap_or_default(),
        entrypoint: c.entrypoint.unwrap_or_default(),
        env: c.env,
        working_dir: c.working_dir.unwrap_or_default(),
        hostname: c.hostname.unwrap_or_default(),
        user: c.user.unwrap_or_default(),
        volumes: named_volumes,
        bind: bind_mounts,
        publish: c.publish,
        networks: c.networks,
        depends_on: c.depends_on,
        init: c.init,
        restart: c.restart.unwrap_or_default(),
        cpus: c.cpus.unwrap_or_default(),
        memory: c.memory.unwrap_or_default(),
        pids: c.pids,
    }
}

// --- YAML structs with strict parsing ---

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StackYaml {
    name: String,
    /// Deprecated, accepted and warned.
    #[serde(default)]
    version: Option<String>,
    /// Containers (also accepts `services:` alias).
    #[serde(default, alias = "services")]
    containers: HashMap<String, ContainerYaml>,
    /// Top-level networks map (compose-style).
    #[serde(default)]
    networks: Option<HashMap<String, Option<NetworkYaml>>>,
    /// Legacy single network block.
    #[serde(default)]
    network: Option<LegacyNetworkYaml>,
    /// Top-level volumes (map or list).
    #[serde(default, deserialize_with = "deserialize_volumes")]
    volumes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkYaml {
    #[serde(default)]
    subnet: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyNetworkYaml {
    #[serde(default)]
    subnet: Option<String>,
    #[serde(default)]
    bridge: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContainerYaml {
    image: String,
    #[serde(default)]
    command: Option<Vec<String>>,
    #[serde(default)]
    entrypoint: Option<Vec<String>>,
    #[serde(default, alias = "environment", deserialize_with = "deserialize_env")]
    env: Vec<String>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    volumes: Vec<String>,
    #[serde(default)]
    bind: Vec<String>,
    #[serde(default, alias = "ports")]
    publish: Vec<String>,
    #[serde(default)]
    networks: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_depends_on")]
    depends_on: Vec<String>,
    #[serde(default)]
    init: bool,
    #[serde(default)]
    restart: Option<String>,
    #[serde(default)]
    cpus: Option<String>,
    #[serde(default)]
    memory: Option<String>,
    #[serde(default)]
    pids: Option<u32>,
}

// --- Custom deserializers ---

/// Deserialize `env`/`environment` from either a list or a map.
///
/// List form: `["FOO=bar", "BAZ=qux"]`
/// Map form: `{ FOO: bar, BAZ: qux }`
fn deserialize_env<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct EnvVisitor;

    impl<'de> Visitor<'de> for EnvVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a list of KEY=VALUE strings or a map of KEY: VALUE")
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Vec<String>, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut result = Vec::new();
            while let Some(val) = seq.next_element::<String>()? {
                result.push(val);
            }
            Ok(result)
        }

        fn visit_map<M>(self, mut map: M) -> std::result::Result<Vec<String>, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut result = Vec::new();
            while let Some((key, value)) = map.next_entry::<String, serde_yaml::Value>()? {
                let val_str = match value {
                    serde_yaml::Value::String(s) => s,
                    serde_yaml::Value::Number(n) => n.to_string(),
                    serde_yaml::Value::Bool(b) => b.to_string(),
                    serde_yaml::Value::Null => String::new(),
                    _ => return Err(de::Error::custom(format!("invalid env value for {key}"))),
                };
                result.push(format!("{key}={val_str}"));
            }
            Ok(result)
        }

        fn visit_none<E>(self) -> std::result::Result<Vec<String>, E>
        where
            E: de::Error,
        {
            Ok(Vec::new())
        }

        fn visit_unit<E>(self) -> std::result::Result<Vec<String>, E>
        where
            E: de::Error,
        {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(EnvVisitor)
}

/// Deserialize `depends_on` from either a list or a map.
///
/// List form: `["db", "cache"]`
/// Map form: `{ db: { condition: service_started }, cache: { condition: service_healthy } }`
fn deserialize_depends_on<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct DependsOnVisitor;

    impl<'de> Visitor<'de> for DependsOnVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a list of service names or a map of service: condition")
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Vec<String>, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut result = Vec::new();
            while let Some(val) = seq.next_element::<String>()? {
                result.push(val);
            }
            Ok(result)
        }

        fn visit_map<M>(self, mut map: M) -> std::result::Result<Vec<String>, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut result = Vec::new();
            while let Some((key, _value)) = map.next_entry::<String, serde_yaml::Value>()? {
                result.push(key);
            }
            Ok(result)
        }

        fn visit_none<E>(self) -> std::result::Result<Vec<String>, E>
        where
            E: de::Error,
        {
            Ok(Vec::new())
        }

        fn visit_unit<E>(self) -> std::result::Result<Vec<String>, E>
        where
            E: de::Error,
        {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(DependsOnVisitor)
}

/// Deserialize top-level `volumes` from either a list or a map.
///
/// List form: `["pgdata", "redis-data"]`
/// Map form: `{ pgdata: null, redis-data: { driver: local } }`
fn deserialize_volumes<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct VolumesVisitor;

    impl<'de> Visitor<'de> for VolumesVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a list of volume names or a map of volume: config")
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Vec<String>, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut result = Vec::new();
            while let Some(val) = seq.next_element::<String>()? {
                result.push(val);
            }
            Ok(result)
        }

        fn visit_map<M>(self, mut map: M) -> std::result::Result<Vec<String>, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut result = Vec::new();
            while let Some((key, _value)) = map.next_entry::<String, serde_yaml::Value>()? {
                result.push(key);
            }
            Ok(result)
        }

        fn visit_none<E>(self) -> std::result::Result<Vec<String>, E>
        where
            E: de::Error,
        {
            Ok(Vec::new())
        }

        fn visit_unit<E>(self) -> std::result::Result<Vec<String>, E>
        where
            E: de::Error,
        {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(VolumesVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compose_format() {
        let yaml = r#"
name: myapp
services:
  db:
    image: postgres
    init: true
    environment:
      POSTGRES_PASSWORD: secret
      POSTGRES_DB: mydb
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"
  web:
    image: nginx
    depends_on:
      - db
    environment:
      - DATABASE_URL=postgres://db:5432/mydb
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    ports:
      - "8080:80"
volumes:
  pgdata:
"#;
        let stack = parse(yaml).unwrap();
        assert_eq!(stack.name, "myapp");
        assert_eq!(stack.volumes, vec!["pgdata"]);
        assert_eq!(stack.containers.len(), 2);

        // db should come first (depends_on ordering: web depends on db)
        assert_eq!(stack.containers[0].name, "db");
        assert_eq!(stack.containers[1].name, "web");

        // Check env map was converted to list
        assert!(
            stack.containers[0]
                .env
                .contains(&"POSTGRES_PASSWORD=secret".to_string())
        );

        // Check bind mount detection
        assert!(
            stack.containers[1]
                .bind
                .contains(&"./nginx.conf:/etc/nginx/nginx.conf:ro".to_string())
        );
    }

    #[test]
    fn test_legacy_format() {
        let yaml = r#"
name: myapp
volumes:
  - pgdata
containers:
  db:
    image: postgres
    init: true
    env:
      - POSTGRES_PASSWORD=secret
    publish:
      - "5432:5432"
"#;
        let stack = parse(yaml).unwrap();
        assert_eq!(stack.name, "myapp");
        assert_eq!(stack.volumes, vec!["pgdata"]);
        assert_eq!(stack.containers[0].name, "db");
    }

    #[test]
    fn test_strict_parsing_rejects_unknown() {
        let yaml = r#"
name: myapp
unknown_field: true
containers:
  app:
    image: alpine
"#;
        let result = parse(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown"));
    }

    #[test]
    fn test_version_field_accepted() {
        let yaml = r#"
name: myapp
version: "3.8"
services:
  app:
    image: alpine
"#;
        let stack = parse(yaml).unwrap();
        assert_eq!(stack.name, "myapp");
    }

    #[test]
    fn test_depends_on_map_form() {
        let yaml = r#"
name: myapp
services:
  db:
    image: postgres
  web:
    image: nginx
    depends_on:
      db:
        condition: service_started
"#;
        let stack = parse(yaml).unwrap();
        // db first (web depends on db)
        assert_eq!(stack.containers[0].name, "db");
        assert_eq!(stack.containers[1].name, "web");
    }

    #[test]
    fn test_networks_map() {
        let yaml = r#"
name: myapp
networks:
  frontend:
  backend:
    subnet: 10.5.0.0/24
services:
  app:
    image: alpine
"#;
        let stack = parse(yaml).unwrap();
        // Should use first network
        assert!(!stack.network.bridge.is_empty() || !stack.network.subnet.is_empty());
    }

    #[test]
    fn test_resource_limits() {
        let yaml = r#"
name: myapp
services:
  app:
    image: alpine
    cpus: "2.0"
    memory: "512M"
    pids: 100
"#;
        let stack = parse(yaml).unwrap();
        assert_eq!(stack.containers[0].cpus, "2.0");
        assert_eq!(stack.containers[0].memory, "512M");
        assert_eq!(stack.containers[0].pids, Some(100));
    }
}
