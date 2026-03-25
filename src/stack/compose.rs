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
        restart: raw.restart.unwrap_or_default(),
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
        allow_new_privs: false, // Docker Compose compat: default secure
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
    /// Default restart policy for all services in this stack.
    /// Per-service `restart:` overrides this.
    #[serde(default)]
    restart: Option<String>,
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

// --- Compatibility check ---

/// Known fields at the top level of a stack YAML.
const STACK_FIELDS: &[&str] = &[
    "name",
    "version",
    "services",
    "containers",
    "networks",
    "network",
    "volumes",
    "restart",
];

/// Known fields for a service/container definition.
const CONTAINER_FIELDS: &[&str] = &[
    "image",
    "command",
    "entrypoint",
    "env",
    "environment",
    "working_dir",
    "hostname",
    "user",
    "volumes",
    "bind",
    "publish",
    "ports",
    "networks",
    "depends_on",
    "init",
    "restart",
    "cpus",
    "memory",
    "pids",
];

/// Known fields for a network definition.
const NETWORK_FIELDS: &[&str] = &["subnet"];

/// Result of checking a stack YAML file for compatibility.
pub struct CheckResult {
    pub name: String,
    pub services: Vec<String>,
    pub volumes: Vec<String>,
    pub supported: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl CheckResult {
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }
}

/// Check a compose YAML string for compatibility without starting anything.
///
/// Reports supported features, warnings for partially supported features,
/// and errors for unknown/unsupported fields.
pub fn check(yaml: &str) -> CheckResult {
    let mut result = CheckResult {
        name: String::new(),
        services: Vec::new(),
        volumes: Vec::new(),
        supported: Vec::new(),
        warnings: Vec::new(),
        errors: Vec::new(),
    };

    // Parse as generic YAML value first
    let value: serde_yaml::Value = match serde_yaml::from_str(yaml) {
        Ok(v) => v,
        Err(e) => {
            result.errors.push(format!("YAML syntax error: {e}"));
            return result;
        }
    };

    let mapping = match value.as_mapping() {
        Some(m) => m,
        None => {
            result
                .errors
                .push("stack file must be a YAML mapping".into());
            return result;
        }
    };

    // Extract name
    if let Some(name) = mapping.get("name").and_then(|v| v.as_str()) {
        result.name = name.to_string();
    } else {
        result.errors.push("missing required field: 'name'".into());
    }

    // Check top-level fields
    for (key, _) in mapping {
        if let Some(key_str) = key.as_str() {
            if !STACK_FIELDS.contains(&key_str) {
                result
                    .errors
                    .push(format!("unknown top-level field: '{key_str}'"));
            }
        }
    }

    // Check version field
    if mapping.contains_key("version") {
        result
            .warnings
            .push("'version' field is deprecated and ignored".into());
    }

    // Check services/containers
    let services = mapping
        .get("services")
        .or_else(|| mapping.get("containers"));

    if let Some(svc_value) = services {
        if let Some(svc_map) = svc_value.as_mapping() {
            for (svc_key, svc_val) in svc_map {
                let svc_name = svc_key.as_str().unwrap_or("?");
                result.services.push(svc_name.to_string());

                if let Some(svc_fields) = svc_val.as_mapping() {
                    let mut svc_supported = Vec::new();

                    for (field_key, _) in svc_fields {
                        if let Some(field_str) = field_key.as_str() {
                            if CONTAINER_FIELDS.contains(&field_str) {
                                svc_supported.push(field_str.to_string());
                            } else {
                                result.errors.push(format!(
                                    "service '{svc_name}': unknown field '{field_str}'"
                                ));
                            }
                        }
                    }

                    // Check required field
                    if !svc_fields.contains_key("image") {
                        result.errors.push(format!(
                            "service '{svc_name}': missing required field 'image'"
                        ));
                    }

                    for s in svc_supported {
                        if !result.supported.contains(&s) {
                            result.supported.push(s);
                        }
                    }
                }
            }
        }
    } else {
        result
            .errors
            .push("missing 'services' or 'containers' section".into());
    }

    // Check top-level volumes
    if let Some(vol_value) = mapping.get("volumes") {
        match vol_value {
            serde_yaml::Value::Mapping(m) => {
                for (k, _) in m {
                    if let Some(name) = k.as_str() {
                        result.volumes.push(name.to_string());
                    }
                }
            }
            serde_yaml::Value::Sequence(s) => {
                for v in s {
                    if let Some(name) = v.as_str() {
                        result.volumes.push(name.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    // Check top-level networks
    if let Some(net_value) = mapping.get("networks") {
        if let Some(net_map) = net_value.as_mapping() {
            for (net_key, net_val) in net_map {
                if let Some(net_fields) = net_val.as_mapping() {
                    for (field_key, _) in net_fields {
                        if let Some(field_str) = field_key.as_str() {
                            if !NETWORK_FIELDS.contains(&field_str) {
                                let net_name = net_key.as_str().unwrap_or("?");
                                result.errors.push(format!(
                                    "network '{net_name}': unknown field '{field_str}'"
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // Check for multi-network containers
    if let Some(svc_value) = services {
        if let Some(svc_map) = svc_value.as_mapping() {
            for (svc_key, svc_val) in svc_map {
                let svc_name = svc_key.as_str().unwrap_or("?");
                if let Some(svc_fields) = svc_val.as_mapping() {
                    if let Some(nets) = svc_fields.get("networks") {
                        if let Some(net_seq) = nets.as_sequence() {
                            if net_seq.len() > 1 {
                                result.warnings.push(format!(
                                    "service '{svc_name}': multiple networks not yet supported, will use first"
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    result
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

    #[test]
    fn test_check_valid() {
        let yaml = r#"
name: myapp
services:
  app:
    image: alpine
    command: ["echo", "hello"]
"#;
        let result = check(yaml);
        assert!(!result.has_errors());
        assert!(!result.has_warnings());
        assert_eq!(result.services, vec!["app"]);
    }

    #[test]
    fn test_check_unknown_fields() {
        let yaml = r#"
name: myapp
services:
  app:
    image: alpine
    healthcheck:
      test: ["CMD", "true"]
    deploy:
      resources:
        limits:
          cpus: "2.0"
"#;
        let result = check(yaml);
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| e.contains("healthcheck")));
        assert!(result.errors.iter().any(|e| e.contains("deploy")));
    }

    #[test]
    fn test_check_warnings() {
        let yaml = r#"
name: myapp
version: "3.8"
services:
  app:
    image: alpine
    restart: unless-stopped
"#;
        let result = check(yaml);
        assert!(!result.has_errors());
        assert!(result.has_warnings());
        assert!(result.warnings.iter().any(|w| w.contains("version")));
        // restart is now fully enforced, no warning expected
    }

    #[test]
    fn test_check_missing_image() {
        let yaml = r#"
name: myapp
services:
  app:
    command: ["echo", "hello"]
"#;
        let result = check(yaml);
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| e.contains("image")));
    }
}
