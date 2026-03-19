mod client;
mod daemon;

use clap::{Parser, Subcommand};
use sandbox::protocol::{
    self, BindMount, CgroupSpec, ContainerSpec, IdMapping, NetworkMode, Request, Response,
    SeccompMode, CapabilitySpec,
};

#[derive(Parser)]
#[command(name = "sandbox", about = "A minimal Linux container manager")]
struct Cli {
    /// Path to the daemon socket
    #[arg(long, global = true)]
    socket: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage the sandbox daemon
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Create and start a container (ephemeral — auto-removed on exit)
    Run {
        /// Container name
        #[arg(long)]
        name: String,

        /// Image to use as the root filesystem
        #[arg(long)]
        image: String,

        /// Storage pool (default: main)
        #[arg(long)]
        pool: Option<String>,

        /// Set container hostname
        #[arg(long)]
        hostname: Option<String>,

        /// Memory limit (e.g., 128M, 1G)
        #[arg(long)]
        memory: Option<String>,

        /// CPU limit as fraction (e.g., 0.5 = half a core)
        #[arg(long)]
        cpus: Option<f64>,

        /// Maximum number of processes
        #[arg(long)]
        pids_max: Option<u32>,

        /// Network mode: host, bridged, none
        #[arg(long, default_value = "host")]
        network: String,

        /// Bridge name for bridged networking
        #[arg(long, default_value = "sbr0")]
        bridge: Option<String>,

        /// Container IP address (for bridged mode)
        #[arg(long)]
        ip: Option<String>,

        /// Gateway IP (for bridged mode)
        #[arg(long)]
        gateway: Option<String>,

        /// Seccomp mode: default, disabled
        #[arg(long, default_value = "default")]
        seccomp: String,

        /// Capabilities to keep (can be specified multiple times)
        #[arg(long = "cap-add")]
        cap_add: Vec<String>,

        /// Bind mount (SRC:DST or SRC:DST:ro)
        #[arg(long = "bind")]
        bind: Vec<String>,

        /// Use built-in mini-init as PID 1
        #[arg(long)]
        init: bool,

        /// Run detached (no interactive PTY)
        #[arg(long, short = 'd')]
        detach: bool,

        /// UID mapping (CONTAINER:HOST:COUNT)
        #[arg(long = "uid-map")]
        uid_map: Vec<String>,

        /// GID mapping (CONTAINER:HOST:COUNT)
        #[arg(long = "gid-map")]
        gid_map: Vec<String>,

        /// Command to run inside the container
        #[arg(last = true)]
        command: Vec<String>,
    },

    /// Create a container (persistent — needs explicit destroy)
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        image: String,
        #[arg(long)]
        pool: Option<String>,
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long)]
        memory: Option<String>,
        #[arg(long)]
        cpus: Option<f64>,
        #[arg(long)]
        pids_max: Option<u32>,
        #[arg(long, default_value = "host")]
        network: String,
        #[arg(long, default_value = "sbr0")]
        bridge: Option<String>,
        #[arg(long)]
        ip: Option<String>,
        #[arg(long)]
        gateway: Option<String>,
        #[arg(long, default_value = "default")]
        seccomp: String,
        #[arg(long = "cap-add")]
        cap_add: Vec<String>,
        #[arg(long = "bind")]
        bind: Vec<String>,
        #[arg(long)]
        init: bool,

        /// Start the container immediately after creation
        #[arg(long)]
        start: bool,

        /// Run detached (no interactive PTY). Only used with --start.
        #[arg(long, short = 'd')]
        detach: bool,

        #[arg(long = "uid-map")]
        uid_map: Vec<String>,
        #[arg(long = "gid-map")]
        gid_map: Vec<String>,
        #[arg(last = true)]
        command: Vec<String>,
    },

    /// Start a previously created container
    Start {
        /// Container name
        name: String,

        /// Override the command
        #[arg(last = true)]
        command: Vec<String>,
    },

    /// Stop a running container
    Stop {
        /// Container name
        name: String,

        /// Timeout in seconds before SIGKILL
        #[arg(long, default_value = "10")]
        timeout: u32,
    },

    /// Destroy a container
    Destroy {
        /// Container name
        name: String,
    },

    /// List all containers
    #[command(alias = "ls")]
    List,

    /// Execute a command in a running container
    Exec {
        /// Container name
        name: String,

        /// Run detached (no PTY, no interactive I/O)
        #[arg(short, long)]
        detach: bool,

        /// Command to execute
        #[arg(last = true)]
        command: Vec<String>,
    },

    /// Manage images
    Image {
        #[command(subcommand)]
        action: ImageAction,
    },

    /// Manage storage pools
    Pool {
        #[command(subcommand)]
        action: PoolAction,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the daemon
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(long)]
        foreground: bool,

        /// Data directory (default: /var/lib/sandbox)
        #[arg(long)]
        data_dir: Option<String>,
    },
    /// Stop the daemon
    Stop,
}

#[derive(Subcommand)]
enum ImageAction {
    /// Import an image from a directory or tar.gz
    Import {
        /// Image name
        name: String,

        /// Path to directory or .tar.gz file
        source: String,

        /// Storage pool (default: main)
        #[arg(long)]
        pool: Option<String>,
    },
    /// List images
    #[command(alias = "ls")]
    List {
        /// Storage pool (default: main)
        #[arg(long)]
        pool: Option<String>,
    },
    /// Remove an image
    Rm {
        /// Image name
        name: String,

        /// Storage pool (default: main)
        #[arg(long)]
        pool: Option<String>,
    },
    /// Pull an image from an OCI registry (e.g., Docker Hub)
    Pull {
        /// Image reference (e.g., alpine:latest, docker.io/library/ubuntu:22.04)
        reference: String,

        /// Local image name override (defaults to repo basename)
        #[arg(long)]
        name: Option<String>,

        /// Storage pool (default: main)
        #[arg(long)]
        pool: Option<String>,
    },
}

#[derive(Subcommand)]
enum PoolAction {
    /// List storage pools
    #[command(alias = "ls")]
    List,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sandbox=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon { action } => match action {
            DaemonAction::Start { foreground, data_dir } => {
                daemon::run_daemon(cli.socket.as_deref(), foreground, data_dir.as_deref())?;
            }
            DaemonAction::Stop => {
                let mut client = client::Client::connect(cli.socket.as_deref())?;
                let resp = client.request(&Request::Shutdown)?;
                print_response(&resp);
            }
        },

        Commands::Run {
            name, image, pool, hostname, memory, cpus, pids_max, network, bridge,
            ip, gateway, seccomp, cap_add, bind, init, detach, uid_map, gid_map, command,
        } => {
            let mut spec = build_spec(
                name, image, pool, hostname, memory, cpus, pids_max, network, bridge,
                ip, gateway, seccomp, cap_add, bind, init, uid_map, gid_map, command,
            )?;
            spec.detach = detach;
            let mut client = client::Client::connect(cli.socket.as_deref())?;

            if detach {
                let resp = client.request(&Request::Run(spec))?;
                print_response(&resp);
            } else {
                let (resp, exit_code) = client.request_interactive(&Request::Run(spec))?;
                if let Response::Error { .. } = &resp {
                    print_response(&resp);
                }
                if let Some(code) = exit_code {
                    std::process::exit(code);
                }
            }
        }

        Commands::Create {
            name, image, pool, hostname, memory, cpus, pids_max, network, bridge,
            ip, gateway, seccomp, cap_add, bind, init, start, detach, uid_map, gid_map, command,
        } => {
            let spec = build_spec(
                name, image, pool, hostname, memory, cpus, pids_max, network, bridge,
                ip, gateway, seccomp, cap_add, bind, init, uid_map, gid_map, command,
            )?;
            let mut client = client::Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::Create(spec))?;

            if start {
                if let Response::Created { ref name } = resp {
                    let start_req = Request::Start {
                        name: name.clone(),
                        command: None,
                    };
                    if detach {
                        let resp = client.request(&start_req)?;
                        print_response(&resp);
                    } else {
                        let (resp, exit_code) = client.request_interactive(&start_req)?;
                        if let Response::Error { .. } = &resp {
                            print_response(&resp);
                        }
                        if let Some(code) = exit_code {
                            std::process::exit(code);
                        }
                    }
                } else {
                    print_response(&resp);
                }
            } else {
                print_response(&resp);
            }
        }

        Commands::Start { name, command } => {
            let cmd = if command.is_empty() { None } else { Some(command) };
            let mut client = client::Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::Start { name, command: cmd })?;
            print_response(&resp);
        }

        Commands::Stop { name, timeout } => {
            let mut client = client::Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::Stop { name, timeout_secs: timeout })?;
            print_response(&resp);
        }

        Commands::Destroy { name } => {
            let mut client = client::Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::Destroy { name })?;
            print_response(&resp);
        }

        Commands::List => {
            let mut client = client::Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::List)?;
            match &resp {
                Response::ContainerList(list) => {
                    if list.is_empty() {
                        println!("No containers");
                    } else {
                        println!("{:<20} {:<15} {:<10}", "NAME", "STATE", "PID");
                        for info in list {
                            let state_str = match &info.state {
                                protocol::ContainerState::Created => "Created".to_string(),
                                protocol::ContainerState::Running => "Running".to_string(),
                                protocol::ContainerState::Stopped { exit_code } => {
                                    format!("Stopped({exit_code})")
                                }
                            };
                            let pid_str = info.pid
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| "-".to_string());
                            println!("{:<20} {:<15} {:<10}", info.name, state_str, pid_str);
                        }
                    }
                }
                _ => print_response(&resp),
            }
        }

        Commands::Exec { name, command, detach } => {
            let mut client = client::Client::connect(cli.socket.as_deref())?;
            if detach {
                let resp = client.request(&Request::Exec { name, command, detach: true })?;
                print_response(&resp);
            } else {
                let (resp, exit_code) = client.request_interactive(&Request::Exec { name, command, detach: false })?;
                if let Response::Error { .. } = &resp {
                    print_response(&resp);
                }
                if let Some(code) = exit_code {
                    std::process::exit(code);
                }
            }
        }

        Commands::Image { action } => {
            let mut client = client::Client::connect(cli.socket.as_deref())?;
            match action {
                ImageAction::Import { name, source, pool } => {
                    let resp = client.request(&Request::ImageImport { name, source, pool })?;
                    print_response(&resp);
                }
                ImageAction::List { pool } => {
                    let resp = client.request(&Request::ImageList { pool })?;
                    match &resp {
                        Response::ImageList(images) => {
                            if images.is_empty() {
                                println!("No images");
                            } else {
                                println!("{:<20} {:<10} {:<15}", "NAME", "POOL", "SIZE");
                                for img in images {
                                    let size = format_size(img.size_bytes);
                                    println!("{:<20} {:<10} {:<15}", img.name, img.pool, size);
                                }
                            }
                        }
                        _ => print_response(&resp),
                    }
                }
                ImageAction::Rm { name, pool } => {
                    let resp = client.request(&Request::ImageRemove { name, pool })?;
                    print_response(&resp);
                }
                ImageAction::Pull { reference, name, pool } => {
                    let resp = client.request(&Request::ImagePull { reference, name, pool })?;
                    print_response(&resp);
                }
            }
        }

        Commands::Pool { action } => {
            let mut client = client::Client::connect(cli.socket.as_deref())?;
            match action {
                PoolAction::List => {
                    let resp = client.request(&Request::PoolList)?;
                    match &resp {
                        Response::PoolList(pools) => {
                            if pools.is_empty() {
                                println!("No pools");
                            } else {
                                println!("{:<15} {:<12} {:<10}", "NAME", "FILESYSTEM", "SNAPSHOTS");
                                for p in pools {
                                    let snap = if p.supports_snapshots { "yes" } else { "no" };
                                    println!("{:<15} {:<12} {:<10}", p.name, p.fs_type, snap);
                                }
                            }
                        }
                        _ => print_response(&resp),
                    }
                }
            }
        }
    }

    Ok(())
}

fn print_response(resp: &Response) {
    match resp {
        Response::Ok => println!("OK"),
        Response::Created { name } => println!("Created container: {name}"),
        Response::Started { name, pid } => println!("Started container: {name} (PID {pid})"),
        Response::Stopped { name, exit_code } => {
            println!("Stopped container: {name} (exit code {exit_code})")
        }
        Response::Destroyed { name } => println!("Destroyed container: {name}"),
        Response::ExecStarted { pid } => println!("Exec started (PID {pid})"),
        Response::ImageImported { name } => println!("Imported image: {name}"),
        Response::ImageRemoved { name } => println!("Removed image: {name}"),
        Response::ContainerList(_) => {}
        Response::ImageList(_) => {}
        Response::PoolList(_) => {}
        Response::ContainerExited { exit_code } => {
            println!("Container exited with code {exit_code}")
        }
        Response::ExecExited { exit_code } => println!("Exec exited with code {exit_code}"),
        Response::ImagePulled { name } => println!("Pulled image: {name}"),
        Response::Error { message } => eprintln!("Error: {message}"),
    }
}

fn build_spec(
    name: String,
    image: String,
    pool: Option<String>,
    hostname: Option<String>,
    memory: Option<String>,
    cpus: Option<f64>,
    pids_max: Option<u32>,
    network: String,
    bridge: Option<String>,
    ip: Option<String>,
    gateway: Option<String>,
    seccomp: String,
    cap_add: Vec<String>,
    bind: Vec<String>,
    init: bool,
    uid_map: Vec<String>,
    gid_map: Vec<String>,
    command: Vec<String>,
) -> anyhow::Result<ContainerSpec> {
    let memory_max = memory.map(parse_size).transpose()?;

    let cpu_max = cpus.map(|c| {
        let quota = (c * 100_000.0) as u64;
        (quota, 100_000u64)
    });

    let network_mode = match network.as_str() {
        "host" => NetworkMode::Host,
        "none" => NetworkMode::None,
        "bridged" => {
            let addr: std::net::Ipv4Addr = ip
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--ip required for bridged networking"))?
                .parse()?;
            let gw: std::net::Ipv4Addr = gateway
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--gateway required for bridged networking"))?
                .parse()?;
            NetworkMode::Bridged {
                bridge: bridge.unwrap_or_else(|| "sbr0".to_string()),
                address: addr,
                gateway: gw,
                prefix_len: 24,
            }
        }
        other => anyhow::bail!("unknown network mode: {other}"),
    };

    let seccomp_mode = match seccomp.as_str() {
        "default" => SeccompMode::Default,
        "disabled" => SeccompMode::Disabled,
        other => anyhow::bail!("unknown seccomp mode: {other}"),
    };

    let bind_mounts: Vec<BindMount> = bind
        .iter()
        .map(|b| {
            let parts: Vec<&str> = b.split(':').collect();
            match parts.len() {
                2 => Ok(BindMount {
                    source: parts[0].to_string(),
                    target: parts[1].to_string(),
                    readonly: false,
                }),
                3 => Ok(BindMount {
                    source: parts[0].to_string(),
                    target: parts[1].to_string(),
                    readonly: parts[2] == "ro",
                }),
                _ => anyhow::bail!("invalid bind mount format: {b} (expected SRC:DST or SRC:DST:ro)"),
            }
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let uid_mappings = if uid_map.is_empty() {
        Vec::new()
    } else {
        uid_map.iter().map(|m| parse_id_mapping(m)).collect::<anyhow::Result<Vec<_>>>()?
    };

    let gid_mappings = if gid_map.is_empty() {
        Vec::new()
    } else {
        gid_map.iter().map(|m| parse_id_mapping(m)).collect::<anyhow::Result<Vec<_>>>()?
    };

    let cmd = if command.is_empty() {
        vec!["/bin/sh".to_string()]
    } else {
        command
    };

    Ok(ContainerSpec {
        name,
        image,
        pool,
        entrypoint: Vec::new(),
        command: cmd,
        env: Vec::new(),
        working_dir: "/".to_string(),
        hostname,
        uid_mappings,
        gid_mappings,
        cgroup: CgroupSpec {
            memory_max,
            memory_high: None,
            cpu_max,
            cpu_weight: None,
            pids_max,
        },
        network: network_mode,
        seccomp: seccomp_mode,
        capabilities: if cap_add.is_empty() {
            CapabilitySpec::default()
        } else {
            let mut caps = CapabilitySpec::default();
            for cap in cap_add {
                if !caps.keep.contains(&cap) {
                    caps.keep.push(cap);
                }
            }
            caps
        },
        bind_mounts,
        use_init: init,
        detach: false,
    })
}

fn parse_size(s: String) -> anyhow::Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty size");
    }

    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('G').or_else(|| s.strip_suffix('g')) {
        (n, 1024 * 1024 * 1024u64)
    } else if let Some(n) = s.strip_suffix('M').or_else(|| s.strip_suffix('m')) {
        (n, 1024 * 1024u64)
    } else if let Some(n) = s.strip_suffix('K').or_else(|| s.strip_suffix('k')) {
        (n, 1024u64)
    } else {
        (s, 1u64)
    };

    let num: u64 = num_str.parse()?;
    Ok(num * multiplier)
}

fn parse_id_mapping(s: &str) -> anyhow::Result<IdMapping> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        anyhow::bail!("invalid ID mapping: {s} (expected CONTAINER_ID:HOST_ID:COUNT)");
    }
    Ok(IdMapping {
        container_id: parts[0].parse()?,
        host_id: parts[1].parse()?,
        count: parts[2].parse()?,
    })
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else {
        format!("{bytes}B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("128M".to_string()).unwrap(), 128 * 1024 * 1024);
        assert_eq!(parse_size("1G".to_string()).unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("512K".to_string()).unwrap(), 512 * 1024);
        assert_eq!(parse_size("1024".to_string()).unwrap(), 1024);
    }

    #[test]
    fn test_parse_id_mapping() {
        let m = parse_id_mapping("0:1000:1").unwrap();
        assert_eq!(m.container_id, 0);
        assert_eq!(m.host_id, 1000);
        assert_eq!(m.count, 1);
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0G");
        assert_eq!(format_size(128 * 1024 * 1024), "128.0M");
        assert_eq!(format_size(512 * 1024), "512.0K");
        assert_eq!(format_size(100), "100B");
    }
}
