mod cgroup;
mod client;
mod container;
mod daemon;
mod error;
mod namespace;
mod net;
mod protocol;
mod rootfs;
mod security;
mod sys;

use clap::{Parser, Subcommand};
use protocol::{
    BindMount, CgroupSpec, ContainerSpec, IdMapping, NetworkMode, Request, Response, SeccompMode,
    CapabilitySpec,
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

    /// Create and start a container
    Run {
        /// Container name
        #[arg(long)]
        name: String,

        /// Path to the root filesystem
        #[arg(long)]
        rootfs: String,

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

    /// Create a container without starting it
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        rootfs: String,
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

        /// Command to execute
        #[arg(last = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the daemon
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(long)]
        foreground: bool,
    },
    /// Stop the daemon
    Stop,
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
            DaemonAction::Start { foreground } => {
                daemon::run_daemon(cli.socket.as_deref(), foreground)?;
            }
            DaemonAction::Stop => {
                let mut client = client::Client::connect(cli.socket.as_deref())?;
                let resp = client.request(&Request::Shutdown)?;
                print_response(&resp);
            }
        },

        Commands::Run {
            name,
            rootfs,
            hostname,
            memory,
            cpus,
            pids_max,
            network,
            bridge,
            ip,
            gateway,
            seccomp,
            cap_add,
            bind,
            init,
            uid_map,
            gid_map,
            command,
        } => {
            let spec = build_spec(
                name, rootfs, hostname, memory, cpus, pids_max, network, bridge, ip, gateway,
                seccomp, cap_add, bind, init, uid_map, gid_map, command,
            )?;
            let mut client = client::Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::Run(spec))?;
            print_response(&resp);
        }

        Commands::Create {
            name,
            rootfs,
            hostname,
            memory,
            cpus,
            pids_max,
            network,
            bridge,
            ip,
            gateway,
            seccomp,
            cap_add,
            bind,
            init,
            uid_map,
            gid_map,
            command,
        } => {
            let spec = build_spec(
                name, rootfs, hostname, memory, cpus, pids_max, network, bridge, ip, gateway,
                seccomp, cap_add, bind, init, uid_map, gid_map, command,
            )?;
            let mut client = client::Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::Create(spec))?;
            print_response(&resp);
        }

        Commands::Start { name, command } => {
            let cmd = if command.is_empty() {
                None
            } else {
                Some(command)
            };
            let mut client = client::Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::Start { name, command: cmd })?;
            print_response(&resp);
        }

        Commands::Stop { name, timeout } => {
            let mut client = client::Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::Stop {
                name,
                timeout_secs: timeout,
            })?;
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
                            let pid_str = info
                                .pid
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| "-".to_string());
                            println!("{:<20} {:<15} {:<10}", info.name, state_str, pid_str);
                        }
                    }
                }
                _ => print_response(&resp),
            }
        }

        Commands::Exec { name, command } => {
            let mut client = client::Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::Exec { name, command })?;
            print_response(&resp);
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
        Response::ContainerList(_) => {} // handled above
        Response::Error { message } => eprintln!("Error: {message}"),
    }
}

fn build_spec(
    name: String,
    rootfs: String,
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
        vec![IdMapping {
            container_id: 0,
            host_id: unsafe { libc::getuid() },
            count: 1,
        }]
    } else {
        uid_map
            .iter()
            .map(|m| parse_id_mapping(m))
            .collect::<anyhow::Result<Vec<_>>>()?
    };

    let gid_mappings = if gid_map.is_empty() {
        vec![IdMapping {
            container_id: 0,
            host_id: unsafe { libc::getgid() },
            count: 1,
        }]
    } else {
        gid_map
            .iter()
            .map(|m| parse_id_mapping(m))
            .collect::<anyhow::Result<Vec<_>>>()?
    };

    let cmd = if command.is_empty() {
        vec!["/bin/sh".to_string()]
    } else {
        command
    };

    Ok(ContainerSpec {
        name,
        rootfs,
        command: cmd,
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
        capabilities: CapabilitySpec { keep: cap_add },
        bind_mounts,
        use_init: init,
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
        anyhow::bail!(
            "invalid ID mapping: {s} (expected CONTAINER_ID:HOST_ID:COUNT)"
        );
    }
    Ok(IdMapping {
        container_id: parts[0].parse()?,
        host_id: parts[1].parse()?,
        count: parts[2].parse()?,
    })
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
}
