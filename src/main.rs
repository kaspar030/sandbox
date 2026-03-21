mod completer;
mod daemon;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::ArgValueCandidates;
use sandbox_client::Client;
use sandbox_proto::{
    BindMount, CapabilitySpec, CgroupSpec, ContainerSpec, IdMapping, NetworkMode, Request,
    Response, SeccompMode,
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
        /// Container name (auto-generated if omitted)
        #[arg(long)]
        name: Option<String>,

        /// Image to use as the root filesystem
        #[arg(long, add = ArgValueCandidates::new(completer::image_completer))]
        image: String,

        /// Storage pool (default: main)
        #[arg(long, add = ArgValueCandidates::new(completer::pool_completer))]
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

        /// Publish container port (hostPort:containerPort[/tcp|udp])
        #[arg(long = "publish", short = 'p')]
        publish: Vec<String>,

        /// Mount a named volume (name:/path or name:/path:ro)
        #[arg(long = "volume", short = 'v')]
        volume: Vec<String>,

        /// Set environment variable (KEY=VALUE or KEY to pass from host)
        #[arg(short = 'e', long = "env")]
        env: Vec<String>,

        /// Run as user (UID, UID:GID, name, or name:group)
        #[arg(short = 'u', long)]
        user: Option<String>,

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
        /// Container name (auto-generated if omitted)
        #[arg(long)]
        name: Option<String>,
        #[arg(long, add = ArgValueCandidates::new(completer::image_completer))]
        image: String,
        #[arg(long, add = ArgValueCandidates::new(completer::pool_completer))]
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
        #[arg(long = "publish", short = 'p')]
        publish: Vec<String>,
        #[arg(long = "volume", short = 'v')]
        volume: Vec<String>,
        /// Set environment variable (KEY=VALUE or KEY to pass from host)
        #[arg(short = 'e', long = "env")]
        env: Vec<String>,
        /// Run as user (UID, UID:GID, name, or name:group)
        #[arg(short = 'u', long)]
        user: Option<String>,
        #[arg(long)]
        init: bool,

        /// Restart policy: no, always, on-failure, unless-stopped (default: unless-stopped)
        #[arg(long, default_value = "unless-stopped")]
        restart: String,

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

    /// Update a container's configuration (container must be stopped)
    Update {
        /// Container name
        #[arg(add = ArgValueCandidates::new(completer::container_completer))]
        name: String,

        /// Restart policy (no|always|on-failure|unless-stopped)
        #[arg(long)]
        restart: Option<String>,

        /// Memory limit (e.g., 512M, 1G)
        #[arg(long)]
        memory: Option<String>,

        /// CPU limit as fraction (e.g., 0.5 = half a core)
        #[arg(long)]
        cpus: Option<f64>,

        /// Maximum number of processes
        #[arg(long)]
        pids_max: Option<u32>,
    },

    /// Start a previously created container
    Start {
        /// Container name
        #[arg(add = ArgValueCandidates::new(completer::container_completer))]
        name: String,

        /// Override the command
        #[arg(last = true)]
        command: Vec<String>,
    },

    /// Stop a running container
    Stop {
        /// Container name
        #[arg(add = ArgValueCandidates::new(completer::container_completer))]
        name: String,

        /// Timeout in seconds before SIGKILL
        #[arg(long, default_value = "10")]
        timeout: u32,
    },

    /// Destroy a container
    Destroy {
        /// Container name
        #[arg(add = ArgValueCandidates::new(completer::container_completer))]
        name: String,
    },

    /// Snapshot a container's rootfs into a reusable image
    Snapshot {
        /// Container name
        #[arg(add = ArgValueCandidates::new(completer::container_completer))]
        name: String,

        /// Image name to create
        image_name: String,

        /// Force snapshot even if container is running on non-CoW filesystem
        #[arg(long)]
        force: bool,

        /// Overwrite existing image, adding a new layer on CoW filesystems
        #[arg(long)]
        update: bool,
    },

    /// List all containers
    #[command(alias = "ls")]
    List,

    /// Show detailed information about a container
    Inspect {
        /// Container name
        #[arg(add = ArgValueCandidates::new(completer::container_completer))]
        name: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Execute a command in a running container
    Exec {
        /// Container name
        #[arg(add = ArgValueCandidates::new(completer::container_completer))]
        name: String,

        /// Run as user UID or UID:GID (default: 0, container root)
        #[arg(short = 'u', long)]
        user: Option<String>,

        /// Set environment variable for this exec only (KEY=VALUE or KEY to pass from host)
        #[arg(short = 'e', long = "env")]
        env: Vec<String>,

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

    /// Manage bind mounts on containers
    Mount {
        #[command(subcommand)]
        action: MountAction,
    },

    /// Manage named networks
    Network {
        #[command(subcommand)]
        action: NetworkAction,
    },

    /// Manage container stacks (groups of containers, networks, volumes)
    Stack {
        #[command(subcommand)]
        action: StackAction,
    },

    /// Manage named volumes
    Volume {
        #[command(subcommand)]
        action: VolumeAction,
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
        #[arg(long, add = ArgValueCandidates::new(completer::pool_completer))]
        pool: Option<String>,
    },
    /// List images
    #[command(alias = "ls")]
    List {
        /// Storage pool (default: main)
        #[arg(long, add = ArgValueCandidates::new(completer::pool_completer))]
        pool: Option<String>,

        /// Show image sizes (slower — walks directory tree)
        #[arg(long)]
        size: bool,

        /// Show exclusive size on btrfs (requires btrfs quotas enabled)
        #[arg(long)]
        exclusive: bool,

        /// Show layer tree for each image
        #[arg(long)]
        layers: bool,
    },
    /// Show detailed image information
    Inspect {
        /// Image name
        #[arg(add = ArgValueCandidates::new(completer::image_completer))]
        name: String,

        /// Storage pool (default: main)
        #[arg(long, add = ArgValueCandidates::new(completer::pool_completer))]
        pool: Option<String>,
    },
    /// Remove an image
    Rm {
        /// Image name
        #[arg(add = ArgValueCandidates::new(completer::image_completer))]
        name: String,

        /// Storage pool (default: main)
        #[arg(long, add = ArgValueCandidates::new(completer::pool_completer))]
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
        #[arg(long, add = ArgValueCandidates::new(completer::pool_completer))]
        pool: Option<String>,
    },
}

#[derive(Subcommand)]
enum MountAction {
    /// Add a bind mount to a running container
    Add {
        /// Container name
        #[arg(add = ArgValueCandidates::new(completer::container_completer))]
        name: String,

        /// Mount spec: SOURCE[:TARGET][:ro|:rw] or SOURCE::ro
        spec: String,

        /// Mount read-only (overrides :ro/:rw in spec)
        #[arg(long = "read-only", alias = "ro")]
        read_only: bool,

        /// Mount read-write (overrides :ro/:rw in spec)
        #[arg(long = "read-write", alias = "rw")]
        read_write: bool,
    },
    /// Remove a bind mount from a running container
    #[command(alias = "rm")]
    Remove {
        /// Container name
        #[arg(add = ArgValueCandidates::new(completer::container_completer))]
        name: String,

        /// Target path inside the container
        target: String,
    },
    /// List bind mounts for a container
    #[command(alias = "ls")]
    List {
        /// Container name
        #[arg(add = ArgValueCandidates::new(completer::container_completer))]
        name: String,
    },
    /// Mount a block device inside a container (daemon-assisted)
    Block {
        /// Container name
        #[arg(add = ArgValueCandidates::new(completer::container_completer))]
        name: String,
        /// Device path inside the container (e.g., /dev/myblk)
        device: String,
        /// Mount target inside the container (e.g., /data)
        target: String,
        /// Filesystem type (e.g., ext4)
        #[arg(long = "type", short = 't')]
        fs_type: String,
        /// Mount options (e.g., "noatime,rw")
        #[arg(short = 'o', long = "options")]
        options: Option<String>,
    },
}

#[derive(Subcommand)]
enum NetworkAction {
    /// Create a named network
    Create {
        /// Network name
        name: String,
        /// Subnet (e.g., 10.1.0.0/24). Auto-allocated if omitted.
        #[arg(long)]
        subnet: Option<String>,
    },
    /// List networks
    #[command(alias = "ls")]
    List,
    /// Remove a network
    #[command(alias = "rm")]
    Remove {
        /// Network name
        #[arg(add = ArgValueCandidates::new(completer::network_completer))]
        name: String,
    },
}

#[derive(Subcommand)]
enum StackAction {
    /// Bring up a stack from a YAML definition file
    Up {
        /// Path to stack YAML file (default: sandbox-stack.yaml)
        #[arg(default_value = "sandbox-stack.yaml")]
        file: String,
    },
    /// Tear down a stack
    Down {
        /// Stack name
        #[arg(add = ArgValueCandidates::new(completer::stack_completer))]
        name: String,
    },
    /// List containers in a stack
    Ps {
        /// Stack name
        #[arg(add = ArgValueCandidates::new(completer::stack_completer))]
        name: String,
    },
    /// List all stacks
    #[command(alias = "ls")]
    List,
    /// Check a stack file for compatibility
    #[command(alias = "validate")]
    Check {
        /// Path to stack file (default: docker-compose.yml)
        #[arg(default_value = "docker-compose.yml")]
        file: String,
        /// Treat warnings as errors
        #[arg(long)]
        strict: bool,
        /// No output, only exit code
        #[arg(long, short)]
        quiet: bool,
    },
}

#[derive(Subcommand)]
enum VolumeAction {
    /// Create a named volume
    Create {
        /// Volume name
        name: String,
        /// Storage pool (default: main)
        #[arg(long, add = ArgValueCandidates::new(completer::pool_completer))]
        pool: Option<String>,
        /// Create a block device volume
        #[arg(long)]
        block: bool,
        /// Size of the block volume (e.g., "1G", "500M"). Default: 1G.
        #[arg(long)]
        size: Option<String>,
        /// Format the block volume with a filesystem (e.g., "ext4")
        #[arg(long)]
        format: Option<String>,
    },
    /// List volumes
    #[command(alias = "ls")]
    List {
        /// Storage pool (default: main)
        #[arg(long, add = ArgValueCandidates::new(completer::pool_completer))]
        pool: Option<String>,
    },
    /// Remove a volume
    #[command(alias = "rm")]
    Remove {
        /// Volume name
        #[arg(add = ArgValueCandidates::new(completer::volume_completer))]
        name: String,
        /// Storage pool (default: main)
        #[arg(long, add = ArgValueCandidates::new(completer::pool_completer))]
        pool: Option<String>,
    },
    /// Attach a volume to a running container
    Attach {
        /// Container name
        #[arg(add = ArgValueCandidates::new(completer::container_completer))]
        container: String,
        /// Volume spec: name:/path or name:/path:ro
        spec: String,
    },
    /// Detach a volume from a running container
    Detach {
        /// Container name
        #[arg(add = ArgValueCandidates::new(completer::container_completer))]
        container: String,
        /// Target path inside the container
        target: String,
    },
}

#[derive(Subcommand)]
enum PoolAction {
    /// List storage pools
    #[command(alias = "ls")]
    List,
}

fn main() -> anyhow::Result<()> {
    clap_complete::env::CompleteEnv::with_factory(Cli::command).complete();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sandbox=info".parse().unwrap()),
        )
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon { action } => match action {
            DaemonAction::Start {
                foreground,
                data_dir,
            } => {
                daemon::run_daemon(cli.socket.as_deref(), foreground, data_dir.as_deref())?;
            }
            DaemonAction::Stop => {
                let mut client = Client::connect(cli.socket.as_deref())?;
                let resp = client.request(&Request::Shutdown)?;
                print_response(&resp);
            }
        },

        Commands::Run {
            name,
            image,
            pool,
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
            publish,
            volume,
            env,
            user,
            init,
            detach,
            uid_map,
            gid_map,
            command,
        } => {
            let name = name.unwrap_or_else(|| petname::petname(2, "-").unwrap());
            let resolved_env = resolve_env(&env);
            let mut spec = build_spec(
                name,
                image,
                pool,
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
                resolved_env,
                user,
                init,
                uid_map,
                gid_map,
                command,
            )?;
            spec.detach = detach;
            spec.publish = parse_port_mappings(&publish)?;
            spec.volumes = parse_volume_mounts(&volume)?;
            let mut client = Client::connect(cli.socket.as_deref())?;

            if detach {
                let resp = client.request(&Request::Run(spec))?;
                print_response(&resp);
            } else {
                let (resp, pty_fd) = client.request_with_fd(&Request::Run(spec))?;
                if let Response::Error { .. } = &resp {
                    print_response(&resp);
                } else if let Some(fd) = pty_fd {
                    interactive_session(fd)?;
                    let exit_resp = client.read_exit_code()?;
                    let code = match exit_resp {
                        Response::ContainerExited { exit_code } => exit_code,
                        Response::ExecExited { exit_code } => exit_code,
                        _ => 0,
                    };
                    std::process::exit(code);
                }
            }
        }

        Commands::Create {
            name,
            image,
            pool,
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
            publish,
            volume,
            env,
            user,
            init,
            restart,
            start,
            detach,
            uid_map,
            gid_map,
            command,
        } => {
            let name = name.unwrap_or_else(|| petname::petname(2, "-").unwrap());
            let resolved_env = resolve_env(&env);
            let restart_policy = sandbox_proto::RestartPolicy::parse(&restart)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "unknown restart policy: {restart} (expected: no, always, on-failure, unless-stopped)"
                    )
                })?;
            let mut spec = build_spec(
                name,
                image,
                pool,
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
                resolved_env,
                user,
                init,
                uid_map,
                gid_map,
                command,
            )?;
            spec.publish = parse_port_mappings(&publish)?;
            spec.volumes = parse_volume_mounts(&volume)?;
            spec.restart_policy = restart_policy;
            let mut client = Client::connect(cli.socket.as_deref())?;
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
                        let (resp, pty_fd) = client.request_with_fd(&start_req)?;
                        if let Response::Error { .. } = &resp {
                            print_response(&resp);
                        } else if let Some(fd) = pty_fd {
                            interactive_session(fd)?;
                            let exit_resp = client.read_exit_code()?;
                            let code = match exit_resp {
                                Response::ContainerExited { exit_code } => exit_code,
                                Response::ExecExited { exit_code } => exit_code,
                                _ => 0,
                            };
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

        Commands::Update {
            name,
            restart,
            memory,
            cpus,
            pids_max,
        } => {
            // At least one flag must be specified
            if restart.is_none() && memory.is_none() && cpus.is_none() && pids_max.is_none() {
                eprintln!(
                    "Error: no update flags specified (use --restart, --memory, --cpus, or --pids-max)"
                );
                std::process::exit(1);
            }

            let restart_policy = restart
                .map(|r| {
                    sandbox_proto::RestartPolicy::parse(&r).ok_or_else(|| {
                        anyhow::anyhow!(
                            "unknown restart policy: {r} (expected: no, always, on-failure, unless-stopped)"
                        )
                    })
                })
                .transpose()?;

            let memory_max = memory.map(parse_size).transpose()?;
            let cpu_max = cpus.map(|c| {
                let quota = (c * 100_000.0) as u64;
                (quota, 100_000u64)
            });

            let update = sandbox_proto::ContainerUpdate {
                restart_policy,
                memory_max,
                cpu_max,
                pids_max,
            };

            let mut client = Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::UpdateContainer { name, update })?;
            print_response(&resp);
        }

        Commands::Start { name, command } => {
            let cmd = if command.is_empty() {
                None
            } else {
                Some(command)
            };
            let mut client = Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::Start { name, command: cmd })?;
            print_response(&resp);
        }

        Commands::Stop { name, timeout } => {
            let mut client = Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::Stop {
                name,
                timeout_secs: timeout,
            })?;
            print_response(&resp);
        }

        Commands::Destroy { name } => {
            let mut client = Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::Destroy { name })?;
            print_response(&resp);
        }

        Commands::Snapshot {
            name,
            image_name,
            force,
            update,
        } => {
            let mut client = Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::Snapshot {
                name,
                image_name,
                force,
                update,
            })?;
            print_response(&resp);
        }

        Commands::List => {
            let mut client = Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::List)?;
            match &resp {
                Response::ContainerList(list) => {
                    if list.is_empty() {
                        println!("No containers");
                    } else {
                        println!("{:<20} {:<15} {:<10}", "NAME", "STATE", "PID");
                        for info in list {
                            let state_str = match &info.state {
                                sandbox_proto::ContainerState::Created => "Created".to_string(),
                                sandbox_proto::ContainerState::Running => "Running".to_string(),
                                sandbox_proto::ContainerState::Stopped { exit_code } => {
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

        Commands::Inspect { name, json } => {
            let mut client = Client::connect(cli.socket.as_deref())?;
            let resp = client.request(&Request::Inspect { name })?;
            match &resp {
                Response::ContainerInspect(detail) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(detail)
                                .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")),
                        );
                    } else {
                        print_container_inspect(detail);
                    }
                }
                _ => print_response(&resp),
            }
        }

        Commands::Exec {
            name,
            user,
            env,
            command,
            detach,
        } => {
            let exec_user = user.map(|u| parse_exec_user(&u)).transpose()?;
            let resolved_env = resolve_env(&env);
            let mut client = Client::connect(cli.socket.as_deref())?;
            if detach {
                let resp = client.request(&Request::Exec {
                    name,
                    command,
                    detach: true,
                    user: exec_user,
                    env: resolved_env,
                })?;
                print_response(&resp);
            } else {
                let (resp, pty_fd) = client.request_with_fd(&Request::Exec {
                    name,
                    command,
                    detach: false,
                    user: exec_user,
                    env: resolved_env,
                })?;
                if let Response::Error { .. } = &resp {
                    print_response(&resp);
                } else if let Some(fd) = pty_fd {
                    interactive_session(fd)?;
                    let exit_resp = client.read_exit_code()?;
                    let code = match exit_resp {
                        Response::ContainerExited { exit_code } => exit_code,
                        Response::ExecExited { exit_code } => exit_code,
                        _ => 0,
                    };
                    std::process::exit(code);
                }
            }
        }

        Commands::Image { action } => {
            let mut client = Client::connect(cli.socket.as_deref())?;
            match action {
                ImageAction::Import { name, source, pool } => {
                    let resp = client.request(&Request::ImageImport { name, source, pool })?;
                    print_response(&resp);
                }
                ImageAction::List {
                    pool,
                    size,
                    exclusive,
                    layers,
                } => {
                    let resp = client.request(&Request::ImageList {
                        pool,
                        show_size: size,
                        show_exclusive: exclusive,
                        show_layers: layers,
                    })?;
                    match &resp {
                        Response::ImageList(images) => {
                            if images.is_empty() {
                                println!("No images");
                            } else {
                                print_image_list(images, size, exclusive);
                            }
                        }
                        _ => print_response(&resp),
                    }
                }
                ImageAction::Inspect { name, pool } => {
                    let resp = client.request(&Request::ImageInspect { name, pool })?;
                    match &resp {
                        Response::ImageInspect(detail) => {
                            print_image_inspect(detail);
                        }
                        _ => print_response(&resp),
                    }
                }
                ImageAction::Rm { name, pool } => {
                    let resp = client.request(&Request::ImageRemove { name, pool })?;
                    print_response(&resp);
                }
                ImageAction::Pull {
                    reference,
                    name,
                    pool,
                } => {
                    let resp = client.request(&Request::ImagePull {
                        reference,
                        name,
                        pool,
                    })?;
                    print_response(&resp);
                }
            }
        }

        Commands::Mount { action } => {
            let mut client = Client::connect(cli.socket.as_deref())?;
            match action {
                MountAction::Add {
                    name,
                    spec,
                    read_only,
                    read_write,
                } => {
                    let (source, target, mut readonly) = parse_mount_spec(&spec)?;
                    // Flags override the spec
                    if read_only {
                        readonly = true;
                    }
                    if read_write {
                        readonly = false;
                    }
                    let resp = client.request(&Request::MountAdd {
                        name,
                        source,
                        target,
                        readonly,
                    })?;
                    print_response(&resp);
                }
                MountAction::Remove { name, target } => {
                    let target = make_absolute(&target);
                    let resp = client.request(&Request::MountRemove { name, target })?;
                    print_response(&resp);
                }
                MountAction::List { name } => {
                    let resp = client.request(&Request::MountList { name })?;
                    match &resp {
                        Response::MountList(mounts) => {
                            if mounts.is_empty() {
                                println!("No bind mounts");
                            } else {
                                println!("{:<30} {:<30} {:<5}", "SOURCE", "TARGET", "RO");
                                for m in mounts {
                                    let ro = if m.readonly { "yes" } else { "no" };
                                    println!("{:<30} {:<30} {:<5}", m.source, m.target, ro);
                                }
                            }
                        }
                        _ => print_response(&resp),
                    }
                }
                MountAction::Block {
                    name,
                    device,
                    target,
                    fs_type,
                    options,
                } => {
                    let resp = client.request(&Request::MountBlock {
                        container: name,
                        device,
                        target,
                        fs_type,
                        options,
                    })?;
                    print_response(&resp);
                }
            }
        }

        Commands::Network { action } => {
            let mut client = Client::connect(cli.socket.as_deref())?;
            match action {
                NetworkAction::Create { name, subnet } => {
                    let resp = client.request(&Request::NetworkCreate { name, subnet })?;
                    print_response(&resp);
                }
                NetworkAction::List => {
                    let resp = client.request(&Request::NetworkList)?;
                    match &resp {
                        Response::NetworkList(networks) => {
                            if networks.is_empty() {
                                println!("No networks");
                            } else {
                                println!(
                                    "{:<20} {:<15} {:<18} {:<15} {:<10}",
                                    "NAME", "BRIDGE", "SUBNET", "GATEWAY", "CONTAINERS"
                                );
                                for n in networks {
                                    println!(
                                        "{:<20} {:<15} {:<18} {:<15} {:<10}",
                                        n.name, n.bridge, n.subnet, n.gateway, n.containers
                                    );
                                }
                            }
                        }
                        _ => print_response(&resp),
                    }
                }
                NetworkAction::Remove { name } => {
                    let resp = client.request(&Request::NetworkRemove { name })?;
                    print_response(&resp);
                }
            }
        }

        Commands::Stack { action } => match action {
            StackAction::Up { file } => {
                let path = std::path::Path::new(&file);
                let def = sandbox::stack::parse_stack_file(path)?;
                let mut client = Client::connect(cli.socket.as_deref())?;
                let resp = client.request(&Request::StackUp(def))?;
                match &resp {
                    Response::StackUp { name, containers } => {
                        println!("Stack '{name}' is up:");
                        for c in containers {
                            println!("  {c}");
                        }
                    }
                    _ => print_response(&resp),
                }
            }
            StackAction::Down { name } => {
                let mut client = Client::connect(cli.socket.as_deref())?;
                let resp = client.request(&Request::StackDown { name })?;
                print_response(&resp);
            }
            StackAction::Ps { name } => {
                let mut client = Client::connect(cli.socket.as_deref())?;
                let resp = client.request(&Request::StackPs { name })?;
                match &resp {
                    Response::StackPs(containers) => {
                        if containers.is_empty() {
                            println!("No containers in stack");
                        } else {
                            println!("{:<25} {:<15} {:<10}", "NAME", "STATE", "PID");
                            for c in containers {
                                let state = match &c.state {
                                    sandbox_proto::ContainerState::Created => "Created".to_string(),
                                    sandbox_proto::ContainerState::Running => "Running".to_string(),
                                    sandbox_proto::ContainerState::Stopped { exit_code } => {
                                        format!("Stopped({exit_code})")
                                    }
                                };
                                let pid = c
                                    .pid
                                    .map(|p| p.to_string())
                                    .unwrap_or_else(|| "-".to_string());
                                println!("{:<25} {:<15} {:<10}", c.name, state, pid);
                            }
                        }
                    }
                    _ => print_response(&resp),
                }
            }
            StackAction::List => {
                let mut client = Client::connect(cli.socket.as_deref())?;
                let resp = client.request(&Request::StackList)?;
                match &resp {
                    Response::StackList(stacks) => {
                        if stacks.is_empty() {
                            println!("No stacks");
                        } else {
                            println!("{:<20} {:<15} {:<10}", "NAME", "BRIDGE", "CONTAINERS");
                            for s in stacks {
                                println!(
                                    "{:<20} {:<15} {:<10}",
                                    s.name,
                                    s.bridge,
                                    s.containers.len()
                                );
                            }
                        }
                    }
                    _ => print_response(&resp),
                }
            }
            StackAction::Check {
                file,
                strict,
                quiet,
            } => {
                let path = std::path::Path::new(&file);
                let contents = std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
                let result = sandbox::stack::compose::check(&contents);

                if !quiet {
                    println!("Checking {}...\n", path.display());
                    println!("  Name: {}", result.name);
                    if !result.services.is_empty() {
                        println!(
                            "  Services: {} ({})",
                            result.services.len(),
                            result.services.join(", ")
                        );
                    }
                    if !result.volumes.is_empty() {
                        println!(
                            "  Volumes: {} ({})",
                            result.volumes.len(),
                            result.volumes.join(", ")
                        );
                    }

                    if !result.supported.is_empty() {
                        println!("\n  Supported:");
                        println!("    \u{2713} {}", result.supported.join(", "));
                    }

                    if !result.warnings.is_empty() {
                        println!("\n  Warnings:");
                        for w in &result.warnings {
                            println!("    \u{26a0} {w}");
                        }
                    }

                    if !result.errors.is_empty() {
                        println!("\n  Errors:");
                        for e in &result.errors {
                            println!("    \u{2717} {e}");
                        }
                    }

                    println!(
                        "\n  Result: {} error(s), {} warning(s)",
                        result.errors.len(),
                        result.warnings.len()
                    );
                }

                if result.has_errors() || (strict && result.has_warnings()) {
                    std::process::exit(1);
                }
            }
        },

        Commands::Volume { action } => {
            let mut client = Client::connect(cli.socket.as_deref())?;
            match action {
                VolumeAction::Create {
                    name,
                    pool,
                    block,
                    size,
                    format,
                } => {
                    let volume_type = if block {
                        sandbox_proto::VolumeType::Block
                    } else {
                        sandbox_proto::VolumeType::Filesystem
                    };
                    let size_bytes = if block {
                        Some(parse_size(size.as_deref().unwrap_or("1G").to_string())?)
                    } else {
                        None
                    };
                    if format.is_some() && !block {
                        anyhow::bail!("--format requires --block");
                    }
                    let resp = client.request(&Request::VolumeCreate {
                        name,
                        pool,
                        volume_type,
                        size: size_bytes,
                        format,
                    })?;
                    print_response(&resp);
                }
                VolumeAction::List { pool } => {
                    let resp = client.request(&Request::VolumeList { pool })?;
                    match &resp {
                        Response::VolumeList(volumes) => {
                            if volumes.is_empty() {
                                println!("No volumes");
                            } else {
                                println!(
                                    "{:<25} {:<10} {:<12} {:<10}",
                                    "NAME", "POOL", "TYPE", "SIZE"
                                );
                                for v in volumes {
                                    let type_str = match v.volume_type {
                                        sandbox_proto::VolumeType::Filesystem => "filesystem",
                                        sandbox_proto::VolumeType::Block => "block",
                                    };
                                    let size_str =
                                        v.size.map(format_size).unwrap_or_else(|| "-".to_string());
                                    println!(
                                        "{:<25} {:<10} {:<12} {:<10}",
                                        v.name, v.pool, type_str, size_str
                                    );
                                }
                            }
                        }
                        _ => print_response(&resp),
                    }
                }
                VolumeAction::Remove { name, pool } => {
                    let resp = client.request(&Request::VolumeRemove { name, pool })?;
                    print_response(&resp);
                }
                VolumeAction::Attach { container, spec } => {
                    let vm = parse_volume_spec(&spec)?;
                    let resp = client.request(&Request::VolumeAttach {
                        container,
                        volume_name: vm.name,
                        target: vm.target,
                        readonly: vm.readonly,
                    })?;
                    print_response(&resp);
                }
                VolumeAction::Detach { container, target } => {
                    let resp = client.request(&Request::VolumeDetach { container, target })?;
                    print_response(&resp);
                }
            }
        }

        Commands::Pool { action } => {
            let mut client = Client::connect(cli.socket.as_deref())?;
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
        Response::ContainerInspect(detail) => print_container_inspect(detail),
        Response::ImageList(_) => {}
        Response::PoolList(_) => {}
        Response::ContainerExited { exit_code } => {
            println!("Container exited with code {exit_code}")
        }
        Response::ExecExited { exit_code } => println!("Exec exited with code {exit_code}"),
        Response::ImagePulled { name } => println!("Pulled image: {name}"),
        Response::Snapshotted { image_name } => println!("Snapshotted as image: {image_name}"),
        Response::ContainerUpdated { name } => println!("Updated container: {name}"),
        Response::StackUp { name, containers } => {
            println!("Stack '{name}' up ({} containers)", containers.len());
        }
        Response::StackDown { name } => println!("Stack '{name}' down"),
        Response::StackPs(_) => {}   // handled inline
        Response::StackList(_) => {} // handled inline
        Response::VolumeCreated { name } => println!("Created volume: {name}"),
        Response::VolumeRemoved { name } => println!("Removed volume: {name}"),
        Response::VolumeList(volumes) => {
            for v in volumes {
                println!("{}", v.name);
            }
        }
        Response::VolumeAttached { target } => println!("Volume attached at: {target}"),
        Response::VolumeDetached { target } => println!("Volume detached from: {target}"),
        Response::BlockMounted { target } => println!("Block device mounted at: {target}"),
        Response::ImageInspect(detail) => print_image_inspect(detail),
        Response::MountAdded { target } => println!("Mount added: {target}"),
        Response::MountRemoved { target } => println!("Mount removed: {target}"),
        Response::MountList(mounts) => {
            for m in mounts {
                let ro = if m.readonly { ":ro" } else { "" };
                println!("{}:{}{}", m.source, m.target, ro);
            }
        }
        Response::NetworkCreated { name } => println!("Created network: {name}"),
        Response::NetworkRemoved { name } => println!("Removed network: {name}"),
        Response::NetworkList(_) => {}
        Response::Error { message } => {
            eprintln!("Error: {message}");
            std::process::exit(1);
        }
    }
}

fn print_container_inspect(d: &sandbox_proto::ContainerDetail) {
    let state_str = match &d.state {
        sandbox_proto::ContainerState::Created => "Created".to_string(),
        sandbox_proto::ContainerState::Running => "Running".to_string(),
        sandbox_proto::ContainerState::Stopped { exit_code } => {
            format!("Stopped (exit code {exit_code})")
        }
    };
    let pid_str = d
        .pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "-".to_string());

    println!("Name:       {}", d.name);
    println!("Image:      {}", d.image);
    println!("Pool:       {}", d.pool);
    println!("State:      {state_str}");
    println!("PID:        {pid_str}");
    println!("Ephemeral:  {}", if d.ephemeral { "yes" } else { "no" });
    println!("Restart:    {}", d.restart_policy);
    println!("Init:       {}", if d.use_init { "yes" } else { "no" });
    println!(
        "User:       {}",
        d.user.as_deref().unwrap_or("root (default)")
    );

    if !d.entrypoint.is_empty() {
        println!("Entrypoint: {}", d.entrypoint.join(" "));
    }
    println!("Command:    {}", d.command.join(" "));
    println!("WorkingDir: {}", d.working_dir);

    if let Some(ref h) = d.hostname {
        println!("Hostname:   {h}");
    }

    // Network
    match &d.network {
        sandbox_proto::NetworkMode::Host => println!("Network:    host"),
        sandbox_proto::NetworkMode::None => println!("Network:    none"),
        sandbox_proto::NetworkMode::Named { name } => println!("Network:    {name}"),
        sandbox_proto::NetworkMode::Bridged {
            bridge,
            address,
            gateway,
            prefix_len,
        } => {
            let addr = address
                .map(|a| format!("{a}/{prefix_len}"))
                .unwrap_or_else(|| "auto".to_string());
            let gw = gateway
                .map(|g| g.to_string())
                .unwrap_or_else(|| "auto".to_string());
            println!("Network:    bridged ({addr}, gw {gw}, br {bridge})");
        }
    }

    if !d.env.is_empty() {
        println!("Env:");
        for e in &d.env {
            println!("  {e}");
        }
    }

    if !d.bind_mounts.is_empty() {
        println!("Mounts:");
        for m in &d.bind_mounts {
            let ro = if m.readonly { " (ro)" } else { "" };
            println!("  {}:{}{ro}", m.source, m.target);
        }
    }

    if !d.volumes.is_empty() {
        println!("Volumes:");
        for v in &d.volumes {
            let ro = if v.readonly { " (ro)" } else { "" };
            println!("  {}:{}{ro}", v.name, v.target);
        }
    }

    if !d.publish.is_empty() {
        println!("Ports:");
        for p in &d.publish {
            println!("  {}:{}/{}", p.host_port, p.container_port, p.protocol);
        }
    }

    // Cgroup limits (only print non-default)
    let cg = &d.cgroup;
    if cg.memory_max.is_some() || cg.cpu_max.is_some() || cg.pids_max.is_some() {
        println!("Cgroup:");
        if let Some(mem) = cg.memory_max {
            println!("  memory: {}", format_size(mem));
        }
        if let Some((quota, period)) = cg.cpu_max {
            println!("  cpus:   {:.1}", quota as f64 / period as f64);
        }
        if let Some(pids) = cg.pids_max {
            println!("  pids:   {pids}");
        }
    }

    match d.seccomp {
        sandbox_proto::SeccompMode::Default => println!("Seccomp:    default"),
        sandbox_proto::SeccompMode::Disabled => println!("Seccomp:    disabled"),
    }

    if let Some(ref rp) = d.rootfs_path {
        println!("Rootfs:     {rp}");
    }
    println!("Cgroup:     {}", d.cgroup_path);
}

/// Resolve environment variable arguments.
///
/// - `KEY=VALUE` → passed as-is
/// - `KEY` (no `=`) → resolved from the caller's environment; silently skipped if not set
fn resolve_env(raw: &[String]) -> Vec<String> {
    let mut resolved = Vec::with_capacity(raw.len());
    for item in raw {
        if item.contains('=') {
            resolved.push(item.clone());
        } else if let Ok(val) = std::env::var(item) {
            resolved.push(format!("{item}={val}"));
        }
        // else: bare name not set in caller env → silently skip (Docker behavior)
    }
    resolved
}

#[allow(clippy::too_many_arguments)]
fn build_spec(
    name: String,
    image: String,
    pool: Option<String>,
    hostname: Option<String>,
    memory: Option<String>,
    cpus: Option<f64>,
    pids_max: Option<u32>,
    network: String,
    _bridge: Option<String>,
    _ip: Option<String>,
    _gateway: Option<String>,
    seccomp: String,
    cap_add: Vec<String>,
    bind: Vec<String>,
    env: Vec<String>,
    user: Option<String>,
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
        // "bridged" is an alias for the "default" named network
        "bridged" | "default" => NetworkMode::Named {
            name: "default".to_string(),
        },
        // Anything else is a named network
        name => NetworkMode::Named {
            name: name.to_string(),
        },
    };

    let seccomp_mode = match seccomp.as_str() {
        "default" => SeccompMode::Default,
        "disabled" => SeccompMode::Disabled,
        other => anyhow::bail!("unknown seccomp mode: {other}"),
    };

    let bind_mounts: Vec<BindMount> = bind
        .iter()
        .map(|b| {
            let (source, target, readonly) = parse_mount_spec(b)?;
            Ok(BindMount {
                source,
                target,
                readonly,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let uid_mappings = if uid_map.is_empty() {
        Vec::new()
    } else {
        uid_map
            .iter()
            .map(|m| parse_id_mapping(m))
            .collect::<anyhow::Result<Vec<_>>>()?
    };

    let gid_mappings = if gid_map.is_empty() {
        Vec::new()
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
        image,
        pool,
        entrypoint: Vec::new(),
        command: cmd,
        env,
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
        volumes: Vec::new(), // populated by caller from --volume flags
        publish: Vec::new(), // populated by caller from --publish flags
        use_init: init,
        detach: false,
        user,
        restart_policy: sandbox_proto::RestartPolicy::No, // caller sets this
    })
}

/// Parse a user spec: "UID" or "UID:GID"
fn parse_exec_user(s: &str) -> anyhow::Result<sandbox_proto::ExecUser> {
    if let Some((uid_str, gid_str)) = s.split_once(':') {
        let uid: u32 = uid_str
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid UID: {uid_str}"))?;
        let gid: u32 = gid_str
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid GID: {gid_str}"))?;
        Ok(sandbox_proto::ExecUser { uid, gid })
    } else {
        let uid: u32 = s.parse().map_err(|_| anyhow::anyhow!("invalid UID: {s}"))?;
        Ok(sandbox_proto::ExecUser { uid, gid: uid })
    }
}

/// Parse a mount spec: "SOURCE:TARGET" or "SOURCE:TARGET:ro"
/// Parse volume mount specs: "name:/path" or "name:/path:ro"
fn parse_volume_mounts(specs: &[String]) -> anyhow::Result<Vec<sandbox_proto::VolumeMount>> {
    specs.iter().map(|s| parse_volume_spec(s)).collect()
}

/// Parse a single volume spec: "name:/path" or "name:/path:ro"
fn parse_volume_spec(spec: &str) -> anyhow::Result<sandbox_proto::VolumeMount> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    match parts.len() {
        2 => Ok(sandbox_proto::VolumeMount {
            name: parts[0].to_string(),
            target: parts[1].to_string(),
            readonly: false,
            volume_type: sandbox_proto::VolumeType::default(),
        }),
        3 => Ok(sandbox_proto::VolumeMount {
            name: parts[0].to_string(),
            target: parts[1].to_string(),
            readonly: parts[2] == "ro",
            volume_type: sandbox_proto::VolumeType::default(),
        }),
        _ => anyhow::bail!("invalid volume spec: {spec} (expected name:/path or name:/path:ro)"),
    }
}

/// Parse port mapping specs: "hostPort:containerPort[/tcp|/udp]"
fn parse_port_mappings(specs: &[String]) -> anyhow::Result<Vec<sandbox_proto::PortMapping>> {
    specs.iter().map(|s| parse_port_mapping(s)).collect()
}

fn parse_port_mapping(spec: &str) -> anyhow::Result<sandbox_proto::PortMapping> {
    // Format: hostPort:containerPort[/protocol]
    // Examples: 8080:80, 8080:80/tcp, 5353:53/udp
    let (ports, proto) = if let Some((p, pr)) = spec.rsplit_once('/') {
        let protocol = match pr {
            "tcp" => sandbox_proto::PortProtocol::Tcp,
            "udp" => sandbox_proto::PortProtocol::Udp,
            other => anyhow::bail!("unknown protocol: {other} (expected tcp or udp)"),
        };
        (p, protocol)
    } else {
        (spec, sandbox_proto::PortProtocol::Tcp)
    };

    let (host, container) = ports.split_once(':').ok_or_else(|| {
        anyhow::anyhow!("invalid port mapping: {spec} (expected hostPort:containerPort)")
    })?;

    let host_port: u16 = host
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid host port: {host}"))?;
    let container_port: u16 = container
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid container port: {container}"))?;

    Ok(sandbox_proto::PortMapping {
        host_port,
        container_port,
        protocol: proto,
    })
}

/// Parse a mount spec with multiple supported formats:
///
///   /path                     → source=/path, target=/path, rw
///   /path:ro                  → source=/path, target=/path, ro
///   /path::ro                 → source=/path, target=/path, ro
///   /source:/target           → source=/source, target=/target, rw
///   /source:/target:ro        → source=/source, target=/target, ro
///
/// Source path is made absolute before parsing.
fn parse_mount_spec(spec: &str) -> anyhow::Result<(String, String, bool)> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    match parts.len() {
        1 => {
            // /path — source only, target = source
            let source = make_absolute(parts[0]);
            Ok((source.clone(), source, false))
        }
        2 => {
            let source = make_absolute(parts[0]);
            if parts[1].is_empty() || parts[1] == "ro" || parts[1] == "rw" {
                // /path:ro or /path:rw or /path: (trailing colon)
                let readonly = parts[1] == "ro";
                Ok((source.clone(), source, readonly))
            } else {
                // /source:/target
                Ok((source, parts[1].to_string(), false))
            }
        }
        3 => {
            let source = make_absolute(parts[0]);
            if parts[1].is_empty() {
                // /path::ro — double colon, no target, with flag
                let readonly = parts[2] == "ro";
                Ok((source.clone(), source, readonly))
            } else {
                // /source:/target:ro
                let readonly = parts[2] == "ro";
                Ok((source, parts[1].to_string(), readonly))
            }
        }
        _ => anyhow::bail!("invalid mount spec: {spec}"),
    }
}

/// Make a path absolute (resolve relative to cwd).
fn make_absolute(path: &str) -> String {
    let p = std::path::Path::new(path);
    if p.is_absolute() {
        path.to_string()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(p).to_string_lossy().to_string())
            .unwrap_or_else(|_| path.to_string())
    }
}

fn parse_size(s: String) -> anyhow::Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty size");
    }

    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('G').or_else(|| s.strip_suffix('g'))
    {
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

/// Run an interactive session, proxying between the local terminal and
/// a PTY master fd received from the daemon.
fn interactive_session(pty_master: std::os::fd::OwnedFd) -> anyhow::Result<()> {
    use nix::sys::termios::{SetArg, cfmakeraw, tcgetattr, tcsetattr};
    use std::io::{Read, Write};
    use std::os::fd::{AsFd, AsRawFd};

    let stdin_fd = std::io::stdin();
    let is_tty = nix::unistd::isatty(stdin_fd.as_fd()).unwrap_or(false);

    // Save original terminal settings
    let original_termios = if is_tty {
        Some(tcgetattr(&stdin_fd)?)
    } else {
        None
    };

    // Guard to restore terminal on exit (including panic)
    struct TerminalGuard {
        original: Option<nix::sys::termios::Termios>,
    }
    impl Drop for TerminalGuard {
        fn drop(&mut self) {
            if let Some(ref orig) = self.original {
                let stdin = std::io::stdin();
                let _ =
                    nix::sys::termios::tcsetattr(&stdin, nix::sys::termios::SetArg::TCSANOW, orig);
            }
        }
    }
    let _guard = TerminalGuard {
        original: original_termios.clone(),
    };

    // Put stdin in raw mode
    if let Some(ref orig) = original_termios {
        let mut raw = orig.clone();
        cfmakeraw(&mut raw);
        tcsetattr(&stdin_fd, SetArg::TCSANOW, &raw)?;
    }

    // Forward current terminal size to the PTY
    if is_tty {
        if let Ok(ws) = sandbox::sys::pty::get_window_size(&stdin_fd) {
            let _ = sandbox::sys::pty::set_window_size(&pty_master, &ws);
        }
    }

    let master_raw = pty_master.as_raw_fd();

    // Thread 1: stdin → PTY master
    let _stdin_handle = std::thread::spawn(move || {
        let master_fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(master_raw) };
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if nix::unistd::write(master_fd, &buf[..n]).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });

    // Thread 2 (main): PTY master → stdout
    let mut stdout = std::io::stdout().lock();
    let mut buf = [0u8; 4096];
    loop {
        match nix::unistd::read(&pty_master, &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stdout.write_all(&buf[..n]).is_err() {
                    break;
                }
                if stdout.flush().is_err() {
                    break;
                }
            }
        }
    }

    Ok(())
}

fn print_image_list(images: &[sandbox_proto::ImageInfo], show_size: bool, show_exclusive: bool) {
    // Header
    let mut header = format!("{:<25} {:<8} ", "NAME", "POOL");
    if show_size {
        header += &format!("{:<12} ", "SIZE");
    }
    if show_exclusive {
        header += &format!("{:<12} ", "EXCLUSIVE");
    }
    header += &format!("{:<8} {}", "LAYERS", "SOURCE");
    println!("{header}");

    for img in images {
        // Image row
        let mut row = format!("{:<25} {:<8} ", img.name, img.pool);
        if show_size {
            let size = img
                .size_bytes
                .map(format_size)
                .unwrap_or_else(|| "-".to_string());
            row += &format!("{:<12} ", size);
        }
        if show_exclusive {
            let excl = img
                .exclusive_bytes
                .map(format_size)
                .unwrap_or_else(|| "N/A".to_string());
            row += &format!("{:<12} ", excl);
        }
        row += &format!("{:<8} {}", img.layer_count, img.source);
        println!("{row}");

        // Layer tree (if --layers)
        if !img.layers.is_empty() {
            let last_idx = img.layers.len() - 1;
            for (i, layer) in img.layers.iter().enumerate() {
                let connector = if i == last_idx {
                    "└── "
                } else {
                    "├── "
                };
                let short_id = if layer.chain_id.len() > 19 {
                    &layer.chain_id[..19]
                } else {
                    &layer.chain_id
                };

                let mut line = format!("{connector}{short_id}");

                if show_size {
                    if let Some(size) = layer.size_bytes {
                        line += &format!("  {}", format_size(size));
                    }
                }

                if !layer.shared_with.is_empty() {
                    line += &format!("  (shared with: {})", layer.shared_with.join(", "));
                }

                println!("{line}");
            }
            println!();
        }
    }
}

fn print_image_inspect(detail: &sandbox_proto::ImageDetail) {
    println!("Name: {}", detail.name);
    println!("Source: {}", detail.source);
    println!("Pool: {}", detail.pool);
    println!("Size: {}", format_size(detail.size_bytes));
    println!("Reference: {}", detail.reference);
    println!("Config:");
    if detail.config.entrypoint.is_empty() {
        println!("  Entrypoint: []");
    } else {
        println!("  Entrypoint: {:?}", detail.config.entrypoint);
    }
    if detail.config.cmd.is_empty() {
        println!("  Cmd: []");
    } else {
        println!("  Cmd: {:?}", detail.config.cmd);
    }
    if detail.config.env.is_empty() {
        println!("  Env: []");
    } else {
        println!("  Env:");
        for e in &detail.config.env {
            println!("    {e}");
        }
    }
    println!("  WorkingDir: {}", detail.config.working_dir);
    println!("Layers: {}", detail.layers.len());
    let last_idx = detail.layers.len().saturating_sub(1);
    for (i, layer) in detail.layers.iter().enumerate() {
        let connector = if i == last_idx {
            "└── "
        } else {
            "├── "
        };
        let short_id = if layer.chain_id.len() > 19 {
            &layer.chain_id[..19]
        } else {
            &layer.chain_id
        };
        let mut line = format!("{connector}{short_id}  {}", format_size(layer.size_bytes));
        if !layer.shared_with.is_empty() {
            line += &format!("  (shared with: {})", layer.shared_with.join(", "));
        }
        println!("{line}");
    }
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
