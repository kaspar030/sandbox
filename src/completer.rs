//! Dynamic shell completion for sandbox CLI arguments.
//!
//! Each completer connects to the daemon, queries live data, and returns
//! completion candidates. All functions silently return an empty list if
//! the daemon is unreachable.

use clap_complete::CompletionCandidate;
use sandbox_client::Client;
use sandbox_proto::{Request, Response};

/// Try to connect to the daemon using the default socket path.
///
/// Returns `None` if the daemon is not running — completion should
/// degrade gracefully rather than error.
fn connect() -> Option<Client> {
    Client::connect(None).ok()
}

/// Complete container names (with state as help text).
pub fn container_completer() -> Vec<CompletionCandidate> {
    let Some(mut client) = connect() else {
        return vec![];
    };
    let Ok(Response::ContainerList(containers)) = client.request(&Request::List) else {
        return vec![];
    };
    containers
        .into_iter()
        .map(|c| {
            let state = match &c.state {
                sandbox_proto::ContainerState::Created => "created".into(),
                sandbox_proto::ContainerState::Running => "running".into(),
                sandbox_proto::ContainerState::Stopped { exit_code } => {
                    format!("stopped({exit_code})")
                }
            };
            CompletionCandidate::new(c.name).help(Some(state.into()))
        })
        .collect()
}

/// Complete image names (with source as help text).
pub fn image_completer() -> Vec<CompletionCandidate> {
    let Some(mut client) = connect() else {
        return vec![];
    };
    let Ok(Response::ImageList(images)) = client.request(&Request::ImageList {
        pool: None,
        show_size: false,
        show_exclusive: false,
        show_layers: false,
    }) else {
        return vec![];
    };
    images
        .into_iter()
        .map(|img| CompletionCandidate::new(img.name).help(Some(img.source.into())))
        .collect()
}

/// Complete network names (with subnet as help text).
pub fn network_completer() -> Vec<CompletionCandidate> {
    let Some(mut client) = connect() else {
        return vec![];
    };
    let Ok(Response::NetworkList(networks)) = client.request(&Request::NetworkList) else {
        return vec![];
    };
    networks
        .into_iter()
        .map(|net| CompletionCandidate::new(net.name).help(Some(net.subnet.into())))
        .collect()
}

/// Complete volume names (with pool as help text).
pub fn volume_completer() -> Vec<CompletionCandidate> {
    let Some(mut client) = connect() else {
        return vec![];
    };
    let Ok(Response::VolumeList(volumes)) = client.request(&Request::VolumeList { pool: None })
    else {
        return vec![];
    };
    volumes
        .into_iter()
        .map(|vol| CompletionCandidate::new(vol.name).help(Some(vol.pool.into())))
        .collect()
}

/// Complete pool names (with filesystem type as help text).
pub fn pool_completer() -> Vec<CompletionCandidate> {
    let Some(mut client) = connect() else {
        return vec![];
    };
    let Ok(Response::PoolList(pools)) = client.request(&Request::PoolList) else {
        return vec![];
    };
    pools
        .into_iter()
        .map(|pool| CompletionCandidate::new(pool.name).help(Some(pool.fs_type.into())))
        .collect()
}

/// Complete stack names (with container count as help text).
pub fn stack_completer() -> Vec<CompletionCandidate> {
    let Some(mut client) = connect() else {
        return vec![];
    };
    let Ok(Response::StackList(stacks)) = client.request(&Request::StackList) else {
        return vec![];
    };
    stacks
        .into_iter()
        .map(|stack| {
            let n = stack.containers.len();
            let help = format!("{n} container{}", if n == 1 { "" } else { "s" });
            CompletionCandidate::new(stack.name).help(Some(help.into()))
        })
        .collect()
}
