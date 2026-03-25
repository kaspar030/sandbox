mod context;
mod tests;

use clap::Parser;
use context::TestContext;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "sandbox-e2e", about = "End-to-end tests for sandbox")]
struct Args {
    /// Path to sandbox binary
    #[arg(long, default_value = "sandbox")]
    sandbox_bin: PathBuf,

    /// Btrfs pool path (for test working directory)
    #[arg(long, env = "SANDBOX_E2E_POOL", default_value = "/pool")]
    pool: PathBuf,

    /// Run only tests matching this pattern
    #[arg(long)]
    filter: Option<String>,

    /// Don't stop daemon or clean up after tests
    #[arg(long)]
    keep: bool,

    /// List all tests without running
    #[arg(long)]
    list: bool,
}

type TestFn = fn(&TestContext) -> Result<(), String>;
type TestFnMut = fn(&mut TestContext) -> Result<(), String>;

enum Test {
    Immutable(&'static str, &'static str, TestFn),
    Mutable(&'static str, &'static str, TestFnMut),
}

impl Test {
    fn group(&self) -> &str {
        match self {
            Test::Immutable(g, _, _) | Test::Mutable(g, _, _) => g,
        }
    }
    fn name(&self) -> &str {
        match self {
            Test::Immutable(_, n, _) | Test::Mutable(_, n, _) => n,
        }
    }
}

fn all_tests() -> Vec<Test> {
    vec![
        // Lifecycle
        Test::Immutable("Lifecycle", "run_echo", tests::lifecycle::test_run_echo),
        Test::Immutable("Lifecycle", "run_init", tests::lifecycle::test_run_init),
        Test::Immutable(
            "Lifecycle",
            "create_start_stop_destroy",
            tests::lifecycle::test_create_start_stop_destroy,
        ),
        Test::Immutable(
            "Lifecycle",
            "petname_auto",
            tests::lifecycle::test_petname_auto,
        ),
        Test::Immutable(
            "Lifecycle",
            "list_containers",
            tests::lifecycle::test_list_containers,
        ),
        Test::Immutable("Lifecycle", "inspect", tests::lifecycle::test_inspect),
        // Images
        Test::Immutable("Images", "image_list", tests::images::test_image_list),
        Test::Immutable("Images", "image_inspect", tests::images::test_image_inspect),
        Test::Immutable(
            "Images",
            "image_create_from",
            tests::images::test_image_create_from,
        ),
        Test::Immutable(
            "Images",
            "image_create_update",
            tests::images::test_image_create_update,
        ),
        // Exec
        Test::Immutable("Exec", "exec_basic", tests::exec::test_exec_basic),
        Test::Immutable("Exec", "exec_user", tests::exec::test_exec_user),
        Test::Immutable("Exec", "exec_env_clean", tests::exec::test_exec_env_clean),
        Test::Immutable("Exec", "exec_setpgid", tests::exec::test_exec_setpgid),
        Test::Immutable("Exec", "exec_groups", tests::exec::test_exec_groups),
        Test::Immutable("Exec", "run_user", tests::exec::test_run_user),
        Test::Immutable(
            "Exec",
            "run_user_by_name",
            tests::exec::test_run_user_by_name,
        ),
        Test::Immutable(
            "Exec",
            "exec_killed_on_stop",
            tests::exec::test_exec_killed_on_stop,
        ),
        Test::Immutable(
            "Exec",
            "exec_piped_stdout_stderr",
            tests::exec::test_exec_piped_stdout_stderr,
        ),
        Test::Immutable(
            "Exec",
            "exec_piped_exit_code",
            tests::exec::test_exec_piped_exit_code,
        ),
        Test::Immutable(
            "Exec",
            "exec_piped_explicit",
            tests::exec::test_exec_piped_explicit,
        ),
        Test::Immutable("Exec", "allow_new_privs", tests::exec::test_allow_new_privs),
        Test::Immutable(
            "Exec",
            "no_new_privs_default",
            tests::exec::test_no_new_privs_default,
        ),
        Test::Immutable(
            "Exec",
            "update_allow_new_privs",
            tests::exec::test_update_allow_new_privs,
        ),
        // Mounts
        Test::Immutable(
            "Mounts",
            "bind_mount_at_create",
            tests::mounts::test_bind_mount_at_create,
        ),
        Test::Immutable(
            "Mounts",
            "hot_mount_add_remove",
            tests::mounts::test_hot_mount_add_remove,
        ),
        Test::Immutable(
            "Mounts",
            "mount_shorthand",
            tests::mounts::test_mount_shorthand,
        ),
        Test::Immutable("Mounts", "mount_stopped", tests::mounts::test_mount_stopped),
        // Environment
        Test::Immutable(
            "Environment",
            "env_home_user",
            tests::env::test_env_home_user,
        ),
        Test::Immutable("Environment", "env_hostname", tests::env::test_env_hostname),
        Test::Immutable(
            "Environment",
            "env_no_daemon_leak",
            tests::env::test_env_no_daemon_leak,
        ),
        Test::Immutable("Environment", "env_run", tests::env::test_env_run),
        Test::Immutable(
            "Environment",
            "env_create_persist",
            tests::env::test_env_create_persist,
        ),
        Test::Immutable(
            "Environment",
            "env_exec_override",
            tests::env::test_env_exec_override,
        ),
        // Networking
        Test::Immutable(
            "Networking",
            "bridged_auto_ip",
            tests::networking::test_bridged_auto_ip,
        ),
        Test::Immutable(
            "Networking",
            "publish_requires_bridged",
            tests::networking::test_publish_requires_bridged,
        ),
        Test::Immutable(
            "Networking",
            "bridged_dns",
            tests::networking::test_bridged_dns,
        ),
        // Named Networks
        Test::Immutable(
            "Networks",
            "network_create_list_remove",
            tests::networks::test_network_create_list_remove,
        ),
        Test::Immutable(
            "Networks",
            "network_with_subnet",
            tests::networks::test_network_with_subnet,
        ),
        Test::Immutable(
            "Networks",
            "container_on_named_network",
            tests::networks::test_container_on_named_network,
        ),
        Test::Immutable(
            "Networks",
            "default_network",
            tests::networks::test_default_network,
        ),
        // Volumes
        Test::Immutable(
            "Volumes",
            "volume_create_list_remove",
            tests::volumes::test_volume_create_list_remove,
        ),
        Test::Immutable(
            "Volumes",
            "volume_mount_write_read",
            tests::volumes::test_volume_mount_write_read,
        ),
        Test::Immutable(
            "Volumes",
            "volume_attach_detach",
            tests::volumes::test_volume_attach_detach,
        ),
        Test::Immutable(
            "Volumes",
            "volume_remove_in_use",
            tests::volumes::test_volume_remove_in_use,
        ),
        Test::Immutable(
            "Block Volumes",
            "block_volume_create_remove",
            tests::volumes::test_block_volume_create_remove,
        ),
        Test::Immutable(
            "Block Volumes",
            "block_volume_raw_device",
            tests::volumes::test_block_volume_raw_device,
        ),
        Test::Immutable(
            "Block Volumes",
            "block_volume_format_mount",
            tests::volumes::test_block_volume_format_mount,
        ),
        Test::Immutable(
            "Block Volumes",
            "block_volume_formatted_auto",
            tests::volumes::test_block_volume_formatted_auto,
        ),
        // Stacks
        Test::Immutable("Stacks", "stack_up_down", tests::stacks::test_stack_up_down),
        Test::Immutable(
            "Stacks",
            "stack_with_volumes",
            tests::stacks::test_stack_with_volumes,
        ),
        Test::Immutable(
            "Stacks",
            "stack_with_networking",
            tests::stacks::test_stack_with_networking,
        ),
        Test::Immutable(
            "Stacks",
            "stack_dns_resolution",
            tests::stacks::test_stack_dns_resolution,
        ),
        Test::Immutable(
            "Stacks",
            "stack_compose_format",
            tests::stacks::test_stack_compose_format,
        ),
        Test::Immutable(
            "Stacks",
            "stack_strict_parsing",
            tests::stacks::test_stack_strict_parsing,
        ),
        Test::Immutable(
            "Stacks",
            "stack_check_valid",
            tests::stacks::test_stack_check_valid,
        ),
        Test::Immutable(
            "Stacks",
            "stack_check_unsupported",
            tests::stacks::test_stack_check_unsupported,
        ),
        Test::Immutable(
            "Stacks",
            "stack_check_quiet",
            tests::stacks::test_stack_check_quiet,
        ),
        // Idle init
        Test::Immutable(
            "Idle",
            "create_idle_default",
            tests::idle::test_create_idle_default,
        ),
        Test::Immutable(
            "Idle",
            "create_idle_explicit_init",
            tests::idle::test_create_idle_explicit_init,
        ),
        Test::Immutable(
            "Idle",
            "create_with_command",
            tests::idle::test_create_with_command,
        ),
        Test::Immutable(
            "Idle",
            "run_default_shell",
            tests::idle::test_run_default_shell,
        ),
        Test::Immutable(
            "Idle",
            "idle_reaps_zombies",
            tests::idle::test_idle_reaps_zombies,
        ),
        // Restart policies
        Test::Immutable(
            "Restart",
            "restart_always",
            tests::restart::test_restart_always,
        ),
        Test::Immutable(
            "Restart",
            "restart_on_failure",
            tests::restart::test_restart_on_failure,
        ),
        Test::Immutable(
            "Restart",
            "restart_unless_stopped",
            tests::restart::test_restart_unless_stopped,
        ),
        Test::Immutable("Restart", "restart_no", tests::restart::test_restart_no),
        Test::Immutable(
            "Restart",
            "restart_inspect",
            tests::restart::test_restart_inspect,
        ),
        // Update
        Test::Immutable(
            "Update",
            "update_restart_policy",
            tests::update::test_update_restart_policy,
        ),
        Test::Immutable("Update", "update_memory", tests::update::test_update_memory),
        Test::Immutable("Update", "update_cpus", tests::update::test_update_cpus),
        Test::Immutable(
            "Update",
            "update_pids_max",
            tests::update::test_update_pids_max,
        ),
        Test::Immutable(
            "Update",
            "update_running",
            tests::update::test_update_running,
        ),
        Test::Immutable(
            "Update",
            "update_multiple",
            tests::update::test_update_multiple,
        ),
        Test::Immutable("Update", "update_env", tests::update::test_update_env),
        Test::Immutable(
            "Update",
            "update_command",
            tests::update::test_update_command,
        ),
        Test::Immutable(
            "Update",
            "update_identity",
            tests::update::test_update_identity,
        ),
        Test::Immutable("Update", "update_init", tests::update::test_update_init),
        Test::Mutable(
            "Update",
            "update_persists",
            tests::update::test_update_persists,
        ),
        // Snapshot / Restore
        Test::Immutable(
            "Snapshot",
            "snapshot_and_restore",
            tests::snapshot_restore::test_snapshot_and_restore,
        ),
        Test::Immutable(
            "Snapshot",
            "snapshot_with_volumes",
            tests::snapshot_restore::test_snapshot_with_volumes,
        ),
        Test::Immutable(
            "Snapshot",
            "snapshot_exclude_volumes",
            tests::snapshot_restore::test_snapshot_exclude_volumes,
        ),
        Test::Immutable(
            "Snapshot",
            "snapshot_running_container",
            tests::snapshot_restore::test_snapshot_running_container,
        ),
        Test::Immutable(
            "Snapshot",
            "restore_requires_stopped",
            tests::snapshot_restore::test_restore_requires_stopped,
        ),
        Test::Immutable(
            "Snapshot",
            "snapshot_list_and_delete",
            tests::snapshot_restore::test_snapshot_list_and_delete,
        ),
        Test::Immutable(
            "Snapshot",
            "snapshot_auto_name",
            tests::snapshot_restore::test_snapshot_auto_name,
        ),
        Test::Immutable(
            "Snapshot",
            "snapshot_list_size",
            tests::snapshot_restore::test_snapshot_list_size,
        ),
        // Clone
        Test::Immutable(
            "Clone",
            "clone_from_container",
            tests::clone::test_clone_from_container,
        ),
        Test::Immutable(
            "Clone",
            "clone_from_snapshot",
            tests::clone::test_clone_from_snapshot,
        ),
        Test::Immutable(
            "Clone",
            "clone_with_overrides",
            tests::clone::test_clone_with_overrides,
        ),
        Test::Immutable(
            "Clone",
            "clone_independence",
            tests::clone::test_clone_independence,
        ),
        // Session mode
        Test::Immutable(
            "Session",
            "session_multi_request",
            tests::session::test_session_multi_request,
        ),
        Test::Immutable(
            "Session",
            "session_single_shot_compat",
            tests::session::test_session_single_shot_compat,
        ),
        Test::Immutable(
            "Session",
            "session_piped_exec",
            tests::session::test_session_piped_exec,
        ),
        // Persistence (needs mutable context for restart)
        Test::Mutable(
            "Persistence",
            "daemon_restart_recovery",
            tests::persistence::test_daemon_restart_recovery,
        ),
        Test::Mutable(
            "Persistence",
            "graceful_shutdown",
            tests::persistence::test_graceful_shutdown,
        ),
    ]
}

fn main() {
    let args = Args::parse();
    let tests = all_tests();

    if args.list {
        let mut current_group = "";
        for test in &tests {
            if test.group() != current_group {
                current_group = test.group();
                println!("\n  {current_group}:");
            }
            println!("    {}", test.name());
        }
        return;
    }

    // Validate pool
    if !args.pool.is_dir() {
        eprintln!(
            "error: pool directory '{}' does not exist",
            args.pool.display()
        );
        eprintln!("set SANDBOX_E2E_POOL or use --pool");
        std::process::exit(1);
    }

    println!("sandbox e2e tests");
    println!("  binary: {}", args.sandbox_bin.display());
    println!("  pool: {}", args.pool.display());

    let mut ctx = TestContext::new(args.sandbox_bin.clone(), &args.pool, args.keep);
    println!("  workdir: {}", ctx.workdir.display());
    println!();

    // Start daemon
    eprint!("  Starting daemon...");
    ctx.start_daemon();
    eprintln!("OK");

    // Ensure images
    ctx.ensure_images();
    println!();

    // Run tests
    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut skipped = 0u32;
    let mut failures: Vec<(String, String)> = Vec::new();
    let mut current_group = "";
    let total_start = Instant::now();

    for test in &tests {
        // Filter
        #[allow(clippy::collapsible_if)]
        if let Some(ref filter) = args.filter {
            if !test.name().contains(filter.as_str())
                && !test.group().to_lowercase().contains(&filter.to_lowercase())
            {
                skipped += 1;
                continue;
            }
        }

        // Print group header
        if test.group() != current_group {
            current_group = test.group();
            println!("  {current_group}:");
        }

        // Run test
        let padded_name = format!("{:<35}", test.name());
        eprint!("    {padded_name}");
        let start = Instant::now();

        let result = match test {
            Test::Immutable(_, _, f) => f(&ctx),
            Test::Mutable(_, _, f) => f(&mut ctx),
        };

        let elapsed = start.elapsed();
        match result {
            Ok(()) => {
                println!("PASS ({elapsed:.0?})");
                passed += 1;
            }
            Err(msg) => {
                println!("FAIL ({elapsed:.0?})");
                println!("      {msg}");
                failed += 1;
                failures.push((test.name().to_string(), msg));
            }
        }
    }

    let total_elapsed = total_start.elapsed();
    println!();

    if !failures.is_empty() {
        println!("  Failures:");
        for (name, msg) in &failures {
            println!("    {name}: {msg}");
        }
        println!();
    }

    println!(
        "  Summary: {passed} passed, {failed} failed, {skipped} skipped ({total_elapsed:.1?})"
    );

    if failed > 0 {
        std::process::exit(1);
    }
}
