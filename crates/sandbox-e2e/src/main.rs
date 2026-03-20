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
        // Images
        Test::Immutable("Images", "image_list", tests::images::test_image_list),
        Test::Immutable("Images", "image_inspect", tests::images::test_image_inspect),
        Test::Immutable("Images", "snapshot", tests::images::test_snapshot),
        Test::Immutable(
            "Images",
            "snapshot_update",
            tests::images::test_snapshot_update,
        ),
        // Exec
        Test::Immutable("Exec", "exec_basic", tests::exec::test_exec_basic),
        Test::Immutable("Exec", "exec_user", tests::exec::test_exec_user),
        Test::Immutable("Exec", "exec_env_clean", tests::exec::test_exec_env_clean),
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
