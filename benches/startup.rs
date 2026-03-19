//! Criterion benchmarks for container startup performance.
//!
//! Prerequisites:
//! - The sandbox daemon must be running (`sudo sandbox daemon start`)
//! - An alpine image must be available (`sandbox image pull alpine:latest` or `sandbox image import`)
//!
//! Run with: `cargo bench --bench startup`
//!
//! The benchmark measures end-to-end wall-clock time for:
//! - `sandbox run --image alpine -- /bin/true` (full lifecycle: create, start, exec, exit, cleanup)

use criterion::{Criterion, criterion_group, criterion_main};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Check that the daemon is running and alpine image is available.
fn check_prerequisites() -> bool {
    // Check daemon is reachable
    let output = Command::new("sandbox").args(["list"]).output();
    if output.is_err() || !output.unwrap().status.success() {
        eprintln!("SKIP: sandbox daemon is not running");
        return false;
    }

    // Check alpine image exists
    let output = Command::new("sandbox")
        .args(["image", "list"])
        .output()
        .expect("failed to list images");
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("alpine") {
        eprintln!("SKIP: alpine image not found (run: sandbox image pull alpine:latest)");
        return false;
    }

    true
}

fn bench_run_true(c: &mut Criterion) {
    if !check_prerequisites() {
        return;
    }

    let mut group = c.benchmark_group("container");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));
    group.warm_up_time(Duration::from_secs(5));

    group.bench_function("run_alpine_true", |b| {
        b.iter(|| {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let name = format!("bench-{n}");
            let output = Command::new("sandbox")
                .args([
                    "run",
                    "--name",
                    &name,
                    "--image",
                    "alpine",
                    "--",
                    "/bin/true",
                ])
                .output()
                .expect("failed to run sandbox");
            assert!(
                output.status.success(),
                "sandbox run failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        });
    });

    group.bench_function("run_alpine_echo", |b| {
        b.iter(|| {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let name = format!("bench-echo-{n}");
            let output = Command::new("sandbox")
                .args([
                    "run", "--name", &name, "--image", "alpine", "--", "echo", "hello",
                ])
                .output()
                .expect("failed to run sandbox");
            assert!(
                output.status.success(),
                "sandbox run failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        });
    });

    group.finish();
}

criterion_group!(benches, bench_run_true);
criterion_main!(benches);
