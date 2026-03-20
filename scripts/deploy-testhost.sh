#!/bin/bash
# Build sandbox + e2e test binary and deploy to testhost.
set -e

echo "=== Building release ==="
cargo clippy --workspace -- -W clippy::all
cargo fmt --all --check
cargo build --release

echo "=== Deploying to testhost ==="
scp target/release/sandbox target/release/sandbox-e2e testhost:/tmp/
ssh testhost "sudo install /tmp/sandbox /usr/local/bin/sandbox && sudo install /tmp/sandbox-e2e /usr/local/bin/sandbox-e2e"

echo "=== Deployed ==="
ssh testhost "sandbox --version 2>/dev/null || echo 'sandbox installed'"
