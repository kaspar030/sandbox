#!/bin/bash
# Build, deploy, and run e2e tests on testhost.
# Usage:
#   scripts/test-remote.sh                    # run all tests
#   scripts/test-remote.sh --filter bridged   # run specific tests
#   scripts/test-remote.sh --keep             # keep daemon running after tests
#   scripts/test-remote.sh --list             # list all tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"${SCRIPT_DIR}/deploy-testhost.sh"

echo ""
echo "=== Running e2e tests on testhost ==="
ssh testhost "sudo SANDBOX_E2E_POOL=/pool sandbox-e2e --sandbox-bin /usr/local/bin/sandbox $*"
