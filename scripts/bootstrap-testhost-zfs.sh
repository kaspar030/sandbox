#!/bin/bash
# Bootstrap a testhost for sandbox e2e testing on ZFS.
#
# Prerequisites:
#   - Ubuntu 24.04 or similar
#   - sudo access
#
# This script creates a 4GiB loop-backed ZFS pool at /zpool.
# It is idempotent — safe to run multiple times.

set -e

POOL_NAME="sandbox"
POOL_MOUNT="/zpool"
LOOP_FILE="/var/lib/sandbox-zfs.img"
LOOP_SIZE="4G"

echo "=== Installing packages ==="
sudo apt-get update -qq
sudo apt-get install -y -qq nftables zfsutils-linux

echo "=== Setting up ZFS pool ==="
if zpool list "$POOL_NAME" &>/dev/null; then
    echo "  Pool '$POOL_NAME' already exists"
else
    # Create the loop file if it doesn't exist
    if [ ! -f "$LOOP_FILE" ]; then
        echo "  Creating ${LOOP_SIZE} loop file at ${LOOP_FILE}..."
        sudo truncate -s "$LOOP_SIZE" "$LOOP_FILE"
    else
        echo "  Loop file ${LOOP_FILE} already exists"
    fi

    echo "  Creating ZFS pool '$POOL_NAME' on ${LOOP_FILE}..."
    sudo zpool create -f \
        -o ashift=12 \
        -O mountpoint="$POOL_MOUNT" \
        -O acltype=posixacl \
        -O xattr=sa \
        -O dnodesize=auto \
        -O compression=lz4 \
        -O normalization=formD \
        -O relatime=on \
        "$POOL_NAME" "$LOOP_FILE"
fi

# Verify pool is mounted
if ! mountpoint -q "$POOL_MOUNT"; then
    echo "  ERROR: $POOL_MOUNT is not a mountpoint"
    echo "  Trying to import pool..."
    sudo zpool import "$POOL_NAME" || true
fi

echo "=== Creating directories ==="
sudo mkdir -p /run/sandbox /var/lib/sandbox/state /var/lib/sandbox/ipam

echo "=== Verifying subuid/subgid ==="
if grep -q "$(whoami)" /etc/subuid; then
    echo "  subuid configured: $(grep "$(whoami)" /etc/subuid)"
else
    echo "  WARNING: no subuid entry for $(whoami)"
fi
# Ensure root has subuid/subgid (needed when daemon runs via sudo)
if ! grep -q "^root:" /etc/subuid; then
    echo "root:100000:65536" | sudo tee -a /etc/subuid
    echo "  Added root to /etc/subuid"
fi
if ! grep -q "^root:" /etc/subgid; then
    echo "root:100000:65536" | sudo tee -a /etc/subgid
    echo "  Added root to /etc/subgid"
fi

echo "=== Checking nft ==="
if command -v nft &>/dev/null; then
    echo "  nft available: $(nft --version)"
else
    echo "  WARNING: nft not found"
fi

echo "=== Checking ZFS ==="
echo "  zfs version: $(zfs version 2>/dev/null | head -1)"
echo "  pool status:"
zpool list "$POOL_NAME"

echo ""
echo "=== Bootstrap complete ==="
echo "  Pool: $POOL_MOUNT ($(zpool list -H -o size "$POOL_NAME") total)"
echo "  Filesystem: zfs"
echo ""
echo "  To run e2e tests with ZFS:"
echo "    SANDBOX_E2E_POOL=$POOL_MOUNT scripts/test-remote.sh"
