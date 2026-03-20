#!/bin/bash
# Bootstrap a testhost for sandbox e2e testing.
#
# Prerequisites:
#   - Ubuntu 24.04 or similar
#   - /dev/sdb available for btrfs
#   - sudo access
#
# This script is idempotent — safe to run multiple times.

set -e

echo "=== Installing packages ==="
sudo apt-get update -qq
sudo apt-get install -y -qq nftables btrfs-progs

echo "=== Setting up btrfs on /dev/sdb ==="
if ! blkid /dev/sdb 2>/dev/null | grep -q btrfs; then
    echo "  Formatting /dev/sdb as btrfs..."
    sudo mkfs.btrfs -f /dev/sdb
else
    echo "  /dev/sdb already formatted as btrfs"
fi

sudo mkdir -p /pool
if ! mountpoint -q /pool; then
    echo "  Mounting /dev/sdb at /pool..."
    sudo mount /dev/sdb /pool
else
    echo "  /pool already mounted"
fi

if ! grep -q '/pool' /etc/fstab; then
    echo "  Adding /pool to /etc/fstab..."
    echo '/dev/sdb /pool btrfs defaults 0 0' | sudo tee -a /etc/fstab
fi

echo "=== Creating directories ==="
sudo mkdir -p /run/sandbox /var/lib/sandbox/state /var/lib/sandbox/ipam

echo "=== Verifying subuid/subgid ==="
if grep -q "$(whoami)" /etc/subuid; then
    echo "  subuid configured: $(grep $(whoami) /etc/subuid)"
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

echo ""
echo "=== Bootstrap complete ==="
echo "  Pool: /pool ($(df -h /pool | tail -1 | awk '{print $2}') total)"
echo "  Filesystem: $(stat -f -c %T /pool)"
