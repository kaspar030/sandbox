#!/bin/bash
# Bootstrap a testhost for sandbox e2e testing on bcachefs.
#
# Prerequisites:
#   - Ubuntu 24.04 or similar
#   - sudo access
#
# This script:
#   1. Installs the HWE kernel (>= 6.7, which includes bcachefs)
#   2. Installs bcachefs-tools from the distro repos
#   3. Creates a 4GiB loop-backed bcachefs filesystem at /bcachepool
#
# After installing a new kernel, a REBOOT is required. Run this
# script again after rebooting to complete the setup.
#
# It is idempotent — safe to run multiple times.

set -e

MOUNT_POINT="/bcachepool"
LOOP_FILE="/var/lib/sandbox-bcachefs.img"
LOOP_SIZE="4G"

# bcachefs was merged in kernel 6.7
MIN_KERNEL="6.7"

## ── Step 1: Ensure kernel >= 6.7 with bcachefs module ──────────

current_kernel=$(uname -r | cut -d- -f1)
echo "=== Kernel check ==="
echo "  Running: $(uname -r)"

version_ge() {
    # Returns 0 if $1 >= $2 (dot-separated version compare)
    printf '%s\n%s' "$2" "$1" | sort -V -C
}

if ! version_ge "$current_kernel" "$MIN_KERNEL"; then
    echo "  Kernel $current_kernel < $MIN_KERNEL — installing HWE kernel..."
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        linux-image-generic-hwe-24.04 \
        linux-headers-generic-hwe-24.04
    echo ""
    echo "  *** HWE kernel installed. Please REBOOT and re-run this script. ***"
    echo "  Run: sudo reboot"
    exit 0
fi

echo "  Kernel $current_kernel >= $MIN_KERNEL — OK"

# Ensure linux-modules-extra is installed (contains bcachefs.ko)
MODULES_EXTRA="linux-modules-extra-$(uname -r)"
if ! dpkg -l "$MODULES_EXTRA" &>/dev/null; then
    echo "  Installing $MODULES_EXTRA..."
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$MODULES_EXTRA"
fi

## ── Step 2: Install bcachefs-tools ─────────────────────────────
# The Ubuntu 24.04 bcachefs-tools (1.3.x) is too old for the 6.17
# kernel. Install the upstream version from apt.bcachefs.org.
# The upstream .deb requires liburcu >= 0.15 but Ubuntu 24.04 only
# has 0.14; this works fine at runtime so we use --force-depends.

echo "=== Installing packages ==="
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables

BCACHEFS_TOOLS_VER="1.36.1"
BCACHEFS_TOOLS_URL="https://apt.bcachefs.org/unstable/pool/main/b/bcachefs-tools/bcachefs-tools_${BCACHEFS_TOOLS_VER}_amd64.deb"

installed_ver=$(bcachefs version 2>/dev/null || echo "none")
if [ "$installed_ver" != "$BCACHEFS_TOOLS_VER" ]; then
    echo "  Installing bcachefs-tools ${BCACHEFS_TOOLS_VER} from upstream..."
    DEB_PATH="/tmp/bcachefs-tools_${BCACHEFS_TOOLS_VER}_amd64.deb"
    wget -qO "$DEB_PATH" "$BCACHEFS_TOOLS_URL"
    # liburcu 0.14 works at runtime despite 0.15 being declared
    sudo DEBIAN_FRONTEND=noninteractive dpkg --force-depends -i "$DEB_PATH"
    rm -f "$DEB_PATH"
else
    echo "  bcachefs-tools ${BCACHEFS_TOOLS_VER} already installed"
fi

echo "=== Loading bcachefs module ==="
if ! lsmod | grep -q "^bcachefs"; then
    sudo modprobe bcachefs
    echo "  bcachefs module loaded"
else
    echo "  bcachefs module already loaded"
fi

## ── Step 3: Create loop-backed bcachefs filesystem ─────────────

echo "=== Setting up bcachefs filesystem ==="
if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
    echo "  $MOUNT_POINT already mounted"
else
    if [ ! -f "$LOOP_FILE" ]; then
        echo "  Creating ${LOOP_SIZE} loop file at ${LOOP_FILE}..."
        sudo truncate -s "$LOOP_SIZE" "$LOOP_FILE"
        echo "  Formatting as bcachefs..."
        sudo bcachefs format --force "$LOOP_FILE"
    else
        echo "  Loop file ${LOOP_FILE} already exists"
    fi

    sudo mkdir -p "$MOUNT_POINT"
    echo "  Mounting at $MOUNT_POINT..."
    sudo mount -t bcachefs "$LOOP_FILE" "$MOUNT_POINT"
fi

# Add fstab entry if not present
if ! grep -q "$MOUNT_POINT" /etc/fstab; then
    echo "  Adding $MOUNT_POINT to /etc/fstab..."
    echo "$LOOP_FILE $MOUNT_POINT bcachefs defaults,nofail 0 0" \
        | sudo tee -a /etc/fstab
fi

## ── Step 4: Verify setup ───────────────────────────────────────

echo "=== Creating directories ==="
sudo mkdir -p /run/sandbox /var/lib/sandbox/state /var/lib/sandbox/ipam

echo "=== Verifying subuid/subgid ==="
if grep -q "$(whoami)" /etc/subuid; then
    echo "  subuid configured: $(grep "$(whoami)" /etc/subuid)"
else
    echo "  WARNING: no subuid entry for $(whoami)"
fi
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

echo "=== Checking bcachefs ==="
echo "  bcachefs version: $(bcachefs version 2>/dev/null || echo unknown)"
echo "  kernel module: $(modinfo -F vermagic bcachefs 2>/dev/null | cut -d' ' -f1)"
echo "  mount: $(mount | grep bcachefs | head -1)"

echo ""
echo "=== Bootstrap complete ==="
echo "  Pool: $MOUNT_POINT (${LOOP_SIZE})"
echo "  Filesystem: bcachefs"
echo "  Kernel: $(uname -r)"
echo ""
echo "  To run e2e tests with bcachefs:"
echo "    SANDBOX_E2E_POOL=$MOUNT_POINT scripts/test-remote.sh"
