#!/bin/bash
# =============================================================================
# Stargazer NGFW — Launch Stargazer VM with two NICs (WAN + LAN)
# =============================================================================
#
# Requires:
#   1. make test-build   (builds kernel + initramfs)
#   2. sudo ./scripts/test_net_setup.sh up   (creates bridges/TAPs)
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"

UBOOT_BIN="$BUILD_DIR/u-boot/u-boot.bin"
BOOT_IMG="$BUILD_DIR/test/boot.img"
DATA_IMG="$BUILD_DIR/test/data.img"

# Pre-flight checks
fail=0
for f in "$UBOOT_BIN" "$BOOT_IMG"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: missing $f — run 'make test-build' first" >&2
        fail=1
    fi
done
for tap in tap-sg-wan tap-sg-lan; do
    if ! ip link show "$tap" &>/dev/null; then
        echo "ERROR: missing $tap — run 'sudo ./scripts/test_net_setup.sh up' first" >&2
        fail=1
    fi
done
[[ $fail -eq 0 ]] || exit 1

# Create persistent data disk if missing
if [[ ! -f "$DATA_IMG" ]]; then
    mke2fs -t ext2 -L sgdata "$DATA_IMG" 64M 2>/dev/null
    echo "Created data disk: $DATA_IMG"
fi

# U-Boot boots from boot.img (virtio0), then loads kernel+initramfs from disk
exec qemu-system-aarch64 \
    -machine virt -cpu cortex-a72 -smp 4 -m 2G \
    -bios "$UBOOT_BIN" \
    -drive file="$BOOT_IMG",format=raw,if=virtio \
    -drive file="$DATA_IMG",format=raw,if=virtio \
    -nographic \
    -netdev tap,id=wan,ifname=tap-sg-wan,script=no,downscript=no \
    -device virtio-net-pci,netdev=wan,mac=52:54:00:12:01:02 \
    -netdev tap,id=lan,ifname=tap-sg-lan,script=no,downscript=no \
    -device virtio-net-pci,netdev=lan,mac=52:54:00:12:02:fe
