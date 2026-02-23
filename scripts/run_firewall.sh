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

KERNEL="$BUILD_DIR/kernel.img"
INITRD="$BUILD_DIR/test/initramfs.gz"

# Pre-flight checks
fail=0
for f in "$KERNEL" "$INITRD"; do
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

exec qemu-system-aarch64 \
    -machine virt -cpu cortex-a72 -smp 4 -m 2G \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -append "console=ttyAMA0 rw" \
    -nographic -no-reboot \
    -netdev tap,id=wan,ifname=tap-sg-wan,script=no,downscript=no \
    -device virtio-net-pci,netdev=wan,mac=52:54:00:12:01:02 \
    -netdev tap,id=lan,ifname=tap-sg-lan,script=no,downscript=no \
    -device virtio-net-pci,netdev=lan,mac=52:54:00:12:02:fe
