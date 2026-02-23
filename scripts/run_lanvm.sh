#!/bin/bash
# =============================================================================
# Stargazer NGFW — Launch LAN VM (minimal BusyBox client)
# =============================================================================
#
# Requires:
#   1. make lanvm        (builds LAN VM initramfs)
#   2. sudo ./scripts/test_net_setup.sh up   (creates bridges/TAPs)
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"

KERNEL="$BUILD_DIR/kernel.img"
INITRD="$BUILD_DIR/lanvm/initramfs.gz"

# Pre-flight checks
fail=0
for f in "$KERNEL" "$INITRD"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: missing $f — run 'make lanvm' first" >&2
        fail=1
    fi
done
if ! ip link show tap-lan-vm &>/dev/null; then
    echo "ERROR: missing tap-lan-vm — run 'sudo ./scripts/test_net_setup.sh up' first" >&2
    fail=1
fi
[[ $fail -eq 0 ]] || exit 1

exec qemu-system-aarch64 \
    -machine virt -cpu cortex-a72 -smp 2 -m 512M \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -append "console=ttyAMA0 rw" \
    -nographic -no-reboot \
    -netdev tap,id=lan,ifname=tap-lan-vm,script=no,downscript=no \
    -device virtio-net-pci,netdev=lan,mac=52:54:00:12:03:64
