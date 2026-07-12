#!/bin/bash
#
# Build full BPI-R4 kernel image for QEMU and hardware deployment
# Output: build/bpi-r4-kernel.img (for QEMU/hardware)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
KDIR="${PROJECT_ROOT}/../stargazer-kernel"
BUILD_DIR="${PROJECT_ROOT}/build"
KERNEL_IMAGE="${BUILD_DIR}/bpi-r4-kernel.img"

ARCH=arm64
CROSS_COMPILE=aarch64-linux-gnu-

log_info() { echo "[INFO] $*"; }
log_warn() { echo "[WARN] $*"; }
log_error() { echo "[ERROR] $*" >&2; exit 1; }

# Check dependencies
for cmd in make gcc ${CROSS_COMPILE}gcc bc bison flex; do
    command -v "$cmd" >/dev/null || log_error "Missing: $cmd"
done

# Ensure kernel source exists
if [ ! -d "$KDIR" ]; then
    log_error "BPI-R4 kernel not found: $KDIR\nRun: make kernel-source"
fi

cd "$KDIR"

# Configure kernel if needed
if [ ! -f .config ]; then
    log_info "Creating kernel config..."
    make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE defconfig
fi

# Enable essential options for Stargazer
log_info "Enabling kernel features for Stargazer NGFW..."
scripts/config --enable CONFIG_MODULES
scripts/config --enable CONFIG_NETFILTER
scripts/config --enable CONFIG_NETFILTER_ADVANCED
scripts/config --enable CONFIG_NF_CONNTRACK
scripts/config --enable CONFIG_NETFILTER_XTABLES
scripts/config --enable CONFIG_IP_NF_IPTABLES
scripts/config --enable CONFIG_IP_NF_FILTER
scripts/config --enable CONFIG_IP_NF_NAT
scripts/config --enable CONFIG_IP_NF_MANGLE
scripts/config --enable CONFIG_IPV6
scripts/config --enable CONFIG_IP6_NF_IPTABLES

# ipset — backs FQDN address objects: mgmtd keeps one hash:ip set per
# fqdn object (refreshed via DNS), iptables matches it with -m set.
# Built-in (=y), not =m: the flat /lib/modules/stargazer loader has no
# dependency resolution and the data plane must not depend on load order.
scripts/config --enable CONFIG_IP_SET
scripts/config --set-val CONFIG_IP_SET_MAX 256
scripts/config --enable CONFIG_IP_SET_HASH_IP
scripts/config --enable CONFIG_NETFILTER_XT_SET

# QEMU virtio drivers
log_info "Enabling QEMU/KVM virtio drivers..."
scripts/config --enable CONFIG_VIRTIO
scripts/config --enable CONFIG_VIRTIO_PCI
scripts/config --enable CONFIG_VIRTIO_MMIO
scripts/config --enable CONFIG_VIRTIO_BLK
scripts/config --enable CONFIG_VIRTIO_NET
scripts/config --enable CONFIG_VIRTIO_CONSOLE

# Filesystems for testing
scripts/config --enable CONFIG_EXT4_FS
scripts/config --enable CONFIG_TMPFS
scripts/config --enable CONFIG_DEVTMPFS
scripts/config --enable CONFIG_DEVTMPFS_MOUNT

# Apply config changes
make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE olddefconfig

# Build kernel
log_info "Building BPI-R4 kernel (this takes 30-60 minutes)..."
log_info "CPU cores: $(nproc)"

time make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE -j$(nproc) Image dtbs modules

# Copy kernel image
mkdir -p "$BUILD_DIR"
cp arch/arm64/boot/Image "$KERNEL_IMAGE"

# Copy device trees
mkdir -p "${BUILD_DIR}/dtbs"
cp arch/arm64/boot/dts/mediatek/mt7988a-bananapi-bpi-r4.dtb "${BUILD_DIR}/dtbs/" 2>/dev/null || true

log_info ""
log_info "=== Kernel Build Complete ==="
log_info "Kernel image: $KERNEL_IMAGE ($(du -h "$KERNEL_IMAGE" | cut -f1))"
log_info "Device trees: ${BUILD_DIR}/dtbs/"
log_info ""
log_info "This kernel can be used for:"
log_info "  1. QEMU testing (make qemu-test)"
log_info "  2. BPI-R4 hardware deployment"
