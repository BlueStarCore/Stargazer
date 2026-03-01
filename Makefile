# =============================================================================
# Stargazer NGFW - Build System
# =============================================================================
#
# Build flow:
#   1. make kernel     - Build BPI-R4 kernel (if not exists)
#   2. make modules    - Build kernel modules
#   3. make busybox    - Cross-compile BusyBox for ARM64
#   4. make rootfs     - Create userspace rootfs
#   5. make image      - Create partitioned disk image for BPI-R4
#
# Quick commands:
#   make all           - Build everything
#   make test          - Test in QEMU
#   make clean         - Clean all artifacts
#
# =============================================================================

# Cross-compile settings for BPI-R4 (ARM64)
ARCH           := arm64
CROSS_COMPILE  := aarch64-linux-gnu-

# Paths
PROJECT_ROOT   := $(CURDIR)
BUILD_DIR      := $(PROJECT_ROOT)/build
KERNEL_DIR     := $(PROJECT_ROOT)/kernel
MODULE_DIR     := $(PROJECT_ROOT)/src/modules
USERSPACE_DIR  := $(PROJECT_ROOT)/src/userspace
ROOTFS_DIR     := $(BUILD_DIR)/rootfs

# Version management - single source of truth
VERSION        := $(shell cat $(PROJECT_ROOT)/VERSION)

# Kernel settings
KERNEL_REPO    := https://github.com/BlueStarCore/BPI-Router-Linux
KERNEL_BRANCH  := stargazer/6.12-main
KERNEL_IMAGE   := $(BUILD_DIR)/kernel.img
KERNEL_DTB     := $(BUILD_DIR)/bpi-r4.dtb

# Output
ISO_FILE       := $(BUILD_DIR)/stargazer-bpi-r4-$(VERSION).iso
IMG_FILE       := $(BUILD_DIR)/stargazer-bpi-r4-$(VERSION).img
MODULE_NAME    := pkt_forward

# BusyBox settings
BUSYBOX_REPO   := https://git.busybox.net/busybox
BUSYBOX_TAG    := 1_36_1
BUSYBOX_CACHE_DIR := $(PROJECT_ROOT)/.cache
BUSYBOX_DIR    := $(BUSYBOX_CACHE_DIR)/busybox-src
BUSYBOX_BIN    := $(BUILD_DIR)/busybox/busybox
BUSYBOX_LINKS  := $(BUSYBOX_DIR)/busybox.links

# Dash shell settings (replaces BusyBox ash as /bin/sh)
DASH_VERSION   := 0.5.12
DASH_URL       := http://gondor.apana.org.au/~herbert/dash/files/dash-$(DASH_VERSION).tar.gz
DASH_DIR       := $(BUSYBOX_CACHE_DIR)/dash-src
DASH_BIN       := $(BUILD_DIR)/dash/dash

# iptables settings (cross-compiled from netfilter.org; BusyBox has no iptables applet)
LIBMNL_VERSION := 1.0.5
LIBMNL_URL     := https://netfilter.org/projects/libmnl/files/libmnl-$(LIBMNL_VERSION).tar.bz2
LIBMNL_DIR     := $(BUSYBOX_CACHE_DIR)/libmnl-$(LIBMNL_VERSION)
IPTABLES_VERSION := 1.8.10
IPTABLES_URL   := https://netfilter.org/projects/iptables/files/iptables-$(IPTABLES_VERSION).tar.xz
IPTABLES_DIR   := $(BUSYBOX_CACHE_DIR)/iptables-$(IPTABLES_VERSION)
IPTABLES_BIN   := $(BUILD_DIR)/iptables/iptables

# Logind / C helpers
LOGIND_DIR     := $(PROJECT_ROOT)/src/userspace/logind

# mgmtd (management daemon + IPC client)
MGMTD_DIR      := $(PROJECT_ROOT)/src/userspace/mgmtd

# CLI (C binary replacing shell stargazer-cli for interactive mode)
CLI_DIR        := $(PROJECT_ROOT)/src/userspace/cli

# Musl cross toolchain (for clean static linking — no glibc NSS issues)
# Auto-downloaded from musl.cc on first build
MUSL_CROSS_URL := https://musl.cc/aarch64-linux-musl-cross.tgz
MUSL_CROSS_DIR := $(BUSYBOX_CACHE_DIR)/aarch64-linux-musl-cross
MUSL_CC        := $(MUSL_CROSS_DIR)/bin/aarch64-linux-musl-gcc
MUSL_CROSS     := $(MUSL_CROSS_DIR)/bin/aarch64-linux-musl-

# U-Boot bootloader (pre-built from Ubuntu u-boot-qemu package)
UBOOT_DEB_URL  := http://archive.ubuntu.com/ubuntu/pool/main/u/u-boot/u-boot-qemu_2022.01+dfsg-2ubuntu2.7_all.deb
UBOOT_BIN      := $(BUILD_DIR)/u-boot/u-boot.bin

# Source watch: any .c/.h/Makefile change under src/ triggers rebuild.
# Sub-Makefiles have fine-grained deps; this just ensures they get invoked.
SRC_WATCH := $(shell find $(PROJECT_ROOT)/src -name '*.c' -o -name '*.h' -o -name 'Makefile' -o -name 'Kbuild' 2>/dev/null)

# =============================================================================
# Main targets
# =============================================================================

.PHONY: all kernel modules busybox musl-toolchain dash iptables logind mgmtd cli uboot rootfs iso image firmware test-build test test-run lanvm clean help

all: image

# =============================================================================
# 1. Kernel
# =============================================================================

kernel: $(KERNEL_IMAGE)

$(KERNEL_IMAGE): | kernel-source kernel-config
	@echo "[1/5] Building kernel..."
	$(MAKE) -C $(KERNEL_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) olddefconfig
	$(MAKE) -C $(KERNEL_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -j$$(nproc) Image dtbs modules
	@mkdir -p $(BUILD_DIR)
	cp $(KERNEL_DIR)/arch/$(ARCH)/boot/Image $(KERNEL_IMAGE)
	cp $(KERNEL_DIR)/arch/$(ARCH)/boot/dts/mediatek/mt7988a-bananapi-bpi-r4.dtb $(KERNEL_DTB) 2>/dev/null || true
	@echo "[1/5] Kernel ready: $(KERNEL_IMAGE)"

kernel-source:
	@if [ ! -d "$(KERNEL_DIR)" ]; then \
		echo "Cloning kernel source..."; \
		git clone --depth 1 -b $(KERNEL_BRANCH) $(KERNEL_REPO) $(KERNEL_DIR); \
	fi

kernel-config:
	@if [ ! -f "$(KERNEL_DIR)/.config" ]; then \
		echo "Configuring kernel..."; \
		$(MAKE) -C $(KERNEL_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) defconfig; \
		$(KERNEL_DIR)/scripts/config --file $(KERNEL_DIR)/.config \
			--enable NETFILTER --enable NF_CONNTRACK \
			--enable NF_CT_NETLINK \
			--enable IP_NF_RAW \
			--enable NETFILTER_XT_TARGET_CT \
			--module NF_CONNTRACK_TFTP \
			--module NF_NAT_TFTP \
			--enable VIRTIO --enable VIRTIO_PCI --enable VIRTIO_NET \
			--enable VIRTIO_BLK --enable VIRTIO_MMIO \
			--enable MODULES --enable MODULE_UNLOAD \
			--enable EXT4_FS --enable SQUASHFS; \
		$(MAKE) -C $(KERNEL_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) olddefconfig; \
	fi

# =============================================================================
# 2. Modules
# =============================================================================

modules: $(BUILD_DIR)/modules/$(MODULE_NAME).ko

$(BUILD_DIR)/modules/$(MODULE_NAME).ko: $(KERNEL_IMAGE) $(SRC_WATCH)
	@echo "[2/5] Building modules..."
	$(MAKE) -C $(KERNEL_DIR) M=$(MODULE_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules KBUILD_MODPOST_WARN=1
	@mkdir -p $(BUILD_DIR)/modules
	cp $(MODULE_DIR)/*.ko $(BUILD_DIR)/modules/
	# Copy netfilter conntrack helper modules (TFTP etc.)
	@for m in nf_conntrack_tftp.ko nf_nat_tftp.ko; do \
		[ -f $(KERNEL_DIR)/net/netfilter/$$m ] && \
		cp $(KERNEL_DIR)/net/netfilter/$$m $(BUILD_DIR)/modules/ || true; \
	done
	@echo "[2/5] Module ready: $@"

# =============================================================================
# 3. BusyBox (cross-compile from source)
# =============================================================================

busybox: $(BUSYBOX_BIN) $(BUSYBOX_LINKS)

$(BUSYBOX_BIN):
	@echo "[3/5] Building BusyBox..."
	@if [ ! -d "$(BUSYBOX_DIR)" ]; then \
		mkdir -p "$(BUSYBOX_CACHE_DIR)"; \
		echo "Cloning BusyBox source..."; \
		git clone --depth 1 -b $(BUSYBOX_TAG) $(BUSYBOX_REPO) $(BUSYBOX_DIR); \
	else \
		echo "Updating BusyBox source..."; \
		git -C $(BUSYBOX_DIR) fetch --tags --prune origin >/dev/null 2>&1 || true; \
		if git -C $(BUSYBOX_DIR) rev-parse --verify "refs/tags/$(BUSYBOX_TAG)" >/dev/null 2>&1; then \
			git -C $(BUSYBOX_DIR) checkout -f "$(BUSYBOX_TAG)" >/dev/null 2>&1 || true; \
			git -C $(BUSYBOX_DIR) reset --hard "refs/tags/$(BUSYBOX_TAG)" >/dev/null 2>&1 || true; \
		else \
			git -C $(BUSYBOX_DIR) checkout -f "$(BUSYBOX_TAG)" >/dev/null 2>&1 || true; \
			git -C $(BUSYBOX_DIR) reset --hard "origin/$(BUSYBOX_TAG)" >/dev/null 2>&1 || true; \
		fi; \
	fi
	$(MAKE) -C $(BUSYBOX_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) defconfig
	@sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/' $(BUSYBOX_DIR)/.config
	@sed -i 's/# CONFIG_TFTP is not set/CONFIG_TFTP=y/' $(BUSYBOX_DIR)/.config
	@sed -i 's/# CONFIG_FEATURE_TFTP_GET is not set/CONFIG_FEATURE_TFTP_GET=y/' $(BUSYBOX_DIR)/.config
	@sed -i 's/# CONFIG_FEATURE_TFTP_BLOCKSIZE is not set/CONFIG_FEATURE_TFTP_BLOCKSIZE=y/' $(BUSYBOX_DIR)/.config
	@sed -i 's/# CONFIG_TRACEROUTE is not set/CONFIG_TRACEROUTE=y/' $(BUSYBOX_DIR)/.config
	@sed -i 's/# CONFIG_NSLOOKUP is not set/CONFIG_NSLOOKUP=y/' $(BUSYBOX_DIR)/.config
	@sed -i 's/# CONFIG_ARPING is not set/CONFIG_ARPING=y/' $(BUSYBOX_DIR)/.config
	# --- Hardening: disable shell applets (prevent shell escape) ---
	@sed -i 's/CONFIG_ASH=y/CONFIG_ASH=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_HUSH=y/CONFIG_HUSH=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_SH_IS_ASH=y/CONFIG_SH_IS_NONE=y/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_BASH_IS_ASH=y/CONFIG_BASH_IS_NONE=y/' $(BUSYBOX_DIR)/.config
	# --- Hardening: disable dangerous interactive/server applets ---
	@sed -i 's/CONFIG_VI=y/CONFIG_VI=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_LESS=y/CONFIG_LESS=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_ED=y/CONFIG_ED=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_FTPD=y/CONFIG_FTPD=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_HTTPD=y/CONFIG_HTTPD=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_TELNETD=y/CONFIG_TELNETD=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_TFTPD=y/CONFIG_TFTPD=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_SU=y/CONFIG_SU=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_LOGIN=y/CONFIG_LOGIN=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_PASSWD=y/CONFIG_PASSWD=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_ADDUSER=y/CONFIG_ADDUSER=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_DELUSER=y/CONFIG_DELUSER=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_ADDGROUP=y/CONFIG_ADDGROUP=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_DELGROUP=y/CONFIG_DELGROUP=n/' $(BUSYBOX_DIR)/.config
	# Resolve Kconfig dependencies after hardening changes
	yes "" | $(MAKE) -C $(BUSYBOX_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) oldconfig
	$(MAKE) -C $(BUSYBOX_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -j$$(nproc)
	$(MAKE) -C $(BUSYBOX_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) busybox.links
	@mkdir -p $(BUILD_DIR)/busybox
	cp $(BUSYBOX_DIR)/busybox $(BUSYBOX_BIN)
	@echo "[3/5] BusyBox ready: $(BUSYBOX_BIN)"

$(BUSYBOX_LINKS):
	@if [ ! -d "$(BUSYBOX_DIR)" ]; then \
		mkdir -p "$(BUSYBOX_CACHE_DIR)"; \
		echo "Cloning BusyBox source..."; \
		git clone --depth 1 -b $(BUSYBOX_TAG) $(BUSYBOX_REPO) $(BUSYBOX_DIR); \
	fi
	$(MAKE) -C $(BUSYBOX_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) defconfig
	@sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/' $(BUSYBOX_DIR)/.config
	@sed -i 's/# CONFIG_TFTP is not set/CONFIG_TFTP=y/' $(BUSYBOX_DIR)/.config
	@sed -i 's/# CONFIG_FEATURE_TFTP_GET is not set/CONFIG_FEATURE_TFTP_GET=y/' $(BUSYBOX_DIR)/.config
	@sed -i 's/# CONFIG_FEATURE_TFTP_BLOCKSIZE is not set/CONFIG_FEATURE_TFTP_BLOCKSIZE=y/' $(BUSYBOX_DIR)/.config
	@sed -i 's/# CONFIG_TRACEROUTE is not set/CONFIG_TRACEROUTE=y/' $(BUSYBOX_DIR)/.config
	@sed -i 's/# CONFIG_NSLOOKUP is not set/CONFIG_NSLOOKUP=y/' $(BUSYBOX_DIR)/.config
	@sed -i 's/# CONFIG_ARPING is not set/CONFIG_ARPING=y/' $(BUSYBOX_DIR)/.config
	# --- Hardening: disable shell applets (prevent shell escape) ---
	@sed -i 's/CONFIG_ASH=y/CONFIG_ASH=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_HUSH=y/CONFIG_HUSH=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_SH_IS_ASH=y/CONFIG_SH_IS_NONE=y/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_BASH_IS_ASH=y/CONFIG_BASH_IS_NONE=y/' $(BUSYBOX_DIR)/.config
	# --- Hardening: disable dangerous interactive/server applets ---
	@sed -i 's/CONFIG_VI=y/CONFIG_VI=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_LESS=y/CONFIG_LESS=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_ED=y/CONFIG_ED=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_FTPD=y/CONFIG_FTPD=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_HTTPD=y/CONFIG_HTTPD=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_TELNETD=y/CONFIG_TELNETD=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_TFTPD=y/CONFIG_TFTPD=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_SU=y/CONFIG_SU=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_LOGIN=y/CONFIG_LOGIN=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_PASSWD=y/CONFIG_PASSWD=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_ADDUSER=y/CONFIG_ADDUSER=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_DELUSER=y/CONFIG_DELUSER=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_ADDGROUP=y/CONFIG_ADDGROUP=n/' $(BUSYBOX_DIR)/.config
	@sed -i 's/CONFIG_DELGROUP=y/CONFIG_DELGROUP=n/' $(BUSYBOX_DIR)/.config
	# Resolve Kconfig dependencies after hardening changes
	yes "" | $(MAKE) -C $(BUSYBOX_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) oldconfig
	$(MAKE) -C $(BUSYBOX_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) busybox.links

# =============================================================================
# 3b. Musl cross toolchain (auto-download)
# =============================================================================

musl-toolchain: $(MUSL_CC)

$(MUSL_CC):
	@echo "[3b/5] Downloading musl cross toolchain..."
	@mkdir -p "$(BUSYBOX_CACHE_DIR)"
	@if [ ! -x "$(MUSL_CC)" ]; then \
		curl -fSL "$(MUSL_CROSS_URL)" -o "$(BUSYBOX_CACHE_DIR)/musl-cross.tgz"; \
		tar -xzf "$(BUSYBOX_CACHE_DIR)/musl-cross.tgz" -C "$(BUSYBOX_CACHE_DIR)"; \
		rm -f "$(BUSYBOX_CACHE_DIR)/musl-cross.tgz"; \
		echo "[3b/5] Musl toolchain ready: $(MUSL_CROSS_DIR)"; \
	fi

# =============================================================================
# 3c. Dash shell (cross-compile with musl for clean static linking)
# =============================================================================

dash: $(DASH_BIN)

$(DASH_BIN): $(MUSL_CC)
	@echo "[3c/5] Building dash shell (musl static)..."
	@mkdir -p "$(BUSYBOX_CACHE_DIR)"
	@if [ ! -d "$(DASH_DIR)" ]; then \
		echo "Downloading dash $(DASH_VERSION) source..."; \
		curl -fSL "$(DASH_URL)" -o "$(BUSYBOX_CACHE_DIR)/dash-$(DASH_VERSION).tar.gz"; \
		mkdir -p "$(DASH_DIR)"; \
		tar -xzf "$(BUSYBOX_CACHE_DIR)/dash-$(DASH_VERSION).tar.gz" -C "$(DASH_DIR)" --strip-components=1; \
		rm -f "$(BUSYBOX_CACHE_DIR)/dash-$(DASH_VERSION).tar.gz"; \
	fi
	@if [ -f "$(DASH_DIR)/Makefile" ]; then \
		$(MAKE) -C $(DASH_DIR) distclean 2>/dev/null || true; \
	fi
	cd $(DASH_DIR) && ./configure --host=aarch64-linux-musl \
		CC=$(MUSL_CC) CFLAGS="-Os -static" LDFLAGS="-static"
	# Fix CC_FOR_BUILD: configure copies the cross compiler but
	# helper tools (mknodes, mksyntax, mksignames) must run on host.
	sed -i 's|^CC_FOR_BUILD = .*|CC_FOR_BUILD = gcc|' $(DASH_DIR)/src/Makefile
	$(MAKE) -C $(DASH_DIR) -j$$(nproc)
	@mkdir -p $(BUILD_DIR)/dash
	cp $(DASH_DIR)/src/dash $(DASH_BIN)
	@echo "[3c/5] Dash ready: $(DASH_BIN)"

# =============================================================================
# 3d. iptables (cross-compile from netfilter.org with musl)
#     BusyBox has no iptables applet — we build the real one.
#     Depends on libmnl (small netfilter netlink library).
# =============================================================================

iptables: $(IPTABLES_BIN)

$(IPTABLES_BIN): $(MUSL_CC)
	@echo "[3d/5] Building iptables (musl static)..."
	@mkdir -p "$(BUSYBOX_CACHE_DIR)" $(BUILD_DIR)/iptables
	# --- Build libmnl (iptables dependency) ---
	@if [ ! -d "$(LIBMNL_DIR)" ]; then \
		echo "Downloading libmnl $(LIBMNL_VERSION)..."; \
		curl -fSL "$(LIBMNL_URL)" -o "$(BUSYBOX_CACHE_DIR)/libmnl-$(LIBMNL_VERSION).tar.bz2"; \
		tar -xjf "$(BUSYBOX_CACHE_DIR)/libmnl-$(LIBMNL_VERSION).tar.bz2" -C "$(BUSYBOX_CACHE_DIR)"; \
		rm -f "$(BUSYBOX_CACHE_DIR)/libmnl-$(LIBMNL_VERSION).tar.bz2"; \
	fi
	@if [ ! -f "$(LIBMNL_DIR)/src/.libs/libmnl.a" ]; then \
		cd $(LIBMNL_DIR) && ./configure --host=aarch64-linux-musl \
			CC=$(MUSL_CC) CFLAGS="-Os" LDFLAGS="-static" \
			--enable-static --disable-shared --prefix=$(BUILD_DIR)/iptables/libmnl-prefix && \
		$(MAKE) -C $(LIBMNL_DIR) -j$$(nproc) && \
		$(MAKE) -C $(LIBMNL_DIR) install; \
	fi
	# --- Build iptables (legacy backend only, no nftables) ---
	@if [ ! -d "$(IPTABLES_DIR)" ]; then \
		echo "Downloading iptables $(IPTABLES_VERSION)..."; \
		curl -fSL "$(IPTABLES_URL)" -o "$(BUSYBOX_CACHE_DIR)/iptables-$(IPTABLES_VERSION).tar.xz"; \
		tar -xJf "$(BUSYBOX_CACHE_DIR)/iptables-$(IPTABLES_VERSION).tar.xz" -C "$(BUSYBOX_CACHE_DIR)"; \
		rm -f "$(BUSYBOX_CACHE_DIR)/iptables-$(IPTABLES_VERSION).tar.xz"; \
	fi
	@if [ -f "$(IPTABLES_DIR)/Makefile" ]; then \
		$(MAKE) -C $(IPTABLES_DIR) distclean 2>/dev/null || true; \
	fi
	cd $(IPTABLES_DIR) && ./configure --host=aarch64-linux-musl \
		CC=$(MUSL_CC) \
		CFLAGS="-Os -static" \
		LDFLAGS="-static" \
		libmnl_CFLAGS="-I$(BUILD_DIR)/iptables/libmnl-prefix/include" \
		libmnl_LIBS="-L$(BUILD_DIR)/iptables/libmnl-prefix/lib -lmnl" \
		--enable-static --disable-shared \
		--disable-nftables \
		--prefix=/usr
	# Force fully-static binary: -all-static is a libtool flag (not gcc),
	# so we inject it after configure into AM_LDFLAGS.
	sed -i 's/^AM_LDFLAGS = .*/& -all-static/' $(IPTABLES_DIR)/iptables/Makefile
	$(MAKE) -C $(IPTABLES_DIR) -j$$(nproc)
	cp $(IPTABLES_DIR)/iptables/xtables-legacy-multi $(IPTABLES_BIN)
	@echo "[3d/5] iptables ready: $(IPTABLES_BIN)"

# =============================================================================
# 3e. Logind + C helpers (cross-compile with musl)
# =============================================================================

logind: $(BUILD_DIR)/logind/stargazer-logind $(BUILD_DIR)/logind/stargazer-hashpw $(BUILD_DIR)/logind/stargazer-readline

$(BUILD_DIR)/logind/stargazer-logind $(BUILD_DIR)/logind/stargazer-hashpw $(BUILD_DIR)/logind/stargazer-readline: $(MUSL_CC) $(SRC_WATCH)
	@echo "[3e/5] Building logind + C helpers (musl static)..."
	@mkdir -p $(BUILD_DIR)/logind
	$(MAKE) -C $(LOGIND_DIR) \
		CROSS_COMPILE=$(MUSL_CROSS) \
		BUILD_DIR=$(BUILD_DIR)/logind
	@echo "[3e/5] Logind + helpers ready."

# =============================================================================
# 3f. mgmtd — management daemon + IPC client (cross-compile with musl)
# =============================================================================

mgmtd: $(BUILD_DIR)/mgmtd/stargazer-mgmtd $(BUILD_DIR)/mgmtd/stargazer-ipc-cli

$(BUILD_DIR)/mgmtd/stargazer-mgmtd $(BUILD_DIR)/mgmtd/stargazer-ipc-cli: $(MUSL_CC) $(SRC_WATCH)
	@echo "[3f/5] Building mgmtd + IPC client (musl static)..."
	@mkdir -p $(BUILD_DIR)/mgmtd
	$(MAKE) -C $(MGMTD_DIR) \
		CROSS_COMPILE=$(MUSL_CROSS) \
		BUILD_DIR=$(BUILD_DIR)/mgmtd
	@echo "[3f/5] mgmtd + IPC client ready."

# =============================================================================
# 3g. CLI — C binary (cross-compile with musl)
# =============================================================================

cli: $(BUILD_DIR)/cli/stargazer-cli

$(BUILD_DIR)/cli/stargazer-cli: $(MUSL_CC) $(SRC_WATCH)
	@echo "[3g/5] Building C CLI binary (musl static)..."
	@mkdir -p $(BUILD_DIR)/cli
	$(MAKE) -C $(CLI_DIR) \
		CROSS_COMPILE=$(MUSL_CROSS) \
		BUILD_DIR=$(BUILD_DIR)/cli \
		VERSION=$(VERSION)
	@echo "[3g/5] CLI binary ready."

# =============================================================================
# 3h. U-Boot bootloader (for QEMU disk-based boot)
# =============================================================================

uboot: $(UBOOT_BIN)

$(UBOOT_BIN):
	@echo "[3h/5] Fetching pre-built U-Boot for QEMU ARM64..."
	@mkdir -p $(BUILD_DIR)/u-boot
	@TMPDIR=$$(mktemp -d); \
	curl -fSL "$(UBOOT_DEB_URL)" -o "$$TMPDIR/u-boot-qemu.deb"; \
	cd "$$TMPDIR" && ar x u-boot-qemu.deb && tar xf data.tar.* 2>/dev/null; \
	cp "$$TMPDIR/usr/lib/u-boot/qemu_arm64/u-boot.bin" $(UBOOT_BIN); \
	rm -rf "$$TMPDIR"
	@echo "[3h/5] U-Boot ready: $(UBOOT_BIN)"

# =============================================================================
# 4. Rootfs (userspace)
# =============================================================================

rootfs: $(ROOTFS_DIR)/.stamp

$(ROOTFS_DIR)/.stamp: modules busybox dash iptables logind mgmtd cli
	@echo "[4/5] Creating rootfs..."
	@rm -rf $(ROOTFS_DIR)
	@mkdir -p $(ROOTFS_DIR)

	# Create filesystem structure
	@mkdir -p $(ROOTFS_DIR)/bin $(ROOTFS_DIR)/sbin
	@mkdir -p $(ROOTFS_DIR)/usr/bin $(ROOTFS_DIR)/usr/sbin
	@mkdir -p $(ROOTFS_DIR)/etc $(ROOTFS_DIR)/proc $(ROOTFS_DIR)/sys
	@mkdir -p $(ROOTFS_DIR)/dev $(ROOTFS_DIR)/tmp $(ROOTFS_DIR)/run
	@mkdir -p $(ROOTFS_DIR)/var/log $(ROOTFS_DIR)/var/run
	@mkdir -p $(ROOTFS_DIR)/root $(ROOTFS_DIR)/home

	# Install BusyBox and create applet symlinks from busybox.links
	cp $(BUSYBOX_BIN) $(ROOTFS_DIR)/bin/busybox
	@chmod +x $(ROOTFS_DIR)/bin/busybox
	@while IFS= read -r link; do \
		dir=$$(dirname "$(ROOTFS_DIR)$$link"); \
		mkdir -p "$$dir"; \
		ln -sf /bin/busybox "$(ROOTFS_DIR)$$link"; \
	done < $(BUSYBOX_DIR)/busybox.links

	# Install dash as /bin/sh (overrides BusyBox ash symlink)
	cp $(DASH_BIN) $(ROOTFS_DIR)/bin/dash
	@chmod +x $(ROOTFS_DIR)/bin/dash
	@ln -sf dash $(ROOTFS_DIR)/bin/sh

	# Install iptables (xtables-legacy-multi with symlinks)
	cp $(IPTABLES_BIN) $(ROOTFS_DIR)/sbin/xtables-legacy-multi
	@chmod +x $(ROOTFS_DIR)/sbin/xtables-legacy-multi
	@ln -sf xtables-legacy-multi $(ROOTFS_DIR)/sbin/iptables
	@ln -sf xtables-legacy-multi $(ROOTFS_DIR)/sbin/iptables-save
	@ln -sf xtables-legacy-multi $(ROOTFS_DIR)/sbin/iptables-restore

	# Install logind + C helpers
	cp $(BUILD_DIR)/logind/stargazer-logind $(ROOTFS_DIR)/sbin/
	cp $(BUILD_DIR)/logind/stargazer-hashpw $(ROOTFS_DIR)/sbin/
	cp $(BUILD_DIR)/logind/stargazer-readline $(ROOTFS_DIR)/sbin/
	@chmod +x $(ROOTFS_DIR)/sbin/stargazer-logind $(ROOTFS_DIR)/sbin/stargazer-hashpw $(ROOTFS_DIR)/sbin/stargazer-readline

	# Install mgmtd + IPC client
	cp $(BUILD_DIR)/mgmtd/stargazer-mgmtd $(ROOTFS_DIR)/sbin/
	cp $(BUILD_DIR)/mgmtd/stargazer-ipc-cli $(ROOTFS_DIR)/sbin/
	@chmod +x $(ROOTFS_DIR)/sbin/stargazer-mgmtd $(ROOTFS_DIR)/sbin/stargazer-ipc-cli

	# Install C CLI binary as primary CLI
	cp $(BUILD_DIR)/cli/stargazer-cli $(ROOTFS_DIR)/sbin/stargazer-cli
	@chmod +x $(ROOTFS_DIR)/sbin/stargazer-cli

	# Create /sbin/nologin stub (blocks direct root login)
	@printf '#!/bin/sh\necho "Direct login disabled."\nexit 1\n' > $(ROOTFS_DIR)/sbin/nologin
	@chmod +x $(ROOTFS_DIR)/sbin/nologin

	# Create minimal /etc files (no Alpine branding)
	@echo 'root:x:0:0:root:/root:/sbin/nologin' > $(ROOTFS_DIR)/etc/passwd
	@echo 'nobody:x:65534:65534:nobody:/:/bin/false' >> $(ROOTFS_DIR)/etc/passwd
	@echo 'root:x:0:root' > $(ROOTFS_DIR)/etc/group
	@echo 'nobody:x:65534:' >> $(ROOTFS_DIR)/etc/group
	@echo 'root:*:19700:0:99999:7:::' > $(ROOTFS_DIR)/etc/shadow
	@echo 'nobody:*:19700:0:99999:7:::' >> $(ROOTFS_DIR)/etc/shadow
	@chmod 640 $(ROOTFS_DIR)/etc/shadow
	@echo 'stargazer' > $(ROOTFS_DIR)/etc/hostname
	@printf '127.0.0.1\tlocalhost\n::1\t\tlocalhost\n' > $(ROOTFS_DIR)/etc/hosts
	@printf '/sbin/stargazer-cli\n' > $(ROOTFS_DIR)/etc/shells

	# Install kernel modules
	@mkdir -p $(ROOTFS_DIR)/lib/modules
	cp -r $(BUILD_DIR)/modules $(ROOTFS_DIR)/lib/modules/stargazer

	# Copy etc configuration (modules-load.d, sysctl.d, init.d)
	@mkdir -p $(ROOTFS_DIR)/etc/modules-load.d
	@mkdir -p $(ROOTFS_DIR)/etc/sysctl.d
	@mkdir -p $(ROOTFS_DIR)/etc/init.d
	@cp $(USERSPACE_DIR)/etc/modules-load.d/*.conf $(ROOTFS_DIR)/etc/modules-load.d/
	@cp $(USERSPACE_DIR)/etc/sysctl.d/*.conf $(ROOTFS_DIR)/etc/sysctl.d/
	@cp $(USERSPACE_DIR)/etc/init.d/* $(ROOTFS_DIR)/etc/init.d/
	@chmod +x $(ROOTFS_DIR)/etc/init.d/*

	# Copy init script with version substitution
	@cp $(USERSPACE_DIR)/init $(ROOTFS_DIR)/init.tmp
	@sed -i 's/@VERSION@/$(VERSION)/g' $(ROOTFS_DIR)/init.tmp
	@mv $(ROOTFS_DIR)/init.tmp $(ROOTFS_DIR)/init
	@chmod +x $(ROOTFS_DIR)/init

	# Copy login script
	@cp $(USERSPACE_DIR)/sbin/stargazer-login $(ROOTFS_DIR)/sbin/
	@chmod +x $(ROOTFS_DIR)/sbin/stargazer-login

	# Copy CLI command scripts
	@mkdir -p $(ROOTFS_DIR)/usr/libexec/stargazer
	@cp $(USERSPACE_DIR)/usr/libexec/stargazer/* $(ROOTFS_DIR)/usr/libexec/stargazer/
	@chmod +x $(ROOTFS_DIR)/usr/libexec/stargazer/*

	# Install udhcpc default script (for DHCP network configuration)
	@mkdir -p $(ROOTFS_DIR)/usr/share/udhcpc
	@cp $(USERSPACE_DIR)/usr/share/udhcpc/default.script $(ROOTFS_DIR)/usr/share/udhcpc/
	@chmod +x $(ROOTFS_DIR)/usr/share/udhcpc/default.script

	# Create stargazer config directory (mgmtd seeds defaults on first boot)
	@mkdir -p $(ROOTFS_DIR)/etc/stargazer

	@touch $@
	@echo "[4/5] Rootfs ready: $(ROOTFS_DIR)"

# =============================================================================
# 5. ISO Image
# =============================================================================

iso: $(ISO_FILE)

$(ISO_FILE): $(ROOTFS_DIR)/.stamp
	@echo "[5/5] Creating ISO image..."
	@mkdir -p $(BUILD_DIR)/iso/boot

	# Copy kernel
	cp $(KERNEL_IMAGE) $(BUILD_DIR)/iso/boot/kernel
	@if [ -f "$(KERNEL_DTB)" ]; then cp $(KERNEL_DTB) $(BUILD_DIR)/iso/boot/; fi

	# Create initramfs from rootfs
	cd $(ROOTFS_DIR) && find . | sort | cpio -o -H newc 2>/dev/null | gzip -n -9 > $(BUILD_DIR)/iso/boot/initramfs.gz

	# Create ISO (for UEFI boot on BPI-R4)
	@if command -v xorriso >/dev/null 2>&1; then \
		xorriso -as mkisofs \
			-o $(ISO_FILE) \
			-iso-level 3 \
			-full-iso9660-filenames \
			$(BUILD_DIR)/iso; \
	else \
		echo "[WARN] xorriso not found, creating tar archive instead"; \
		tar -czf $(BUILD_DIR)/stargazer-bpi-r4-$(VERSION).tar.gz -C $(BUILD_DIR)/iso .; \
	fi

	@echo ""
	@echo "============================================"
	@echo " Build Complete!"
	@echo "============================================"
	@echo " Kernel:   $(KERNEL_IMAGE)"
	@echo " Modules:  $(BUILD_DIR)/modules/"
	@echo " BusyBox:  $(BUSYBOX_BIN)"
	@echo " Dash:     $(DASH_BIN)"
	@echo " Logind:   $(BUILD_DIR)/logind/"
	@echo " mgmtd:    $(BUILD_DIR)/mgmtd/"
	@echo " CLI:      $(BUILD_DIR)/cli/"
	@echo " Rootfs:   $(ROOTFS_DIR)"
	@echo " Image:    $(ISO_FILE)"
	@echo ""
	@echo " Deploy to BPI-R4:"
	@echo "   dd if=$(ISO_FILE) of=/dev/sdX bs=4M"
	@echo "============================================"

# =============================================================================
# Disk Image (for real hardware — persistent config partition)
# =============================================================================

image: rootfs
	@echo "[5/5] Creating disk image with persistent storage..."
	@mkdir -p $(BUILD_DIR)/image/boot/extlinux

	# Prepare boot partition contents (with extlinux.conf for U-Boot)
	cp $(KERNEL_IMAGE) $(BUILD_DIR)/image/boot/kernel
	@if [ -f "$(KERNEL_DTB)" ]; then cp $(KERNEL_DTB) $(BUILD_DIR)/image/boot/; fi
	cd $(ROOTFS_DIR) && find . | sort | cpio -o -H newc 2>/dev/null | gzip -n -9 > $(BUILD_DIR)/image/boot/initramfs.gz
	cp $(USERSPACE_DIR)/boot/extlinux.conf $(BUILD_DIR)/image/boot/extlinux/extlinux.conf

	# Create boot partition image (64MB ext2, populated with kernel+initramfs+extlinux)
	mke2fs -t ext2 -L boot -d $(BUILD_DIR)/image/boot \
		$(BUILD_DIR)/image/boot.img 64M 2>/dev/null

	# Create data partition image (512MB ext2, empty)
	mke2fs -t ext2 -L sgdata $(BUILD_DIR)/image/data.img 512M 2>/dev/null

	# Assemble: empty image → GPT → partitions
	# Boot: 64MB (131072 sectors), Data: 512MB (1048576 sectors), 1MB GPT header
	dd if=/dev/zero of=$(IMG_FILE) bs=1M count=578 2>/dev/null
	printf 'label: gpt\nfirst-lba: 2048\n\n' > $(BUILD_DIR)/image/sfdisk.script
	printf 'start=2048, size=131072, type=linux, name="boot"\n' >> $(BUILD_DIR)/image/sfdisk.script
	printf 'start=133120, size=1048576, type=linux, name="data"\n' >> $(BUILD_DIR)/image/sfdisk.script
	sfdisk $(IMG_FILE) < $(BUILD_DIR)/image/sfdisk.script
	dd if=$(BUILD_DIR)/image/boot.img of=$(IMG_FILE) bs=512 seek=2048 conv=notrunc 2>/dev/null
	dd if=$(BUILD_DIR)/image/data.img of=$(IMG_FILE) bs=512 seek=133120 conv=notrunc 2>/dev/null

	@echo ""
	@echo "============================================"
	@echo " Build Complete!"
	@echo "============================================"
	@echo " Image: $(IMG_FILE)"
	@echo ""
	@echo " Deploy to BPI-R4 SD/eMMC:"
	@echo "   dd if=$(IMG_FILE) of=/dev/mmcblk0 bs=4M status=progress"
	@echo "============================================"

# =============================================================================
# Firmware upgrade package (for in-place upgrades on running devices)
# =============================================================================

FW_PKG := $(BUILD_DIR)/stargazer-fw-$(VERSION).tar.gz

firmware: rootfs
	@echo "Building firmware upgrade package..."
	@mkdir -p $(BUILD_DIR)/firmware
	cp $(KERNEL_IMAGE) $(BUILD_DIR)/firmware/kernel
	cd $(ROOTFS_DIR) && find . | sort | cpio -o -H newc 2>/dev/null | gzip -n -9 > $(BUILD_DIR)/firmware/initramfs.gz
	@# Generate manifest with checksums
	@KSHA=$$(sha256sum $(BUILD_DIR)/firmware/kernel | cut -d' ' -f1); \
	ISHA=$$(sha256sum $(BUILD_DIR)/firmware/initramfs.gz | cut -d' ' -f1); \
	printf 'version=%s\nbuild_date=%s\nkernel_sha256=%s\ninitramfs_sha256=%s\n' \
		"$(VERSION)" "$$(date -u +%Y-%m-%dT%H:%M:%S)" "$$KSHA" "$$ISHA" \
		> $(BUILD_DIR)/firmware/manifest.txt
	@# Package into tar.gz
	cd $(BUILD_DIR)/firmware && tar -czf $(FW_PKG) manifest.txt kernel initramfs.gz
	@# Clean staging
	@rm -rf $(BUILD_DIR)/firmware
	@echo ""
	@echo "============================================"
	@echo " Firmware Package Ready"
	@echo "============================================"
	@echo " Package: $(FW_PKG)"
	@echo " Version: $(VERSION)"
	@echo ""
	@echo " Deploy: host on HTTP server, then on device:"
	@echo "   execute firmware upgrade http://<server>/stargazer-fw-$(VERSION).tar.gz"
	@echo "============================================"

# =============================================================================
# Test in QEMU
# =============================================================================

test-build: modules busybox dash iptables logind mgmtd cli uboot
	@echo "Building test initramfs..."
	@mkdir -p $(BUILD_DIR)/test

	# Create minimal initramfs for testing
	@rm -rf $(BUILD_DIR)/test/initramfs
	@mkdir -p $(BUILD_DIR)/test/initramfs

	# Create filesystem structure
	@mkdir -p $(BUILD_DIR)/test/initramfs/bin $(BUILD_DIR)/test/initramfs/sbin
	@mkdir -p $(BUILD_DIR)/test/initramfs/usr/bin $(BUILD_DIR)/test/initramfs/usr/sbin
	@mkdir -p $(BUILD_DIR)/test/initramfs/etc $(BUILD_DIR)/test/initramfs/proc
	@mkdir -p $(BUILD_DIR)/test/initramfs/sys $(BUILD_DIR)/test/initramfs/dev
	@mkdir -p $(BUILD_DIR)/test/initramfs/tmp $(BUILD_DIR)/test/initramfs/run
	@mkdir -p $(BUILD_DIR)/test/initramfs/var/log $(BUILD_DIR)/test/initramfs/var/run
	@mkdir -p $(BUILD_DIR)/test/initramfs/root $(BUILD_DIR)/test/initramfs/home

	# Install BusyBox and create applet symlinks from busybox.links
	cp $(BUSYBOX_BIN) $(BUILD_DIR)/test/initramfs/bin/busybox
	@chmod +x $(BUILD_DIR)/test/initramfs/bin/busybox
	@while IFS= read -r link; do \
		dir=$$(dirname "$(BUILD_DIR)/test/initramfs$$link"); \
		mkdir -p "$$dir"; \
		ln -sf /bin/busybox "$(BUILD_DIR)/test/initramfs$$link"; \
	done < $(BUSYBOX_DIR)/busybox.links

	# Install dash as /bin/sh (overrides BusyBox ash symlink)
	cp $(DASH_BIN) $(BUILD_DIR)/test/initramfs/bin/dash
	@chmod +x $(BUILD_DIR)/test/initramfs/bin/dash
	@ln -sf dash $(BUILD_DIR)/test/initramfs/bin/sh

	# Install logind + C helpers
	cp $(BUILD_DIR)/logind/stargazer-logind $(BUILD_DIR)/test/initramfs/sbin/
	cp $(BUILD_DIR)/logind/stargazer-hashpw $(BUILD_DIR)/test/initramfs/sbin/
	cp $(BUILD_DIR)/logind/stargazer-readline $(BUILD_DIR)/test/initramfs/sbin/
	@chmod +x $(BUILD_DIR)/test/initramfs/sbin/stargazer-logind $(BUILD_DIR)/test/initramfs/sbin/stargazer-hashpw $(BUILD_DIR)/test/initramfs/sbin/stargazer-readline

	# Install mgmtd + IPC client
	cp $(BUILD_DIR)/mgmtd/stargazer-mgmtd $(BUILD_DIR)/test/initramfs/sbin/
	cp $(BUILD_DIR)/mgmtd/stargazer-ipc-cli $(BUILD_DIR)/test/initramfs/sbin/
	@chmod +x $(BUILD_DIR)/test/initramfs/sbin/stargazer-mgmtd $(BUILD_DIR)/test/initramfs/sbin/stargazer-ipc-cli

	# Install C CLI binary as primary CLI
	cp $(BUILD_DIR)/cli/stargazer-cli $(BUILD_DIR)/test/initramfs/sbin/stargazer-cli
	@chmod +x $(BUILD_DIR)/test/initramfs/sbin/stargazer-cli

	# Install iptables (xtables-legacy-multi with symlinks)
	cp $(IPTABLES_BIN) $(BUILD_DIR)/test/initramfs/sbin/xtables-legacy-multi
	@chmod +x $(BUILD_DIR)/test/initramfs/sbin/xtables-legacy-multi
	@ln -sf xtables-legacy-multi $(BUILD_DIR)/test/initramfs/sbin/iptables
	@ln -sf xtables-legacy-multi $(BUILD_DIR)/test/initramfs/sbin/iptables-save
	@ln -sf xtables-legacy-multi $(BUILD_DIR)/test/initramfs/sbin/iptables-restore

	# Create /sbin/nologin stub (blocks direct root login)
	@printf '#!/bin/sh\necho "Direct login disabled."\nexit 1\n' > $(BUILD_DIR)/test/initramfs/sbin/nologin
	@chmod +x $(BUILD_DIR)/test/initramfs/sbin/nologin

	# Create minimal /etc files
	@echo 'root:x:0:0:root:/root:/sbin/nologin' > $(BUILD_DIR)/test/initramfs/etc/passwd
	@echo 'nobody:x:65534:65534:nobody:/:/bin/false' >> $(BUILD_DIR)/test/initramfs/etc/passwd
	@echo 'root:x:0:root' > $(BUILD_DIR)/test/initramfs/etc/group
	@echo 'nobody:x:65534:' >> $(BUILD_DIR)/test/initramfs/etc/group
	@echo 'root:*:19700:0:99999:7:::' > $(BUILD_DIR)/test/initramfs/etc/shadow
	@echo 'nobody:*:19700:0:99999:7:::' >> $(BUILD_DIR)/test/initramfs/etc/shadow
	@chmod 640 $(BUILD_DIR)/test/initramfs/etc/shadow
	@echo 'stargazer' > $(BUILD_DIR)/test/initramfs/etc/hostname
	@printf '127.0.0.1\tlocalhost\n::1\t\tlocalhost\n' > $(BUILD_DIR)/test/initramfs/etc/hosts
	@printf '/sbin/stargazer-cli\n' > $(BUILD_DIR)/test/initramfs/etc/shells

	# Install kernel modules
	@mkdir -p $(BUILD_DIR)/test/initramfs/lib/modules/stargazer
	cp $(BUILD_DIR)/modules/*.ko $(BUILD_DIR)/test/initramfs/lib/modules/stargazer/

	# Copy init script with version substitution
	@cp $(USERSPACE_DIR)/init $(BUILD_DIR)/test/initramfs/init.tmp
	@sed -i 's/@VERSION@/$(VERSION)/g' $(BUILD_DIR)/test/initramfs/init.tmp
	@mv $(BUILD_DIR)/test/initramfs/init.tmp $(BUILD_DIR)/test/initramfs/init
	@chmod +x $(BUILD_DIR)/test/initramfs/init

	# Copy etc configuration (init.d, modules-load.d, sysctl.d)
	@mkdir -p $(BUILD_DIR)/test/initramfs/etc/init.d
	@mkdir -p $(BUILD_DIR)/test/initramfs/etc/modules-load.d
	@mkdir -p $(BUILD_DIR)/test/initramfs/etc/sysctl.d
	@cp $(USERSPACE_DIR)/etc/init.d/* $(BUILD_DIR)/test/initramfs/etc/init.d/
	@chmod +x $(BUILD_DIR)/test/initramfs/etc/init.d/*
	@cp $(USERSPACE_DIR)/etc/modules-load.d/*.conf $(BUILD_DIR)/test/initramfs/etc/modules-load.d/
	@cp $(USERSPACE_DIR)/etc/sysctl.d/*.conf $(BUILD_DIR)/test/initramfs/etc/sysctl.d/

	# Copy login script
	@cp $(USERSPACE_DIR)/sbin/stargazer-login $(BUILD_DIR)/test/initramfs/sbin/
	@chmod +x $(BUILD_DIR)/test/initramfs/sbin/stargazer-login

	# Copy CLI command scripts
	@mkdir -p $(BUILD_DIR)/test/initramfs/usr/libexec/stargazer
	@cp $(USERSPACE_DIR)/usr/libexec/stargazer/* $(BUILD_DIR)/test/initramfs/usr/libexec/stargazer/
	@chmod +x $(BUILD_DIR)/test/initramfs/usr/libexec/stargazer/*

	# Install udhcpc default script (for DHCP network configuration)
	@mkdir -p $(BUILD_DIR)/test/initramfs/usr/share/udhcpc
	@cp $(USERSPACE_DIR)/usr/share/udhcpc/default.script $(BUILD_DIR)/test/initramfs/usr/share/udhcpc/
	@chmod +x $(BUILD_DIR)/test/initramfs/usr/share/udhcpc/default.script

	# Create stargazer config directory (mgmtd seeds defaults on first boot)
	@mkdir -p $(BUILD_DIR)/test/initramfs/etc/stargazer

	# Pack initramfs
	cd $(BUILD_DIR)/test/initramfs && find . | sort | cpio -o -H newc 2>/dev/null | gzip -n -9 > $(BUILD_DIR)/test/initramfs.gz
	@echo "Test initramfs ready: $(BUILD_DIR)/test/initramfs.gz"

	# Create persistent data disk for QEMU (only if not already present)
	@if [ ! -f $(BUILD_DIR)/test/data.img ]; then \
		mke2fs -t ext2 -L sgdata $(BUILD_DIR)/test/data.img 64M 2>/dev/null; \
		echo "Test data disk created: $(BUILD_DIR)/test/data.img"; \
	else \
		echo "Test data disk exists (preserving config): $(BUILD_DIR)/test/data.img"; \
	fi

	# Create boot partition disk (with MBR so U-Boot distro boot finds it)
	@mkdir -p $(BUILD_DIR)/test/boot-contents/extlinux
	cp $(KERNEL_IMAGE) $(BUILD_DIR)/test/boot-contents/kernel
	cd $(BUILD_DIR)/test/initramfs && find . | sort | cpio -o -H newc 2>/dev/null | gzip -n -9 > $(BUILD_DIR)/test/boot-contents/initramfs.gz
	cp $(USERSPACE_DIR)/boot/extlinux.conf $(BUILD_DIR)/test/boot-contents/extlinux/extlinux.conf
	mke2fs -t ext2 -L boot -d $(BUILD_DIR)/test/boot-contents \
		$(BUILD_DIR)/test/boot-fs.img 64M 2>/dev/null
	@# Wrap filesystem in a partitioned image (1MB MBR + 64MB partition)
	dd if=/dev/zero of=$(BUILD_DIR)/test/boot.img bs=1M count=65 2>/dev/null
	printf 'start=2048, type=linux\n' | sfdisk $(BUILD_DIR)/test/boot.img >/dev/null 2>&1
	dd if=$(BUILD_DIR)/test/boot-fs.img of=$(BUILD_DIR)/test/boot.img \
		bs=512 seek=2048 conv=notrunc 2>/dev/null
	@rm -f $(BUILD_DIR)/test/boot-fs.img
	@rm -rf $(BUILD_DIR)/test/boot-contents
	@echo "Test boot disk created: $(BUILD_DIR)/test/boot.img"

	# TFTP directory for QEMU built-in TFTP server (firmware testing)
	@mkdir -p $(BUILD_DIR)/test/tftp

test: test-build
	@$(MAKE) --no-print-directory test-run

test-run:
	@if [ ! -f $(UBOOT_BIN) ]; then \
		echo "Error: u-boot.bin not found, run 'make test-build' first"; exit 1; \
	fi
	@if [ ! -f $(BUILD_DIR)/test/boot.img ]; then \
		echo "Error: boot.img not found, run 'make test-build' first"; exit 1; \
	fi
	@if [ ! -f $(BUILD_DIR)/test/data.img ]; then \
		mke2fs -t ext2 -L sgdata $(BUILD_DIR)/test/data.img 64M 2>/dev/null; \
		echo "Test data disk created: $(BUILD_DIR)/test/data.img"; \
	fi
	# Run QEMU — U-Boot loads kernel+initramfs from boot.img (virtio0)
	qemu-system-aarch64 \
		-machine virt -cpu cortex-a72 -smp 4 -m 2G \
		-bios $(UBOOT_BIN) \
		-drive file=$(BUILD_DIR)/test/boot.img,format=raw,if=virtio \
		-drive file=$(BUILD_DIR)/test/data.img,format=raw,if=virtio \
		-netdev user,id=net0,hostfwd=tcp::2222-:22,net=10.0.1.0/24,host=10.0.1.1,tftp=$(BUILD_DIR)/test/tftp \
		-device virtio-net-device,netdev=net0 \
		-nographic

# =============================================================================
# LAN VM (minimal BusyBox client for network testing)
# =============================================================================

lanvm: busybox dash
	@echo "Building LAN VM initramfs..."
	@rm -rf $(BUILD_DIR)/lanvm/initramfs
	@mkdir -p $(BUILD_DIR)/lanvm/initramfs

	# Minimal filesystem
	@mkdir -p $(BUILD_DIR)/lanvm/initramfs/bin
	@mkdir -p $(BUILD_DIR)/lanvm/initramfs/sbin
	@mkdir -p $(BUILD_DIR)/lanvm/initramfs/etc
	@mkdir -p $(BUILD_DIR)/lanvm/initramfs/proc
	@mkdir -p $(BUILD_DIR)/lanvm/initramfs/sys
	@mkdir -p $(BUILD_DIR)/lanvm/initramfs/dev
	@mkdir -p $(BUILD_DIR)/lanvm/initramfs/tmp

	# Install BusyBox and create applet symlinks
	cp $(BUSYBOX_BIN) $(BUILD_DIR)/lanvm/initramfs/bin/busybox
	@chmod +x $(BUILD_DIR)/lanvm/initramfs/bin/busybox
	@while IFS= read -r link; do \
		dir=$$(dirname "$(BUILD_DIR)/lanvm/initramfs$$link"); \
		mkdir -p "$$dir"; \
		ln -sf /bin/busybox "$(BUILD_DIR)/lanvm/initramfs$$link"; \
	done < $(BUSYBOX_DIR)/busybox.links

	# Install dash as /bin/sh
	cp $(DASH_BIN) $(BUILD_DIR)/lanvm/initramfs/bin/dash
	@chmod +x $(BUILD_DIR)/lanvm/initramfs/bin/dash
	@ln -sf dash $(BUILD_DIR)/lanvm/initramfs/bin/sh

	# Install LAN VM init script
	@cp $(USERSPACE_DIR)/lanvm/init $(BUILD_DIR)/lanvm/initramfs/init
	@chmod +x $(BUILD_DIR)/lanvm/initramfs/init

	# Pack initramfs
	cd $(BUILD_DIR)/lanvm/initramfs && find . | sort | cpio -o -H newc 2>/dev/null | gzip -n -9 > $(BUILD_DIR)/lanvm/initramfs.gz
	@echo "LAN VM initramfs ready: $(BUILD_DIR)/lanvm/initramfs.gz"

# =============================================================================
# Utilities
# =============================================================================

clean:
	@echo "Cleaning (preserving kernel)..."
	$(MAKE) -C $(MODULE_DIR) clean 2>/dev/null || true
	$(MAKE) -C $(LOGIND_DIR) clean BUILD_DIR=$(BUILD_DIR)/logind 2>/dev/null || true
	$(MAKE) -C $(MGMTD_DIR) clean BUILD_DIR=$(BUILD_DIR)/mgmtd 2>/dev/null || true
	$(MAKE) -C $(CLI_DIR) clean BUILD_DIR=$(BUILD_DIR)/cli 2>/dev/null || true
	@# Remove build subdirectories but keep kernel.img
	rm -rf $(BUILD_DIR)/busybox $(BUILD_DIR)/cli $(BUILD_DIR)/dash \
	       $(BUILD_DIR)/image $(BUILD_DIR)/iptables $(BUILD_DIR)/logind \
	       $(BUILD_DIR)/mgmtd $(BUILD_DIR)/modules $(BUILD_DIR)/rootfs \
	       $(BUILD_DIR)/test $(BUILD_DIR)/u-boot $(BUILD_DIR)/firmware
	@echo "Clean complete (kernel + source caches preserved)"

help:
	@echo "Stargazer NGFW Build System"
	@echo ""
	@echo "Build flow: kernel -> modules -> busybox/dash/logind -> rootfs -> image"
	@echo ""
	@echo "Targets:"
	@echo "  make all      - Build everything (default)"
	@echo "  make kernel   - Build BPI-R4 kernel"
	@echo "  make modules  - Build kernel modules"
	@echo "  make busybox  - Cross-compile BusyBox (system utilities)"
	@echo "  make dash     - Cross-compile dash (POSIX shell, replaces ash)"
	@echo "  make iptables - Cross-compile iptables (firewall management)"
	@echo "  make logind   - Cross-compile logind + C helpers"
	@echo "  make mgmtd    - Cross-compile mgmtd daemon + IPC client"
	@echo "  make cli      - Cross-compile C CLI binary"
	@echo "  make uboot    - Fetch pre-built U-Boot bootloader (QEMU ARM64)"
	@echo "  make rootfs   - Create userspace rootfs"
	@echo "  make iso      - Create bootable ISO"
	@echo "  make image    - Create partitioned disk image (persistent config)"
	@echo "  make firmware - Build firmware upgrade package (tar.gz)"
	@echo "  make test-build - Build test initramfs (no QEMU)"
	@echo "  make test     - Build + launch in QEMU (serial only)"
	@echo "  make test-run - Re-launch QEMU without rebuilding"
	@echo "  make lanvm    - Build LAN VM initramfs"
	@echo "  make clean    - Remove all artifacts"
	@echo "                 (keeps source caches in .cache/)"
	@echo ""
	@echo "Output: $(IMG_FILE)"
