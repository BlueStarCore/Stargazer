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
IMG_FILE       := $(BUILD_DIR)/stargazer-bpi-r4-EMMC-$(VERSION).img
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

# BPI-R4 eMMC bootloader (built from mtk-openwrt ATF/U-Boot source)
# BL2 (EMMC_BOOT header): written to eMMC boot0 HW partition (mmcblk0boot0).
#   eMMC is 8GTF4R 7.28GiB with boot0/boot1 partitions (HS400 mode).
#   Boot ROM reads BL2 from boot0 when DIP switch selects eMMC.
# FIP (BL31 + U-Boot): written to GPT "fip" partition.
# Built by 'make bpi-r4-bootloader' or automatically by 'make image'
BPIR4_BL2        := $(BUILD_DIR)/bpi-r4/bl2_emmc_mtk.img
BPIR4_FIP        := $(BUILD_DIR)/bpi-r4/fip_emmc_mtk.bin

# BPI-R4 NAND bootloader header (BL2 + env + factory + FIP, first 0x780000 bytes)
# Extracted from stock MTK NAND image. UBI partition starts right after.
BPIR4_NAND_BOOT  := $(BUILD_DIR)/bpi-r4/nand_bootloader.bin

# ubinize from mtd-utils (extracted without root — see .cache/mtd-utils-extracted/)
UBINIZE          := $(PROJECT_ROOT)/.cache/mtd-utils-extracted/usr/sbin/ubinize
UBINIZE_LDPATH   := $(PROJECT_ROOT)/.cache/mtd-utils-extracted/usr/lib/x86_64-linux-gnu

# Source watch: any .c/.h/Makefile change under src/ triggers rebuild.
# Sub-Makefiles have fine-grained deps; this just ensures they get invoked.
SRC_WATCH := $(shell find $(PROJECT_ROOT)/src -name '*.c' -o -name '*.h' -o -name 'Makefile' -o -name 'Kbuild' 2>/dev/null)

# =============================================================================
# Main targets
# =============================================================================

.PHONY: all kernel modules busybox musl-toolchain dash iptables logind mgmtd cli tools uboot bpi-r4-bootloader rootfs iso nand-fit nand-image image firmware test-build test test-run lanvm clean help

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
	# Merge eMMC overlay into base DTB (eMMC controller is disabled in base DTS)
	@cp $(KERNEL_DIR)/arch/$(ARCH)/boot/dts/mediatek/mt7988a-bananapi-bpi-r4.dtb $(KERNEL_DTB).base 2>/dev/null || true
	@if [ -f "$(KERNEL_DTB).base" ] && [ -f "$(KERNEL_DIR)/arch/$(ARCH)/boot/dts/mediatek/mt7988a-bananapi-bpi-r4-emmc.dtbo" ]; then \
		fdtoverlay -i $(KERNEL_DTB).base -o $(KERNEL_DTB) \
			$(KERNEL_DIR)/arch/$(ARCH)/boot/dts/mediatek/mt7988a-bananapi-bpi-r4-emmc.dtbo; \
		echo "  DTB: merged eMMC overlay"; \
	else \
		cp $(KERNEL_DTB).base $(KERNEL_DTB) 2>/dev/null || true; \
	fi
	@rm -f $(KERNEL_DTB).base
	@echo "[1/5] Kernel ready: $(KERNEL_IMAGE)"

kernel-source:
	@if [ ! -d "$(KERNEL_DIR)" ]; then \
		echo "Cloning kernel source..."; \
		git clone --depth 1 -b $(KERNEL_BRANCH) $(KERNEL_REPO) $(KERNEL_DIR); \
	fi

kernel-config:
	@if [ ! -f "$(KERNEL_DIR)/.config" ]; then \
		echo "Configuring kernel for BPI-R4 (MT7988A)..."; \
		$(MAKE) -C $(KERNEL_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) mt7988a_bpi-r4_defconfig; \
		$(KERNEL_DIR)/scripts/config --file $(KERNEL_DIR)/.config \
			--enable NETFILTER \
			--enable NF_CONNTRACK \
			--enable NF_NAT \
			--enable NF_DEFRAG_IPV4 \
			--enable NF_DEFRAG_IPV6 \
			--enable IP_NF_IPTABLES \
			--enable IP_NF_FILTER \
			--enable IP_NF_NAT \
			--enable IP_NF_MANGLE \
			--enable IP_NF_TARGET_MASQUERADE \
			--enable IP_NF_TARGET_REJECT \
			--enable IP_NF_RAW \
			--enable IP6_NF_IPTABLES \
			--enable IP6_NF_FILTER \
			--enable IP6_NF_NAT \
			--enable IP6_NF_MANGLE \
			--enable IP6_NF_TARGET_MASQUERADE \
			--enable IP6_NF_TARGET_REJECT \
			--enable NETFILTER_XT_TARGET_CT \
			--enable NETFILTER_XT_MATCH_CONNTRACK \
			--enable NETFILTER_XT_MATCH_STATE \
			--enable NETFILTER_XT_MATCH_LIMIT \
			--enable NETFILTER_XT_TARGET_LOG \
			--enable NETFILTER_XT_TARGET_CHECKSUM \
			--enable NETFILTER_XT_MARK \
			--enable NETFILTER_XT_CONNMARK \
			--enable NF_LOG_IPV4 \
			--enable NF_REJECT_IPV4 \
			--enable NF_LOG_IPV6 \
			--enable NF_REJECT_IPV6 \
			--enable NF_CT_NETLINK \
			--module NF_CONNTRACK_TFTP \
			--module NF_NAT_TFTP \
			--module NF_FLOW_TABLE \
			--module NF_FLOW_TABLE_INET \
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
	$(MAKE) -C $(KERNEL_DIR) M=$(MODULE_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) \
		KCFLAGS='-DPKT_FWD_VERSION="\"$(VERSION)\"" -DSESS_VERSION="\"$(VERSION)\""' \
		modules KBUILD_MODPOST_WARN=1
	@mkdir -p $(BUILD_DIR)/modules
	cp $(MODULE_DIR)/*.ko $(BUILD_DIR)/modules/
	# Copy netfilter helper/offload modules (TFTP, flow offload)
	@for m in nf_conntrack_tftp.ko nf_nat_tftp.ko nf_flow_table.ko nf_flow_table_inet.ko; do \
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
		CC=$(MUSL_CC) CFLAGS="-Os -static -no-pie" LDFLAGS="-static -no-pie"
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
# 3h. Tools (sg-partinit — first-boot partition creator)
# =============================================================================

TOOLS_DIR := $(PROJECT_ROOT)/src/userspace/tools

tools: $(BUILD_DIR)/tools/sg-partinit

$(BUILD_DIR)/tools/sg-partinit: $(MUSL_CC) $(TOOLS_DIR)/sg-partinit.c
	@echo "[3h/5] Building tools (musl static)..."
	@mkdir -p $(BUILD_DIR)/tools
	$(MAKE) -C $(TOOLS_DIR) \
		CROSS_COMPILE=$(MUSL_CROSS) \
		BUILD_DIR=$(BUILD_DIR)/tools
	@echo "[3h/5] Tools ready."

# =============================================================================
# 3i. U-Boot bootloader (for QEMU disk-based boot)
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
# 3j. BPI-R4 eMMC bootloader (BL2 + FIP from ATF/U-Boot source)
# =============================================================================
# Builds ARM Trusted Firmware BL2 (eMMC preloader) and FIP (BL31 + U-Boot)
# from mtk-openwrt repos. BL2 uses EMMC_BOOT header for MT7988A boot ROM.
#
# BPI-R4 eMMC (8GTF4R 7.28GiB) has boot0/boot1 HW partitions and runs HS400.
# BL2 goes to boot0, FIP goes to GPT "fip" partition. Boot ROM reads boot0
# when DIP switch selects eMMC mode.
#
# Note: MSDC0 muxes between SD and eMMC based on DIP switch. Only one is
# visible as mmcblk0 at a time. When booted from SD, eMMC is NOT accessible.
#
# Must use MTK U-Boot (not frank-w) — frank-w U-Boot rewrites NMBM tables
# on SPI-NAND during boot, corrupting the NAND installation.
#
# Sources cached in .cache/uboot-mtk/ and .cache/atf-mtk/

UBOOT_MTK_DIR  := $(PROJECT_ROOT)/.cache/uboot-mtk
ATF_MTK_DIR    := $(PROJECT_ROOT)/.cache/atf-mtk

bpi-r4-bootloader: $(BPIR4_BL2) $(BPIR4_FIP)

# Build U-Boot for eMMC, then ATF (BL2 + FIP)
$(BPIR4_BL2) $(BPIR4_FIP): $(UBOOT_MTK_DIR)/.stamp $(ATF_MTK_DIR)/.stamp
	@echo "Building eMMC bootloader (BL2 + FIP)..."
	@mkdir -p $(BUILD_DIR)/bpi-r4
	# Build U-Boot (BL33 input for FIP)
	cd $(UBOOT_MTK_DIR) && \
		$(MAKE) mt7988_emmc_rfb_defconfig CROSS_COMPILE=$(CROSS_COMPILE) && \
		sed -i 's/CONFIG_MTK_DEFAULT_FIT_BOOT_CONF=.*/CONFIG_MTK_DEFAULT_FIT_BOOT_CONF="conf-base"/' .config && \
		sed -i 's/CONFIG_TOOLS_KWBIMAGE=y/\# CONFIG_TOOLS_KWBIMAGE is not set/' .config && \
		sed -i 's/CONFIG_TOOLS_LIBCRYPTO=y/\# CONFIG_TOOLS_LIBCRYPTO is not set/' .config && \
		$(MAKE) olddefconfig CROSS_COMPILE=$(CROSS_COMPILE) && \
		$(MAKE) CROSS_COMPILE=$(CROSS_COMPILE) -j$$(nproc)
	# Build ATF with eMMC BL2 + FIP (includes BL31 + U-Boot)
	cd $(ATF_MTK_DIR) && \
		$(MAKE) PLAT=mt7988 BOOT_DEVICE=emmc DRAM_USE_COMB=1 \
			BL33=$(UBOOT_MTK_DIR)/u-boot.bin \
			USE_MKIMAGE=1 MKIMAGE=$(UBOOT_MTK_DIR)/tools/mkimage \
			CROSS_COMPILE=$(CROSS_COMPILE) all fip -j$$(nproc)
	cp $(ATF_MTK_DIR)/build/mt7988/release/bl2.img $(BPIR4_BL2)
	cp $(ATF_MTK_DIR)/build/mt7988/release/fip.bin $(BPIR4_FIP)
	@echo "  BL2: $(BPIR4_BL2) ($$(stat -c %s $(BPIR4_BL2)) bytes)"
	@echo "  FIP: $(BPIR4_FIP) ($$(stat -c %s $(BPIR4_FIP)) bytes)"

# Clone U-Boot and ATF repos if not present
$(UBOOT_MTK_DIR)/.stamp:
	@if [ ! -d "$(UBOOT_MTK_DIR)/.git" ]; then \
		echo "Cloning mtk-openwrt/u-boot..."; \
		git clone --depth=1 https://github.com/mtk-openwrt/u-boot.git $(UBOOT_MTK_DIR); \
	fi
	@touch $@

$(ATF_MTK_DIR)/.stamp:
	@if [ ! -d "$(ATF_MTK_DIR)/.git" ]; then \
		echo "Cloning mtk-openwrt/arm-trusted-firmware..."; \
		git clone --depth=1 --branch mtksoc https://github.com/mtk-openwrt/arm-trusted-firmware.git $(ATF_MTK_DIR); \
	fi
	@touch $@

# =============================================================================
# 4. Rootfs (userspace)
# =============================================================================

rootfs: $(ROOTFS_DIR)/.stamp

$(ROOTFS_DIR)/.stamp: modules busybox dash iptables logind mgmtd cli tools
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

	# Install tools (sg-partinit — first-boot partition creator)
	cp $(BUILD_DIR)/tools/sg-partinit $(ROOTFS_DIR)/sbin/sg-partinit
	@chmod +x $(ROOTFS_DIR)/sbin/sg-partinit

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
# NAND FIT Image (for BPI-R4 SPI-NAND boot via UBI)
# =============================================================================

NAND_FIT := $(BUILD_DIR)/stargazer-nand.itb

nand-fit: rootfs
	@echo "[5/5] Building NAND FIT image..."
	@mkdir -p $(BUILD_DIR)/image/fit-nand
	cd $(ROOTFS_DIR) && find . | sort | cpio -o -H newc 2>/dev/null | gzip -n -9 > $(BUILD_DIR)/image/fit-nand/initramfs.gz
	lzma -z -k -f $(KERNEL_IMAGE) -c > $(BUILD_DIR)/image/fit-nand/Image.lzma
	# Use pre-merged DTB (base + eMMC overlay) so eMMC is accessible for sgdata
	cp $(KERNEL_DTB) $(BUILD_DIR)/image/fit-nand/bpi-r4.dtb
	# Clear stale bootargs (root=/dev/fit0 etc.) — U-Boot sets args at runtime
	fdtput -t s $(BUILD_DIR)/image/fit-nand/bpi-r4.dtb /chosen bootargs \
		"console=ttyS0,115200n1 earlycon=uart8250,mmio32,0x11000000"
	# Fix SPI-NAND partition table to match MTK SDK layout.
	# The stock DTB has UBI starting at 0x200000 (OpenWrt layout) which overlaps
	# the FIP area at 0x580000. UBI's wear leveling erases the FIP, killing boot.
	# MTK SDK layout: bl2(1M) + env(512K) + factory(4M) + fip(2M) + ubi(rest)
	@_P="$(BUILD_DIR)/image/fit-nand/bpi-r4.dtb"; \
	_PARTS="/soc/spi@11007000/spi_nand@0/partitions"; \
	fdtput -t x "$$_P" "$$_PARTS/partition@0" reg 0x0 0x100000; \
	fdtput -c "$$_P" "$$_PARTS/partition@580000" 2>/dev/null || true; \
	fdtput -t s "$$_P" "$$_PARTS/partition@580000" label "fip"; \
	fdtput -t x "$$_P" "$$_PARTS/partition@580000" reg 0x580000 0x200000; \
	fdtput -t x "$$_P" "$$_PARTS/partition@200000" reg 0x780000 0x7880000
	cp $(USERSPACE_DIR)/boot/stargazer-nand.its $(BUILD_DIR)/image/fit-nand/stargazer-nand.its
	mkimage -f $(BUILD_DIR)/image/fit-nand/stargazer-nand.its $(NAND_FIT)
	cp $(PROJECT_ROOT)/scripts/flash-nand.sh $(BUILD_DIR)/flash-nand.sh
	@echo ""
	@echo "============================================"
	@echo " NAND FIT Image Ready!"
	@echo "============================================"
	@echo " FIT:    $(NAND_FIT)"
	@echo " Script: $(BUILD_DIR)/flash-nand.sh"
	@echo " Size:   $$(du -h $(NAND_FIT) | cut -f1)"
	@echo ""
	@echo " Flash from SD card or eMMC OpenWrt:"
	@echo "   1. Copy to USB drive:"
	@echo "      stargazer-nand.itb"
	@echo "      flash-nand.sh"
	@echo "      mtk-bpi-r4-*-NAND-*.img  (stock MTK image)"
	@echo ""
	@echo "   2. Boot BPI-R4 from SD card (or eMMC)"
	@echo "   3. Mount USB:  mount /dev/sda1 /mnt"
	@echo "   4. Full flash (first time):"
	@echo "      sh /mnt/flash-nand.sh /mnt/mtk-*.img /mnt/stargazer-nand.itb"
	@echo ""
	@echo "   5. Kernel-only update (subsequent):"
	@echo "      sh /mnt/flash-nand.sh --kernel-only /mnt/stargazer-nand.itb"
	@echo "============================================"

# =============================================================================
# Complete NAND Image (dd-able, like stock MTK image)
# =============================================================================
# Layout: BL2(1MB) + env(512K) + factory(4MB) + FIP(2MB) + UBI(kernel FIT)
# Flash:  mtd erase /dev/mtd0 && dd if=stargazer-*.img of=/dev/mtdblock0
#
# Requires: NAND bootloader header extracted from stock MTK NAND image.
# One-time setup:
#   dd if=mtk-bpi-r4-*-NAND-*.img of=build/bpi-r4/nand_bootloader.bin \
#      bs=$$((0x780000)) count=1

NAND_IMG := $(BUILD_DIR)/stargazer-bpi-r4-NAND-$(VERSION).img

nand-image: nand-fit
	@echo "[6/6] Building complete NAND image..."
	@# Verify bootloader header exists
	@if [ ! -f "$(BPIR4_NAND_BOOT)" ]; then \
		echo "ERROR: NAND bootloader header not found: $(BPIR4_NAND_BOOT)"; \
		echo ""; \
		echo "Extract it from your stock MTK NAND image:"; \
		echo "  dd if=mtk-bpi-r4-*-NAND-*.img of=$(BPIR4_NAND_BOOT) bs=\$$((0x780000)) count=1"; \
		exit 1; \
	fi
	@# Verify ubinize is available
	@if [ ! -x "$(UBINIZE)" ]; then \
		echo "ERROR: ubinize not found at $(UBINIZE)"; \
		echo ""; \
		echo "Install mtd-utils (no root needed):"; \
		echo "  cd .cache && apt-get download mtd-utils libiniparser1"; \
		echo "  dpkg-deb -x mtd-utils_*.deb mtd-utils-extracted/"; \
		echo "  dpkg-deb -x libiniparser1_*.deb mtd-utils-extracted/"; \
		exit 1; \
	fi
	@# Create ubinize config (kernel volume only — config storage uses eMMC,
	@# because UBIFS on NAND gets ECC errors through the NMBM/mtdblock path)
	@printf '[kernel-vol]\nmode=ubi\nimage=stargazer-nand.itb\nvol_id=0\nvol_size=20MiB\nvol_type=dynamic\nvol_name=kernel\n' \
		> $(BUILD_DIR)/image/ubinize-nand.cfg
	@# Build UBI image (SPI-NAND: 2048B page, 128KB erase block)
	cd $(BUILD_DIR) && LD_LIBRARY_PATH="$(UBINIZE_LDPATH):$$LD_LIBRARY_PATH" \
		$(UBINIZE) -o $(BUILD_DIR)/image/ubi-nand.img \
		-m 2048 -p 128KiB -s 2048 \
		$(BUILD_DIR)/image/ubinize-nand.cfg
	@# Assemble: bootloader header (7.5MB) + UBI image
	cat $(BPIR4_NAND_BOOT) $(BUILD_DIR)/image/ubi-nand.img > $(NAND_IMG)
	@echo ""
	@echo "============================================"
	@echo " NAND Image Ready!"
	@echo "============================================"
	@echo " Image: $(NAND_IMG)"
	@echo " Size:  $$(du -h $(NAND_IMG) | cut -f1)"
	@echo ""
	@echo " Flash from SD card or eMMC:"
	@echo "   mtd erase /dev/mtd0"
	@echo "   dd if=$(notdir $(NAND_IMG)) of=/dev/mtdblock0"
	@echo "============================================"

# =============================================================================
# Disk Image (for real hardware — persistent config partition)
# =============================================================================

image: rootfs bpi-r4-bootloader
	@echo "[5/5] Creating disk image with persistent storage..."
	@mkdir -p $(BUILD_DIR)/image/fit

	# Build FIT image (kernel + DTB + initramfs in single .itb)
	# MTK U-Boot reads the "firmware" partition as a raw FIT image
	cd $(ROOTFS_DIR) && find . | sort | cpio -o -H newc 2>/dev/null | gzip -n -9 > $(BUILD_DIR)/image/fit/initramfs.gz
	lzma -z -k -f $(KERNEL_IMAGE) -c > $(BUILD_DIR)/image/fit/Image.lzma
	cp $(KERNEL_DIR)/arch/$(ARCH)/boot/dts/mediatek/mt7988a-bananapi-bpi-r4.dtb $(BUILD_DIR)/image/fit/bpi-r4.dtb
	# Clear hardcoded bootargs from base DTB (root=/dev/fit0, ubi.block etc.)
	# U-Boot sets bootargs at runtime; stale DTB args conflict with initramfs boot
	fdtput -t s $(BUILD_DIR)/image/fit/bpi-r4.dtb /chosen bootargs \
		"console=ttyS0,115200n1 earlycon=uart8250,mmio32,0x11000000"
	# Pre-merge eMMC overlay into base DTB (U-Boot lacks CONFIG_OF_LIBFDT_OVERLAY)
	@if [ -f "$(KERNEL_DIR)/arch/$(ARCH)/boot/dts/mediatek/mt7988a-bananapi-bpi-r4-emmc.dtbo" ]; then \
		echo "  Merging eMMC overlay into base DTB..."; \
		fdtoverlay -i $(BUILD_DIR)/image/fit/bpi-r4.dtb \
			-o $(BUILD_DIR)/image/fit/bpi-r4-merged.dtb \
			$(KERNEL_DIR)/arch/$(ARCH)/boot/dts/mediatek/mt7988a-bananapi-bpi-r4-emmc.dtbo; \
		mv $(BUILD_DIR)/image/fit/bpi-r4-merged.dtb $(BUILD_DIR)/image/fit/bpi-r4.dtb; \
	else \
		echo "  WARNING: eMMC overlay not found, eMMC may not be detected by kernel"; \
	fi
	# Fix SPI-NAND partition table — same fix as nand-image target.
	# Stock DTB has UBI at 0x200000, overlapping our raw FIP at 0x580000.
	# UBI wear-leveling erases the FIP area, killing NAND boot.
	# Correct: bl2(1M) + fip(0x580000,2M) + ubi(0x780000,rest)
	@_P="$(BUILD_DIR)/image/fit/bpi-r4.dtb"; \
	_PARTS="/soc/spi@11007000/spi_nand@0/partitions"; \
	fdtput -t x "$$_P" "$$_PARTS/partition@0" reg 0x0 0x100000; \
	fdtput -c "$$_P" "$$_PARTS/partition@580000" 2>/dev/null || true; \
	fdtput -t s "$$_P" "$$_PARTS/partition@580000" label "fip"; \
	fdtput -t x "$$_P" "$$_PARTS/partition@580000" reg 0x580000 0x200000; \
	fdtput -t x "$$_P" "$$_PARTS/partition@200000" reg 0x780000 0x7880000
	cp $(USERSPACE_DIR)/boot/stargazer.its $(BUILD_DIR)/image/fit/stargazer.its
	mkimage -f $(BUILD_DIR)/image/fit/stargazer.its $(BUILD_DIR)/image/bpi-r4.itb

	# Assemble: GPT + FIP + FIT only. sgdata/sglogs formatted on first boot.
	# BL2 lives in boot0 HW partition (separate dd). GPT has FIP + kernel + data.
	# Layout (verified against stock OpenWrt eMMC on BPI-R4, 8GTF4R 7.28GiB):
	#   boot0 HW partition: BL2 (EMMC_BOOT header) — flashed separately
	#   Sector 0:         Protective MBR
	#   Sector 1:         GPT header
	#   Sector 2-33:      GPT entries
	#   P1 "u-boot-env":  sector 8192   size 1024   — U-Boot saved environment
	#   P2 "factory":     sector 9216   size 8192   — factory calibration data (4MB)
	#   P3 "fip":         sector 17408  size 4096   — FIP (BL31+U-Boot), BL2 finds by name
	#   P4 "firmware":    sector 21504  size 131072 — kernel+initramfs+DTB FIT (64MB)
	#   P5 "sgdata":      sector 152576 size 1048576 — persistent config (/etc/stargazer)
	#   P6 "sglogs":      sector 1201152 size 1048576 — audit/system logs (512MB)
	truncate -s 1200M $(IMG_FILE)
	printf 'label: gpt\nfirst-lba: 34\n\n' > $(BUILD_DIR)/image/sfdisk.script
	printf 'start=8192, size=1024, type=linux, name="u-boot-env"\n' >> $(BUILD_DIR)/image/sfdisk.script
	printf 'start=9216, size=8192, type=linux, name="factory"\n' >> $(BUILD_DIR)/image/sfdisk.script
	printf 'start=17408, size=4096, type=linux, name="fip"\n' >> $(BUILD_DIR)/image/sfdisk.script
	printf 'start=21504, size=131072, type=linux, name="firmware"\n' >> $(BUILD_DIR)/image/sfdisk.script
	printf 'start=152576, size=1048576, type=linux, name="sgdata"\n' >> $(BUILD_DIR)/image/sfdisk.script
	printf 'start=1201152, size=1048576, type=linux, name="sglogs"\n' >> $(BUILD_DIR)/image/sfdisk.script
	sfdisk $(IMG_FILE) < $(BUILD_DIR)/image/sfdisk.script
	# Write FIP into partition 3 "fip"
	dd if=$(BPIR4_FIP) of=$(IMG_FILE) bs=512 seek=17408 conv=notrunc 2>/dev/null
	# Write FIT image raw into partition 4 "firmware"
	dd if=$(BUILD_DIR)/image/bpi-r4.itb of=$(IMG_FILE) bs=512 seek=21504 conv=notrunc 2>/dev/null
	# Truncate after FIT data — sgdata/sglogs are blank, init formats on first boot
	@_fit_sectors=$$(( ($$(stat -c %s $(BUILD_DIR)/image/bpi-r4.itb) + 511) / 512 )); \
	 _end_sector=$$(( 21504 + $$_fit_sectors )); \
	 truncate -s $$(( $$_end_sector * 512 )) $(IMG_FILE); \
	 echo "  IMG: truncated to $$(($$_end_sector * 512 / 1024 / 1024))MB (GPT + FIP + FIT)"

	# Copy BL2 alongside image (user writes this to mmcblk0boot0 separately)
	cp $(BPIR4_BL2) $(BUILD_DIR)/bl2_emmc.img

	@echo ""
	@echo "============================================"
	@echo " Build Complete!"
	@echo "============================================"
	@echo " Image: $(IMG_FILE)"
	@echo " BL2:   $(BUILD_DIR)/bl2_emmc.img"
	@echo " Size:  $$(du -h $(IMG_FILE) | cut -f1)"
	@echo ""
	@echo " Flash to BPI-R4 eMMC (from eMMC OpenWrt):"
	@echo "   echo 0 > /sys/block/mmcblk0boot0/force_ro"
	@echo "   dd if=bl2_emmc.img of=/dev/mmcblk0boot0"
	@echo "   dd if=$(notdir $(IMG_FILE)) of=/dev/mmcblk0 bs=4M"
	@echo "   sync && reboot -f"
	@echo "============================================"

# =============================================================================
# Firmware upgrade package (for in-place upgrades on running devices)
# =============================================================================

FW_PKG := $(BUILD_DIR)/stargazer-fw-$(VERSION).tar.gz

firmware: rootfs
	@echo "Building firmware upgrade package..."
	@mkdir -p $(BUILD_DIR)/firmware $(BUILD_DIR)/firmware/fit
	# Build FIT image (same as image target)
	cd $(ROOTFS_DIR) && find . | sort | cpio -o -H newc 2>/dev/null | gzip -n -9 > $(BUILD_DIR)/firmware/fit/initramfs.gz
	lzma -z -k -f $(KERNEL_IMAGE) -c > $(BUILD_DIR)/firmware/fit/Image.lzma
	cp $(KERNEL_DIR)/arch/$(ARCH)/boot/dts/mediatek/mt7988a-bananapi-bpi-r4.dtb $(BUILD_DIR)/firmware/fit/bpi-r4.dtb
	fdtput -t s $(BUILD_DIR)/firmware/fit/bpi-r4.dtb /chosen bootargs \
		"console=ttyS0,115200n1 earlycon=uart8250,mmio32,0x11000000"
	# Pre-merge eMMC overlay into base DTB
	@if [ -f "$(KERNEL_DIR)/arch/$(ARCH)/boot/dts/mediatek/mt7988a-bananapi-bpi-r4-emmc.dtbo" ]; then \
		fdtoverlay -i $(BUILD_DIR)/firmware/fit/bpi-r4.dtb \
			-o $(BUILD_DIR)/firmware/fit/bpi-r4-merged.dtb \
			$(KERNEL_DIR)/arch/$(ARCH)/boot/dts/mediatek/mt7988a-bananapi-bpi-r4-emmc.dtbo; \
		mv $(BUILD_DIR)/firmware/fit/bpi-r4-merged.dtb $(BUILD_DIR)/firmware/fit/bpi-r4.dtb; \
	fi
	# Fix SPI-NAND partition table (same as image/nand-image targets)
	@_P="$(BUILD_DIR)/firmware/fit/bpi-r4.dtb"; \
	_PARTS="/soc/spi@11007000/spi_nand@0/partitions"; \
	fdtput -t x "$$_P" "$$_PARTS/partition@0" reg 0x0 0x100000; \
	fdtput -c "$$_P" "$$_PARTS/partition@580000" 2>/dev/null || true; \
	fdtput -t s "$$_P" "$$_PARTS/partition@580000" label "fip"; \
	fdtput -t x "$$_P" "$$_PARTS/partition@580000" reg 0x580000 0x200000; \
	fdtput -t x "$$_P" "$$_PARTS/partition@200000" reg 0x780000 0x7880000
	cp $(USERSPACE_DIR)/boot/stargazer.its $(BUILD_DIR)/firmware/fit/stargazer.its
	mkimage -f $(BUILD_DIR)/firmware/fit/stargazer.its $(BUILD_DIR)/firmware/stargazer.itb
	@# Generate manifest with FIT checksum
	@FSHA=$$(sha256sum $(BUILD_DIR)/firmware/stargazer.itb | cut -d' ' -f1); \
	printf 'version=%s\nbuild_date=%s\nfit_sha256=%s\n' \
		"$(VERSION)" "$$(date -u +%Y-%m-%dT%H:%M:%S)" "$$FSHA" \
		> $(BUILD_DIR)/firmware/manifest.txt
	@# Package into tar.gz
	cd $(BUILD_DIR)/firmware && tar -czf $(FW_PKG) manifest.txt stargazer.itb
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

test-build: modules busybox dash iptables logind mgmtd cli tools uboot
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

	# Install tools (sg-partinit — first-boot partition creator)
	cp $(BUILD_DIR)/tools/sg-partinit $(BUILD_DIR)/test/initramfs/sbin/sg-partinit
	@chmod +x $(BUILD_DIR)/test/initramfs/sbin/sg-partinit

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

	# Create persistent logs disk for QEMU (only if not already present)
	@if [ ! -f $(BUILD_DIR)/test/logs.img ]; then \
		mke2fs -t ext2 -L sglogs $(BUILD_DIR)/test/logs.img 64M 2>/dev/null; \
		echo "Test logs disk created: $(BUILD_DIR)/test/logs.img"; \
	else \
		echo "Test logs disk exists (preserving logs): $(BUILD_DIR)/test/logs.img"; \
	fi

	# Create boot partition disk (with MBR so U-Boot distro boot finds it)
	@mkdir -p $(BUILD_DIR)/test/boot-contents/extlinux
	cp $(KERNEL_IMAGE) $(BUILD_DIR)/test/boot-contents/kernel
	cd $(BUILD_DIR)/test/initramfs && find . | sort | cpio -o -H newc 2>/dev/null | gzip -n -9 > $(BUILD_DIR)/test/boot-contents/initramfs.gz
	cp $(USERSPACE_DIR)/boot/extlinux.conf $(BUILD_DIR)/test/boot-contents/extlinux/extlinux.conf
	# Override console for QEMU virt machine (ttyAMA0 instead of BPI-R4 ttyS0)
	sed -i 's/console=ttyS0,115200n8 earlycon=[^ ]*/console=ttyAMA0/' \
		$(BUILD_DIR)/test/boot-contents/extlinux/extlinux.conf
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
	@if [ ! -f $(BUILD_DIR)/test/logs.img ]; then \
		mke2fs -t ext2 -L sglogs $(BUILD_DIR)/test/logs.img 64M 2>/dev/null; \
		echo "Test logs disk created: $(BUILD_DIR)/test/logs.img"; \
	fi
	# Run QEMU — U-Boot loads kernel+initramfs from boot.img (virtio0)
	# Drive order: vda=boot, vdb=sgdata, vdc=sglogs
	qemu-system-aarch64 \
		-machine virt -cpu cortex-a72 -smp 4 -m 2G \
		-bios $(UBOOT_BIN) \
		-drive file=$(BUILD_DIR)/test/boot.img,format=raw,if=virtio \
		-drive file=$(BUILD_DIR)/test/data.img,format=raw,if=virtio \
		-drive file=$(BUILD_DIR)/test/logs.img,format=raw,if=virtio \
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
	$(MAKE) -C $(TOOLS_DIR) clean BUILD_DIR=$(BUILD_DIR)/tools 2>/dev/null || true
	@# Remove build subdirectories but keep kernel.img
	rm -rf $(BUILD_DIR)/busybox $(BUILD_DIR)/cli $(BUILD_DIR)/dash \
	       $(BUILD_DIR)/image $(BUILD_DIR)/iptables $(BUILD_DIR)/logind \
	       $(BUILD_DIR)/mgmtd $(BUILD_DIR)/modules $(BUILD_DIR)/rootfs \
	       $(BUILD_DIR)/test $(BUILD_DIR)/tools $(BUILD_DIR)/u-boot \
	       $(BUILD_DIR)/bpi-r4 $(BUILD_DIR)/bl2_emmc.img \
	       $(BUILD_DIR)/firmware
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
