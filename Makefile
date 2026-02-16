# =============================================================================
# Stargazer NGFW - Build System
# =============================================================================
#
# Build flow:
#   1. make kernel     - Build BPI-R4 kernel (if not exists)
#   2. make modules    - Build kernel modules
#   3. make busybox    - Cross-compile BusyBox for ARM64
#   4. make rootfs     - Create userspace rootfs
#   5. make iso        - Create bootable ISO for BPI-R4
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
KERNEL_REPO    := https://github.com/frank-w/BPI-Router-Linux
KERNEL_BRANCH  := 6.12-main
KERNEL_IMAGE   := $(BUILD_DIR)/kernel.img
KERNEL_DTB     := $(BUILD_DIR)/bpi-r4.dtb

# Output
ISO_FILE       := $(BUILD_DIR)/stargazer-bpi-r4.iso
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

# Logind / C helpers
LOGIND_DIR     := $(PROJECT_ROOT)/src/userspace/logind

# mgmtd (management daemon + IPC client)
MGMTD_DIR      := $(PROJECT_ROOT)/src/userspace/mgmtd

# Musl cross toolchain (for clean static linking — no glibc NSS issues)
# Auto-downloaded from musl.cc on first build
MUSL_CROSS_URL := https://musl.cc/aarch64-linux-musl-cross.tgz
MUSL_CROSS_DIR := $(BUSYBOX_CACHE_DIR)/aarch64-linux-musl-cross
MUSL_CC        := $(MUSL_CROSS_DIR)/bin/aarch64-linux-musl-gcc
MUSL_CROSS     := $(MUSL_CROSS_DIR)/bin/aarch64-linux-musl-

# =============================================================================
# Main targets
# =============================================================================

.PHONY: all kernel modules busybox musl-toolchain dash logind mgmtd rootfs iso test clean help

all: iso
	@echo ""
	@echo "Build complete: $(ISO_FILE)"
	@echo "Deploy: dd if=$(ISO_FILE) of=/dev/sdX bs=4M status=progress"

# =============================================================================
# 1. Kernel
# =============================================================================

kernel: $(KERNEL_IMAGE)

$(KERNEL_IMAGE): | kernel-source kernel-config
	@echo "[1/5] Building kernel..."
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
			--enable VIRTIO --enable VIRTIO_PCI --enable VIRTIO_NET \
			--enable MODULES --enable MODULE_UNLOAD \
			--enable EXT4_FS --enable SQUASHFS; \
		$(MAKE) -C $(KERNEL_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) olddefconfig; \
	fi

# =============================================================================
# 2. Modules
# =============================================================================

modules: $(BUILD_DIR)/modules/$(MODULE_NAME).ko

$(BUILD_DIR)/modules/$(MODULE_NAME).ko: $(KERNEL_IMAGE)
	@echo "[2/5] Building modules..."
	$(MAKE) -C $(KERNEL_DIR) M=$(MODULE_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules KBUILD_MODPOST_WARN=1
	@mkdir -p $(BUILD_DIR)/modules
	cp $(MODULE_DIR)/*.ko $(BUILD_DIR)/modules/
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
# 3d. Logind + C helpers (cross-compile with musl)
# =============================================================================

logind: $(BUILD_DIR)/logind/stargazer-logind $(BUILD_DIR)/logind/stargazer-hashpw $(BUILD_DIR)/logind/stargazer-readline

$(BUILD_DIR)/logind/stargazer-logind $(BUILD_DIR)/logind/stargazer-hashpw $(BUILD_DIR)/logind/stargazer-readline: $(MUSL_CC)
	@echo "[3d/5] Building logind + C helpers (musl static)..."
	@mkdir -p $(BUILD_DIR)/logind
	$(MAKE) -C $(LOGIND_DIR) \
		CROSS_COMPILE=$(MUSL_CROSS) \
		BUILD_DIR=$(BUILD_DIR)/logind
	@echo "[3d/5] Logind + helpers ready."

# =============================================================================
# 3e. mgmtd — management daemon + IPC client (cross-compile with musl)
# =============================================================================

mgmtd: $(BUILD_DIR)/mgmtd/stargazer-mgmtd $(BUILD_DIR)/mgmtd/stargazer-ipc-cli

$(BUILD_DIR)/mgmtd/stargazer-mgmtd $(BUILD_DIR)/mgmtd/stargazer-ipc-cli: $(MUSL_CC)
	@echo "[3e/5] Building mgmtd + IPC client (musl static)..."
	@mkdir -p $(BUILD_DIR)/mgmtd
	$(MAKE) -C $(MGMTD_DIR) \
		CROSS_COMPILE=$(MUSL_CROSS) \
		BUILD_DIR=$(BUILD_DIR)/mgmtd
	@echo "[3e/5] mgmtd + IPC client ready."

# =============================================================================
# 4. Rootfs (userspace)
# =============================================================================

rootfs: $(ROOTFS_DIR)/.stamp

$(ROOTFS_DIR)/.stamp: modules busybox dash logind mgmtd
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

	# Install logind + C helpers
	cp $(BUILD_DIR)/logind/stargazer-logind $(ROOTFS_DIR)/sbin/
	cp $(BUILD_DIR)/logind/stargazer-hashpw $(ROOTFS_DIR)/sbin/
	cp $(BUILD_DIR)/logind/stargazer-readline $(ROOTFS_DIR)/sbin/
	@chmod +x $(ROOTFS_DIR)/sbin/stargazer-logind $(ROOTFS_DIR)/sbin/stargazer-hashpw $(ROOTFS_DIR)/sbin/stargazer-readline

	# Install mgmtd + IPC client
	cp $(BUILD_DIR)/mgmtd/stargazer-mgmtd $(ROOTFS_DIR)/sbin/
	cp $(BUILD_DIR)/mgmtd/stargazer-ipc-cli $(ROOTFS_DIR)/sbin/
	@chmod +x $(ROOTFS_DIR)/sbin/stargazer-mgmtd $(ROOTFS_DIR)/sbin/stargazer-ipc-cli

	# Create minimal /etc files (no Alpine branding)
	@echo 'root:x:0:0:root:/root:/bin/sh' > $(ROOTFS_DIR)/etc/passwd
	@echo 'nobody:x:65534:65534:nobody:/:/bin/false' >> $(ROOTFS_DIR)/etc/passwd
	@echo 'root:x:0:root' > $(ROOTFS_DIR)/etc/group
	@echo 'nobody:x:65534:' >> $(ROOTFS_DIR)/etc/group
	@echo 'root:*:19700:0:99999:7:::' > $(ROOTFS_DIR)/etc/shadow
	@echo 'nobody:*:19700:0:99999:7:::' >> $(ROOTFS_DIR)/etc/shadow
	@chmod 640 $(ROOTFS_DIR)/etc/shadow
	@echo 'stargazer' > $(ROOTFS_DIR)/etc/hostname
	@printf '127.0.0.1\tlocalhost\n::1\t\tlocalhost\n' > $(ROOTFS_DIR)/etc/hosts
	@printf '/bin/sh\n/sbin/stargazer-cli\n' > $(ROOTFS_DIR)/etc/shells

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

	# Copy login and CLI scripts
	@cp $(USERSPACE_DIR)/sbin/stargazer-login $(ROOTFS_DIR)/sbin/
	@cp $(USERSPACE_DIR)/sbin/stargazer-cli $(ROOTFS_DIR)/sbin/stargazer-cli.tmp
	@sed -i 's/@VERSION@/$(VERSION)/g' $(ROOTFS_DIR)/sbin/stargazer-cli.tmp
	@mv $(ROOTFS_DIR)/sbin/stargazer-cli.tmp $(ROOTFS_DIR)/sbin/stargazer-cli
	@chmod +x $(ROOTFS_DIR)/sbin/stargazer-login $(ROOTFS_DIR)/sbin/stargazer-cli

	# Copy CLI command scripts
	@mkdir -p $(ROOTFS_DIR)/usr/libexec/stargazer
	@cp $(USERSPACE_DIR)/usr/libexec/stargazer/* $(ROOTFS_DIR)/usr/libexec/stargazer/
	@chmod +x $(ROOTFS_DIR)/usr/libexec/stargazer/*

	# Copy automated test suite (for test_mode=1 boots)
	@cp $(PROJECT_ROOT)/tests/test_suite.sh $(ROOTFS_DIR)/usr/libexec/stargazer/test_suite.sh
	@chmod +x $(ROOTFS_DIR)/usr/libexec/stargazer/test_suite.sh

	# Create stargazer config directory
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
	cd $(ROOTFS_DIR) && find . | cpio -o -H newc 2>/dev/null | gzip -9 > $(BUILD_DIR)/iso/boot/initramfs.gz

	# Create ISO (for UEFI boot on BPI-R4)
	@if command -v xorriso >/dev/null 2>&1; then \
		xorriso -as mkisofs \
			-o $(ISO_FILE) \
			-iso-level 3 \
			-full-iso9660-filenames \
			$(BUILD_DIR)/iso; \
	else \
		echo "[WARN] xorriso not found, creating tar archive instead"; \
		tar -czf $(BUILD_DIR)/stargazer-bpi-r4.tar.gz -C $(BUILD_DIR)/iso .; \
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
	@echo " Rootfs:   $(ROOTFS_DIR)"
	@echo " Image:    $(ISO_FILE)"
	@echo ""
	@echo " Deploy to BPI-R4:"
	@echo "   dd if=$(ISO_FILE) of=/dev/sdX bs=4M"
	@echo "============================================"

# =============================================================================
# Test in QEMU
# =============================================================================

test: modules busybox dash logind mgmtd
	@echo "Starting QEMU test..."
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

	# Create minimal /etc files
	@echo 'root:x:0:0:root:/root:/bin/sh' > $(BUILD_DIR)/test/initramfs/etc/passwd
	@echo 'nobody:x:65534:65534:nobody:/:/bin/false' >> $(BUILD_DIR)/test/initramfs/etc/passwd
	@echo 'root:x:0:root' > $(BUILD_DIR)/test/initramfs/etc/group
	@echo 'nobody:x:65534:' >> $(BUILD_DIR)/test/initramfs/etc/group
	@echo 'root:*:19700:0:99999:7:::' > $(BUILD_DIR)/test/initramfs/etc/shadow
	@echo 'nobody:*:19700:0:99999:7:::' >> $(BUILD_DIR)/test/initramfs/etc/shadow
	@chmod 640 $(BUILD_DIR)/test/initramfs/etc/shadow
	@echo 'stargazer' > $(BUILD_DIR)/test/initramfs/etc/hostname
	@printf '127.0.0.1\tlocalhost\n::1\t\tlocalhost\n' > $(BUILD_DIR)/test/initramfs/etc/hosts
	@printf '/bin/sh\n/sbin/stargazer-cli\n' > $(BUILD_DIR)/test/initramfs/etc/shells

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

	# Copy login and CLI scripts
	@cp $(USERSPACE_DIR)/sbin/stargazer-login $(BUILD_DIR)/test/initramfs/sbin/
	@cp $(USERSPACE_DIR)/sbin/stargazer-cli $(BUILD_DIR)/test/initramfs/sbin/stargazer-cli.tmp
	@sed -i 's/@VERSION@/$(VERSION)/g' $(BUILD_DIR)/test/initramfs/sbin/stargazer-cli.tmp
	@mv $(BUILD_DIR)/test/initramfs/sbin/stargazer-cli.tmp $(BUILD_DIR)/test/initramfs/sbin/stargazer-cli
	@chmod +x $(BUILD_DIR)/test/initramfs/sbin/stargazer-login $(BUILD_DIR)/test/initramfs/sbin/stargazer-cli

	# Copy CLI command scripts
	@mkdir -p $(BUILD_DIR)/test/initramfs/usr/libexec/stargazer
	@cp $(USERSPACE_DIR)/usr/libexec/stargazer/* $(BUILD_DIR)/test/initramfs/usr/libexec/stargazer/
	@chmod +x $(BUILD_DIR)/test/initramfs/usr/libexec/stargazer/*

	# Create stargazer config directory
	@mkdir -p $(BUILD_DIR)/test/initramfs/etc/stargazer

	# Pack initramfs
	cd $(BUILD_DIR)/test/initramfs && find . | cpio -o -H newc 2>/dev/null | gzip -9 > $(BUILD_DIR)/test/initramfs.gz

	# Run QEMU
	qemu-system-aarch64 \
		-machine virt -cpu cortex-a72 -smp 4 -m 2G \
		-kernel $(KERNEL_IMAGE) \
		-initrd $(BUILD_DIR)/test/initramfs.gz \
		-append "console=ttyAMA0 rw" \
		-nographic -no-reboot

# =============================================================================
# Utilities
# =============================================================================

clean:
	@echo "Cleaning..."
	$(MAKE) -C $(MODULE_DIR) clean 2>/dev/null || true
	$(MAKE) -C $(LOGIND_DIR) clean BUILD_DIR=$(BUILD_DIR)/logind 2>/dev/null || true
	$(MAKE) -C $(MGMTD_DIR) clean BUILD_DIR=$(BUILD_DIR)/mgmtd 2>/dev/null || true
	rm -rf $(BUILD_DIR)
	@echo "Clean complete (source caches preserved in .cache/)"

help:
	@echo "Stargazer NGFW Build System"
	@echo ""
	@echo "Build flow: kernel -> modules -> busybox/dash/logind -> rootfs -> iso"
	@echo ""
	@echo "Targets:"
	@echo "  make all      - Build everything (default)"
	@echo "  make kernel   - Build BPI-R4 kernel"
	@echo "  make modules  - Build kernel modules"
	@echo "  make busybox  - Cross-compile BusyBox (system utilities)"
	@echo "  make dash     - Cross-compile dash (POSIX shell, replaces ash)"
	@echo "  make logind   - Cross-compile logind + C helpers"
	@echo "  make mgmtd    - Cross-compile mgmtd daemon + IPC client"
	@echo "  make rootfs   - Create userspace rootfs"
	@echo "  make iso      - Create bootable ISO"
	@echo "  make test     - Test in QEMU"
	@echo "  make clean    - Remove all artifacts"
	@echo "                 (keeps source caches in .cache/)"
	@echo ""
	@echo "Output: $(ISO_FILE)"
