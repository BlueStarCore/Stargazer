# =============================================================================
# Stargazer NGFW - Build System
# =============================================================================
#
# Build flow:
#   1. make kernel     - Build BPI-R4 kernel (if not exists)
#   2. make modules    - Build kernel modules
#   3. make rootfs     - Create userspace rootfs
#   4. make iso        - Create bootable ISO for BPI-R4
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
PROJECT_ROOT   := $(shell pwd)
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

# Alpine base for rootfs
ALPINE_VERSION := 3.19
ALPINE_URL     := https://dl-cdn.alpinelinux.org/alpine/v$(ALPINE_VERSION)/releases/aarch64/alpine-minirootfs-$(ALPINE_VERSION).0-aarch64.tar.gz

# =============================================================================
# Main targets
# =============================================================================

.PHONY: all kernel modules rootfs iso test clean help

all: iso
	@echo ""
	@echo "Build complete: $(ISO_FILE)"
	@echo "Deploy: dd if=$(ISO_FILE) of=/dev/sdX bs=4M status=progress"

# =============================================================================
# 1. Kernel
# =============================================================================

kernel: $(KERNEL_IMAGE)

$(KERNEL_IMAGE): | kernel-source kernel-config
	@echo "[1/4] Building kernel..."
	$(MAKE) -C $(KERNEL_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -j$$(nproc) Image dtbs modules
	@mkdir -p $(BUILD_DIR)
	cp $(KERNEL_DIR)/arch/$(ARCH)/boot/Image $(KERNEL_IMAGE)
	cp $(KERNEL_DIR)/arch/$(ARCH)/boot/dts/mediatek/mt7988a-bananapi-bpi-r4.dtb $(KERNEL_DTB) 2>/dev/null || true
	@echo "[1/4] Kernel ready: $(KERNEL_IMAGE)"

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
	@echo "[2/4] Building modules..."
	$(MAKE) -C $(KERNEL_DIR) M=$(MODULE_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules KBUILD_MODPOST_WARN=1
	@mkdir -p $(BUILD_DIR)/modules
	cp $(MODULE_DIR)/*.ko $(BUILD_DIR)/modules/
	@echo "[2/4] Module ready: $@"

# =============================================================================
# 3. Rootfs (userspace)
# =============================================================================

rootfs: $(ROOTFS_DIR)/.stamp

$(ROOTFS_DIR)/.stamp: modules
	@echo "[3/4] Creating rootfs..."
	@rm -rf $(ROOTFS_DIR)
	@mkdir -p $(ROOTFS_DIR)
	
	# Download and extract Alpine base
	@if [ ! -f "$(BUILD_DIR)/alpine-base.tar.gz" ]; then \
		wget -q --show-progress $(ALPINE_URL) -O $(BUILD_DIR)/alpine-base.tar.gz; \
	fi
	tar -xzf $(BUILD_DIR)/alpine-base.tar.gz -C $(ROOTFS_DIR)
	
	# Install kernel modules
	mkdir -p $(ROOTFS_DIR)/lib/modules
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
	@mkdir -p $(ROOTFS_DIR)
	@cp $(USERSPACE_DIR)/init $(ROOTFS_DIR)/init.tmp
	@sed -i 's/@VERSION@/$(VERSION)/g' $(ROOTFS_DIR)/init.tmp
	@mv $(ROOTFS_DIR)/init.tmp $(ROOTFS_DIR)/init
	@chmod +x $(ROOTFS_DIR)/init
	
	# Copy userspace tools (if exists)
	@if [ -d "$(USERSPACE_DIR)" ] && [ "$$(ls -A $(USERSPACE_DIR) 2>/dev/null)" ]; then \
		cp -r $(USERSPACE_DIR)/* $(ROOTFS_DIR)/usr/local/; \
	fi
	
	@touch $@
	@echo "[3/4] Rootfs ready: $(ROOTFS_DIR)"

# =============================================================================
# 4. ISO Image
# =============================================================================

iso: $(ISO_FILE)

$(ISO_FILE): $(ROOTFS_DIR)/.stamp
	@echo "[4/4] Creating ISO image..."
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
	@echo " Rootfs:   $(ROOTFS_DIR)"
	@echo " Image:    $(ISO_FILE)"
	@echo ""
	@echo " Deploy to BPI-R4:"
	@echo "   dd if=$(ISO_FILE) of=/dev/sdX bs=4M"
	@echo "============================================"

# =============================================================================
# Test in QEMU
# =============================================================================

test: modules
	@echo "Starting QEMU test..."
	@mkdir -p $(BUILD_DIR)/test
	
	# Create minimal initramfs for testing
	@rm -rf $(BUILD_DIR)/test/initramfs
	@mkdir -p $(BUILD_DIR)/test/initramfs
	@if [ ! -f "$(BUILD_DIR)/alpine-base.tar.gz" ]; then \
		wget -q --show-progress $(ALPINE_URL) -O $(BUILD_DIR)/alpine-base.tar.gz; \
	fi
	tar -xzf $(BUILD_DIR)/alpine-base.tar.gz -C $(BUILD_DIR)/test/initramfs
	mkdir -p $(BUILD_DIR)/test/initramfs/root/modules
	cp $(BUILD_DIR)/modules/*.ko $(BUILD_DIR)/test/initramfs/root/modules/
	
	# Copy init script
	cp $(USERSPACE_DIR)/init $(BUILD_DIR)/test/initramfs/init
	chmod +x $(BUILD_DIR)/test/initramfs/init
	
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
	rm -rf $(BUILD_DIR)
	@echo "Clean complete"

help:
	@echo "Stargazer NGFW Build System"
	@echo ""
	@echo "Build flow: kernel -> modules -> rootfs -> iso"
	@echo ""
	@echo "Targets:"
	@echo "  make all      - Build everything (default)"
	@echo "  make kernel   - Build BPI-R4 kernel"
	@echo "  make modules  - Build kernel modules"
	@echo "  make rootfs   - Create userspace rootfs"
	@echo "  make iso      - Create bootable ISO"
	@echo "  make test     - Test in QEMU"
	@echo "  make clean    - Remove all artifacts"
	@echo ""
	@echo "Output: $(ISO_FILE)"
