#!/bin/sh
# flash-nand.sh — Flash Stargazer NGFW to BPI-R4 SPI-NAND
# Run from eMMC OpenWrt (or any Linux booted from eMMC/SD)
#
# Usage:
#   flash-nand.sh <stock-nand.img> <stargazer-nand.itb>
#       Full flash: restore bootloader from stock image, then install Stargazer kernel.
#
#   flash-nand.sh --kernel-only <stargazer-nand.itb>
#       Update only the kernel UBI volume (bootloader must already be working).
#
# After flashing, set the DIP switch to NAND boot and power cycle.

set -e

die() { echo "FATAL: $*" >&2; exit 1; }
warn() { echo "WARNING: $*" >&2; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
KERNEL_ONLY=0
STOCK_IMG=""
FIT_IMG=""

if [ "$1" = "--kernel-only" ]; then
	KERNEL_ONLY=1
	FIT_IMG="$2"
elif [ $# -eq 2 ]; then
	STOCK_IMG="$1"
	FIT_IMG="$2"
else
	echo "Usage:"
	echo "  $0 <stock-nand.img> <stargazer-nand.itb>    # full flash"
	echo "  $0 --kernel-only <stargazer-nand.itb>        # kernel update only"
	exit 1
fi

[ -f "$FIT_IMG" ] || die "FIT image not found: $FIT_IMG"
[ "$KERNEL_ONLY" -eq 1 ] || [ -f "$STOCK_IMG" ] || die "Stock NAND image not found: $STOCK_IMG"

# ---------------------------------------------------------------------------
# Detect SPI-NAND MTD devices from /proc/mtd
# ---------------------------------------------------------------------------
[ -f /proc/mtd ] || die "/proc/mtd not found — is this running on the BPI-R4?"

# Find the whole-NAND mtdblock device (largest one, should be 128MB = 131072 KB)
NAND_MTD=""
NAND_SIZE=0
UBI_MTD=""

echo "=== SPI-NAND MTD partitions ==="
cat /proc/mtd
echo ""

# Parse /proc/mtd to find partitions by name
while IFS=': ' read -r dev size erasesize name rest; do
	# Skip header
	[ "$dev" = "dev" ] && continue
	name=$(echo "$name" | tr -d '"')
	size_dec=$((0x$size))

	case "$name" in
		ubi)
			UBI_MTD="/dev/${dev}"
			echo "Found UBI partition: $UBI_MTD ($(($size_dec / 1024 / 1024))MB)"
			;;
	esac

	# Track the largest partition (whole NAND)
	if [ "$size_dec" -gt "$NAND_SIZE" ]; then
		NAND_SIZE=$size_dec
		NAND_MTD="/dev/${dev}"
	fi
done < /proc/mtd

# Derive mtdblock device from mtd device (mtd0 -> mtdblock0)
if [ -n "$NAND_MTD" ]; then
	NAND_BLOCK=$(echo "$NAND_MTD" | sed 's|/dev/mtd|/dev/mtdblock|')
	echo "Whole NAND device: $NAND_MTD ($NAND_BLOCK, $(($NAND_SIZE / 1024 / 1024))MB)"
else
	die "Could not find SPI-NAND MTD device in /proc/mtd"
fi

[ -b "$NAND_BLOCK" ] || die "Block device $NAND_BLOCK not found"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
# Check for required UBI tools
for tool in ubiattach ubidetach ubinfo ubiupdatevol; do
	command -v "$tool" >/dev/null 2>&1 || die "'$tool' not found. Install ubi-utils: opkg install ubi-utils"
done

FIT_SIZE=$(stat -c %s "$FIT_IMG" 2>/dev/null || stat -f %z "$FIT_IMG" 2>/dev/null)
echo "Stargazer FIT size: $(($FIT_SIZE / 1024 / 1024))MB ($FIT_SIZE bytes)"

# ---------------------------------------------------------------------------
# Step 1: Restore stock NAND image (bootloader + factory + stock UBI)
# ---------------------------------------------------------------------------
if [ "$KERNEL_ONLY" -eq 0 ]; then
	STOCK_SIZE=$(stat -c %s "$STOCK_IMG" 2>/dev/null || stat -f %z "$STOCK_IMG" 2>/dev/null)
	echo ""
	echo "=== Step 1: Restore NAND bootloader from stock image ==="
	echo "Stock image: $STOCK_IMG ($STOCK_SIZE bytes)"
	echo "Target: $NAND_BLOCK"
	echo ""

	# Detach any existing UBI first
	for ubi_num in 0 1 2; do
		[ -e "/dev/ubi${ubi_num}" ] && ubidetach -d "$ubi_num" 2>/dev/null || true
	done

	# Erase NAND
	echo "Erasing NAND..."
	mtd erase "$NAND_MTD" 2>/dev/null || {
		# Fallback: try OpenWrt mtd syntax with partition name
		flash_erase "$NAND_MTD" 0 0 2>/dev/null || {
			warn "mtd erase failed, trying dd with zeros..."
			dd if=/dev/zero of="$NAND_BLOCK" bs=128k 2>/dev/null || true
		}
	}

	# Write stock image
	echo "Writing stock NAND image (this takes ~30 seconds)..."
	dd if="$STOCK_IMG" of="$NAND_BLOCK" bs=128k 2>/dev/null
	sync
	echo "Stock image written successfully."
else
	echo ""
	echo "=== Kernel-only update (skipping bootloader restore) ==="
fi

# ---------------------------------------------------------------------------
# Step 2: Attach UBI and update kernel volume
# ---------------------------------------------------------------------------
echo ""
echo "=== Step 2: Update kernel UBI volume with Stargazer ==="

# Detach any existing UBI
for ubi_num in 0 1 2; do
	[ -e "/dev/ubi${ubi_num}" ] && ubidetach -d "$ubi_num" 2>/dev/null || true
done

# Find UBI MTD partition
if [ -z "$UBI_MTD" ]; then
	# Fallback: try to find by scanning partition names
	for mtd_dev in /sys/class/mtd/mtd*/name; do
		[ -f "$mtd_dev" ] || continue
		pname=$(cat "$mtd_dev")
		if [ "$pname" = "ubi" ]; then
			mtd_num=$(echo "$mtd_dev" | grep -o 'mtd[0-9]*' | head -n 1)
			UBI_MTD="/dev/$mtd_num"
			break
		fi
	done
fi

[ -n "$UBI_MTD" ] || die "Could not find UBI MTD partition. Check /proc/mtd."
[ -c "$UBI_MTD" ] || die "UBI MTD device $UBI_MTD is not a character device"

echo "Attaching UBI on $UBI_MTD..."
ubiattach -p "$UBI_MTD" || die "ubiattach failed on $UBI_MTD"

# Wait for UBI device to appear
sleep 1

# Find the UBI device number
UBI_DEV=""
for ubi_num in 0 1 2; do
	if [ -e "/dev/ubi${ubi_num}" ]; then
		UBI_DEV="/dev/ubi${ubi_num}"
		break
	fi
done
[ -n "$UBI_DEV" ] || die "UBI device not found after attach"

echo "UBI device: $UBI_DEV"
ubinfo "$UBI_DEV"
echo ""

# Find "kernel" volume
KERNEL_VOL=""
VOL_COUNT=$(ubinfo "$UBI_DEV" | grep "Volumes count:" | awk '{print $NF}')
echo "Scanning $VOL_COUNT UBI volumes..."

vol_idx=0
while [ "$vol_idx" -lt 20 ]; do
	vol_dev="${UBI_DEV}_${vol_idx}"
	[ -e "$vol_dev" ] || { vol_idx=$((vol_idx + 1)); continue; }

	vol_name=$(ubinfo "$vol_dev" 2>/dev/null | grep "Name:" | awk '{print $NF}')
	vol_size=$(ubinfo "$vol_dev" 2>/dev/null | grep "Size:" | head -n 1 | awk '{print $NF}')
	echo "  Volume $vol_idx: name=$vol_name size=$vol_size"

	if [ "$vol_name" = "kernel" ]; then
		KERNEL_VOL="$vol_dev"
	fi
	vol_idx=$((vol_idx + 1))
done

if [ -z "$KERNEL_VOL" ]; then
	echo ""
	echo "No 'kernel' volume found. Creating one..."
	# Create kernel volume (20MB should be more than enough for our ~11MB FIT)
	ubimkvol "$UBI_DEV" -N kernel -s 20MiB -t dynamic || die "Failed to create kernel UBI volume"

	# Find the newly created volume
	vol_idx=0
	while [ "$vol_idx" -lt 20 ]; do
		vol_dev="${UBI_DEV}_${vol_idx}"
		[ -e "$vol_dev" ] || { vol_idx=$((vol_idx + 1)); continue; }
		vol_name=$(ubinfo "$vol_dev" 2>/dev/null | grep "Name:" | awk '{print $NF}')
		if [ "$vol_name" = "kernel" ]; then
			KERNEL_VOL="$vol_dev"
			break
		fi
		vol_idx=$((vol_idx + 1))
	done
	[ -n "$KERNEL_VOL" ] || die "Failed to find kernel volume after creation"
fi

echo ""
echo "Updating kernel volume: $KERNEL_VOL"
echo "Writing Stargazer FIT ($FIT_SIZE bytes)..."
ubiupdatevol "$KERNEL_VOL" "$FIT_IMG" || die "ubiupdatevol failed"

sync
echo ""
echo "============================================"
echo " Stargazer NAND flash complete!"
echo "============================================"
echo ""
echo " Next steps:"
echo "   1. Power off:  poweroff"
echo "   2. Set DIP switch to NAND boot"
echo "   3. Power on"
echo ""
echo " The firewall will auto-format persistent"
echo " storage on first boot."
echo "============================================"
