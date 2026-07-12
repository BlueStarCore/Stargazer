/* SPDX-License-Identifier: MIT */
/*
 * sg-partinit — First-boot GPT partition creator for Stargazer NGFW
 *
 * On first boot after flashing, the disk image defines 6 partitions
 * (bl2, u-boot-env, factory, fip, boot, data) but the backup GPT header
 * is at the wrong offset (sized for the .img file, not the actual disk).
 * This tool:
 *   1. Fixes the GPT to match the actual disk size
 *   2. Creates a "logs" partition filling remaining space
 *   3. Re-reads the partition table via ioctl
 *
 * Usage: sg-partinit /dev/mmcblk0
 *
 * Idempotent — safe to run multiple times (skips if "logs" exists).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>

/* ── GPT structures ─────────────────────────────────────────────────────── */

#define GPT_SIGNATURE  "EFI PART"
#define SECTOR_SIZE    512

typedef struct {
	uint8_t   signature[8];
	uint32_t  revision;
	uint32_t  header_size;
	uint32_t  header_crc32;
	uint32_t  reserved;
	uint64_t  my_lba;
	uint64_t  alternate_lba;
	uint64_t  first_usable_lba;
	uint64_t  last_usable_lba;
	uint8_t   disk_guid[16];
	uint64_t  partition_entry_lba;
	uint32_t  num_partition_entries;
	uint32_t  partition_entry_size;
	uint32_t  partition_entries_crc32;
} __attribute__((packed)) gpt_header_t;

typedef struct {
	uint8_t   type_guid[16];
	uint8_t   unique_guid[16];
	uint64_t  first_lba;
	uint64_t  last_lba;
	uint64_t  attributes;
	uint16_t  name[36];
} __attribute__((packed)) gpt_entry_t;

/* Linux filesystem GUID: 0FC63DAF-8483-4772-8E79-3D69D8477DE4 (mixed-endian) */
static const uint8_t linux_fs_guid[16] = {
	0xAF, 0x3D, 0xC6, 0x0F,  0x83, 0x84,  0x72, 0x47,
	0x8E, 0x79,  0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4
};

/* ── CRC32 (standard Ethernet/GPT polynomial) ──────────────────────────── */

static uint32_t crc32_table[256];
static int crc32_ready;

static void crc32_init(void)
{
	if (crc32_ready) return;
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;
		for (int j = 0; j < 8; j++)
			c = (c & 1) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
		crc32_table[i] = c;
	}
	crc32_ready = 1;
}

static uint32_t crc32(const void *buf, size_t len)
{
	crc32_init();
	const uint8_t *p = buf;
	uint32_t c = 0xFFFFFFFFU;
	for (size_t i = 0; i < len; i++)
		c = crc32_table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
	return c ^ 0xFFFFFFFFU;
}

/* ── Helpers ────────────────────────────────────────────────────────────── */

static void set_utf16le_name(void *dst, const char *src, size_t max)
{
	uint8_t *p = dst;
	size_t i;
	for (i = 0; i < max - 1 && src[i]; i++) {
		p[i * 2]     = (uint8_t)src[i];
		p[i * 2 + 1] = 0;
	}
	for (; i < max; i++) {
		p[i * 2]     = 0;
		p[i * 2 + 1] = 0;
	}
}

static int entry_is_empty(const gpt_entry_t *e)
{
	static const uint8_t zero[16] = {0};
	return memcmp(e->type_guid, zero, 16) == 0;
}

static int entry_name_equals(const gpt_entry_t *e, const char *name)
{
	const uint8_t *p = (const uint8_t *)e->name;
	for (int i = 0; i < 36 && name[i]; i++) {
		if (p[i * 2] != (uint8_t)name[i] || p[i * 2 + 1] != 0)
			return 0;
	}
	return 1;
}

static int read_urandom(void *buf, size_t len)
{
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) return -1;
	ssize_t n = read(fd, buf, len);
	close(fd);
	return (n == (ssize_t)len) ? 0 : -1;
}

static void update_header_crc(gpt_header_t *hdr, const uint8_t *entries,
			      size_t entries_size)
{
	hdr->partition_entries_crc32 = crc32(entries, entries_size);
	hdr->header_crc32 = 0;
	hdr->header_crc32 = crc32(hdr, hdr->header_size);
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: sg-partinit <disk-device>\n");
		fprintf(stderr, "  e.g. sg-partinit /dev/mmcblk0\n");
		return 1;
	}

	const char *dev = argv[1];
	int fd = open(dev, O_RDWR | O_SYNC);
	if (fd < 0) {
		fprintf(stderr, "sg-partinit: cannot open %s: %s\n",
			dev, strerror(errno));
		return 1;
	}

	/* Get actual disk size */
	uint64_t disk_bytes = 0;
	if (ioctl(fd, BLKGETSIZE64, &disk_bytes) < 0) {
		fprintf(stderr, "sg-partinit: BLKGETSIZE64 failed: %s\n",
			strerror(errno));
		close(fd);
		return 1;
	}
	uint64_t disk_sectors = disk_bytes / SECTOR_SIZE;
	if (disk_sectors < 2048) {
		fprintf(stderr, "sg-partinit: disk too small (%lu sectors)\n",
			(unsigned long)disk_sectors);
		close(fd);
		return 1;
	}

	/* Read primary GPT header (LBA 1) */
	gpt_header_t hdr;
	if (pread(fd, &hdr, sizeof(hdr), SECTOR_SIZE) != sizeof(hdr)) {
		fprintf(stderr, "sg-partinit: cannot read GPT header\n");
		close(fd);
		return 1;
	}
	if (memcmp(hdr.signature, GPT_SIGNATURE, 8) != 0) {
		fprintf(stderr, "sg-partinit: no GPT signature on %s\n", dev);
		close(fd);
		return 1;
	}

	/* Read partition entries */
	size_t entry_size = hdr.partition_entry_size;
	if (entry_size < sizeof(gpt_entry_t)) entry_size = sizeof(gpt_entry_t);
	size_t entries_bytes = hdr.num_partition_entries * entry_size;
	uint8_t *entries = calloc(1, entries_bytes);
	if (!entries) {
		fprintf(stderr, "sg-partinit: malloc failed\n");
		close(fd);
		return 1;
	}
	if (pread(fd, entries, entries_bytes,
		  hdr.partition_entry_lba * SECTOR_SIZE) != (ssize_t)entries_bytes) {
		fprintf(stderr, "sg-partinit: cannot read partition entries\n");
		free(entries);
		close(fd);
		return 1;
	}

	/* Check if "logs" partition already exists */
	uint64_t highest_end = 0;
	for (uint32_t i = 0; i < hdr.num_partition_entries; i++) {
		gpt_entry_t *e = (gpt_entry_t *)(entries + i * entry_size);
		if (entry_is_empty(e)) continue;
		if (entry_name_equals(e, "logs")) {
			printf("sg-partinit: 'logs' partition already exists, skipping\n");
			free(entries);
			close(fd);
			return 0;
		}
		if (e->last_lba > highest_end)
			highest_end = e->last_lba;
	}

	/* Fix GPT to match actual disk size.
	 * Backup GPT: 32 sectors for entries + 1 sector for header = 33.
	 * last_usable_lba = disk_sectors - 34 (sector 0-indexed). */
	uint64_t actual_last_usable = disk_sectors - 34;
	uint64_t actual_alternate = disk_sectors - 1;

	if (actual_last_usable <= highest_end + 1) {
		fprintf(stderr, "sg-partinit: no space for logs partition "
			"(disk=%lu sectors, used up to LBA %lu)\n",
			(unsigned long)disk_sectors,
			(unsigned long)highest_end);
		free(entries);
		close(fd);
		return 1;
	}

	/* Update GPT header for actual disk size */
	hdr.last_usable_lba = actual_last_usable;
	hdr.alternate_lba = actual_alternate;

	/* Find first free partition entry */
	int new_idx = -1;
	for (uint32_t i = 0; i < hdr.num_partition_entries; i++) {
		gpt_entry_t *e = (gpt_entry_t *)(entries + i * entry_size);
		if (entry_is_empty(e)) {
			new_idx = (int)i;
			break;
		}
	}
	if (new_idx < 0) {
		fprintf(stderr, "sg-partinit: no free partition entry slot\n");
		free(entries);
		close(fd);
		return 1;
	}

	/* Create "logs" partition: from end of last partition to end of disk */
	gpt_entry_t *ne = (gpt_entry_t *)(entries + new_idx * entry_size);
	memcpy(ne->type_guid, linux_fs_guid, 16);
	if (read_urandom(ne->unique_guid, 16) < 0) {
		fprintf(stderr, "sg-partinit: cannot read /dev/urandom\n");
		free(entries);
		close(fd);
		return 1;
	}
	/* Set version bits for UUID v4 */
	ne->unique_guid[6] = (ne->unique_guid[6] & 0x0F) | 0x40;
	ne->unique_guid[8] = (ne->unique_guid[8] & 0x3F) | 0x80;

	ne->first_lba = highest_end + 1;
	ne->last_lba = actual_last_usable;
	ne->attributes = 0;
	set_utf16le_name(ne->name, "logs", 36);

	uint64_t logs_size_mb = (ne->last_lba - ne->first_lba + 1) * SECTOR_SIZE
				/ (1024 * 1024);
	printf("sg-partinit: creating 'logs' partition (%lu MB) "
	       "LBA %lu - %lu\n",
	       (unsigned long)logs_size_mb,
	       (unsigned long)ne->first_lba,
	       (unsigned long)ne->last_lba);

	/* Update primary GPT CRCs and write */
	update_header_crc(&hdr, entries, entries_bytes);

	if (pwrite(fd, &hdr, sizeof(hdr), SECTOR_SIZE) != sizeof(hdr)) {
		fprintf(stderr, "sg-partinit: write primary header failed\n");
		free(entries);
		close(fd);
		return 1;
	}
	if (pwrite(fd, entries, entries_bytes,
		   hdr.partition_entry_lba * SECTOR_SIZE) != (ssize_t)entries_bytes) {
		fprintf(stderr, "sg-partinit: write primary entries failed\n");
		free(entries);
		close(fd);
		return 1;
	}

	/* Write backup GPT at end of disk.
	 * Backup entries start 32 sectors before the backup header.
	 * Backup header is at the last sector. */
	uint64_t backup_entries_lba = actual_alternate - 32;
	gpt_header_t backup = hdr;
	backup.my_lba = actual_alternate;
	backup.alternate_lba = 1;  /* points to primary */
	backup.partition_entry_lba = backup_entries_lba;
	backup.header_crc32 = 0;
	backup.header_crc32 = crc32(&backup, backup.header_size);

	if (pwrite(fd, entries, entries_bytes,
		   backup_entries_lba * SECTOR_SIZE) != (ssize_t)entries_bytes) {
		fprintf(stderr, "sg-partinit: write backup entries failed "
			"(non-fatal)\n");
	}
	if (pwrite(fd, &backup, sizeof(backup),
		   actual_alternate * SECTOR_SIZE) != sizeof(backup)) {
		fprintf(stderr, "sg-partinit: write backup header failed "
			"(non-fatal)\n");
	}

	/* Sync and re-read partition table */
	fsync(fd);
	if (ioctl(fd, BLKRRPART) < 0) {
		fprintf(stderr, "sg-partinit: BLKRRPART failed: %s "
			"(reboot may be needed)\n", strerror(errno));
	}

	/*
	 * Wait for the new partition device node to appear.
	 *
	 * BLKRRPART tells the kernel to re-read the partition table, which
	 * is synchronous — the kernel creates partition block devices before
	 * the ioctl returns.  However, devtmpfs creates the /dev/ node
	 * asynchronously via a kernel thread, so there can be a short gap
	 * between the ioctl returning and the node being visible in /dev.
	 *
	 * We wait here so callers (init script) can rely on the device
	 * node existing when sg-partinit exits successfully.
	 *
	 * GPT partition numbers are 1-indexed: entry index 0 → p1, etc.
	 * For mmcblk devices: /dev/mmcblk0p6.  For sd/vd: /dev/sda6.
	 */
	{
		char part_path[256];
		const char *base = strrchr(dev, '/');
		base = base ? base + 1 : dev;

		/* mmcblk0 → mmcblk0p6, sda → sda6 */
		if (strncmp(base, "mmcblk", 6) == 0 ||
		    strncmp(base, "loop", 4) == 0 ||
		    strncmp(base, "nvme", 4) == 0)
			snprintf(part_path, sizeof(part_path),
				 "%sp%d", dev, new_idx + 1);
		else
			snprintf(part_path, sizeof(part_path),
				 "%s%d", dev, new_idx + 1);

		struct stat st;
		int tries = 0;
		while (stat(part_path, &st) != 0 || !S_ISBLK(st.st_mode)) {
			if (++tries > 50) { /* 50 × 100ms = 5s */
				fprintf(stderr, "sg-partinit: WARNING: "
					"%s not found after 5s — "
					"devtmpfs may be slow\n",
					part_path);
				break;
			}
			usleep(100000);
		}
		if (tries <= 50)
			printf("sg-partinit: verified %s exists\n", part_path);
	}

	printf("sg-partinit: done — partition table updated\n");
	free(entries);
	close(fd);
	return 0;
}
