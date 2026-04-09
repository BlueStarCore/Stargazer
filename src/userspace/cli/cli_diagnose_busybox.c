/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose_busybox.c — BusyBox applet whitelist drift detection
 *
 * Stargazer ships BusyBox built from `allnoconfig` plus an explicit applet
 * fragment (configs/busybox.config.fragment). This selftest enumerates
 * every busybox symlink under /bin /sbin /usr/bin /usr/sbin via mgmtd
 * (the CLI sandbox blocks readdir/readlink) and verifies the result
 * matches the hardcoded whitelist below — neither too many applets
 * (a BusyBox upstream addition silently slipped in) nor too few (a build
 * regression dropped a critical applet).
 *
 * The CLI is sandboxed (no openat-write, no readlinkat, no getdents64),
 * so the actual enumeration runs in mgmtd via SG_CMD_DIAG_BUSYBOX_LIST.
 *
 * To intentionally add or remove an applet:
 *   1. Edit configs/busybox.config.fragment.
 *   2. Update the `whitelist[]` array below to match.
 *   3. Rebuild and re-run this selftest.
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_diagnose.h"
#include "cli_ipc.h"

#include <stdio.h>
#include <string.h>

/* ── Hardcoded whitelist (must match configs/busybox.config.fragment) ─── */

static const char *whitelist[] = {
	/* networking */
	"/sbin/ip",
	"/bin/ping",
	"/usr/bin/traceroute",
	"/usr/bin/nslookup",
	"/usr/sbin/arping",
	"/sbin/udhcpc",
	"/usr/sbin/udhcpd",
	"/usr/sbin/ntpd",
	"/usr/bin/wget",
	"/usr/bin/tftp",
	"/usr/bin/logger",
	/* filesystem & block */
	"/bin/mount",
	"/bin/umount",
	"/bin/mountpoint",
	"/bin/mkdir",
	"/usr/bin/mkfifo",
	"/sbin/blkid",
	"/sbin/mke2fs",
	"/bin/dd",
	"/bin/sync",
	/* file ops */
	"/bin/cp",
	"/bin/mv",
	"/bin/rm",
	"/bin/chmod",
	"/bin/chown",
	"/bin/touch",
	"/bin/cat",
	"/bin/mktemp",
	/* process / kernel module */
	"/sbin/insmod",
	"/sbin/rmmod",
	"/sbin/lsmod",
	"/bin/kill",
	"/usr/bin/killall",
	"/bin/sleep",
	"/bin/dmesg",
	"/usr/bin/setsid",
	/*
	 * /sbin/halt, /sbin/reboot, /sbin/poweroff are NOT in the whitelist:
	 * init replaces them with shell scripts that exec
	 * `/bin/busybox halt -f` / `reboot -f` directly (init:335,447,452).
	 * The CONFIG_HALT/REBOOT/POWEROFF applets still exist inside the
	 * busybox binary (required, since shutdown.sh invokes them by full
	 * path), but the /sbin symlinks are gone at runtime.
	 */
	/* text utilities */
	"/bin/grep",
	"/bin/sed",
	"/usr/bin/cut",
	"/usr/bin/tr",
	"/usr/bin/head",
	"/usr/bin/printf",
	/* misc */
	"/usr/bin/clear",
	"/bin/uname",
	"/bin/stty",
	"/bin/echo",
	/*
	 * /bin/sh is NOT in the whitelist: although busybox.links emits a
	 * /bin/sh entry at build time, the rootfs install step overrides it
	 * with `ln -sf dash /bin/sh`, so at runtime /bin/sh → dash, not
	 * /bin/busybox.
	 */
};
#define N_WHITELIST (sizeof(whitelist) / sizeof(whitelist[0]))

/* ── Test helpers ──────────────────────────────────────────────────────── */

static int run_test(const char *id, const char *desc,
		    int passed, diag_result_t *out)
{
	out->total++;
	if (passed) {
		out->passed++;
		printf("  [" C_GREEN "PASS" C_NC "] %s: %s\n", id, desc);
		return 0;
	}
	out->failed++;
	printf("  [" C_RED "FAIL" C_NC "] %s: %s\n", id, desc);
	return 1;
}

/* Return non-zero if `path` is in the whitelist. */
static int in_whitelist(const char *path)
{
	for (size_t i = 0; i < N_WHITELIST; i++) {
		if (strcmp(whitelist[i], path) == 0)
			return 1;
	}
	return 0;
}

/* Return non-zero if `path` appears as a line in `payload`. */
static int in_payload(const char *payload, const char *path)
{
	const char *p = payload;
	size_t plen = strlen(path);
	while (*p) {
		if (strncmp(p, path, plen) == 0 &&
		    (p[plen] == '\n' || p[plen] == '\0')) {
			return 1;
		}
		const char *nl = strchr(p, '\n');
		if (!nl) break;
		p = nl + 1;
	}
	return 0;
}

/* ── Public entry point ────────────────────────────────────────────────── */

int cli_diagnose_test_busybox(int mode, diag_result_t *out)
{
	(void)mode;
	diag_result_t local = {0};
	if (!out) out = &local;
	int failures = 0;

	printf("\n  " C_CYAN "--- BusyBox Whitelist Tests (BBX-WL) ---" C_NC "\n");

	/* BBX-WL-1: IPC round-trip succeeds */
	struct ipc_response resp = {0};
	int conn = ipc_send_str(SG_CMD_DIAG_BUSYBOX_LIST, "", &resp);
	failures += run_test("BBX-WL-1",
		"DIAG_BUSYBOX_LIST IPC succeeds",
		conn == 0 && resp.status == SG_OK && resp.payload, out);

	if (conn != 0 || resp.status != SG_OK || !resp.payload) {
		ipc_resp_free(&resp);
		return 1;
	}

	/* BBX-WL-2: every reported symlink must be in whitelist (no extras) */
	int extras = 0;
	const char *p = resp.payload;
	char path[256];
	while (*p) {
		const char *nl = strchr(p, '\n');
		size_t len = nl ? (size_t)(nl - p) : strlen(p);
		if (len > 0 && len < sizeof(path)) {
			memcpy(path, p, len);
			path[len] = '\0';
			if (!in_whitelist(path)) {
				printf("    " C_RED "extra applet:" C_NC " %s\n",
				       path);
				extras++;
			}
		}
		if (!nl) break;
		p = nl + 1;
	}
	failures += run_test("BBX-WL-2",
		"no applets outside whitelist",
		extras == 0, out);

	/* BBX-WL-3: every whitelist entry must exist in the rootfs */
	int missing = 0;
	for (size_t i = 0; i < N_WHITELIST; i++) {
		if (!in_payload(resp.payload, whitelist[i])) {
			printf("    " C_RED "missing applet:" C_NC " %s\n",
			       whitelist[i]);
			missing++;
		}
	}
	failures += run_test("BBX-WL-3",
		"no whitelist applets missing from rootfs",
		missing == 0, out);

	ipc_resp_free(&resp);
	printf("\n");
	return failures > 0 ? 1 : 0;
}
