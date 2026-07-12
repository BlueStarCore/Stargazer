/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose_disk.c — Disk health diagnostics for Stargazer CLI
 *
 * Implements "execute diagnose selftest [full]" disk module:
 *   - Mode 0: sgdata partition health (mount, fstype, writable, usage, DB)
 *   - Mode 1: adds sglogs + eMMC block device checks
 *
 * All file reads go through mgmtd IPC (SG_CMD_DIAG_DISK_HEALTH)
 * because the CLI sandbox blocks openat().
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_diagnose.h"
#include "cli_ipc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Test counters ────────────────────────────────────────────────────── */

static int dk_pass;
static int dk_fail;
static int dk_total;

/* ── Assertion helper ─────────────────────────────────────────────────── */

static void dk_check(const char *id, const char *desc, int cond)
{
	dk_total++;
	if (cond) {
		dk_pass++;
		printf(C_GREEN "  PASS" C_NC " [%s] %s\n", id, desc);
	} else {
		dk_fail++;
		printf(C_RED "  FAIL" C_NC " [%s] %s\n", id, desc);
	}
}

/* ── Key=value extraction from IPC payload ────────────────────────────── */

/*
 * Find value for 'key' in "key=value\n..." payload.
 * Returns pointer to value (within payload), or NULL if not found.
 * Writes value length into *vlen.
 */
static const char *dk_get_val(const char *payload, const char *key,
			      size_t *vlen)
{
	if (!payload || !key)
		return NULL;
	size_t klen = strlen(key);
	const char *p = payload;
	while ((p = strstr(p, key)) != NULL) {
		if (p != payload && *(p - 1) != '\n') {
			p += klen;
			continue;
		}
		if (p[klen] != '=') {
			p += klen;
			continue;
		}
		const char *val = p + klen + 1;
		const char *eol = strchr(val, '\n');
		*vlen = eol ? (size_t)(eol - val) : strlen(val);
		return val;
	}
	return NULL;
}

/* Return integer value for key, or dflt if not found. */
static int dk_get_int(const char *payload, const char *key, int dflt)
{
	size_t vlen;
	const char *v = dk_get_val(payload, key, &vlen);
	if (!v)
		return dflt;
	return atoi(v);
}

/* Return 1 if key's value equals 'expected' string. */
static int dk_val_eq(const char *payload, const char *key,
		     const char *expected)
{
	size_t vlen;
	const char *v = dk_get_val(payload, key, &vlen);
	if (!v)
		return 0;
	return vlen == strlen(expected) &&
	       strncmp(v, expected, vlen) == 0;
}

/* ── Public entry point ───────────────────────────────────────────────── */

int cli_diagnose_test_disk(int mode, diag_result_t *out)
{
	dk_pass  = 0;
	dk_fail  = 0;
	dk_total = 0;

	printf("\n  Stargazer Disk Health Diagnostics\n");
	printf("  ==================================\n");

	/* Fetch disk health data via IPC */
	struct ipc_response resp;
	int conn = ipc_send_str(SG_CMD_DIAG_DISK_HEALTH, "", &resp);

	if (conn != 0 || resp.status != SG_OK || !resp.payload) {
		printf(C_RED "\n  ERROR" C_NC
		       ": DIAG_DISK_HEALTH IPC failed (conn=%d status=%u)\n",
		       conn, conn == 0 ? resp.status : 0);
		printf("  All disk tests skipped.\n");
		ipc_resp_free(&resp);
		if (out) {
			out->passed = 0;
			out->failed = 1;
			out->total  = 1;
		}
		return 1;
	}

	const char *data = resp.payload;

	/* --- Mode 0: sgdata tests (local/sgdata only) --- */

	printf(C_CYAN "\n  --- SEC-DISK-1: sgdata mounted at /etc/stargazer ---"
	       C_NC "\n");
	dk_check("SEC-DISK-1", "sgdata mounted",
		 dk_get_int(data, "sgdata_mounted", 0) == 1);

	printf(C_CYAN "\n  --- SEC-DISK-2: sgdata filesystem is ext2 ---"
	       C_NC "\n");
	dk_check("SEC-DISK-2", "sgdata fstype is ext2",
		 dk_val_eq(data, "sgdata_fstype", "ext2"));

	printf(C_CYAN "\n  --- SEC-DISK-3: sgdata writable ---"
	       C_NC "\n");
	dk_check("SEC-DISK-3", "sgdata is writable",
		 dk_get_int(data, "sgdata_writable", 0) == 1);

	printf(C_CYAN "\n  --- SEC-DISK-4: sgdata usage < 90%% ---"
	       C_NC "\n");
	{
		int pct = dk_get_int(data, "sgdata_pct_used", -1);
		char desc[64];
		if (pct >= 0)
			snprintf(desc, sizeof(desc),
				 "sgdata usage %d%% < 90%%", pct);
		else
			snprintf(desc, sizeof(desc),
				 "sgdata usage unknown");
		dk_check("SEC-DISK-4", desc, pct >= 0 && pct < 90);
	}

	printf(C_CYAN "\n  --- SEC-DISK-5: database file accessible ---"
	       C_NC "\n");
	dk_check("SEC-DISK-5", "stargazer.db exists",
		 dk_get_int(data, "sgdata_db_exists", 0) == 1);

	/* --- Mode 1: sglogs + eMMC tests --- */

	if (mode == 1) {
		printf(C_CYAN "\n  --- SEC-DISK-6: sglogs mounted at /etc/stargazer/logs ---"
		       C_NC "\n");
		dk_check("SEC-DISK-6", "sglogs mounted",
			 dk_get_int(data, "sglogs_mounted", 0) == 1);

		printf(C_CYAN "\n  --- SEC-DISK-7: sglogs filesystem is ext2 ---"
		       C_NC "\n");
		dk_check("SEC-DISK-7", "sglogs fstype is ext2",
			 dk_val_eq(data, "sglogs_fstype", "ext2"));

		printf(C_CYAN "\n  --- SEC-DISK-8: sglogs writable ---"
		       C_NC "\n");
		dk_check("SEC-DISK-8", "sglogs is writable",
			 dk_get_int(data, "sglogs_writable", 0) == 1);

		printf(C_CYAN "\n  --- SEC-DISK-9: sglogs usage < 90%% ---"
		       C_NC "\n");
		{
			int pct = dk_get_int(data, "sglogs_pct_used", -1);
			char desc[64];
			if (pct >= 0)
				snprintf(desc, sizeof(desc),
					 "sglogs usage %d%% < 90%%", pct);
			else
				snprintf(desc, sizeof(desc),
					 "sglogs usage unknown");
			dk_check("SEC-DISK-9", desc, pct >= 0 && pct < 90);
		}

		printf(C_CYAN "\n  --- SEC-DISK-10: eMMC block device detected ---"
		       C_NC "\n");
		dk_check("SEC-DISK-10", "eMMC device present",
			 !dk_val_eq(data, "emmc_dev", "none"));

		printf(C_CYAN "\n  --- SEC-DISK-11: eMMC capacity > 0 ---"
		       C_NC "\n");
		{
			size_t vlen;
			const char *v = dk_get_val(data, "emmc_bytes", &vlen);
			unsigned long long bytes = 0;
			if (v)
				bytes = strtoull(v, NULL, 10);
			char desc[64];
			snprintf(desc, sizeof(desc),
				 "eMMC capacity %llu bytes", bytes);
			dk_check("SEC-DISK-11", desc, bytes > 0);
		}
	}

	ipc_resp_free(&resp);

	/* Summary */
	printf("\n  Results: %d/%d passed", dk_pass, dk_total);
	if (dk_fail > 0)
		printf(C_RED ", %d FAILED" C_NC, dk_fail);
	else
		printf(C_GREEN " (all passed)" C_NC);
	printf("\n\n");

	if (out) {
		out->passed = dk_pass;
		out->failed = dk_fail;
		out->total  = dk_total;
	}

	return dk_fail > 0 ? 1 : 0;
}
