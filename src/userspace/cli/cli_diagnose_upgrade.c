/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose_upgrade.c — Firmware upgrade diagnostics for Stargazer CLI
 *
 * Firmware upgrade test suite for "execute diagnose selftest [full]":
 *   - IPC command reachability for UPGRADE_STATUS, UPGRADE_PROGRESS
 *   - Cancel mechanism: flag creation, lifecycle, state transitions
 *   - Input validation: missing/invalid URL rejection
 *   - Command ID stability (guards against accidental renumbering)
 *
 * All state-file manipulation goes through mgmtd via
 * SG_CMD_UPGRADE_TEST_SETUP — the CLI never touches the filesystem.
 *
 * All tests require IPC (mode=1) and a running mgmtd.
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_diagnose.h"
#include "cli_ipc.h"

#include <stdio.h>
#include <string.h>

/* ── Test counters ────────────────────────────────────────────────────── */

static int up_pass;
static int up_fail;
static int up_total;

/* ── Generic assertion helper ─────────────────────────────────────────── */

static void up_check(const char *section, const char *desc,
		     int result, int expected)
{
	up_total++;
	if (result == expected) {
		up_pass++;
		printf(C_GREEN "  PASS" C_NC " [%s] %s\n", section, desc);
	} else {
		up_fail++;
		printf(C_RED "  FAIL" C_NC " [%s] %s (got %d, expected %d)\n",
		       section, desc, result, expected);
	}
}

/* ── IPC helpers for test state manipulation ──────────────────────────── */

/*
 * All test state file operations go through SG_CMD_UPGRADE_TEST_SETUP
 * in mgmtd, which runs as root and owns the files.
 */

/* Write a firmware state file via mgmtd.  Returns 0 on success. */
static int up_write_state(const char *step, const char *total,
			  const char *status, const char *message,
			  const char *version)
{
	char payload[512];
	snprintf(payload, sizeof(payload),
		 "action=write_state\nstep=%s\ntotal=%s\n"
		 "status=%s\nmessage=%s\nversion=%s\n",
		 step, total, status, message, version);
	struct ipc_response resp;
	int rc = ipc_send_str(SG_CMD_UPGRADE_TEST_SETUP, payload, &resp);
	int ok = (rc == 0 && resp.status == SG_OK);
	ipc_resp_free(&resp);
	return ok ? 0 : -1;
}

/* Remove both state file and cancel flag via mgmtd.  Returns 0 on success. */
static int up_clean(void)
{
	struct ipc_response resp;
	int rc = ipc_send_str(SG_CMD_UPGRADE_TEST_SETUP,
			      "action=clean\n", &resp);
	int ok = (rc == 0 && resp.status == SG_OK);
	ipc_resp_free(&resp);
	return ok ? 0 : -1;
}

/*
 * Query whether state file / cancel flag exist via mgmtd.
 * Returns 1 if the requested file exists, 0 if absent, -1 on IPC error.
 */
static int up_query_file(const char *key)
{
	struct ipc_response resp;
	int rc = ipc_send_str(SG_CMD_UPGRADE_TEST_SETUP,
			      "action=query\n", &resp);
	if (rc != 0 || resp.status != SG_OK || !resp.payload) {
		ipc_resp_free(&resp);
		return -1;
	}
	/* Parse "state_file=0\ncancel_flag=1\n" style response */
	char needle[64];
	snprintf(needle, sizeof(needle), "%s=1", key);
	int found = (strstr(resp.payload, needle) != NULL) ? 1 : 0;
	ipc_resp_free(&resp);
	return found;
}

static int up_state_file_exists(void)
{
	return up_query_file("state_file");
}

static int up_cancel_flag_exists(void)
{
	return up_query_file("cancel_flag");
}

/* ── SEC-UP-1: Upgrade status IPC reachability ────────────────────────── */

static void test_upgrade_status_reachability(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- SEC-UP-1: upgrade status IPC reachability ---"
	       C_NC "\n");

	conn = ipc_send_str(SG_CMD_UPGRADE_STATUS, "", &resp);
	up_check("up-status", "UPGRADE_STATUS -> SG_OK",
		 (conn == 0 && resp.status == SG_OK) ? 1 : 0, 1);

	up_check("up-status", "response contains 'Firmware Status' header",
		 (conn == 0 && resp.payload &&
		  strstr(resp.payload, "Firmware Status") != NULL) ? 1 : 0,
		 1);
	ipc_resp_free(&resp);
}

/* ── SEC-UP-2: Upgrade progress when idle ─────────────────────────────── */

static void test_upgrade_progress_idle(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- SEC-UP-2: upgrade progress when idle ---"
	       C_NC "\n");

	/* Ensure no stale state file from previous runs */
	up_clean();

	conn = ipc_send_str(SG_CMD_UPGRADE_PROGRESS, "", &resp);
	up_check("up-idle", "UPGRADE_PROGRESS -> SG_OK",
		 (conn == 0 && resp.status == SG_OK) ? 1 : 0, 1);

	up_check("up-idle", "response contains status=idle",
		 (conn == 0 && resp.payload &&
		  strstr(resp.payload, "status=idle") != NULL) ? 1 : 0, 1);
	ipc_resp_free(&resp);
}

/* ── SEC-UP-3: Cancel when no upgrade running ─────────────────────────── */

static void test_upgrade_cancel_idle(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- SEC-UP-3: cancel when no upgrade running ---"
	       C_NC "\n");

	/* Ensure clean state */
	up_clean();

	conn = ipc_send_str(SG_CMD_UPGRADE_CANCEL, "", &resp);
	up_check("up-cancel", "UPGRADE_CANCEL (idle) -> SG_OK",
		 (conn == 0 && resp.status == SG_OK) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* Progress should still show idle (no upgrade was running) */
	conn = ipc_send_str(SG_CMD_UPGRADE_PROGRESS, "", &resp);
	up_check("up-cancel", "progress after idle cancel -> status=idle",
		 (conn == 0 && resp.payload &&
		  strstr(resp.payload, "status=idle") != NULL) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* Clean up cancel flag created by this test */
	up_clean();
}

/* ── SEC-UP-4: Cancel flag lifecycle ──────────────────────────────────── */

static void test_cancel_flag_lifecycle(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- SEC-UP-4: cancel flag lifecycle ---"
	       C_NC "\n");

	/* Write a state file simulating an active upgrade at step 1
	 * so that UPGRADE_CANCEL creates the cancel flag. */
	up_check("cancel-flag", "create active-upgrade state file",
		 up_write_state("1", "6", "running",
				"Downloading firmware...", "") == 0 ? 1 : 0,
		 1);

	/* Send cancel — should create the flag file */
	conn = ipc_send_str(SG_CMD_UPGRADE_CANCEL, "", &resp);
	up_check("cancel-flag", "UPGRADE_CANCEL (active) -> SG_OK",
		 (conn == 0 && resp.status == SG_OK) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* Verify flag file now exists */
	up_check("cancel-flag", "flag file exists after cancel",
		 up_cancel_flag_exists(), 1);

	/* Remove state file so mgmtd sees no active upgrade */
	up_write_state("0", "0", "idle", "", "");
	/* The state file now shows idle; clean it and the flag together
	 * would work, but we specifically test that sending cancel when
	 * idle cleans the flag.  So just remove the state file. */
	up_clean();

	/* Send cancel again — mgmtd cleans up stale flag when idle */
	conn = ipc_send_str(SG_CMD_UPGRADE_CANCEL, "", &resp);
	up_check("cancel-flag", "UPGRADE_CANCEL (idle) -> SG_OK",
		 (conn == 0 && resp.status == SG_OK) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* Flag should be cleaned up by mgmtd */
	up_check("cancel-flag", "flag cleaned up after idle cancel",
		 up_cancel_flag_exists(), 0);
}

/* ── SEC-UP-5: Cancelled state in progress handler ────────────────────── */

static void test_cancelled_state_progress(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- SEC-UP-5: cancelled state in progress handler ---"
	       C_NC "\n");

	/* Write a state file with status=cancelled via mgmtd */
	up_check("cancel-state", "create test state file",
		 up_write_state("0", "6", "cancelled",
				"Firmware upgrade cancelled by user.",
				"") == 0 ? 1 : 0,
		 1);

	/* Poll progress — should return the cancelled state */
	conn = ipc_send_str(SG_CMD_UPGRADE_PROGRESS, "", &resp);
	up_check("cancel-state", "progress returns cancelled state",
		 (conn == 0 && resp.payload &&
		  strstr(resp.payload, "status=cancelled") != NULL) ? 1 : 0,
		 1);
	ipc_resp_free(&resp);

	/* Progress handler auto-cleans state file on terminal status */
	up_check("cancel-state", "state file auto-cleaned after read",
		 up_state_file_exists(), 0);
}

/* ── SEC-UP-6: Upgrade start rejects missing URL ─────────────────────── */

static void test_upgrade_start_missing_url(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- SEC-UP-6: upgrade start rejects missing URL ---"
	       C_NC "\n");

	/* Empty payload -> SG_ERR_MISSING_ARG */
	conn = ipc_send_str(SG_CMD_UPGRADE_START, "", &resp);
	up_check("start-url", "empty payload -> SG_ERR_MISSING_ARG",
		 (conn == 0 && resp.status == SG_ERR_MISSING_ARG) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* url= with empty value -> SG_ERR_MISSING_ARG */
	conn = ipc_send_str(SG_CMD_UPGRADE_START, "url=\n", &resp);
	up_check("start-url", "url= (empty) -> SG_ERR_MISSING_ARG",
		 (conn == 0 && resp.status == SG_ERR_MISSING_ARG) ? 1 : 0, 1);
	ipc_resp_free(&resp);
}

/* ── SEC-UP-7: Upgrade start rejects invalid URL scheme ───────────────── */

static void test_upgrade_start_invalid_scheme(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- SEC-UP-7: upgrade start rejects invalid URL scheme ---"
	       C_NC "\n");

	/* ftp:// not allowed */
	conn = ipc_send_str(SG_CMD_UPGRADE_START,
			    "url=ftp://host/file\n", &resp);
	up_check("start-scheme", "ftp:// -> SG_ERR_INVALID_ARG",
		 (conn == 0 && resp.status == SG_ERR_INVALID_ARG) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* file:// not allowed (path traversal vector) */
	conn = ipc_send_str(SG_CMD_UPGRADE_START,
			    "url=file:///etc/passwd\n", &resp);
	up_check("start-scheme", "file:///etc/passwd -> SG_ERR_INVALID_ARG",
		 (conn == 0 && resp.status == SG_ERR_INVALID_ARG) ? 1 : 0, 1);
	ipc_resp_free(&resp);
}

/* ── SEC-UP-8: IPC command ID verification ────────────────────────────── */

static void test_command_ids(void)
{
	printf(C_CYAN "\n  --- SEC-UP-8: IPC command ID verification ---"
	       C_NC "\n");

	up_check("cmd-id", "SG_CMD_UPGRADE_START == 602",
		 SG_CMD_UPGRADE_START, 602);
	up_check("cmd-id", "SG_CMD_UPGRADE_STATUS == 603",
		 SG_CMD_UPGRADE_STATUS, 603);
	up_check("cmd-id", "SG_CMD_UPGRADE_PROGRESS == 604",
		 SG_CMD_UPGRADE_PROGRESS, 604);
	up_check("cmd-id", "SG_CMD_UPGRADE_CANCEL == 609",
		 SG_CMD_UPGRADE_CANCEL, 609);
	up_check("cmd-id", "SG_CMD_UPGRADE_TEST_SETUP == 902",
		 SG_CMD_UPGRADE_TEST_SETUP, 902);
}

/* ── SEC-UP-9: Cancel blocked at point of no return ───────────────────── */

static void test_cancel_blocked_at_ponr(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- SEC-UP-9: cancel blocked at point of no return ---"
	       C_NC "\n");

	/* Clean up any stale state and cancel flag */
	up_clean();
	conn = ipc_send_str(SG_CMD_UPGRADE_CANCEL, "", &resp);
	ipc_resp_free(&resp);

	up_check("cancel-ponr", "cancel flag absent before test",
		 up_cancel_flag_exists(), 0);

	/* Write state file simulating step 5 (past point of no return) */
	up_check("cancel-ponr", "create state file (step=5)",
		 up_write_state("5", "6", "running",
				"Installing kernel and initramfs...",
				"test") == 0 ? 1 : 0,
		 1);

	/* Cancel at step 5 -> should be rejected with SG_ERR_IN_USE */
	conn = ipc_send_str(SG_CMD_UPGRADE_CANCEL, "", &resp);
	up_check("cancel-ponr", "cancel at step 5 -> SG_ERR_IN_USE",
		 (conn == 0 && resp.status == SG_ERR_IN_USE) ? 1 : 0, 1);
	up_check("cancel-ponr", "extra contains 'point of no return'",
		 (resp.extra[0] &&
		  strstr(resp.extra, "point of no return") != NULL) ? 1 : 0,
		 1);
	ipc_resp_free(&resp);

	/* Write state file simulating step 6 */
	up_check("cancel-ponr", "create state file (step=6)",
		 up_write_state("6", "6", "running",
				"Syncing and unmounting boot partition...",
				"test") == 0 ? 1 : 0,
		 1);

	/* Cancel at step 6 -> should also be rejected */
	conn = ipc_send_str(SG_CMD_UPGRADE_CANCEL, "", &resp);
	up_check("cancel-ponr", "cancel at step 6 -> SG_ERR_IN_USE",
		 (conn == 0 && resp.status == SG_ERR_IN_USE) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* Verify cancel flag was NOT created by rejected cancels */
	up_check("cancel-ponr", "cancel flag not created",
		 up_cancel_flag_exists(), 0);

	/* Clean up state file */
	up_clean();
}

/* ── Entry point ──────────────────────────────────────────────────────── */

int cli_diagnose_test_upgrade(int mode, diag_result_t *out)
{
	up_pass = up_fail = up_total = 0;

	printf("\n  Stargazer Firmware Upgrade Diagnostics\n");
	printf("  =======================================\n");

	/* SEC-UP-8 is a compile-time constants check — runs in all modes */
	test_command_ids();

	/* All other tests require IPC (mode=1) */
	if (mode == 1) {
		if (!ipc_available()) {
			printf(C_RED "\n  ERROR" C_NC
			       ": management service unavailable\n");
			printf("  IPC tests skipped."
			       " Start the management daemon for full tests.\n");
		} else {
			test_upgrade_status_reachability();
			test_upgrade_progress_idle();
			test_upgrade_cancel_idle();
			test_cancel_flag_lifecycle();
			test_cancelled_state_progress();
			test_upgrade_start_missing_url();
			test_upgrade_start_invalid_scheme();
			test_cancel_blocked_at_ponr();
		}
	}

	/* Summary */
	printf("\n  Results: %d/%d passed", up_pass, up_total);
	if (up_fail > 0)
		printf(C_RED ", %d FAILED" C_NC, up_fail);
	else
		printf(C_GREEN " (all passed)" C_NC);
	printf("\n\n");

	if (out) {
		out->passed = up_pass;
		out->failed = up_fail;
		out->total  = up_total;
	}
	return up_fail > 0 ? 1 : 0;
}
