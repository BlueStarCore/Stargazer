/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose_supervisor.c — Supervisor selftest suite
 *
 * Implements "execute diagnose selftest supervisor":
 *   - Mode 0: no local-only tests (all checks need IPC)
 *   - Mode 1: IPC round-trip tests for mgmtd process supervisor
 *
 * Tests verify that the supervisor can start, stop, restart, and
 * enforce crash limits on child processes.
 *
 * Uses /bin/sleep and /bin/sh as test binaries — always available.
 * Kills are done via IPC "kill" op (CLI seccomp sandbox blocks fork).
 */

#define _GNU_SOURCE

#include "cli_diagnose.h"
#include "cli_ipc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Test counters ────────────────────────────────────────────────────── */

static int sup_pass;
static int sup_fail;
static int sup_total;

/* ── IPC helpers ──────────────────────────────────────────────────────── */

/*
 * Send a supervisor test command and check the response status.
 */
static void
sup_check(const char *id, const char *desc,
	  const char *payload, uint32_t expect)
{
	struct ipc_response resp;
	int conn;

	sup_total++;
	conn = ipc_send_str(SG_CMD_SUPERVISOR_TEST, payload, &resp);

	if (conn == 0 && resp.status == expect) {
		sup_pass++;
		printf(C_GREEN "  PASS" C_NC " [%s] %s\n", id, desc);
	} else {
		sup_fail++;
		printf(C_RED "  FAIL" C_NC " [%s] %s"
		       " (expected status=%u, got %u)\n",
		       id, desc, expect,
		       conn < 0 ? 999 : resp.status);
	}

	ipc_resp_free(&resp);
}

/*
 * Query a supervised process and parse pid from response.
 * Returns pid (>0 if running), 0 if not found, -1 on error.
 */
static int
sup_query_pid(const char *name)
{
	char payload[128];
	snprintf(payload, sizeof(payload), "query\n%s", name);

	struct ipc_response resp;
	int conn = ipc_send_str(SG_CMD_SUPERVISOR_TEST, payload, &resp);
	if (conn < 0 || resp.status != SG_OK) {
		uint32_t st = resp.status;
		ipc_resp_free(&resp);
		return st == SG_ERR_NOT_FOUND ? 0 : -1;
	}

	int pid = 0;
	if (resp.payload)
		sscanf(resp.payload, "pid=%d", &pid);
	ipc_resp_free(&resp);
	return pid;
}

/*
 * Query restart_count for a supervised process. Returns -1 on error.
 */
static int
sup_query_restart_count(const char *name)
{
	char payload[128];
	snprintf(payload, sizeof(payload), "query\n%s", name);

	struct ipc_response resp;
	int conn = ipc_send_str(SG_CMD_SUPERVISOR_TEST, payload, &resp);
	if (conn < 0 || resp.status != SG_OK) {
		ipc_resp_free(&resp);
		return -1;
	}

	int count = -1;
	if (resp.payload) {
		const char *p = strstr(resp.payload, "restart_count=");
		if (p)
			sscanf(p, "restart_count=%d", &count);
	}
	ipc_resp_free(&resp);
	return count;
}

/* Fire-and-forget IPC helper */
static void
sup_ipc(const char *payload)
{
	struct ipc_response resp;
	ipc_send_str(SG_CMD_SUPERVISOR_TEST, payload, &resp);
	ipc_resp_free(&resp);
}

/* Kill a supervised child via IPC (CLI can't fork due to seccomp) */
static void
sup_kill(const char *name)
{
	char payload[128];
	snprintf(payload, sizeof(payload), "kill\n%s", name);
	sup_ipc(payload);
}

/* ── Tests ────────────────────────────────────────────────────────────── */

static void test_supervisor(void)
{
	/* ── SEC-SUP-1: Start sleep 300, query, verify running ──────── */
	printf(C_CYAN "\n  --- SEC-SUP-1: Start and query ---" C_NC "\n");

	sup_check("SEC-SUP-1a", "start sleep 300",
		  "start\n__test_sup1\n/bin/sleep\n300", SG_OK);

	/* Give child time to start */
	usleep(200000);

	int pid1 = sup_query_pid("__test_sup1");
	sup_total++;
	if (pid1 > 0) {
		sup_pass++;
		printf(C_GREEN "  PASS" C_NC " [SEC-SUP-1b] child running "
		       "(pid=%d)\n", pid1);
	} else {
		sup_fail++;
		printf(C_RED "  FAIL" C_NC " [SEC-SUP-1b] child not running "
		       "(pid=%d)\n", pid1);
	}

	/* Cleanup */
	sup_ipc("stop\n__test_sup1");

	/* ── SEC-SUP-2: Start exit-1, wait, verify restart count ────── */
	printf(C_CYAN "\n  --- SEC-SUP-2: Auto-restart on crash ---"
	       C_NC "\n");

	/* /bin/sh -c 'exit 1' exits immediately with code 1 */
	sup_check("SEC-SUP-2a", "start crashing child",
		  "start\n__test_sup2\n/bin/sh\n-c\nexit 1", SG_OK);

	/* Wait for a few restart cycles (backoff: 1+2+3 = 6s) */
	sleep(8);

	int count = sup_query_restart_count("__test_sup2");
	sup_total++;
	if (count > 0) {
		sup_pass++;
		printf(C_GREEN "  PASS" C_NC " [SEC-SUP-2b] restart_count=%d "
		       "(> 0)\n", count);
	} else {
		sup_fail++;
		printf(C_RED "  FAIL" C_NC " [SEC-SUP-2b] restart_count=%d "
		       "(expected > 0)\n", count);
	}

	/* Cleanup */
	sup_ipc("stop\n__test_sup2");

	/* ── SEC-SUP-3: Kill child, verify restarted with new PID ───── */
	printf(C_CYAN "\n  --- SEC-SUP-3: Restart after kill ---" C_NC "\n");

	sup_check("SEC-SUP-3a", "start sleep 300",
		  "start\n__test_sup3\n/bin/sleep\n300", SG_OK);
	usleep(200000);

	int pid3a = sup_query_pid("__test_sup3");
	if (pid3a > 0) {
		/* Kill via IPC (sends SIGKILL to the child) */
		sup_kill("__test_sup3");

		/* Wait for supervisor to detect and restart */
		sleep(3);

		int pid3b = sup_query_pid("__test_sup3");
		sup_total++;
		if (pid3b > 0 && pid3b != pid3a) {
			sup_pass++;
			printf(C_GREEN "  PASS" C_NC " [SEC-SUP-3b] restarted "
			       "with new pid (old=%d, new=%d)\n",
			       pid3a, pid3b);
		} else {
			sup_fail++;
			printf(C_RED "  FAIL" C_NC " [SEC-SUP-3b] not restarted "
			       "(old=%d, current=%d)\n", pid3a, pid3b);
		}
	} else {
		sup_total++;
		sup_fail++;
		printf(C_RED "  FAIL" C_NC " [SEC-SUP-3b] initial start "
		       "failed\n");
	}

	/* Cleanup */
	sup_ipc("stop\n__test_sup3");

	/* ── SEC-SUP-4: Start then stop, verify gone ────────────────── */
	printf(C_CYAN "\n  --- SEC-SUP-4: Stop removes from table ---"
	       C_NC "\n");

	sup_check("SEC-SUP-4a", "start sleep 300",
		  "start\n__test_sup4\n/bin/sleep\n300", SG_OK);
	usleep(200000);

	sup_check("SEC-SUP-4b", "stop child",
		  "stop\n__test_sup4", SG_OK);

	/* Query should return NOT_FOUND */
	sup_check("SEC-SUP-4c", "query after stop -> not found",
		  "query\n__test_sup4", SG_ERR_NOT_FOUND);

	/* ── SEC-SUP-5: SRC_CONFIG restart gating ───────────────────── */
	printf(C_CYAN "\n  --- SEC-SUP-5: Config-gated restart ---"
	       C_NC "\n");

	/* Create a test interface config entry with mode=dhcp */
	{
		struct ipc_response r;
		ipc_send_str(SG_CMD_CFG_SET,
			     "system_interface:__sup_test\n"
			     "mode=dhcp\nstatus=up\nip=127.0.0.1/8\n"
			     "mtu=1500\n", &r);
		ipc_resp_free(&r);
	}

	/* Start config-gated child: only restart if mode=dhcp.
	 * Use sleep 300 so it stays alive between kills. */
	sup_check("SEC-SUP-5a", "start config-gated child",
		  "start_config\n__test_sup5\n"
		  "/bin/sleep\n300\n"
		  "---\n"
		  "system_interface\n__sup_test\nmode\ndhcp", SG_OK);
	usleep(200000);

	/* Kill it — should restart because mode=dhcp */
	int pid5a = sup_query_pid("__test_sup5");
	if (pid5a > 0) {
		sup_kill("__test_sup5");
		sleep(3);

		int pid5b = sup_query_pid("__test_sup5");
		sup_total++;
		if (pid5b > 0 && pid5b != pid5a) {
			sup_pass++;
			printf(C_GREEN "  PASS" C_NC
			       " [SEC-SUP-5b] restarted (mode=dhcp)\n");
		} else {
			sup_fail++;
			printf(C_RED "  FAIL" C_NC
			       " [SEC-SUP-5b] should have restarted\n");
		}

		/* Change config to mode=static */
		{
			struct ipc_response r;
			ipc_send_str(SG_CMD_CFG_SET,
				     "system_interface:__sup_test\n"
				     "mode=static\nstatus=up\n"
				     "ip=127.0.0.1/8\nmtu=1500\n", &r);
			ipc_resp_free(&r);
		}

		/* Kill again — should NOT restart (mode != dhcp) */
		int pid5c = sup_query_pid("__test_sup5");
		if (pid5c > 0) {
			sup_kill("__test_sup5");
			sleep(3);

			int pid5d = sup_query_pid("__test_sup5");
			sup_total++;
			if (pid5d == 0) {
				sup_pass++;
				printf(C_GREEN "  PASS" C_NC
				       " [SEC-SUP-5c] not restarted"
				       " (mode=static)\n");
			} else {
				sup_fail++;
				printf(C_RED "  FAIL" C_NC
				       " [SEC-SUP-5c] should not have"
				       " restarted\n");
			}
		}
	} else {
		sup_total += 2;
		sup_fail += 2;
		printf(C_RED "  FAIL" C_NC " [SEC-SUP-5b] initial start "
		       "failed\n");
		printf(C_RED "  FAIL" C_NC " [SEC-SUP-5c] skipped\n");
	}

	/* Cleanup */
	sup_ipc("stop\n__test_sup5");
	{
		struct ipc_response r;
		ipc_send_str(SG_CMD_CFG_DEL,
			     "system_interface:__sup_test", &r);
		ipc_resp_free(&r);
	}

	/* ── SEC-SUP-6: Crash loop gives up after max attempts ──────── */
	printf(C_CYAN "\n  --- SEC-SUP-6: Crash loop limit ---" C_NC "\n");

	sup_check("SEC-SUP-6a", "start crashing child",
		  "start\n__test_sup6\n/bin/sh\n-c\nexit 1", SG_OK);

	/* Wait for crash loop to exhaust (5 restarts x ~5s backoff max
	 * = ~15s worst case; we wait generously) */
	sleep(20);

	int pid6 = sup_query_pid("__test_sup6");
	sup_total++;
	if (pid6 == 0) {
		sup_pass++;
		printf(C_GREEN "  PASS" C_NC " [SEC-SUP-6b] child gave up "
		       "after max restarts\n");
	} else {
		sup_fail++;
		printf(C_RED "  FAIL" C_NC " [SEC-SUP-6b] child still in "
		       "table (pid=%d)\n", pid6);
	}

	/* Cleanup (may already be gone) */
	sup_ipc("stop\n__test_sup6");
}

/* ── Public entry point ───────────────────────────────────────────────── */

int cli_diagnose_test_supervisor(int mode, diag_result_t *out)
{
	sup_pass  = 0;
	sup_fail  = 0;
	sup_total = 0;

	printf("\n  Stargazer Supervisor Tests\n");
	printf("  ==========================\n");

	if (mode == 0) {
		printf("  (no local-only tests — run 'selftest supervisor'"
		       " for full IPC tests)\n");
	}

	if (mode == 1) {
		if (!ipc_available()) {
			printf(C_RED "\n  ERROR" C_NC
			       ": mgmtd socket not found (%s)\n",
			       SG_MGMTD_SOCK);
			printf("  IPC tests skipped."
			       " Run with mgmtd for full test.\n");
		} else {
			test_supervisor();
		}
	}

	/* Summary */
	printf("\n  Results: %d/%d passed", sup_pass, sup_total);
	if (sup_fail > 0)
		printf(C_RED ", %d FAILED" C_NC, sup_fail);
	else if (sup_total > 0)
		printf(C_GREEN " (all passed)" C_NC);
	printf("\n\n");

	if (out) {
		out->passed = sup_pass;
		out->failed = sup_fail;
		out->total  = sup_total;
	}

	return sup_fail > 0 ? 1 : 0;
}
