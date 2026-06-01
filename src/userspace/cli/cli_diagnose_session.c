/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose_session.c — Connection-tracking diagnostics for Stargazer CLI
 *
 * Connection state lives in the kernel's nf_conntrack. These checks verify the
 * conntrack-backed session views work (SG_CMD_SESSION_STATS /
 * SG_CMD_SHOW_SESSIONS) and that pkt_forward.ko's anomaly screen is active.
 *
 * Invoked via: execute diagnose selftest session
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_diagnose.h"
#include "cli_ipc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Test counters ────────────────────────────────────────────────────── */

static int ss_pass;
static int ss_fail;
static int ss_total;

/* ── Assertion helper ─────────────────────────────────────────────────── */

static void ss_check(const char *id, const char *desc, int result)
{
	ss_total++;
	if (result) {
		ss_pass++;
		printf("  [" C_GREEN "PASS" C_NC "] %s: %s\n", id, desc);
	} else {
		ss_fail++;
		printf("  [" C_RED "FAIL" C_NC "] %s: %s\n", id, desc);
	}
}

/* ── SESS-01..05: conntrack availability + session views ──────────────── */

static void test_conntrack_views(void)
{
	printf(C_CYAN "\n  --- SESS-01..05: conntrack-backed session views ---" C_NC "\n");

	/* Stats: conntrack availability + pkt_forward status + counters */
	struct ipc_response stats = {0};
	int stats_ok = (ipc_send_str(SG_CMD_SESSION_STATS, "", &stats) == 0 &&
			stats.status == SG_OK);
	const char *sp = (stats_ok && stats.payload) ? stats.payload : "";
	const char *kv;

	int ct_ok = 0;
	kv = strstr(sp, "conntrack_available=");
	if (kv) ct_ok = (int)strtol(kv + 20, NULL, 10);
	ss_check("SESS-01", "conntrack available (/proc/net/nf_conntrack readable)",
		 stats_ok && ct_ok);

	int pkt_fwd = 0;
	kv = strstr(sp, "pkt_forward_loaded=");
	if (kv) pkt_fwd = (int)strtol(kv + 19, NULL, 10);
	ss_check("SESS-02", "pkt_forward.ko loaded (anomaly screen active)",
		 stats_ok && pkt_fwd);

	ss_check("SESS-04", "stats report a flow count (active= field)",
		 strstr(sp, "active=") != NULL);
	ss_check("SESS-05", "stats report pkt_forward counters (forwarded= field)",
		 strstr(sp, "forwarded=") != NULL);

	ipc_resp_free(&stats);

	/* Show: the normalized connection list */
	struct ipc_response resp = {0};
	int conn = ipc_send_str(SG_CMD_SHOW_SESSIONS, "", &resp);
	int ok = (conn == 0 && resp.status == SG_OK &&
		  strcmp(resp.extra, "not_available") != 0);
	const char *p = (ok && resp.payload) ? resp.payload : "";
	ss_check("SESS-03", "show sessions returns conntrack table (active= header)",
		 ok && strstr(p, "active=") != NULL);
	ipc_resp_free(&resp);
}

/* ── Public entry point ────────────────────────────────────────────────── */

int cli_diagnose_test_session(int mode, diag_result_t *out)
{
	(void)mode;   /* conntrack views are the same in basic/full mode */
	diag_result_t local = {0};
	if (!out) out = &local;

	ss_pass = ss_fail = ss_total = 0;

	printf("\n  " C_CYAN "=== Session (conntrack) Tests ===" C_NC "\n");

	test_conntrack_views();

	out->passed += ss_pass;
	out->failed += ss_fail;
	out->total  += ss_total;

	return ss_fail > 0 ? 1 : 0;
}
