/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose_session.c — Session tracking diagnostics for Stargazer CLI
 *
 * Tests that session.ko and pkt_forward.ko are loaded and working correctly.
 *
 * mode=0 (basic): Verify procfs is readable and correctly formatted.
 * mode=1 (full):  Load session_test.ko via mgmtd and verify bidirectional
 *                 session tracking (requires session.ko loaded, root capable).
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

/* ── SESS-01..07: Module status + procfs format (mode=0) ─────────────── */

static void test_procfs_format(void)
{
	printf(C_CYAN "\n  --- SESS-01..07: module status + procfs format ---" C_NC "\n");

	/* Structured stats includes module load status + parsed counters */
	struct ipc_response stats_resp = {0};
	int stats_ok = (ipc_send_str(SG_CMD_SESSION_STATS, "", &stats_resp) == 0 &&
			stats_resp.status == SG_OK);

	const char *sp = (stats_ok && stats_resp.payload) ? stats_resp.payload : "";
	const char *kv;

	/* SESS-01: session.ko loaded */
	int sess_loaded = 0;
	kv = strstr(sp, "session_loaded=");
	if (kv) sess_loaded = (int)strtol(kv + 15, NULL, 10);
	ss_check("SESS-01", "session.ko loaded (/proc/stargazer/sessions readable)",
		 stats_ok && sess_loaded);

	/* SESS-02: pkt_forward.ko loaded */
	int pkt_fwd_loaded = 0;
	kv = strstr(sp, "pkt_forward_loaded=");
	if (kv) pkt_fwd_loaded = (int)strtol(kv + 19, NULL, 10);
	ss_check("SESS-02", "pkt_forward.ko loaded (/sys/module/pkt_forward exists)",
		 stats_ok && pkt_fwd_loaded);

	ipc_resp_free(&stats_resp);

	/* Fetch raw procfs for format checks */
	struct ipc_response resp = {0};
	int conn = ipc_send_str(SG_CMD_SHOW_SESSIONS, "", &resp);
	int loaded = (conn == 0 && resp.status == SG_OK &&
		      strcmp(resp.extra, "not_available") != 0);

	if (!loaded) {
		ss_check("SESS-03", "procfs header contains active= field",    0);
		ss_check("SESS-04", "procfs header contains created= counter", 0);
		ss_check("SESS-05", "procfs header contains expired= counter", 0);
		ss_check("SESS-06", "procfs header contains invalid= counter", 0);
		ss_check("SESS-07", "procfs column header present (# proto)",  0);
		ipc_resp_free(&resp);
		return;
	}

	const char *p = resp.payload ? resp.payload : "";

	ss_check("SESS-03", "procfs header contains active= field",
		 strstr(p, "active=") != NULL);
	ss_check("SESS-04", "procfs header contains created= counter",
		 strstr(p, "created=") != NULL);
	ss_check("SESS-05", "procfs header contains expired= counter",
		 strstr(p, "expired=") != NULL);
	ss_check("SESS-06", "procfs header contains invalid= counter",
		 strstr(p, "invalid=") != NULL);
	ss_check("SESS-07", "procfs column header present (# proto src dst)",
		 strstr(p, "# proto") != NULL);

	ipc_resp_free(&resp);
}

/* ── SESS-08..12: session_test.ko kernel self-test (mode=1) ────────────── */

static void test_session_inject(void)
{
	printf(C_CYAN "\n  --- SESS-08..12: kernel session API test ---" C_NC "\n");

	struct ipc_response resp = {0};
	int conn = ipc_send_str(SG_CMD_DIAG_SESSION, "inject\n", &resp);

	/* SESS-08: inject test completes without error */
	int ok = (conn == 0 && resp.status == SG_OK);
	ss_check("SESS-08", "session_test.ko loaded and ran (mgmtd returned SG_OK)", ok);

	if (!ok) {
		const char *hint = (resp.extra[0]) ? resp.extra : "(no detail)";
		printf("           hint: %s\n", hint);
		ss_check("SESS-09", "session created (sessions_created=1)",  0);
		ss_check("SESS-10", "orig direction tracked (pkts_orig=1)",  0);
		ss_check("SESS-11", "bytes accounted (bytes_orig=32)",       0);
		ss_check("SESS-12", "bidirectional tracking (pkts_reply=1)", 0);
		ipc_resp_free(&resp);
		return;
	}

	const char *p = resp.payload ? resp.payload : "";

	/* SESS-09: sessions_created=1 */
	long long sc = -1;
	const char *kv = strstr(p, "sessions_created=");
	if (kv) sc = strtoll(kv + 17, NULL, 10);
	ss_check("SESS-09", "session created (sessions_created=1)", sc == 1);

	/* SESS-10: pkts_orig=1 */
	long long po = -1;
	kv = strstr(p, "pkts_orig=");
	if (kv) po = strtoll(kv + 10, NULL, 10);
	ss_check("SESS-10", "orig direction tracked (pkts_orig=1)", po == 1);

	/* SESS-11: bytes_orig=32 (IP+UDP+payload) */
	long long bo = -1;
	kv = strstr(p, "bytes_orig=");
	if (kv) bo = strtoll(kv + 11, NULL, 10);
	ss_check("SESS-11", "bytes accounted (bytes_orig=32)", bo == 32);

	/* SESS-12: bidirectional=1 */
	long long bi = -1;
	kv = strstr(p, "bidirectional=");
	if (kv) bi = strtoll(kv + 14, NULL, 10);
	ss_check("SESS-12", "bidirectional tracking (pkts_reply=1)", bi == 1);

	ipc_resp_free(&resp);
}

/* ── Public entry point ────────────────────────────────────────────────── */

int cli_diagnose_test_session(int mode, diag_result_t *out)
{
	diag_result_t local = {0};
	if (!out) out = &local;

	ss_pass = ss_fail = ss_total = 0;

	printf("\n  " C_CYAN "=== Session Tracking Tests ===" C_NC "\n");

	test_procfs_format();

	if (mode >= 1)
		test_session_inject();

	out->passed += ss_pass;
	out->failed += ss_fail;
	out->total  += ss_total;

	return ss_fail > 0 ? 1 : 0;
}
