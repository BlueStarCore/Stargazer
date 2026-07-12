/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose.h — Built-in diagnostic commands for Stargazer CLI
 */

#ifndef CLI_DIAGNOSE_H
#define CLI_DIAGNOSE_H

/* ── ANSI colors (shared by cli_diagnose.c and cli_diagnose_config.c) ── */

#define C_GREEN  "\033[0;32m"
#define C_RED    "\033[0;31m"
#define C_CYAN   "\033[0;36m"
#define C_NC     "\033[0m"

/*
 * Test result counters — if non-NULL, each function writes its totals here
 * so the unified selftest runner can aggregate across all suites.
 */
typedef struct {
	int passed;
	int failed;
	int total;
} diag_result_t;

/*
 * Run IPC permission model diagnostics.
 *   mode=0: self-test (verify current user's access matches permissions)
 *   mode=1: full test (also creates temp accounts and verifies profile data)
 * Returns 0 on all-pass, 1 on any failure.
 */
int cli_diagnose_test_permissions(int mode, const char *permissions,
				  diag_result_t *out);

/*
 * Run configuration validation diagnostics.
 *   mode=0: validator unit tests (no IPC needed)
 *   mode=1: full test (also runs IPC round-trip create/read/delete)
 * Returns 0 on all-pass, 1 on any failure.
 */
int cli_diagnose_test_configure(int mode, diag_result_t *out);

/*
 * Run firewall & network validator diagnostics.
 *   mode=0: local-only tests (validators, no IPC needed)
 *   mode=1: full test (adds IPC round-trip tests requiring mgmtd)
 * Returns 0 on all-pass, 1 on any failure.
 */
int cli_diagnose_test_firewall(int mode, diag_result_t *out);

/*
 * Run firmware upgrade diagnostics.
 *   mode=0: command ID verification only (no IPC needed)
 *   mode=1: full test (IPC round-trip: status, progress, cancel, start validation)
 * Returns 0 on all-pass, 1 on any failure.
 */
int cli_diagnose_test_upgrade(int mode, diag_result_t *out);

/*
 * Run sandbox integrity diagnostics.
 *   mode=0: local checks only (seccomp + no_new_privs)
 *   mode=1: full test (adds AF_UNIX socket + IPC round-trip)
 * Returns 0 on all-pass, 1 on any failure.
 */
int cli_diagnose_test_sandbox(int mode, diag_result_t *out);

/*
 * Run penetration tests (adversarial input, auth IPC security, config perms).
 *   mode=0: SEC-16..18 (auth gate, config visibility, password handler fuzzing)
 *   mode=1: full test (also runs SEC-1..15 injection/overflow/escalation tests)
 * Returns 0 on all-pass, 1 on any failure.
 */
int cli_diagnose_test_pentest(int mode, const char *permissions,
			      diag_result_t *out);

/*
 * Run database health diagnostics.
 *   mode=0: registry consistency (local, no IPC)
 *   mode=1: full test (IPC round-trips for DB state verification)
 * Returns 0 on all-pass, 1 on any failure.
 */
int cli_diagnose_test_database(int mode, diag_result_t *out);

/*
 * Run disk health diagnostics (via IPC — CLI sandbox blocks openat).
 *   mode=0: sgdata checks (mount, fstype, writable, usage, DB file)
 *   mode=1: full test (adds sglogs + eMMC block device checks)
 * Returns 0 on all-pass, 1 on any failure.
 */
int cli_diagnose_test_disk(int mode, diag_result_t *out);

/*
 * Run DHCP client/server cross-validation diagnostics.
 *   mode=0: no local-only tests (all checks need IPC)
 *   mode=1: full test (IPC round-trips for conflict detection)
 * Returns 0 on all-pass, 1 on any failure.
 */
int cli_diagnose_test_dhcp(int mode, diag_result_t *out);

/*
 * Run supervisor diagnostics (process start/stop/restart/crash-loop).
 *   mode=0: no local-only tests (all checks need IPC)
 *   mode=1: full test (IPC round-trips via SG_CMD_SUPERVISOR_TEST)
 * Returns 0 on all-pass, 1 on any failure.
 */
int cli_diagnose_test_supervisor(int mode, diag_result_t *out);

/*
 * Run webd backend IPC diagnostics.
 *   mode=0: no local-only tests (all checks need IPC)
 *   mode=1: full test (session tags, WHOAMI, error codes, CRUD, diag)
 * Returns 0 on all-pass, 1 on any failure.
 */
int cli_diagnose_test_webd(int mode, diag_result_t *out);

/*
 * Run BusyBox applet whitelist diagnostics.
 *   mode=0: same as mode=1 (no local-only checks possible — needs IPC)
 *   mode=1: enumerate /bin /sbin /usr/bin /usr/sbin via mgmtd, compare
 *           against the hardcoded whitelist. Fails on unexpected applets
 *           (drift detection) or missing applets (build broken).
 * Returns 0 on all-pass, 1 on any failure.
 */
int cli_diagnose_test_busybox(int mode, diag_result_t *out);

/*
 * Run connection-tracking diagnostics against nf_conntrack: that conntrack is
 * available, pkt_forward is loaded, and the normalized "show sessions" view
 * parses (header + flow rows). `mode` is accepted for signature compatibility
 * but ignored — there is a single conntrack-based test path.
 * Returns 0 on all-pass, 1 on any failure.
 */
int cli_diagnose_test_session(int mode, diag_result_t *out);

#endif /* CLI_DIAGNOSE_H */
