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
 * Run database health diagnostics.
 *   mode=0: registry consistency (local, no IPC)
 *   mode=1: full test (IPC round-trips for DB state verification)
 * Returns 0 on all-pass, 1 on any failure.
 */
int cli_diagnose_test_database(int mode, diag_result_t *out);

/*
 * Refresh the main loop's session rev baseline.
 * Called by selftest after SEC-8 self-bump to prevent the acting admin
 * from being kicked by their own diagnostic operations.
 */
void cli_refresh_session(void);

#endif /* CLI_DIAGNOSE_H */
