/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose.h — Built-in diagnostic commands for Stargazer CLI
 */

#ifndef CLI_DIAGNOSE_H
#define CLI_DIAGNOSE_H

/*
 * Run IPC permission model diagnostics.
 *   mode=0: self-test (verify current user's access matches permissions)
 *   mode=1: full test (also creates temp accounts and verifies profile data)
 * Returns 0 on all-pass, 1 on any failure.
 */
int cli_diagnose_test_permissions(int mode, const char *permissions);

/*
 * Run configuration validation diagnostics.
 *   mode=0: validator unit tests (no IPC needed)
 *   mode=1: full test (also runs IPC round-trip create/read/delete)
 * Returns 0 on all-pass, 1 on any failure.
 */
int cli_diagnose_test_configure(int mode);

#endif /* CLI_DIAGNOSE_H */
