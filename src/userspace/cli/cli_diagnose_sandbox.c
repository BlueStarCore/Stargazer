/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose_sandbox.c — Sandbox integrity self-tests
 *
 * Verifies that the seccomp-bpf sandbox and related protections are
 * active and functioning. Run via: execute diagnose selftest full
 *
 * Tests:
 *   SEC-SBX-1: seccomp filter is active (SECCOMP_MODE_FILTER)
 *   SEC-SBX-2: PR_SET_NO_NEW_PRIVS is set
 *   SEC-SBX-3: AF_UNIX socket creation works (IPC allowed)
 *   SEC-SBX-4: IPC round-trip (PING) succeeds
 *   SEC-SBX-5: terminal echo control works (tcgetattr/tcsetattr)
 *   SEC-SBX-6: terminal window size query works (TIOCGWINSZ)
 */

#define _GNU_SOURCE
#include "cli_diagnose.h"
#include "cli_ipc.h"
#include "cli_readline.h"

#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <linux/seccomp.h>

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

/* ── Public entry point ────────────────────────────────────────────────── */

int cli_diagnose_test_sandbox(int mode, diag_result_t *out)
{
	diag_result_t local = {0};
	if (!out) out = &local;
	int failures = 0;

	printf("\n  " C_CYAN "--- Sandbox Tests (SEC-SBX) ---" C_NC "\n");

	/* SEC-SBX-1: seccomp filter active */
	{
		int seccomp_mode = prctl(PR_GET_SECCOMP);
		failures += run_test("SEC-SBX-1",
			"seccomp filter active (SECCOMP_MODE_FILTER=2)",
			seccomp_mode == SECCOMP_MODE_FILTER, out);
	}

	/* SEC-SBX-2: no_new_privs set */
	{
		int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
		failures += run_test("SEC-SBX-2",
			"PR_SET_NO_NEW_PRIVS is set",
			nnp == 1, out);
	}

	if (mode == 0) {
		printf("  (Use mode=1 / selftest full for IPC tests)\n");
		return failures > 0 ? 1 : 0;
	}

	/* SEC-SBX-3: AF_UNIX socket creation works */
	{
		int fd = socket(AF_UNIX, SOCK_STREAM, 0);
		int ok = (fd >= 0);
		if (fd >= 0)
			close(fd);
		failures += run_test("SEC-SBX-3",
			"AF_UNIX socket creation allowed",
			ok, out);
	}

	/* SEC-SBX-4: IPC round-trip */
	{
		struct ipc_response resp = {0};
		int ok = (ipc_send_str(SG_CMD_PING, "", &resp) == 0 &&
			  resp.status == SG_OK);
		ipc_resp_free(&resp);
		failures += run_test("SEC-SBX-4",
			"IPC PING round-trip succeeds",
			ok, out);
	}

	/* SEC-SBX-5: terminal echo control (needed by configure set-password) */
	{
		int tty = cli_get_tty_fd();
		struct termios old;
		int ok = (tty >= 0 && tcgetattr(tty, &old) == 0);
		if (ok) {
			struct termios noecho = old;
			noecho.c_lflag &= ~(tcflag_t)ECHO;
			ok = (tcsetattr(tty, TCSANOW, &noecho) == 0);
			tcsetattr(tty, TCSANOW, &old); /* restore */
		}
		failures += run_test("SEC-SBX-5",
			"terminal echo control works (tcgetattr/tcsetattr)",
			ok, out);
	}

	/* SEC-SBX-6: window size query (needed by readline) */
	{
		int tty = cli_get_tty_fd();
		struct winsize ws;
		int ok = (tty >= 0 && ioctl(tty, TIOCGWINSZ, &ws) == 0);
		failures += run_test("SEC-SBX-6",
			"terminal window size query works (TIOCGWINSZ)",
			ok, out);
	}

	printf("\n");
	return failures > 0 ? 1 : 0;
}
