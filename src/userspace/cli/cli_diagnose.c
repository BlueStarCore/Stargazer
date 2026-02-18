/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose.c — Built-in IPC permission diagnostics for Stargazer CLI
 *
 * Implements "execute diagnose test-permissions [full]":
 *   - Self-test: verifies current user's IPC access matches their permission tier
 *   - Full test: creates temp accounts, verifies profile data, cleans up
 *
 * Uses ipc_send_str() directly — zero forks.
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_diagnose.h"
#include "cli_ipc.h"
#include "cli_dispatch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Test counters ─────────────────────────────────────────────────────── */

static int diag_pass;
static int diag_fail;
static int diag_total;

/* ── ANSI colors ───────────────────────────────────────────────────────── */

#define C_GREEN  "\033[0;32m"
#define C_RED    "\033[0;31m"
#define C_CYAN   "\033[0;36m"
#define C_NC     "\033[0m"

/* ── Test helpers ──────────────────────────────────────────────────────── */

/*
 * diag_test — send IPC opcode and check for exact status match.
 *   expect_ok=1: expect SG_OK (status==0)
 *   expect_ok=0: expect SG_ERR_PERM_DENIED (status==200)
 */
static void diag_test(const char *desc, uint32_t opcode,
		      const char *payload, int expect_ok)
{
	struct ipc_response resp;
	int conn;

	diag_total++;
	conn = ipc_send_str(opcode, payload, &resp);

	if (expect_ok) {
		if (conn == 0 && resp.status == SG_OK) {
			printf(C_GREEN "  PASS" C_NC " [%3u] %s\n",
			       opcode, desc);
			diag_pass++;
		} else {
			printf(C_RED "  FAIL" C_NC " [%3u] %s"
			       " (expected OK, got status=%u)\n",
			       opcode, desc,
			       conn < 0 ? 999 : resp.status);
			diag_fail++;
		}
	} else {
		if (conn == 0 && resp.status == SG_ERR_PERM_DENIED) {
			printf(C_GREEN "  PASS" C_NC " [%3u] %s (DENIED)\n",
			       opcode, desc);
			diag_pass++;
		} else {
			printf(C_RED "  FAIL" C_NC " [%3u] %s"
			       " (expected PERM_DENIED, got status=%u)\n",
			       opcode, desc,
			       conn < 0 ? 999 : resp.status);
			diag_fail++;
		}
	}

	ipc_resp_free(&resp);
}

/*
 * diag_test_access — send IPC opcode and check that permission was not denied.
 * For operations that may return other errors (USER_NOT_FOUND etc) when the
 * caller has sufficient access.
 *   expect_allowed=1: status != SG_ERR_PERM_DENIED
 *   expect_allowed=0: status == SG_ERR_PERM_DENIED
 */
static void diag_test_access(const char *desc, uint32_t opcode,
			     const char *payload, int expect_allowed)
{
	struct ipc_response resp;
	int conn;

	diag_total++;
	conn = ipc_send_str(opcode, payload, &resp);

	if (expect_allowed) {
		if (conn == 0 && resp.status != SG_ERR_PERM_DENIED) {
			printf(C_GREEN "  PASS" C_NC " [%3u] %s"
			       " (ALLOWED, status=%u)\n",
			       opcode, desc, resp.status);
			diag_pass++;
		} else {
			printf(C_RED "  FAIL" C_NC " [%3u] %s"
			       " (expected ALLOWED, got PERM_DENIED)\n",
			       opcode, desc);
			diag_fail++;
		}
	} else {
		if (conn == 0 && resp.status == SG_ERR_PERM_DENIED) {
			printf(C_GREEN "  PASS" C_NC " [%3u] %s (DENIED)\n",
			       opcode, desc);
			diag_pass++;
		} else {
			printf(C_RED "  FAIL" C_NC " [%3u] %s"
			       " (expected PERM_DENIED, got status=%u)\n",
			       opcode, desc,
			       conn < 0 ? 999 : resp.status);
			diag_fail++;
		}
	}

	ipc_resp_free(&resp);
}

/* ── Get current username from environment ─────────────────────────────── */

static const char *diag_username(void)
{
	const char *u = getenv("STARGAZER_USER");
	return u ? u : "admin";
}

/* ── Self-test ─────────────────────────────────────────────────────────── */

static void diag_self_test(const char *permissions)
{
	int is_mon = has_permission(permissions, "monitor");
	int is_cfg = has_permission(permissions, "configure");
	int is_adm = has_permission(permissions, "admin");

	printf(C_CYAN "  --- Self-test (permissions: %s) ---" C_NC "\n",
	       permissions);

	/* Universally allowed ops */
	diag_test("PING keepalive",
		  SG_CMD_PING, "", 1);
	diag_test("WHOAMI identity",
		  SG_CMD_WHOAMI, "", 1);
	diag_test("SESSION_REV session revision",
		  SG_CMD_SESSION_REV, diag_username(), 1);

	/* Monitor-level ops */
	diag_test("SHOW_STATUS system status",
		  SG_CMD_SHOW_STATUS, "", is_mon);
	diag_test("SHOW_IFACES interfaces",
		  SG_CMD_SHOW_IFACES, "", is_mon);
	diag_test("SHOW_ROUTES routes",
		  SG_CMD_SHOW_ROUTES, "", is_mon);

	/*
	 * Config read (allowed for all tiers with monitor).
	 * mgmtd CFG_GET payload: "section_name"
	 * mgmtd CFG_LIST payload: "type_prefix"
	 */
	diag_test_access("CFG_GET read config (system_admin:admin)",
			 SG_CMD_CFG_GET,
			 "system_admin:admin", is_mon);
	diag_test("CFG_LIST list entries (firewall_policy)",
		  SG_CMD_CFG_LIST,
		  "firewall_policy", is_mon);

	/*
	 * Config write (requires configure or admin).
	 * mgmtd CFG_SET payload: "section\nkey=val\n"
	 * mgmtd CFG_DEL payload: "section"
	 */
	diag_test("CFG_SET write config (__diag_test)",
		  SG_CMD_CFG_SET,
		  "__diag_test\ndiag=1\n", is_cfg || is_adm);
	diag_test("CFG_DEL delete config (__diag_test)",
		  SG_CMD_CFG_DEL,
		  "__diag_test", is_cfg || is_adm);

	/* Admin-only ops */
	diag_test_access("ADMIN_DELETE __diag_nobody (access check)",
			 SG_CMD_ADMIN_DELETE,
			 "__diag_nobody", is_adm);
	diag_test("SESSION_BUMP bump session",
		  SG_CMD_SESSION_BUMP, "__diag_nobody", is_adm);
}

/* ── Cleanup temp accounts ─────────────────────────────────────────────── */

static void diag_cleanup_accounts(void)
{
	struct ipc_response resp;

	if (ipc_send_str(SG_CMD_ADMIN_DELETE, "__diag_rw", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted __diag_rw\n");
	ipc_resp_free(&resp);

	if (ipc_send_str(SG_CMD_ADMIN_DELETE, "__diag_ro", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted __diag_ro\n");
	ipc_resp_free(&resp);
}

/* ── Full test ─────────────────────────────────────────────────────────── */

static void diag_full_test(void)
{
	struct ipc_response resp;

	printf("\n" C_CYAN "  --- Full test (temp account verification) ---"
	       C_NC "\n");

	/* 1. Pre-cleanup leftover accounts from a previous crashed run */
	diag_cleanup_accounts();

	/* 2. Create temp accounts: __diag_rw (read-write), __diag_ro (read-only)
	 *    Payload: "username\nprofile\n" */
	diag_total++;
	if (ipc_send_str(SG_CMD_ADMIN_CREATE,
			 "__diag_rw\nread-write\n", &resp) == 0 &&
	    resp.status == SG_OK) {
		printf(C_GREEN "  PASS" C_NC " [300] Create __diag_rw"
		       " (profile=read-write)\n");
		diag_pass++;
	} else {
		printf(C_RED "  FAIL" C_NC " [300] Create __diag_rw"
		       " (status=%u)\n",
		       resp.status);
		diag_fail++;
		ipc_resp_free(&resp);
		return; /* Cannot continue without accounts */
	}
	ipc_resp_free(&resp);

	diag_total++;
	if (ipc_send_str(SG_CMD_ADMIN_CREATE,
			 "__diag_ro\nread-only\n", &resp) == 0 &&
	    resp.status == SG_OK) {
		printf(C_GREEN "  PASS" C_NC " [300] Create __diag_ro"
		       " (profile=read-only)\n");
		diag_pass++;
	} else {
		printf(C_RED "  FAIL" C_NC " [300] Create __diag_ro"
		       " (status=%u)\n",
		       resp.status);
		diag_fail++;
		ipc_resp_free(&resp);
		goto cleanup;
	}
	ipc_resp_free(&resp);

	/* 3. Verify __diag_rw has profile=read-write via CFG_GET
	 *    Payload: "system_admin:__diag_rw" */
	diag_total++;
	if (ipc_send_str(SG_CMD_CFG_GET,
			 "system_admin:__diag_rw",
			 &resp) == 0 &&
	    resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "profile=read-write")) {
		printf(C_GREEN "  PASS" C_NC " [100] __diag_rw"
		       " has profile=read-write\n");
		diag_pass++;
	} else {
		printf(C_RED "  FAIL" C_NC " [100] __diag_rw"
		       " profile verification (status=%u)\n",
		       resp.status);
		diag_fail++;
	}
	ipc_resp_free(&resp);

	/* 4. Verify __diag_ro has profile=read-only via CFG_GET */
	diag_total++;
	if (ipc_send_str(SG_CMD_CFG_GET,
			 "system_admin:__diag_ro",
			 &resp) == 0 &&
	    resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "profile=read-only")) {
		printf(C_GREEN "  PASS" C_NC " [100] __diag_ro"
		       " has profile=read-only\n");
		diag_pass++;
	} else {
		printf(C_RED "  FAIL" C_NC " [100] __diag_ro"
		       " profile verification (status=%u)\n",
		       resp.status);
		diag_fail++;
	}
	ipc_resp_free(&resp);

	/* 5. Verify profile permissions via CFG_GET on profile sections */
	diag_total++;
	if (ipc_send_str(SG_CMD_CFG_GET,
			 "system_admin-profile:read-write",
			 &resp) == 0 &&
	    resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "monitor") &&
	    strstr(resp.payload, "configure") &&
	    strstr(resp.payload, "admin")) {
		printf(C_GREEN "  PASS" C_NC " [100] read-write profile"
		       " has monitor,configure,admin\n");
		diag_pass++;
	} else {
		printf(C_RED "  FAIL" C_NC " [100] read-write profile"
		       " permissions check (status=%u)\n",
		       resp.status);
		diag_fail++;
	}
	ipc_resp_free(&resp);

	diag_total++;
	if (ipc_send_str(SG_CMD_CFG_GET,
			 "system_admin-profile:read-only",
			 &resp) == 0 &&
	    resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "monitor") &&
	    !strstr(resp.payload, "configure") &&
	    !strstr(resp.payload, "admin")) {
		printf(C_GREEN "  PASS" C_NC " [100] read-only profile"
		       " has monitor only\n");
		diag_pass++;
	} else {
		printf(C_RED "  FAIL" C_NC " [100] read-only profile"
		       " permissions check (status=%u)\n",
		       resp.status);
		diag_fail++;
	}
	ipc_resp_free(&resp);

	/* 6. Test admin capabilities: CFG_SET, CFG_DEL, SESSION_BUMP
	 *    CFG_SET payload: "section\nkey=val\n"
	 *    CFG_DEL payload: "section" */
	diag_test("CFG_SET __diag_test (admin write)",
		  SG_CMD_CFG_SET,
		  "__diag_test\ndiag=full\n", 1);
	diag_test("CFG_DEL __diag_test (admin delete)",
		  SG_CMD_CFG_DEL,
		  "__diag_test", 1);
	diag_test("SESSION_BUMP __diag_rw (admin bump)",
		  SG_CMD_SESSION_BUMP, "__diag_rw", 1);

	/* 7. Delete temp accounts */
	diag_test("ADMIN_DELETE __diag_rw",
		  SG_CMD_ADMIN_DELETE, "__diag_rw", 1);
	diag_test("ADMIN_DELETE __diag_ro",
		  SG_CMD_ADMIN_DELETE, "__diag_ro", 1);
	return;

cleanup:
	diag_cleanup_accounts();
}

/* ── Public entry point ────────────────────────────────────────────────── */

int cli_diagnose_test_permissions(int mode, const char *permissions)
{
	diag_pass  = 0;
	diag_fail  = 0;
	diag_total = 0;

	printf("\n  Stargazer IPC Permission Diagnostics\n");
	printf("  =====================================\n\n");

	if (!ipc_available()) {
		printf(C_RED "  ERROR" C_NC ": mgmtd socket not found (%s)\n",
		       SG_MGMTD_SOCK);
		printf("  Is stargazer-mgmtd running?\n\n");
		return 1;
	}

	diag_self_test(permissions);

	if (mode == 1)
		diag_full_test();

	/* Summary */
	printf("\n  Results: %d/%d passed", diag_pass, diag_total);
	if (diag_fail > 0)
		printf(C_RED ", %d FAILED" C_NC, diag_fail);
	printf("\n\n");

	return diag_fail > 0 ? 1 : 0;
}
