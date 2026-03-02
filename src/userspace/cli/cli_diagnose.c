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

/*
 * diag_test_status — send IPC opcode and check for an exact expected status.
 * Used for adversarial tests where we expect specific error codes.
 */
static void diag_test_status(const char *desc, uint32_t opcode,
			     const char *payload, uint32_t expect)
{
	struct ipc_response resp;
	int conn;

	diag_total++;
	conn = ipc_send_str(opcode, payload, &resp);

	if (conn == 0 && resp.status == expect) {
		printf(C_GREEN "  PASS" C_NC " [%3u] %s (status=%u)\n",
		       opcode, desc, expect);
		diag_pass++;
	} else {
		printf(C_RED "  FAIL" C_NC " [%3u] %s"
		       " (expected status=%u, got %u)\n",
		       opcode, desc, expect,
		       conn < 0 ? 999 : resp.status);
		diag_fail++;
	}

	ipc_resp_free(&resp);
}

/*
 * diag_test_status2 — like diag_test_status but accepts two possible codes.
 * Used when mgmtd may return different-but-acceptable error codes.
 */
static void diag_test_status2(const char *desc, uint32_t opcode,
			      const char *payload,
			      uint32_t expect_a, uint32_t expect_b)
{
	struct ipc_response resp;
	int conn;

	diag_total++;
	conn = ipc_send_str(opcode, payload, &resp);

	if (conn == 0 &&
	    (resp.status == expect_a || resp.status == expect_b)) {
		printf(C_GREEN "  PASS" C_NC " [%3u] %s (status=%u)\n",
		       opcode, desc, resp.status);
		diag_pass++;
	} else {
		printf(C_RED "  FAIL" C_NC " [%3u] %s"
		       " (expected status=%u or %u, got %u)\n",
		       opcode, desc, expect_a, expect_b,
		       conn < 0 ? 999 : resp.status);
		diag_fail++;
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
	 * mgmtd CFG_SET payload: "type:id\nkey=value\n"
	 * mgmtd CFG_DEL payload: "type:id"
	 * Use a real config type so mgmtd's type validation passes.
	 */
	diag_test("CFG_SET write config (firewall_address:__diag_test)",
		  SG_CMD_CFG_SET,
		  "firewall_address:__diag_test\n"
		  "name=__diag_test\n"
		  "subnet=10.0.0.0/8\n"
		  "type=ipmask\n",
		  is_cfg || is_adm);
	diag_test("CFG_DEL delete config (firewall_address:__diag_test)",
		  SG_CMD_CFG_DEL,
		  "firewall_address:__diag_test", is_cfg || is_adm);

	/* Admin-only ops */
	diag_test_access("ADMIN_DELETE __diag_nobody (access check)",
			 SG_CMD_ADMIN_DELETE,
			 "__diag_nobody", is_adm);
	diag_test("SESSION_BUMP bump session",
		  SG_CMD_SESSION_BUMP, "__diag_nobody", is_adm);
	diag_test("DEBUG_FETCH debug traces",
		  SG_CMD_DEBUG_FETCH, "", is_adm);
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

/* ── Cleanup all test artifacts ─────────────────────────────────────────── */

static void diag_cleanup_all(void)
{
	struct ipc_response resp;

	diag_cleanup_accounts();

	/* Clean up config entries left by security tests */
	ipc_send_str(SG_CMD_CFG_DEL, "firewall_address:__diag_test", &resp);
	ipc_resp_free(&resp);
	ipc_send_str(SG_CMD_CFG_DEL, "firewall_address:__diag_inj", &resp);
	ipc_resp_free(&resp);
	ipc_send_str(SG_CMD_CFG_DEL, "system_admin:__diag_esc", &resp);
	ipc_resp_free(&resp);
	ipc_send_str(SG_CMD_CFG_DEL, "system_admin-profile:__diag_evil", &resp);
	ipc_resp_free(&resp);

	/* SEC-12 boundary test entries */
	ipc_send_str(SG_CMD_CFG_DEL, "firewall_address:__diag_long", &resp);
	ipc_resp_free(&resp);

	/* SEC-14 password test user */
	ipc_send_str(SG_CMD_ADMIN_DELETE, "__diag_pw", &resp);
	ipc_resp_free(&resp);

	/* Profile upgrade test user */
	ipc_send_str(SG_CMD_ADMIN_DELETE, "__diag_upg", &resp);
	ipc_resp_free(&resp);
}

/* ── Security tests ────────────────────────────────────────────────────── */

static void diag_security_tests(void)
{
	struct ipc_response resp;

	/* ── SEC-1: Input injection (IDs) ─────────────────────────────── */

	printf("\n" C_CYAN "  --- SEC-1: Input injection (IDs) ---"
	       C_NC "\n");

	diag_test_status("ADMIN_DELETE rejects colon in username",
			 SG_CMD_ADMIN_DELETE, "admin:evil",
			 SG_ERR_INVALID_ARG);
	diag_test_status("ADMIN_DELETE rejects slash in username",
			 SG_CMD_ADMIN_DELETE, "../etc",
			 SG_ERR_INVALID_ARG);
	diag_test_status("ADMIN_DELETE rejects space in username",
			 SG_CMD_ADMIN_DELETE, "ad min",
			 SG_ERR_INVALID_ARG);
	diag_test_status("ADMIN_DELETE rejects quote in username",
			 SG_CMD_ADMIN_DELETE, "admin'",
			 SG_ERR_INVALID_ARG);
	diag_test_status("SESSION_BUMP rejects semicolon in username",
			 SG_CMD_SESSION_BUMP, "admin;reboot",
			 SG_ERR_INVALID_ARG);
	diag_test_status("SESSION_REV rejects pipe in username",
			 SG_CMD_SESSION_REV, "admin|cat /etc/shadow",
			 SG_ERR_INVALID_ARG);
	diag_test_status("ADMIN_SET_ENF rejects backtick in username",
			 SG_CMD_ADMIN_SET_ENF, "`reboot`\nenable\n",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CFG_GET rejects path traversal",
			 SG_CMD_CFG_GET, "../../etc/shadow",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CFG_SET rejects shell chars in type",
			 SG_CMD_CFG_SET, "$(reboot):test\nx=1\n",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CFG_LIST rejects semicolon in type",
			 SG_CMD_CFG_LIST, "firewall;rm -rf /",
			 SG_ERR_INVALID_ARG);

	/* ── SEC-2: Empty / missing payload ───────────────────────────── */

	printf("\n" C_CYAN "  --- SEC-2: Empty / missing payload ---"
	       C_NC "\n");

	diag_test_status("ADMIN_CREATE empty payload",
			 SG_CMD_ADMIN_CREATE, "",
			 SG_ERR_MISSING_ARG);
	diag_test_status("ADMIN_DELETE empty payload",
			 SG_CMD_ADMIN_DELETE, "",
			 SG_ERR_MISSING_ARG);
	diag_test_status("ADMIN_SET_PW empty payload",
			 SG_CMD_ADMIN_SET_PW, "",
			 SG_ERR_MISSING_ARG);
	diag_test_status("ADMIN_SET_ENF empty payload",
			 SG_CMD_ADMIN_SET_ENF, "",
			 SG_ERR_MISSING_ARG);
	diag_test_status("CFG_SET empty payload",
			 SG_CMD_CFG_SET, "",
			 SG_ERR_MISSING_ARG);
	diag_test_status("CFG_DEL empty payload",
			 SG_CMD_CFG_DEL, "",
			 SG_ERR_MISSING_ARG);
	diag_test_status("CFG_GET empty payload",
			 SG_CMD_CFG_GET, "",
			 SG_ERR_MISSING_ARG);
	diag_test_status("SESSION_BUMP empty payload",
			 SG_CMD_SESSION_BUMP, "",
			 SG_ERR_MISSING_ARG);

	/* ── SEC-3: Nonexistent resources ─────────────────────────────── */

	printf("\n" C_CYAN "  --- SEC-3: Nonexistent resources ---"
	       C_NC "\n");

	diag_test_status("Delete nonexistent user",
			 SG_CMD_ADMIN_DELETE, "__diag_ghost",
			 SG_ERR_USER_NOT_FOUND);
	diag_test_status2("Set password for nonexistent user",
			  SG_CMD_ADMIN_SET_PW,
			  "__diag_ghost\nPass123!\n",
			  SG_ERR_USER_NOT_FOUND, SG_ERR_SYSTEM_FAIL);
	diag_test_status("Set enforce for nonexistent user",
			 SG_CMD_ADMIN_SET_ENF,
			 "__diag_ghost\nenable\n",
			 SG_ERR_USER_NOT_FOUND);
	diag_test_status("Lock password for nonexistent user",
			 SG_CMD_ADMIN_LOCK_PW, "__diag_ghost",
			 SG_ERR_SYSTEM_FAIL);
	diag_test_status("CFG_GET nonexistent section",
			 SG_CMD_CFG_GET,
			 "firewall_address:__diag_ghost",
			 SG_ERR_ENTRY_NOT_FOUND);
	diag_test_status("Create user with nonexistent profile",
			 SG_CMD_ADMIN_CREATE,
			 "__diag_x\n__diag_noprof\n",
			 SG_ERR_PROFILE_NOT_FOUND);

	/* ── SEC-4: Builtin protection ────────────────────────────────── */

	printf("\n" C_CYAN "  --- SEC-4: Builtin protection ---"
	       C_NC "\n");

	diag_test_status("Delete builtin admin user",
			 SG_CMD_ADMIN_DELETE, "admin",
			 SG_ERR_BUILTIN);
	diag_test_status("CFG_DEL builtin admin record",
			 SG_CMD_CFG_DEL, "system_admin:admin",
			 SG_ERR_BUILTIN);
	diag_test_status("CFG_DEL builtin read-write profile",
			 SG_CMD_CFG_DEL,
			 "system_admin-profile:read-write",
			 SG_ERR_BUILTIN);
	diag_test_status("CFG_DEL builtin read-only profile",
			 SG_CMD_CFG_DEL,
			 "system_admin-profile:read-only",
			 SG_ERR_BUILTIN);
	diag_test_status("CFG_DEL builtin password policy",
			 SG_CMD_CFG_DEL,
			 "system_password-policy:0",
			 SG_ERR_BUILTIN);
	diag_test_status("Duplicate admin creation",
			 SG_CMD_ADMIN_CREATE, "admin\nread-write\n",
			 SG_ERR_ALREADY_EXISTS);

	/* ── SEC-5: Invalid config types ──────────────────────────────── */

	printf("\n" C_CYAN "  --- SEC-5: Invalid config types ---"
	       C_NC "\n");

	diag_test_status("CFG_SET unknown type",
			 SG_CMD_CFG_SET, "bogus_type:test\nx=1\n",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CFG_DEL unknown type",
			 SG_CMD_CFG_DEL, "bogus_type:test",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CFG_SET missing colon separator",
			 SG_CMD_CFG_SET, "firewallpolicy\nx=1\n",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CFG_SET type with only colon",
			 SG_CMD_CFG_SET, ":test\nx=1\n",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CFG_SET colon but no id",
			 SG_CMD_CFG_SET, "firewall_address:\nx=1\n",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CFG_DEL type only (no colon)",
			 SG_CMD_CFG_DEL, "firewall_address",
			 SG_ERR_INVALID_ARG);

	/* ── SEC-6: Payload format attacks ────────────────────────────── */

	printf("\n" C_CYAN "  --- SEC-6: Payload format attacks ---"
	       C_NC "\n");

	diag_test_status("ADMIN_CREATE no profile line",
			 SG_CMD_ADMIN_CREATE, "__diag_x",
			 SG_ERR_INVALID_ARG);
	diag_test_status2("ADMIN_CREATE only newline",
			  SG_CMD_ADMIN_CREATE, "\n",
			  SG_ERR_MISSING_ARG, SG_ERR_INVALID_ARG);
	diag_test_status("ADMIN_SET_PW no password line",
			 SG_CMD_ADMIN_SET_PW, "admin",
			 SG_ERR_INVALID_ARG);
	diag_test_status("ADMIN_SET_ENF no value line",
			 SG_CMD_ADMIN_SET_ENF, "admin",
			 SG_ERR_INVALID_ARG);
	diag_test_status("ADMIN_SET_ENF bad value",
			 SG_CMD_ADMIN_SET_ENF, "admin\nmaybe\n",
			 SG_ERR_INVALID_VAL);
	diag_test_status("CFG_SET section only (no data)",
			 SG_CMD_CFG_SET,
			 "firewall_address:__diag_test",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CFG_SET section + newline only",
			 SG_CMD_CFG_SET,
			 "firewall_address:__diag_test\n",
			 SG_ERR_INVALID_ARG);
	/* CFG_SET with value but no key= — server-side validation
	 * rejects because required fields are missing */
	diag_test_status("CFG_SET value with no key= (rejected)",
			 SG_CMD_CFG_SET,
			 "firewall_address:__diag_test\njust_a_value\n",
			 SG_ERR_MISSING_ARG);

	/* ── SEC-7: Invalid command opcode ────────────────────────────── */

	printf("\n" C_CYAN "  --- SEC-7: Invalid command opcode ---"
	       C_NC "\n");

	diag_test_status("Opcode 0 (unassigned)",
			 0, "", SG_ERR_INVALID_CMD);
	diag_test_status("Opcode 999 (unassigned)",
			 999, "", SG_ERR_INVALID_CMD);
	diag_test_status("Opcode 65535 (max range)",
			 65535, "", SG_ERR_INVALID_CMD);

	/* ── SEC-8: Privilege escalation via config ───────────────────── */

	printf("\n" C_CYAN
	       "  --- SEC-8: Privilege escalation via config ---"
	       C_NC "\n");

	/* Admin can create system_admin entries via CFG_SET */
	diag_test_status("CFG_SET system_admin (admin can do this)",
			 SG_CMD_CFG_SET,
			 "system_admin:__diag_esc\n"
			 "profile=read-write\n"
			 "enforce-change-password=enable\n"
			 "enforce-password-policy=enable\n",
			 SG_OK);

	/* Verify the entry was created */
	diag_total++;
	if (ipc_send_str(SG_CMD_CFG_GET, "system_admin:__diag_esc",
			 &resp) == 0 &&
	    resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "profile=read-write")) {
		printf(C_GREEN "  PASS" C_NC " [%3u] Verify __diag_esc"
		       " created (profile=read-write)\n",
		       SG_CMD_CFG_GET);
		diag_pass++;
	} else {
		printf(C_RED "  FAIL" C_NC " [%3u] Verify __diag_esc"
		       " created (status=%u)\n",
		       SG_CMD_CFG_GET, resp.status);
		diag_fail++;
	}
	ipc_resp_free(&resp);

	/* Clean up __diag_esc */
	diag_test_status("CFG_DEL __diag_esc cleanup",
			 SG_CMD_CFG_DEL, "system_admin:__diag_esc",
			 SG_OK);

	/* Create evil profile via CFG_SET */
	diag_test_status("CFG_SET evil profile (admin can create)",
			 SG_CMD_CFG_SET,
			 "system_admin-profile:__diag_evil\n"
			 "permissions=monitor,configure,admin\n"
			 "description=evil-test\n",
			 SG_OK);

	/* Verify evil profile exists */
	diag_total++;
	if (ipc_send_str(SG_CMD_CFG_GET,
			 "system_admin-profile:__diag_evil",
			 &resp) == 0 &&
	    resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "permissions")) {
		printf(C_GREEN "  PASS" C_NC " [%3u] Verify __diag_evil"
		       " profile created\n", SG_CMD_CFG_GET);
		diag_pass++;
	} else {
		printf(C_RED "  FAIL" C_NC " [%3u] Verify __diag_evil"
		       " profile created (status=%u)\n",
		       SG_CMD_CFG_GET, resp.status);
		diag_fail++;
	}
	ipc_resp_free(&resp);

	/* Clean up evil profile */
	diag_test_status("CFG_DEL __diag_evil cleanup",
			 SG_CMD_CFG_DEL,
			 "system_admin-profile:__diag_evil",
			 SG_OK);

	/* Admin self-delete blocked */
	diag_test_status2("Admin self-delete blocked",
			  SG_CMD_ADMIN_DELETE, diag_username(),
			  SG_ERR_BUILTIN, SG_ERR_IN_USE);

	/* Session bump for self */
	diag_test_status("Session bump for self",
			 SG_CMD_SESSION_BUMP, diag_username(),
			 SG_OK);

	/* ── SEC-9: Unimplemented opcode coverage ────────────────────── */

	printf("\n" C_CYAN
	       "  --- SEC-9: Unimplemented opcode coverage ---"
	       C_NC "\n");

	diag_test_status("CFG_LIST_TYPES unimplemented",
			 SG_CMD_CFG_LIST_TYPES, "",
			 SG_ERR_INVALID_CMD);
	diag_test_status("COMMIT unimplemented",
			 SG_CMD_COMMIT, "",
			 SG_ERR_INVALID_CMD);
	diag_test_status("REVISIONS unimplemented",
			 SG_CMD_REVISIONS, "",
			 SG_ERR_INVALID_CMD);
	diag_test_status("ROLLBACK unimplemented",
			 SG_CMD_ROLLBACK, "",
			 SG_ERR_INVALID_CMD);
	diag_test_status("SHOW_CONFIG unimplemented",
			 SG_CMD_SHOW_CONFIG, "",
			 SG_ERR_INVALID_CMD);

	/* ── SEC-10: ADMIN_CHECK_PW validation ───────────────────────── */

	printf("\n" C_CYAN
	       "  --- SEC-10: ADMIN_CHECK_PW validation ---"
	       C_NC "\n");

	diag_test_status("CHECK_PW empty payload",
			 SG_CMD_ADMIN_CHECK_PW, "",
			 SG_ERR_MISSING_ARG);
	diag_test_status("CHECK_PW username only (no newline)",
			 SG_CMD_ADMIN_CHECK_PW, "admin",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CHECK_PW injection semicolon in username",
			 SG_CMD_ADMIN_CHECK_PW,
			 "admin;reboot\nPass1abc\n",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CHECK_PW injection backtick in username",
			 SG_CMD_ADMIN_CHECK_PW,
			 "`id`\nPass1abc\n",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CHECK_PW valid user + weak password",
			 SG_CMD_ADMIN_CHECK_PW,
			 "admin\nabc\nenable\n",
			 SG_ERR_POLICY_FAIL);
	diag_test_status("CHECK_PW valid user + compliant password",
			 SG_CMD_ADMIN_CHECK_PW,
			 "admin\nAbcdefg1\nenable\n",
			 SG_OK);
	diag_test_status("CHECK_PW nonexistent user (policy not enforced)",
			 SG_CMD_ADMIN_CHECK_PW,
			 "__diag_ghost\nabc\n",
			 SG_OK);

	/* ── SEC-11: CFG_APPLY validation ────────────────────────────── */

	printf("\n" C_CYAN
	       "  --- SEC-11: CFG_APPLY validation ---"
	       C_NC "\n");

	diag_test_status("CFG_APPLY empty payload",
			 SG_CMD_CFG_APPLY, "",
			 SG_ERR_MISSING_ARG);
	diag_test_status("CFG_APPLY type only (no newline)",
			 SG_CMD_CFG_APPLY, "system_settings",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CFG_APPLY type + id (missing 2nd newline)",
			 SG_CMD_CFG_APPLY, "system_settings\n0",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CFG_APPLY shell chars in type field",
			 SG_CMD_CFG_APPLY,
			 "$(reboot)\n0\nx=1\n",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CFG_APPLY unknown type (rejected by registry)",
			 SG_CMD_CFG_APPLY,
			 "bogus_type\ntest\nx=1\n",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CFG_APPLY valid apply (hostname, idempotent)",
			 SG_CMD_CFG_APPLY,
			 "system_settings\n0\nhostname=stargazer\n",
			 SG_OK);

	/* ── SEC-12: Boundary / overflow tests ───────────────────────── */

	printf("\n" C_CYAN
	       "  --- SEC-12: Boundary / overflow tests ---"
	       C_NC "\n");

	{
		char buf[4096];

		/* Test 1: Long username (256 chars) to ADMIN_DELETE */
		memset(buf, 'a', 256);
		buf[256] = '\0';
		diag_test_status("ADMIN_DELETE long username (256 chars)",
				 SG_CMD_ADMIN_DELETE, buf,
				 SG_ERR_INVALID_ARG);

		/* Test 2: Username at SG_USERNAME_MAX (64 chars) to SESSION_REV */
		memset(buf, 'a', SG_USERNAME_MAX);
		buf[SG_USERNAME_MAX] = '\0';
		diag_test_status("SESSION_REV username at max (64 chars)",
				 SG_CMD_SESSION_REV, buf,
				 SG_OK);

		/* Test 3: Long config type (256 chars) to CFG_GET */
		memset(buf, 'a', 256);
		buf[256] = '\0';
		diag_test_status("CFG_GET long type (256 chars)",
				 SG_CMD_CFG_GET, buf,
				 SG_ERR_INVALID_ARG);

		/* Test 4: Near-max payload (~4000 bytes) to CFG_SET */
		{
			const char *hdr = "firewall_address:__diag_long\n"
					  "name=__diag_long\n"
					  "subnet=10.0.0.0/8\n"
					  "type=ipmask\n"
					  "comment=";
			size_t hdr_len = strlen(hdr);
			size_t fill = 4000 - hdr_len - 1; /* -1 for trailing \n */

			memcpy(buf, hdr, hdr_len);
			memset(buf + hdr_len, 'x', fill);
			buf[hdr_len + fill] = '\n';
			buf[hdr_len + fill + 1] = '\0';

			diag_test_status(
				"CFG_SET near-max payload (~4000 bytes)",
				SG_CMD_CFG_SET, buf, SG_OK);
		}

		/* Test 5: Clean up boundary test entry */
		diag_test_status("CFG_DEL boundary test cleanup",
				 SG_CMD_CFG_DEL,
				 "firewall_address:__diag_long",
				 SG_OK);
	}

	/* ── SEC-13: CFG_GET/CFG_DEL ID validation gaps ──────────────── */

	printf("\n" C_CYAN
	       "  --- SEC-13: CFG_GET/CFG_DEL ID validation gaps ---"
	       C_NC "\n");

	diag_test_status("CFG_GET semicolon in ID",
			 SG_CMD_CFG_GET,
			 "firewall_address:test;evil",
			 SG_ERR_ENTRY_NOT_FOUND);
	diag_test_status("CFG_GET single-quote in ID",
			 SG_CMD_CFG_GET,
			 "firewall_address:test'evil",
			 SG_ERR_ENTRY_NOT_FOUND);
	diag_test_status("CFG_DEL semicolon in ID (no-op OK)",
			 SG_CMD_CFG_DEL,
			 "firewall_address:test;evil",
			 SG_OK);
	diag_test_status("CFG_DEL backtick in ID (no-op OK)",
			 SG_CMD_CFG_DEL,
			 "firewall_address:test`evil",
			 SG_OK);
	diag_test_status("CFG_SET firewall_policy non-numeric ID",
			 SG_CMD_CFG_SET,
			 "firewall_policy:abc\nname=test\n",
			 SG_ERR_INVALID_ARG);
	diag_test_status("CFG_GET path traversal in ID",
			 SG_CMD_CFG_GET,
			 "firewall_address:../../../etc/shadow",
			 SG_ERR_ENTRY_NOT_FOUND);

	/* ── SEC-14: Password policy enforcement ─────────────────────── */

	printf("\n" C_CYAN
	       "  --- SEC-14: Password policy enforcement ---"
	       C_NC "\n");

	/* Create temp user __diag_pw */
	diag_test_status("Create temp user __diag_pw",
			 SG_CMD_ADMIN_CREATE,
			 "__diag_pw\nread-write\n",
			 SG_OK);

	/* Enable password policy enforcement via CFG_SET */
	diag_test_status("Enable password policy for __diag_pw",
			 SG_CMD_CFG_SET,
			 "system_admin:__diag_pw\n"
			 "profile=read-write\n"
			 "enforce-password-policy=enable\n"
			 "enforce-change-password=enable\n",
			 SG_OK);

	/* Password policy failure cases */
	diag_test_status("Too short (3 chars: \"abc\")",
			 SG_CMD_ADMIN_SET_PW,
			 "__diag_pw\nabc\n",
			 SG_ERR_POLICY_FAIL);
	diag_test_status("Too short (7 chars: \"Abcdef1\")",
			 SG_CMD_ADMIN_SET_PW,
			 "__diag_pw\nAbcdef1\n",
			 SG_ERR_POLICY_FAIL);
	diag_test_status("No uppercase (\"abcdefg1\")",
			 SG_CMD_ADMIN_SET_PW,
			 "__diag_pw\nabcdefg1\n",
			 SG_ERR_POLICY_FAIL);
	diag_test_status("No lowercase (\"ABCDEFG1\")",
			 SG_CMD_ADMIN_SET_PW,
			 "__diag_pw\nABCDEFG1\n",
			 SG_ERR_POLICY_FAIL);
	diag_test_status("No digit (\"Abcdefgh\")",
			 SG_CMD_ADMIN_SET_PW,
			 "__diag_pw\nAbcdefgh\n",
			 SG_ERR_POLICY_FAIL);
	diag_test_status("Contains username",
			 SG_CMD_ADMIN_SET_PW,
			 "__diag_pw\nABC__diag_pw1\n",
			 SG_ERR_POLICY_FAIL);
	diag_test_status("Empty password",
			 SG_CMD_ADMIN_SET_PW,
			 "__diag_pw\n\n",
			 SG_ERR_POLICY_FAIL);

	/* Valid password — may return SYSTEM_FAIL if Linux user not created */
	diag_test_status2("Valid password (\"Abcdefg1\")",
			  SG_CMD_ADMIN_SET_PW,
			  "__diag_pw\nAbcdefg1\n",
			  SG_OK, SG_ERR_SYSTEM_FAIL);

	/* Cross-check via CHECK_PW */
	diag_test_status("Cross-check via CHECK_PW",
			 SG_CMD_ADMIN_CHECK_PW,
			 "__diag_pw\nAbcdefg1\n",
			 SG_OK);

	/* Delete temp user */
	diag_test_status("Delete temp user __diag_pw",
			 SG_CMD_ADMIN_DELETE,
			 "__diag_pw",
			 SG_OK);

	/* Verify deletion */
	diag_test_status("Verify __diag_pw deletion",
			 SG_CMD_ADMIN_DELETE,
			 "__diag_pw",
			 SG_ERR_USER_NOT_FOUND);
}

/* ── Full test ─────────────────────────────────────────────────────────── */

static void diag_full_test(void)
{
	struct ipc_response resp;

	printf("\n" C_CYAN "  --- Full test (temp account verification) ---"
	       C_NC "\n");

	/* 1. Pre-cleanup leftover artifacts from a previous crashed run */
	diag_cleanup_all();

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
	 *    CFG_SET payload: "type:id\nkey=value\n"
	 *    CFG_DEL payload: "type:id" */
	diag_test("CFG_SET firewall_address:__diag_test (admin write)",
		  SG_CMD_CFG_SET,
		  "firewall_address:__diag_test\n"
		  "name=__diag_test\n"
		  "subnet=10.0.0.0/8\n"
		  "type=ipmask\n", 1);
	diag_test("CFG_DEL firewall_address:__diag_test (admin delete)",
		  SG_CMD_CFG_DEL,
		  "firewall_address:__diag_test", 1);
	diag_test("SESSION_BUMP __diag_rw (admin bump)",
		  SG_CMD_SESSION_BUMP, "__diag_rw", 1);

	/* 7. Delete temp accounts */
	diag_test("ADMIN_DELETE __diag_rw",
		  SG_CMD_ADMIN_DELETE, "__diag_rw", 1);
	diag_test("ADMIN_DELETE __diag_ro",
		  SG_CMD_ADMIN_DELETE, "__diag_ro", 1);

	/* 8. Profile upgrade verification: read-only → read-write */
	printf("\n" C_CYAN
	       "  --- Profile upgrade (read-only -> read-write) ---"
	       C_NC "\n");

	diag_test_status("Create __diag_upg (profile=read-only)",
			 SG_CMD_ADMIN_CREATE,
			 "__diag_upg\nread-only\n",
			 SG_OK);

	diag_test_status("Upgrade __diag_upg to read-write",
			 SG_CMD_CFG_SET,
			 "system_admin:__diag_upg\n"
			 "profile=read-write\n"
			 "enforce-change-password=enable\n"
			 "enforce-password-policy=enable\n",
			 SG_OK);

	diag_total++;
	if (ipc_send_str(SG_CMD_CFG_GET,
			 "system_admin:__diag_upg",
			 &resp) == 0 &&
	    resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "profile=read-write")) {
		printf(C_GREEN "  PASS" C_NC " [%3u] Verify __diag_upg"
		       " upgraded to read-write\n",
		       SG_CMD_CFG_GET);
		diag_pass++;
	} else {
		printf(C_RED "  FAIL" C_NC " [%3u] Verify __diag_upg"
		       " profile upgrade (status=%u)\n",
		       SG_CMD_CFG_GET, resp.status);
		diag_fail++;
	}
	ipc_resp_free(&resp);

	diag_test_status("Delete __diag_upg",
			 SG_CMD_ADMIN_DELETE,
			 "__diag_upg",
			 SG_OK);

	/* 9. Security/adversarial tests */
	diag_security_tests();

	return;

cleanup:
	diag_cleanup_all();
}

/* ── Public entry point ────────────────────────────────────────────────── */

int cli_diagnose_test_permissions(int mode, const char *permissions,
				  diag_result_t *out)
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
	else
		printf(C_GREEN " (all passed)" C_NC);
	printf("\n\n");

	if (out) {
		out->passed = diag_pass;
		out->failed = diag_fail;
		out->total  = diag_total;
	}
	return diag_fail > 0 ? 1 : 0;
}
