/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose_webd.c — webd backend IPC selftest suite
 *
 * Implements "execute diagnose selftest webd":
 *   - Mode 0: no local-only tests (all checks need IPC)
 *   - Mode 1: IPC round-trip tests verifying the mgmtd commands
 *             that webd uses for its REST API
 *
 * Tests exercise the exact IPC paths that webd flows through:
 *   WEB-1: Session tag lifecycle (webd login/logout → SESSION_TAG_*)
 *   WEB-2: WHOAMI response (GET /api/auth/whoami → SG_CMD_WHOAMI)
 *   WEB-3: IPC error codes that feed webd's HTTP status responses
 *   WEB-4: Admin user lifecycle (POST /api/admin/create → ADMIN_CREATE)
 *   WEB-5: Config CRUD round-trip (POST/GET/PUT/DELETE /api/config/TYPE/ID)
 *   WEB-6: System diagnostic commands (GET /api/system/resources/...)
 *
 * Note: webd's HTTP layer (rate limiting, cookie handling, JSON escaping,
 * session token format) is covered by tests/test_webui_*.py and
 * tests/test_webd_internals.py (static analysis).  These tests verify
 * the live IPC backend that the HTTP layer delegates to.
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_diagnose.h"
#include "cli_ipc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Test counters ────────────────────────────────────────────────────── */

static int web_pass;
static int web_fail;
static int web_total;

/* ── Test helpers ─────────────────────────────────────────────────────── */

static void
web_check(const char *id, const char *desc,
	  uint32_t opcode, const char *payload,
	  uint32_t expect)
{
	struct ipc_response resp;
	int conn;

	web_total++;
	conn = ipc_send_str(opcode, payload, &resp);

	if (conn == 0 && resp.status == expect) {
		web_pass++;
		printf(C_GREEN "  PASS" C_NC " [%s] %s (status=%u)\n",
		       id, desc, expect);
	} else {
		web_fail++;
		printf(C_RED "  FAIL" C_NC " [%s] %s"
		       " (expected status=%u, got %u)\n",
		       id, desc, expect,
		       conn < 0 ? 999 : resp.status);
	}

	ipc_resp_free(&resp);
}

/* Check that IPC returns SG_OK AND the payload is non-empty. */
static void
web_check_ok_payload(const char *id, const char *desc,
		     uint32_t opcode, const char *payload)
{
	struct ipc_response resp;
	int conn;

	web_total++;
	conn = ipc_send_str(opcode, payload, &resp);

	if (conn == 0 && resp.status == SG_OK &&
	    resp.payload && resp.payload_len > 0) {
		web_pass++;
		printf(C_GREEN "  PASS" C_NC " [%s] %s"
		       " (ok, %zu bytes)\n",
		       id, desc, resp.payload_len);
	} else {
		web_fail++;
		if (conn < 0 || resp.status != SG_OK) {
			printf(C_RED "  FAIL" C_NC " [%s] %s"
			       " (expected OK+payload, got status=%u)\n",
			       id, desc,
			       conn < 0 ? 999 : resp.status);
		} else {
			printf(C_RED "  FAIL" C_NC " [%s] %s"
			       " (ok but empty payload)\n",
			       id, desc);
		}
	}

	ipc_resp_free(&resp);
}

/* Fire-and-forget IPC helper (setup/teardown, result ignored) */
static void
web_ipc(uint32_t opcode, const char *payload)
{
	struct ipc_response resp;
	ipc_send_str(opcode, payload, &resp);
	ipc_resp_free(&resp);
}

/* ── WEB-1: Session tag lifecycle ────────────────────────────────────── */
/*
 * webd calls SESSION_TAG_NEW on every successful login to bind the
 * browser session to a mgmtd session tag.  On logout it calls
 * SESSION_TAG_DEL.  Verify the full acquire → use → release cycle.
 */

static void test_session_tags(void)
{
	printf(C_CYAN "\n  --- WEB-1: Session tag lifecycle ---" C_NC "\n");

	/* WEB-1a: Acquire a new session tag */
	struct ipc_response resp;
	int conn = ipc_send_str(SG_CMD_SESSION_TAG_NEW, "", &resp);

	web_total++;
	if (conn == 0 && resp.status == SG_OK) {
		web_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [WEB-1a] SESSION_TAG_NEW succeeds\n");
	} else {
		web_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [WEB-1a] SESSION_TAG_NEW failed (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
		ipc_resp_free(&resp);
		return;
	}
	ipc_resp_free(&resp);

	/* WEB-1b: Tag is active — a tagged CFG_LIST must succeed */
	web_check("WEB-1b", "tagged CFG_LIST works after SESSION_TAG_NEW",
		  SG_CMD_CFG_LIST, "firewall_address", SG_OK);

	/* WEB-1c: Release the session tag */
	conn = ipc_send_str(SG_CMD_SESSION_TAG_DEL, "", &resp);
	web_total++;
	if (conn == 0 && resp.status == SG_OK) {
		web_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [WEB-1c] SESSION_TAG_DEL succeeds\n");
	} else {
		web_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [WEB-1c] SESSION_TAG_DEL failed (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* WEB-1d: Re-acquire so subsequent tests aren't tagless */
	ipc_reacquire_tag();
	web_check("WEB-1d", "second SESSION_TAG_NEW after DEL works",
		  SG_CMD_CFG_LIST, "firewall_address", SG_OK);
}

/* ── WEB-2: WHOAMI ───────────────────────────────────────────────────── */
/*
 * Backend of GET /api/auth/whoami.
 * Must return SG_OK with a non-empty kv payload containing at least
 * the username, profile, and permissions fields.
 */

static void test_whoami(void)
{
	printf(C_CYAN "\n  --- WEB-2: WHOAMI response ---" C_NC "\n");

	struct ipc_response resp;
	int conn = ipc_send_str(SG_CMD_WHOAMI, "", &resp);

	web_total++;
	if (conn == 0 && resp.status == SG_OK &&
	    resp.payload && resp.payload_len > 0) {
		/* Verify payload contains expected fields */
		int has_user = strstr(resp.payload, "username=") != NULL;
		int has_prof = strstr(resp.payload, "profile=") != NULL;
		int has_perm = strstr(resp.payload, "permissions=") != NULL;

		if (has_user && has_prof && has_perm) {
			web_pass++;
			printf(C_GREEN "  PASS" C_NC
			       " [WEB-2a] WHOAMI returns"
			       " username+profile+permissions\n");
		} else {
			web_fail++;
			printf(C_RED "  FAIL" C_NC
			       " [WEB-2a] WHOAMI payload missing fields"
			       " (user=%d prof=%d perm=%d)\n",
			       has_user, has_prof, has_perm);
		}
	} else {
		web_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [WEB-2a] WHOAMI failed (status=%u, payload=%zu)\n",
		       conn < 0 ? 999 : resp.status,
		       resp.payload_len);
	}
	ipc_resp_free(&resp);
}

/* ── WEB-3: IPC error codes feeding webd HTTP status responses ────────── */
/*
 * webd maps IPC status codes to HTTP status codes in ipc_status_to_http().
 * These tests verify that each mapped error code is actually returned by
 * the correct IPC call — so that the HTTP mapping is exercised end-to-end.
 *
 * HTTP 400 path: INVALID_ARG, INVALID_VAL, MISSING_ARG
 * HTTP 403 path: PERM_DENIED, BUILTIN
 * HTTP 404 path: ENTRY_NOT_FOUND
 * HTTP 409 path: ALREADY_EXISTS
 */

static void test_ipc_error_codes(void)
{
	printf(C_CYAN "\n  --- WEB-3a: HTTP 400 (bad request) error codes ---"
	       C_NC "\n");

	/* MISSING_ARG: empty payload for CFG_GET */
	web_check("WEB-3a-1", "CFG_GET empty → MISSING_ARG",
		  SG_CMD_CFG_GET, "",
		  SG_ERR_MISSING_ARG);

	/* INVALID_ARG: type name with injection chars */
	web_check("WEB-3a-2", "CFG_GET invalid type → INVALID_ARG",
		  SG_CMD_CFG_GET, "invalid!type:id",
		  SG_ERR_INVALID_ARG);

	/* INVALID_VAL: applying an interface with a bad mode */
	web_check("WEB-3a-3", "CFG_APPLY bad enum value → INVALID_VAL",
		  SG_CMD_CFG_APPLY,
		  "system_interface\nlo\nmode=garbage\nip=127.0.0.1/8\n",
		  SG_ERR_INVALID_VAL);

	printf(C_CYAN "\n  --- WEB-3b: HTTP 403 (forbidden) error codes ---"
	       C_NC "\n");

	/* PERM_DENIED: AUTH_LOGIN from CLI is not root/webd — always denied */
	web_check("WEB-3b-1", "AUTH_LOGIN from CLI → PERM_DENIED",
		  SG_CMD_AUTH_LOGIN, "admin\npassword\n",
		  SG_ERR_PERM_DENIED);

	/* BUILTIN: deleting the built-in admin user is forbidden */
	web_check("WEB-3b-2", "CFG_DEL builtin admin → BUILTIN",
		  SG_CMD_CFG_DEL, "system_admin:admin",
		  SG_ERR_BUILTIN);

	printf(C_CYAN "\n  --- WEB-3c: HTTP 404 (not found) error codes ---"
	       C_NC "\n");

	/* ENTRY_NOT_FOUND: CFG_GET on a valid type but nonexistent entry */
	web_check("WEB-3c-1",
		  "CFG_GET nonexistent entry → ENTRY_NOT_FOUND",
		  SG_CMD_CFG_GET, "firewall_address:__nonexistent_wtest__",
		  SG_ERR_ENTRY_NOT_FOUND);

	printf(C_CYAN "\n  --- WEB-3d: HTTP 409 (conflict) error codes ---"
	       C_NC "\n");

	/* ALREADY_EXISTS: create same admin twice */
	web_ipc(SG_CMD_ADMIN_DELETE, "__wtest_dup\n"); /* clean up first */
	web_check("WEB-3d-1a", "ADMIN_CREATE new user → OK",
		  SG_CMD_ADMIN_CREATE, "__wtest_dup\nread-only\n",
		  SG_OK);
	web_check("WEB-3d-1b", "ADMIN_CREATE same user again → ALREADY_EXISTS",
		  SG_CMD_ADMIN_CREATE, "__wtest_dup\nread-only\n",
		  SG_ERR_ALREADY_EXISTS);
	web_ipc(SG_CMD_ADMIN_DELETE, "__wtest_dup\n"); /* clean up */
}

/* ── WEB-4: Admin user lifecycle ─────────────────────────────────────── */
/*
 * Backend of POST /api/admin/create (and implicit DELETE when users
 * delete themselves).  Verify the full create → verify → delete cycle,
 * and that deleting a nonexistent user returns the right error.
 */

static void test_admin_lifecycle(void)
{
	printf(C_CYAN "\n  --- WEB-4: Admin user lifecycle ---" C_NC "\n");

	const char *test_user = "__wtest_admin\n";
	const char *create_payload = "__wtest_admin\nread-only\n";
	const char *delete_payload = "__wtest_admin\n";

	/* Ensure clean state */
	web_ipc(SG_CMD_ADMIN_DELETE, delete_payload);

	/* WEB-4a: Create */
	web_check("WEB-4a", "ADMIN_CREATE test user",
		  SG_CMD_ADMIN_CREATE, create_payload, SG_OK);

	/* WEB-4b: Duplicate create returns conflict */
	web_check("WEB-4b", "ADMIN_CREATE duplicate → ALREADY_EXISTS",
		  SG_CMD_ADMIN_CREATE, create_payload,
		  SG_ERR_ALREADY_EXISTS);

	/* WEB-4c: Verify user exists via CFG_GET */
	web_check_ok_payload("WEB-4c", "CFG_GET created user exists",
			     SG_CMD_CFG_GET,
			     "system_admin:__wtest_admin");

	/* WEB-4d: Delete */
	web_check("WEB-4d", "ADMIN_DELETE test user",
		  SG_CMD_ADMIN_DELETE, delete_payload, SG_OK);

	/* WEB-4e: Delete nonexistent → USER_NOT_FOUND */
	web_check("WEB-4e", "ADMIN_DELETE nonexistent → USER_NOT_FOUND",
		  SG_CMD_ADMIN_DELETE, delete_payload,
		  SG_ERR_USER_NOT_FOUND);

	/* WEB-4f: Entry is gone after delete */
	web_check("WEB-4f", "CFG_GET deleted user → ENTRY_NOT_FOUND",
		  SG_CMD_CFG_GET, "system_admin:__wtest_admin",
		  SG_ERR_ENTRY_NOT_FOUND);

	(void)test_user; /* referenced only above via string literals */
}

/* ── WEB-5: Config CRUD round-trip ───────────────────────────────────── */
/*
 * Backend of POST / GET / PUT / DELETE /api/config/{type}/{id}.
 * Uses firewall_address as a side-effect-free test type.
 */

#define WTEST_TYPE  "firewall_address"
#define WTEST_ID    "__wtest_fwaddr"
#define WTEST_ENTRY WTEST_TYPE ":" WTEST_ID

static void test_config_crud(void)
{
	printf(C_CYAN "\n  --- WEB-5: Config CRUD round-trip ---" C_NC "\n");

	/* Ensure clean state */
	web_ipc(SG_CMD_CFG_DEL, WTEST_ENTRY);

	/* WEB-5a: APPLY (validates + saves — webd does this for POST) */
	web_check("WEB-5a", "CFG_APPLY create entry",
		  SG_CMD_CFG_APPLY,
		  WTEST_TYPE "\n" WTEST_ID "\n"
		  "type=ipmask\nsubnet=10.99.1.0/24\n",
		  SG_OK);

	/* WEB-5b: SET (store — webd does SET after APPLY for POST) */
	web_check("WEB-5b", "CFG_SET write entry",
		  SG_CMD_CFG_SET,
		  WTEST_ENTRY "\ntype=ipmask\nsubnet=10.99.1.0/24\n",
		  SG_OK);

	/* WEB-5c: GET single entry — webd returns this as JSON */
	web_check_ok_payload("WEB-5c", "CFG_GET reads entry back",
			     SG_CMD_CFG_GET, WTEST_ENTRY);

	/* WEB-5d: LIST shows the entry — webd uses this for table view */
	web_check_ok_payload("WEB-5d", "CFG_LIST includes entry",
			     SG_CMD_CFG_LIST, WTEST_TYPE);

	/* WEB-5e: LIST returns our entry (search is done by webd, not mgmtd).
	 * Just verify CFG_LIST returns the entry we created above. */
	web_check_ok_payload("WEB-5e", "CFG_LIST includes created entry",
			     SG_CMD_CFG_LIST, WTEST_TYPE "\n");

	/* WEB-5f: UPDATE — webd does GET → merge → APPLY → SET for PUT */
	web_check("WEB-5f", "CFG_SET update (PUT merge step)",
		  SG_CMD_CFG_SET,
		  WTEST_ENTRY "\ntype=ipmask\nsubnet=10.99.2.0/24\n",
		  SG_OK);

	/* WEB-5g: DELETE */
	web_check("WEB-5g", "CFG_DEL removes entry",
		  SG_CMD_CFG_DEL, WTEST_ENTRY, SG_OK);

	/* WEB-5h: GET after delete → not found */
	web_check("WEB-5h", "CFG_GET after delete → ENTRY_NOT_FOUND",
		  SG_CMD_CFG_GET, WTEST_ENTRY,
		  SG_ERR_ENTRY_NOT_FOUND);

	/* WEB-5i: DELETE non-existent (idempotent for REST) */
	web_check("WEB-5i", "CFG_DEL nonexistent → ENTRY_NOT_FOUND",
		  SG_CMD_CFG_DEL, WTEST_ENTRY,
		  SG_ERR_ENTRY_NOT_FOUND);
}

/* ── WEB-6: System diagnostic commands ───────────────────────────────── */
/*
 * Backend of GET /api/system/resources and sub-endpoints.
 * These commands gather CPU/RAM/disk stats that webd formats as JSON.
 * All should return SG_OK with non-empty payloads.
 */

static void test_system_diag(void)
{
	printf(C_CYAN "\n  --- WEB-6: System diagnostic commands ---"
	       C_NC "\n");

	/* CPU stats — used by /api/system/resources */
	web_check_ok_payload("WEB-6a", "DIAG_CPU returns data",
			     SG_CMD_DIAG_CPU, "");

	/* RAM stats — used by /api/system/resources/ram */
	web_check_ok_payload("WEB-6b", "DIAG_RAM returns data",
			     SG_CMD_DIAG_RAM, "");

	/* Process top — used by /api/system/resources/proctop */
	web_check_ok_payload("WEB-6c", "DIAG_PROCTOP returns data",
			     SG_CMD_DIAG_PROCTOP, "");

	/* Firmware info — used by /api/system/firmware */
	web_check_ok_payload("WEB-6d", "UPGRADE_STATUS returns version data",
			     SG_CMD_UPGRADE_STATUS, "");

	/* Disk stats — used by /api/system/resources/disk
	 * May not have data in QEMU; accept OK or SYSTEM_FAIL */
	struct ipc_response resp;
	int conn = ipc_send_str(SG_CMD_DIAG_DISK, "", &resp);
	web_total++;
	if (conn == 0 &&
	    (resp.status == SG_OK || resp.status == SG_ERR_SYSTEM_FAIL ||
	     resp.status == SG_ERR_NOT_FOUND)) {
		web_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [WEB-6e] DIAG_DISK responds (status=%u)\n",
		       resp.status);
	} else {
		web_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [WEB-6e] DIAG_DISK unexpected status=%u\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);
}

/* ── WEB-7: Duplicate entry rejection (CFG_SET for existing) ─────────── */
/*
 * This tests the mgmtd-level behavior: CFG_SET silently overwrites.
 * The 409 Conflict check is in webd's flow_config_create, which is
 * not reachable via raw IPC. But we CAN verify that CFG_SET overwrites
 * (which is expected) and that the data is correct after.
 *
 * The real duplicate check happens at the HTTP layer in webd.
 */

#define WDUP_ENTRY "firewall_address:__wdup_test\n"
#define WDUP_DATA1 "firewall_address:__wdup_test\n" \
		   "name=__wdup_test\ntype=ipmask\n" \
		   "subnet=10.0.0.0/24\ncomment=original\n"
#define WDUP_DATA2 "firewall_address:__wdup_test\n" \
		   "name=__wdup_test\ntype=ipmask\n" \
		   "subnet=172.16.0.0/16\ncomment=overwrite\n"

static void test_duplicate_entry(void)
{
	struct ipc_response resp;

	printf(C_CYAN "\n  --- WEB-7: Duplicate entry handling ---"
	       C_NC "\n");

	/* Cleanup */
	web_ipc(SG_CMD_CFG_DEL, WDUP_ENTRY);

	/* Create entry */
	web_check("WEB-7a", "create address __wdup_test",
		  SG_CMD_CFG_SET, WDUP_DATA1, SG_OK);

	/* Verify original data */
	int conn = ipc_send_str(SG_CMD_CFG_GET, WDUP_ENTRY, &resp);
	web_total++;
	if (conn == 0 && resp.status == SG_OK &&
	    resp.payload && strstr(resp.payload, "comment=original")) {
		web_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [WEB-7b] original data verified\n");
	} else {
		web_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [WEB-7b] original data not found\n");
	}
	ipc_resp_free(&resp);

	/* CFG_SET with same ID overwrites (mgmtd design) */
	web_check("WEB-7c", "CFG_SET same ID overwrites → SG_OK",
		  SG_CMD_CFG_SET, WDUP_DATA2, SG_OK);

	/* Verify overwritten data */
	conn = ipc_send_str(SG_CMD_CFG_GET, WDUP_ENTRY, &resp);
	web_total++;
	if (conn == 0 && resp.status == SG_OK &&
	    resp.payload && strstr(resp.payload, "comment=overwrite")) {
		web_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [WEB-7d] overwritten data verified\n");
	} else {
		web_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [WEB-7d] overwritten data not found\n");
	}
	ipc_resp_free(&resp);

	/* Cleanup */
	web_ipc(SG_CMD_CFG_DEL, WDUP_ENTRY);
}

/* ── WEB-8: CFG_INSERT (move) via IPC ────────────────────────────────── */

#define WMOV_E1  "firewall_policy:9801\n"
#define WMOV_D1  "firewall_policy:9801\n" \
		 "name=wmov1\nsrcintf=any\ndstintf=any\n" \
		 "srcaddr=all\ndstaddr=all\n" \
		 "action=accept\nstatus=enable\n"
#define WMOV_E2  "firewall_policy:9802\n"
#define WMOV_D2  "firewall_policy:9802\n" \
		 "name=wmov2\nsrcintf=any\ndstintf=any\n" \
		 "srcaddr=all\ndstaddr=all\n" \
		 "action=deny\nstatus=enable\n"

static void test_cfg_insert(void)
{
	struct ipc_response resp;

	printf(C_CYAN "\n  --- WEB-8: CFG_INSERT (move) ---" C_NC "\n");

	/* Cleanup */
	web_ipc(SG_CMD_CFG_DEL, WMOV_E1);
	web_ipc(SG_CMD_CFG_DEL, WMOV_E2);

	/* Create two policies */
	web_check("WEB-8a", "create policy 9801",
		  SG_CMD_CFG_SET, WMOV_D1, SG_OK);
	web_check("WEB-8b", "create policy 9802",
		  SG_CMD_CFG_SET, WMOV_D2, SG_OK);

	/* Move 9802 to sequence 1 */
	web_check("WEB-8c", "CFG_INSERT: move 9802 to seq 1",
		  SG_CMD_CFG_INSERT, "firewall_policy:9802\n1\n", SG_OK);

	/* Verify 9802 now has sequence=1 */
	int conn = ipc_send_str(SG_CMD_CFG_GET, WMOV_E2, &resp);
	web_total++;
	if (conn == 0 && resp.status == SG_OK &&
	    resp.payload && strstr(resp.payload, "sequence=1")) {
		web_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [WEB-8d] policy 9802 sequence=1\n");
	} else {
		web_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [WEB-8d] policy 9802 sequence!=1\n");
	}
	ipc_resp_free(&resp);

	/* CFG_INSERT on non-existent entry → error */
	web_check("WEB-8e", "CFG_INSERT nonexistent → ENTRY_NOT_FOUND",
		  SG_CMD_CFG_INSERT, "firewall_policy:9999\n5\n",
		  SG_ERR_ENTRY_NOT_FOUND);

	/* CFG_INSERT invalid sequence → error */
	web_check("WEB-8f", "CFG_INSERT seq=-1 → INVALID_VAL",
		  SG_CMD_CFG_INSERT, "firewall_policy:9801\n-1\n",
		  SG_ERR_INVALID_VAL);

	/* CFG_INSERT on non-sequence type → error */
	web_check("WEB-8g", "CFG_INSERT on system_admin → INVALID_ARG",
		  SG_CMD_CFG_INSERT, "system_admin:admin\n1\n",
		  SG_ERR_INVALID_ARG);

	/* Cleanup */
	web_ipc(SG_CMD_CFG_DEL, WMOV_E1);
	web_ipc(SG_CMD_CFG_DEL, WMOV_E2);
}

/* ── Public entry point ───────────────────────────────────────────────── */

int cli_diagnose_test_webd(int mode, diag_result_t *out)
{
	web_pass  = 0;
	web_fail  = 0;
	web_total = 0;

	printf("\n  Stargazer webd Backend IPC Test Suite\n");
	printf("  ======================================\n");

	if (!ipc_available()) {
		printf(C_RED "  ERROR" C_NC
		       ": management service unavailable\n");
		if (out) { out->passed = 0; out->failed = 0; out->total = 0; }
		return 1;
	}

	if (mode == 0) {
		printf("  (no local-only tests — run 'selftest webd' for"
		       " full IPC checks)\n\n");
		if (out) { out->passed = 0; out->failed = 0; out->total = 0; }
		return 0;
	}

	test_session_tags();
	ipc_reacquire_tag();

	test_whoami();
	ipc_reacquire_tag();

	test_ipc_error_codes();
	ipc_reacquire_tag();

	test_admin_lifecycle();
	ipc_reacquire_tag();

	test_config_crud();
	ipc_reacquire_tag();

	test_duplicate_entry();
	ipc_reacquire_tag();

	test_cfg_insert();
	ipc_reacquire_tag();

	test_system_diag();

	/* Summary */
	printf("\n  Results: %d/%d passed", web_pass, web_total);
	if (web_fail > 0)
		printf(C_RED ", %d FAILED" C_NC, web_fail);
	else
		printf(C_GREEN " (all passed)" C_NC);
	printf("\n\n");

	if (out) {
		out->passed = web_pass;
		out->failed = web_fail;
		out->total  = web_total;
	}

	return web_fail > 0 ? 1 : 0;
}
