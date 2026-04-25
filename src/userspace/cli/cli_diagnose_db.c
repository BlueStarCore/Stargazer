/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose_db.c — Database health diagnostics for Stargazer CLI
 *
 * Implements "execute diagnose selftest [full]" database module:
 *   - Mode 0: Registry consistency checks (local, no IPC)
 *   - Mode 1: IPC round-trips for DB state verification
 *
 * Uses the same PASS/FAIL pattern as cli_diagnose_config.c.
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_diagnose.h"
#include "cli_ipc.h"
#include "sg_validate.h"

#include <stdio.h>
#include <string.h>

/* ── Test counters ────────────────────────────────────────────────────── */

static int db_pass;
static int db_fail;
static int db_total;

/* ── Generic assertion helper ─────────────────────────────────────────── */

static void db_check(const char *id, const char *desc, int result, int expected)
{
	db_total++;
	if (result == expected) {
		db_pass++;
		printf(C_GREEN "  PASS" C_NC " [%s] %s\n", id, desc);
	} else {
		db_fail++;
		printf(C_RED "  FAIL" C_NC " [%s] %s (got %d, expected %d)\n",
		       id, desc, result, expected);
	}
}

/* ── Payload key lookup helper ────────────────────────────────────────── */

/*
 * Check if "key=..." line exists in a "key=val\nkey=val\n" payload.
 * Returns 1 if found, 0 if not.
 */
static int db_has_key(const char *payload, const char *key)
{
	if (!payload || !key)
		return 0;
	size_t klen = strlen(key);
	const char *p = payload;
	while ((p = strstr(p, key)) != NULL) {
		/* Must be at start of line or start of string */
		if (p != payload && *(p - 1) != '\n') {
			p += klen;
			continue;
		}
		if (p[klen] == '=')
			return 1;
		p += klen;
	}
	return 0;
}

/* ── Mode 0: Registry consistency ─────────────────────────────────────── */

static void test_registry_consistency(void)
{
	const sg_type_info_t *types = sg_reg_types();

	printf(C_CYAN "\n  --- SEC-DB-1: Registered types have valid mode ---"
	       C_NC "\n");
	for (int i = 0; types[i].name; i++) {
		char desc[256];
		snprintf(desc, sizeof(desc), "%s has valid mode", types[i].name);
		db_check("SEC-DB-1", desc,
			 sg_reg_type_mode(types[i].name) != -1, 1);
	}

	printf(C_CYAN "\n  --- SEC-DB-2: Registered types have permission ---"
	       C_NC "\n");
	for (int i = 0; types[i].name; i++) {
		char desc[256];
		snprintf(desc, sizeof(desc), "%s has perm", types[i].name);
		db_check("SEC-DB-2", desc, types[i].perm != NULL, 1);
	}

	printf(C_CYAN "\n  --- SEC-DB-3: Registered types have description ---"
	       C_NC "\n");
	for (int i = 0; types[i].name; i++) {
		char desc[256];
		snprintf(desc, sizeof(desc), "%s has desc", types[i].name);
		db_check("SEC-DB-3", desc, types[i].desc != NULL, 1);
	}

	printf(C_CYAN "\n  --- SEC-DB-4: Unknown type returns -1 ---"
	       C_NC "\n");
	db_check("SEC-DB-4", "__nonexistent__ returns -1",
		 sg_reg_type_mode("__nonexistent__"), -1);

	printf(C_CYAN "\n  --- SEC-DB-5: Unknown key rejected ---"
	       C_NC "\n");
	db_check("SEC-DB-5", "__bogus__ key rejected for system_settings",
		 sg_reg_is_valid_key("system_settings", "__bogus__"), 0);

	printf(C_CYAN "\n  --- SEC-DB-6: Types with defaults have keys ---"
	       C_NC "\n");
	for (int i = 0; types[i].name; i++) {
		const char *defs = sg_reg_default_values(types[i].name);
		if (!defs || !defs[0])
			continue; /* stub type — no defaults, no keys yet */
		const char *keys = sg_reg_valid_keys(types[i].name);
		char desc[256];
		snprintf(desc, sizeof(desc), "%s has keys", types[i].name);
		db_check("SEC-DB-6", desc, keys && keys[0] != '\0', 1);
	}
}

/* ── Mode 1: Database health (IPC required) ───────────────────────────── */

static void test_db_health(void)
{
	struct ipc_response resp;
	const sg_type_info_t *types = sg_reg_types();

	/* SEC-DB-7: CFG_LIST_TYPES reachable */
	printf(C_CYAN "\n  --- SEC-DB-7: CFG_LIST_TYPES IPC reachable ---"
	       C_NC "\n");
	int conn = ipc_send_str(SG_CMD_CFG_LIST_TYPES, "", &resp);
	db_check("SEC-DB-7", "CFG_LIST_TYPES returns SG_OK",
		 (conn == 0 && resp.status == SG_OK) ? 1 : 0, 1);

	/* Save type list for SEC-DB-14 */
	char type_list[4096] = {0};
	if (resp.payload && resp.payload_len > 0 &&
	    resp.payload_len < sizeof(type_list))
		memcpy(type_list, resp.payload, resp.payload_len);
	ipc_resp_free(&resp);

	/* SEC-DB-8: Seeded CFG_SINGLE types have data
	 * Only test types that have default values — stub types without
	 * defaults (e.g. ospf, rip, bgp) are not seeded on first boot. */
	printf(C_CYAN "\n  --- SEC-DB-8: Seeded CFG_SINGLE types have data ---"
	       C_NC "\n");
	for (int i = 0; types[i].name; i++) {
		if (types[i].mode != CFG_SINGLE)
			continue;
		const char *defs = sg_reg_default_values(types[i].name);
		if (!defs || !defs[0])
			continue; /* no defaults → not seeded */
		char section[256];
		snprintf(section, sizeof(section), "%s", types[i].name);
		conn = ipc_send_str(SG_CMD_CFG_GET, section, &resp);
		char desc[256];
		snprintf(desc, sizeof(desc), "%s has data", types[i].name);
		db_check("SEC-DB-8", desc,
			 (conn == 0 && resp.status == SG_OK &&
			  resp.payload && resp.payload_len > 0) ? 1 : 0, 1);
		ipc_resp_free(&resp);
	}

	/* SEC-DB-9: Critical TABLE types populated */
	printf(C_CYAN "\n  --- SEC-DB-9: Critical TABLE types populated ---"
	       C_NC "\n");
	{
		static const char *critical_tables[] = {
			"system_admin-profile",
			"system_admin",
			NULL
		};
		for (int i = 0; critical_tables[i]; i++) {
			conn = ipc_send_str(SG_CMD_CFG_LIST,
					    critical_tables[i], &resp);
			char desc[256];
			snprintf(desc, sizeof(desc), "%s has entries",
				 critical_tables[i]);
			db_check("SEC-DB-9", desc,
				 (conn == 0 && resp.status == SG_OK &&
				  resp.payload && resp.payload_len > 0) ? 1 : 0,
				 1);
			ipc_resp_free(&resp);
		}
	}

	/* SEC-DB-10: system_password-policy has required keys */
	printf(C_CYAN "\n  --- SEC-DB-10: password-policy required keys ---"
	       C_NC "\n");
	conn = ipc_send_str(SG_CMD_CFG_GET, "system_password-policy", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload) {
		db_check("SEC-DB-10", "has min-length",
			 db_has_key(resp.payload, "min-length"), 1);
		db_check("SEC-DB-10", "has min-uppercase",
			 db_has_key(resp.payload, "min-uppercase"), 1);
		db_check("SEC-DB-10", "has min-lowercase",
			 db_has_key(resp.payload, "min-lowercase"), 1);
		db_check("SEC-DB-10", "has min-digit",
			 db_has_key(resp.payload, "min-digit"), 1);
	} else {
		db_total += 4;
		db_fail += 4;
		printf(C_RED "  FAIL" C_NC " [SEC-DB-10] "
		       "could not read system_password-policy (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* SEC-DB-11: system_settings has required keys */
	printf(C_CYAN "\n  --- SEC-DB-11: system_settings required keys ---"
	       C_NC "\n");
	conn = ipc_send_str(SG_CMD_CFG_GET, "system_settings", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload) {
		db_check("SEC-DB-11", "has hostname",
			 db_has_key(resp.payload, "hostname"), 1);
		db_check("SEC-DB-11", "has timezone",
			 db_has_key(resp.payload, "timezone"), 1);
	} else {
		db_total += 2;
		db_fail += 2;
		printf(C_RED "  FAIL" C_NC " [SEC-DB-11] "
		       "could not read system_settings (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* SEC-DB-12: admin profile "read-write" has permissions key */
	printf(C_CYAN "\n  --- SEC-DB-12: read-write profile has permissions ---"
	       C_NC "\n");
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "system_admin-profile:read-write", &resp);
	db_check("SEC-DB-12", "read-write has permissions=",
		 (conn == 0 && resp.status == SG_OK && resp.payload &&
		  db_has_key(resp.payload, "permissions")) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* SEC-DB-13: admin "admin" has profile key */
	printf(C_CYAN "\n  --- SEC-DB-13: admin user has profile ---"
	       C_NC "\n");
	conn = ipc_send_str(SG_CMD_CFG_GET, "system_admin:admin", &resp);
	db_check("SEC-DB-13", "admin has profile=",
		 (conn == 0 && resp.status == SG_OK && resp.payload &&
		  db_has_key(resp.payload, "profile")) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* SEC-DB-14: No stale types in DB */
	printf(C_CYAN "\n  --- SEC-DB-14: No stale types in DB ---"
	       C_NC "\n");
	if (type_list[0]) {
		int stale_found = 0;
		char list_copy[4096];
		snprintf(list_copy, sizeof(list_copy), "%s", type_list);
		char *line = list_copy;
		while (*line) {
			char *eol = strchr(line, '\n');
			if (eol)
				*eol = '\0';
			if (*line) {
				/* system_meta is internal, always allowed */
				if (strcmp(line, "system_meta") != 0 &&
				    sg_reg_type_mode(line) < 0) {
					db_total++;
					db_fail++;
					stale_found++;
					printf(C_RED "  FAIL" C_NC
					       " [SEC-DB-14] stale type"
					       " in DB: %s\n", line);
				}
			}
			if (!eol)
				break;
			line = eol + 1;
		}
		if (!stale_found) {
			db_total++;
			db_pass++;
			printf(C_GREEN "  PASS" C_NC
			       " [SEC-DB-14] no stale types found\n");
		}
	} else {
		db_total++;
		db_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [SEC-DB-14] no type list available\n");
	}

	/* SEC-DB-15: Backfill round-trip */
	printf(C_CYAN "\n  --- SEC-DB-15: Backfill round-trip ---"
	       C_NC "\n");
	{
		/* Create a firewall_address entry without comment (optional key).
		 * The seed/reconciliation should have defaults, and we verify
		 * the entry round-trips correctly. */
		const char *set_payload =
			"firewall_address:__diag_dbtest\n"
			"name=__diag_dbtest\n"
			"subnet=10.99.0.0/16\n"
			"type=ipmask\n";

		conn = ipc_send_str(SG_CMD_CFG_SET, set_payload, &resp);
		int created = (conn == 0 && resp.status == SG_OK);
		ipc_resp_free(&resp);

		if (created) {
			/* Read it back and verify name key present */
			conn = ipc_send_str(SG_CMD_CFG_GET,
					    "firewall_address:__diag_dbtest",
					    &resp);
			db_check("SEC-DB-15",
				 "backfill entry readable with name=",
				 (conn == 0 && resp.status == SG_OK &&
				  resp.payload &&
				  db_has_key(resp.payload, "name")) ? 1 : 0,
				 1);
			ipc_resp_free(&resp);

			/* Cleanup */
			ipc_send_str(SG_CMD_CFG_DEL,
				     "firewall_address:__diag_dbtest", &resp);
			ipc_resp_free(&resp);
		} else {
			db_total++;
			db_fail++;
			printf(C_RED "  FAIL" C_NC
			       " [SEC-DB-15] could not create test entry\n");
		}
	}
}

/* ── Public entry point ───────────────────────────────────────────────── */

int cli_diagnose_test_database(int mode, diag_result_t *out)
{
	db_pass  = 0;
	db_fail  = 0;
	db_total = 0;

	printf("\n  Stargazer Database Health Diagnostics\n");
	printf("  =====================================\n");

	/* Mode 0: registry consistency (local, no IPC) */
	test_registry_consistency();

	if (mode == 1) {
		/* Full mode: IPC round-trip tests */
		if (!ipc_available()) {
			printf(C_RED "\n  ERROR" C_NC
			       ": mgmtd socket not found (%s)\n",
			       SG_MGMTD_SOCK);
			printf("  IPC tests skipped."
			       " Run with mgmtd for full test.\n");
		} else {
			test_db_health();
		}
	}

	/* Summary */
	printf("\n  Results: %d/%d passed", db_pass, db_total);
	if (db_fail > 0)
		printf(C_RED ", %d FAILED" C_NC, db_fail);
	else
		printf(C_GREEN " (all passed)" C_NC);
	printf("\n\n");

	if (out) {
		out->passed = db_pass;
		out->failed = db_fail;
		out->total  = db_total;
	}

	return db_fail > 0 ? 1 : 0;
}
