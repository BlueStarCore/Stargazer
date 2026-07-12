/* SPDX-License-Identifier: MIT */
/*
 * cli_debug.c — Debug state manager for Stargazer CLI
 *
 * C replacement for the debug subtree of cmd_execute.
 *
 * Primary state is in-memory (fast, no I/O per check).
 * Secondary persistence through mgmtd IPC (SG_CMD_DEBUG_STATE_*).
 * No direct file I/O — works in the seccomp sandbox.
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_debug.h"
#include "cli_ipc.h"
#include "sg_validate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_STATE_KEYS   32
#define MAX_KEY_LEN      64
#define MAX_VAL_LEN      64

/* ── In-memory state ──────────────────────────────────────────────────── */

struct dbg_entry {
	char key[MAX_KEY_LEN];
	char val[MAX_VAL_LEN];
};

static struct dbg_entry mem_state[MAX_STATE_KEYS];
static int mem_count;
static int mem_loaded; /* 1 after first load attempt */

/*
 * Load state via IPC (once, on first access).
 *
 * Safe from deadlock because ipc_send() computes debug flags
 * BEFORE connect() — so this inner IPC completes fully before
 * the outer connection is established.
 *
 * Call chain: ipc_send(X) → dbg_enabled() → mem_load_once()
 *   → ipc_send(DEBUG_STATE_GET) → dbg_enabled() → mem_loaded=1 → return
 *   → inner IPC completes → outer ipc_send(X) continues
 */
static void mem_load_once(void)
{
	if (mem_loaded)
		return;
	mem_loaded = 1;

	struct ipc_response resp = {0};
	if (ipc_send_str(SG_CMD_DEBUG_STATE_GET, "", &resp) != 0 ||
	    resp.status != SG_OK || !resp.payload) {
		ipc_resp_free(&resp);
		return;
	}

	/* Parse key=value lines from mgmtd response */
	const char *p = resp.payload;
	while (*p && mem_count < MAX_STATE_KEYS) {
		const char *eq = strchr(p, '=');
		const char *nl = strchr(p, '\n');
		if (!eq || (nl && eq > nl)) {
			if (!nl) break;
			p = nl + 1;
			continue;
		}

		size_t klen = (size_t)(eq - p);
		if (klen == 0 || klen >= MAX_KEY_LEN) {
			if (!nl) break;
			p = nl + 1;
			continue;
		}

		memcpy(mem_state[mem_count].key, p, klen);
		mem_state[mem_count].key[klen] = '\0';

		const char *v = eq + 1;
		size_t vlen = nl ? (size_t)(nl - v) : strlen(v);
		if (vlen >= MAX_VAL_LEN) vlen = MAX_VAL_LEN - 1;
		memcpy(mem_state[mem_count].val, v, vlen);
		mem_state[mem_count].val[vlen] = '\0';

		mem_count++;
		if (!nl) break;
		p = nl + 1;
	}
	ipc_resp_free(&resp);
}

/* Lookup key in memory */
static const char *mem_get(const char *key)
{
	for (int i = 0; i < mem_count; i++) {
		if (strcmp(mem_state[i].key, key) == 0)
			return mem_state[i].val;
	}
	return NULL;
}

/* Set key in memory */
static void mem_set(const char *key, const char *val)
{
	for (int i = 0; i < mem_count; i++) {
		if (strcmp(mem_state[i].key, key) == 0) {
			snprintf(mem_state[i].val, MAX_VAL_LEN, "%s", val);
			return;
		}
	}
	if (mem_count < MAX_STATE_KEYS) {
		snprintf(mem_state[mem_count].key, MAX_KEY_LEN, "%s", key);
		snprintf(mem_state[mem_count].val, MAX_VAL_LEN, "%s", val);
		mem_count++;
	}
}

/* Persist in-memory state via mgmtd IPC */
static void mem_persist(void)
{
	/* Build key=value payload */
	char payload[4096];
	size_t pos = 0;
	for (int i = 0; i < mem_count; i++) {
		int n = snprintf(payload + pos, sizeof(payload) - pos,
				 "%s=%s\n", mem_state[i].key,
				 mem_state[i].val);
		if (n > 0 && (size_t)n < sizeof(payload) - pos)
			pos += (size_t)n;
	}

	struct ipc_response resp = {0};
	ipc_send_str(SG_CMD_DEBUG_STATE_SET, payload, &resp);
	ipc_resp_free(&resp);
}

/* ── Public API ───────────────────────────────────────────────────────── */

const char *dbg_get(const char *key, const char *defval)
{
	mem_load_once();
	const char *v = mem_get(key);
	return v ? v : defval;
}

void dbg_set(const char *key, const char *val)
{
	mem_load_once();
	mem_set(key, val);
	mem_persist();
}

void dbg_reset(void)
{
	mem_count = 0;
	mem_loaded = 1; /* don't reload stale data */

	struct ipc_response resp = {0};
	ipc_send_str(SG_CMD_DEBUG_STATE_RESET, "", &resp);
	ipc_resp_free(&resp);
}

int dbg_enabled(void)
{
	/* Defer debug state load until session tag is acquired.
	 * ipc_send() calls dbg_enabled() before connect — if we
	 * trigger mem_load_once() before the tag exists, the inner
	 * DEBUG_STATE_GET IPC is rejected (no tag). */
	if (!mem_loaded && !ipc_has_tag())
		return 0;
	mem_load_once();
	const char *v = mem_get("enabled");
	return v && strcmp(v, "1") == 0;
}

/* ── Helpers ──────────────────────────────────────────────────────────── */

/* Normalize enable/disable/on/off to "1"/"0". Returns NULL on invalid. */
static const char *bool_norm(const char *s)
{
	if (!s) return NULL;
	if (strcmp(s, "enable") == 0 || strcmp(s, "on") == 0 ||
	    strcmp(s, "1") == 0 || strcmp(s, "yes") == 0)
		return "1";
	if (strcmp(s, "disable") == 0 || strcmp(s, "off") == 0 ||
	    strcmp(s, "0") == 0 || strcmp(s, "no") == 0)
		return "0";
	return NULL;
}

/* Parse next space-delimited token from *pp, advance pointer */
static int next_token(const char **pp, char *out, size_t outsz)
{
	const char *p = *pp;
	while (*p == ' ') p++;
	if (!*p) { out[0] = '\0'; return 0; }

	const char *start = p;
	while (*p && *p != ' ') p++;
	size_t len = (size_t)(p - start);
	if (len >= outsz) len = outsz - 1;
	memcpy(out, start, len);
	out[len] = '\0';
	*pp = p;
	return 1;
}

/* ── Debug status ─────────────────────────────────────────────────────── */

static void print_status(void)
{
	printf("\n");
	printf("  Debug status:\n");
	printf("  Global debug:        %s\n",
	       strcmp(dbg_get("enabled", "0"), "1") == 0 ? "enable" : "disable");
	printf("  Option timestamp:    %s\n",
	       strcmp(dbg_get("opt_timestamp", "1"), "1") == 0 ? "enable" : "disable");
	printf("  Option actor:        %s\n",
	       strcmp(dbg_get("opt_actor", "1"), "1") == 0 ? "enable" : "disable");
	printf("  Option function:     %s\n",
	       strcmp(dbg_get("opt_function", "1"), "1") == 0 ? "enable" : "disable");
	printf("  Option hierarchy:    %s\n",
	       strcmp(dbg_get("opt_hierarchy", "1"), "1") == 0 ? "enable" : "disable");
	printf("  Flow trace:          %s\n",
	       strcmp(dbg_get("flow_trace", "0"), "1") == 0 ? "enable" : "disable");

	const char *fl = dbg_get("flow_limit", "0");
	if (strcmp(fl, "0") == 0)
		printf("  Flow limit:          unlimited\n");
	else
		printf("  Flow limit:          %s\n", fl);

	printf("  CLI debug:           %s\n",
	       strcmp(dbg_get("cli_debug", "0"), "1") == 0 ? "enable" : "disable");
	printf("  mgmtd debug:         %s\n",
	       strcmp(dbg_get("mgmtd_debug", "0"), "1") == 0 ? "enable" : "disable");
	printf("  Auth admin debug:    %s\n",
	       strcmp(dbg_get("auth_admin", "0"), "1") == 0 ? "enable" : "disable");
	printf("  Auth user debug:     %s\n",
	       strcmp(dbg_get("auth_user", "0"), "1") == 0 ? "enable" : "disable");
	printf("\n");
}

/* ── Public handler functions ─────────────────────────────────────────── */

int cmd_debug_enable(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	dbg_set("enabled", "1");
	printf("  Debug enabled.\n");
	return 0;
}

int cmd_debug_disable(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	dbg_set("enabled", "0");
	printf("  Debug disabled.\n");
	return 0;
}

int cmd_debug_reset(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	dbg_reset();
	printf("  Debug state reset. All debug features disabled and options restored.\n");
	return 0;
}

int cmd_debug_status(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	print_status();
	return 0;
}

int cmd_debug_option(const char *args, const char *permissions)
{
	(void)permissions;
	const char *rest = args ? args : "";
	while (*rest == ' ') rest++;

	char opt_name[32], opt_act[16];
	if (!next_token(&rest, opt_name, sizeof(opt_name)) || !opt_name[0]) {
		printf("  Usage: execute debug option <timestamp|actor|function|hierarchy> <enable|disable>\n");
		return 0;
	}

	const char *state_key = NULL;
	if (strcmp(opt_name, "timestamp") == 0)
		state_key = "opt_timestamp";
	else if (strcmp(opt_name, "actor") == 0)
		state_key = "opt_actor";
	else if (strcmp(opt_name, "function") == 0)
		state_key = "opt_function";
	else if (strcmp(opt_name, "hierarchy") == 0)
		state_key = "opt_hierarchy";
	else {
		printf("  Usage: execute debug option <timestamp|actor|function|hierarchy> <enable|disable>\n");
		return 0;
	}

	if (!next_token(&rest, opt_act, sizeof(opt_act)) || !opt_act[0]) {
		printf("  Usage: execute debug option %s <enable|disable>\n", opt_name);
		return 0;
	}
	const char *bv = bool_norm(opt_act);
	if (!bv) {
		printf("  Usage: execute debug option %s <enable|disable>\n", opt_name);
		return 0;
	}
	dbg_set(state_key, bv);
	printf("  Debug option %s %sd.\n", opt_name, opt_act);
	return 0;
}

int cmd_debug_cli(const char *args, const char *permissions)
{
	(void)permissions;
	const char *rest = args ? args : "";
	while (*rest == ' ') rest++;

	char act[16];
	if (!next_token(&rest, act, sizeof(act)) || !act[0])
		snprintf(act, sizeof(act), "enable");
	const char *bv = bool_norm(act);
	if (!bv) {
		printf("  Usage: execute debug cli [enable|disable]\n");
		return 0;
	}
	dbg_set("cli_debug", bv);
	printf("  Debug CLI %sd.\n", act);
	return 0;
}

int cmd_debug_mgmtd(const char *args, const char *permissions)
{
	(void)permissions;
	const char *rest = args ? args : "";
	while (*rest == ' ') rest++;

	char act[16];
	if (!next_token(&rest, act, sizeof(act)) || !act[0])
		snprintf(act, sizeof(act), "enable");
	const char *bv = bool_norm(act);
	if (!bv) {
		printf("  Usage: execute debug mgmtd [enable|disable]\n");
		return 0;
	}
	dbg_set("mgmtd_debug", bv);
	printf("  Debug mgmtd %sd.\n", act);
	return 0;
}

int cmd_debug_auth(const char *args, const char *permissions)
{
	(void)permissions;
	const char *rest = args ? args : "";
	while (*rest == ' ') rest++;

	char role[16], act[16];
	if (!next_token(&rest, role, sizeof(role)) || !role[0]) {
		printf("  Usage: execute debug auth <admin|user> [enable|disable]\n");
		return 0;
	}
	const char *state_key = NULL;
	if (strcmp(role, "admin") == 0)
		state_key = "auth_admin";
	else if (strcmp(role, "user") == 0)
		state_key = "auth_user";
	else {
		printf("  Usage: execute debug auth <admin|user> [enable|disable]\n");
		return 0;
	}

	if (!next_token(&rest, act, sizeof(act)) || !act[0])
		snprintf(act, sizeof(act), "enable");
	const char *bv = bool_norm(act);
	if (!bv) {
		printf("  Usage: execute debug auth <admin|user> [enable|disable]\n");
		return 0;
	}
	dbg_set(state_key, bv);
	printf("  Debug auth %s %sd.\n", role, act);
	return 0;
}

int cmd_debug_flow(const char *args, const char *permissions)
{
	(void)permissions;
	const char *rest = args ? args : "";
	while (*rest == ' ') rest++;

	/* "trace" keyword already consumed by dispatch — args starts after it.
	 * But if caller passed the full "trace ..." string, skip it. */
	char peek[16];
	const char *saved = rest;
	if (next_token(&saved, peek, sizeof(peek)) &&
	    strcmp(peek, "trace") == 0)
		rest = saved;

	/* Optional enable/disable */
	char act[16] = "enable";
	saved = rest;
	if (next_token(&saved, peek, sizeof(peek)) && peek[0]) {
		if (strcmp(peek, "enable") == 0 ||
		    strcmp(peek, "disable") == 0) {
			snprintf(act, sizeof(act), "%s", peek);
			rest = saved;
		}
	}

	const char *bv = bool_norm(act);
	if (!bv) {
		printf("  Usage: execute debug flow trace [enable|disable] [limit <n>|unlimited]\n");
		return 0;
	}
	dbg_set("flow_trace", bv);

	/* Optional limit */
	char lim_tok[16];
	if (next_token(&rest, lim_tok, sizeof(lim_tok)) && lim_tok[0]) {
		if (strcmp(lim_tok, "limit") == 0) {
			char lim_val[16];
			if (next_token(&rest, lim_val, sizeof(lim_val)) &&
			    lim_val[0]) {
				if (strcmp(lim_val, "unlimited") == 0) {
					dbg_set("flow_limit", "0");
				} else if (sg_is_uint_range(lim_val, 0, 999999)) {
					dbg_set("flow_limit", lim_val);
				} else {
					printf("  Invalid limit value: %s\n", lim_val);
					return 0;
				}
			}
		} else if (strcmp(lim_tok, "unlimited") == 0) {
			dbg_set("flow_limit", "0");
		} else {
			printf("  Usage: execute debug flow trace [enable|disable] [limit <n>|unlimited]\n");
			return 0;
		}
	}

	printf("  Debug flow trace flag %sd.\n", act);
	if (strcmp(act, "enable") == 0)
		printf("  Note: per-flow state now lives in nf_conntrack; this"
		       " flag is recorded but has no consumer yet — flow-trace"
		       " output arrives with the Phase 3 ML scoring daemon.\n");
	return 0;
}
