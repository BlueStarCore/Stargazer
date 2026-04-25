/* SPDX-License-Identifier: MIT */
/*
 * cli_show.c — Show command implementations for Stargazer CLI
 *
 * All data comes exclusively via IPC to mgmtd. No direct file reads,
 * no fork/exec — the CLI is a pure terminal-to-IPC bridge after sandbox.
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_show.h"
#include "cli_ipc.h"
#include "sg_validate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Helpers ──────────────────────────────────────────────────────────── */

/* Print IPC response or error */
static void show_ipc(uint32_t cmd, const char *payload_str,
		     const char *header)
{
	struct ipc_response resp = {0};
	if (ipc_send_str(cmd, payload_str, &resp) == 0 &&
	    resp.status == SG_OK && resp.payload && resp.payload[0]) {
		if (header)
			printf("  %s\n", header);
		printf("%s", resp.payload);
		ipc_resp_free(&resp);
		return;
	}
	ipc_resp_free(&resp);

	if (header)
		printf("  %s\n", header);
	printf("  (service unavailable)\n");
}

/* ── show status ──────────────────────────────────────────────────────── */

void show_status(void)
{
	struct ipc_response resp = {0};
	if (ipc_send_str(SG_CMD_SHOW_STATUS, "", &resp) == 0 &&
	    resp.status == SG_OK && resp.payload && resp.payload[0]) {
		printf("%s", resp.payload);
		ipc_resp_free(&resp);
		return;
	}
	ipc_resp_free(&resp);
	printf("  (service unavailable — cannot show status)\n");
}

/* ── show sessions ────────────────────────────────────────────────────── */

void show_sessions(void)
{
	struct ipc_response resp = {0};
	if (ipc_send_str(SG_CMD_SHOW_SESSIONS, "", &resp) == 0 &&
	    resp.status == SG_OK && resp.payload && resp.payload[0]) {
		printf("  === Active Sessions ===\n");
		printf("%s", resp.payload);
	} else {
		printf("  Session tracking not available (module not loaded)\n");
	}
	ipc_resp_free(&resp);
}

/* ── show stats ───────────────────────────────────────────────────────── */

void show_stats(void)
{
	printf("  === Packet Statistics ===\n");
	show_ipc(SG_CMD_SHOW_STATS, "", NULL);
}

/* ── show interfaces ──────────────────────────────────────────────────── */

void show_interfaces(void)
{
	show_ipc(SG_CMD_SHOW_IFACES, "", "=== Network Interfaces ===");
}

/* ── show routes ──────────────────────────────────────────────────────── */

void show_routes(void)
{
	show_ipc(SG_CMD_SHOW_ROUTES, "", "=== Routing Table ===");
}

/* Check whether a value should be quoted in FortiGate-style output. */
static int value_needs_quote(const char *type, const char *key)
{
	const char *kind = sg_reg_value_kind(type, key);
	return strcmp(kind, "string") == 0;
}

/*
 * Print ALL registered keys for an entry type.
 * Walks sg_reg_all_keys_defaults() to get every key, then looks up the
 * actual value from the DB payload (kv "key=val\n" string).
 * Keys not in the DB get the registry default (or empty).
 * Skips internal keys (builtin, password-hash).
 */
static void show_entry_keys(const char *type, const char *payload,
			    const char *indent)
{
	const char *all = sg_reg_all_keys_defaults(type);
	if (!all || !all[0]) return;

	/* Copy static buffer — sg_reg_all_keys_defaults uses static */
	char allcopy[2048];
	snprintf(allcopy, sizeof(allcopy), "%s", all);

	char *kp = allcopy;
	while (*kp) {
		char *knl = strchr(kp, '\n');
		if (knl) *knl = '\0';
		char *keq = strchr(kp, '=');
		if (!keq) { if (!knl) break; kp = knl + 1; continue; }

		*keq = '\0';
		/* Bounded key copy — field keys are short (< 64 chars) */
		char key[64];
		size_t kplen = strlen(kp);
		if (kplen >= sizeof(key)) kplen = sizeof(key) - 1;
		memcpy(key, kp, kplen);
		key[kplen] = '\0';
		const char *defval = keq + 1;

		/* Skip internal keys */
		if (strcmp(key, "builtin") == 0 ||
		    strcmp(key, "password-hash") == 0) {
			if (!knl) break;
			kp = knl + 1;
			continue;
		}

		/* Look up actual value from DB payload */
		char val[SG_PAYLOAD_MAX];
		sg_kv_get(payload, key, val, sizeof(val));

		/* Use default if not in DB */
		if (!val[0] && defval[0])
			snprintf(val, sizeof(val), "%s", defval);

		/* Mask passwords */
		if (strcmp(key, "password") == 0) {
			if (val[0])
				printf("%sset %s ********\n", indent, key);
		} else if (value_needs_quote(type, key) && val[0]) {
			printf("%sset %s \"%s\"\n", indent, key, val);
		} else {
			printf("%sset %s %s\n", indent, key, val);
		}

		if (!knl) break;
		kp = knl + 1;
	}
}

/* ── show configure (FortiGate-style dump) ────────────────────────────── */

/*
 * Iterate all known config types from sg_validate's type_table.
 * For each, query mgmtd via IPC to get entries, then format in
 * FortiGate "config ... / edit ... / set ... / next / end" style.
 */
void show_configure(void)
{
	printf("  === Running Configuration ===\n\n");

	/* Walk all types known to the registry */
	const sg_type_info_t *types = sg_reg_types();

	for (int t = 0; types[t].name; t++) {
		const char *type = types[t].name;
		int mode = (int)types[t].mode;

		const char *label = sg_reg_type_label(type);

		if (mode == CFG_TABLE) {
			/* Get list of IDs */
			struct ipc_response lresp = {0};
			if (ipc_send_str(SG_CMD_CFG_LIST, type, &lresp) != 0 ||
			    lresp.status != SG_OK || !lresp.payload ||
			    !lresp.payload[0]) {
				ipc_resp_free(&lresp);
				continue;
			}

			printf("config %s\n", label);

			/* Parse newline-separated IDs */
			char *ids = lresp.payload;
			char *id = ids;
			while (id && *id) {
				char *nl = strchr(id, '\n');
				if (nl) *nl = '\0';
				if (!*id) { if (nl) id = nl + 1; else break; continue; }

				printf("  edit \"%s\"\n", id);

				/* Get entry data */
				char section[512];
				snprintf(section, sizeof(section), "%s:%s",
					 type, id);
				struct ipc_response dresp;
				if (ipc_send_str(SG_CMD_CFG_GET, section,
						 &dresp) == 0 &&
				    dresp.status == SG_OK && dresp.payload) {
					show_entry_keys(type, dresp.payload, "    ");
				}
				ipc_resp_free(&dresp);

				printf("  next\n");
				if (!nl) break;
				id = nl + 1;
			}
			printf("end\n\n");
			ipc_resp_free(&lresp);
		} else {
			/* CFG_SINGLE — id is implicitly "0" */
			struct ipc_response gresp = {0};
			char section[256];
			snprintf(section, sizeof(section), "%s", type);
			if (ipc_send_str(SG_CMD_CFG_GET, section, &gresp) != 0 ||
			    gresp.status != SG_OK || !gresp.payload ||
			    !gresp.payload[0]) {
				ipc_resp_free(&gresp);
				continue;
			}

			printf("config %s\n", label);
			show_entry_keys(type, gresp.payload, "  ");
			printf("end\n\n");
			ipc_resp_free(&gresp);
		}
	}
}

/* ── show firmware ────────────────────────────────────────────────────── */

void show_firmware(void)
{
	struct ipc_response resp = {0};
	if (ipc_send_str(SG_CMD_UPGRADE_STATUS, "", &resp) == 0 &&
	    resp.status == SG_OK && resp.payload && resp.payload[0]) {
		printf("%s", resp.payload);
		ipc_resp_free(&resp);
		return;
	}
	ipc_resp_free(&resp);

	/* Fallback: compiled-in version */
	printf("  === Firmware Status ===\n");
#ifdef VERSION
	printf("  Running version: %s\n", VERSION);
#else
	printf("  Running version: unknown\n");
#endif
}

/* ── show config (modules + sysctl) ───────────────────────────────────── */

void show_config(void)
{
	printf("  === Stargazer Configuration ===\n");

	struct ipc_response resp = {0};
	if (ipc_send_str(SG_CMD_SHOW_BOOT_CONFIG, "", &resp) == 0 &&
	    resp.status == SG_OK && resp.payload && resp.payload[0]) {
		/* Parse [modules] and [sysctl] sections */
		const char *p = resp.payload;
		while (*p) {
			const char *eol = strchr(p, '\n');
			size_t llen = eol ? (size_t)(eol - p) : strlen(p);

			if (llen == 9 && strncmp(p, "[modules]", 9) == 0)
				printf("  Modules:\n");
			else if (llen == 8 && strncmp(p, "[sysctl]", 8) == 0)
				printf("  Sysctl:\n");
			else if (llen > 0)
				printf("    %.*s\n", (int)llen, p);

			if (!eol) break;
			p = eol + 1;
		}
	} else {
		printf("  (service unavailable — cannot show config)\n");
	}
	ipc_resp_free(&resp);
}
