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
					/* Parse key=value lines */
					const char *p = dresp.payload;
					while (*p) {
						const char *eol = strchr(p, '\n');
						size_t llen = eol ? (size_t)(eol - p) : strlen(p);
						if (llen > 0) {
							const char *eq = memchr(p, '=', llen);
							if (eq) {
								size_t klen = (size_t)(eq - p);
								/* Skip builtin marker */
								if (klen == 7 && strncmp(p, "builtin", 7) == 0) {
									p += llen;
									if (eol) p++;
									continue;
								}
								/* Mask passwords */
								if (klen == 8 && strncmp(p, "password", 8) == 0) {
									printf("    set password ********\n");
								} else {
									char kbuf[64];
									size_t kl = klen;
									if (kl >= sizeof(kbuf))
										kl = sizeof(kbuf) - 1;
									memcpy(kbuf, p, kl);
									kbuf[kl] = '\0';
									if (value_needs_quote(type, kbuf))
										printf("    set %.*s \"%.*s\"\n",
										       (int)klen, p,
										       (int)(llen - klen - 1), eq + 1);
									else
										printf("    set %.*s %.*s\n",
										       (int)klen, p,
										       (int)(llen - klen - 1), eq + 1);
								}
							}
						}
						p += llen;
						if (eol) p++;
					}
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

			const char *p = gresp.payload;
			while (*p) {
				const char *eol = strchr(p, '\n');
				size_t llen = eol ? (size_t)(eol - p) : strlen(p);
				if (llen > 0) {
					const char *eq = memchr(p, '=', llen);
					if (eq) {
						size_t klen = (size_t)(eq - p);
						if (klen == 7 && strncmp(p, "builtin", 7) == 0) {
							p += llen;
							if (eol) p++;
							continue;
						}
						char kbuf[64];
						size_t kl = klen;
						if (kl >= sizeof(kbuf))
							kl = sizeof(kbuf) - 1;
						memcpy(kbuf, p, kl);
						kbuf[kl] = '\0';
						if (value_needs_quote(type, kbuf))
							printf("  set %.*s \"%.*s\"\n",
							       (int)klen, p,
							       (int)(llen - klen - 1), eq + 1);
						else
							printf("  set %.*s %.*s\n",
							       (int)klen, p,
							       (int)(llen - klen - 1), eq + 1);
					}
				}
				p += llen;
				if (eol) p++;
			}
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
