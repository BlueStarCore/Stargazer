/* SPDX-License-Identifier: MIT */
/*
 * cli_cmd_table.c — Table-driven command registry for Stargazer CLI
 *
 * Single declarative table drives registration, dispatch, and auto-usage
 * for all CLI commands.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "cli_cmd_table.h"
#include "cli_dispatch.h"
#include "cli_readline.h"
#include "cli_configure.h"
#include "cli_diagnose.h"
#include "cli_diagnose_sys.h"
#include "cli_debug.h"
#include "cli_show.h"
#include "cli_ipc.h"
#include "sg_validate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Thin handler wrappers ────────────────────────────────────────────── */

static int cmd_help(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	cli_print_help();
	return 0;
}

static int cmd_exit(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	printf("  Goodbye.\n");
	return 1;
}

static int cmd_show_status(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	show_status();
	return 0;
}

static int cmd_show_sessions(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	show_sessions();
	return 0;
}

static int cmd_show_stats(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	show_stats();
	return 0;
}

static int cmd_show_interfaces(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	show_interfaces();
	return 0;
}

static int cmd_show_routes(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	show_routes();
	return 0;
}

static int cmd_show_configure(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	show_configure();
	return 0;
}

static int cmd_show_config(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	show_config();
	return 0;
}

#define CMD_MAX_ARGS     32  /* max tokens in configure argument list */
#define CMD_MAX_SHOWN    64  /* max subcommands in auto-usage output  */

static int cmd_configure(const char *args, const char *permissions)
{
	(void)permissions;
	const char *argv[CMD_MAX_ARGS];
	int argc = 0;
	char args_copy[CLI_MAX_LINE];

	if (args && args[0]) {
		snprintf(args_copy, sizeof(args_copy), "%s", args);
		char *tok = args_copy;
		while (*tok && argc < CMD_MAX_ARGS - 1) {
			while (*tok == ' ')
				tok++;
			if (!*tok)
				break;
			argv[argc++] = tok;
			while (*tok && *tok != ' ')
				tok++;
			if (*tok)
				*tok++ = '\0';
		}
	}
	argv[argc] = NULL;
	cli_configure(argc, argv);
	return 0;
}

static int cmd_show_firmware(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	show_firmware();
	return 0;
}

/*
 * Parse a key=value line from firmware progress state.
 * Copies the value for 'key' into 'out' (max outsz bytes).
 */
static void fw_parse_val(const char *data, const char *key,
			 char *out, size_t outsz)
{
	out[0] = '\0';
	if (!data || !key || outsz == 0)
		return;
	size_t klen = strlen(key);
	const char *p = data;
	while ((p = strstr(p, key)) != NULL) {
		/* Must be at start of line or start of string */
		if (p != data && *(p - 1) != '\n') {
			p += klen;
			continue;
		}
		if (p[klen] != '=') {
			p += klen;
			continue;
		}
		const char *val = p + klen + 1;
		const char *eol = strchr(val, '\n');
		size_t vlen = eol ? (size_t)(eol - val) : strlen(val);
		if (vlen >= outsz)
			vlen = outsz - 1;
		memcpy(out, val, vlen);
		out[vlen] = '\0';
		return;
	}
}

static int cmd_fw_upgrade(const char *args, const char *permissions)
{
	(void)permissions;

	/* Require a URL argument */
	if (!args || !*args) {
		printf("  Usage: execute firmware upgrade <url>\n");
		printf("  Supported schemes: http://, https://, tftp://\n");
		return 0;
	}

	/* Validate URL scheme */
	if (strncmp(args, "http://", 7) != 0 &&
	    strncmp(args, "https://", 8) != 0 &&
	    strncmp(args, "tftp://", 7) != 0) {
		printf("  Invalid URL: must start with http://, https://, or tftp://\n");
		return 0;
	}

	/* Confirm with admin */
	printf("  WARNING: This will download firmware, install it, and reboot the device.\n");
	printf("  Do you want to continue? [y/N] ");
	fflush(stdout);

	char confirm[16] = {0};
	if (!fgets(confirm, sizeof(confirm), stdin) ||
	    (confirm[0] != 'y' && confirm[0] != 'Y')) {
		printf("  Firmware upgrade cancelled.\n");
		return 0;
	}

	/* Build payload and send IPC */
	char payload[SG_PAYLOAD_MAX];
	snprintf(payload, sizeof(payload), "url=%s\n", args);

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_FW_UPGRADE, payload, &resp) != 0) {
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		printf("  Firmware upgrade failed: %s\n",
		       resp.extra[0] ? resp.extra : sg_status_str(resp.status));
		ipc_resp_free(&resp);
		return 0;
	}
	ipc_resp_free(&resp);

	/* Poll for progress updates */
	printf("\n  Starting firmware upgrade...\n\n");
	fflush(stdout);

	int last_step = -1;
	for (int i = 0; i < 240; i++) {  /* 240 * 500ms = 120s timeout */
		usleep(500000);

		struct ipc_response pr;
		if (ipc_send_str(SG_CMD_FW_PROGRESS, "", &pr) != 0) {
			printf("  Connection lost — device may be rebooting.\n");
			break;
		}

		if (pr.status != SG_OK || !pr.payload) {
			ipc_resp_free(&pr);
			continue;
		}

		char step_s[16], total_s[16], status[32], message[256];
		fw_parse_val(pr.payload, "step", step_s, sizeof(step_s));
		fw_parse_val(pr.payload, "total", total_s, sizeof(total_s));
		fw_parse_val(pr.payload, "status", status, sizeof(status));
		fw_parse_val(pr.payload, "message", message, sizeof(message));

		int step = atoi(step_s);
		int total = atoi(total_s);

		if (step > last_step && message[0]) {
			if (total > 0)
				printf("  [%d/%d] %s\n", step, total, message);
			else
				printf("  %s\n", message);
			fflush(stdout);
			last_step = step;
		}

		if (strcmp(status, "done") == 0) {
			printf("\n  System is rebooting now...\n");
			ipc_resp_free(&pr);
			break;
		}
		if (strcmp(status, "error") == 0) {
			printf("\n  Firmware upgrade failed.\n");
			ipc_resp_free(&pr);
			break;
		}
		if (strcmp(status, "idle") == 0) {
			/* Upgrade finished and state was already cleaned up */
			ipc_resp_free(&pr);
			break;
		}

		ipc_resp_free(&pr);
	}

	if (last_step < 0)
		printf("  Timed out waiting for upgrade progress.\n");

	return 0;
}

static int cmd_sys_shutdown(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	struct ipc_response resp;
	printf("  System shutting down...\n");
	ipc_send_str(SG_CMD_SYS_POWEROFF, "", &resp);
	ipc_resp_free(&resp);
	return 0;
}

static int cmd_sys_reboot(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	struct ipc_response resp;
	printf("  System rebooting...\n");
	ipc_send_str(SG_CMD_SYS_REBOOT, "", &resp);
	ipc_resp_free(&resp);
	return 0;
}

static int cmd_diag_top(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	diag_show_top();
	return 0;
}

static int cmd_diag_resources(const char *args, const char *permissions)
{
	(void)permissions;
	const char *which = args;
	if (which) {
		while (*which == ' ')
			which++;
	}
	if (!which || !*which)
		which = "all";
	diag_show_resources(which);
	return 0;
}

static int cmd_diag_test_perms(const char *args, const char *permissions)
{
	int mode = 0;
	if (args) {
		while (*args == ' ')
			args++;
		if (strcmp(args, "full") == 0)
			mode = 1;
		else if (*args != '\0') {
			printf("  Unknown argument: %s\n", args);
			printf("  Usage: execute diagnose test-permissions [full]\n");
			return 0;
		}
	}
	cli_diagnose_test_permissions(mode, permissions);
	return 0;
}

static int cmd_diag_test_cfg(const char *args, const char *permissions)
{
	(void)permissions;
	int mode = 0;
	if (args) {
		while (*args == ' ')
			args++;
		if (strcmp(args, "full") == 0)
			mode = 1;
		else if (*args != '\0') {
			printf("  Unknown argument: %s\n", args);
			printf("  Usage: execute diagnose test-configure [full]\n");
			return 0;
		}
	}
	cli_diagnose_test_configure(mode);
	return 0;
}

static int cmd_ping(const char *args, const char *permissions)
{
	(void)permissions;

	if (!args || !*args) {
		printf("  Usage: execute ping <IPv4-address-or-hostname>\n");
		return 0;
	}

	char payload[SG_PAYLOAD_MAX];
	snprintf(payload, sizeof(payload), "target=%s\n", args);

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_NET_PING, payload, &resp) != 0) {
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		printf("  Ping failed: %s\n",
		       resp.extra[0] ? resp.extra : sg_status_str(resp.status));
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

static int cmd_traceroute(const char *args, const char *permissions)
{
	(void)permissions;

	if (!args || !*args) {
		printf("  Usage: execute traceroute <IPv4-address-or-hostname>\n");
		return 0;
	}

	char payload[SG_PAYLOAD_MAX];
	snprintf(payload, sizeof(payload), "target=%s\n", args);

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_NET_TRACEROUTE, payload, &resp) != 0) {
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		printf("  Traceroute failed: %s\n",
		       resp.extra[0] ? resp.extra : sg_status_str(resp.status));
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

static int cmd_nslookup(const char *args, const char *permissions)
{
	(void)permissions;

	if (!args || !*args) {
		printf("  Usage: execute nslookup <hostname-or-IP>\n");
		return 0;
	}

	char payload[SG_PAYLOAD_MAX];
	snprintf(payload, sizeof(payload), "target=%s\n", args);

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_NET_NSLOOKUP, payload, &resp) != 0) {
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		printf("  Nslookup failed: %s\n",
		       resp.extra[0] ? resp.extra : sg_status_str(resp.status));
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

static int cmd_arping(const char *args, const char *permissions)
{
	(void)permissions;

	if (!args || !*args) {
		printf("  Usage: execute arping <IPv4-address> [interface]\n");
		return 0;
	}

	/* Parse: first word = target, optional second word = interface */
	char target[256], iface[64];
	target[0] = '\0';
	iface[0] = '\0';

	const char *p = args;
	while (*p == ' ')
		p++;
	const char *end = p;
	while (*end && *end != ' ')
		end++;
	size_t tlen = (size_t)(end - p);
	if (tlen >= sizeof(target))
		tlen = sizeof(target) - 1;
	memcpy(target, p, tlen);
	target[tlen] = '\0';

	if (*end) {
		p = end + 1;
		while (*p == ' ')
			p++;
		if (*p) {
			snprintf(iface, sizeof(iface), "%s", p);
			/* Trim trailing spaces */
			size_t ilen = strlen(iface);
			while (ilen > 0 && iface[ilen - 1] == ' ')
				iface[--ilen] = '\0';
		}
	}

	char payload[SG_PAYLOAD_MAX];
	if (iface[0])
		snprintf(payload, sizeof(payload),
			 "target=%s\niface=%s\n", target, iface);
	else
		snprintf(payload, sizeof(payload), "target=%s\n", target);

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_NET_ARPING, payload, &resp) != 0) {
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		printf("  Arping failed: %s\n",
		       resp.extra[0] ? resp.extra : sg_status_str(resp.status));
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

/* ── Command table ────────────────────────────────────────────────────── */

static const cmd_entry_t cmd_table[] = {
	/* path                                    desc                                      perm              handler */
	{"help",                                   "Show available commands",                 NULL,             cmd_help},
	{"exit",                                   "Logout from CLI",                         NULL,             cmd_exit},
	{"logout",                                 "Logout from CLI",                         NULL,             cmd_exit},

	{"show",                                   "Show system information",                 "monitor",        NULL},
	{"show status",                            "Module and system status",                "monitor",        cmd_show_status},
	{"show sessions",                          "Active session table",                    "monitor",        cmd_show_sessions},
	{"show stats",                             "Packet statistics",                       "monitor",        cmd_show_stats},
	{"show interfaces",                        "Network interfaces",                      "monitor",        cmd_show_interfaces},
	{"show routes",                            "Routing table",                           "monitor",        cmd_show_routes},
	{"show configure",                         "Running configuration (FortiGate-style)", "monitor",        cmd_show_configure},
	{"show config",                            "Current configuration",                   "monitor",        cmd_show_config},
	{"show firmware",                          "Firmware version and status",             "monitor",        cmd_show_firmware},

	{"configure",                              "Configure firewall",                      "configure,admin", cmd_configure},
	{"configure commit",                       "Save a configuration revision",           "configure",      NULL},
	{"configure revisions",                    "List configuration revisions",            "configure",      NULL},
	{"configure rollback",                     "Rollback configuration to revision",      "configure",      NULL},

	{"execute system",                         "System management commands",              "admin",          NULL},
	{"execute system shutdown",                "Shut down the system",                    "admin",          cmd_sys_shutdown},
	{"execute system reboot",                  "Reboot the system",                       "admin",          cmd_sys_reboot},

	{"execute firmware",                       "Firmware management",                     "admin",          NULL},
	{"execute firmware upgrade",               "Upgrade firmware from URL",               "admin",          cmd_fw_upgrade},

	{"execute ping",                           "Ping a host (ICMP echo request)",         "monitor",        cmd_ping},
	{"execute traceroute",                     "Trace route to a host",                   "monitor",        cmd_traceroute},
	{"execute nslookup",                       "DNS lookup for a host or IP",             "monitor",        cmd_nslookup},
	{"execute arping",                         "ARP ping a host on local network",        "monitor",        cmd_arping},

	{"execute debug",                          "Runtime debug control",                   "admin",          cmd_debug_status},
	{"execute debug enable",                   "Enable debug output",                     "admin",          cmd_debug_enable},
	{"execute debug disable",                  "Disable debug output",                    "admin",          cmd_debug_disable},
	{"execute debug reset",                    "Reset all debug options",                 "admin",          cmd_debug_reset},
	{"execute debug status",                   "Show debug status",                       "admin",          cmd_debug_status},
	{"execute debug option",                   "Set debug output options",                "admin",          cmd_debug_option},
	{"execute debug option timestamp",         "Print timestamp in debug logs",           "admin",          NULL},
	{"execute debug option actor",             "Print actor (user/system) in debug logs", "admin",          NULL},
	{"execute debug option function",          "Print function name in debug logs",       "admin",          NULL},
	{"execute debug option hierarchy",         "Print call hierarchy in debug logs",      "admin",          NULL},
	{"execute debug flow trace",               "Enable packet flow tracing",              "admin",          cmd_debug_flow},
	{"execute debug flow trace limit",         "Limit number of flow records",            "admin",          NULL},
	{"execute debug flow trace unlimited",     "No flow record limit",                    "admin",          NULL},
	{"execute debug cli",                      "Enable/disable CLI debug tracing",        "admin",          cmd_debug_cli},
	{"execute debug mgmtd",                    "Enable/disable mgmtd daemon debug tracing", "admin",       cmd_debug_mgmtd},
	{"execute debug auth",                     "Enable/disable auth debug tracing",       "admin",          cmd_debug_auth},
	{"execute debug auth admin",               "Debug admin authentication",              "admin",          NULL},
	{"execute debug auth user",                "Debug user authentication",               "admin",          NULL},

	{"execute diagnose",                       "Run diagnostic tools",                    "admin",          NULL},
	{"execute diagnose top",                   "Show process snapshot",                   "admin",          cmd_diag_top},
	{"execute diagnose resources",             "Show system resource usage",              "admin",          cmd_diag_resources},
	{"execute diagnose resources cpu",         "Show CPU usage and temperature",          "admin",          NULL},
	{"execute diagnose resources ram",         "Show RAM usage",                          "admin",          NULL},
	{"execute diagnose resources disk",        "Show disk usage",                         "admin",          NULL},
	{"execute diagnose resources interface",   "Show interface throughput",               "admin",          NULL},
	{"execute diagnose resources all",         "Show all resource metrics",               "admin",          NULL},
	{"execute diagnose test-permissions",      "Test IPC permission model",               "admin",          cmd_diag_test_perms},
	{"execute diagnose test-permissions full", "Full test with temp accounts",            "admin",          NULL},
	{"execute diagnose test-configure",        "Test config validation",                  "admin",          cmd_diag_test_cfg},
	{"execute diagnose test-configure full",   "Full test with IPC round-trip",           "admin",          NULL},

	{NULL, NULL, NULL, NULL}
};

/* ── Permission OR check ──────────────────────────────────────────────── */

/*
 * Check if user has any of the comma-separated permissions in 'required'.
 * E.g. required="configure,admin" matches if user has "configure" OR "admin".
 * NULL required = no permission needed (always allowed).
 */
static int cmd_check_perm(const char *user_perms, const char *required)
{
	if (!required)
		return 1;

	char buf[256];
	snprintf(buf, sizeof(buf), "%s", required);

	char *tok = buf;
	while (*tok) {
		char *comma = strchr(tok, ',');
		if (comma)
			*comma = '\0';
		if (has_permission(user_perms, tok))
			return 1;
		if (!comma)
			break;
		tok = comma + 1;
	}
	return 0;
}

/* ── Registration ─────────────────────────────────────────────────────── */

void cmd_register_all(const char *permissions)
{
	/* Register commands from the table */
	for (int i = 0; cmd_table[i].path; i++) {
		if (!cmd_check_perm(permissions, cmd_table[i].perm))
			continue;
		cli_register(cmd_table[i].path, cmd_table[i].desc);
	}

	/* Auto-register configure commands from config type registry */
	const sg_type_info_t *types = sg_reg_types();
	for (int i = 0; types[i].name; i++) {
		if (!has_permission(permissions, types[i].perm))
			continue;
		const char *label = sg_reg_type_label(types[i].name);
		char path[256];
		snprintf(path, sizeof(path), "configure %s", label);
		cli_register(path, types[i].desc);
	}
}

/* ── Dispatch ─────────────────────────────────────────────────────────── */

/*
 * Check if 'input' starts with 'prefix' at a word boundary.
 * The prefix must match completely, and the next char in input must be
 * space or end-of-string.
 */
static int starts_with_path(const char *input, const char *prefix)
{
	size_t plen = strlen(prefix);
	if (strncmp(input, prefix, plen) != 0)
		return 0;
	return input[plen] == '\0' || input[plen] == ' ';
}

int cmd_dispatch(const char *resolved, const char *permissions)
{
	if (!resolved)
		return 0;
	while (*resolved == ' ')
		resolved++;
	if (!*resolved)
		return 0;

	/* CLI debug trace */
	if (dbg_enabled() &&
	    strcmp(dbg_get("cli_debug", "0"), "1") == 0)
		fprintf(stderr, "[CLI-DBG] dispatch: %s\n", resolved);

	/* 1. Find longest matching handler */
	const cmd_entry_t *best = NULL;
	size_t best_len = 0;

	for (int i = 0; cmd_table[i].path; i++) {
		if (!cmd_table[i].handler)
			continue;
		size_t plen = strlen(cmd_table[i].path);
		if (plen <= best_len)
			continue;
		if (starts_with_path(resolved, cmd_table[i].path)) {
			best = &cmd_table[i];
			best_len = plen;
		}
	}

	/* 2. If found, permission check + call */
	if (best) {
		if (!cmd_check_perm(permissions, best->perm)) {
			printf("  Permission denied: requires '%s'\n",
			       best->perm);
			return 0;
		}

		const char *args = resolved + best_len;
		while (*args == ' ')
			args++;

		if (dbg_enabled() &&
		    strcmp(dbg_get("cli_debug", "0"), "1") == 0)
			fprintf(stderr, "[CLI-DBG] handler: %s args=\"%s\"\n",
				best->path, args);

		return best->handler(args, permissions);
	}

	/* 3. Auto-usage: resolved is a prefix of table entries */
	size_t rlen = strlen(resolved);
	int found_prefix = 0;

	/* Collect direct child subcommands (one level deeper) */
	const char *shown[CMD_MAX_SHOWN];
	int nshown = 0;

	for (int i = 0; cmd_table[i].path; i++) {
		const char *path = cmd_table[i].path;
		size_t plen = strlen(path);

		/* path must start with resolved + space */
		if (plen <= rlen)
			continue;
		if (strncmp(path, resolved, rlen) != 0)
			continue;
		if (path[rlen] != ' ')
			continue;
		if (!cmd_check_perm(permissions, cmd_table[i].perm))
			continue;

		/* Extract the next word after the prefix */
		const char *child = path + rlen + 1;
		const char *sp = strchr(child, ' ');
		size_t clen = sp ? (size_t)(sp - child) : strlen(child);

		/* Deduplicate */
		int dup = 0;
		for (int j = 0; j < nshown; j++) {
			if (strlen(shown[j]) == clen &&
			    strncmp(shown[j], child, clen) == 0) {
				dup = 1;
				break;
			}
		}
		if (dup)
			continue;

		if (!found_prefix) {
			printf("  Available subcommands:\n");
			found_prefix = 1;
		}

		/* Find the entry for exactly "resolved child" for its desc */
		char full[512];
		snprintf(full, sizeof(full), "%.*s", (int)(rlen + 1 + clen),
			 path);
		const char *desc = "";
		for (int k = 0; cmd_table[k].path; k++) {
			if (strcmp(cmd_table[k].path, full) == 0) {
				desc = cmd_table[k].desc;
				break;
			}
		}

		printf("    %-20.*s %s\n", (int)clen, child, desc);

		if (nshown < CMD_MAX_SHOWN - 1)
			shown[nshown++] = child;
	}

	if (found_prefix)
		return 0;

	/* 4. Truly unknown */
	printf("  Unknown command: %s\n", resolved);
	printf("  Type 'help' or '?' for available commands.\n");
	return 0;
}
