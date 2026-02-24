/* SPDX-License-Identifier: MIT */
/*
 * cli_cmd_table.c — Table-driven command registry for Stargazer CLI
 *
 * Single declarative table drives registration, dispatch, and auto-usage
 * for all CLI commands.
 */

#define _POSIX_C_SOURCE 200809L

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
#include <string.h>

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

	{"configure",                              "Configure firewall",                      "configure,admin", cmd_configure},
	{"configure commit",                       "Save a configuration revision",           "configure",      NULL},
	{"configure revisions",                    "List configuration revisions",            "configure",      NULL},
	{"configure rollback",                     "Rollback configuration to revision",      "configure",      NULL},

	{"execute system",                         "System management commands",              "admin",          NULL},
	{"execute system shutdown",                "Shut down the system",                    "admin",          cmd_sys_shutdown},
	{"execute system reboot",                  "Reboot the system",                       "admin",          cmd_sys_reboot},

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
