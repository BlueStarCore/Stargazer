/* SPDX-License-Identifier: MIT */
/*
 * cli_dispatch.c — Command registration and dispatch for Stargazer CLI
 *
 * Registers readline completions based on permissions, then dispatches
 * parsed commands to C handlers.  All commands are now pure C — no
 * shell script forks.
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_dispatch.h"
#include "cli_readline.h"
#include "cli_configure.h"
#include "cli_diagnose.h"
#include "cli_show.h"
#include "cli_execute.h"
#include "cli_ipc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Permission check (zero-fork) ──────────────────────────────────────── */

int has_permission(const char *permissions, const char *perm)
{
	/*
	 * Check if perm appears as a complete token in the comma-separated
	 * permissions string.  E.g. "monitor,configure,admin" contains
	 * "configure" but not "config".
	 */
	if (!permissions || !perm)
		return 0;

	size_t plen = strlen(perm);
	const char *p = permissions;

	while (*p) {
		if (strncmp(p, perm, plen) == 0 &&
		    (p[plen] == ',' || p[plen] == '\0'))
			return 1;
		/* Skip to next comma */
		while (*p && *p != ',')
			p++;
		if (*p == ',')
			p++;
	}
	return 0;
}

/* ── Command registration ──────────────────────────────────────────────── */

void register_commands(const char *permissions)
{
	cli_register("help",   "Show available commands");
	cli_register("exit",   "Logout from CLI");
	cli_register("logout", "Logout from CLI");

	if (has_permission(permissions, "admin")) {
		cli_register("execute system",           "System management commands");
		cli_register("execute system shutdown",  "Shut down the system");
		cli_register("execute system reboot",    "Reboot the system");
		cli_register("execute debug",                  "Runtime debug control");
		cli_register("execute debug enable",           "Enable debug output");
		cli_register("execute debug disable",          "Disable debug output");
		cli_register("execute debug reset",            "Reset all debug options");
		cli_register("execute debug status",           "Show debug status");
		cli_register("execute debug option",           "Set debug output options");
		cli_register("execute debug option timestamp", "Print timestamp in debug logs");
		cli_register("execute debug option actor",     "Print actor (user/system) in debug logs");
		cli_register("execute debug option function",  "Print function name in debug logs");
		cli_register("execute debug option hierarchy", "Print call hierarchy in debug logs");
		cli_register("execute debug flow trace",       "Enable packet flow tracing");
		cli_register("execute debug flow trace limit", "Limit number of flow records");
		cli_register("execute debug flow trace unlimited", "No flow record limit");
		cli_register("execute debug cli",              "Enable/disable CLI debug tracing");
		cli_register("execute debug mgmtd",            "Enable/disable mgmtd daemon debug tracing");
		cli_register("execute debug auth",             "Enable/disable auth debug tracing");
		cli_register("execute debug auth admin",       "Debug admin authentication");
		cli_register("execute debug auth user",        "Debug user authentication");
		cli_register("execute debug top",              "Show process snapshot like top");
		cli_register("execute debug resources",        "Show system resource usage");
		cli_register("execute debug resources cpu",    "Show CPU usage and temperature");
		cli_register("execute debug resources ram",    "Show RAM usage");
		cli_register("execute debug resources disk",   "Show disk usage");
		cli_register("execute debug resources interface", "Show interface throughput");
		cli_register("execute debug resources all",    "Show all resource metrics");
		cli_register("execute diagnose",                       "Run diagnostic tools");
		cli_register("execute diagnose test-permissions",      "Test IPC permission model");
		cli_register("execute diagnose test-permissions full", "Full test with temp accounts");
		cli_register("execute diagnose test-configure",       "Test config validation");
		cli_register("execute diagnose test-configure full",  "Full test with IPC round-trip");
	}

	if (has_permission(permissions, "monitor")) {
		cli_register("show status",     "Module and system status");
		cli_register("show sessions",   "Active session table");
		cli_register("show stats",      "Packet statistics");
		cli_register("show interfaces", "Network interfaces");
		cli_register("show routes",     "Routing table");
		cli_register("show configure",  "Running configuration (FortiGate-style)");
		cli_register("show config",     "Current configuration");
	}

	if (has_permission(permissions, "configure")) {
		cli_register("configure",                      "Configure firewall");
		cli_register("configure commit",               "Save a configuration revision");
		cli_register("configure revisions",            "List configuration revisions");
		cli_register("configure rollback",             "Rollback configuration to revision");
		cli_register("configure network route static", "Configure static routes");
		cli_register("configure network route policy", "Configure policy-based routing");
		cli_register("configure network ospf",         "Configure OSPF dynamic routing");
		cli_register("configure network rip",          "Configure RIP dynamic routing");
		cli_register("configure network bgp",          "Configure BGP dynamic routing");
		cli_register("configure network nat",          "Configure NAT rules (SNAT/DNAT)");
		cli_register("configure network dns",          "Configure DNS settings");
		cli_register("configure system settings",      "System general settings");
		cli_register("configure system interface",     "Configure network interfaces");
		cli_register("configure system hostname",      "Set system hostname");
		cli_register("configure system ntp",           "Configure NTP time sync");
		cli_register("configure firewall policy",      "Configure firewall policies");
		cli_register("configure firewall address",     "Configure address objects");
		cli_register("configure firewall service",     "Configure service objects");
	}

	if (has_permission(permissions, "admin")) {
		cli_register("configure system password-policy", "Configure global password policy");
		cli_register("configure system admin-profile",   "Configure admin permission profiles");
		cli_register("configure system admin",           "Configure admin accounts");
	}
}

/* ── Command dispatch ──────────────────────────────────────────────────── */

int dispatch_command(const char *cmd, const char *args,
		     const char *permissions)
{
	if (strcmp(cmd, "help") == 0) {
		cli_print_help();
		return 0;
	}

	if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "logout") == 0) {
		printf("  Goodbye.\n");
		return 1;
	}

	if (strcmp(cmd, "show") == 0) {
		if (!has_permission(permissions, "monitor")) {
			printf("  Permission denied: requires 'monitor'\n");
			return 0;
		}
		cli_show(args);
		return 0;
	}

	if (strcmp(cmd, "configure") == 0) {
		if (has_permission(permissions, "configure") ||
		    has_permission(permissions, "admin")) {
			/* Parse args into argv array for C configure */
			const char *argv[32];
			int argc = 0;
			char args_copy[CLI_MAX_LINE];

			if (args && args[0]) {
				snprintf(args_copy, sizeof(args_copy), "%s", args);
				char *tok = args_copy;
				while (*tok && argc < 31) {
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
		} else {
			printf("  Permission denied: requires 'configure' or 'admin'\n");
		}
		return 0;
	}

	if (strcmp(cmd, "execute") == 0) {
		if (!has_permission(permissions, "admin")) {
			printf("  Permission denied: requires 'admin'\n");
			return 0;
		}
		/* Handle "execute system shutdown|reboot" via IPC */
		if (args && strncmp(args, "system", 6) == 0 &&
		    (args[6] == ' ' || args[6] == '\0')) {
			const char *subcmd = args + 6;
			while (*subcmd == ' ')
				subcmd++;
			if (strcmp(subcmd, "shutdown") == 0) {
				struct ipc_response resp;
				printf("  System shutting down...\n");
				ipc_send_str(SG_CMD_SYS_POWEROFF, "", &resp);
				ipc_resp_free(&resp);
			} else if (strcmp(subcmd, "reboot") == 0) {
				struct ipc_response resp;
				printf("  System rebooting...\n");
				ipc_send_str(SG_CMD_SYS_REBOOT, "", &resp);
				ipc_resp_free(&resp);
			} else if (*subcmd == '\0') {
				printf("  Usage: execute system shutdown|reboot\n");
			} else {
				printf("  Unknown system command: %s\n", subcmd);
				printf("  Usage: execute system shutdown|reboot\n");
			}
			return 0;
		}
		/* Handle "execute diagnose ..." in C */
		if (args && strncmp(args, "diagnose", 8) == 0 &&
		    (args[8] == ' ' || args[8] == '\0')) {
			const char *dsub = args + 8;
			while (*dsub == ' ')
				dsub++;
			if (strncmp(dsub, "test-permissions", 16) == 0 &&
			    (dsub[16] == ' ' || dsub[16] == '\0')) {
				int mode = 0;
				const char *rest = dsub + 16;
				while (*rest == ' ')
					rest++;
				if (*rest == '\0') {
					mode = 0;
				} else if (strcmp(rest, "full") == 0) {
					mode = 1;
				} else {
					printf("  Unknown argument: %s\n",
					       rest);
					printf("  Usage: execute diagnose"
					       " test-permissions [full]\n");
					return 0;
				}
				cli_diagnose_test_permissions(mode,
							     permissions);
			} else if (strncmp(dsub, "test-configure", 14) == 0 &&
				   (dsub[14] == ' ' || dsub[14] == '\0')) {
				int mode = 0;
				const char *rest = dsub + 14;
				while (*rest == ' ')
					rest++;
				if (*rest == '\0') {
					mode = 0;
				} else if (strcmp(rest, "full") == 0) {
					mode = 1;
				} else {
					printf("  Unknown argument: %s\n",
					       rest);
					printf("  Usage: execute diagnose"
					       " test-configure [full]\n");
					return 0;
				}
				cli_diagnose_test_configure(mode);
			} else if (*dsub == '\0') {
				printf("  Usage: execute diagnose"
				       " test-permissions|test-configure"
				       " [full]\n");
			} else {
				printf("  Unknown diagnose command: %s\n",
				       dsub);
				printf("  Usage: execute diagnose"
				       " test-permissions|test-configure"
				       " [full]\n");
			}
			return 0;
		}
		/* All other execute subcommands (debug, etc.) */
		cli_execute(args, permissions);
		return 0;
	}

	printf("  Unknown command: %s\n", cmd);
	printf("  Type 'help' or '?' for available commands.\n");
	return 0;
}
