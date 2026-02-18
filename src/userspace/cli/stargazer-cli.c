/* SPDX-License-Identifier: MIT */
/*
 * stargazer-cli.c — Main entry point for Stargazer NGFW CLI
 *
 * Replaces the shell-based stargazer-cli with a C binary.
 * Zero forks in the interactive loop (readline + dispatch are in-process).
 * Non-interactive command handlers (show, execute, system) are still
 * shell scripts called via fork+exec.
 *
 * Build: aarch64-linux-musl-gcc -static -DVERSION=\"x.y.z\" ...
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_readline.h"
#include "cli_ipc.h"
#include "cli_dispatch.h"
#include "cli_configure.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef VERSION
#define VERSION "dev"
#endif

/* ── Parse WHOAMI response ─────────────────────────────────────────────── */

static void parse_whoami(const char *payload,
			 char *profile, size_t prof_sz,
			 char *perms, size_t perms_sz)
{
	const char *p = payload;

	while (p && *p) {
		const char *eol = strchr(p, '\n');
		size_t llen = eol ? (size_t)(eol - p) : strlen(p);

		if (llen > 8 && strncmp(p, "profile=", 8) == 0) {
			size_t vlen = llen - 8;
			if (vlen >= prof_sz)
				vlen = prof_sz - 1;
			memcpy(profile, p + 8, vlen);
			profile[vlen] = '\0';
		} else if (llen > 12 && strncmp(p, "permissions=", 12) == 0) {
			size_t vlen = llen - 12;
			if (vlen >= perms_sz)
				vlen = perms_sz - 1;
			memcpy(perms, p + 12, vlen);
			perms[vlen] = '\0';
		}

		if (!eol)
			break;
		p = eol + 1;
	}
}

/* ── Get session revision via IPC ──────────────────────────────────────── */

static int get_session_rev(const char *user)
{
	struct ipc_response resp;
	int rev = 0;

	if (ipc_send_str(SG_CMD_SESSION_REV, user, &resp) == 0 &&
	    resp.status == SG_OK && resp.payload) {
		rev = atoi(resp.payload);
	}
	ipc_resp_free(&resp);
	return rev;
}

/* ── Main ──────────────────────────────────────────────────────────────── */

int main(void)
{
	/* 1. Resolve user identity from environment */
	const char *user = getenv("STARGAZER_USER");
	if (!user)
		user = getenv("LOGNAME");
	if (!user)
		user = getenv("USER");
	if (!user)
		user = "unknown";

	/* 2. Get profile and permissions via IPC (opcode 620: WHOAMI) */
	char profile[128]    = "read-only";
	char permissions[256] = "monitor";

	if (ipc_init(user) == 0 && ipc_available()) {
		struct ipc_response resp;
		if (ipc_send_str(SG_CMD_WHOAMI, "", &resp) == 0 &&
		    resp.status == SG_OK && resp.payload) {
			parse_whoami(resp.payload, profile, sizeof(profile),
				     permissions, sizeof(permissions));
		}
		ipc_resp_free(&resp);
	}

	/* Export for shell subcommands */
	setenv("STARGAZER_PROFILE", profile, 1);
	setenv("STARGAZER_PERMISSIONS", permissions, 1);
	setenv("STARGAZER_USER", user, 1);

	/* 3. Initialize terminal and readline */
	if (cli_term_init() < 0) {
		fprintf(stderr, "Error: cannot open terminal\n");
		return 1;
	}

	/* 4. Register commands based on permissions */
	register_commands(permissions);

	/* 5. Load history */
	char hist_path[256];
	snprintf(hist_path, sizeof(hist_path),
		 "/tmp/stargazer_cli_history_%ld", (long)getuid());
	cli_hist_load(hist_path);

	/* 6. Print banner */
	printf("\n  Stargazer NGFW %s\n", VERSION);
	printf("  User: %s | Profile: %s | Perms: %s\n",
	       user, profile, permissions);
	printf("  Type 'help' or '?' for available commands.\n\n");

	/* 7. Session tracking */
	int session_rev_start = get_session_rev(user);
	int session_rev_cached = session_rev_start;
	int cmd_count = 0;
	int force_session_check = 0;

	/* 8. Main loop */
	const char *line;
	while ((line = cli_readline("stargazer> ")) != NULL) {
		/* Trim leading whitespace */
		while (*line == ' ' || *line == '\t')
			line++;
		/* Find end and check for trailing whitespace */
		size_t len = strlen(line);
		char trimmed[CLI_MAX_LINE];
		if (len >= sizeof(trimmed))
			len = sizeof(trimmed) - 1;
		memcpy(trimmed, line, len);
		trimmed[len] = '\0';
		/* Trim trailing */
		while (len > 0 && (trimmed[len - 1] == ' ' ||
				   trimmed[len - 1] == '\t'))
			trimmed[--len] = '\0';

		if (len == 0)
			continue;

		/* Session check (every command) */
		cmd_count++;
		if (cmd_count >= 1 || force_session_check) {
			cmd_count = 0;
			force_session_check = 0;
			session_rev_cached = get_session_rev(user);
			if (session_rev_cached != session_rev_start) {
				printf("  Session expired due to account/profile change.\n");
				printf("  Please login again.\n");
				break;
			}
		}

		/* Extract command and args (zero forks) */
		char cmd[CLI_MAX_LINE];
		const char *args = "";
		const char *sp = strchr(trimmed, ' ');
		if (sp) {
			size_t clen = (size_t)(sp - trimmed);
			if (clen >= sizeof(cmd))
				clen = sizeof(cmd) - 1;
			memcpy(cmd, trimmed, clen);
			cmd[clen] = '\0';
			args = sp + 1;
			while (*args == ' ')
				args++;
		} else {
			snprintf(cmd, sizeof(cmd), "%s", trimmed);
		}

		/* Dispatch */
		int rc = dispatch_command(cmd, args, permissions);

		/* Force session recheck after configure or execute */
		if (strcmp(cmd, "configure") == 0 ||
		    strcmp(cmd, "execute") == 0)
			force_session_check = 1;

		if (rc != 0)
			break;
	}

	/* 9. Cleanup */
	cli_hist_save(hist_path);
	cli_term_cleanup();
	return 0;
}
