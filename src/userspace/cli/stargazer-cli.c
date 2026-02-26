/* SPDX-License-Identifier: MIT */
/*
 * stargazer-cli.c — Main entry point for Stargazer NGFW CLI
 * Zero forks in the interactive loop (readline + dispatch are in-process).
 * Only low-level system queries (ip, dmesg, etc.) fork external binaries.
 *
 * Build: aarch64-linux-musl-gcc -static -DVERSION=\"x.y.z\" ...
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_readline.h"
#include "cli_ipc.h"
#include "cli_cmd_table.h"
#include "cli_debug.h"

#include <signal.h>
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

	/*
	 * Ignore SIGINT globally.  In raw mode, Ctrl+C is handled as byte
	 * 0x03 by readline.  During streaming/polling, cli_ipc polls the
	 * tty directly for 0x03 — no signal needed.  SIG_IGN prevents an
	 * accidental kill if a stray SIGINT is delivered.
	 */
	signal(SIGINT, SIG_IGN);

	/* Tell the IPC layer which fd to poll for Ctrl+C during streaming */
	ipc_set_interrupt_fd(cli_get_tty_fd());

	/* 4. Register commands based on permissions */
	cmd_register_all(permissions);

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

		/* Resolve abbreviated commands */
		char resolved[CLI_MAX_LINE];
		if (cli_resolve_cmd(trimmed, resolved,
				    sizeof(resolved)) != 0)
			continue;

		if (dbg_enabled() &&
		    strcmp(dbg_get("cli_debug", "0"), "1") == 0 &&
		    strcmp(trimmed, resolved) != 0)
			fprintf(stderr,
				"[CLI-DBG] resolve: \"%s\""
				" -> \"%s\"\n", trimmed, resolved);

		/* Session check — detect external account/profile changes */
		session_rev_cached = get_session_rev(user);
		if (session_rev_cached != session_rev_start) {
			if (dbg_enabled() &&
			    strcmp(dbg_get("cli_debug", "0"), "1") == 0)
				fprintf(stderr,
					"[CLI-DBG] session expired:"
					" rev %d -> %d\n",
					session_rev_start,
					session_rev_cached);
			printf("  Session expired due to account/profile change.\n");
			printf("  Please login again.\n");
			break;
		}

		/* Dispatch */
		int rc = cmd_dispatch(resolved, permissions);

		/* Fetch mgmtd/auth debug traces after each command */
		ipc_fetch_debug();

		if (dbg_enabled() &&
		    strcmp(dbg_get("cli_debug", "0"), "1") == 0)
			fprintf(stderr,
				"[CLI-DBG] dispatch rc=%d\n", rc);

		/* Refresh session baseline after commands that modify config */
		if (strncmp(resolved, "configure", 9) == 0 ||
		    strncmp(resolved, "execute", 7) == 0) {
			session_rev_start = get_session_rev(user);
		}

		if (rc != 0)
			break;
	}

	/* 9. Cleanup */
	cli_hist_save(hist_path);
	cli_term_cleanup();
	return 0;
}
