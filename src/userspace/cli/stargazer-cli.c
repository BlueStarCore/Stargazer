/* SPDX-License-Identifier: MIT */
/*
 * stargazer-cli.c — Main entry point for Stargazer NGFW CLI
 * Zero forks in the interactive loop (readline + dispatch are in-process).
 * Only low-level system queries (ip, dmesg, etc.) fork external binaries.
 *
 * Build: aarch64-linux-musl-gcc -static -DVERSION=\"x.y.z\" ...
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "cli_readline.h"
#include "cli_ipc.h"
#include "cli_cmd_table.h"
#include "cli_debug.h"
#include "cli_sandbox.h"

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

/* ── Idle permission check ─────────────────────────────────────────────── */

static char *g_permissions = NULL;

static int check_permissions_cb(void)
{
	if (!g_permissions)
		return 0;

	/* PING is tag-validated: if the tag was purged (admin mutation),
	 * mgmtd returns SG_ERR_SESSION_EXPIRED and we kick the user. */
	struct ipc_response ping_resp;
	if (ipc_send_str(SG_CMD_PING, "", &ping_resp) == 0 &&
	    ping_resp.status == SG_ERR_SESSION_EXPIRED) {
		ipc_resp_free(&ping_resp);
		printf("\r\n  Session expired due to account/profile change.\r\n"
		       "  Please login again.\r\n");
		return -1;
	}
	ipc_resp_free(&ping_resp);

	/* Check permissions — catches profile permission edits.
	 * WHOAMI is tag-exempt so it always works. */
	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_WHOAMI, "", &resp) != 0) {
		ipc_resp_free(&resp);
		return 0;  /* mgmtd unreachable — don't kick */
	}
	if (resp.status != SG_OK) {
		ipc_resp_free(&resp);
		return -1;  /* user no longer valid */
	}

	char new_perms[256]   = "monitor";
	char new_profile[128] = "read-only";
	if (resp.payload)
		parse_whoami(resp.payload, new_profile, sizeof(new_profile),
			     new_perms, sizeof(new_perms));
	ipc_resp_free(&resp);

	if (strcmp(g_permissions, new_perms) != 0) {
		printf("\r\n  Permissions changed (was: %s, now: %s).\r\n"
		       "  Please login again.\r\n",
		       g_permissions, new_perms);
		return -1;
	}
	return 0;
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

	/* 2. Initialize IPC client */
	ipc_init(user);

	/* 3. Initialize terminal (opens /dev/tty — last file open) */
	if (cli_term_init() < 0) {
		fprintf(stderr, "Error: cannot open terminal\n");
		return 1;
	}

	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);  /* let readline see EOF instead of dying */
	ipc_set_interrupt_fd(cli_get_tty_fd());

	/* 4. SANDBOX — all file opens done, lock down the process.
	 * After this point: no open(), fork(), exec(), or network.
	 * Only pre-opened fds and AF_UNIX IPC to mgmtd. */
	if (cli_sandbox_install() != 0) {
		fprintf(stderr, "Error: sandbox installation failed — refusing to run\n");
		cli_term_cleanup();
		return 1;
	}

	/* ── Everything below runs inside the sandbox ────────────── */

	/* 5. Get profile and permissions via IPC (WHOAMI) */
	char profile[128]    = "read-only";
	char permissions[256] = "monitor";
	for (int attempt = 0; attempt < 5; attempt++) {
		struct ipc_response resp;
		if (ipc_send_str(SG_CMD_WHOAMI, "", &resp) == 0 &&
		    resp.status == SG_OK && resp.payload) {
			parse_whoami(resp.payload, profile,
				     sizeof(profile),
				     permissions,
				     sizeof(permissions));
			ipc_resp_free(&resp);
			break;
		}
		ipc_resp_free(&resp);
		usleep(200000);
	}

	setenv("STARGAZER_PROFILE", profile, 1);
	setenv("STARGAZER_PERMISSIONS", permissions, 1);
	setenv("STARGAZER_USER", user, 1);

	/* 6. Register commands based on permissions */
	cmd_register_all(permissions);

	/* 7. Load history via IPC (inside sandbox) */
	cli_hist_load_ipc();

	/* 8. Print banner */
	printf("\n  Stargazer NGFW %s\n", VERSION);
	printf("  User: %s | Profile: %s | Perms: %s\n",
	       user, profile, permissions);
	printf("  Type 'help' or '?' for available commands.\n\n");

	/* 9. Acquire session tag from mgmtd */
	{
		struct ipc_response tresp;
		uint64_t tag = 0;
		if (ipc_send_str(SG_CMD_SESSION_TAG_NEW, "", &tresp) == 0 &&
		    tresp.status == SG_OK && tresp.payload) {
			tag = strtoull(tresp.payload, NULL, 10);
		}
		ipc_resp_free(&tresp);
		if (tag == 0) {
			fprintf(stderr, "Error: failed to acquire session\n");
			cli_term_cleanup();
			return 1;
		}
		ipc_set_session_tag(tag);
		/* Clear any stale expired flag from pre-tag IPC calls
		 * (e.g. HISTORY_LOAD runs before tag acquisition). */
		ipc_clear_session_expired();
	}

	/* 10. Idle permission polling — detects profile changes while idle */
	g_permissions = permissions;
	cli_set_idle_cb(check_permissions_cb);

	/* 11. Main loop */
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

		/* Dispatch */
		int rc = cmd_dispatch(resolved, permissions);

		/* Check if session was expired by mgmtd during dispatch */
		if (ipc_session_expired()) {
			printf("  Session expired due to account/profile change.\n");
			printf("  Please login again.\n");
			break;
		}

		/* Fetch mgmtd/auth debug traces after each command */
		ipc_fetch_debug();

		if (dbg_enabled() &&
		    strcmp(dbg_get("cli_debug", "0"), "1") == 0)
			fprintf(stderr,
				"[CLI-DBG] dispatch rc=%d\n", rc);

		if (rc != 0)
			break;
	}

	/* 12. Release session tag (graceful logout) */
	{
		struct ipc_response lr;
		memset(&lr, 0, sizeof(lr));
		ipc_send_str(SG_CMD_SESSION_TAG_DEL, "", &lr);
		ipc_resp_free(&lr);
	}

	/* 13. Cleanup — save history via IPC (works inside sandbox) */
	cli_hist_save_ipc(user);
	cli_term_cleanup();
	return 0;
}
