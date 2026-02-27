/* SPDX-License-Identifier: MIT */
/*
 * cli_cmd_table.h — Table-driven command registry for Stargazer CLI
 *
 * Single declarative table drives registration, dispatch, and auto-usage
 * for all CLI commands. Replaces the scattered routing across cli_dispatch,
 * cli_execute, cli_show, and cli_debug.
 */

#ifndef CLI_CMD_TABLE_H
#define CLI_CMD_TABLE_H

typedef int (*cmd_handler_t)(const char *args, const char *permissions);

typedef struct {
	const char    *path;    /* "execute debug enable" */
	const char    *desc;    /* "Enable debug output" */
	const char    *perm;    /* "admin", "configure,admin" (OR), or NULL */
	int            max_args;/* 0=none, N=at most N, -1=variadic */
	cmd_handler_t  handler; /* leaf handler, or NULL = completion-only */
} cmd_entry_t;

/* Register all commands (table + config registry) for tab-completion. */
void cmd_register_all(const char *permissions);

/* Dispatch a resolved command line. Returns 0 to continue, 1 to exit. */
int cmd_dispatch(const char *resolved, const char *permissions);

#endif /* CLI_CMD_TABLE_H */
