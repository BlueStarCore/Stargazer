/* SPDX-License-Identifier: MIT */
/*
 * cli_dispatch.h — Command registration and dispatch for Stargazer CLI
 */

#ifndef CLI_DISPATCH_H
#define CLI_DISPATCH_H

/* Permission check: returns 1 if perm is in the comma-separated permissions. */
int has_permission(const char *permissions, const char *perm);

/* Register readline completions based on user permissions. */
void register_commands(const char *permissions);

/* Dispatch a parsed command. Returns 0 to continue, 1 to exit. */
int dispatch_command(const char *cmd, const char *args,
		     const char *permissions);

#endif /* CLI_DISPATCH_H */
