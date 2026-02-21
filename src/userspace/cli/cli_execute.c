/* SPDX-License-Identifier: MIT */
/*
 * cli_execute.c — Execute command dispatcher for Stargazer CLI
 *
 * Thin router: the heavy logic is in cli_debug.c.
 * "execute system" and "execute diagnose" are handled in cli_dispatch.c
 * before reaching here. This handles the remaining "execute debug *".
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_execute.h"
#include "cli_debug.h"

#include <stdio.h>
#include <string.h>

void cli_execute(const char *args, const char *permissions)
{
	(void)permissions; /* admin already checked by caller */

	if (!args || !*args) {
		printf("  Usage: execute debug ...\n");
		return;
	}

	/* Skip leading whitespace */
	while (*args == ' ')
		args++;

	/* Route "debug ..." to cli_debug_dispatch */
	if (strncmp(args, "debug", 5) == 0 &&
	    (args[5] == ' ' || args[5] == '\0')) {
		const char *sub = args + 5;
		while (*sub == ' ')
			sub++;
		cli_debug_dispatch(sub);
		return;
	}

	printf("  Usage: execute debug ...\n");
}
