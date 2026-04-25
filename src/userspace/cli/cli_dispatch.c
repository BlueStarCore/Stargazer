/* SPDX-License-Identifier: MIT */
/*
 * cli_dispatch.c — Permission check utility for Stargazer CLI
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_dispatch.h"

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
