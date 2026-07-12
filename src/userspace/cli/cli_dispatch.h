/* SPDX-License-Identifier: MIT */
/*
 * cli_dispatch.h — Permission check utility for Stargazer CLI
 */

#ifndef CLI_DISPATCH_H
#define CLI_DISPATCH_H

/* Permission check: returns 1 if perm is in the comma-separated permissions. */
int has_permission(const char *permissions, const char *perm);

#endif /* CLI_DISPATCH_H */
