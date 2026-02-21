/* SPDX-License-Identifier: MIT */
/*
 * cli_configure.h — Interactive configuration contexts for Stargazer CLI
 */

#ifndef CLI_CONFIGURE_H
#define CLI_CONFIGURE_H

/* Entry point: parse args and dispatch to context_table or context_single.
 * argc/argv are the arguments after "configure" (e.g. "system admin"). */
int cli_configure(int argc, const char **argv);

#endif /* CLI_CONFIGURE_H */
