/* SPDX-License-Identifier: MIT */
/*
 * cli_show.h — Show command implementations for Stargazer CLI
 */

#ifndef CLI_SHOW_H
#define CLI_SHOW_H

/* Dispatch "show <subcmd>" — replaces cmd_show shell script. */
void cli_show(const char *subcmd);

#endif /* CLI_SHOW_H */
