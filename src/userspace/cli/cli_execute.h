/* SPDX-License-Identifier: MIT */
/*
 * cli_execute.h — Execute command dispatcher for Stargazer CLI
 */

#ifndef CLI_EXECUTE_H
#define CLI_EXECUTE_H

/* Dispatch "execute <args>" — routes to debug and other handlers. */
void cli_execute(const char *args, const char *permissions);

#endif /* CLI_EXECUTE_H */
