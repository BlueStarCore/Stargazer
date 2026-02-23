/* SPDX-License-Identifier: MIT */
/*
 * cli_debug.h — Debug state manager for Stargazer CLI
 *
 * Manages /tmp/stargazer-debug.conf key=value state file.
 */

#ifndef CLI_DEBUG_H
#define CLI_DEBUG_H

/* Debug state I/O */
const char *dbg_get(const char *key, const char *defval);
void dbg_set(const char *key, const char *val);
void dbg_reset(void);
int  dbg_enabled(void);

/* Debug command handlers (table-driven dispatch) */
int cmd_debug_enable(const char *args, const char *permissions);
int cmd_debug_disable(const char *args, const char *permissions);
int cmd_debug_reset(const char *args, const char *permissions);
int cmd_debug_status(const char *args, const char *permissions);
int cmd_debug_option(const char *args, const char *permissions);
int cmd_debug_cli(const char *args, const char *permissions);
int cmd_debug_mgmtd(const char *args, const char *permissions);
int cmd_debug_auth(const char *args, const char *permissions);
int cmd_debug_flow(const char *args, const char *permissions);

#endif /* CLI_DEBUG_H */
