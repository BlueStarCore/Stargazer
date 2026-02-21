/* SPDX-License-Identifier: MIT */
/*
 * cli_debug.h — Debug state manager for Stargazer CLI
 *
 * Replaces the debug portion of cmd_execute shell script.
 * Manages /tmp/stargazer-debug.conf key=value state file.
 */

#ifndef CLI_DEBUG_H
#define CLI_DEBUG_H

/* Debug state I/O */
const char *dbg_get(const char *key, const char *defval);
void dbg_set(const char *key, const char *val);
void dbg_reset(void);
int  dbg_enabled(void);

/* Debug subcommand dispatch: "execute debug <args>" */
void cli_debug_dispatch(const char *args);

/* Resource monitoring subcommands */
void dbg_show_cpu(void);
void dbg_show_ram(void);
void dbg_show_disk(void);
void dbg_show_interface(void);
void dbg_show_resources(const char *which);

/* Top/process snapshot */
void dbg_show_top(void);

#endif /* CLI_DEBUG_H */
