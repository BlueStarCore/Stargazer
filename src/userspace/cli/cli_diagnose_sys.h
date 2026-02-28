/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose_sys.h — System diagnostics for Stargazer CLI
 *
 * Pure C resource monitoring (zero-fork). Replaces the shell-based
 * resource functions that previously lived in cli_debug.c.
 */

#ifndef CLI_DIAGNOSE_SYS_H
#define CLI_DIAGNOSE_SYS_H

/* Individual resource monitors */
void diag_show_cpu(void);
void diag_show_ram(void);
void diag_show_disk(void);
void diag_show_interface(void);

/* Live process monitor (like top). interval=seconds, max_procs=display limit. */
void diag_show_top(int interval, int max_procs);

/* Dispatcher: cpu|ram|disk|interface|all */
void diag_show_resources(const char *which);

#endif /* CLI_DIAGNOSE_SYS_H */
