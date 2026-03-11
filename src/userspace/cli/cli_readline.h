/* SPDX-License-Identifier: MIT */
/*
 * cli_readline.h — Embedded readline engine for Stargazer CLI
 *
 * Provides interactive line editing with Tab completion, ? help, history,
 * arrow keys, and UTF-8 support. Zero forks per keystroke.
 *
 * Completion registry supports push/pop for nested CLI contexts.
 */

#ifndef CLI_READLINE_H
#define CLI_READLINE_H

#include <stddef.h>

#define CLI_MAX_LINE   512
#define CLI_MAX_COMPS  128
#define CLI_MAX_HIST   100
#define CLI_MAX_DESC   128
#define CLI_MAX_STACK  8

/* Initialize terminal I/O (opens /dev/tty). Returns 0 on success. */
int cli_term_init(void);

/* Restore terminal and close fds. */
void cli_term_cleanup(void);

/* Register a completion entry for the current context. */
void cli_register(const char *path, const char *desc);

/* Save current completion set and start fresh (for sub-contexts). */
void cli_push(void);

/* Restore previous completion set. */
void cli_pop(void);

/* Clear all completions in the current context. */
void cli_clear(void);

/* Print all registered commands and descriptions. */
void cli_print_help(void);

/*
 * Read one line interactively with prompt, Tab completion, ? help.
 * Returns pointer to internal buffer (valid until next call), or NULL on EOF.
 * Buffer is null-terminated, no trailing newline.
 */
const char *cli_readline(const char *prompt);

/*
 * Resolve abbreviated commands against the completion registry.
 * Returns 0 on success (output filled), -1 on ambiguity (error printed).
 */
int cli_resolve_cmd(const char *input, char *output, size_t out_sz);

/* Return the terminal fd used by readline (-1 if not initialized). */
int cli_get_tty_fd(void);

/*
 * Idle callback — called every ~5 seconds while waiting for input.
 * Return 0 to keep waiting, non-zero to abort readline (returns NULL).
 */
typedef int (*cli_idle_cb_t)(void);
void cli_set_idle_cb(cli_idle_cb_t cb);

/* History via IPC (works inside sandbox). */
void cli_hist_load_ipc(void);
void cli_hist_save_ipc(const char *username);

#endif /* CLI_READLINE_H */
