/* SPDX-License-Identifier: MIT */
/*
 * cli_sandbox.h — seccomp-bpf + capability sandbox for Stargazer CLI
 *
 * After cli_sandbox_install(), the CLI can only:
 *   - Read/write on pre-opened fds (terminal, IPC socket)
 *   - Open AF_UNIX sockets (for IPC to mgmtd)
 *   - Terminal ioctls (TIOCGWINSZ, TCGETS/TCSETS*)
 *   - Memory management (mmap, brk, etc.)
 *   - Signal handling, timing, identity queries
 *
 * Everything else (openat, execve, fork, etc.) is killed at the kernel level.
 */

#ifndef CLI_SANDBOX_H
#define CLI_SANDBOX_H

/*
 * Install the sandbox. Must be called after all file opens are complete
 * (history loaded, terminal initialized, etc.) but before the main loop.
 *
 * Returns 0 on success, -1 on failure (should be fatal).
 */
int cli_sandbox_install(void);

#endif /* CLI_SANDBOX_H */
