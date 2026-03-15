/* SPDX-License-Identifier: MIT */
/*
 * webd_sandbox.h — seccomp-bpf lockdown for stargazer-webd
 *
 * Installed after privilege drop and thread pool creation.
 * All worker threads inherit the filter.
 */

#ifndef WEBD_SANDBOX_H
#define WEBD_SANDBOX_H

/*
 * Install seccomp-bpf sandbox.
 * Must be called after:
 *   - Thread pool is created (clone blocked after sandbox)
 *   - Privileges are dropped (setuid/setgid done)
 *   - Listeners are bound (initial bind done)
 * Returns 0 on success, -1 on failure.
 */
int webd_sandbox_install(void);

#endif /* WEBD_SANDBOX_H */
