/* SPDX-License-Identifier: MIT */
/*
 * sig_reload.h - hot-reload ruleset without stopping the NFQUEUE loop.
 *
 * Architecture follows Snort README.reload:
 *   - The reload thread BUILDS the new ruleset while the NFQUEUE thread keeps
 *     using the old one.
 *   - When the new version is ready → SWAP under write-lock → free the old
 *     version AFTER the swap.
 *   - There is never a "0 rules active" window.
 *   - New ruleset fails → rollback, old version keeps running.
 *   - SIGUSR1 signals a reload via a self-pipe (async-signal-safe).
 */
#ifndef SG_SIG_RELOAD_H
#define SG_SIG_RELOAD_H

#define _GNU_SOURCE   /* pthread_rwlock_t on older glibc */
#include "sig_rule.h"
#include <pthread.h>

struct sig_reload {
	struct sig_ruleset  *active;          /* running ruleset (never NULL after init)         */
	struct sig_ruleset  *pending;         /* building in the reload thread; NULL when idle   */
	pthread_rwlock_t     rwlock;          /* readers = sig_reload_match(); writer = swap      */
	pthread_mutex_t      spawn_lock;      /* protects thread + pending + rules_path          */
	pthread_t            thread;          /* reload thread handle; 0 = idle                  */
	int                  pipe_rd;         /* self-pipe: NFQUEUE loop poll                    */
	int                  pipe_wr;         /* self-pipe: signal handler writes                */
	char                 rules_path[256]; /* table path loaded on SIGUSR1 (rebuild AC)       */
	char                 prof_dir[256];   /* per-profile selection maps; reloaded on SIGUSR2 */
	int                  last_result;     /* last reload result: 0=ok, -1=error              */
	unsigned long        reload_count;
	unsigned long        reload_errors;
};

/*
 * Initialize: load the initial ruleset from rules_path, open the self-pipe,
 * register the SIGUSR1 handler. Returns 0/-1.
 */
int  sig_reload_init(struct sig_reload *sr, const char *rules_path);

/*
 * Call from the NFQUEUE loop when pipe_rd is readable (SIGUSR1 arrived).
 * Starts the reload thread if not already running; drains the pipe. Returns
 * 0=started, 1=reload already in progress (skipped), -1=error.
 */
int  sig_reload_handle_signal(struct sig_reload *sr);

/*
 * Re-apply the per-profile selection maps (prof_dir) to the LIVE ruleset under
 * the write-lock — WITHOUT rebuilding the automaton. Call from the NFQUEUE loop
 * on a scope change (SIGUSR2). Cheap; returns 0/-1.
 */
int  sig_reload_apply_scope(struct sig_reload *sr);

/*
 * Drop-in replacement for sig_match(): rdlock → sig_match → unlock.
 * Caller MUST NOT hold the lock before calling.
 */
int  sig_reload_match(struct sig_reload *sr, const uint8_t *payload,
		      size_t len, const struct flow_ctx *fc);

/*
 * Trigger a reload directly (no signal needed) — used by the IPC handler
 * when the operator runs "execute ips update file <path>". Async (returns
 * immediately).
 */
int  sig_reload_trigger(struct sig_reload *sr, const char *new_path);

/*
 * Block until the reload thread finishes. Returns 0=success, -1=error/rollback.
 */
int  sig_reload_wait(struct sig_reload *sr);

/* Release: join thread, free both rulesets, destroy locks. Idempotent. */
void sig_reload_free(struct sig_reload *sr);

#endif /* SG_SIG_RELOAD_H */
