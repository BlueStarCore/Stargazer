/* SPDX-License-Identifier: MIT */
/*
 * webd_session.h — In-memory session store
 *
 * Maps browser tokens (64-char hex) to username + mgmtd session tag.
 * Protected by pthread_mutex_t (accessed from main thread + workers).
 *
 * session_lookup() copies data into caller-provided buffer under the
 * lock, so the caller never holds a pointer into the shared array.
 */

#ifndef WEBD_SESSION_H
#define WEBD_SESSION_H

#include <stdint.h>
#include <time.h>

#define WEBD_MAX_SESSIONS  16
#define WEBD_TOKEN_LEN     64     /* 32 bytes → 64 hex chars */
#define WEBD_SESSION_TTL   3600   /* 1 hour absolute max */
#define WEBD_IDLE_TIMEOUT  900    /* 15 minutes idle — matches CLI TMOUT */

typedef struct {
	char     token[WEBD_TOKEN_LEN + 1];
	char     username[64];
	uint64_t ipc_session_tag;
	time_t   created;
	time_t   last_used;
} webd_session_t;

/*
 * Create a session with a pre-acquired mgmtd session tag.
 * Generates a random 64-char hex token via getrandom().
 * Copies the token into out_token (must be WEBD_TOKEN_LEN+1 bytes).
 * Returns 0 on success, -1 on failure (getrandom error).
 */
int session_create_with_tag(const char *username, uint64_t tag,
			    char *out_token);

/*
 * Look up session by token. Copies session data into *out under the
 * lock so the caller never holds a dangling pointer into the shared
 * array. Returns 0 on success (out filled), -1 if not found/expired.
 * Updates last_used on success.
 */
int session_lookup(const char *token, webd_session_t *out);

/* Destroy a session by token. */
void session_destroy(const char *token);

/* Expire sessions older than WEBD_SESSION_TTL. */
void session_expire_check(void);

/* Destroy all sessions (used during shutdown). */
void session_destroy_all(void);

/* Get number of active sessions. */
int session_count(void);

#endif /* WEBD_SESSION_H */
