/* SPDX-License-Identifier: MIT */
/*
 * webd_session.c — In-memory session store
 *
 * Fixed-size array of sessions protected by a mutex.
 * Tokens are 32 random bytes rendered as 64 hex chars.
 */

#define _GNU_SOURCE
#include "webd_session.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

static webd_session_t sessions[WEBD_MAX_SESSIONS];
static pthread_mutex_t sess_lock = PTHREAD_MUTEX_INITIALIZER;

static void hex_encode(const unsigned char *in, size_t len, char *out)
{
	static const char hex[] = "0123456789abcdef";
	for (size_t i = 0; i < len; i++) {
		out[i * 2]     = hex[in[i] >> 4];
		out[i * 2 + 1] = hex[in[i] & 0x0F];
	}
	out[len * 2] = '\0';
}

int session_create_with_tag(const char *username, uint64_t tag,
			    char *out_token)
{
	unsigned char rnd[32];
	if (getrandom(rnd, sizeof(rnd), 0) != (ssize_t)sizeof(rnd))
		return -1;

	pthread_mutex_lock(&sess_lock);

	/* Find a free slot */
	int slot = -1;
	for (int i = 0; i < WEBD_MAX_SESSIONS; i++) {
		if (sessions[i].token[0] == '\0') {
			slot = i;
			break;
		}
	}

	/* If no free slot, evict oldest session */
	if (slot < 0) {
		slot = 0;
		time_t oldest = sessions[0].last_used;
		for (int i = 1; i < WEBD_MAX_SESSIONS; i++) {
			if (sessions[i].last_used < oldest) {
				oldest = sessions[i].last_used;
				slot = i;
			}
		}
	}

	webd_session_t *s = &sessions[slot];
	hex_encode(rnd, sizeof(rnd), s->token);
	snprintf(s->username, sizeof(s->username), "%s", username);
	s->ipc_session_tag = tag;
	s->created = time(NULL);
	s->last_used = s->created;

	/* Copy token under lock so caller never holds dangling pointer */
	memcpy(out_token, s->token, WEBD_TOKEN_LEN + 1);

	pthread_mutex_unlock(&sess_lock);

	return 0;
}

int session_lookup(const char *token, webd_session_t *out)
{
	if (!token || strlen(token) != WEBD_TOKEN_LEN || !out)
		return -1;

	pthread_mutex_lock(&sess_lock);

	int found = -1;
	time_t now = time(NULL);

	for (int i = 0; i < WEBD_MAX_SESSIONS; i++) {
		if (sessions[i].token[0] &&
		    memcmp(sessions[i].token, token, WEBD_TOKEN_LEN) == 0) {
			/* Check absolute expiry */
			if (now - sessions[i].created > WEBD_SESSION_TTL) {
				memset(&sessions[i], 0, sizeof(sessions[i]));
				break;
			}
			/* Check idle timeout */
			if (now - sessions[i].last_used > WEBD_IDLE_TIMEOUT) {
				memset(&sessions[i], 0, sizeof(sessions[i]));
				break;
			}
			sessions[i].last_used = now;
			/* Copy under lock so caller never holds dangling ptr */
			memcpy(out, &sessions[i], sizeof(*out));
			found = 0;
			break;
		}
	}

	pthread_mutex_unlock(&sess_lock);
	return found;
}

void session_destroy(const char *token)
{
	if (!token) return;

	pthread_mutex_lock(&sess_lock);

	for (int i = 0; i < WEBD_MAX_SESSIONS; i++) {
		if (sessions[i].token[0] &&
		    memcmp(sessions[i].token, token, WEBD_TOKEN_LEN) == 0) {
			memset(&sessions[i], 0, sizeof(sessions[i]));
			break;
		}
	}

	pthread_mutex_unlock(&sess_lock);
}

void session_expire_check(void)
{
	time_t now = time(NULL);

	pthread_mutex_lock(&sess_lock);

	for (int i = 0; i < WEBD_MAX_SESSIONS; i++) {
		if (sessions[i].token[0] &&
		    now - sessions[i].created > WEBD_SESSION_TTL) {
			memset(&sessions[i], 0, sizeof(sessions[i]));
		}
	}

	pthread_mutex_unlock(&sess_lock);
}

void session_destroy_all(void)
{
	pthread_mutex_lock(&sess_lock);
	memset(sessions, 0, sizeof(sessions));
	pthread_mutex_unlock(&sess_lock);
}

int session_count(void)
{
	int count = 0;

	pthread_mutex_lock(&sess_lock);
	for (int i = 0; i < WEBD_MAX_SESSIONS; i++) {
		if (sessions[i].token[0])
			count++;
	}
	pthread_mutex_unlock(&sess_lock);

	return count;
}
