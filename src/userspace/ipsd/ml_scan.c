/* SPDX-License-Identifier: MIT */
/*
 * ml_scan.c - init_win cache + checkpoint scoring (see ml_scan.h).
 *
 * ML is NO longer driven by a polling thread. process_packet (main.c) scores ML
 * exactly once per flow at the CHECKPOINT min(N packets, K bytes, T age) when no
 * signature has matched; each scoring calls ml_record_score() → RAM ring; the
 * main loop calls ml_scores_flush() to push to /run/stargazer-ipsd.scores for
 * `execute diagnose ips scores`.
 */
#define _GNU_SOURCE
#include "ml_scan.h"

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define SCORE_FILE  "/run/stargazer-ipsd.scores"
#define SCORE_TMP   "/run/stargazer-ipsd.scores.tmp"
#define THR_ALERT   0.50
#define THR_BLOCK   0.95

/* ---- per-flow Init_Win_bytes_forward cache -------------------------------
 *
 * init_win is a HIGH-weight feature; on a cache MISS (→ -1) the model leans
 * BENIGN (in CIC-IDS-2017, init_win=-1 ⇒ 0% attack), so -1 is a potential FALSE
 * NEGATIVE. The cache must therefore survive until the checkpoint (min N=16
 * packets / 14KB / 8s) EVEN UNDER DoS LOAD (slowhttptest -c 1000 -r 200 opens
 * thousands of flows per second).
 *
 * Anti-evict design:
 *   - 4-way SET-ASSOCIATIVE: one hash collision does NOT evict immediately; all
 *     4 ways must be full before the OLDEST victim (by stamp) is replaced → new
 *     flows survive long enough to reach the checkpoint.
 *   - 16384 buckets × 4 = 65536 entries table (~1.3MB) — ample for tens of
 *     thousands of concurrent flows.
 *   - LOOK UP BOTH tuple DIRECTIONS: put stores the forward SYN tuple
 *     (client→server) but the checkpoint packet may be the REVERSE packet
 *     (server→client) → get also tries the reversed tuple. */
#define IWIN_BUCKETS 16384   /* power-of-2 */
#define IWIN_WAYS    4
struct iwin_ent {
	uint32_t sip, dip;
	uint16_t sp, dp;
	uint8_t  proto, used;
	int32_t  win;
	uint32_t stamp;          /* insertion order — evict smallest (oldest) stamp */
};
static struct iwin_ent  g_iwin[IWIN_BUCKETS][IWIN_WAYS];
static uint32_t          g_iwin_stamp;   /* insertion counter, guarded by g_iwin_lk */
static pthread_mutex_t   g_iwin_lk = PTHREAD_MUTEX_INITIALIZER;

static uint32_t iwin_hash(uint8_t proto, uint32_t sip, uint32_t dip,
			  uint16_t sp, uint16_t dp)
{
	uint32_t h = 2166136261u;
	h = (h ^ sip) * 16777619u;
	h = (h ^ dip) * 16777619u;
	h = (h ^ sp)  * 16777619u;
	h = (h ^ dp)  * 16777619u;
	h = (h ^ proto) * 16777619u;
	return h & (IWIN_BUCKETS - 1);
}

void ml_iwin_put(uint8_t proto, uint32_t sip, uint32_t dip,
		 uint16_t sp, uint16_t dp, int32_t win)
{
	if (win < 0)
		return;
	uint32_t b = iwin_hash(proto, sip, dip, sp, dp);
	pthread_mutex_lock(&g_iwin_lk);
	struct iwin_ent *set = g_iwin[b];
	int victim = -1;              /* free way if any */
	int oldest_w = 0;            /* oldest way (fallback when full) */
	uint32_t oldest = UINT32_MAX;
	for (int w = 0; w < IWIN_WAYS; w++) {
		struct iwin_ent *e = &set[w];
		/* tuple already present → update in place (refresh stamp) */
		if (e->used && e->sip == sip && e->dip == dip &&
		    e->sp == sp && e->dp == dp && e->proto == proto) {
			oldest_w = w;
			goto install;
		}
		if (!e->used && victim < 0)
			victim = w;          /* remember the first free way */
		if (e->stamp < oldest) {
			oldest = e->stamp;
			oldest_w = w;        /* oldest victim if eviction is needed */
		}
	}
	if (victim >= 0)
		oldest_w = victim;          /* prefer a free way */
install:
	{
		struct iwin_ent *e = &set[oldest_w];
		e->sip = sip; e->dip = dip; e->sp = sp; e->dp = dp;
		e->proto = proto; e->used = 1; e->win = win;
		e->stamp = ++g_iwin_stamp;
	}
	pthread_mutex_unlock(&g_iwin_lk);
}

/* Look up one tuple direction in the set (called under lock). -1 if no match. */
static int32_t iwin_lookup_locked(uint8_t proto, uint32_t sip, uint32_t dip,
				  uint16_t sp, uint16_t dp)
{
	uint32_t b = iwin_hash(proto, sip, dip, sp, dp);
	struct iwin_ent *set = g_iwin[b];
	for (int w = 0; w < IWIN_WAYS; w++) {
		struct iwin_ent *e = &set[w];
		if (e->used && e->sip == sip && e->dip == dip &&
		    e->sp == sp && e->dp == dp && e->proto == proto)
			return e->win;
	}
	return -1;
}

int32_t ml_iwin_get(uint8_t proto, uint32_t sip, uint32_t dip,
		    uint16_t sp, uint16_t dp)
{
	pthread_mutex_lock(&g_iwin_lk);
	/* Forward direction (checkpoint packet is client→server). */
	int32_t r = iwin_lookup_locked(proto, sip, dip, sp, dp);
	/* Miss → try the REVERSED tuple: the checkpoint packet is server→client
	 * but init_win was stored under the forward SYN tuple. */
	if (r < 0)
		r = iwin_lookup_locked(proto, dip, sip, dp, sp);
	pthread_mutex_unlock(&g_iwin_lk);
	return r;
}

/* ---- ring of scored flows ------------------------------------------------- */
#define SCORE_RING 256
static char g_score_ring[SCORE_RING][192];
static int  g_score_pos;
static int  g_score_full;
static int  g_score_dirty;   /* something new not yet flushed */

static const char *verdict_str(double s)
{
	if (s >= THR_BLOCK) return "BLOCK";
	if (s >= THR_ALERT) return "ALERT";
	return "pass";
}

void ml_record_score(uint8_t proto, uint32_t sip, uint32_t dip,
		     uint16_t sp, uint16_t dp,
		     uint32_t pkts, uint32_t syn, uint32_t ack,
		     int32_t iwin, double score)
{
	struct in_addr s = { .s_addr = htonl(sip) };
	struct in_addr d = { .s_addr = htonl(dip) };
	char sa[INET_ADDRSTRLEN], da[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &s, sa, sizeof(sa));
	inet_ntop(AF_INET, &d, da, sizeof(da));

	snprintf(g_score_ring[g_score_pos], sizeof(g_score_ring[0]),
		 "proto=%u src=%s:%u dst=%s:%u pkts=%u syn=%u ack=%u iwin=%d "
		 "score=%.4f verdict=%s\n",
		 proto, sa, sp, da, dp, pkts, syn, ack, iwin,
		 score, verdict_str(score));
	g_score_pos = (g_score_pos + 1) % SCORE_RING;
	if (g_score_pos == 0) g_score_full = 1;
	g_score_dirty = 1;
}

void ml_scores_flush(void)
{
	if (!g_score_dirty)
		return;
	FILE *f = fopen(SCORE_TMP, "w");
	if (!f)
		return;
	fprintf(f, "# Per-flow ML scores @checkpoint (thr_alert=%.2f thr_block=%.2f)\n",
		THR_ALERT, THR_BLOCK);
	int n     = g_score_full ? SCORE_RING : g_score_pos;
	int start = g_score_full ? g_score_pos : 0;
	for (int i = 0; i < n; i++)
		fputs(g_score_ring[(start + i) % SCORE_RING], f);
	fclose(f);
	rename(SCORE_TMP, SCORE_FILE);
	g_score_dirty = 0;
}
