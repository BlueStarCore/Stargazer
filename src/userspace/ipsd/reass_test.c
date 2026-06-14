/* SPDX-License-Identifier: MIT */
/*
 * reass_test.c - Unit test for TCP stream reassembly + streaming AC, runs on the HOST.
 *
 *   cc -O2 -Wall -Wextra -fsanitize=address,undefined \
 *      -o /tmp/reass_test ac.c reass.c reass_test.c && /tmp/reass_test
 *
 * Coverage: in order, split across 2–3 segments, reordered, duplicate
 * (retransmit), overlap (first-wins), gap > limit (fail-closed), contig/inspected.
 */
#include "reass.h"

#include <stdio.h>
#include <string.h>

static int g_failed;
static void check(int cond, const char *name)
{
	printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
	if (!cond) g_failed++;
}

/* Collect matches. */
struct collected { int n; int ids[64]; uint64_t ends[64]; int dirs[64]; };
static int on_m(int id, uint64_t end, int dir, void *ctx)
{
	struct collected *c = ctx;
	if (c->n < 64) { c->ids[c->n] = id; c->ends[c->n] = end;
			 c->dirs[c->n] = dir; c->n++; }
	return 0;   /* do not stop early */
}
static int has_match(const struct collected *c, int id, uint64_t end)
{
	for (int i = 0; i < c->n; i++)
		if (c->ids[i] == id && c->ends[i] == end) return 1;
	return 0;
}

/* send a segment as a C string (without the trailing '\0'). */
static int seg(struct reass_flow *rf, int dir, uint32_t seq, const char *s,
	       struct collected *c)
{
	return reass_segment(rf, dir, seq, (const uint8_t *)s,
			     (uint32_t)strlen(s), on_m, c);
}

#define BASE 1000u

int main(void)
{
	/* AC: pattern 0 = "ATTACK", pattern 1 = "EVIL" (case-sensitive). */
	struct ac_automaton ac;
	ac_init(&ac, 0);
	ac_add_pattern(&ac, (const uint8_t *)"ATTACK", 6, 0);
	ac_add_pattern(&ac, (const uint8_t *)"EVIL",   4, 1);
	ac_build(&ac);

	printf("T1 in order, pattern within 1 segment:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		int rc = seg(&rf, REASS_TO_SERVER, BASE, "xxATTACKyy", &c);
		check(rc == REASS_OK, "REASS_OK");
		check(has_match(&c, 0, 7), "ATTACK matched, end_off=7");
		reass_flow_free(&rf);
	}

	printf("T2 pattern split across 2 segments (in order):\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE,     "xxATT", &c);  /* off 0..4 */
		check(c.n == 0, "no match yet after segment 1");
		seg(&rf, REASS_TO_SERVER, BASE + 5, "ACKyy", &c);  /* off 5..9 */
		check(has_match(&c, 0, 7), "ATTACK matched across segment boundary, end=7");
		reass_flow_free(&rf);
	}

	printf("T3 pattern split across 3 segments:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE,     "xxAT", &c);   /* 0..3 */
		seg(&rf, REASS_TO_SERVER, BASE + 4, "TA",   &c);   /* 4..5 */
		seg(&rf, REASS_TO_SERVER, BASE + 6, "CKyy", &c);   /* 6..9 */
		check(has_match(&c, 0, 7), "ATTACK across 3 segments, end=7");
		reass_flow_free(&rf);
	}

	printf("T4 reordered (later segment arrives first):\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE,     "AB",     &c); /* base, 0..1 */
		seg(&rf, REASS_TO_SERVER, BASE + 6, "CKzz",   &c); /* 6..9, HELD */
		check(c.n == 0, "out-of-place segment → held, not yet fed");
		seg(&rf, REASS_TO_SERVER, BASE + 2, "ATTA",   &c); /* 2..5 → fill gap */
		check(has_match(&c, 0, 7), "after filling the gap → ATTACK matched, end=7");
		reass_flow_free(&rf);
	}

	printf("T5 duplicate (retransmit) → no double-match, no crash:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE, "xxATTACKyy", &c);
		seg(&rf, REASS_TO_SERVER, BASE, "xxATTACKyy", &c); /* resend */
		int n0 = 0;
		for (int i = 0; i < c.n; i++) if (c.ids[i] == 0) n0++;
		check(n0 == 1, "ATTACK matched only once despite resend");
		reass_flow_free(&rf);
	}

	printf("T6 overlap with different data → first-wins (byte that arrives first wins):\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE, "ABCDEFGH", &c);   /* fill 0..7 */
		seg(&rf, REASS_TO_SERVER, BASE + 2, "ATTACK", &c); /* overlap 2..7 */
		check(!has_match(&c, 0, 7), "ATTACK does NOT overwrite (first-wins) → no match");
		uint32_t cl; const uint8_t *b = reass_dir_buf(&rf, REASS_TO_SERVER, &cl);
		check(b && memcmp(b, "ABCDEFGH", 8) == 0, "stream keeps the bytes that arrived first");
		reass_flow_free(&rf);
	}

	printf("T7 gap > REASS_GAP_LIMIT → fail-closed:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE, "xx", &c);         /* 0..1 */
		/* data jumps past GAP_LIMIT while the gap at 2.. is still unfilled */
		int rc = seg(&rf, REASS_TO_SERVER, BASE + 2 + REASS_GAP_LIMIT + 10,
			     "yy", &c);
		check(rc == REASS_FAILCLOSED, "data piled behind an over-limit gap → fail-closed");
		/* sticky: the next call still fails */
		check(seg(&rf, REASS_TO_SERVER, BASE + 2, "zz", &c) == REASS_FAILCLOSED,
		      "fail-closed sticky");
		reass_flow_free(&rf);
	}

	printf("T8 two independent directions + contig/inspected:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE, "GET /EVIL", &c);  /* 9 byte, EVIL@5..8 */
		seg(&rf, REASS_TO_CLIENT, BASE, "HTTP", &c);       /* 4 byte */
		check(has_match(&c, 1, 8) && c.dirs[0] == REASS_TO_SERVER,
		      "EVIL matched in the to_server direction, end=8");
		uint32_t cl;
		reass_dir_buf(&rf, REASS_TO_SERVER, &cl);
		check(cl == 9, "to_server contig=9");
		check(reass_inspected_bytes(&rf) == 13, "inspected = 9+4");
		reass_flow_free(&rf);
	}

	printf("T9 hot-reload rebind: swap automaton → re-scan existing stream:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c1 = {0};
		seg(&rf, REASS_TO_SERVER, BASE, "xxATTACKyy", &c1);
		check(has_match(&c1, 0, 7), "AC1: ATTACK matched end=7");

		/* AC2: a different pattern ("TACKyy") — present in the reassembled stream */
		struct ac_automaton ac2; ac_init(&ac2, 0);
		ac_add_pattern(&ac2, (const uint8_t *)"TACKyy", 6, 0);
		ac_build(&ac2);

		struct collected c2 = {0};
		reass_flow_rebind(&rf, &ac2, on_m, &c2);
		check(has_match(&c2, 0, 9), "after rebind: AC2 re-scans old stream → TACKyy end=9");

		/* keep feeding after rebind: AC2 state continues correctly (no re-scan from start) */
		struct collected c3 = {0};
		seg(&rf, REASS_TO_SERVER, BASE + 10, "TACKyy", &c3);
		check(has_match(&c3, 0, 15), "feed after rebind: AC2 keeps streaming, end=15");

		ac_free(&ac2);
		reass_flow_free(&rf);
	}

	printf("T10 reass_consume: slide the window (flat RAM) + continuity:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE, "0123456789", &c);
		uint32_t cl; const uint8_t *b;
		b = reass_dir_buf(&rf, REASS_TO_SERVER, &cl);
		check(cl == 10, "contig=10 before consume");
		reass_consume(&rf, REASS_TO_SERVER, 5, 1, on_m, &c);
		b = reass_dir_buf(&rf, REASS_TO_SERVER, &cl);
		check(cl == 5 && memcmp(b, "56789", 5) == 0,
		      "after consume 5 → window '56789'");
		seg(&rf, REASS_TO_SERVER, BASE + 10, "ABCDE", &c);
		b = reass_dir_buf(&rf, REASS_TO_SERVER, &cl);
		check(cl == 10 && memcmp(b, "56789ABCDE", 10) == 0,
		      "feed contiguous seq → continuity after slide");
		reass_flow_free(&rf);
	}

	printf("T11 transaction isolation: AC reset khi consume(reset_ac)\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE, "xxATT", &c);      /* half of ATTACK */
		reass_consume(&rf, REASS_TO_SERVER, 5, 1, on_m, &c); /* new tx, reset AC */
		seg(&rf, REASS_TO_SERVER, BASE + 5, "ACKyy", &c);  /* second half */
		int n0 = 0;
		for (int i = 0; i < c.n; i++) if (c.ids[i] == 0) n0++;
		check(n0 == 0, "ATTACK spanning the transaction boundary → NO match");
		reass_flow_free(&rf);
	}

	ac_free(&ac);
	printf("\n%s (%d test(s) failed)\n",
	       g_failed ? "=== FAILURES ===" : "=== ALL PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
