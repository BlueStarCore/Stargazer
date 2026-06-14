/* SPDX-License-Identifier: MIT */
/*
 * reass_test.c - Unit test ráp dòng TCP + streaming AC, chạy trên HOST.
 *
 *   cc -O2 -Wall -Wextra -fsanitize=address,undefined \
 *      -o /tmp/reass_test ac.c reass.c reass_test.c && /tmp/reass_test
 *
 * Phủ: đúng thứ tự, cắt qua 2–3 segment, đảo thứ tự, trùng lặp (retransmit),
 * overlap (first-wins), lỗ trống > limit (fail-closed), contig/inspected.
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

/* Thu thập match. */
struct collected { int n; int ids[64]; uint64_t ends[64]; int dirs[64]; };
static int on_m(int id, uint64_t end, int dir, void *ctx)
{
	struct collected *c = ctx;
	if (c->n < 64) { c->ids[c->n] = id; c->ends[c->n] = end;
			 c->dirs[c->n] = dir; c->n++; }
	return 0;   /* không dừng sớm */
}
static int has_match(const struct collected *c, int id, uint64_t end)
{
	for (int i = 0; i < c->n; i++)
		if (c->ids[i] == id && c->ends[i] == end) return 1;
	return 0;
}

/* gửi segment dạng chuỗi C (không '\0' cuối). */
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

	printf("T1 đúng thứ tự, pattern trong 1 segment:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		int rc = seg(&rf, REASS_TO_SERVER, BASE, "xxATTACKyy", &c);
		check(rc == REASS_OK, "REASS_OK");
		check(has_match(&c, 0, 7), "ATTACK khớp, end_off=7");
		reass_flow_free(&rf);
	}

	printf("T2 pattern cắt qua 2 segment (đúng thứ tự):\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE,     "xxATT", &c);  /* off 0..4 */
		check(c.n == 0, "chưa khớp sau segment 1");
		seg(&rf, REASS_TO_SERVER, BASE + 5, "ACKyy", &c);  /* off 5..9 */
		check(has_match(&c, 0, 7), "ATTACK khớp qua biên segment, end=7");
		reass_flow_free(&rf);
	}

	printf("T3 pattern cắt qua 3 segment:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE,     "xxAT", &c);   /* 0..3 */
		seg(&rf, REASS_TO_SERVER, BASE + 4, "TA",   &c);   /* 4..5 */
		seg(&rf, REASS_TO_SERVER, BASE + 6, "CKyy", &c);   /* 6..9 */
		check(has_match(&c, 0, 7), "ATTACK qua 3 segment, end=7");
		reass_flow_free(&rf);
	}

	printf("T4 đảo thứ tự (segment sau đến trước):\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE,     "AB",     &c); /* base, 0..1 */
		seg(&rf, REASS_TO_SERVER, BASE + 6, "CKzz",   &c); /* 6..9, HELD */
		check(c.n == 0, "segment lệch chỗ → giữ tạm, chưa feed");
		seg(&rf, REASS_TO_SERVER, BASE + 2, "ATTA",   &c); /* 2..5 → lấp lỗ */
		check(has_match(&c, 0, 7), "sau khi lấp lỗ → ATTACK khớp, end=7");
		reass_flow_free(&rf);
	}

	printf("T5 trùng lặp (retransmit) → không double-match, không crash:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE, "xxATTACKyy", &c);
		seg(&rf, REASS_TO_SERVER, BASE, "xxATTACKyy", &c); /* gửi lại */
		int n0 = 0;
		for (int i = 0; i < c.n; i++) if (c.ids[i] == 0) n0++;
		check(n0 == 1, "ATTACK chỉ khớp 1 lần dù gửi lại");
		reass_flow_free(&rf);
	}

	printf("T6 overlap khác dữ liệu → first-wins (byte đến trước thắng):\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE, "ABCDEFGH", &c);   /* lấp 0..7 */
		seg(&rf, REASS_TO_SERVER, BASE + 2, "ATTACK", &c); /* overlap 2..7 */
		check(!has_match(&c, 0, 7), "ATTACK KHÔNG ghi đè (first-wins) → không khớp");
		uint32_t cl; const uint8_t *b = reass_dir_buf(&rf, REASS_TO_SERVER, &cl);
		check(b && memcmp(b, "ABCDEFGH", 8) == 0, "dòng giữ byte đến trước");
		reass_flow_free(&rf);
	}

	printf("T7 lỗ trống > REASS_GAP_LIMIT → fail-closed:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE, "xx", &c);         /* 0..1 */
		/* data nhảy xa quá GAP_LIMIT trong khi lỗ 2.. chưa lấp */
		int rc = seg(&rf, REASS_TO_SERVER, BASE + 2 + REASS_GAP_LIMIT + 10,
			     "yy", &c);
		check(rc == REASS_FAILCLOSED, "data chất sau lỗ trống quá hạn → fail-closed");
		/* sticky: lần gọi tiếp vẫn fail */
		check(seg(&rf, REASS_TO_SERVER, BASE + 2, "zz", &c) == REASS_FAILCLOSED,
		      "fail-closed sticky");
		reass_flow_free(&rf);
	}

	printf("T8 2 chiều độc lập + contig/inspected:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE, "GET /EVIL", &c);  /* 9 byte, EVIL@5..8 */
		seg(&rf, REASS_TO_CLIENT, BASE, "HTTP", &c);       /* 4 byte */
		check(has_match(&c, 1, 8) && c.dirs[0] == REASS_TO_SERVER,
		      "EVIL khớp chiều to_server, end=8");
		uint32_t cl;
		reass_dir_buf(&rf, REASS_TO_SERVER, &cl);
		check(cl == 9, "to_server contig=9");
		check(reass_inspected_bytes(&rf) == 13, "inspected = 9+4");
		reass_flow_free(&rf);
	}

	printf("T9 hot-reload rebind: đổi automaton → re-scan dòng đã có:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c1 = {0};
		seg(&rf, REASS_TO_SERVER, BASE, "xxATTACKyy", &c1);
		check(has_match(&c1, 0, 7), "AC1: ATTACK khớp end=7");

		/* AC2: pattern khác ("TACKyy") — có trong dòng đã ghép */
		struct ac_automaton ac2; ac_init(&ac2, 0);
		ac_add_pattern(&ac2, (const uint8_t *)"TACKyy", 6, 0);
		ac_build(&ac2);

		struct collected c2 = {0};
		reass_flow_rebind(&rf, &ac2, on_m, &c2);
		check(has_match(&c2, 0, 9), "sau rebind: AC2 re-scan dòng cũ → TACKyy end=9");

		/* feed tiếp sau rebind: state AC2 tiếp tục đúng (không quét lại từ đầu) */
		struct collected c3 = {0};
		seg(&rf, REASS_TO_SERVER, BASE + 10, "TACKyy", &c3);
		check(has_match(&c3, 0, 15), "feed sau rebind: AC2 streaming tiếp, end=15");

		ac_free(&ac2);
		reass_flow_free(&rf);
	}

	printf("T10 reass_consume: trượt cửa sổ (RAM phẳng) + continuity:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE, "0123456789", &c);
		uint32_t cl; const uint8_t *b;
		b = reass_dir_buf(&rf, REASS_TO_SERVER, &cl);
		check(cl == 10, "contig=10 trước consume");
		reass_consume(&rf, REASS_TO_SERVER, 5, 1, on_m, &c);
		b = reass_dir_buf(&rf, REASS_TO_SERVER, &cl);
		check(cl == 5 && memcmp(b, "56789", 5) == 0,
		      "sau consume 5 → cửa sổ '56789'");
		seg(&rf, REASS_TO_SERVER, BASE + 10, "ABCDE", &c);
		b = reass_dir_buf(&rf, REASS_TO_SERVER, &cl);
		check(cl == 10 && memcmp(b, "56789ABCDE", 10) == 0,
		      "feed tiếp seq liền mạch → continuity sau slide");
		reass_flow_free(&rf);
	}

	printf("T11 transaction isolation: AC reset khi consume(reset_ac)\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct collected c = {0};
		seg(&rf, REASS_TO_SERVER, BASE, "xxATT", &c);      /* nửa ATTACK */
		reass_consume(&rf, REASS_TO_SERVER, 5, 1, on_m, &c); /* new tx, reset AC */
		seg(&rf, REASS_TO_SERVER, BASE + 5, "ACKyy", &c);  /* nửa sau */
		int n0 = 0;
		for (int i = 0; i < c.n; i++) if (c.ids[i] == 0) n0++;
		check(n0 == 0, "ATTACK vắt qua ranh giới transaction → KHÔNG match");
		reass_flow_free(&rf);
	}

	ac_free(&ac);
	printf("\n%s (%d test thất bại)\n",
	       g_failed ? "=== CÓ LỖI ===" : "=== TẤT CẢ PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
