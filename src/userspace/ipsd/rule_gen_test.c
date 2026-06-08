/* SPDX-License-Identifier: MIT */
/*
 * rule_gen_test.c - test Rule Generation Unit, chạy trên HOST.
 *
 *   gcc -O2 -Wall -Wextra -std=c11 -fsanitize=thread \
 *       -o /tmp/rule_gen_test rule_gen.c sig_rule.c ac.c rule_gen_test.c -lpthread
 *
 * T1 feed < min_support → không sinh rule
 * T2 feed ≥ min_support & score ≥ threshold → sinh rule, cấp SID
 * T3 feed trùng → không sinh lần hai
 * T4 save + load roundtrip → cùng tập rule
 * T5 feed đồng thời từ 2 thread → không data race (TSan), chống trùng đúng
 */
#include "rule_gen.h"

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in.h>

static int g_failed;

static void check(int cond, const char *name)
{
	printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
	if (!cond) g_failed++;
}

static struct rule_gen_input mk(uint8_t proto, uint16_t dport, uint8_t flags, double score)
{
	struct rule_gen_input in;
	memset(&in, 0, sizeof(in));
	in.proto = proto; in.dport = dport; in.tcp_flags = flags; in.ml_score = score;
	return in;
}

static long read_all(const char *path, char *buf, long cap)
{
	FILE *f = fopen(path, "r");
	long n;
	if (!f) return -1;
	n = (long)fread(buf, 1, (size_t)cap - 1, f);
	buf[n] = '\0';
	fclose(f);
	return n;
}

/* ---- T5 thread worker ---- */
struct worker_arg { struct rule_gen_ctx *ctx; int iters; };
static void *worker(void *p)
{
	struct worker_arg *a = p;
	struct rule_gen_input in = mk(IPPROTO_TCP, 4444, SIG_TCP_SYN | SIG_TCP_PSH, 0.99);
	for (int i = 0; i < a->iters; i++)
		rule_gen_feed(a->ctx, &in, NULL);
	return NULL;
}

int main(void)
{
	const uint8_t  FL = SIG_TCP_SYN | SIG_TCP_PSH;
	struct rule_gen_input in = mk(IPPROTO_TCP, 80, FL, 0.99);

	/* ---- T1: dưới ngưỡng support ---- */
	printf("T1 feed < min_support:\n");
	struct rule_gen_ctx c1;
	rule_gen_init(&c1, 3, 0.95, RULE_GEN_SID_BASE);
	int e1 = rule_gen_feed(&c1, &in, NULL);
	int e2 = rule_gen_feed(&c1, &in, NULL);
	check(e1 == 0 && e2 == 0, "2 lần feed (count<3) → chưa sinh");
	check(c1.rules_emitted == 0, "rules_emitted == 0");
	rule_gen_free(&c1);

	/* ---- T2: đủ support + đủ score ---- */
	printf("T2 feed ≥ min_support, score ≥ threshold:\n");
	struct rule_gen_ctx c2;
	rule_gen_init(&c2, 3, 0.95, RULE_GEN_SID_BASE);
	check(rule_gen_feed(&c2, &in, NULL) == 0, "feed#1 chưa sinh");
	check(rule_gen_feed(&c2, &in, NULL) == 0, "feed#2 chưa sinh");
	check(rule_gen_feed(&c2, &in, NULL) == 1, "feed#3 SINH rule");
	check(c2.rules_emitted == 1, "rules_emitted == 1");
	check(c2.sid_counter == RULE_GEN_SID_BASE + 1, "SID 9000000 đã cấp (counter→9000001)");

	/* score gate: bộ khác, score thấp, feed nhiều vẫn không sinh */
	struct rule_gen_input low = mk(IPPROTO_TCP, 53, SIG_TCP_ACK, 0.40);
	for (int i = 0; i < 10; i++) rule_gen_feed(&c2, &low, NULL);
	check(c2.rules_emitted == 1, "score<threshold → vẫn không sinh thêm");

	/* ---- T3: feed trùng không sinh lần hai ---- */
	printf("T3 feed trùng:\n");
	check(rule_gen_feed(&c2, &in, NULL) == 0, "feed#4 (đã có rule) → 0");
	check(rule_gen_feed(&c2, &in, NULL) == 0, "feed#5 → 0");
	check(c2.rules_emitted == 1 && c2.sid_counter == RULE_GEN_SID_BASE + 1,
	      "không sinh trùng, SID không nhảy");

	/* ---- T4: save + load roundtrip ---- */
	printf("T4 save/load roundtrip:\n");
	const char *f1 = "/tmp/rgtest1.rules", *f2 = "/tmp/rgtest2.rules";
	check(rule_gen_save(&c2, f1) == 0, "save ctx2 → file1");

	struct rule_gen_ctx c3;
	rule_gen_init(&c3, 3, 0.95, RULE_GEN_SID_BASE);
	int n = rule_gen_load(&c3, NULL, f1);
	check(n == 1, "load → 1 rule");
	check(c3.rules_emitted == 1, "ctx3 rules_emitted == 1");
	check(rule_gen_feed(&c3, &in, NULL) == 0, "feed lại bộ đã nạp → không sinh (nhớ trạng thái)");

	check(rule_gen_save(&c3, f2) == 0, "save ctx3 → file2");
	{
		char b1[4096], b2[4096];
		long n1 = read_all(f1, b1, sizeof(b1));
		long n2 = read_all(f2, b2, sizeof(b2));
		check(n1 > 0 && n1 == n2 && memcmp(b1, b2, (size_t)n1) == 0,
		      "file1 == file2 (roundtrip giữ nguyên rule)");
	}
	rule_gen_free(&c2);
	rule_gen_free(&c3);

	/* ---- T5: feed đồng thời 2 thread ---- */
	printf("T5 feed đồng thời 2 thread (cùng bộ):\n");
	struct rule_gen_ctx c4;
	rule_gen_init(&c4, 3, 0.95, RULE_GEN_SID_BASE);
	pthread_t t1, t2;
	struct worker_arg a1 = { &c4, 200 }, a2 = { &c4, 200 };
	pthread_create(&t1, NULL, worker, &a1);
	pthread_create(&t2, NULL, worker, &a2);
	pthread_join(t1, NULL);
	pthread_join(t2, NULL);
	check(c4.rules_emitted == 1, "đúng 1 rule dù 400 feed đồng thời (chống trùng)");
	check(c4.sid_counter == RULE_GEN_SID_BASE + 1, "đúng 1 SID được cấp");
	rule_gen_free(&c4);

	printf("\n%s (%d test thất bại)\n",
	       g_failed ? "=== CÓ LỖI ===" : "=== TẤT CẢ PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
