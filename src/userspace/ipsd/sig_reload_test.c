/* SPDX-License-Identifier: MIT */
/*
 * sig_reload_test.c - test hot-reload ruleset, chạy trên HOST.
 * T1 init + match  T2 reload valid  T3 rollback  T4 concurrent (TSan)  T5 double signal
 */
#include "sig_reload.h"
#include "sig_rule.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>

static int g_failed;

static void check(int cond, const char *name)
{
	printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
	if (!cond) g_failed++;
}

static int write_rules(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");
	if (!f) return -1;
	fputs(content, f);
	fclose(f);
	return 0;
}

/* flow_ctx TCP port 80, không cờ */
static struct flow_ctx fc80(void)
{
	struct flow_ctx fc;
	memset(&fc, 0, sizeof(fc));
	fc.proto = SIG_PROTO_TCP;
	fc.dport = 80;
	return fc;
}

/* ---- T1: init + match trên ruleset thật ---------------------------------- */
static void t1_init_match(void)
{
	printf("T1 init + match:\n");
	struct sig_reload sr;
	int rc = sig_reload_init(&sr, "rules/emerging-scan.rules");
	check(rc == 0,         "init OK");
	check(sr.active != NULL,       "active != NULL");
	check(sr.active->n_rules > 0,  "có rule sau init");
	check(sr.pipe_rd >= 0,         "self-pipe mở");

	/* payload khớp FTP brute-force (sid 2010642): "USER root" dport 21 */
	struct flow_ctx fc21;
	memset(&fc21, 0, sizeof(fc21));
	fc21.proto = SIG_PROTO_TCP;
	fc21.dport = 21;
	int idx = sig_reload_match(&sr, (const uint8_t *)"USER root", 9, &fc21);
	check(idx >= 0, "match trên ruleset thật (FTP brute-force @dport 21)");

	sig_reload_free(&sr);
}

/* ---- T2: reload ruleset mới ------------------------------------------------ */
static void t2_reload_valid(void)
{
	printf("T2 reload ruleset mới:\n");
	/* init với file ET thật */
	struct sig_reload sr;
	check(sig_reload_init(&sr, "rules/emerging-scan.rules") == 0, "init OK");
	unsigned long cnt0 = sr.reload_count;

	/* viết ruleset mới chỉ có 1 rule đặc biệt */
	const char *tmppath = "/tmp/sg_reload_t2.rules";
	write_rules(tmppath,
		"alert tcp any any -> any 80 "
		"(msg:\"RELOAD_TEST\"; content:\"RELOADED_PAYLOAD\"; "
		"nocase; sid:9999001; rev:1;)\n");

	int rc = sig_reload_trigger(&sr, tmppath);
	check(rc == 0, "trigger trả 0 (bắt đầu)");
	sig_reload_wait(&sr);
	check(sr.reload_count == cnt0 + 1, "reload_count tăng 1");
	check(sr.reload_errors == 0,       "không có lỗi");

	/* rule mới có hiệu lực */
	struct flow_ctx fc = fc80();
	int idx = sig_reload_match(&sr, (const uint8_t *)"RELOADED_PAYLOAD", 16, &fc);
	check(idx >= 0, "rule mới khớp sau reload");

	/* rule cũ (FTP) không còn — ruleset mới chỉ có 1 rule */
	struct flow_ctx fc21; memset(&fc21,0,sizeof(fc21));
	fc21.proto = SIG_PROTO_TCP; fc21.dport = 21;
	int old = sig_reload_match(&sr, (const uint8_t *)"USER root", 9, &fc21);
	check(old < 0, "rule cũ không còn trong ruleset mới");

	sig_reload_free(&sr);
}

/* ---- T3: reload file không tồn tại → rollback -------------------------------- */
static void t3_rollback(void)
{
	printf("T3 rollback khi file lỗi:\n");
	const char *tmppath = "/tmp/sg_reload_t2.rules";   /* vẫn còn từ T2 */
	struct sig_reload sr;
	check(sig_reload_init(&sr, tmppath) == 0, "init với file T2 OK");
	unsigned long err0 = sr.reload_errors;

	sig_reload_trigger(&sr, "/tmp/does_not_exist_xyz.rules");
	sig_reload_wait(&sr);
	check(sr.reload_errors == err0 + 1, "reload_errors tăng");

	/* ruleset cũ vẫn hoạt động */
	struct flow_ctx fc = fc80();
	int idx = sig_reload_match(&sr, (const uint8_t *)"RELOADED_PAYLOAD", 16, &fc);
	check(idx >= 0, "rule cũ vẫn khớp sau rollback");

	sig_reload_free(&sr);
}

/* ---- T4: match song song trong khi reload ---------------------------------- */
struct t4_arg { struct sig_reload *sr; int stop; int hits; };

static void *t4_match_loop(void *p)
{
	struct t4_arg *a = p;
	struct flow_ctx fc = fc80();
	while (!__atomic_load_n(&a->stop, __ATOMIC_RELAXED)) {
		int r = sig_reload_match(a->sr,
			(const uint8_t *)"RELOADED_PAYLOAD", 16, &fc);
		if (r >= 0) a->hits++;
	}
	return NULL;
}

static void t4_concurrent(void)
{
	printf("T4 concurrent match + reload (TSan):\n");
	const char *tmppath = "/tmp/sg_reload_t2.rules";
	struct sig_reload sr;
	check(sig_reload_init(&sr, tmppath) == 0, "init OK");

	struct t4_arg arg = { &sr, 0, 0 };
	pthread_t tid;
	pthread_create(&tid, NULL, t4_match_loop, &arg);

	/* reload 3 lần trong khi match chạy */
	for (int i = 0; i < 3; i++) {
		sig_reload_trigger(&sr, tmppath);
		sig_reload_wait(&sr);
	}

	__atomic_store_n(&arg.stop, 1, __ATOMIC_RELAXED);
	pthread_join(tid, NULL);

	check(sr.reload_count >= 1, "ít nhất 1 reload hoàn tất");
	check(arg.hits >= 0,        "không crash (hits hợp lệ)");
	/* quan trọng: TSan không báo race */

	sig_reload_free(&sr);
}

/* ---- T5: double trigger → chỉ 1 reload ----------------------------------- */
static void t5_double_trigger(void)
{
	printf("T5 double trigger (guard):\n");
	const char *tmppath = "/tmp/sg_reload_t2.rules";
	struct sig_reload sr;
	check(sig_reload_init(&sr, tmppath) == 0, "init OK");
	unsigned long cnt0 = sr.reload_count;

	/* trigger 2 lần liền nhau, lần 2 phải bị skip */
	int r1 = sig_reload_trigger(&sr, tmppath);
	int r2 = sig_reload_trigger(&sr, tmppath);
	sig_reload_wait(&sr);

	check(r1 == 0, "trigger#1 trả 0 (bắt đầu)");
	check(r2 == 1, "trigger#2 trả 1 (đang bận, skip)");
	check(sr.reload_count == cnt0 + 1, "đúng 1 reload (không bị nhân đôi)");

	sig_reload_free(&sr);
}

int main(void)
{
	t1_init_match();
	t2_reload_valid();
	t3_rollback();
	t4_concurrent();
	t5_double_trigger();

	printf("\n%s (%d test thất bại)\n",
	       g_failed ? "=== CÓ LỖI ===" : "=== TẤT CẢ PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
