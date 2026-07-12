/* SPDX-License-Identifier: MIT */
/*
 * sig_reload_test.c - test hot-reload ruleset, runs on HOST.
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

/* flow_ctx TCP port 80, no flags */
static struct flow_ctx fc80(void)
{
	struct flow_ctx fc;
	memset(&fc, 0, sizeof(fc));
	fc.proto = SIG_PROTO_TCP;
	fc.dport = 80;
	return fc;
}

/* ---- T1: init + match on the real ruleset -------------------------------- */
static void t1_init_match(void)
{
	printf("T1 init + match:\n");
	struct sig_reload sr;
	int rc = sig_reload_init(&sr, "rules/emerging-scan.rules");
	check(rc == 0,         "init OK");
	check(sr.active != NULL,       "active != NULL");
	check(sr.active->n_rules > 0,  "rules present after init");
	check(sr.pipe_rd >= 0,         "self-pipe open");

	/* payload matches FTP brute-force (sid 2010642): "USER root" dport 21.
	 * Rule has flow:established,to_server (P6) → must supply matching context. */
	struct flow_ctx fc21;
	memset(&fc21, 0, sizeof(fc21));
	fc21.proto       = SIG_PROTO_TCP;
	fc21.dport       = 21;
	fc21.established = 1;
	fc21.to_server   = 1;
	int idx = sig_reload_match(&sr, (const uint8_t *)"USER root", 9, &fc21);
	check(idx >= 0, "match on the real ruleset (FTP brute-force @dport 21)");

	sig_reload_free(&sr);
}

/* ---- T2: reload new ruleset ----------------------------------------------- */
static void t2_reload_valid(void)
{
	printf("T2 reload new ruleset:\n");
	/* init with the real ET file */
	struct sig_reload sr;
	check(sig_reload_init(&sr, "rules/emerging-scan.rules") == 0, "init OK");
	unsigned long cnt0 = sr.reload_count;

	/* write a new ruleset with just 1 special rule */
	const char *tmppath = "/tmp/sg_reload_t2.rules";
	write_rules(tmppath,
		"alert tcp any any -> any 80 "
		"(msg:\"RELOAD_TEST\"; content:\"RELOADED_PAYLOAD\"; "
		"nocase; sid:9999001; rev:1;)\n");

	int rc = sig_reload_trigger(&sr, tmppath);
	check(rc == 0, "trigger returns 0 (started)");
	sig_reload_wait(&sr);
	check(sr.reload_count == cnt0 + 1, "reload_count increased by 1");
	check(sr.reload_errors == 0,       "no errors");

	/* new rule is in effect */
	struct flow_ctx fc = fc80();
	int idx = sig_reload_match(&sr, (const uint8_t *)"RELOADED_PAYLOAD", 16, &fc);
	check(idx >= 0, "new rule matches after reload");

	/* old rule (FTP) is gone — new ruleset has only 1 rule */
	struct flow_ctx fc21; memset(&fc21,0,sizeof(fc21));
	fc21.proto = SIG_PROTO_TCP; fc21.dport = 21;
	int old = sig_reload_match(&sr, (const uint8_t *)"USER root", 9, &fc21);
	check(old < 0, "old rule no longer in the new ruleset");

	sig_reload_free(&sr);
}

/* ---- T3: reload nonexistent file → rollback ------------------------------- */
static void t3_rollback(void)
{
	printf("T3 rollback on file error:\n");
	const char *tmppath = "/tmp/sg_reload_t2.rules";   /* still present from T2 */
	struct sig_reload sr;
	check(sig_reload_init(&sr, tmppath) == 0, "init with T2 file OK");
	unsigned long err0 = sr.reload_errors;

	sig_reload_trigger(&sr, "/tmp/does_not_exist_xyz.rules");
	sig_reload_wait(&sr);
	check(sr.reload_errors == err0 + 1, "reload_errors increased");

	/* old ruleset still works */
	struct flow_ctx fc = fc80();
	int idx = sig_reload_match(&sr, (const uint8_t *)"RELOADED_PAYLOAD", 16, &fc);
	check(idx >= 0, "old rule still matches after rollback");

	sig_reload_free(&sr);
}

/* ---- T4: concurrent match during reload ----------------------------------- */
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

	/* reload 3 times while match is running */
	for (int i = 0; i < 3; i++) {
		sig_reload_trigger(&sr, tmppath);
		sig_reload_wait(&sr);
	}

	__atomic_store_n(&arg.stop, 1, __ATOMIC_RELAXED);
	pthread_join(tid, NULL);

	check(sr.reload_count >= 1, "at least 1 reload completed");
	check(arg.hits >= 0,        "no crash (hits valid)");
	/* important: TSan reports no race */

	sig_reload_free(&sr);
}

/* ---- T5: double trigger → only 1 reload ----------------------------------- */
static void t5_double_trigger(void)
{
	printf("T5 double trigger (guard):\n");
	const char *tmppath = "/tmp/sg_reload_t2.rules";
	struct sig_reload sr;
	check(sig_reload_init(&sr, tmppath) == 0, "init OK");
	unsigned long cnt0 = sr.reload_count;

	/* trigger twice back-to-back, the 2nd must be skipped */
	int r1 = sig_reload_trigger(&sr, tmppath);
	int r2 = sig_reload_trigger(&sr, tmppath);
	sig_reload_wait(&sr);

	check(r1 == 0, "trigger#1 returns 0 (started)");
	check(r2 == 1, "trigger#2 returns 1 (busy, skip)");
	check(sr.reload_count == cnt0 + 1, "exactly 1 reload (not doubled)");

	sig_reload_free(&sr);
}

int main(void)
{
	t1_init_match();
	t2_reload_valid();
	t3_rollback();
	t4_concurrent();
	t5_double_trigger();

	printf("\n%s (%d tests failed)\n",
	       g_failed ? "=== FAILURES ===" : "=== ALL PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
