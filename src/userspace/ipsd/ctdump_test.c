/* SPDX-License-Identifier: MIT */
/*
 * ctdump_test.c - test parse + convert, chạy trên HOST (không cần kernel).
 *
 * Dựng buffer nlattr giả lập chứa CTA_ML + CTA_COUNTERS rồi gọi
 * ctdump_parse_response() để kiểm parser. Không cần socket netlink.
 *
 *   gcc -O2 -Wall -Wextra -std=c11 -fsanitize=address,undefined \
 *       -o /tmp/ctdump_test ctdump.c feature.c ctdump_test.c -lm
 */
#define _GNU_SOURCE
#include "ctdump.h"
#include "feature.h"
#include "flow_rule.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <endian.h>
#include <arpa/inet.h>
#include <linux/netlink.h>   /* struct nlattr, NLA_HDRLEN, NLA_ALIGN */

static int g_failed;

static void check(int cond, const char *name)
{
	printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
	if (!cond) g_failed++;
}

/* ---- builder NLA giả lập ------------------------------------------------- */

/* Khớp định nghĩa trong ctdump.c */
#define T_CTA_ML             27
#define T_CTA_COUNTERS_ORIG  9
#define T_CTA_COUNTERS_REPLY 10
#define T_CTA_COUNTERS_PKTS  1
#define T_NLA_F_NESTED       0x8000

static int buf_off;
static char buf[4096];

static void buf_reset(void) { buf_off = 0; memset(buf, 0, sizeof(buf)); }

/* ghi nlattr {type, data[len]} */
static void buf_nla(uint16_t type, const void *data, int len)
{
	struct nlattr *nla = (struct nlattr *)(buf + buf_off);
	nla->nla_len  = (uint16_t)(4 + len);
	nla->nla_type = type;
	if (len > 0) memcpy(buf + buf_off + 4, data, (size_t)len);
	buf_off += (int)NLA_ALIGN(4 + len);
}

static int buf_nest_start(uint16_t type)
{
	int off = buf_off;
	struct nlattr *nla = (struct nlattr *)(buf + buf_off);
	nla->nla_len  = 4;
	nla->nla_type = type | T_NLA_F_NESTED;
	buf_off += 4;
	return off;
}

static void buf_nest_end(int start)
{
	((struct nlattr *)(buf + start))->nla_len = (uint16_t)(buf_off - start);
}

static void buf_nla_be64(uint16_t type, uint64_t v)
{
	uint64_t be = htobe64(v);
	buf_nla(type, &be, 8);
}

/* ---- build fake ml struct ------------------------------------------------ */

static void fill_fake_ml(struct sg_nf_conn_ml *ml)
{
	memset(ml, 0, sizeof(*ml));
	ml->first_ns        = 1000000000ULL;
	ml->last_ns         = 2000000000ULL;
	ml->iat_sum_us      = 100;
	ml->iat_count       = 4;
	ml->flow_iat_sq_sum = 3000;
	ml->flow_iat_min    = 10;
	ml->fwd_iat_sum     = 30;
	ml->fwd_iat_sq_sum  = 500;
	ml->fwd_iat_count   = 2;
	ml->pktlen_sum      = 600;
	ml->pktlen_sq_sum   = 140000;
	ml->pktlen_count    = 3;
	ml->bytes_fwd       = 600;
	ml->bytes_bwd       = 400;
	ml->len_min[0]      = 100; ml->len_max[0] = 300;
	ml->len_min[1]      = 150; ml->len_max[1] = 250;
	ml->syn_count       = 1;
	ml->ack_count       = 3;
	ml->psh_count       = 1;
	ml->urg_count       = 0;
	ml->tcp_flags[0]    = 0x02 | 0x10;  /* SYN | ACK */
	ml->tcp_flags[1]    = 0x10;
}

/* ---- T1: parse CTA_ML ---------------------------------------------------- */
static void t1_parse_ml(void)
{
	printf("T1 parse CTA_ML:\n");
	buf_reset();

	struct sg_nf_conn_ml fake_ml;
	fill_fake_ml(&fake_ml);
	buf_nla(T_CTA_ML, &fake_ml, sizeof(fake_ml));

	struct ctdump_result r;
	int rc = ctdump_parse_response(buf, buf_off, &r);

	check(rc == 0,               "parse trả 0");
	check(r.ml_valid == 1,       "ml_valid = 1");
	check(r.ml.iat_count == 4,   "iat_count khớp");
	check(r.ml.syn_count == 1,   "syn_count khớp");
	check(r.ml.bytes_fwd == 600, "bytes_fwd khớp");
	check(r.acct_valid == 0,     "acct_valid = 0 (không có COUNTERS)");
}

/* ---- T2: parse CTA_ML + CTA_COUNTERS ------------------------------------- */
static void t2_parse_counters(void)
{
	printf("T2 parse CTA_ML + CTA_COUNTERS:\n");
	buf_reset();

	struct sg_nf_conn_ml fake_ml;
	fill_fake_ml(&fake_ml);
	buf_nla(T_CTA_ML, &fake_ml, sizeof(fake_ml));

	int co = buf_nest_start(T_CTA_COUNTERS_ORIG);
	buf_nla_be64(T_CTA_COUNTERS_PKTS, 50);
	buf_nest_end(co);

	int cr = buf_nest_start(T_CTA_COUNTERS_REPLY);
	buf_nla_be64(T_CTA_COUNTERS_PKTS, 30);
	buf_nest_end(cr);

	struct ctdump_result r;
	ctdump_parse_response(buf, buf_off, &r);

	check(r.ml_valid == 1,        "ml_valid");
	check(r.acct_valid == 1,      "acct_valid = 1");
	check(r.pkts_orig == 50,      "pkts_orig = 50");
	check(r.pkts_reply == 30,     "pkts_reply = 30");
}

/* ---- T3: không có CTA_ML → ml_valid = 0 --------------------------------- */
static void t3_no_ml(void)
{
	printf("T3 không có CTA_ML:\n");
	buf_reset();

	int co = buf_nest_start(T_CTA_COUNTERS_ORIG);
	buf_nla_be64(T_CTA_COUNTERS_PKTS, 10);
	buf_nest_end(co);

	struct ctdump_result r;
	ctdump_parse_response(buf, buf_off, &r);
	check(r.ml_valid == 0,  "ml_valid = 0");
	check(r.acct_valid == 1, "acct_valid = 1 (COUNTERS có)");
}

/* ---- T4: ctdump_to_flow_stats ------------------------------------------- */
static void t4_to_flow_stats(void)
{
	printf("T4 ctdump_to_flow_stats:\n");
	struct ctdump_result r;
	memset(&r, 0, sizeof(r));
	r.ml_valid    = 1;
	r.acct_valid  = 1;
	r.pkts_orig   = 25;
	r.pkts_reply  = 15;
	r.ml.syn_count      = 2;
	r.ml.ack_count      = 10;
	r.ml.psh_count      = 3;
	r.ml.urg_count      = 0;
	r.ml.tcp_flags[0]   = 0x12;  /* SYN|ACK */
	r.ml.tcp_flags[1]   = 0x10;

	struct flow_stats fs;
	ctdump_to_flow_stats(&r, &fs);

	check(fs.pkts_fwd == 25,           "pkts_fwd từ ACCT = 25");
	check(fs.pkts_bwd == 15,           "pkts_bwd từ ACCT = 15");
	check(fs.syn_count == 2,           "syn_count khớp");
	check(fs.tcp_flags_fwd == 0x12,    "tcp_flags_fwd khớp");
}

/* ---- T5: ctdump_to_features → feature_extract --------------------------- */
static void t5_to_features(void)
{
	printf("T5 ctdump_to_features (pipeline):\n");
	struct ctdump_result r;
	memset(&r, 0, sizeof(r));
	r.ml_valid   = 1;
	r.acct_valid = 1;
	r.pkts_orig  = 3;
	r.pkts_reply = 7;

	struct sg_nf_conn_ml *ml = &r.ml;
	ml->iat_count = 4; ml->iat_sum_us = 100; ml->flow_iat_sq_sum = 3000; ml->flow_iat_min = 10;
	ml->fwd_iat_count = 2; ml->fwd_iat_sum = 30; ml->fwd_iat_sq_sum = 500;
	ml->pktlen_count = 3; ml->pktlen_sum = 600; ml->pktlen_sq_sum = 140000;
	ml->bytes_fwd = 600; ml->bytes_bwd = 400;
	ml->syn_count = 2; ml->ack_count = 5; ml->psh_count = 1;

	double feat[FEAT_COUNT];
	ctdump_to_features(&r, (uint32_t)r.pkts_orig, (uint32_t)r.pkts_reply,
			   8192, feat);

	check(feat[FEAT_FLOW_IAT_MEAN] > 0,     "Flow IAT Mean > 0");
	check(feat[FEAT_FWD_PKTLEN_MEAN] == 200.0, "Fwd Pkt Mean = 600/3 = 200");
	check(feat[FEAT_BWD_PKTLEN_MEAN] > 57.0 && feat[FEAT_BWD_PKTLEN_MEAN] < 58.0,
	      "Bwd Pkt Mean ≈ 400/7");
	check(feat[FEAT_DOWNUP_RATIO] == 2.0,   "Down/Up = 7/3 chia nguyên = 2");
	check(feat[FEAT_INIT_WIN_FWD] == 8192.0,"Init_Win_fwd = 8192");
	check(feat[FEAT_SYN_CNT] == 2.0,        "SYN count = 2");
}

/* ---- T6: buffer NULL / rỗng --------------------------------------------- */
static void t6_edge(void)
{
	printf("T6 edge cases:\n");
	struct ctdump_result r;

	check(ctdump_parse_response(NULL, 0, &r) == -1, "NULL → -1");
	check(ctdump_parse_response(buf, 0, &r) == -1,   "len=0 → -1");

	/* buf hợp lệ nhưng không chứa attr nào quen */
	buf_reset();
	char junk[4] = {1, 2, 3, 4};
	buf_nla(99, junk, 4);   /* attr type lạ */
	int rc = ctdump_parse_response(buf, buf_off, &r);
	check(rc == 0,           "attr lạ → parse OK (không crash)");
	check(r.ml_valid == 0,   "ml_valid = 0 (không có CTA_ML)");
}

int main(void)
{
	t1_parse_ml();
	t2_parse_counters();
	t3_no_ml();
	t4_to_flow_stats();
	t5_to_features();
	t6_edge();

	printf("\n%s (%d test thất bại)\n",
	       g_failed ? "=== CÓ LỖI ===" : "=== TẤT CẢ PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
