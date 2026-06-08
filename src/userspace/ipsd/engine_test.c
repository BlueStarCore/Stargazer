/* SPDX-License-Identifier: MIT */
/*
 * engine_test.c - test pipeline hybrid (signature short-circuit + ML), HOST.
 *
 *   gcc ... engine.c fusion.c sig_rule.c ac.c ips_model.c model/predict.c \
 *           engine_test.c -lm
 *
 * Trọng tâm: signature khớp → KHÔNG chạy ML (ml_evaluated==0, score==-1);
 * không signature → ML chạy (ml_evaluated==1).
 */
#include "engine.h"
#include "sig_rule.h"
#include "flow_rule.h"
#include "fusion.h"

#include <stdio.h>
#include <string.h>

static int g_failed;

static void check(int cond, const char *name)
{
	printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
	if (!cond) g_failed++;
}

static struct ips_decision eval(const struct ips_config *cfg,
				const struct sig_ruleset *rs, const char *payload,
				const double feat[FEAT_COUNT])
{
	struct flow_ctx fc = { .proto = SIG_PROTO_TCP, .dport = 0, .tcp_flags = 0 };
	return ips_evaluate(cfg, rs, (const uint8_t *)payload, strlen(payload),
			    &fc, feat, NULL);   /* fs=NULL: bỏ qua L1 */
}

int main(void)
{
	struct sig_ruleset rs;
	sig_ruleset_init(&rs);
	sig_parse_line(&rs, "drop tcp any any -> any any (msg:\"evil\"; content:\"EVIL\"; sid:1;)");
	sig_parse_line(&rs, "alert tcp any any -> any any (msg:\"warn\"; content:\"WARN\"; sid:2;)");
	sig_build(&rs);

	double feat[FEAT_COUNT] = {
		12.9099, 10, 25, 7.07107, 10000, 100, 200, 57.1429, 2, 5, 1, 0, 2, 8192,
	};

	struct ips_config prevent, detect;
	ips_config_default(&prevent);
	ips_config_default(&detect); detect.mode = IPS_MODE_DETECT;

	printf("T1 signature DROP → short-circuit (bỏ ML):\n");
	struct ips_decision d = eval(&prevent, &rs, "noise EVIL noise", feat);
	check(d.verdict == IPS_DROP,        "verdict DROP");
	check(d.reason == IPS_R_SIGNATURE,  "reason signature");
	check(d.ml_evaluated == 0,          "ML KHÔNG chạy (ml_evaluated=0)");
	check(d.score == -1.0,              "score = -1 (chưa chấm ML)");
	check(d.sig_rule == 0,              "khớp rule EVIL (idx 0)");

	printf("T2 signature ALERT cũng bỏ ML:\n");
	d = eval(&prevent, &rs, "see WARN here", feat);
	check(d.verdict == IPS_ALERT && d.reason == IPS_R_SIGNATURE, "ALERT do signature");
	check(d.ml_evaluated == 0,          "ML KHÔNG chạy với rule alert");

	printf("T3 không signature → ML chạy:\n");
	d = eval(&prevent, &rs, "totally harmless payload", feat);
	check(d.ml_evaluated == 1,          "ML CHẠY (ml_evaluated=1)");
	check(d.score >= 0.0 && d.score <= 1.0, "score ∈ [0,1]");
	check(d.sig_rule == -1,             "không rule signature nào");

	printf("T4 không signature + ngưỡng ép → ML DROP:\n");
	struct ips_config force = prevent; force.thr_block = 0.0;  /* mọi score ≥0 → DROP */
	d = eval(&force, &rs, "totally harmless payload", feat);
	check(d.verdict == IPS_DROP && d.reason == IPS_R_ML_BLOCK, "ML quyết DROP");
	check(d.ml_evaluated == 1,          "ML đã chạy");

	printf("T5 detect mode: signature DROP → ALERT, vẫn bỏ ML:\n");
	d = eval(&detect, &rs, "noise EVIL noise", feat);
	check(d.verdict == IPS_ALERT,       "verdict hạ xuống ALERT (detect)");
	check(d.reason == IPS_R_SIGNATURE,  "reason vẫn signature");
	check(d.ml_evaluated == 0,          "ML vẫn KHÔNG chạy");

	sig_ruleset_free(&rs);

	/* ---- T6: L1 built-in short-circuit (SYN flood) ---- */
	printf("T6 L1 built-in: SYN flood → DROP (bỏ ML và L2):\n");
	{
		struct sig_ruleset rs2;
		sig_ruleset_init(&rs2);
		sig_build(&rs2);

		struct flow_stats fs = {
			.syn_count = 50, .ack_count = 0,
			.pkts_fwd = 50,  .pkts_bwd = 0,
			.tcp_flags_fwd = SIG_TCP_SYN,
		};
		struct flow_ctx fc = { .proto = SIG_PROTO_TCP, .dport = 80 };
		struct ips_decision d2 = ips_evaluate(&prevent, &rs2,
			(const uint8_t *)"", 0, &fc, feat, &fs);

		check(d2.verdict == IPS_DROP,       "SYN flood → DROP");
		check(d2.ml_evaluated == 0,         "ML KHÔNG chạy (L1 short-circuit)");
		check(d2.score == -1.0,             "score = -1");
		sig_ruleset_free(&rs2);
	}

	/* ---- T7: L1 built-in: known-bad port → ALERT ---- */
	printf("T7 L1 built-in: known-bad port 4444 → ALERT:\n");
	{
		struct sig_ruleset rs3;
		sig_ruleset_init(&rs3);
		sig_build(&rs3);

		struct flow_stats fs = { .pkts_fwd = 5, .pkts_bwd = 3,
					 .syn_count = 1, .ack_count = 3 };
		struct flow_ctx fc = { .proto = SIG_PROTO_TCP, .dport = 4444 };
		struct ips_decision d3 = ips_evaluate(&prevent, &rs3,
			(const uint8_t *)"some data", 9, &fc, feat, &fs);

		check(d3.verdict == IPS_ALERT,      "dport 4444 → ALERT");
		check(d3.ml_evaluated == 0,         "ML KHÔNG chạy");
		sig_ruleset_free(&rs3);
	}

	/* ---- T8: L1 user-defined (rule_gen output không content) ---- */
	printf("T8 L1 user-defined: rule không content từ rule_gen:\n");
	{
		struct sig_ruleset rs4;
		sig_ruleset_init(&rs4);
		/* rule không content (flags:S, dport 8888) — kiểu output của rule_gen */
		sig_parse_line(&rs4,
			"alert tcp any any -> any 8888 "
			"(msg:\"AUTO rule\"; flags:S; sid:9000001; rev:1;)");
		sig_build(&rs4);

		check(rs4.n_l1 == 1, "rule không content vào l1_rules");
		check(rs4.n_rules == 0, "L2 rules vẫn rỗng");

		struct flow_stats fs = {
			/* pkts > PORT_SCAN_MAX_PKTS (3) để không bị built-in port-scan chặn trước */
			.syn_count = 1, .ack_count = 5, .pkts_fwd = 5, .pkts_bwd = 3,
			.tcp_flags_fwd = SIG_TCP_SYN | SIG_TCP_ACK,
		};
		struct flow_ctx fc = { .proto = SIG_PROTO_TCP, .dport = 8888 };
		struct ips_decision d4 = ips_evaluate(&prevent, &rs4,
			(const uint8_t *)"", 0, &fc, feat, &fs);

		check(d4.verdict == IPS_ALERT,      "user L1 rule khớp → ALERT");
		check(d4.ml_evaluated == 0,         "ML KHÔNG chạy");
		sig_ruleset_free(&rs4);
	}

	printf("\n%s (%d test thất bại)\n",
	       g_failed ? "=== CÓ LỖI ===" : "=== TẤT CẢ PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
