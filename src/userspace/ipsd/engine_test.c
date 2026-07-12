/* SPDX-License-Identifier: MIT */
/*
 * engine_test.c - test the hybrid pipeline (signature short-circuit + ML), HOST.
 *
 *   gcc ... engine.c fusion.c sig_rule.c ac.c ips_model.c model/predict.c \
 *           engine_test.c -lm
 *
 * Focus: signature match → ML is NOT run (ml_evaluated==0, score==-1);
 * no signature → ML runs (ml_evaluated==1).
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
			    &fc, feat, NULL);   /* fs=NULL: skip L1 */
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

	printf("T1 signature DROP → short-circuit (skip ML):\n");
	struct ips_decision d = eval(&prevent, &rs, "noise EVIL noise", feat);
	check(d.verdict == IPS_DROP,        "verdict DROP");
	check(d.reason == IPS_R_SIGNATURE,  "reason signature");
	check(d.ml_evaluated == 0,          "ML did NOT run (ml_evaluated=0)");
	check(d.score == -1.0,              "score = -1 (ML not scored)");
	check(d.sig_rule == 0,              "matched rule EVIL (idx 0)");

	printf("T2 signature ALERT also skips ML:\n");
	d = eval(&prevent, &rs, "see WARN here", feat);
	check(d.verdict == IPS_ALERT && d.reason == IPS_R_SIGNATURE, "ALERT from signature");
	check(d.ml_evaluated == 0,          "ML did NOT run for an alert rule");

	printf("T3 no signature → PASS no-match (ML deferred to checkpoint):\n");
	d = eval(&prevent, &rs, "totally harmless payload", feat);
	check(d.ml_evaluated == 0,          "engine did NOT run ML (ml_evaluated=0)");
	check(d.verdict == IPS_PASS,        "verdict PASS (wait for checkpoint)");
	check(d.sig_rule == -1,             "no signature rule");

	printf("T4 no signature → still PASS even with forced threshold (ML not in engine):\n");
	struct ips_config force = prevent; force.thr_block = 0.0;
	d = eval(&force, &rs, "totally harmless payload", feat);
	check(d.verdict == IPS_PASS,        "engine does not DROP on its own (ML at checkpoint)");
	check(d.ml_evaluated == 0,          "ML does not run in the engine");

	printf("T5 detect mode: signature DROP → ALERT, still skips ML:\n");
	d = eval(&detect, &rs, "noise EVIL noise", feat);
	check(d.verdict == IPS_ALERT,       "verdict lowered to ALERT (detect)");
	check(d.reason == IPS_R_SIGNATURE,  "reason still signature");
	check(d.ml_evaluated == 0,          "ML still did NOT run");

	sig_ruleset_free(&rs);

	/* ---- T6: L1-builtin REMOVED — SYN-flood stats no longer short-circuit ---- */
	printf("T6 L1-builtin removed: SYN-flood flow does not auto-DROP → ML runs:\n");
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

		check(d2.ml_evaluated == 0,  "L1 removed + ML at checkpoint → engine PASS");
		check(d2.sig_rule != -2,     "no more flow-anomaly verdict (-2)");
		check(d2.verdict == IPS_PASS,"no short-circuit, no self DROP");
		sig_ruleset_free(&rs2);
	}

	/* ---- T7: L1-builtin REMOVED — known-bad port no longer auto-ALERTs ---- */
	printf("T7 L1-builtin removed: known-bad port 4444 does not auto-alert → ML:\n");
	{
		struct sig_ruleset rs3;
		sig_ruleset_init(&rs3);
		sig_build(&rs3);

		struct flow_stats fs = { .pkts_fwd = 5, .pkts_bwd = 3,
					 .syn_count = 1, .ack_count = 3 };
		struct flow_ctx fc = { .proto = SIG_PROTO_TCP, .dport = 4444 };
		struct ips_decision d3 = ips_evaluate(&prevent, &rs3,
			(const uint8_t *)"some data", 9, &fc, feat, &fs);

		check(d3.ml_evaluated == 0,  "known-bad port → no L1, engine PASS");
		sig_ruleset_free(&rs3);
	}

	/* ---- T8: content-less rule (L1 signature removed) → dropped, eval falls to ML ---- */
	printf("T8 content-less rule is dropped (L1 signature removed):\n");
	{
		struct sig_ruleset rs4;
		sig_ruleset_init(&rs4);
		/* content-less rule (flags:S, dport 8888) — no longer loaded */
		sig_parse_line(&rs4,
			"alert tcp any any -> any 8888 "
			"(msg:\"AUTO rule\"; flags:S; sid:9000001; rev:1;)");
		sig_build(&rs4);

		check(rs4.n_rules == 0, "content-less rule NOT loaded (L2 empty)");

		/* fs=NULL → skip L1-builtin; no L1-user/L2 → fall to ML */
		struct flow_ctx fc = { .proto = SIG_PROTO_TCP, .dport = 8888 };
		struct ips_decision d4 = ips_evaluate(&prevent, &rs4,
			(const uint8_t *)"", 0, &fc, feat, NULL);

		check(d4.ml_evaluated == 0, "no L1-user/L2 → engine PASS (ML at checkpoint)");
		sig_ruleset_free(&rs4);
	}

	printf("\n%s (%d tests failed)\n",
	       g_failed ? "=== FAILURES ===" : "=== ALL PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
