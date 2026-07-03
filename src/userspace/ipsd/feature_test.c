/* SPDX-License-Identifier: MIT */
/*
 * feature_test.c - tests the arithmetic of the 17 features + edge cases, runs on HOST.
 *
 *   gcc -O2 -Wall -Wextra -fsanitize=address,undefined \
 *       -o /tmp/feature_test feature.c feature_test.c -lm && /tmp/feature_test
 *
 * Note: this tests FORMULA CORRECTNESS. End-to-end parity with CICFlowMeter
 * (whether the accumulators match) is a KERNEL-side test on real pcaps (QEMU) —
 * because feature.c only does arithmetic on the sums the kernel accumulates.
 */
#include "feature.h"

#include <stdio.h>
#include <string.h>
#include <math.h>

static int g_failed;

static void check(int cond, const char *name)
{
	printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
	if (!cond) g_failed++;
}

/* relative double comparison */
static int approx(double a, double b)
{
	double d = fabs(a - b);
	return d <= 1e-6 * (1.0 + fabs(b));
}

int main(void)
{
	double f[FEAT_COUNT];

	/* ---- T1: "normal" flow, numbers chosen to yield clean values ---- */
	/* Flow IAT gaps {10,20,30,40}: sum100 sqsum3000 → mean25, var=500/3, std≈12.9099
	 * Fwd IAT gaps {10,20}:        sum30  sqsum500  → var=50,    std≈7.07107
	 * Payload {100,200,300}:       sum600 sqsum140000 n3 → var10000, std100
	 * bytes_fwd600/pkts3=200 ; bytes_bwd400/pkts7≈57.142857
	 * Down/Up: 7/3 (integer)=2 */
	struct sg_nf_conn_ml ml = {0};
	ml.iat_count = 4;  ml.iat_sum_us = 100;  ml.flow_iat_sq_sum = 3000;  ml.flow_iat_min = 10;
	ml.fwd_iat_count = 2;  ml.fwd_iat_sum = 30;  ml.fwd_iat_sq_sum = 500;
	ml.pktlen_count = 3;  ml.pktlen_sum = 600;  ml.pktlen_sq_sum = 140000;
	ml.bytes_fwd = 600;  ml.bytes_bwd = 400;
	ml.syn_count = 2;  ml.ack_count = 5;  ml.psh_count = 1;  ml.urg_count = 0;

	feature_extract(&ml, /*pkts_fwd*/3, /*pkts_bwd*/7, /*init_win*/8192, f);

	printf("T1 basic arithmetic:\n");
	check(approx(f[FEAT_FLOW_IAT_MEAN], 25.0),            "Flow IAT Mean = 25 (µs)");
	check(approx(f[FEAT_FLOW_IAT_STD], sqrt(500.0/3.0)),  "Flow IAT Std = sqrt(500/3)");
	check(approx(f[FEAT_FLOW_IAT_MIN], 10.0),             "Flow IAT Min = 10");
	check(approx(f[FEAT_FWD_IAT_STD], sqrt(50.0)),        "Fwd IAT Std = sqrt(50)");
	check(approx(f[FEAT_PKTLEN_VAR], 10000.0),            "Packet Length Variance = 10000");
	check(approx(f[FEAT_PKTLEN_STD], 100.0),              "Packet Length Std = 100");
	check(approx(f[FEAT_FWD_PKTLEN_MEAN], 200.0),         "Fwd Pkt Len Mean = 600/3 = 200");
	check(approx(f[FEAT_BWD_PKTLEN_MEAN], 400.0/7.0),     "Bwd Pkt Len Mean = 400/7");
	check(approx(f[FEAT_SYN_CNT], 2.0) && approx(f[FEAT_ACK_CNT], 5.0) &&
	      approx(f[FEAT_PSH_CNT], 1.0) && approx(f[FEAT_URG_CNT], 0.0),
	      "Flag counts raw = 2/5/1/0");
	check(approx(f[FEAT_DOWNUP_RATIO], 2.0),              "Down/Up = 7/3 integer divide = 2");
	check(approx(f[FEAT_INIT_WIN_FWD], 8192.0),           "Init_Win_fwd = 8192");

	/* print the vector for visual inspection */
	printf("  vector: ");
	for (int i = 0; i < FEAT_COUNT; i++) printf("%g ", f[i]);
	printf("\n");

	/* ---- T2: empty flow (no gaps, no packets) → 0, no NaN ---- */
	struct sg_nf_conn_ml empty = {0};
	empty.flow_iat_min = UINT32_MAX;          /* sentinel: no gap yet */
	feature_extract(&empty, 0, 0, -1, f);

	printf("T2 empty flow:\n");
	int any_nan = 0, all_zero = 1;
	for (int i = 0; i < FEAT_COUNT; i++) {
		if (isnan(f[i]) || isinf(f[i])) any_nan = 1;
		if (i != FEAT_INIT_WIN_FWD && f[i] != 0.0) all_zero = 0;
	}
	check(!any_nan, "no NaN/Inf");
	check(all_zero, "all features (except init_win) = 0");
	check(approx(f[FEAT_FLOW_IAT_MIN], 0.0), "Flow IAT Min sentinel → 0");
	check(approx(f[FEAT_INIT_WIN_FWD], -1.0), "Init_Win unknown → -1");

	/* ---- T3: Down/Up must be INTEGER divide, not real ---- */
	feature_extract(&empty, /*fwd*/4, /*bwd*/9, -1, f);
	printf("T3 Down/Up integer divide:\n");
	check(approx(f[FEAT_DOWNUP_RATIO], 2.0), "9/4 = 2 (not 2.25)");

	printf("\n%s (%d tests failed)\n",
	       g_failed ? "=== FAILURES ===" : "=== ALL PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
