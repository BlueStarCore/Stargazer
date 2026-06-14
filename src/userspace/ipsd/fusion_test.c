/* SPDX-License-Identifier: MIT */
/*
 * fusion_test.c - kiểm bảng quyết định fusion, chạy trên HOST.
 *
 *   gcc -O2 -Wall -Wextra -fsanitize=address,undefined \
 *       -o /tmp/fusion_test fusion.c fusion_test.c && /tmp/fusion_test
 */
#include "fusion.h"
#include "sig_rule.h"   /* SIG_DROP / SIG_ALERT */

#include <stdio.h>

static int g_failed;

/* kiểm verdict + reason cho một lần fuse */
static void expect(const struct ips_config *cfg, int sig_idx, int sig_action,
		   double score, int want_verdict, int want_reason, const char *name)
{
	struct ips_decision d = ips_fuse(cfg, sig_idx, sig_action, score);
	int ok = (d.verdict == want_verdict && d.reason == want_reason);

	printf("  [%s] %-46s → %s/%s\n", ok ? "PASS" : "FAIL", name,
	       ips_verdict_str(d.verdict), ips_reason_str(d.reason));
	if (!ok) {
		printf("        kỳ vọng %s/%s\n",
		       ips_verdict_str(want_verdict), ips_reason_str(want_reason));
		g_failed++;
	}
}

int main(void)
{
	struct ips_config prevent, detect;
	ips_config_default(&prevent);                 /* prevent, 0.95 / 0.50 */
	ips_config_default(&detect);
	detect.mode = IPS_MODE_DETECT;

	const int NO = -1;          /* không có signature khớp */
	const int HIT = 0;          /* có rule khớp (index 0)  */

	printf("PREVENT — chỉ ML:\n");
	expect(&prevent, NO, 0, 0.99, IPS_DROP,  IPS_R_ML_BLOCK, "ML 0.99 → DROP");
	expect(&prevent, NO, 0, 0.70, IPS_ALERT, IPS_R_ML_ALERT, "ML 0.70 → ALERT");
	expect(&prevent, NO, 0, 0.10, IPS_PASS,  IPS_R_NONE,     "ML 0.10 → PASS");

	printf("PREVENT — biên ngưỡng:\n");
	expect(&prevent, NO, 0, 0.95, IPS_DROP,  IPS_R_ML_BLOCK, "ML =0.95 → DROP (>=)");
	expect(&prevent, NO, 0, 0.50, IPS_ALERT, IPS_R_ML_ALERT, "ML =0.50 → ALERT (>=)");
	expect(&prevent, NO, 0, 0.4999, IPS_PASS, IPS_R_NONE,    "ML <0.50 → PASS");

	printf("PREVENT — chỉ signature:\n");
	expect(&prevent, HIT, SIG_DROP,  0.10, IPS_DROP,  IPS_R_SIGNATURE, "sig DROP, ML thấp → DROP");
	expect(&prevent, HIT, SIG_ALERT, 0.10, IPS_ALERT, IPS_R_SIGNATURE, "sig ALERT, ML thấp → ALERT");

	printf("PREVENT — kết hợp (lấy mức nặng nhất):\n");
	expect(&prevent, HIT, SIG_ALERT, 0.99, IPS_DROP, IPS_R_ML_BLOCK,  "sig ALERT + ML 0.99 → DROP (ML leo thang)");
	expect(&prevent, HIT, SIG_DROP,  0.99, IPS_DROP, IPS_R_SIGNATURE, "sig DROP + ML 0.99 → DROP (sig dẫn khi hoà)");

	printf("DETECT — không bao giờ chặn:\n");
	expect(&detect, HIT, SIG_DROP, 0.10, IPS_ALERT, IPS_R_SIGNATURE, "sig DROP → ALERT (hạ cấp), lý do giữ");
	expect(&detect, NO,  0,        0.99, IPS_ALERT, IPS_R_ML_BLOCK,  "ML 0.99 → ALERT (hạ cấp)");
	expect(&detect, NO,  0,        0.10, IPS_PASS,  IPS_R_NONE,      "ML thấp → PASS");

	printf("\n%s (%d test thất bại)\n",
	       g_failed ? "=== CÓ LỖI ===" : "=== TẤT CẢ PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
