/* SPDX-License-Identifier: MIT */
/*
 * engine.c - pipeline phát hiện hybrid (xem engine.h).
 */
#include "engine.h"
#include "ips_model.h"   /* ips_score */
#include <string.h>

struct ips_decision ips_evaluate(const struct ips_config *cfg,
				 const struct sig_ruleset *rs,
				 const uint8_t *payload, size_t plen,
				 const struct flow_ctx *fc,
				 const double feat[FEAT_COUNT],
				 const struct flow_stats *fs)
{
	/* L2 tự tính trên payload per-packet (l2_ready=0). */
	return ips_evaluate_full(cfg, rs, payload, plen, fc, feat, fs,
				 0, -1, 0);
}

struct ips_decision ips_evaluate_full(const struct ips_config *cfg,
				 const struct sig_ruleset *rs,
				 const uint8_t *payload, size_t plen,
				 const struct flow_ctx *fc,
				 const double feat[FEAT_COUNT],
				 const struct flow_stats *fs,
				 int l2_ready, int l2_sig_idx,
				 int l2_sig_action)
{
	/* [L1-builtin] flow rule tích hợp: SYN-flood, port-scan, known-bad-port...
	 * Rẻ nhất: chỉ so sánh số nguyên, không đụng payload. */
	if (fs) {
		struct flow_rule_match fm;
		if (flow_rule_match_builtin(fc, fs, &fm) == 0) {
			struct ips_decision d = ips_fuse(cfg, 0, fm.action, -1.0);
			d.score        = -1.0;
			d.ml_evaluated = 0;
			/* dùng sig_rule == -2 để phân biệt với L2 (≥0) và no-match (-1) */
			d.sig_rule     = -2;
			return d;
		}
	}

	/* [L1-user signature] ĐÃ GỠ: engine chỉ còn signature dựa-content (L2).
	 * Rule không content không còn được nạp (xem sig_parse_line). */

	/* [L2] Payload signature. SHORT-CIRCUIT nếu khớp.
	 *   l2_ready=1 (P1): kết quả đã tính trên DÒNG đã ghép ở main.c (reass +
	 *                    streaming AC), action đã fidelity-cap → dùng thẳng.
	 *   l2_ready=0      : tự khớp Aho-Corasick trên payload per-packet (UDP/
	 *                    ICMP hoặc đường không reass), tự fidelity-cap. */
	int sig_idx, action;
	if (l2_ready) {
		sig_idx = l2_sig_idx;
		action  = l2_sig_action;
	} else {
		sig_idx = sig_match(rs, payload, plen, fc);
		action  = (sig_idx >= 0) ? rs->rules[sig_idx].action : 0;
		if (sig_idx >= 0 && rs->rules[sig_idx].fidelity == SIG_FID_ALERT)
			action = SIG_ALERT;
	}
	if (sig_idx >= 0) {
		struct ips_decision d = ips_fuse(cfg, sig_idx, action, -1.0);
		d.score        = -1.0;
		d.ml_evaluated = 0;
		d.matched_sid  = rs->rules[sig_idx].sid;
		strncpy(d.matched_msg, rs->rules[sig_idx].msg,
			sizeof(d.matched_msg) - 1);
		d.matched_msg[sizeof(d.matched_msg) - 1] = '\0';
		return d;
	}

	/* [ML] Không signature nào khớp → chạy LightGBM để bắt zero-day. */
	double score = ips_score(feat);
	struct ips_decision d = ips_fuse(cfg, -1, 0, score);
	d.ml_evaluated = 1;
	return d;
}
