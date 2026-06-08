/* SPDX-License-Identifier: MIT */
/*
 * engine.c - pipeline phát hiện hybrid (xem engine.h).
 */
#include "engine.h"
#include "ips_model.h"   /* ips_score */

struct ips_decision ips_evaluate(const struct ips_config *cfg,
				 const struct sig_ruleset *rs,
				 const uint8_t *payload, size_t plen,
				 const struct flow_ctx *fc,
				 const double feat[FEAT_COUNT],
				 const struct flow_stats *fs)
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

	/* [L1-user] user-defined flow rules (từ rule_gen, không có content). */
	if (fs) {
		int l1_idx = sig_flow_match(rs, fc, fs);
		if (l1_idx >= 0) {
			int action = rs->l1_rules[l1_idx].action;
			struct ips_decision d = ips_fuse(cfg, l1_idx, action, -1.0);
			d.score        = -1.0;
			d.ml_evaluated = 0;
			return d;
		}
	}

	/* [L2] Payload signature (Aho-Corasick). SHORT-CIRCUIT nếu khớp. */
	int sig_idx = sig_match(rs, payload, plen, fc);
	if (sig_idx >= 0) {
		int action = rs->rules[sig_idx].action;
		struct ips_decision d = ips_fuse(cfg, sig_idx, action, -1.0);
		d.score        = -1.0;
		d.ml_evaluated = 0;
		return d;
	}

	/* [ML] Không signature nào khớp → chạy LightGBM để bắt zero-day. */
	double score = ips_score(feat);
	struct ips_decision d = ips_fuse(cfg, -1, 0, score);
	d.ml_evaluated = 1;
	return d;
}
