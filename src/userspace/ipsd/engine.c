/* SPDX-License-Identifier: MIT */
/*
 * engine.c - pipeline phát hiện hybrid (xem engine.h).
 */
#include "engine.h"
#include "ips_model.h"   /* ips_score */
#include <string.h>
#include <stdio.h>

/* Render content bytes kiểu Snort: in được giữ nguyên, còn lại |HH|. Dùng cho
 * alert của rule KHÔNG có msg → vẫn biết byte nào khớp (manh mối tuning/FP). */
static void render_content(const struct sig_content *c, char *out, size_t outsz)
{
	size_t o = 0;
	if (!c || !c->data || outsz == 0) { if (outsz) out[0] = '\0'; return; }
	for (int i = 0; i < c->len && o + 5 < outsz; i++) {
		uint8_t b = c->data[i];
		if (b >= 0x20 && b < 0x7f && b != '"' && b != '\\' && b != '|')
			out[o++] = (char)b;
		else
			o += (size_t)snprintf(out + o, outsz - o, "|%02x|", b);
	}
	out[o] = '\0';
}

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
	/* [L1] ĐÃ GỠ HOÀN TOÀN — cả L1-user signature (rule không content) lẫn
	 * L1-builtin flow-anomaly (SYN-flood/port-scan/URG/ACK-flood/known-bad-port).
	 * Lý do gỡ builtin: các heuristic per-flow đánh giá flow tại thời điểm SYN
	 * → mọi kết nối hợp lệ mới cũng trông như "handshake chưa xong" → false
	 * positive hàng loạt (port-scan flag mọi kết nối). Engine giờ chỉ còn:
	 * L2 payload signature (Aho-Corasick trên dòng đã ghép) + ML (LightGBM). */
	(void)fs;   /* không còn dùng flow stats cho L1; ML dùng `feat` đã tính sẵn */

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
		const struct sig_rule *mr = &rs->rules[sig_idx];
		d.matched_sid = mr->sid;
		if (mr->msg[0]) {
			strncpy(d.matched_msg, mr->msg, sizeof(d.matched_msg) - 1);
			d.matched_msg[sizeof(d.matched_msg) - 1] = '\0';
		} else {
			/* Rule thiếu msg → mô tả bằng nội dung khớp + index để truy vết
			 * (manh mối "signature nào match" thay vì để trống). */
			char cb[72];
			render_content(&mr->content[mr->fast], cb, sizeof(cb));
			snprintf(d.matched_msg, sizeof(d.matched_msg),
				 "no-msg rule#%d content=\"%s\"", sig_idx, cb);
		}
		return d;
	}

	/* [ML] Không signature khớp → KHÔNG chấm ML ở đây nữa. ML được gọi tại
	 * CHECKPOINT min(N,K,T) trong process_packet (main.c) — trên feature TÍCH
	 * LŨY của cả flow + init_win cache, đúng 1 lần/flow. Ở đây trả PASS
	 * "no-match" (score=-1 → PASS), checkpoint sẽ quyết sau. */
	(void)feat;
	struct ips_decision d = ips_fuse(cfg, -1, 0, -1.0);
	d.ml_evaluated = 0;
	return d;
}
