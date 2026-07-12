/* SPDX-License-Identifier: MIT */
/*
 * engine.c - hybrid detection pipeline (see engine.h).
 */
#include "engine.h"
#include "ips_model.h"   /* ips_score */
#include <string.h>
#include <stdio.h>

/* Render content bytes Snort-style: printable kept as-is, the rest as |HH|. Used
 * for alerts of a rule WITHOUT a msg → still know which bytes matched (a clue for
 * tuning/FP). */
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
	/* L2 computed per-packet on the payload (l2_ready=0). */
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
	/* [L1] FULLY REMOVED — both L1-user signatures (content-less rules) and
	 * L1-builtin flow-anomaly (SYN-flood/port-scan/URG/ACK-flood/known-bad-port).
	 * Why builtin was removed: the per-flow heuristics judge the flow at SYN time
	 * → every legitimate new connection also looks like an "incomplete handshake"
	 * → mass false positives (port-scan flags every connection). The engine now
	 * keeps only: L2 payload signatures (Aho-Corasick on the reassembled stream)
	 * + ML (LightGBM). */
	(void)fs;   /* flow stats no longer used for L1; ML uses the precomputed `feat` */

	/* [L2] Payload signature. SHORT-CIRCUIT on a match.
	 *   l2_ready=1 (P1): result already computed on the reassembled STREAM in
	 *                    main.c (reass + streaming AC), action already
	 *                    fidelity-capped → use it directly.
	 *   l2_ready=0      : run Aho-Corasick on the payload per-packet (UDP/ICMP
	 *                    or non-reassembled path), fidelity-cap here. */
	int sig_idx, action;
	if (l2_ready) {
		sig_idx = l2_sig_idx;
		action  = l2_sig_action;
	} else {
		sig_idx = sig_match(rs, payload, plen, fc);
		action  = (sig_idx >= 0)
			? sig_eff_action(&rs->rules[sig_idx], fc ? fc->prof_id : 0)
			: 0;                            /* per-profile action */
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
			/* Rule lacks a msg → describe it by the matched content + index
			 * for tracing (a clue to "which signature matched" instead of
			 * leaving it blank). */
			char cb[72];
			render_content(&mr->content[mr->fast], cb, sizeof(cb));
			snprintf(d.matched_msg, sizeof(d.matched_msg),
				 "no-msg rule#%d content=\"%s\"", sig_idx, cb);
		}
		return d;
	}

	/* [ML] No signature matched → ML is NO LONGER scored here. ML is invoked at
	 * the min(N,K,T) CHECKPOINT in process_packet (main.c) — over the ACCUMULATED
	 * features of the whole flow + init_win cache, exactly once per flow. Here we
	 * return a "no-match" PASS (score=-1 → PASS); the checkpoint decides later. */
	(void)feat;
	struct ips_decision d = ips_fuse(cfg, -1, 0, -1.0);
	d.ml_evaluated = 0;
	return d;
}
