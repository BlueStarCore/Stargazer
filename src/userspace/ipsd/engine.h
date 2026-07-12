/* SPDX-License-Identifier: MIT */
/*
 * engine.h - orchestrates the hybrid detection pipeline (signature → ML → fusion).
 *
 * INTENTIONAL ordering: signature runs FIRST. If a signature matches → decide
 * immediately from the signature and do NOT run ML (saves inference; a "known"
 * attack is blocked right away, no need for an anomaly score). Only when NO
 * signature matches do we score with ML and compare against the threshold. This
 * is the layer that ties sig_rule + ips_model + fusion together.
 */
#ifndef SG_ENGINE_H
#define SG_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "fusion.h"      /* ips_config, ips_decision */
#include "feature.h"     /* FEAT_COUNT */
#include "sig_rule.h"    /* sig_ruleset, flow_ctx */
#include "flow_rule.h"   /* flow_stats */

/*
 * Evaluate a flow/packet. Pipeline order:
 *   [L1-builtin]  flow_rule_match_builtin(fc, fs)     — anomaly (SYN-flood…), no payload
 *   [L2]          sig_match(rs, payload, plen, fc)     — Aho-Corasick payload (signature)
 *   [ML]          ips_score(feat)                      — LightGBM
 *
 * fs == NULL → skip both L1 layers (used when there are no flow stats).
 * Every layer short-circuits: on a match it returns immediately, skipping later layers.
 */
struct ips_decision ips_evaluate(const struct ips_config *cfg,
				 const struct sig_ruleset *rs,
				 const uint8_t *payload, size_t plen,
				 const struct flow_ctx *fc,
				 const double feat[FEAT_COUNT],
				 const struct flow_stats *fs);

/*
 * Variant for P1 reassembly: the L2 layer is ALREADY computed over the
 * REASSEMBLED STREAM (in main.c via reass + streaming AC), so sig_match is NOT
 * run per-packet.
 *   l2_ready    : 1 → use l2_sig_idx/l2_sig_action as the L2 result (already
 *                 fidelity-capped); 0 → behave like ips_evaluate (run sig_match
 *                 on the payload).
 *   l2_sig_idx  : index of the matched L2 rule (in rs->rules), -1 if no match.
 *   l2_sig_action: the rule's ALREADY-capped action (SIG_ALERT/SIG_DROP).
 * Order remains L1-builtin → L1-user → L2 → ML (L1 still takes priority over L2).
 */
struct ips_decision ips_evaluate_full(const struct ips_config *cfg,
				      const struct sig_ruleset *rs,
				      const uint8_t *payload, size_t plen,
				      const struct flow_ctx *fc,
				      const double feat[FEAT_COUNT],
				      const struct flow_stats *fs,
				      int l2_ready, int l2_sig_idx,
				      int l2_sig_action);

#endif /* SG_ENGINE_H */
