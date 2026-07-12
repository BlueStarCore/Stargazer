/* SPDX-License-Identifier: MIT */
/*
 * ml_eval.c - shared ML scoring for one flow (see ml_eval.h).
 */
#include "ml_eval.h"
#include "ips_model.h"   /* ips_score */
#include "feature.h"     /* FEAT_COUNT */

struct ips_decision ips_ml_eval(const struct ctdump_result *ctr,
				uint32_t pkts_fwd, uint32_t pkts_bwd,
				int32_t  init_win,
				const struct ips_config *cfg)
{
	/* Guard: never score an UNOBSERVED flow. The 17-feature vector is built from
	 * the kernel tap (nf_conn_ml). If the tap never saw this flow — an SSL flow
	 * while the LOCAL_IN/OUT tap (ml-https) is off, or any flow that never crossed
	 * pkt_forward — the vector is all-zero and the tree model extrapolates it to a
	 * bogus ~0.99 → a false alert/block. ml_account stamps first_ns on the first
	 * packet it accounts, so first_ns==0 means the tap never observed this flow:
	 * skip ML entirely and return a clean PASS (score -1 = "not evaluated"). */
	if (!ctr->ml_valid || ctr->ml.first_ns == 0) {
		struct ips_decision d = {
			.verdict = IPS_PASS, .reason = IPS_R_NONE,
			.sig_rule = -1, .score = -1.0, .ml_evaluated = 0,
		};
		return d;
	}

	double feat[FEAT_COUNT];
	ctdump_to_features(ctr, pkts_fwd, pkts_bwd, init_win, feat);

	double sc = ips_score(feat);
	struct ips_decision d = ips_fuse(cfg, -1, 0, sc);
	d.ml_evaluated = 1;
	d.score        = sc;
	return d;
}
