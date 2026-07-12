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
	double feat[FEAT_COUNT];
	ctdump_to_features(ctr, pkts_fwd, pkts_bwd, init_win, feat);

	double sc = ips_score(feat);
	struct ips_decision d = ips_fuse(cfg, -1, 0, sc);
	d.ml_evaluated = 1;
	d.score        = sc;
	return d;
}
