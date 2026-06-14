/* SPDX-License-Identifier: MIT */
/*
 * ips_model.c - wrapper around tl2cgen's predict() (see ips_model.h).
 */
#include "ips_model.h"
#include "model/predict.h"

double ips_score(const double feat[FEAT_COUNT])
{
	union Entry inst[FEAT_COUNT];
	double      out = 0.0;

	/* union Entry: set .fvalue = the "present" value. tl2cgen treats a feature as
	 * "missing" only when the low 4 bytes == -1 (0xFFFFFFFF) — which never happens
	 * with our value range, so every feature is used. Even feature 13 = -1.0
	 * (init-win unknown) is treated as the VALUE -1, exactly as at train time. */
	for (int i = 0; i < FEAT_COUNT; i++)
		inst[i].fvalue = feat[i];

	predict(inst, /*pred_margin=*/0, &out);   /* 0 → postprocess (sigmoid) applied */
	return out;
}
