/* SPDX-License-Identifier: MIT */
/*
 * ips_model.c - wrapper quanh predict() của tl2cgen (xem ips_model.h).
 */
#include "ips_model.h"
#include "model/predict.h"

double ips_score(const double feat[FEAT_COUNT])
{
	union Entry inst[FEAT_COUNT];
	double      out = 0.0;

	/* union Entry: gán .fvalue = giá trị "có mặt". tl2cgen coi một feature là
	 * "missing" chỉ khi 4 byte thấp == -1 (0xFFFFFFFF) — không xảy ra với dải
	 * giá trị của ta, nên mọi feature đều được dùng. Riêng feature 13 = -1.0
	 * (init-win chưa biết) vẫn được coi là GIÁ TRỊ -1 đúng như lúc train. */
	for (int i = 0; i < FEAT_COUNT; i++)
		inst[i].fvalue = feat[i];

	predict(inst, /*pred_margin=*/0, &out);   /* 0 → postprocess (sigmoid) đã áp */
	return out;
}
