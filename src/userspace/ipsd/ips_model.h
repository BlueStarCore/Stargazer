/* SPDX-License-Identifier: MIT */
/*
 * ips_model.h - wrapper mỏng quanh model LightGBM đã convert sang C (tl2cgen).
 *
 * Code model nằm ở model/predict.{c,h} (SINH MÁY — không sửa tay). File này chỉ
 * bọc lại cho gọn: nhận vector 14 feature (đúng thứ tự feature.h) → trả xác suất.
 */
#ifndef SG_IPS_MODEL_H
#define SG_IPS_MODEL_H

#include "feature.h"   /* FEAT_COUNT */

/*
 * Chấm điểm anomaly cho một flow. Trả về xác suất ∈ [0,1] (model là binary
 * classifier 'binary sigmoid:1' → predict() với pred_margin=0 đã áp sigmoid).
 */
double ips_score(const double feat[FEAT_COUNT]);

#endif /* SG_IPS_MODEL_H */
