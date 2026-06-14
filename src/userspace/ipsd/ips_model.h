/* SPDX-License-Identifier: MIT */
/*
 * ips_model.h - thin wrapper around the LightGBM model converted to C (tl2cgen).
 *
 * The model code lives in model/predict.{c,h} (MACHINE-GENERATED — do not edit by hand).
 * This file just wraps it conveniently: takes a 14-feature vector (in feature.h order)
 * → returns a probability.
 */
#ifndef SG_IPS_MODEL_H
#define SG_IPS_MODEL_H

#include "feature.h"   /* FEAT_COUNT */

/*
 * Score the anomaly for a flow. Returns a probability in [0,1] (the model is a binary
 * classifier 'binary sigmoid:1' → predict() with pred_margin=0 has sigmoid applied).
 */
double ips_score(const double feat[FEAT_COUNT]);

#endif /* SG_IPS_MODEL_H */
