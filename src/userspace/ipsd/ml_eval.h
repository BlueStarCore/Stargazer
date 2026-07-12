/* SPDX-License-Identifier: MIT */
/*
 * ml_eval.h - shared ML scoring for ONE flow.
 *
 * Deduplicates the checkpoint scoring that lived in both main.c (NFQUEUE path)
 * and insp_ipc.c (ssld bump path), and is the single entry point reused by the
 * new cert-mode INSP_SCORE handler.
 *
 * Given a flow's conntrack snapshot (CTA_ML + packet counts), build the
 * 17-feature vector and run the LightGBM model, returning the fused decision.
 *
 * PURE COMPUTE: the CALLER does ctdump_query() first (netlink I/O, outside any
 * rwlock) and decides WHEN to score (the checkpoint trigger); this function only
 * does feature_extract + ips_score + ips_fuse.
 */
#ifndef SG_ML_EVAL_H
#define SG_ML_EVAL_H

#include <stdint.h>
#include "ctdump.h"   /* struct ctdump_result, ctdump_to_features */
#include "fusion.h"   /* struct ips_config, struct ips_decision, ips_fuse */

/*
 * Checkpoint thresholds — score EXACTLY ONCE per flow at the FIRST trigger.
 * Early triggers: N packets, plus FIN/RST and age (NFQUEUE has them) where
 * available. FINAL fallback: the signature scan window (REASS_MAX_BYTES = 16 KB)
 * is exhausted → the flow is about to be let go, so score ML now before it
 * escapes (see main.c NFQUEUE path and insp_ipc.c HTTPS leg). There is no
 * separate byte gate below 16 KB — the scan-window cap is the single byte trigger.
 * Shared here so every path (NFQUEUE / bump / cert-mode) agrees on the same caps.
 */
#define ML_CKP_PKTS    24u
#define ML_CKP_AGE_NS  12000000000ULL   /* 12 s (ns) */

struct ips_decision ips_ml_eval(const struct ctdump_result *ctr,
				uint32_t pkts_fwd, uint32_t pkts_bwd,
				int32_t  init_win,
				const struct ips_config *cfg);

#endif /* SG_ML_EVAL_H */
