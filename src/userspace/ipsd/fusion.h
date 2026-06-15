/* SPDX-License-Identifier: MIT */
/*
 * fusion.h - combine signature + ML results into a final verdict (decision fusion).
 *
 * Core contribution of the hybrid IPS: signature (known, low FP) and ML (novel/zero-
 * day) complement each other. Rule: take the MOST SEVERE level of the two sources;
 * mode `detect` downgrades every DROP to ALERT (log only, no blocking).
 *
 * Model label: class 1 = ATTACK (notebook: 0=BENIGN, 1=attack) → HIGH score =
 * attack → block when score >= thr_block. Default thr_block=0.95 (THRESHOLD at
 * train time), thr_alert=0.50.
 */
#ifndef SG_FUSION_H
#define SG_FUSION_H

#include <stdint.h>

/* Values increase with severity for direct comparison. */
enum ips_verdict { IPS_PASS = 0, IPS_ALERT = 1, IPS_DROP = 2 };
enum ips_mode    { IPS_MODE_DETECT = 0, IPS_MODE_PREVENT = 1 };
enum ips_reason  { IPS_R_NONE = 0, IPS_R_SIGNATURE, IPS_R_ML_BLOCK, IPS_R_ML_ALERT,
		   IPS_R_FLOW_ANOMALY };

struct ips_config {
	int    mode;        /* IPS_MODE_*                                      */
	double thr_block;   /* score >= → DROP  (default 0.95)                 */
	double thr_alert;   /* score >= → ALERT (default 0.50)                 */
};

struct ips_decision {
	int      verdict;           /* enum ips_verdict — mode applied                  */
	int      reason;            /* enum ips_reason — detection reason (before downgrade) */
	int      sig_rule;          /* index of matched signature rule, -1 if none      */
	double   score;             /* ML score = P(attack); -1 if ML did not run       */
	int      ml_evaluated;      /* 1 if ML was scored; 0 if skipped (signature short-circuit) */
	uint32_t matched_sid;       /* SID of matched rule; 0 = none / ML-only          */
	char     matched_msg[128];  /* msg of matched rule; empty if ML-only            */
};

/* Set default config: prevent, block 0.95, alert 0.50. */
void ips_config_default(struct ips_config *cfg);

/*
 * Fuse one verdict. sig_idx = result of sig_match() (-1 if no match);
 * sig_action = action of the matched rule (SIG_DROP/SIG_ALERT), only considered when sig_idx>=0;
 * score = ips_score() in [0,1].
 */
struct ips_decision ips_fuse(const struct ips_config *cfg,
			     int sig_idx, int sig_action, double score);

const char *ips_verdict_str(int v);
const char *ips_reason_str(int r);

#endif /* SG_FUSION_H */
