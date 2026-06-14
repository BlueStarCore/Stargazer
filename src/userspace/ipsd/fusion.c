/* SPDX-License-Identifier: MIT */
/*
 * fusion.c - decision fusion (xem fusion.h).
 */
#include "fusion.h"
#include "sig_rule.h"   /* SIG_DROP / SIG_ALERT */

void ips_config_default(struct ips_config *cfg)
{
	cfg->mode      = IPS_MODE_PREVENT;
	cfg->thr_block = 0.95;   /* = THRESHOLD lúc train */
	cfg->thr_alert = 0.50;
}

struct ips_decision ips_fuse(const struct ips_config *cfg,
			     int sig_idx, int sig_action, double score)
{
	struct ips_decision d = {
		.verdict = IPS_PASS, .reason = IPS_R_NONE,
		.sig_rule = sig_idx, .score = score, .ml_evaluated = 0,
	};

	/* Mức nặng do từng nguồn đề xuất. */
	int sig_v = IPS_PASS;
	if (sig_idx >= 0)
		sig_v = (sig_action == SIG_DROP) ? IPS_DROP : IPS_ALERT;

	int ml_v = IPS_PASS;
	if (score >= cfg->thr_block)
		ml_v = IPS_DROP;
	else if (score >= cfg->thr_alert)
		ml_v = IPS_ALERT;

	/* Lấy mức nặng nhất. */
	int final = sig_v > ml_v ? sig_v : ml_v;

	/* Gán lý do: signature được ưu tiên khi nó "dẫn" (nặng ≥ ML). */
	if (final == IPS_PASS)
		d.reason = IPS_R_NONE;
	else if (sig_v >= ml_v && sig_idx >= 0)
		d.reason = IPS_R_SIGNATURE;
	else
		d.reason = (final == IPS_DROP) ? IPS_R_ML_BLOCK : IPS_R_ML_ALERT;

	/* Mode detect: không bao giờ chặn — hạ DROP xuống ALERT (giữ nguyên lý do). */
	if (cfg->mode == IPS_MODE_DETECT && final == IPS_DROP)
		final = IPS_ALERT;

	d.verdict = final;
	return d;
}

const char *ips_verdict_str(int v)
{
	switch (v) {
	case IPS_PASS:  return "PASS";
	case IPS_ALERT: return "ALERT";
	case IPS_DROP:  return "DROP";
	default:        return "?";
	}
}

const char *ips_reason_str(int r)
{
	switch (r) {
	case IPS_R_NONE:     return "none";
	case IPS_R_SIGNATURE:return "signature";
	case IPS_R_ML_BLOCK: return "ml-block";
	case IPS_R_ML_ALERT: return "ml-alert";
	case IPS_R_FLOW_ANOMALY: return "flow-anomaly";
	default:             return "?";
	}
}
