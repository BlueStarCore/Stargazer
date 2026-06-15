/* SPDX-License-Identifier: MIT */
/*
 * feature.c - 14 features for LightGBM (see feature.h).
 *
 * All features computed as double (userspace, not bound by the kernel's
 * no-float rule). Formulas follow the EXACT CICFlowMeter definitions — the
 * model is trained on its output, so the runtime must match:
 *   - variance/standard deviation use the SAMPLE form (divide by n-1), like
 *     SummaryStatistics.
 *   - Down/Up Ratio = INTEGER divide (bwd/fwd) and only then cast to double.
 *   - Flag Count kept RAW (not clamped to 0/1) — the tree handles values
 *     outside the training range itself.
 *   - Init_Win_bytes_forward = -1 when absent (matches feature_infos [-1:65535]).
 */
#include "feature.h"

#include <math.h>
#include <stddef.h>

const char *const feature_names[FEAT_COUNT] = {
	"Flow IAT Std", "Flow IAT Min", "Flow IAT Mean", "Fwd IAT Std",
	"Packet Length Variance", "Packet Length Std",
	"Fwd Packet Length Mean", "Bwd Packet Length Mean",
	"SYN Flag Count", "ACK Flag Count", "PSH Flag Count", "URG Flag Count",
	"Down/Up Ratio", "Init_Win_bytes_forward",
};

/*
 * SAMPLE variance: var = (Σx² − (Σx)²/n) / (n−1). n<2 → 0 (CICFlowMeter also
 * returns 0/NaN→0 when fewer than 2 samples). Clamp negatives from
 * floating-point rounding error.
 */
static double sample_var(double sum, double sqsum, uint64_t n)
{
	double v;

	if (n < 2)
		return 0.0;
	v = (sqsum - sum * sum / (double)n) / (double)(n - 1);
	return v > 0.0 ? v : 0.0;
}

/* Mirror struct must match the kernel size; catch layout drift at build time.
 * 144 bytes on LP64 (x86-64 host + aarch64 target, same alignment rules). */
_Static_assert(sizeof(struct sg_nf_conn_ml) == 144,
	       "sg_nf_conn_ml layout differs from kernel nf_conn_ml — recheck field types/order");

void feature_extract(const struct sg_nf_conn_ml *ml,
		     uint32_t pkts_fwd, uint32_t pkts_bwd,
		     int32_t init_win_fwd, double out[FEAT_COUNT])
{
	/* --- Flow IAT (µs; iat_sum_us is already µs in the kernel) --- */
	double iat_sum = (double)ml->iat_sum_us;

	out[FEAT_FLOW_IAT_STD]  = sqrt(sample_var(iat_sum,
				       (double)ml->flow_iat_sq_sum, ml->iat_count));
	out[FEAT_FLOW_IAT_MIN]  = (ml->flow_iat_min == UINT32_MAX)
				  ? 0.0 : (double)ml->flow_iat_min;
	out[FEAT_FLOW_IAT_MEAN] = ml->iat_count
				  ? iat_sum / (double)ml->iat_count : 0.0;

	/* --- Fwd IAT (forward direction only) --- */
	out[FEAT_FWD_IAT_STD] = sqrt(sample_var((double)ml->fwd_iat_sum,
				     (double)ml->fwd_iat_sq_sum, ml->fwd_iat_count));

	/* --- Packet Length (payload, both directions) --- */
	double pvar = sample_var((double)ml->pktlen_sum,
				 (double)ml->pktlen_sq_sum, ml->pktlen_count);
	out[FEAT_PKTLEN_VAR] = pvar;
	out[FEAT_PKTLEN_STD] = sqrt(pvar);

	/* --- Mean payload per direction (packet counts from ACCT) --- */
	out[FEAT_FWD_PKTLEN_MEAN] = pkts_fwd
				    ? (double)ml->bytes_fwd / (double)pkts_fwd : 0.0;
	out[FEAT_BWD_PKTLEN_MEAN] = pkts_bwd
				    ? (double)ml->bytes_bwd / (double)pkts_bwd : 0.0;

	/* --- Flag counts (raw) --- */
	out[FEAT_SYN_CNT] = (double)ml->syn_count;
	out[FEAT_ACK_CNT] = (double)ml->ack_count;
	out[FEAT_PSH_CNT] = (double)ml->psh_count;
	out[FEAT_URG_CNT] = (double)ml->urg_count;

	/* --- Down/Up Ratio = INTEGER divide bwd/fwd then cast to double (matches CICFlowMeter) --- */
	out[FEAT_DOWNUP_RATIO] = pkts_fwd ? (double)(pkts_bwd / pkts_fwd) : 0.0;

	/* --- Init window forward; -1 if unknown --- */
	out[FEAT_INIT_WIN_FWD] = (init_win_fwd < 0) ? -1.0 : (double)init_win_fwd;
}
