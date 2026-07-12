/* SPDX-License-Identifier: MIT */
/*
 * feature.h - build the 17-feature vector for LightGBM from flow statistics.
 *
 * Three data sources (see docs/ips-master-plan.md §3.4 + ips-ipsd-progress):
 *   1) struct sg_nf_conn_ml  — raw accumulator from conntrack (via CTA_ML).
 *   2) pkts_fwd / pkts_bwd   — packet count per direction, from ACCT (CTA_COUNTERS).
 *   3) init_win_fwd          — TCP window of the forward SYN packet, from NFQUEUE
 *                              (-1 if unknown / not TCP).
 *
 * The order of the 17 elements MUST match feature_order.json (the model is
 * trained in this order).
 */
#ifndef SG_FEATURE_H
#define SG_FEATURE_H

#include <stdint.h>

#define FEAT_COUNT 17

/* index per feature_order.json — do not change the order. */
enum {
	FEAT_FLOW_IAT_STD = 0,
	FEAT_FLOW_IAT_MIN,
	FEAT_FLOW_IAT_MEAN,
	FEAT_FWD_IAT_STD,
	FEAT_PKTLEN_VAR,
	FEAT_PKTLEN_STD,
	FEAT_FWD_PKTLEN_MEAN,
	FEAT_BWD_PKTLEN_MEAN,
	FEAT_SYN_CNT,
	FEAT_ACK_CNT,
	FEAT_PSH_CNT,
	FEAT_URG_CNT,
	FEAT_DOWNUP_RATIO,
	FEAT_INIT_WIN_FWD,
	FEAT_TOTLEN_FWD,     /* Total Length of Fwd Packets = bytes_fwd (≡ Subflow F.Bytes) */
	FEAT_FLOW_DUR,       /* Flow Duration (µs) = last_ns - first_ns                     */
	FEAT_BWD_PKTLEN_STD, /* Bwd Packet Length Std: var(bytes_bwd, bwd_pktlen_sq_sum, pkts_bwd) */
};

/*
 * Mirror of the kernel `struct nf_conn_ml`
 * (stargazer-kernel/include/net/netfilter/nf_conntrack_ml.h).
 * MUST match byte-for-byte: ipsd memcpy's the CTA_ML payload straight into this
 * struct. Same order/types as the mirror in mgmtd_diag.c.
 */
struct sg_nf_conn_ml {
	uint64_t first_ns, last_ns, iat_sum_us;   /* iat_sum_us: microseconds */
	uint32_t iat_count;
	uint16_t tcp_flags[2];
	uint16_t len_min[2];                      /* L4 payload, per direction */
	uint16_t len_max[2];
	int32_t  ml_score;
	uint16_t iif, oif;
	uint64_t flow_iat_sq_sum;                 /* (µs)^2 */
	int64_t  last_seen_fwd;                   /* kernel ktime_t */
	uint64_t fwd_iat_sum, fwd_iat_sq_sum;     /* µs, (µs)^2 */
	uint64_t pktlen_sum, pktlen_sq_sum;       /* payload, both directions */
	uint64_t bytes_fwd, bytes_bwd;            /* payload per direction */
	uint32_t flow_iat_min;                    /* µs; UINT32_MAX = no gap yet */
	uint32_t fwd_iat_count;
	uint32_t syn_count, ack_count, psh_count, urg_count;
	uint32_t pktlen_count;                    /* payload sample count (both directions) */
	uint64_t bwd_pktlen_sq_sum;               /* reply-dir payload Σx² → Bwd Packet Length Std */
	uint32_t init_win_fwd;                    /* TCP window of the forward SYN (kernel-captured); 0 = not seen */
};

/*
 * Build the feature[17] vector. No allocation, no errors — always fills all 17
 * elements (safe value 0 / -1 when data is missing).
 */
void feature_extract(const struct sg_nf_conn_ml *ml,
		     uint32_t pkts_fwd, uint32_t pkts_bwd,
		     int32_t  init_win_fwd,
		     double   out[FEAT_COUNT]);

/* Feature names by index, for printing/logging/debugging. */
extern const char *const feature_names[FEAT_COUNT];

#endif /* SG_FEATURE_H */
