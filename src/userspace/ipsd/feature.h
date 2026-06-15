/* SPDX-License-Identifier: MIT */
/*
 * feature.h - dựng vector 14 feature cho LightGBM, từ thống kê flow.
 *
 * Ba nguồn dữ liệu (xem docs/ips-master-plan.md §3.4 + ips-ipsd-progress):
 *   1) struct sg_nf_conn_ml  — accumulator thô từ conntrack (qua CTA_ML).
 *   2) pkts_fwd / pkts_bwd   — số gói mỗi chiều, lấy từ ACCT (CTA_COUNTERS).
 *   3) init_win_fwd          — TCP window gói SYN forward, lấy từ NFQUEUE
 *                              (-1 nếu chưa biết / không phải TCP).
 *
 * Thứ tự 14 phần tử PHẢI khớp feature_order.json (model train theo thứ tự này).
 */
#ifndef SG_FEATURE_H
#define SG_FEATURE_H

#include <stdint.h>

#define FEAT_COUNT 17

/* index theo feature_order.json — đừng đổi thứ tự. */
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
	FEAT_TOTLEN_FWD,   /* Total Length of Fwd Packets = bytes_fwd (Infiltration) */
	FEAT_TOTLEN_BWD,   /* Total Length of Bwd Packets = bytes_bwd                */
	FEAT_FLOW_DUR,     /* Flow Duration (µs) = last_ns - first_ns                */
};

/*
 * Mirror của kernel `struct nf_conn_ml`
 * (stargazer-kernel/include/net/netfilter/nf_conntrack_ml.h).
 * PHẢI khớp byte-for-byte: ipsd memcpy thẳng payload CTA_ML vào struct này.
 * Cùng thứ tự/kiểu như bản mirror trong mgmtd_diag.c.
 */
struct sg_nf_conn_ml {
	uint64_t first_ns, last_ns, iat_sum_us;   /* iat_sum_us: micro-giây */
	uint32_t iat_count;
	uint16_t tcp_flags[2];
	uint16_t len_min[2];                      /* L4 payload, theo chiều */
	uint16_t len_max[2];
	int32_t  ml_score;
	uint16_t iif, oif;
	uint64_t flow_iat_sq_sum;                 /* (µs)^2 */
	int64_t  last_seen_fwd;                   /* kernel ktime_t */
	uint64_t fwd_iat_sum, fwd_iat_sq_sum;     /* µs, (µs)^2 */
	uint64_t pktlen_sum, pktlen_sq_sum;       /* payload, cả hai chiều */
	uint64_t bytes_fwd, bytes_bwd;            /* payload mỗi chiều */
	uint32_t flow_iat_min;                    /* µs; UINT32_MAX = chưa có gap */
	uint32_t fwd_iat_count;
	uint32_t syn_count, ack_count, psh_count, urg_count;
	uint32_t pktlen_count;                    /* số mẫu payload (cả hai chiều) */
};

/*
 * Dựng vector feature[14]. Không cấp phát, không lỗi — luôn điền đủ 14 phần tử
 * (giá trị an toàn 0 / -1 khi thiếu dữ liệu).
 */
void feature_extract(const struct sg_nf_conn_ml *ml,
		     uint32_t pkts_fwd, uint32_t pkts_bwd,
		     int32_t  init_win_fwd,
		     double   out[FEAT_COUNT]);

/* Tên feature theo đúng index, để in/log/debug. */
extern const char *const feature_names[FEAT_COUNT];

#endif /* SG_FEATURE_H */
