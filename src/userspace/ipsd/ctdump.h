/* SPDX-License-Identifier: MIT */
/*
 * ctdump.h - query conntrack cho một flow cụ thể qua ctnetlink.
 *
 * ipsd dùng module này để lấy CTA_ML (14 ML feature accumulators) và
 * CTA_COUNTERS (pkts_fwd / pkts_bwd từ ACCT extension) sau khi nhận gói
 * từ NFQUEUE. Kết quả nạp vào feature_extract() để tính vector 14 feature.
 *
 * Thiết kế: tách parse khỏi I/O → ctdump_parse_response() thuần hàm trên
 * buffer, test được trên host mà không cần kernel; ctdump_query() lo phần
 * socket netlink.
 *
 * Tái dùng hằng số và convention từ mgmtd_diag.c (sg_nla_find, SG_CTA_*).
 */
#ifndef SG_CTDUMP_H
#define SG_CTDUMP_H

#include <stdint.h>
#include "feature.h"   /* struct sg_nf_conn_ml */

/* ---- kết quả một lần query ----------------------------------------------- */

struct ctdump_result {
	struct sg_nf_conn_ml ml;       /* CTA_ML: ML feature vector            */
	int      ml_valid;             /* 1 nếu CTA_ML có trong response        */

	uint64_t pkts_orig;            /* CTA_COUNTERS_ORIG  → packets forward  */
	uint64_t pkts_reply;           /* CTA_COUNTERS_REPLY → packets backward */
	int      acct_valid;           /* 1 nếu CTA_COUNTERS có (CONFIG_NF_CONNTRACK_ACCT) */
};

/* ---- API ------------------------------------------------------------------ */

/*
 * Parse một nlmsghdr response (payload = attrs sau nfgenmsg). Điền *out.
 * Trả 0 nếu OK (kể cả khi một số field vắng mặt — xem *_valid), -1 nếu
 * message không phải CT_GET reply hợp lệ.
 *
 * Hàm này THUẦN (không I/O) → test được trên host với buffer giả lập.
 * attrs_data / attrs_len: con trỏ tới phần nlattr sau nfgenmsg header.
 */
int ctdump_parse_response(const void *attrs_data, int attrs_len,
			  struct ctdump_result *out);

/*
 * Mở AF_NETLINK socket, gửi CT_GET (targeted — không DUMP), đợi response,
 * gọi ctdump_parse_response().
 *
 * src_ip / dst_ip: IPv4 in host byte order.
 * sport / dport:   in host byte order.
 * proto:           IPPROTO_TCP / IPPROTO_UDP / IPPROTO_ICMP.
 *
 * Trả 0 nếu tìm thấy flow + fill *out, -1 nếu không tìm thấy hoặc lỗi.
 */
int ctdump_query(uint32_t src_ip, uint32_t dst_ip,
		 uint16_t sport,  uint16_t dport,
		 uint8_t  proto,
		 struct ctdump_result *out);

/* ---- dump TẤT CẢ flow (cho vòng ML scoring) ------------------------------ */

/* Một flow trong dump: 5-tuple (host order) + kết quả CTA_ML/counters. */
struct ctdump_flow {
	uint32_t src_ip, dst_ip;     /* host byte order */
	uint16_t sport,  dport;      /* host byte order */
	uint8_t  proto;
	struct ctdump_result res;
};

/* Callback gọi cho mỗi flow trong dump. Trả 0 để tiếp tục, !=0 để dừng sớm. */
typedef int (*ctdump_flow_cb)(const struct ctdump_flow *f, void *ctx);

/*
 * Gửi CT_GET với NLM_F_DUMP (lấy mọi flow), parse tuple + CTA_ML từng entry,
 * gọi cb(). Trả số flow đã duyệt, -1 nếu lỗi socket/gửi.
 */
int ctdump_dump_all(ctdump_flow_cb cb, void *ctx);

/*
 * Tiện ích: từ ctdump_result → điền flow_stats (cho engine L1) và
 * feature vector (cho engine ML). init_win_fwd lấy từ gói SYN trong NFQUEUE.
 */
#include "flow_rule.h"   /* struct flow_stats */
void ctdump_to_flow_stats(const struct ctdump_result *r,
			  struct flow_stats *fs);

void ctdump_to_features(const struct ctdump_result *r,
			uint32_t pkts_fwd, uint32_t pkts_bwd,
			int32_t  init_win_fwd,
			double   feat[FEAT_COUNT]);

#endif /* SG_CTDUMP_H */
