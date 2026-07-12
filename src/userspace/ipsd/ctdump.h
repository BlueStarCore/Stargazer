/* SPDX-License-Identifier: MIT */
/*
 * ctdump.h - query conntrack for a specific flow via ctnetlink.
 *
 * ipsd uses this module to fetch CTA_ML (17 ML feature accumulators) and
 * CTA_COUNTERS (pkts_fwd / pkts_bwd from the ACCT extension) after receiving a
 * packet from NFQUEUE. The result is fed into feature_extract() to compute the
 * 17-feature vector.
 *
 * Design: parsing is split from I/O → ctdump_parse_response() is a pure
 * function over a buffer, testable on the host without a kernel;
 * ctdump_query() handles the netlink socket.
 *
 * Reuses constants and conventions from mgmtd_diag.c (sg_nla_find, SG_CTA_*).
 */
#ifndef SG_CTDUMP_H
#define SG_CTDUMP_H

#include <stdint.h>
#include "feature.h"   /* struct sg_nf_conn_ml */

/* ---- result of one query ------------------------------------------------- */

struct ctdump_result {
	struct sg_nf_conn_ml ml;       /* CTA_ML: ML feature vector            */
	int      ml_valid;             /* 1 if CTA_ML is present in the response */

	uint64_t pkts_orig;            /* CTA_COUNTERS_ORIG  → packets forward  */
	uint64_t pkts_reply;           /* CTA_COUNTERS_REPLY → packets backward */
	int      acct_valid;           /* 1 if CTA_COUNTERS is present (CONFIG_NF_CONNTRACK_ACCT) */

	uint32_t mark;                 /* CTA_MARK: the flow's connmark         */
	int      mark_valid;           /* 1 if CTA_MARK is present in the response */
};

/* ---- API ------------------------------------------------------------------ */

/*
 * Parse an nlmsghdr response (payload = attrs after nfgenmsg). Fills *out.
 * Returns 0 on OK (even when some fields are absent — see *_valid), -1 if the
 * message is not a valid CT_GET reply.
 *
 * This function is PURE (no I/O) → testable on the host with a mock buffer.
 * attrs_data / attrs_len: pointer to the nlattr region after the nfgenmsg header.
 */
int ctdump_parse_response(const void *attrs_data, int attrs_len,
			  struct ctdump_result *out);

/*
 * Open an AF_NETLINK socket, send CT_GET (targeted — no DUMP), wait for the
 * response, call ctdump_parse_response().
 *
 * src_ip / dst_ip: IPv4 in host byte order.
 * sport / dport:   in host byte order.
 * proto:           IPPROTO_TCP / IPPROTO_UDP / IPPROTO_ICMP.
 *
 * Returns 0 if the flow is found + *out is filled, -1 if not found or on error.
 */
int ctdump_query(uint32_t src_ip, uint32_t dst_ip,
		 uint16_t sport,  uint16_t dport,
		 uint8_t  proto,
		 struct ctdump_result *out);

/* ---- dump ALL flows (for the ML scoring loop) ---------------------------- */

/* One flow in the dump: 5-tuple (host order) + CTA_ML/counters result. */
struct ctdump_flow {
	uint32_t src_ip, dst_ip;     /* host byte order */
	uint16_t sport,  dport;      /* host byte order */
	uint8_t  proto;
	struct ctdump_result res;
};

/* Callback invoked for each flow in the dump. Return 0 to continue, !=0 to stop early. */
typedef int (*ctdump_flow_cb)(const struct ctdump_flow *f, void *ctx);

/*
 * Send CT_GET with NLM_F_DUMP (fetch all flows), parse tuple + CTA_ML for each
 * entry, call cb(). Returns the number of flows visited, -1 on socket/send error.
 */
int ctdump_dump_all(ctdump_flow_cb cb, void *ctx);

/*
 * Helpers: from ctdump_result → fill flow_stats (for the L1 engine) and the
 * feature vector (for the ML engine). init_win_fwd comes from the SYN packet in NFQUEUE.
 */
#include "flow_rule.h"   /* struct flow_stats */
void ctdump_to_flow_stats(const struct ctdump_result *r,
			  struct flow_stats *fs);

void ctdump_to_features(const struct ctdump_result *r,
			uint32_t pkts_fwd, uint32_t pkts_bwd,
			int32_t  init_win_fwd,
			double   feat[FEAT_COUNT]);

#endif /* SG_CTDUMP_H */
