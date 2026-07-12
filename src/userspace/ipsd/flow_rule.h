/* SPDX-License-Identifier: MIT */
/*
 * flow_rule.h - layer-1 signatures: attack detection from FLOW STATISTICS
 *               (no payload inspection needed).
 *
 * Research basis:
 *   - Roesch, "Snort: Lightweight Intrusion Detection for Networks", LISA 1999
 *     (non-payload detection: flags, dsize, threshold).
 *   - RFC 793 §3.4 — TCP flag semantics (NULL/XMAS/FIN-no-ACK invalid).
 *   - Staniford et al., "Practical Automated Detection of Stealthy Portscans",
 *     JCS 2002 — few-packet incomplete handshake signature.
 *   - Ferguson & Senie, RFC 2827 / BCP38 — SYN flood: high SYN, zero/low ACK.
 *   - ET OPEN rule categories: dos.rules, scan.rules (flow:established checks).
 *
 * Note: NULL scan / XMAS / FIN-no-ACK are blocked by pkt_forward.ko at the
 * PER-PACKET layer (is_tcp_anomaly) before packets reach ipsd — those packets
 * are not accumulated into nf_conn_ml. L1 flow-rules target accumulated
 * FLOW-LEVEL patterns: SYN flood (syn_count >> ack_count), port scan (very few
 * packets, SYN only, no completed handshake), ACK flood, known-bad port.
 */
#ifndef SG_FLOW_RULE_H
#define SG_FLOW_RULE_H

#include <stdint.h>
#include "sig_rule.h"   /* SIG_ALERT / SIG_DROP, SIG_MSG_MAX, SIG_TCP_* */

/*
 * Accumulated flow statistics — mirror of nf_conn_ml (only the fields L1 uses).
 * Caller (ipsd, ctdump.c) fills from CTA_ML + ACCT before calling flow_rule_match.
 */
struct flow_stats {
	uint32_t syn_count;       /* number of packets with the SYN flag      */
	uint32_t ack_count;       /* number of packets with the ACK flag      */
	uint32_t psh_count;
	uint32_t urg_count;
	uint32_t pkts_fwd;        /* packet count, forward direction          */
	uint32_t pkts_bwd;        /* packet count, backward direction         */
	uint16_t tcp_flags_fwd;   /* OR of all TCP flags seen, forward dir     */
	uint16_t tcp_flags_bwd;   /* OR of all TCP flags seen, backward dir    */
};

/*
 * L1 match result (built-in).
 * sid: SID of the matched built-in rule (starts at 1000000 to avoid ET OPEN).
 * msg: attack description.
 * action: SIG_ALERT or SIG_DROP.
 * Returns 0 if there is a match, -1 otherwise.
 */
struct flow_rule_match {
	uint32_t sid;
	char     msg[SIG_MSG_MAX];
	int      action;
};

/*
 * Check the flow against the built-in rules table.
 * Returns 0 + fills *out if any rule matches; -1 if clean.
 * Priority order: DROP before ALERT (like ips_fuse).
 */
int flow_rule_match_builtin(const struct flow_ctx *fc,
			    const struct flow_stats *fs,
			    struct flow_rule_match *out);

/* TCP flag names for printing/logging. */
void flow_rule_flags_str(uint8_t flags, char *buf, size_t n);

#endif /* SG_FLOW_RULE_H */
