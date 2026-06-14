/* SPDX-License-Identifier: MIT */
/*
 * flow_rule.h - Signature lớp 1: phát hiện tấn công từ THỐNG KÊ FLOW
 *               (không cần mở payload).
 *
 * Cơ sở nghiên cứu:
 *   - Roesch, "Snort: Lightweight Intrusion Detection for Networks", LISA 1999
 *     (non-payload detection: flags, dsize, threshold).
 *   - RFC 793 §3.4 — TCP flag semantics (NULL/XMAS/FIN-no-ACK invalid).
 *   - Staniford et al., "Practical Automated Detection of Stealthy Portscans",
 *     JCS 2002 — few-packet incomplete handshake signature.
 *   - Ferguson & Senie, RFC 2827 / BCP38 — SYN flood: high SYN, zero/low ACK.
 *   - ET OPEN rule categories: dos.rules, scan.rules (flow:established checks).
 *
 * Lưu ý: NULL scan / XMAS / FIN-no-ACK được pkt_forward.ko chặn ở tầng
 * PER-PACKET (is_tcp_anomaly) trước khi gói đến ipsd — những gói đó không
 * tích lũy vào nf_conn_ml. L1 flow-rule nhắm vào pattern FLOW-LEVEL tích lũy:
 * SYN flood (syn_count >> ack_count), port scan (rất ít gói, chỉ SYN, không
 * handshake hoàn tất), ACK flood, known-bad port.
 */
#ifndef SG_FLOW_RULE_H
#define SG_FLOW_RULE_H

#include <stdint.h>
#include "sig_rule.h"   /* SIG_ALERT / SIG_DROP, SIG_MSG_MAX, SIG_TCP_* */

/*
 * Thống kê flow tích lũy — mirror từ nf_conn_ml (chỉ các field L1 dùng).
 * Caller (ipsd, ctdump.c) điền từ CTA_ML + ACCT trước khi gọi flow_rule_match.
 */
struct flow_stats {
	uint32_t syn_count;       /* số gói có cờ SYN                        */
	uint32_t ack_count;       /* số gói có cờ ACK                        */
	uint32_t psh_count;
	uint32_t urg_count;
	uint32_t pkts_fwd;        /* số gói chiều forward                    */
	uint32_t pkts_bwd;        /* số gói chiều backward                   */
	uint16_t tcp_flags_fwd;   /* OR tất cả cờ TCP đã thấy, chiều forward */
	uint16_t tcp_flags_bwd;   /* OR tất cả cờ TCP đã thấy, chiều backward */
};

/*
 * Kết quả L1 match (built-in).
 * sid: SID của rule built-in trúng (bắt đầu từ 1000000 để không đụng ET OPEN).
 * msg: mô tả tấn công.
 * action: SIG_ALERT hoặc SIG_DROP.
 * Trả 0 nếu có match, -1 nếu không.
 */
struct flow_rule_match {
	uint32_t sid;
	char     msg[SIG_MSG_MAX];
	int      action;
};

/*
 * Kiểm tra flow so với bảng built-in rules.
 * Trả 0 + điền *out nếu khớp rule nào; -1 nếu lành.
 * Thứ tự ưu tiên: DROP trước ALERT (như ips_fuse).
 */
int flow_rule_match_builtin(const struct flow_ctx *fc,
			    const struct flow_stats *fs,
			    struct flow_rule_match *out);

/* Tên cờ TCP để in/log. */
void flow_rule_flags_str(uint8_t flags, char *buf, size_t n);

#endif /* SG_FLOW_RULE_H */
