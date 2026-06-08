/* SPDX-License-Identifier: MIT */
/*
 * flow_rule.c - Signature lớp 1 built-in (xem flow_rule.h).
 *
 * Mỗi rule là một điều kiện trên flow_stats + flow_ctx.
 * Thứ tự: DROP trước ALERT; dừng ở rule DROP đầu tiên.
 */
#include "flow_rule.h"

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>   /* IPPROTO_* */

/* ---- ánh xạ cờ TCP -------------------------------------------------------- */

void flow_rule_flags_str(uint8_t flags, char *buf, size_t n)
{
	const struct { uint8_t bit; char ch; } map[] = {
		{ SIG_TCP_FIN, 'F' }, { SIG_TCP_SYN, 'S' }, { SIG_TCP_RST, 'R' },
		{ SIG_TCP_PSH, 'P' }, { SIG_TCP_ACK, 'A' }, { SIG_TCP_URG, 'U' },
	};
	size_t k = 0;
	for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++)
		if ((flags & map[i].bit) && k + 1 < n)
			buf[k++] = map[i].ch;
	buf[k] = '\0';
	if (k == 0 && n > 0)
		buf[0] = '\0';
}

/* ---- bảng built-in rules -------------------------------------------------- */

/*
 * Mỗi entry: kiểm tra điều kiện, nếu khớp thì điền *out và trả 0.
 * Thứ tự DROP trước ALERT quan trọng để loop dừng đúng.
 */

/* SID base cho built-in (tránh đụng ET OPEN <3000000 và rule_gen 9000000+) */
#define BIN_SID_BASE 1000000u

/* Ngưỡng SYN flood: syn_count >= N VÀ syn_count > RATIO * ack_count.
 * RFC 2827 / BCP38; threshold 10 là thực tiễn Snort dos.rules. */
#define SYN_FLOOD_MIN_SYN    10u
#define SYN_FLOOD_RATIO      10u   /* syn > 10 * ack */

/* Port scan: flow rất ít gói, chỉ SYN, không hoàn tất handshake.
 * Staniford 2002: 1-3 gói/flow là dấu hiệu scan. */
#define PORT_SCAN_MAX_PKTS   3u

/* URG flood ngưỡng */
#define URG_FLOOD_MIN        20u

/* ACK flood (phản xạ DDoS): nhiều ACK, không SYN (giả mạo). */
#define ACK_FLOOD_MIN_ACK    50u

/* Known-bad ports — Metasploit default, netcat backdoor, IRC botnet, Tor.
 * Nguồn: ET OPEN trojan.rules, malware.rules. */
static const uint16_t KNOWN_BAD_PORTS[] = {
	4444,   /* Metasploit default */
	31337,  /* Back Orifice */
	1337,   /* leet/backdoor */
	6667,   /* IRC (botnet C&C) */
	6666,
	9001,   /* Tor relay */
	9050,   /* Tor SOCKS */
	1080,   /* SOCKS proxy abuse */
};
#define N_BAD_PORTS ((int)(sizeof(KNOWN_BAD_PORTS)/sizeof(KNOWN_BAD_PORTS[0])))

static int is_known_bad_port(uint16_t dport)
{
	for (int i = 0; i < N_BAD_PORTS; i++)
		if (KNOWN_BAD_PORTS[i] == dport)
			return 1;
	return 0;
}

int flow_rule_match_builtin(const struct flow_ctx *fc,
			    const struct flow_stats *fs,
			    struct flow_rule_match *out)
{
	if (!fc || !fs || !out)
		return -1;

	uint32_t pkts_total = fs->pkts_fwd + fs->pkts_bwd;

	/* ── DROP rules (kiểm trước) ─────────────────────────────────── */

	/* R1: SYN flood — TCP, syn_count >= threshold VÀ syn >> ack.
	 * RFC 2827: SYN flood đặc trưng bởi rất nhiều SYN, hầu như không ACK.
	 * Dùng nhân để tránh chia (an toàn với ack_count == 0). */
	if (fc->proto == SIG_PROTO_TCP &&
	    fs->syn_count >= SYN_FLOOD_MIN_SYN &&
	    fs->syn_count > SYN_FLOOD_RATIO * fs->ack_count) {
		out->sid    = BIN_SID_BASE + 1;
		out->action = SIG_DROP;
		snprintf(out->msg, sizeof(out->msg),
			 "SYN flood: syn=%u ack=%u (ratio %u:1 > %u:1)",
			 fs->syn_count, fs->ack_count,
			 fs->ack_count ? fs->syn_count / fs->ack_count : fs->syn_count,
			 SYN_FLOOD_RATIO);
		return 0;
	}

	/* R2: Port scan — TCP, rất ít gói, chỉ SYN (không hoàn tất handshake).
	 * Staniford 2002: ≤3 gói, có SYN, không ACK = probe chưa được trả lời. */
	if (fc->proto == SIG_PROTO_TCP &&
	    pkts_total > 0 && pkts_total <= PORT_SCAN_MAX_PKTS &&
	    fs->syn_count >= 1 && fs->ack_count == 0) {
		out->sid    = BIN_SID_BASE + 2;
		out->action = SIG_DROP;
		snprintf(out->msg, sizeof(out->msg),
			 "Port scan: %u pkts, syn=%u ack=0 (incomplete handshake)",
			 pkts_total, fs->syn_count);
		return 0;
	}

	/* R3: URG flood — nhiều gói URG (DoS qua urgent pointer). */
	if (fc->proto == SIG_PROTO_TCP && fs->urg_count >= URG_FLOOD_MIN) {
		out->sid    = BIN_SID_BASE + 3;
		out->action = SIG_DROP;
		snprintf(out->msg, sizeof(out->msg),
			 "URG flood: urg_count=%u >= %u",
			 fs->urg_count, URG_FLOOD_MIN);
		return 0;
	}

	/* ── ALERT rules ─────────────────────────────────────────────── */

	/* R4: Known-bad destination port (ET OPEN trojan/malware category).
	 * TCP hoặc UDP. Alert thay vì Drop vì port có thể dùng hợp lệ. */
	if ((fc->proto == SIG_PROTO_TCP || fc->proto == SIG_PROTO_UDP) &&
	    is_known_bad_port(fc->dport)) {
		out->sid    = BIN_SID_BASE + 4;
		out->action = SIG_ALERT;
		snprintf(out->msg, sizeof(out->msg),
			 "Known-bad port: dport=%u (malware/backdoor/C2)",
			 fc->dport);
		return 0;
	}

	/* R5: ACK flood phản xạ — nhiều ACK, không SYN (giả mạo địa chỉ).
	 * Đặc trưng của reflected amplification DDoS. */
	if (fc->proto == SIG_PROTO_TCP &&
	    fs->ack_count >= ACK_FLOOD_MIN_ACK && fs->syn_count == 0) {
		out->sid    = BIN_SID_BASE + 5;
		out->action = SIG_ALERT;
		snprintf(out->msg, sizeof(out->msg),
			 "ACK flood (reflection): ack=%u syn=0",
			 fs->ack_count);
		return 0;
	}

	return -1;   /* lành */
}
