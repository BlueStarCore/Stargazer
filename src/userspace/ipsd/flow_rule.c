/* SPDX-License-Identifier: MIT */
/*
 * flow_rule.c - built-in layer-1 signatures (see flow_rule.h).
 *
 * Each rule is a condition over flow_stats + flow_ctx.
 * Order: DROP before ALERT; stop at the first DROP rule.
 */
#include "flow_rule.h"

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>   /* IPPROTO_* */

/* ---- TCP flag mapping ----------------------------------------------------- */

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

/* ---- built-in rules table ------------------------------------------------- */

/*
 * Each entry: test the condition, and if it matches fill *out and return 0.
 * DROP-before-ALERT ordering matters so the loop stops correctly.
 */

/* SID base for built-ins (avoid clashing with ET OPEN (<3000000)) */
#define BIN_SID_BASE 1000000u

/* SYN flood threshold: syn_count >= N AND syn_count > RATIO * ack_count.
 * RFC 2827 / BCP38; threshold 10 follows Snort dos.rules practice. */
#define SYN_FLOOD_MIN_SYN    10u
#define SYN_FLOOD_RATIO      10u   /* syn > 10 * ack */

/* Port scan: flow with very few packets, SYN only, no completed handshake.
 * Staniford 2002: 1-3 packets/flow is a scan signature. */
#define PORT_SCAN_MAX_PKTS   3u

/* URG flood threshold */
#define URG_FLOOD_MIN        20u

/* ACK flood (reflection DDoS): many ACK, no SYN (spoofed). */
#define ACK_FLOOD_MIN_ACK    50u

/* Known-bad ports — Metasploit default, netcat backdoor, IRC botnet, Tor.
 * Source: ET OPEN trojan.rules, malware.rules. */
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

	/* ── DROP rules (checked first) ──────────────────────────────── */

	/* R1: SYN flood — TCP, syn_count >= threshold AND syn >> ack.
	 * RFC 2827: a SYN flood is characterized by very many SYN, almost no ACK.
	 * Use multiplication to avoid division (safe when ack_count == 0). */
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

	/* R2: Port scan — TCP, very few packets, SYN only (no completed handshake).
	 * Staniford 2002: ≤3 packets, with SYN, no ACK = an unanswered probe. */
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

	/* R3: URG flood — many URG packets (DoS via urgent pointer). */
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
	 * TCP or UDP. Alert rather than Drop since the port may have legitimate use. */
	if ((fc->proto == SIG_PROTO_TCP || fc->proto == SIG_PROTO_UDP) &&
	    is_known_bad_port(fc->dport)) {
		out->sid    = BIN_SID_BASE + 4;
		out->action = SIG_ALERT;
		snprintf(out->msg, sizeof(out->msg),
			 "Known-bad port: dport=%u (malware/backdoor/C2)",
			 fc->dport);
		return 0;
	}

	/* R5: ACK flood reflection — many ACK, no SYN (spoofed addresses).
	 * Characteristic of reflected amplification DDoS. */
	if (fc->proto == SIG_PROTO_TCP &&
	    fs->ack_count >= ACK_FLOOD_MIN_ACK && fs->syn_count == 0) {
		out->sid    = BIN_SID_BASE + 5;
		out->action = SIG_ALERT;
		snprintf(out->msg, sizeof(out->msg),
			 "ACK flood (reflection): ack=%u syn=0",
			 fs->ack_count);
		return 0;
	}

	return -1;   /* clean */
}
