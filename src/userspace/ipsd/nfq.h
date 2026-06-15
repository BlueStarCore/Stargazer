/* SPDX-License-Identifier: MIT */
/*
 * nfq.h - NFQUEUE I/O for stargazer-ipsd (raw AF_NETLINK, no libnetfilter_queue).
 *
 * ipsd receives packets from the kernel via NFQUEUE (the kernel queues the
 * first N packets of each flow), parses the IP/TCP/UDP header to get the tuple
 * + payload + TCP window (feature #13), then returns an ACCEPT/DROP verdict and
 * sets a connmark for that flow.
 *
 * Connmark bits used for IPS (do not touch mgmtd's SG_CMK_DIRTY bit0):
 *   SG_CMK_IPS_BLOCK     (bit 1) → every packet after DROP
 *   SG_CMK_IPS_INSPECTED (bit 2) → offload, out of the queue
 *
 * The connmark is set via NFQA_CT → CTA_MARK in the verdict message
 * (Linux ≥ 3.16: the kernel updates the conntrack mark from the verdict).
 *
 * Iptables rules (added by mgmtd when IPS is enabled, per-policy):
 *   <match> -m connmark --mark 0x2/0x2 -j DROP   (flow already convicted)
 *   <match> -m connbytes --connbytes-dir both --connbytes-mode bytes \
 *           --connbytes 0:K -m connmark ! --mark 0x4/0x4 \
 *           -j NFQUEUE --queue-num Q   (P1: inspect first K bytes, both directions)
 */
#ifndef SG_NFQ_H
#define SG_NFQ_H

#include <stdint.h>
#include "sig_rule.h"   /* SIG_TCP_*, SIG_PROTO_*, struct flow_ctx */

/* ---- IPS connmark bits (separate from mgmtd's DIRTY bit0 + policy_id bit8-31) -- */
#define SG_CMK_IPS_BLOCK       0x00000002u   /* bit 1 — flow convicted → DROP    */
#define SG_CMK_IPS_INSPECTED   0x00000004u   /* bit 2 — inspected → offload      */
#define SG_CMK_IPS_MASK        0x00000006u   /* bit 1-2                          */

/* ---- NFQUEUE context ------------------------------------------------------ */
struct nfq_ctx {
	int      fd;           /* AF_NETLINK socket */
	uint16_t queue_num;
	uint32_t portid;       /* netlink port ID of the process */
};

/* ---- packet info from NFQUEUE --------------------------------------------- */
#define NFQ_RAW_MAX 65536

struct nfq_pkt {
	/* NFQUEUE packet ID (needed for the verdict) */
	uint32_t  id;

	/* tuple (host byte order) */
	uint8_t   proto;        /* IPPROTO_TCP / UDP / ICMP / other */
	uint32_t  src_ip;
	uint32_t  dst_ip;
	uint16_t  sport;
	uint16_t  dport;

	/* TCP flags of THIS PACKET (not accumulated) */
	uint8_t   tcp_flags;    /* SIG_TCP_* */

	/* TCP seq of the first payload byte (host order) — places the segment into reass (P1) */
	uint32_t  tcp_seq;

	/* TCP window of the forward SYN packet (feature #13); -1 if not a SYN */
	int32_t   init_win;

	/* IPS profile id of the flow = low byte of the skb mark (NFQA_MARK), set by
	 * mgmtd's per-policy MARK rule. 1..31 = profile; 0 = unknown → inspect all rules. */
	uint8_t   ips_prof_id;

	/* The moment the kernel put the packet into NFQUEUE (NFQA_TIMESTAMP, epoch
	 * seconds) = when the attack packet was RECORDED. 0 = no trustworthy
	 * wall-clock timestamp (kernel did not send it, OR sent monotonic/uptime —
	 * rejected by nfq_recv) → the logger falls back to time(NULL). When >0 it is
	 * more accurate than the log-write time under a burst (userspace lags behind
	 * the kernel queue). */
	int64_t   cap_sec;

	/* L4 payload (points into raw_buf) */
	const uint8_t *payload;
	uint16_t       plen;

	/* raw IP packet from NFQA_PAYLOAD */
	uint8_t   raw_buf[NFQ_RAW_MAX];
	uint16_t  raw_len;
};

/* ---- API ------------------------------------------------------------------ */

/*
 * Open NFQUEUE: create socket, bind, PF_BIND, queue BIND + COPY_PACKET +
 * CONNTRACK flag. Returns 0/-1.
 */
int  nfq_open(struct nfq_ctx *ctx, uint16_t queue_num);

/*
 * Parse the raw IP packet data[0..len) into *pkt.
 * PURE FUNCTION — no I/O, testable on the host.
 * Returns 0 if OK, -1 if the header is invalid/too short.
 */
int  nfq_parse_packet(const uint8_t *data, uint16_t len, struct nfq_pkt *pkt);

/*
 * Receive one packet from NFQUEUE, call nfq_parse_packet(). Blocks until a
 * packet arrives. Returns 0 if a valid packet, -1 on error (EINTR = normal, retry).
 */
int  nfq_recv(struct nfq_ctx *ctx, struct nfq_pkt *pkt);

/*
 * Send a verdict for packet `id`. `accept` = 1 → NF_ACCEPT; 0 → NF_DROP.
 * `connmark` = value set into the flow's connmark (0 = do not set).
 * `connmark_mask` = mask for CTA_MARK (only bits in the mask are modified).
 * Returns 0/-1.
 */
int  nfq_verdict(struct nfq_ctx *ctx, uint32_t id, int accept,
		 uint32_t connmark, uint32_t connmark_mask);

/* Close the socket, release the ctx. */
void nfq_close(struct nfq_ctx *ctx);

/* Build a flow_ctx from an nfq_pkt (to pass into ips_evaluate). */
static inline void nfq_pkt_to_flow_ctx(const struct nfq_pkt *p,
					struct flow_ctx *fc)
{
	fc->proto     = (uint8_t)(p->proto == 6 ? SIG_PROTO_TCP :
				  p->proto == 17 ? SIG_PROTO_UDP :
				  p->proto == 1  ? SIG_PROTO_ICMP :
				  SIG_PROTO_ANY);
	fc->dport     = p->dport;
	fc->tcp_flags = p->tcp_flags;
	fc->established = 0;   /* P6 — caller (main.c) resets from conntrack/dir */
	fc->to_server   = 1;
	fc->prof_id     = p->ips_prof_id; /* per-policy scoping (skb mark) */
	fc->fb          = NULL; /* P5 — only a pooled TCP flow tracks flowbits */
	fc->bufs        = NULL; /* P6 — caller extracts buffers for reassembled TCP */
}

#endif /* SG_NFQ_H */
