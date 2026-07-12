/* SPDX-License-Identifier: MIT */
/*
 * nfq.c - NFQUEUE I/O via raw AF_NETLINK (see nfq.h).
 */
#define _GNU_SOURCE
#include "nfq.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>       /* be64toh — NFQA_TIMESTAMP big-endian */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

/* CTA_* attributes carried inside NFQA_CT in the verdict (set the conntrack mark).
 * These are CTA_* values from nfnetlink_conntrack.h — must be in range [0,CTA_MAX]
 * or the kernel's strict nla validation rejects the whole NFQA_CT nest (then the
 * mark is silently never applied). */
#define SG_CTA_MARK          8     /* CTA_MARK      — matches ctdump.c */
#define SG_CTA_MARK_MASK     21    /* CTA_MARK_MASK — apply only the masked bits  */
#define SG_NLA_F_NESTED      0x8000

/* ---- NLA helpers (compact, internal use) ---------------------------------- */

static int nla_put_u32(char *buf, int *off, int cap, uint16_t type, uint32_t v)
{
	int align = (int)NLA_ALIGN(NLA_HDRLEN + 4);
	if (*off + align > cap) return -1;
	struct nlattr *a = (struct nlattr *)(buf + *off);
	a->nla_len = NLA_HDRLEN + 4; a->nla_type = type;
	memcpy((char *)a + NLA_HDRLEN, &v, 4);
	*off += align; return 0;
}

static int nla_put_raw(char *buf, int *off, int cap,
		       uint16_t type, const void *data, int dlen)
{
	int align = (int)NLA_ALIGN(NLA_HDRLEN + dlen);
	if (*off + align > cap) return -1;
	struct nlattr *a = (struct nlattr *)(buf + *off);
	a->nla_len = (uint16_t)(NLA_HDRLEN + dlen); a->nla_type = type;
	if (dlen > 0) memcpy((char *)a + NLA_HDRLEN, data, (size_t)dlen);
	if (align > NLA_HDRLEN + dlen)
		memset((char *)a + NLA_HDRLEN + dlen, 0,
		       (size_t)(align - NLA_HDRLEN - dlen));
	*off += align; return 0;
}

static int nla_nest_start(char *buf, int *off, int cap, uint16_t type)
{
	if (*off + NLA_HDRLEN > cap) return -1;
	struct nlattr *a = (struct nlattr *)(buf + *off);
	a->nla_len = NLA_HDRLEN;
	a->nla_type = type | SG_NLA_F_NESTED;
	int start = *off;
	*off += NLA_HDRLEN;
	return start;
}

static void nla_nest_end(char *buf, int start, int cur)
{
	((struct nlattr *)(buf + start))->nla_len = (uint16_t)(cur - start);
}

static const void *nla_find(const void *data, int len, uint16_t want, int *plen)
{
	const struct nlattr *a = data;
	while (len >= NLA_HDRLEN) {
		int al = a->nla_len;
		if (al < NLA_HDRLEN || al > len) break;
		if ((a->nla_type & 0x3fff) == want) {
			*plen = al - NLA_HDRLEN;
			return (const char *)a + NLA_HDRLEN;
		}
		len -= NLA_ALIGN(al);
		a = (const struct nlattr *)((const char *)a + NLA_ALIGN(al));
	}
	return NULL;
}

/* ---- build config messages ------------------------------------------------ */

static int build_pf_bind(char *buf, int cap, uint16_t pf, int bind)
{
	memset(buf, 0, (size_t)cap);
	int off = NLMSG_HDRLEN + (int)NLMSG_ALIGN(sizeof(struct nfgenmsg));
	if (off > cap) return -1;

	struct nfqnl_msg_config_cmd cmd = {
		.command = bind ? NFQNL_CFG_CMD_PF_BIND : NFQNL_CFG_CMD_PF_UNBIND,
		._pad    = 0,
		.pf      = htons(pf),
	};
	if (nla_put_raw(buf, &off, cap, NFQA_CFG_CMD, &cmd, sizeof(cmd)) < 0)
		return -1;

	struct nlmsghdr    *h = (struct nlmsghdr *)buf;
	struct nfgenmsg    *g = (struct nfgenmsg *)(buf + NLMSG_HDRLEN);
	h->nlmsg_len   = (uint32_t)NLMSG_ALIGN((size_t)off);
	h->nlmsg_type  = (uint16_t)((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG);
	h->nlmsg_flags = NLM_F_REQUEST;
	h->nlmsg_seq   = 0;
	g->nfgen_family = AF_UNSPEC;
	g->version      = NFNETLINK_V0;
	g->res_id       = 0;
	return off;
}

static int build_queue_config(char *buf, int cap, uint16_t qnum)
{
	memset(buf, 0, (size_t)cap);
	int off = NLMSG_HDRLEN + (int)NLMSG_ALIGN(sizeof(struct nfgenmsg));
	if (off > cap) return -1;

	/* BIND command */
	struct nfqnl_msg_config_cmd cmd = {
		.command = NFQNL_CFG_CMD_BIND, ._pad = 0, .pf = 0,
	};
	if (nla_put_raw(buf, &off, cap, NFQA_CFG_CMD, &cmd, sizeof(cmd)) < 0)
		return -1;

	/* COPY_PACKET mode with range 0xffff */
	struct nfqnl_msg_config_params params;
	params.copy_range = htonl(0xffff);
	params.copy_mode  = NFQNL_COPY_PACKET;
	if (nla_put_raw(buf, &off, cap, NFQA_CFG_PARAMS,
			&params, sizeof(params)) < 0)
		return -1;

	/*
	 * Do NOT fold the NFQA_CFG_F_CONNTRACK flag in here. On a kernel lacking
	 * CONFIG_NETFILTER_NETLINK_GLUE_CT, setting this flag returns -EOPNOTSUPP
	 * which BREAKS the WHOLE message → BIND/COPY not applied → the queue
	 * receives no packets (pkt_seen=0). The conntrack flag is sent SEPARATELY,
	 * best-effort (build_queue_flags).
	 */
	struct nlmsghdr *h = (struct nlmsghdr *)buf;
	struct nfgenmsg *g = (struct nfgenmsg *)(buf + NLMSG_HDRLEN);
	h->nlmsg_len   = (uint32_t)NLMSG_ALIGN((size_t)off);
	h->nlmsg_type  = (uint16_t)((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG);
	h->nlmsg_flags = NLM_F_REQUEST;
	h->nlmsg_seq   = 1;
	g->nfgen_family = AF_UNSPEC;
	g->version      = NFNETLINK_V0;
	g->res_id       = htons(qnum);
	return off;
}

/* Set only the NFQA_CFG_F_CONNTRACK flag (NFQA_CT in the packet notification +
 * allows the verdict to apply a connmark). Sent SEPARATELY so an error on this
 * flag does not break BIND/COPY. */
static int build_queue_flags(char *buf, int cap, uint16_t qnum)
{
	memset(buf, 0, (size_t)cap);
	int off = NLMSG_HDRLEN + (int)NLMSG_ALIGN(sizeof(struct nfgenmsg));
	if (off > cap) return -1;

	uint32_t flags = htonl(NFQA_CFG_F_CONNTRACK);
	uint32_t mask  = htonl(NFQA_CFG_F_CONNTRACK);
	if (nla_put_u32(buf, &off, cap, NFQA_CFG_FLAGS, flags) < 0)
		return -1;
	if (nla_put_u32(buf, &off, cap, NFQA_CFG_MASK, mask) < 0)
		return -1;

	struct nlmsghdr *h = (struct nlmsghdr *)buf;
	struct nfgenmsg *g = (struct nfgenmsg *)(buf + NLMSG_HDRLEN);
	h->nlmsg_len   = (uint32_t)NLMSG_ALIGN((size_t)off);
	h->nlmsg_type  = (uint16_t)((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG);
	h->nlmsg_flags = NLM_F_REQUEST;
	h->nlmsg_seq   = 1;
	g->nfgen_family = AF_UNSPEC;
	g->version      = NFNETLINK_V0;
	g->res_id       = htons(qnum);
	return off;
}

/* ---- open / close --------------------------------------------------------- */

int nfq_open(struct nfq_ctx *ctx, uint16_t queue_num)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->queue_num = queue_num;

	ctx->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (ctx->fd < 0)
		return -1;

	int rcvbuf = 4 * 1024 * 1024;
	setsockopt(ctx->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	socklen_t slen = sizeof(sa);
	if (bind(ctx->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		goto err;
	if (getsockname(ctx->fd, (struct sockaddr *)&sa, &slen) < 0)
		goto err;
	ctx->portid = sa.nl_pid;

	char buf[512];
	struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
	int len;

	/* PF_BIND */
	len = build_pf_bind(buf, sizeof(buf), AF_INET, 1);
	if (len < 0 || sendto(ctx->fd, buf, (size_t)len, 0,
			      (struct sockaddr *)&dst, sizeof(dst)) < 0)
		goto err;

	/* Queue BIND + COPY_PACKET (MANDATORY — without it no packets are received) */
	len = build_queue_config(buf, sizeof(buf), queue_num);
	if (len < 0 || sendto(ctx->fd, buf, (size_t)len, 0,
			      (struct sockaddr *)&dst, sizeof(dst)) < 0)
		goto err;

	/* CONNTRACK flag — BEST-EFFORT, sent SEPARATELY. A kernel lacking glue_ct
	 * returns -EOPNOTSUPP but does NOT affect the BIND/COPY above → packets are
	 * still delivered. Losing the flag only means the verdict cannot apply a
	 * connmark (offload/block the next flow); fine for detect mode, and prevent
	 * mode still NF_DROPs the current packet. */
	len = build_queue_flags(buf, sizeof(buf), queue_num);
	if (len > 0)
		(void)sendto(ctx->fd, buf, (size_t)len, 0,
			     (struct sockaddr *)&dst, sizeof(dst));

	return 0;
err:
	close(ctx->fd);
	ctx->fd = -1;
	return -1;
}

void nfq_close(struct nfq_ctx *ctx)
{
	if (ctx && ctx->fd >= 0) {
		close(ctx->fd);
		ctx->fd = -1;
	}
}

/* ---- parse IP packet ------------------------------------------------------ */

int nfq_parse_packet(const uint8_t *data, uint16_t len, struct nfq_pkt *pkt)
{
	if (!data || len < 20 || !pkt)
		return -1;

	const struct iphdr *iph = (const struct iphdr *)data;
	if (iph->version != 4 || iph->ihl < 5)
		return -1;

	uint16_t ihl = (uint16_t)(iph->ihl * 4);
	if (len < ihl)
		return -1;

	pkt->proto  = iph->protocol;
	pkt->src_ip = ntohl(iph->saddr);
	pkt->dst_ip = ntohl(iph->daddr);
	pkt->sport  = 0;
	pkt->dport  = 0;
	pkt->tcp_flags = 0;
	pkt->init_win  = -1;
	pkt->tcp_seq   = 0;

	uint16_t l4hdr = 0;

	if (iph->protocol == IPPROTO_TCP && len >= ihl + (uint16_t)sizeof(struct tcphdr)) {
		const struct tcphdr *th =
			(const struct tcphdr *)(data + ihl);
		pkt->sport = ntohs(th->source);
		pkt->dport = ntohs(th->dest);
		pkt->tcp_seq = ntohl(th->seq);   /* seq of the first payload byte (P1 reass) */
		l4hdr = (uint16_t)(th->doff * 4);

		if (th->fin) pkt->tcp_flags |= SIG_TCP_FIN;
		if (th->syn) pkt->tcp_flags |= SIG_TCP_SYN;
		if (th->rst) pkt->tcp_flags |= SIG_TCP_RST;
		if (th->psh) pkt->tcp_flags |= SIG_TCP_PSH;
		if (th->ack) pkt->tcp_flags |= SIG_TCP_ACK;
		if (th->urg) pkt->tcp_flags |= SIG_TCP_URG;

		/* TCP window of the forward SYN packet (no ack) → feature #13 */
		if (th->syn && !th->ack)
			pkt->init_win = (int32_t)ntohs(th->window);

	} else if (iph->protocol == IPPROTO_UDP &&
		   len >= ihl + (uint16_t)sizeof(struct udphdr)) {
		const struct udphdr *uh =
			(const struct udphdr *)(data + ihl);
		pkt->sport = ntohs(uh->source);
		pkt->dport = ntohs(uh->dest);
		l4hdr = sizeof(struct udphdr);

	} else if (iph->protocol == IPPROTO_ICMP &&
		   len >= ihl + (uint16_t)sizeof(struct icmphdr)) {
		l4hdr = sizeof(struct icmphdr);
	}

	uint16_t poff = ihl + l4hdr;
	pkt->payload = (poff < len) ? data + poff : NULL;
	pkt->plen    = (poff < len) ? (uint16_t)(len - poff) : 0;

	return 0;
}

/* ---- recv ----------------------------------------------------------------- */

int nfq_recv(struct nfq_ctx *ctx, struct nfq_pkt *pkt)
{
	if (!ctx || ctx->fd < 0 || !pkt)
		return -1;

	char buf[NFQ_RAW_MAX + 512];
	ssize_t rn;

again:
	rn = recv(ctx->fd, buf, sizeof(buf), 0);
	if (rn < 0) {
		if (errno == EINTR) goto again;
		return -1;
	}

	struct nlmsghdr *nh;
	int rem = (int)rn;

	for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, rem);
	     nh = NLMSG_NEXT(nh, rem)) {

		if (nh->nlmsg_type == NLMSG_ERROR || nh->nlmsg_type == NLMSG_DONE)
			continue;

		uint16_t msg_type = nh->nlmsg_type & 0xff;
		if (msg_type != NFQNL_MSG_PACKET)
			continue;

		const void *attrs = (const char *)NLMSG_DATA(nh) +
				    NLMSG_ALIGN(sizeof(struct nfgenmsg));
		int alen = (int)nh->nlmsg_len - NLMSG_HDRLEN -
			   (int)NLMSG_ALIGN(sizeof(struct nfgenmsg));
		if (alen <= 0)
			continue;

		/* NFQA_PACKET_HDR → packet ID */
		int hl = 0;
		const struct nfqnl_msg_packet_hdr *ph =
			nla_find(attrs, alen, NFQA_PACKET_HDR, &hl);
		if (!ph)
			continue;
		pkt->id = ntohl(ph->packet_id);

		/* NFQA_PAYLOAD → raw packet */
		int pl = 0;
		const void *payload = nla_find(attrs, alen, NFQA_PAYLOAD, &pl);
		if (!payload || pl <= 0)
			continue;

		uint16_t copy = (uint16_t)(pl < (int)sizeof(pkt->raw_buf) ?
					   pl : (int)sizeof(pkt->raw_buf) - 1);
		memcpy(pkt->raw_buf, payload, copy);
		pkt->raw_len = copy;

		if (nfq_parse_packet(pkt->raw_buf, copy, pkt) < 0)
			continue;

		/* NFQA_MARK → skb mark; low byte = IPS profile id (per-policy
		 * scoping). Set AFTER nfq_parse_packet (that function does not touch
		 * this field). Use the skb mark since it is more reliable than NFQA_CT
		 * on a kernel lacking glue_ct. */
		pkt->ips_prof_id = 0;
		int mkl = 0;
		const void *mk = nla_find(attrs, alen, NFQA_MARK, &mkl);
		if (mk && mkl >= 4)
			pkt->ips_prof_id =
				(uint8_t)(ntohl(*(const uint32_t *)mk) & 0xFF);

		/* NFQA_TIMESTAMP → the moment the kernel recorded the packet (for the
		 * alert log). struct {be64 sec; be64 usec}. The kernel only sends it
		 * when skb->tstamp is set → absent means cap_sec=0 (log_alert
		 * fallback). memcpy because the payload attribute is only 4-byte
		 * aligned, so reading be64 directly may misalign.
		 *
		 * WARNING: since kernel ~5.18, skb->tstamp of a FORWARD packet is often
		 * CLOCK_MONOTONIC (EDT model), not wall-clock. nfnetlink_queue dumps
		 * that ktime straight through → sec ≈ uptime → "1970-01-01 + uptime".
		 * Guard: only accept it if it looks like a real epoch (≥ 2020-01-01);
		 * for monotonic to exceed this mark would require ~50 years of uptime →
		 * impossible → rejected, fallback. */
		pkt->cap_sec = 0;
		int tsl = 0;
		const void *tsp = nla_find(attrs, alen, NFQA_TIMESTAMP, &tsl);
		if (tsp && tsl >= (int)sizeof(struct nfqnl_msg_packet_timestamp)) {
			uint64_t sec;
			memcpy(&sec, tsp, sizeof(sec));   /* first field = sec */
			int64_t s = (int64_t)be64toh(sec);
			if (s >= 1577836800)              /* 2020-01-01 UTC */
				pkt->cap_sec = s;
		}

		return 0;
	}
	return -1;
}

/* ---- verdict -------------------------------------------------------------- */

int nfq_verdict(struct nfq_ctx *ctx, uint32_t id, int accept,
		uint32_t connmark, uint32_t connmark_mask)
{
	char buf[512];
	memset(buf, 0, sizeof(buf));

	int off = NLMSG_HDRLEN + (int)NLMSG_ALIGN(sizeof(struct nfgenmsg));

	/*
	 * NF_ACCEPT for pass/alert: the NFQUEUE rule uses connbytes (0:N-1) as the
	 * gate — no NF_REPEAT or INSPECTED connmark needed. After N packets,
	 * connbytes exceeds N-1, the rule no longer matches → the packet reaches
	 * the policy CONNMARK+ACCEPT on its own. NF_DROP for block: with connmark
	 * IPS_BLOCK → the global DROP rule at the head of the chain blocks every
	 * subsequent packet of that flow.
	 */
	struct nfqnl_msg_verdict_hdr vh = {
		.verdict = htonl(accept ? NF_ACCEPT : NF_DROP),
		.id      = htonl(id),
	};
	if (nla_put_raw(buf, &off, (int)sizeof(buf),
			NFQA_VERDICT_HDR, &vh, sizeof(vh)) < 0)
		return -1;

	/* Set connmark via NFQA_CT → CTA_MARK (Linux ≥ 3.16).
	 * Kernel applies: ct->mark = (ct->mark & ~mask) | (mark & mask). */
	if (connmark_mask) {
		int nest = nla_nest_start(buf, &off, (int)sizeof(buf), NFQA_CT);
		if (nest < 0) return -1;
		uint32_t m = htonl(connmark);
		if (nla_put_raw(buf, &off, (int)sizeof(buf),
				SG_CTA_MARK, &m, 4) < 0)
			return -1;
		/* CTA_MARK_MASK (21) — inside the NFQA_CT nest — so the kernel does
		 * ct->mark = (ct->mark & ~mask) | (mark & mask), preserving policy_id
		 * (bits 8-31) + DIRTY (bit 0). (Was wrongly 28 > CTA_MAX → the kernel
		 * rejected the whole NFQA_CT nest and never set the convicted bit.) */
		uint32_t mk = htonl(connmark_mask);
		if (nla_put_raw(buf, &off, (int)sizeof(buf),
				SG_CTA_MARK_MASK, &mk, 4) < 0)
			return -1;
		nla_nest_end(buf, nest, off);
	}

	struct nlmsghdr *h = (struct nlmsghdr *)buf;
	struct nfgenmsg *g = (struct nfgenmsg *)(buf + NLMSG_HDRLEN);
	h->nlmsg_len   = (uint32_t)NLMSG_ALIGN((size_t)off);
	h->nlmsg_type  = (uint16_t)((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT);
	h->nlmsg_flags = NLM_F_REQUEST;
	h->nlmsg_seq   = 2;
	g->nfgen_family = AF_UNSPEC;
	g->version      = NFNETLINK_V0;
	g->res_id       = htons(ctx->queue_num);

	struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
	return sendto(ctx->fd, buf, (size_t)NLMSG_ALIGN((size_t)off), 0,
		      (struct sockaddr *)&dst, sizeof(dst)) < 0 ? -1 : 0;
}
