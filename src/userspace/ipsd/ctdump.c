/* SPDX-License-Identifier: MIT */
#define _DEFAULT_SOURCE   /* be64toh / be32toh under strict musl and glibc */
/*
 * ctdump.c - query conntrack CTA_ML + CTA_COUNTERS via ctnetlink (see ctdump.h).
 *
 * Reuses conventions from mgmtd_diag.c:
 *   - sg_nla_find(): walk nlattr stream (handle nested + type-mask).
 *   - SG_CTA_* constants match mgmtd_diag.c so they stay in sync.
 *   - struct sg_nfgenmsg: {u8 family, u8 version, u16 res_id}.
 *
 * Adds CTA_COUNTERS (ACCT) — mgmtd reads it from /proc text, ipsd reads it
 * directly from ctnetlink to get pkts_fwd / pkts_bwd for features #7, #8, #12.
 */
#define _GNU_SOURCE
#include "ctdump.h"
#include "feature.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>          /* struct timeval for SO_RCVTIMEO */
#include <endian.h>            /* be64toh (musl + glibc) */
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <netinet/in.h>

/* ---- ctnetlink constants ------------------------------------------------- */
/* Match mgmtd_diag.c — do not rename */

#define SG_NETLINK_NETFILTER     12
#define SG_NFNL_SUBSYS_CTNETLINK  1
#define SG_IPCTNL_MSG_CT_GET      1
#define SG_NLA_TYPE_MASK          0x3fff
#define SG_NLA_F_NESTED           0x8000

/* CTA_TUPLE_ORIG = 1 (nested) */
#define SG_CTA_TUPLE_ORIG      1
#define SG_CTA_TUPLE_IP        1   /* nested in TUPLE */
#define SG_CTA_IP_V4_SRC       1
#define SG_CTA_IP_V4_DST       2
#define SG_CTA_TUPLE_PROTO     2   /* nested in TUPLE */
#define SG_CTA_PROTO_NUM       1
#define SG_CTA_PROTO_SRC_PORT  2
#define SG_CTA_PROTO_DST_PORT  3

/* CTA_COUNTERS (ACCT) */
#define SG_CTA_COUNTERS_ORIG   9   /* nested */
#define SG_CTA_COUNTERS_REPLY  10  /* nested */
#define SG_CTA_COUNTERS_PKTS   1   /* be64, in COUNTERS */
#define SG_CTA_COUNTERS_BYTES  2   /* be64 */

/* CTA_ML = 27 (Stargazer extension) */
#define SG_CTA_ML              27

/* CTA_MARK = 8 (be32 connmark) — carries the IPS profile id on the HTTPS path */
#define SG_CTA_MARK            8

struct sg_nfgenmsg {
	uint8_t  nfgen_family;
	uint8_t  version;
	uint16_t res_id;
};

/* ---- NLA helpers ---------------------------------------------------------- */

/* Walk nlattr stream [data, data+len), return payload of attr `want`. */
static const void *sg_nla_find(const void *data, int len, int want, int *plen)
{
	const struct nlattr *nla = data;

	while (len >= (int)NLA_HDRLEN) {
		int alen = nla->nla_len;

		if (alen < (int)NLA_HDRLEN || alen > len)
			break;
		if ((nla->nla_type & SG_NLA_TYPE_MASK) == want) {
			*plen = alen - NLA_HDRLEN;
			return (const char *)nla + NLA_HDRLEN;
		}
		len -= NLA_ALIGN(alen);
		nla  = (const struct nlattr *)((const char *)nla + NLA_ALIGN(alen));
	}
	return NULL;
}

/* Write an nlattr into buf[*off..cap). Returns 0/-1. */
static int nla_put_raw(char *buf, int *off, int cap,
		       uint16_t type, const void *data, int dlen)
{
	int align = (int)NLA_ALIGN((size_t)(NLA_HDRLEN + dlen));

	if (*off + align > cap)
		return -1;

	struct nlattr *nla = (struct nlattr *)(buf + *off);

	nla->nla_len  = (uint16_t)(NLA_HDRLEN + dlen);
	nla->nla_type = type;
	if (dlen > 0)
		memcpy((char *)nla + NLA_HDRLEN, data, (size_t)dlen);
	if (align > NLA_HDRLEN + dlen)
		memset((char *)nla + NLA_HDRLEN + dlen, 0,
		       (size_t)(align - NLA_HDRLEN - dlen));
	*off += align;
	return 0;
}

/* Start a nested attr: return a pointer to nla_len to patch later. */
static int nla_nest_start(char *buf, int *off, int cap, uint16_t type)
{
	if (*off + NLA_HDRLEN > cap)
		return -1;
	struct nlattr *nla = (struct nlattr *)(buf + *off);
	nla->nla_len  = NLA_HDRLEN;   /* patched in nla_nest_end */
	nla->nla_type = type | (uint16_t)SG_NLA_F_NESTED;
	*off += NLA_HDRLEN;
	return *off - NLA_HDRLEN;     /* return the nla offset to patch */
}

static void nla_nest_end(char *buf, int nest_off, int cur_off)
{
	struct nlattr *nla = (struct nlattr *)(buf + nest_off);
	nla->nla_len = (uint16_t)(cur_off - nest_off);
}

/* ---- parse response ------------------------------------------------------- */

int ctdump_parse_response(const void *attrs_data, int attrs_len,
			  struct ctdump_result *out)
{
	if (!attrs_data || attrs_len <= 0 || !out)
		return -1;

	memset(out, 0, sizeof(*out));

	/* ---- CTA_ML ---- */
	int ml_len = 0;
	const void *mlp = sg_nla_find(attrs_data, attrs_len, SG_CTA_ML, &ml_len);

	if (mlp && ml_len > 0) {
		int copy = ml_len < (int)sizeof(out->ml) ? ml_len
							  : (int)sizeof(out->ml);
		memcpy(&out->ml, mlp, (size_t)copy);
		out->ml_valid = 1;
	}

	/* ---- CTA_COUNTERS_ORIG (pkts forward) ---- */
	int co_len = 0;
	const void *co = sg_nla_find(attrs_data, attrs_len,
				     SG_CTA_COUNTERS_ORIG, &co_len);
	if (co) {
		int pl = 0;
		const void *pv = sg_nla_find(co, co_len, SG_CTA_COUNTERS_PKTS, &pl);
		if (pv && pl == 8) {
			uint64_t v; memcpy(&v, pv, 8);
			out->pkts_orig = be64toh(v);
			out->acct_valid = 1;
		}
	}

	/* ---- CTA_COUNTERS_REPLY (pkts backward) ---- */
	int cr_len = 0;
	const void *cr = sg_nla_find(attrs_data, attrs_len,
				     SG_CTA_COUNTERS_REPLY, &cr_len);
	if (cr) {
		int pl = 0;
		const void *pv = sg_nla_find(cr, cr_len, SG_CTA_COUNTERS_PKTS, &pl);
		if (pv && pl == 8) {
			uint64_t v; memcpy(&v, pv, 8);
			out->pkts_reply = be64toh(v);
		}
	}

	/* ---- CTA_MARK (connmark; low bits carry the IPS profile id) ---- */
	int mk_len = 0;
	const void *mk = sg_nla_find(attrs_data, attrs_len, SG_CTA_MARK, &mk_len);
	if (mk && mk_len == 4) {
		uint32_t v; memcpy(&v, mk, 4);
		out->mark = be32toh(v);
		out->mark_valid = 1;
	}

	return 0;
}

/* ---- build targeted CT_GET request --------------------------------------- */

/*
 * Build a CT_GET request with CTA_TUPLE_ORIG = {src_ip, dst_ip, sport, dport, proto}.
 * NO NLM_F_DUMP → the kernel returns exactly 1 entry (or NLMSG_ERROR ENOENT).
 * src_ip / dst_ip: host byte order. sport / dport: host byte order.
 */
static int build_ct_get(char *buf, int cap,
			uint32_t src_ip, uint32_t dst_ip,
			uint16_t sport,  uint16_t dport,
			uint8_t  proto)
{
	memset(buf, 0, (size_t)cap);

	/* nlmsghdr + nfgenmsg */
	int off = NLMSG_HDRLEN + (int)NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));
	if (off > cap) return -1;

	struct nlmsghdr    *nlh = (struct nlmsghdr *)buf;
	struct sg_nfgenmsg *nfg = (struct sg_nfgenmsg *)(buf + NLMSG_HDRLEN);

	nfg->nfgen_family = AF_INET;
	nfg->version      = NFNETLINK_V0;
	nfg->res_id       = 0;

	/* CTA_TUPLE_ORIG (nested) */
	int tuple = nla_nest_start(buf, &off, cap, SG_CTA_TUPLE_ORIG);
	if (tuple < 0) return -1;

	/* CTA_TUPLE_IP (nested) */
	int ip_nest = nla_nest_start(buf, &off, cap, SG_CTA_TUPLE_IP);
	if (ip_nest < 0) return -1;
	{
		uint32_t s = htonl(src_ip), d = htonl(dst_ip);
		if (nla_put_raw(buf, &off, cap, SG_CTA_IP_V4_SRC, &s, 4) < 0) return -1;
		if (nla_put_raw(buf, &off, cap, SG_CTA_IP_V4_DST, &d, 4) < 0) return -1;
	}
	nla_nest_end(buf, ip_nest, off);

	/* CTA_TUPLE_PROTO (nested) */
	int pr_nest = nla_nest_start(buf, &off, cap, SG_CTA_TUPLE_PROTO);
	if (pr_nest < 0) return -1;
	{
		if (nla_put_raw(buf, &off, cap, SG_CTA_PROTO_NUM, &proto, 1) < 0) return -1;
		if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
			uint16_t sp = htons(sport), dp = htons(dport);
			if (nla_put_raw(buf, &off, cap, SG_CTA_PROTO_SRC_PORT, &sp, 2) < 0) return -1;
			if (nla_put_raw(buf, &off, cap, SG_CTA_PROTO_DST_PORT, &dp, 2) < 0) return -1;
		}
	}
	nla_nest_end(buf, pr_nest, off);
	nla_nest_end(buf, tuple, off);

	/* patch nlmsghdr */
	nlh->nlmsg_len   = (uint32_t)NLMSG_ALIGN((size_t)off);
	nlh->nlmsg_type  = (uint16_t)((SG_NFNL_SUBSYS_CTNETLINK << 8) |
				       SG_IPCTNL_MSG_CT_GET);
	nlh->nlmsg_flags = NLM_F_REQUEST;   /* exact lookup — no DUMP */
	nlh->nlmsg_seq   = 1;

	return off;
}

/* ---- query (I/O netlink) ------------------------------------------------- */

int ctdump_query(uint32_t src_ip, uint32_t dst_ip,
		 uint16_t sport,  uint16_t dport,
		 uint8_t  proto,
		 struct ctdump_result *out)
{
	char req[512];
	int  rlen = build_ct_get(req, (int)sizeof(req),
				 src_ip, dst_ip, sport, dport, proto);
	if (rlen < 0)
		return -1;

	int fd = socket(AF_NETLINK, SOCK_RAW, SG_NETLINK_NETFILTER);
	if (fd < 0)
		return -1;

	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	struct sockaddr_nl sa;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	if (sendto(fd, req, (size_t)rlen, 0,
		   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	char rbuf[8192];
	ssize_t rn = recv(fd, rbuf, sizeof(rbuf), 0);
	close(fd);

	if (rn <= 0)
		return -1;

	/* Walk response messages */
	struct nlmsghdr *nh;
	int rem = (int)rn;
	for (nh = (struct nlmsghdr *)rbuf; NLMSG_OK(nh, rem);
	     nh = NLMSG_NEXT(nh, rem)) {

		if (nh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = NLMSG_DATA(nh);
			(void)err;   /* ENOENT → flow does not exist */
			return -1;
		}
		if (nh->nlmsg_type == NLMSG_DONE)
			break;

		/* Payload: skip the nfgenmsg header → attrs */
		const void *attrs = (const char *)NLMSG_DATA(nh) +
				    NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));
		int alen = (int)nh->nlmsg_len - NLMSG_HDRLEN -
			   (int)NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));

		if (alen > 0)
			return ctdump_parse_response(attrs, alen, out);
	}
	return -1;
}

/* ---- dump ALL flows ------------------------------------------------------ */

/* Parse CTA_TUPLE_ORIG → 5-tuple (host order) into *f. Returns 0/-1. */
static int parse_tuple(const void *attrs, int alen, struct ctdump_flow *f)
{
	int tl = 0;
	const void *tuple = sg_nla_find(attrs, alen, SG_CTA_TUPLE_ORIG, &tl);
	if (!tuple)
		return -1;

	int il = 0;
	const void *ip = sg_nla_find(tuple, tl, SG_CTA_TUPLE_IP, &il);
	if (ip) {
		int l;
		const void *s = sg_nla_find(ip, il, SG_CTA_IP_V4_SRC, &l);
		const void *d = sg_nla_find(ip, il, SG_CTA_IP_V4_DST, &l);
		if (s) { uint32_t v; memcpy(&v, s, 4); f->src_ip = ntohl(v); }
		if (d) { uint32_t v; memcpy(&v, d, 4); f->dst_ip = ntohl(v); }
	}

	int pl = 0;
	const void *pr = sg_nla_find(tuple, tl, SG_CTA_TUPLE_PROTO, &pl);
	if (pr) {
		int l;
		const void *pn = sg_nla_find(pr, pl, SG_CTA_PROTO_NUM, &l);
		const void *sp = sg_nla_find(pr, pl, SG_CTA_PROTO_SRC_PORT, &l);
		const void *dp = sg_nla_find(pr, pl, SG_CTA_PROTO_DST_PORT, &l);
		if (pn) f->proto = *(const uint8_t *)pn;
		if (sp) { uint16_t v; memcpy(&v, sp, 2); f->sport = ntohs(v); }
		if (dp) { uint16_t v; memcpy(&v, dp, 2); f->dport = ntohs(v); }
	}
	return 0;
}

int ctdump_dump_all(ctdump_flow_cb cb, void *ctx)
{
	/* Request: nlmsghdr + nfgenmsg, NO tuple, NLM_F_DUMP flag → all flows. */
	char req[64];
	memset(req, 0, sizeof(req));
	int off = NLMSG_HDRLEN + (int)NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));
	struct nlmsghdr    *nlh = (struct nlmsghdr *)req;
	struct sg_nfgenmsg *nfg = (struct sg_nfgenmsg *)(req + NLMSG_HDRLEN);
	nfg->nfgen_family = AF_INET;
	nfg->version      = NFNETLINK_V0;
	nfg->res_id       = 0;
	nlh->nlmsg_len   = (uint32_t)NLMSG_ALIGN((size_t)off);
	nlh->nlmsg_type  = (uint16_t)((SG_NFNL_SUBSYS_CTNETLINK << 8) |
				       SG_IPCTNL_MSG_CT_GET);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq   = 1;

	int fd = socket(AF_NETLINK, SOCK_RAW, SG_NETLINK_NETFILTER);
	if (fd < 0)
		return -1;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	struct sockaddr_nl sa;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	if (sendto(fd, req, nlh->nlmsg_len, 0,
		   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	char *rbuf = malloc(65536);
	if (!rbuf) { close(fd); return -1; }

	int count = 0, done = 0;
	while (!done) {
		ssize_t rn = recv(fd, rbuf, 65536, 0);
		if (rn <= 0)
			break;                       /* timeout / error → end of dump */

		struct nlmsghdr *nh;
		int rem = (int)rn;
		for (nh = (struct nlmsghdr *)rbuf; NLMSG_OK(nh, rem);
		     nh = NLMSG_NEXT(nh, rem)) {
			if (nh->nlmsg_type == NLMSG_DONE ||
			    nh->nlmsg_type == NLMSG_ERROR) { done = 1; break; }

			const void *attrs = (const char *)NLMSG_DATA(nh) +
					    NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));
			int al = (int)nh->nlmsg_len - NLMSG_HDRLEN -
				 (int)NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));
			if (al <= 0)
				continue;

			struct ctdump_flow f;
			memset(&f, 0, sizeof(f));
			parse_tuple(attrs, al, &f);
			ctdump_parse_response(attrs, al, &f.res);  /* res is memset inside */
			count++;
			if (cb && cb(&f, ctx) != 0) { done = 1; break; }
		}
	}
	free(rbuf);
	close(fd);
	return count;
}

/* ---- conversion helpers -------------------------------------------------- */

void ctdump_to_flow_stats(const struct ctdump_result *r,
			  struct flow_stats *fs)
{
	memset(fs, 0, sizeof(*fs));
	if (!r->ml_valid)
		return;

	fs->syn_count     = r->ml.syn_count;
	fs->ack_count     = r->ml.ack_count;
	fs->psh_count     = r->ml.psh_count;
	fs->urg_count     = r->ml.urg_count;
	fs->tcp_flags_fwd = r->ml.tcp_flags[0];
	fs->tcp_flags_bwd = r->ml.tcp_flags[1];

	/* pkts_fwd/bwd: prefer ACCT (exact); fall back to estimating from bytes */
	if (r->acct_valid) {
		fs->pkts_fwd = (uint32_t)(r->pkts_orig  <= UINT32_MAX ? r->pkts_orig  : UINT32_MAX);
		fs->pkts_bwd = (uint32_t)(r->pkts_reply <= UINT32_MAX ? r->pkts_reply : UINT32_MAX);
	} else {
		/* no ACCT: estimate from bytes (inexact, L1 use only) */
		uint32_t avg = 512;
		fs->pkts_fwd = r->ml.bytes_fwd ? (uint32_t)((r->ml.bytes_fwd + avg - 1) / avg) : 0;
		fs->pkts_bwd = r->ml.bytes_bwd ? (uint32_t)((r->ml.bytes_bwd + avg - 1) / avg) : 0;
	}
}

void ctdump_to_features(const struct ctdump_result *r,
			uint32_t pkts_fwd, uint32_t pkts_bwd,
			int32_t  init_win_fwd,
			double   feat[FEAT_COUNT])
{
	feature_extract(&r->ml, pkts_fwd, pkts_bwd, init_win_fwd, feat);
}
