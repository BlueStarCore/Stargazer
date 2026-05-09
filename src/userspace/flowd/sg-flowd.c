// SPDX-License-Identifier: MIT
/*
 * sg-flowd.c - Stargazer NetFlow v9 exporter daemon
 *
 * Copyright (C) 2026 Stargazer Team
 *
 * Subscribes to the "sg_flow" Generic Netlink family exported by session.ko.
 * On each SESS_EXPIRED event it formats a NetFlow v9 record and sends it via
 * UDP to the configured collector.  SESS_NEW events are received but ignored
 * (reserved for the Phase 4 ML daemon).
 *
 * Config: /etc/stargazer/flowd.conf  (key=value, one per line)
 *   collector_ip=<ip>      collector IPv4 address (default: 127.0.0.1)
 *   collector_port=<port>  collector UDP port     (default: 2055)
 *   source_id=<id>         NetFlow observation domain ID (default: 1)
 *   enabled=<0|1>          enable/disable export  (default: 1)
 *
 * Runtime files:
 *   /run/stargazer/flowd.pid  — PID of the running daemon
 *   /run/stargazer/flowd.stat — live statistics (key=value)
 *
 * Signals:
 *   SIGHUP  — reload config (new collector/port takes effect immediately)
 *   SIGTERM/SIGINT — clean shutdown
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#include "../../modules/sg_flow.h"

/* ── Runtime paths ───────────────────────────────────────────────────────── */

#define FLOWD_CONF_PATH  "/etc/stargazer/flowd.conf"
#define FLOWD_PID_PATH   "/run/stargazer/flowd.pid"
#define FLOWD_STAT_PATH  "/run/stargazer/flowd.stat"
#define FLOWD_RUN_DIR    "/run/stargazer"

/* ── NLA helpers ─────────────────────────────────────────────────────────── */

#define MY_NLA_ALIGN(n)    (((n) + 3) & ~3)
#define MY_NLA_HDRLEN      ((int)MY_NLA_ALIGN(sizeof(struct nlattr)))
#define MY_NLA_OK(nla, n)  ((n) >= MY_NLA_HDRLEN && \
                            (nla)->nla_len >= MY_NLA_HDRLEN && \
                            (nla)->nla_len <= (n))
#define MY_NLA_NEXT(nla, n) \
	((n) -= MY_NLA_ALIGN((nla)->nla_len), \
	 (struct nlattr *)((char *)(nla) + MY_NLA_ALIGN((nla)->nla_len)))
#define MY_NLA_DATA(nla)   ((void *)((char *)(nla) + MY_NLA_HDRLEN))
#define MY_NLA_PLEN(nla)   ((int)((nla)->nla_len - MY_NLA_HDRLEN))

/* ── NetFlow v9 (RFC 3954) ──────────────────────────────────────────────── */

#define NF9_VERSION          9
#define NF9_TEMPLATE_ID    256
#define NF9_TEMPLATE_REFRESH 512  /* re-send template every N data records */

/* RFC 3954 field type numbers */
#define NF9_IN_BYTES        1
#define NF9_IN_PKTS         2
#define NF9_PROTOCOL        4
#define NF9_TCP_FLAGS       6
#define NF9_L4_SRC_PORT     7
#define NF9_IPV4_SRC_ADDR   8
#define NF9_L4_DST_PORT    11
#define NF9_IPV4_DST_ADDR  12
#define NF9_LAST_SWITCHED  21
#define NF9_FIRST_SWITCHED 22
#define NF9_OUT_BYTES      23
#define NF9_OUT_PKTS       24

#define NF9_RECORD_FIELDS  12

struct __attribute__((packed)) nf9_header {
	uint16_t version;
	uint16_t count;
	uint32_t sys_uptime;   /* ms since router boot */
	uint32_t unix_secs;
	uint32_t pkg_sequence;
	uint32_t source_id;
};

struct __attribute__((packed)) nf9_flowset_hdr {
	uint16_t flowset_id;
	uint16_t length;
};

struct __attribute__((packed)) nf9_tpl_hdr {
	uint16_t template_id;
	uint16_t field_count;
};

struct __attribute__((packed)) nf9_field {
	uint16_t type;
	uint16_t length;
};

/* Data record layout — must match template field order exactly */
struct __attribute__((packed)) nf9_record {
	uint8_t  protocol;
	uint32_t ipv4_src_addr;
	uint32_t ipv4_dst_addr;
	uint16_t l4_src_port;
	uint16_t l4_dst_port;
	uint32_t in_pkts;
	uint32_t in_bytes;
	uint32_t out_pkts;
	uint32_t out_bytes;
	uint32_t first_switched;
	uint32_t last_switched;
	uint8_t  tcp_flags;
};

/* ── Config ─────────────────────────────────────────────────────────────── */

typedef struct {
	char     collector_ip[64];
	uint16_t collector_port;
	uint32_t source_id;
	int      enabled;
} flowd_config_t;

static void config_defaults(flowd_config_t *cfg)
{
	strncpy(cfg->collector_ip, "127.0.0.1", sizeof(cfg->collector_ip) - 1);
	cfg->collector_ip[sizeof(cfg->collector_ip) - 1] = '\0';
	cfg->collector_port = 2055;
	cfg->source_id      = 1;
	cfg->enabled        = 1;
}

static void config_load(flowd_config_t *cfg, const char *path)
{
	FILE *f = fopen(path, "r");
	char  line[256];

	if (!f)
		return;

	while (fgets(line, sizeof(line), f)) {
		char *eq = strchr(line, '=');
		char *nl;

		if (!eq)
			continue;
		*eq = '\0';
		nl = strchr(eq + 1, '\n');
		if (nl)
			*nl = '\0';

		if (strcmp(line, "collector_ip") == 0) {
			strncpy(cfg->collector_ip, eq + 1,
				sizeof(cfg->collector_ip) - 1);
			cfg->collector_ip[sizeof(cfg->collector_ip) - 1] = '\0';
		} else if (strcmp(line, "collector_port") == 0) {
			long port = strtol(eq + 1, NULL, 10);
			if (port < 1 || port > 65535) {
				fprintf(stderr, "flowd: invalid collector_port %ld, using default 2055\n", port);
				port = 2055;
			}
			cfg->collector_port = (uint16_t)port;
		} else if (strcmp(line, "source_id") == 0) {
			cfg->source_id = (uint32_t)strtoul(eq + 1, NULL, 10);
		} else if (strcmp(line, "enabled") == 0) {
			cfg->enabled = atoi(eq + 1);
		}
	}
	fclose(f);
}

/* ── Stats ──────────────────────────────────────────────────────────────── */

typedef struct {
	uint64_t records_sent;
	uint64_t bytes_sent;
	uint64_t errors;
	time_t   start_time;
} flowd_stats_t;

static void stats_write(const flowd_stats_t *st, const flowd_config_t *cfg)
{
	/* Write to a temp file then rename() for atomic visibility — mgmtd
	 * reading the stats file between an fopen()+fclose() pair would see
	 * an empty file otherwise. */
	char tmp[sizeof(FLOWD_STAT_PATH) + 5];
	snprintf(tmp, sizeof(tmp), "%s.tmp", FLOWD_STAT_PATH);

	FILE *f = fopen(tmp, "w");
	if (!f)
		return;
	fprintf(f,
		"running=1\n"
		"records_sent=%llu\n"
		"bytes_sent=%llu\n"
		"errors=%llu\n"
		"uptime_s=%lld\n"
		"collector=%s:%u\n"
		"enabled=%d\n",
		(unsigned long long)st->records_sent,
		(unsigned long long)st->bytes_sent,
		(unsigned long long)st->errors,
		(long long)(time(NULL) - st->start_time),
		cfg->collector_ip, cfg->collector_port,
		cfg->enabled);
	fclose(f);
	rename(tmp, FLOWD_STAT_PATH);
}

/* ── Signals ─────────────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_reload = 0;
static volatile sig_atomic_t g_quit   = 0;

static void sig_handler(int sig)
{
	if (sig == SIGHUP)
		g_reload = 1;
	else
		g_quit = 1;
}

/* ── PID file ────────────────────────────────────────────────────────────── */

static void pid_write(void)
{
	FILE *f;

	mkdir(FLOWD_RUN_DIR, 0755);
	f = fopen(FLOWD_PID_PATH, "w");
	if (f) {
		fprintf(f, "%d\n", (int)getpid());
		fclose(f);
	}
}

/* ── UDP socket ──────────────────────────────────────────────────────────── */

static int udp_open(const flowd_config_t *cfg, struct sockaddr_in *dst)
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (sock < 0)
		return -1;

	memset(dst, 0, sizeof(*dst));
	dst->sin_family = AF_INET;
	dst->sin_port   = htons(cfg->collector_port);
	if (inet_pton(AF_INET, cfg->collector_ip, &dst->sin_addr) != 1) {
		close(sock);
		return -1;
	}
	return sock;
}

/* ── Uptime ──────────────────────────────────────────────────────────────── */

static uint32_t uptime_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint32_t)((uint64_t)ts.tv_sec * 1000 +
			  (uint64_t)ts.tv_nsec / 1000000);
}

/* ── Generic Netlink family resolver ────────────────────────────────────── */

/*
 * Send CTRL_CMD_GETFAMILY and parse the response to find the family ID and
 * the numeric multicast group ID for SG_FLOW_MCGRP_NAME.
 */
static int genl_resolve(int nlsock, uint16_t *family_id, uint32_t *mcgrp_id)
{
	struct {
		struct nlmsghdr   nlh;
		struct genlmsghdr gnlh;
		struct nlattr     nla;
		char              name[GENL_NAMSIZ];
	} req;
	char              resp[4096];
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
	struct nlmsghdr  *nlh;
	struct genlmsghdr *gnlh;
	struct nlattr    *nla;
	int               nla_len, name_len;
	ssize_t           n;

	memset(&req, 0, sizeof(req));
	strncpy(req.name, SG_FLOW_GENL_NAME, GENL_NAMSIZ - 1);
	name_len = (int)strlen(SG_FLOW_GENL_NAME) + 1;

	req.nla.nla_type = CTRL_ATTR_FAMILY_NAME;
	req.nla.nla_len  = (uint16_t)(MY_NLA_HDRLEN + name_len);

	req.gnlh.cmd     = CTRL_CMD_GETFAMILY;
	req.gnlh.version = 1;

	req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.gnlh) +
				MY_NLA_ALIGN(req.nla.nla_len));
	req.nlh.nlmsg_type  = GENL_ID_CTRL;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_seq   = 1;
	req.nlh.nlmsg_pid   = (uint32_t)getpid();

	if (sendto(nlsock, &req, req.nlh.nlmsg_len, 0,
		   (struct sockaddr *)&addr, sizeof(addr)) < 0)
		return -1;

	n = recv(nlsock, resp, sizeof(resp), 0);
	if (n < 0)
		return -1;

	nlh = (struct nlmsghdr *)resp;
	if (!NLMSG_OK(nlh, (uint32_t)n) || nlh->nlmsg_type == NLMSG_ERROR)
		return -1;

	gnlh    = NLMSG_DATA(nlh);
	nla     = (struct nlattr *)((char *)gnlh + NLMSG_ALIGN(sizeof(*gnlh)));
	nla_len = (int)NLMSG_PAYLOAD(nlh, sizeof(*gnlh));

	*family_id = 0;
	*mcgrp_id  = 0;

	while (MY_NLA_OK(nla, nla_len)) {
		if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
			uint16_t fid;
			memcpy(&fid, MY_NLA_DATA(nla), sizeof(fid));
			*family_id = fid;
		} else if (nla->nla_type == CTRL_ATTR_MCAST_GROUPS) {
			struct nlattr *grp;
			int grp_rem = MY_NLA_PLEN(nla);

			grp = MY_NLA_DATA(nla);
			while (MY_NLA_OK(grp, grp_rem)) {
				struct nlattr *ga;
				int            ga_rem = MY_NLA_PLEN(grp);
				char           gname[GENL_NAMSIZ] = {0};
				uint32_t       gid = 0;

				ga = MY_NLA_DATA(grp);
				while (MY_NLA_OK(ga, ga_rem)) {
					if (ga->nla_type == CTRL_ATTR_MCAST_GRP_NAME)
						strncpy(gname, MY_NLA_DATA(ga),
							sizeof(gname) - 1);
					else if (ga->nla_type == CTRL_ATTR_MCAST_GRP_ID)
						memcpy(&gid, MY_NLA_DATA(ga),
						       sizeof(gid));
					ga = MY_NLA_NEXT(ga, ga_rem);
				}
				if (strcmp(gname, SG_FLOW_MCGRP_NAME) == 0)
					*mcgrp_id = gid;

				grp = MY_NLA_NEXT(grp, grp_rem);
			}
		}
		nla = MY_NLA_NEXT(nla, nla_len);
	}

	return (*family_id && *mcgrp_id) ? 0 : -1;
}

/* ── NetFlow v9 sender ───────────────────────────────────────────────────── */

/* Template field descriptors: {RFC3954 type, field length in bytes} */
static const struct { uint16_t type; uint16_t len; }
nf9_tpl_desc[NF9_RECORD_FIELDS] = {
	{ NF9_PROTOCOL,       1 },
	{ NF9_IPV4_SRC_ADDR,  4 },
	{ NF9_IPV4_DST_ADDR,  4 },
	{ NF9_L4_SRC_PORT,    2 },
	{ NF9_L4_DST_PORT,    2 },
	{ NF9_IN_PKTS,        4 },
	{ NF9_IN_BYTES,       4 },
	{ NF9_OUT_PKTS,       4 },
	{ NF9_OUT_BYTES,      4 },
	{ NF9_FIRST_SWITCHED, 4 },
	{ NF9_LAST_SWITCHED,  4 },
	{ NF9_TCP_FLAGS,      1 },
};

static int nf9_send_template(int udp_sock, const struct sockaddr_in *dst,
			     const flowd_config_t *cfg, uint32_t *seq)
{
	struct nf9_field fields[NF9_RECORD_FIELDS];
	int i;

	for (i = 0; i < NF9_RECORD_FIELDS; i++) {
		fields[i].type   = htons(nf9_tpl_desc[i].type);
		fields[i].length = htons(nf9_tpl_desc[i].len);
	}

	struct {
		struct nf9_header      hdr;
		struct nf9_flowset_hdr fshdr;
		struct nf9_tpl_hdr     tplhdr;
		struct nf9_field       flds[NF9_RECORD_FIELDS];
		uint8_t                pad[2];
	} __attribute__((packed)) pkt;
	ssize_t sent;

	memset(&pkt, 0, sizeof(pkt));

	pkt.hdr.version      = htons(NF9_VERSION);
	pkt.hdr.count        = htons(1);
	pkt.hdr.sys_uptime   = htonl(uptime_ms());
	pkt.hdr.unix_secs    = htonl((uint32_t)time(NULL));
	pkt.hdr.pkg_sequence = htonl((*seq)++);
	pkt.hdr.source_id    = htonl(cfg->source_id);

	pkt.fshdr.flowset_id = htons(0);
	pkt.fshdr.length     = htons((uint16_t)(sizeof(pkt.fshdr) +
					sizeof(pkt.tplhdr) +
					sizeof(pkt.flds) + sizeof(pkt.pad)));

	pkt.tplhdr.template_id = htons(NF9_TEMPLATE_ID);
	pkt.tplhdr.field_count = htons(NF9_RECORD_FIELDS);
	memcpy(pkt.flds, fields, sizeof(fields));

	sent = sendto(udp_sock, &pkt, sizeof(pkt), 0,
		      (const struct sockaddr *)dst, sizeof(*dst));
	return (sent == (ssize_t)sizeof(pkt)) ? 0 : -1;
}

static int nf9_send_record(int udp_sock, const struct sockaddr_in *dst,
			   const flowd_config_t *cfg, uint32_t *seq,
			   struct nlattr **attrs, flowd_stats_t *stats)
{
	struct {
		struct nf9_header      hdr;
		struct nf9_flowset_hdr fshdr;
		struct nf9_record      rec;
		uint8_t                pad[2];
	} __attribute__((packed)) pkt;

	uint64_t pkts_orig  = 0, pkts_reply  = 0;
	uint64_t bytes_orig = 0, bytes_reply = 0;
	uint64_t first_ns   = 0, last_ns     = 0;
	ssize_t  sent;

	memset(&pkt, 0, sizeof(pkt));

#define GET64(attr, dst64) \
	do { if (attrs[(attr)]) memcpy(&(dst64), MY_NLA_DATA(attrs[(attr)]), 8); } while (0)

	GET64(SG_FLOW_ATTR_PKTS_ORIG,    pkts_orig);
	GET64(SG_FLOW_ATTR_PKTS_REPLY,   pkts_reply);
	GET64(SG_FLOW_ATTR_BYTES_ORIG,   bytes_orig);
	GET64(SG_FLOW_ATTR_BYTES_REPLY,  bytes_reply);
	GET64(SG_FLOW_ATTR_FIRST_SEEN_NS, first_ns);
	GET64(SG_FLOW_ATTR_LAST_SEEN_NS,  last_ns);
#undef GET64

	/* IP and port: already in network byte order from the kernel */
	if (attrs[SG_FLOW_ATTR_SRC_IP])
		memcpy(&pkt.rec.ipv4_src_addr,
		       MY_NLA_DATA(attrs[SG_FLOW_ATTR_SRC_IP]), 4);
	if (attrs[SG_FLOW_ATTR_DST_IP])
		memcpy(&pkt.rec.ipv4_dst_addr,
		       MY_NLA_DATA(attrs[SG_FLOW_ATTR_DST_IP]), 4);
	if (attrs[SG_FLOW_ATTR_SRC_PORT])
		memcpy(&pkt.rec.l4_src_port,
		       MY_NLA_DATA(attrs[SG_FLOW_ATTR_SRC_PORT]), 2);
	if (attrs[SG_FLOW_ATTR_DST_PORT])
		memcpy(&pkt.rec.l4_dst_port,
		       MY_NLA_DATA(attrs[SG_FLOW_ATTR_DST_PORT]), 2);

	if (attrs[SG_FLOW_ATTR_PROTO])
		pkt.rec.protocol =
			*(uint8_t *)MY_NLA_DATA(attrs[SG_FLOW_ATTR_PROTO]);

	/* Merge orig+reply TCP flags into the single RFC 3954 field */
	if (attrs[SG_FLOW_ATTR_TCP_FLAGS_O]) {
		uint16_t fo = 0, fr = 0;
		memcpy(&fo, MY_NLA_DATA(attrs[SG_FLOW_ATTR_TCP_FLAGS_O]), 2);
		if (attrs[SG_FLOW_ATTR_TCP_FLAGS_R])
			memcpy(&fr, MY_NLA_DATA(attrs[SG_FLOW_ATTR_TCP_FLAGS_R]), 2);
		pkt.rec.tcp_flags = (uint8_t)((fo | fr) & 0xFF);
	}

	/* ktime_t in ns → ms since boot for FIRST/LAST_SWITCHED */
	pkt.rec.first_switched = htonl((uint32_t)(first_ns / 1000000));
	pkt.rec.last_switched  = htonl((uint32_t)(last_ns  / 1000000));

	/* Saturate to u32 — NetFlow v9 data fields are 4 bytes */
#define SAT32(v) ((uint32_t)((v) > 0xFFFFFFFFULL ? 0xFFFFFFFFU : (v)))
	pkt.rec.in_pkts   = htonl(SAT32(pkts_orig));
	pkt.rec.in_bytes  = htonl(SAT32(bytes_orig));
	pkt.rec.out_pkts  = htonl(SAT32(pkts_reply));
	pkt.rec.out_bytes = htonl(SAT32(bytes_reply));
#undef SAT32

	pkt.hdr.version      = htons(NF9_VERSION);
	pkt.hdr.count        = htons(1);
	pkt.hdr.sys_uptime   = htonl(uptime_ms());
	pkt.hdr.unix_secs    = htonl((uint32_t)time(NULL));
	pkt.hdr.pkg_sequence = htonl((*seq)++);
	pkt.hdr.source_id    = htonl(cfg->source_id);

	pkt.fshdr.flowset_id = htons(NF9_TEMPLATE_ID);
	pkt.fshdr.length     = htons((uint16_t)(sizeof(pkt.fshdr) +
					sizeof(pkt.rec) + sizeof(pkt.pad)));

	sent = sendto(udp_sock, &pkt, sizeof(pkt), 0,
		      (const struct sockaddr *)dst, sizeof(*dst));
	if (sent != (ssize_t)sizeof(pkt)) {
		stats->errors++;
		return -1;
	}
	stats->records_sent++;
	stats->bytes_sent += (uint64_t)sent;
	return 0;
}

/* ── NLA attribute parser ────────────────────────────────────────────────── */

static void parse_sg_attrs(struct nlattr *nla, int nla_len,
			   struct nlattr **attrs)
{
	memset(attrs, 0, __SG_FLOW_ATTR_MAX * sizeof(*attrs));
	while (MY_NLA_OK(nla, nla_len)) {
		unsigned int t = nla->nla_type & ~NLA_F_NESTED;
		if (t < (unsigned int)__SG_FLOW_ATTR_MAX)
			attrs[t] = nla;
		nla = MY_NLA_NEXT(nla, nla_len);
	}
}

/* ── Main event loop ─────────────────────────────────────────────────────── */

static void flowd_run(int nlsock, uint16_t family_id,
		      flowd_config_t *cfg, flowd_stats_t *stats)
{
	int               udp_sock = -1;
	struct sockaddr_in collector;
	uint32_t          nf_seq          = 0;
	uint64_t          recs_since_tpl  = 0;
	char              buf[65536];
	time_t            last_stat_write = 0;

	if (cfg->enabled) {
		udp_sock = udp_open(cfg, &collector);
		if (udp_sock >= 0) {
			nf9_send_template(udp_sock, &collector, cfg, &nf_seq);
			recs_since_tpl = 0;
		}
	}

	while (!g_quit) {
		struct pollfd pfd = { .fd = nlsock, .events = POLLIN };
		int rv;

		if (g_reload) {
			g_reload = 0;
			config_load(cfg, FLOWD_CONF_PATH);
			if (udp_sock >= 0) {
				close(udp_sock);
				udp_sock = -1;
			}
			if (cfg->enabled) {
				udp_sock = udp_open(cfg, &collector);
				if (udp_sock >= 0) {
					nf9_send_template(udp_sock, &collector,
							  cfg, &nf_seq);
					recs_since_tpl = 0;
				}
			}
		}

		if (time(NULL) - last_stat_write >= 10) {
			stats_write(stats, cfg);
			last_stat_write = time(NULL);
		}

		rv = poll(&pfd, 1, 1000);
		if (rv < 0 && errno == EINTR)
			continue;
		if (rv <= 0)
			continue;

		ssize_t n = recv(nlsock, buf, sizeof(buf), 0);
		if (n < 0)
			continue;

		struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
		while (NLMSG_OK(nlh, (uint32_t)n)) {
			struct genlmsghdr *gnlh;
			struct nlattr     *nla;
			int                nla_len;
			struct nlattr     *attrs[__SG_FLOW_ATTR_MAX];

			if (nlh->nlmsg_type != family_id)
				goto next_msg;

			gnlh    = NLMSG_DATA(nlh);
			nla     = (struct nlattr *)((char *)gnlh +
					NLMSG_ALIGN(sizeof(*gnlh)));
			nla_len = (int)NLMSG_PAYLOAD(nlh, sizeof(*gnlh));

			if (gnlh->cmd != SG_FLOW_CMD_SESS_EXPIRED)
				goto next_msg;

			parse_sg_attrs(nla, nla_len, attrs);

			if (cfg->enabled && udp_sock >= 0) {
				if (recs_since_tpl >= NF9_TEMPLATE_REFRESH) {
					nf9_send_template(udp_sock, &collector,
							  cfg, &nf_seq);
					recs_since_tpl = 0;
				}
				nf9_send_record(udp_sock, &collector, cfg,
						&nf_seq, attrs, stats);
				recs_since_tpl++;
			}

next_msg:
			n -= (ssize_t)NLMSG_ALIGN(nlh->nlmsg_len);
			nlh = (struct nlmsghdr *)((char *)nlh +
					NLMSG_ALIGN(nlh->nlmsg_len));
		}
	}

	if (udp_sock >= 0)
		close(udp_sock);
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void)
{
	flowd_config_t   cfg;
	flowd_stats_t    stats;
	int              nlsock;
	uint16_t         family_id = 0;
	uint32_t         mcgrp_id  = 0;
	struct sockaddr_nl sa;
	int              grp;

	signal(SIGHUP,  sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGINT,  sig_handler);

	config_defaults(&cfg);
	config_load(&cfg, FLOWD_CONF_PATH);

	memset(&stats, 0, sizeof(stats));
	stats.start_time = time(NULL);

	mkdir(FLOWD_RUN_DIR, 0755);
	pid_write();

	nlsock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nlsock < 0) {
		perror("sg-flowd: socket");
		return 1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_pid    = (uint32_t)getpid();
	if (bind(nlsock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("sg-flowd: bind");
		close(nlsock);
		return 1;
	}

	if (genl_resolve(nlsock, &family_id, &mcgrp_id) < 0) {
		fprintf(stderr,
			"sg-flowd: cannot resolve genl family '%s' "
			"(session.ko loaded?)\n", SG_FLOW_GENL_NAME);
		close(nlsock);
		return 1;
	}

	grp = (int)mcgrp_id;
	if (setsockopt(nlsock, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		       &grp, sizeof(grp)) < 0) {
		perror("sg-flowd: NETLINK_ADD_MEMBERSHIP");
		close(nlsock);
		return 1;
	}

	fprintf(stderr,
		"sg-flowd: started (family=%u mcgrp=%u collector=%s:%u)\n",
		family_id, mcgrp_id, cfg.collector_ip, cfg.collector_port);

	flowd_run(nlsock, family_id, &cfg, &stats);

	stats_write(&stats, &cfg);
	unlink(FLOWD_PID_PATH);
	close(nlsock);
	return 0;
}
