/* SPDX-License-Identifier: MIT */
/*
 * nfq_test.c - test nfq_parse_packet() + connmark bits, HOST only.
 *
 *   gcc -O2 -Wall -Wextra -std=c11 -fsanitize=address,undefined \
 *       -o /tmp/nfq_test nfq.c nfq_test.c && /tmp/nfq_test
 */
#define _GNU_SOURCE
#include "nfq.h"
#include "sig_rule.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static int g_failed;

static void check(int cond, const char *name)
{
	printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
	if (!cond) g_failed++;
}

/* ---- synthetic packet builders ------------------------------------------- */

/* IP checksum (not required for the parse test, but for completeness) */
static uint16_t ip_cksum(const void *p, int len)
{
	const uint16_t *w = p; uint32_t s = 0;
	while (len > 1) { s += *w++; len -= 2; }
	if (len) s += *(const uint8_t *)w;
	s = (s >> 16) + (s & 0xffff); s += (s >> 16);
	return (uint16_t)~s;
}

/* Build a TCP SYN packet: src 1.2.3.4:12345 → dst 5.6.7.8:80, window=65535 */
static int build_syn(uint8_t *buf, int cap,
		     const char *payload, int plen)
{
	int total = 20 + 20 + plen;
	if (total > cap) return -1;
	memset(buf, 0, (size_t)total);

	struct iphdr *iph = (struct iphdr *)buf;
	iph->version = 4; iph->ihl = 5;
	iph->tot_len = htons((uint16_t)total);
	iph->protocol = IPPROTO_TCP;
	iph->saddr = htonl(0x01020304); /* 1.2.3.4 */
	iph->daddr = htonl(0x05060708); /* 5.6.7.8 */
	iph->check = ip_cksum(iph, 20);

	struct tcphdr *th = (struct tcphdr *)(buf + 20);
	th->source = htons(12345);
	th->dest   = htons(80);
	th->doff   = 5;
	th->syn    = 1;
	th->window = htons(65535);

	if (plen > 0)
		memcpy(buf + 40, payload, (size_t)plen);
	return total;
}

/* TCP ACK (not a SYN) */
static int build_ack(uint8_t *buf, int cap,
		     uint16_t sport, uint16_t dport,
		     const char *payload, int plen)
{
	int total = 20 + 20 + plen;
	if (total > cap) return -1;
	memset(buf, 0, (size_t)total);

	struct iphdr *iph = (struct iphdr *)buf;
	iph->version = 4; iph->ihl = 5;
	iph->tot_len = htons((uint16_t)total);
	iph->protocol = IPPROTO_TCP;
	iph->saddr = htonl(0x01020304);
	iph->daddr = htonl(0x05060708);

	struct tcphdr *th = (struct tcphdr *)(buf + 20);
	th->source = htons(sport);
	th->dest   = htons(dport);
	th->doff   = 5;
	th->ack    = 1; th->psh = 1;
	th->window = htons(8192);

	if (plen > 0)
		memcpy(buf + 40, payload, (size_t)plen);
	return total;
}

/* UDP packet */
static int build_udp(uint8_t *buf, int cap,
		     uint16_t sport, uint16_t dport,
		     const char *payload, int plen)
{
	int total = 20 + 8 + plen;
	if (total > cap) return -1;
	memset(buf, 0, (size_t)total);

	struct iphdr *iph = (struct iphdr *)buf;
	iph->version = 4; iph->ihl = 5;
	iph->tot_len = htons((uint16_t)total);
	iph->protocol = IPPROTO_UDP;
	iph->saddr = htonl(0xc0a80101);
	iph->daddr = htonl(0xc0a80102);

	struct udphdr *uh = (struct udphdr *)(buf + 20);
	uh->source = htons(sport);
	uh->dest   = htons(dport);
	uh->len    = htons((uint16_t)(8 + plen));

	if (plen > 0)
		memcpy(buf + 28, payload, (size_t)plen);
	return total;
}

/* ---- tests --------------------------------------------------------------- */

static void t1_syn(void)
{
	printf("T1 parse TCP SYN:\n");
	uint8_t buf[256]; int len;
	len = build_syn(buf, sizeof(buf), NULL, 0);

	struct nfq_pkt pkt;
	int rc = nfq_parse_packet(buf, (uint16_t)len, &pkt);

	check(rc == 0,                        "parse OK");
	check(pkt.proto == IPPROTO_TCP,       "proto TCP");
	check(pkt.src_ip == 0x01020304,       "src_ip 1.2.3.4");
	check(pkt.dst_ip == 0x05060708,       "dst_ip 5.6.7.8");
	check(pkt.sport == 12345,             "sport 12345");
	check(pkt.dport == 80,                "dport 80");
	check(pkt.tcp_flags == SIG_TCP_SYN,   "flags = SYN only");
	check(pkt.init_win == 65535,          "init_win = 65535 (from SYN)");
	check(pkt.plen == 0,                  "payload = 0 (SYN has no data)");
}

static void t2_ack_payload(void)
{
	printf("T2 parse TCP ACK+PSH with payload:\n");
	uint8_t buf[256]; int len;
	const char *pl = "GET / HTTP/1.0\r\n";
	len = build_ack(buf, sizeof(buf), 54321, 80, pl, (int)strlen(pl));

	struct nfq_pkt pkt;
	nfq_parse_packet(buf, (uint16_t)len, &pkt);

	check((pkt.tcp_flags & SIG_TCP_ACK) && (pkt.tcp_flags & SIG_TCP_PSH),
	      "flags ACK+PSH");
	check(pkt.init_win == -1,             "init_win = -1 (not a SYN)");
	check(pkt.plen == (uint16_t)strlen(pl), "payload length correct");
	check(pkt.payload && memcmp(pkt.payload, pl, pkt.plen) == 0,
	      "payload content correct");
}

static void t3_udp(void)
{
	printf("T3 parse UDP:\n");
	uint8_t buf[128]; int len;
	const char *pl = "dns-query";
	len = build_udp(buf, sizeof(buf), 12345, 53, pl, (int)strlen(pl));

	struct nfq_pkt pkt;
	nfq_parse_packet(buf, (uint16_t)len, &pkt);

	check(pkt.proto == IPPROTO_UDP,   "proto UDP");
	check(pkt.dport == 53,            "dport 53 (DNS)");
	check(pkt.tcp_flags == 0,         "tcp_flags = 0 for UDP");
	check(pkt.init_win == -1,         "init_win = -1 for UDP");
	check(pkt.plen == (uint16_t)strlen(pl), "payload length UDP");
}

static void t4_edge(void)
{
	printf("T4 edge cases:\n");
	struct nfq_pkt pkt;

	check(nfq_parse_packet(NULL, 0, &pkt) == -1, "NULL → -1");

	/* header too short */
	uint8_t short_buf[10] = {0x45, 0, 0, 20}; /* tot_len=20 but buf is only 10B */
	check(nfq_parse_packet(short_buf, 10, &pkt) == -1, "buf<ihl → -1");

	/* version != 4 */
	uint8_t v6buf[40]; memset(v6buf, 0, sizeof(v6buf));
	v6buf[0] = 0x60;  /* version 6 */
	check(nfq_parse_packet(v6buf, 40, &pkt) == -1, "IPv6 → -1");
}

static void t5_flow_ctx(void)
{
	printf("T5 nfq_pkt_to_flow_ctx:\n");
	uint8_t buf[256]; int len;
	len = build_syn(buf, sizeof(buf), NULL, 0);

	struct nfq_pkt pkt;
	nfq_parse_packet(buf, (uint16_t)len, &pkt);

	struct flow_ctx fc;
	nfq_pkt_to_flow_ctx(&pkt, &fc);

	check(fc.proto == SIG_PROTO_TCP, "proto = SIG_PROTO_TCP");
	check(fc.dport == 80,            "dport = 80");
	check(fc.tcp_flags == SIG_TCP_SYN, "flags = SYN");
}

static void t6_connmark_bits(void)
{
	printf("T6 connmark bits:\n");
	check((SG_CMK_IPS_BLOCK & SG_CMK_IPS_INSPECTED) == 0,
	      "BLOCK and INSPECTED do not overlap");
	check((SG_CMK_IPS_BLOCK & 0x1) == 0,
	      "BLOCK does not touch DIRTY (bit 0)");
	check((SG_CMK_IPS_INSPECTED & 0x1) == 0,
	      "INSPECTED does not touch DIRTY (bit 0)");
	check((SG_CMK_IPS_BLOCK & ~0xFF) == 0,
	      "BLOCK in the low byte (does not touch policy_id bits 8-31)");
}

int main(void)
{
	t1_syn();
	t2_ack_payload();
	t3_udp();
	t4_edge();
	t5_flow_ctx();
	t6_connmark_bits();

	printf("\n%s (%d tests failed)\n",
	       g_failed ? "=== FAILURES ===" : "=== ALL PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
