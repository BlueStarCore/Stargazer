// SPDX-License-Identifier: GPL-2.0-only
/*
 * pkt_forward.c - Packet forwarding module for Stargazer NGFW
 *
 * Copyright (C) 2026 Stargazer Team
 *
 * Registers Netfilter hook at NF_INET_FORWARD to inspect and control
 * packets traversing the router. All valid IPv4 packets are accepted;
 * malformed packets are dropped and counted.
 *
 * Session tracking: Uses session.c RCU hash table for 5-tuple tracking.
 *   - Phase 3: IPS signature matching
 *   - Phase 4: ML-based threat detection
 */

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <net/ip.h>

/* Session tracking API (exported by session.ko) */
struct sess_key {
	__be32	src_ip;
	__be32	dst_ip;
	__be16	src_port;
	__be16	dst_port;
	u8	proto;
} __packed;

struct session;

extern int extract_key(struct sk_buff *skb, struct sess_key *key);
extern struct session *sess_get_or_create(const struct sess_key *key);
extern void sess_update(struct session *s, struct sk_buff *skb, int dir);

#ifndef PKT_FWD_VERSION
#define PKT_FWD_VERSION "unknown"
#endif

/* Statistics counters (atomic for SMP safety) */
static atomic64_t pkts_forwarded = ATOMIC64_INIT(0);
static atomic64_t pkts_dropped   = ATOMIC64_INIT(0);
static atomic64_t sess_tracked   = ATOMIC64_INIT(0);

/**
 * is_valid_ipv4 - Validate IPv4 packet header
 * @skb: socket buffer containing the packet
 *
 * Performs basic sanity checks on IP header:
 *   - Ensures header is accessible via pskb_may_pull
 *   - Verifies IPv4 version field
 *   - Checks minimum header length (20 bytes)
 *
 * Return: true if valid, false otherwise
 */
static bool is_valid_ipv4(struct sk_buff *skb)
{
	struct iphdr *iph;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return false;

	iph = ip_hdr(skb);
	if (!iph || iph->version != 4 || iph->ihl < 5)
		return false;

	return true;
}

/**
 * forward_hook - Netfilter hook callback for FORWARD chain
 * @priv: private data (unused)
 * @skb: socket buffer
 * @state: hook state containing in/out interfaces
 *
 * Called for every packet being forwarded between interfaces.
 * Validates packet, tracks sessions, and updates statistics.
 *
 * Return: NF_ACCEPT to forward, NF_DROP to discard
 */
static unsigned int forward_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct sess_key key;
	struct session *s;
	int dir = 0; /* 0 = forward (client->server), 1 = backward */

	if (!is_valid_ipv4(skb)) {
		atomic64_inc(&pkts_dropped);
		return NF_DROP;
	}

	iph = ip_hdr(skb);

	/* Extract 5-tuple session key */
	if (extract_key(skb, &key) == 0) {
		/* Lookup or create session */
		s = sess_get_or_create(&key);
		if (s) {
			/* Determine packet direction based on interface
			 * If incoming interface is LAN/WAN relative to session
			 * first-seen direction, classify accordingly.
			 */
			dir = 0; /* Default forward direction */
			sess_update(s, skb, dir);
			atomic64_inc(&sess_tracked);
		}
	}

	/* Rate-limited logging for debugging */
	if (net_ratelimit()) {
		pr_debug("[%s->%s] %pI4 -> %pI4 proto=%u len=%u\n",
			 state->in ? state->in->name : "?",
			 state->out ? state->out->name : "?",
			 &iph->saddr, &iph->daddr,
			 iph->protocol, ntohs(iph->tot_len));
	}

	atomic64_inc(&pkts_forwarded);
	return NF_ACCEPT;
}

static const struct nf_hook_ops nf_forward_ops = {
	.hook     = forward_hook,
	.pf       = NFPROTO_IPV4,
	.hooknum  = NF_INET_FORWARD,
	.priority = NF_IP_PRI_FIRST,
};

static int __init pkt_forward_init(void)
{
	int ret;

	ret = nf_register_net_hook(&init_net, &nf_forward_ops);
	if (ret < 0) {
		pr_err("pkt_forward: hook registration failed (%d)\n", ret);
		return ret;
	}

	pr_info("pkt_forward: loaded (v%s)\n", PKT_FWD_VERSION);
	return 0;
}

static void __exit pkt_forward_exit(void)
{
	nf_unregister_net_hook(&init_net, &nf_forward_ops);
	pr_info("pkt_forward: unloaded (fwd=%lld drop=%lld sess=%lld)\n",
		atomic64_read(&pkts_forwarded),
		atomic64_read(&pkts_dropped),
		atomic64_read(&sess_tracked));
}

module_init(pkt_forward_init);
module_exit(pkt_forward_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stargazer Team");
MODULE_DESCRIPTION("Packet forwarding module for BPI-R4 NGFW");
MODULE_VERSION(PKT_FWD_VERSION);
