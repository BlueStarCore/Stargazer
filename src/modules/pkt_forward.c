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
 * Future phases:
 *   - Phase 2: Session tracking integration
 *   - Phase 3: IPS signature matching
 *   - Phase 4: ML-based threat detection
 */

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>

#ifndef PKT_FWD_VERSION
#define PKT_FWD_VERSION "unknown"
#endif

/* Statistics counters (atomic for SMP safety) */
static atomic64_t pkts_forwarded = ATOMIC64_INIT(0);
static atomic64_t pkts_dropped   = ATOMIC64_INIT(0);

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
 * Validates packet and updates statistics.
 *
 * Return: NF_ACCEPT to forward, NF_DROP to discard
 */
static unsigned int forward_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct iphdr *iph;

	if (!is_valid_ipv4(skb)) {
		atomic64_inc(&pkts_dropped);
		return NF_DROP;
	}

	iph = ip_hdr(skb);

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
	pr_info("pkt_forward: unloaded (fwd=%lld drop=%lld)\n",
		atomic64_read(&pkts_forwarded),
		atomic64_read(&pkts_dropped));
}

module_init(pkt_forward_init);
module_exit(pkt_forward_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stargazer Team");
MODULE_DESCRIPTION("Packet forwarding module for BPI-R4 NGFW");
MODULE_VERSION(PKT_FWD_VERSION);
