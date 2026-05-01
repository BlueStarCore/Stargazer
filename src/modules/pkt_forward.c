// SPDX-License-Identifier: GPL-2.0-only
/*
 * pkt_forward.c - Packet forwarding module for Stargazer NGFW
 *
 * Copyright (C) 2026 Stargazer Team
 *
 * Registers a Netfilter hook at NF_INET_FORWARD to inspect and account
 * packets traversing the router. Each forwarded packet is associated
 * with a session entry maintained by session.ko; per-direction stats
 * are updated for later ML/IPS feature extraction. Sessions whose
 * SESS_BLOCKED flag has been set (by ML scoring or policy) are dropped.
 */

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>

#include "session.h"

#ifndef PKT_FWD_VERSION
#define PKT_FWD_VERSION "unknown"
#endif

/* Counters (atomic for SMP) */
static atomic64_t pkts_forwarded = ATOMIC64_INIT(0);
static atomic64_t pkts_dropped   = ATOMIC64_INIT(0);
static atomic64_t pkts_blocked   = ATOMIC64_INIT(0);

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

/*
 * forward_hook - Netfilter callback for the FORWARD chain.
 *
 * Validates the IPv4 header, then performs session lookup/create/update
 * inside a single RCU read-side critical section so the session pointer
 * stays valid for the entire dereference window. Direction is inferred
 * by sess_lookup_or_create() using the first-packet-wins rule.
 */
static unsigned int forward_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct sess_key key;
	struct session *s;
	int dir;
	unsigned int verdict = NF_ACCEPT;

	if (!is_valid_ipv4(skb)) {
		atomic64_inc(&pkts_dropped);
		return NF_DROP;
	}

	if (extract_key(skb, &key) != 0) {
		/* Header malformed enough that we cannot key the session;
		 * count as forwarded but skip session bookkeeping.
		 */
		atomic64_inc(&pkts_forwarded);
		return NF_ACCEPT;
	}

	rcu_read_lock();
	s = sess_lookup_or_create(&key, &dir);
	if (s) {
		if (READ_ONCE(s->flags) & SESS_BLOCKED) {
			rcu_read_unlock();
			atomic64_inc(&pkts_blocked);
			return NF_DROP;
		}
		sess_update(s, skb, dir);
	}
	rcu_read_unlock();

	if (net_ratelimit()) {
		struct iphdr *iph = ip_hdr(skb);

		pr_debug("[%s->%s] %pI4 -> %pI4 proto=%u len=%u dir=%s\n",
			 state->in  ? state->in->name  : "?",
			 state->out ? state->out->name : "?",
			 &iph->saddr, &iph->daddr,
			 iph->protocol, ntohs(iph->tot_len),
			 dir == SESS_DIR_ORIG ? "orig" : "reply");
	}

	atomic64_inc(&pkts_forwarded);
	return verdict;
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
	pr_info("pkt_forward: unloaded (fwd=%lld drop=%lld block=%lld)\n",
		atomic64_read(&pkts_forwarded),
		atomic64_read(&pkts_dropped),
		atomic64_read(&pkts_blocked));
}

module_init(pkt_forward_init);
module_exit(pkt_forward_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stargazer Team");
MODULE_DESCRIPTION("Packet forwarding module for BPI-R4 NGFW");
MODULE_VERSION(PKT_FWD_VERSION);
MODULE_SOFTDEP("pre: session");
