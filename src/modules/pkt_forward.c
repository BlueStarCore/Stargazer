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
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>

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
	int dir = SESS_DIR_ORIG;
	bool tcp_is_syn = false;

	if (!is_valid_ipv4(skb)) {
		atomic64_inc(&pkts_dropped);
		return NF_DROP;
	}

	if (extract_key(skb, &key) != 0) {
		/* Genuinely malformed L4 header — defrag runs at PRE_ROUTING so
		 * any NOTRACK non-first fragment that defrag skips also lands here.
		 * Either way there is no usable 5-tuple; drop rather than forward
		 * untracked and bypass policy. */
		pr_warn_ratelimited("pkt_forward: dropping unresolvable packet "
				    "(src=%pI4 proto=%u)\n",
				    &ip_hdr(skb)->saddr, ip_hdr(skb)->protocol);
		atomic64_inc(&pkts_dropped);
		return NF_DROP;
	}

	/* extract_key() already pulled the TCP header — safe to read directly */
	if (key.proto == IPPROTO_TCP)
		tcp_is_syn = tcp_hdr(skb)->syn != 0;

	rcu_read_lock();

	if (key.proto == IPPROTO_TCP && !tcp_is_syn) {
		/*
		 * Stateful enforcement: non-SYN TCP must match an existing session.
		 * sess_lookup_bidir() never creates, so injected mid-stream packets
		 * with no session are dropped below.
		 * Asymmetric routing exception: if sess_asymmetric_mode is on, a
		 * non-SYN with no session is allowed to create one (pickup). The
		 * TCP state machine will promote it to ESTABLISHED on the first
		 * data packet.
		 */
		s = sess_lookup_bidir(&key, &dir);
		if (!s && READ_ONCE(sess_asymmetric_mode))
			s = sess_lookup_or_create(&key, &dir);
	} else if (key.proto == IPPROTO_ICMP) {
		/*
		 * For ICMP error messages (type 3/11/12), look up the parent
		 * TCP/UDP session using the embedded original header. If found,
		 * policy from the parent session applies (SESS_BLOCKED check,
		 * stats update). For non-error ICMP (echo, etc.), falls through
		 * to sess_lookup_or_create() for a normal ICMP-keyed session.
		 */
		s = sess_icmp_error_lookup(skb, &dir);
		if (!s)
			s = sess_lookup_or_create(&key, &dir);
	} else {
		s = sess_lookup_or_create(&key, &dir);
	}

	if (!s) {
		rcu_read_unlock();
		/* No session: drop.
		 * TCP non-SYN: mid-stream packet with no matching flow.
		 * TCP SYN / UDP / ICMP: session table full or kmalloc failed. */
		atomic64_inc(&pkts_dropped);
		return NF_DROP;
	}

	/* Record ingress/egress interface (set-once on the first packet).
	 * cmpxchg ensures only one CPU wins the race; the loser discards
	 * its value without overwriting what the winner stored. */
	if (state->in && READ_ONCE(s->ifindex_in) == 0) {
		u32 ifin = (u32)state->in->ifindex;
		if (cmpxchg(&s->ifindex_in, 0u, ifin) == 0)
			WRITE_ONCE(s->ifindex_out,
				   state->out ? (u32)state->out->ifindex : 0u);
	}

	if (READ_ONCE(s->flags) & SESS_BLOCKED) {
		rcu_read_unlock();
		atomic64_inc(&pkts_blocked);
		return NF_DROP;
	}

	if (key.proto == IPPROTO_TCP) {
		unsigned int verdict = sess_tcp_check(s, skb, dir);

		if (verdict != NF_ACCEPT) {
			rcu_read_unlock();
			atomic64_inc(&pkts_dropped);
			return verdict;
		}
	}

	sess_update(s, skb, dir);

	if (net_ratelimit()) {
		struct iphdr *iph = ip_hdr(skb);

		pr_debug("[%s->%s] %pI4 -> %pI4 proto=%u len=%u dir=%s\n",
			 state->in  ? state->in->name  : "?",
			 state->out ? state->out->name : "?",
			 &iph->saddr, &iph->daddr,
			 iph->protocol, ntohs(iph->tot_len),
			 dir == SESS_DIR_ORIG ? "orig" : "reply");
	}

	rcu_read_unlock();
	atomic64_inc(&pkts_forwarded);
	return NF_ACCEPT;
}

static const struct nf_hook_ops nf_forward_ops = {
	.hook     = forward_hook,
	.pf       = NFPROTO_IPV4,
	.hooknum  = NF_INET_FORWARD,
	/* Defrag registers on PRE_ROUTING; by the time any FORWARD hook fires
	 * fragments are already reassembled regardless of priority here.
	 * The value (-399) just places us before conntrack (-200) and filter (0). */
	.priority = NF_IP_PRI_CONNTRACK_DEFRAG + 1,
};

static int __init pkt_forward_init(void)
{
	int ret;

	ret = nf_defrag_ipv4_enable(&init_net);
	if (ret < 0) {
		pr_err("pkt_forward: failed to enable IPv4 defrag (%d)\n", ret);
		return ret;
	}

	ret = nf_register_net_hook(&init_net, &nf_forward_ops);
	if (ret < 0) {
		nf_defrag_ipv4_disable(&init_net);
		pr_err("pkt_forward: hook registration failed (%d)\n", ret);
		return ret;
	}

	pr_info("pkt_forward: loaded (v%s)\n", PKT_FWD_VERSION);
	return 0;
}

static void __exit pkt_forward_exit(void)
{
	nf_unregister_net_hook(&init_net, &nf_forward_ops);
	nf_defrag_ipv4_disable(&init_net);
	pr_info("pkt_forward: unloaded (fwd=%lld drop=%lld block=%lld)\n",
		atomic64_read(&pkts_forwarded),
		atomic64_read(&pkts_dropped),
		atomic64_read(&pkts_blocked));
}

module_init(pkt_forward_init);
module_exit(pkt_forward_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Stargazer Team");
MODULE_DESCRIPTION("Packet forwarding module for BPI-R4 NGFW");
MODULE_VERSION(PKT_FWD_VERSION);
MODULE_SOFTDEP("pre: session nf_defrag_ipv4");
