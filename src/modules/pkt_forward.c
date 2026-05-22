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
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>

#include "session.h"

#ifndef PKT_FWD_VERSION
#define PKT_FWD_VERSION "unknown"
#endif

/* Counters (atomic for SMP) */
static atomic64_t pkts_forwarded    = ATOMIC64_INIT(0);
static atomic64_t pkts_dropped      = ATOMIC64_INIT(0);
static atomic64_t pkts_blocked      = ATOMIC64_INIT(0);
static atomic64_t pkts_syn_dropped  = ATOMIC64_INIT(0); /* DoS: SYN flood */
static atomic64_t pkts_udp_dropped  = ATOMIC64_INIT(0); /* DoS: UDP flood */
static atomic64_t pkts_icmp_dropped = ATOMIC64_INIT(0); /* DoS: ICMP flood */

/*
 * FortiGate-style per-source DoS protection.
 *
 * Architecture mirrors FortiGate's DoS policy:
 *   - Per-protocol token-bucket rate trackers detect flood onset.
 *   - Shared block list remembers violators for src_block_dur seconds so
 *     subsequent packets are rejected at the top of forward_hook() before
 *     touching the session table.
 *   - All checks are WAN-interface-scoped (wan_ifindex) so LAN traffic
 *     (including large NAT pools) is never rate-limited.
 *
 * Lock-free approximate hash arrays: collisions cause a slot to be taken
 * over by the displacing IP, which loses block/rate state and gets a fresh
 * burst allowance.  This is intentional — perfect accuracy is unnecessary
 * for flood detection, and no locking keeps the fast path contention-free.
 */
#define SRC_RATE_SLOTS   4096U   /* per-protocol tracker: ~64 KB each      */
#define SRC_BLOCK_SLOTS  65536U  /* shared block list:   ~1 MB total        */

struct src_rate_slot {
	__be32         ip;
	s32            tokens;    /* token bucket fill level                 */
	unsigned long  last_ts;   /* jiffies of last refill                  */
};

struct src_block_slot {
	__be32         ip;
	u32            _pad;
	unsigned long  expires;   /* jiffies; 0 = slot empty                 */
} ____cacheline_aligned;

static struct src_rate_slot  syn_rate[SRC_RATE_SLOTS];
static struct src_rate_slot  udp_rate[SRC_RATE_SLOTS];
static struct src_rate_slot  icmp_rate[SRC_RATE_SLOTS];
static struct src_block_slot src_block[SRC_BLOCK_SLOTS];

static u32 dos_hash_seed;

/* --- Module params -------------------------------------------------------- */

static unsigned int wan_ifindex;
module_param(wan_ifindex, uint, 0644);
MODULE_PARM_DESC(wan_ifindex,
	"WAN interface ifindex for DoS protection (0 = disabled)");

static unsigned int syn_flood_thr   = 200;
static unsigned int syn_flood_burst = 400;
module_param(syn_flood_thr,   uint, 0644);
module_param(syn_flood_burst, uint, 0644);
MODULE_PARM_DESC(syn_flood_thr,
	"TCP SYN new-session rate limit per source, sessions/s (default: 200)");
MODULE_PARM_DESC(syn_flood_burst,
	"TCP SYN token-bucket burst capacity (default: 400)");

static unsigned int udp_flood_thr   = 1000;
static unsigned int udp_flood_burst = 2000;
module_param(udp_flood_thr,   uint, 0644);
module_param(udp_flood_burst, uint, 0644);
MODULE_PARM_DESC(udp_flood_thr,
	"UDP new-session rate limit per source, sessions/s (default: 1000)");
MODULE_PARM_DESC(udp_flood_burst,
	"UDP token-bucket burst capacity (default: 2000)");

static unsigned int icmp_flood_thr   = 100;
static unsigned int icmp_flood_burst = 200;
module_param(icmp_flood_thr,   uint, 0644);
module_param(icmp_flood_burst, uint, 0644);
MODULE_PARM_DESC(icmp_flood_thr,
	"ICMP new-session rate limit per source, sessions/s (default: 100)");
MODULE_PARM_DESC(icmp_flood_burst,
	"ICMP token-bucket burst capacity (default: 200)");

static unsigned int src_block_dur = 30;
module_param(src_block_dur, uint, 0644);
MODULE_PARM_DESC(src_block_dur,
	"Seconds a violating source stays blocked (default: 30)");

/* --- DoS helper functions ------------------------------------------------- */

/*
 * src_block_check - return true if src is in the block list and not expired.
 * Lazy expiry: clears the slot on the first check after expiry rather than
 * running a separate timer, keeping the hot path branch-free for most packets.
 */
static bool src_block_check(__be32 src)
{
	u32 idx = jhash_1word((__force u32)src, dos_hash_seed) % SRC_BLOCK_SLOTS;
	struct src_block_slot *sl = &src_block[idx];
	unsigned long exp = READ_ONCE(sl->expires);

	if (!exp || READ_ONCE(sl->ip) != src)
		return false;
	if (time_after(jiffies, exp)) {
		WRITE_ONCE(sl->expires, 0);
		return false;
	}
	return true;
}

/* src_block_add - add src to the block list for src_block_dur seconds. */
static void src_block_add(__be32 src)
{
	u32 idx = jhash_1word((__force u32)src, dos_hash_seed) % SRC_BLOCK_SLOTS;
	struct src_block_slot *sl = &src_block[idx];

	WRITE_ONCE(sl->ip,      src);
	WRITE_ONCE(sl->expires, jiffies + (unsigned long)src_block_dur * HZ);
}

/*
 * src_rate_check - token-bucket rate limiter per source IP.
 *
 * Tokens refill at `rate` per second up to `burst`.  Returns true (flooding)
 * when the bucket runs dry.  Lock-free: races produce slight over/under
 * counts, which are acceptable for flood detection.
 */
static bool src_rate_check(struct src_rate_slot *tbl, __be32 src,
			    u32 rate, u32 burst)
{
	u32 idx = jhash_1word((__force u32)src, dos_hash_seed) % SRC_RATE_SLOTS;
	struct src_rate_slot *sl = &tbl[idx];
	unsigned long now = jiffies;
	unsigned long elapsed;
	s32 refill;

	if (sl->ip != src) {
		/* New IP displaces previous occupant — start with full burst. */
		sl->ip      = src;
		sl->tokens  = (s32)burst - 1;
		sl->last_ts = now;
		return false;
	}

	elapsed = now - sl->last_ts;
	if (elapsed) {
		refill     = (s32)min_t(u64, (u64)elapsed * rate / HZ, burst);
		sl->tokens = min(sl->tokens + refill, (s32)burst);
		sl->last_ts = now;
	}

	if (sl->tokens > 0) {
		sl->tokens--;
		return false;
	}
	return true;
}

/*
 * src_dos_check - per-protocol rate check + block-list update.
 *
 * Selects the right token-bucket table for proto, runs the rate check, and
 * if flooding adds the source to the block list and bumps its drop counter.
 * Returns true when the packet should be dropped.
 */
static bool src_dos_check(__be32 src, u8 proto)
{
	bool flooding;

	if (proto == IPPROTO_TCP)
		flooding = src_rate_check(syn_rate,  src,
					  syn_flood_thr,  syn_flood_burst);
	else if (proto == IPPROTO_UDP)
		flooding = src_rate_check(udp_rate,  src,
					  udp_flood_thr,  udp_flood_burst);
	else
		flooding = src_rate_check(icmp_rate, src,
					  icmp_flood_thr, icmp_flood_burst);

	if (flooding) {
		src_block_add(src);
		if (proto == IPPROTO_TCP)
			atomic64_inc(&pkts_syn_dropped);
		else if (proto == IPPROTO_UDP)
			atomic64_inc(&pkts_udp_dropped);
		else
			atomic64_inc(&pkts_icmp_dropped);
	}
	return flooding;
}

/* --- Packet validation ---------------------------------------------------- */

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
 * Processing order (mirrors FortiGate's pipeline):
 *   [1] IPv4 + L4 header validation
 *   [2] DoS block list check (WAN-scoped, before session table)
 *   [3] Session lookup / create with per-protocol rate limiting for new
 *       sessions on the WAN interface
 *   [4] SESS_BLOCKED policy enforcement
 *   [5] TCP state machine
 *   [6] Stats update
 */
static unsigned int forward_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct sess_key key;
	struct session *s;
	int dir = SESS_DIR_ORIG;
	bool tcp_is_syn = false;
	bool is_wan;

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

	if (key.proto == IPPROTO_TCP)
		tcp_is_syn = tcp_hdr(skb)->syn != 0;

	/*
	 * DoS protection — WAN-interface-scoped, FortiGate-style.
	 *
	 * is_wan is evaluated once and reused below so the ifindex comparison
	 * is not repeated for every branch.  When wan_ifindex == 0 the entire
	 * DoS subsystem is disabled with a single branch.
	 */
	is_wan = wan_ifindex != 0 && state->in != NULL &&
		 (unsigned int)state->in->ifindex == wan_ifindex;

	/*
	 * [2] Block list: O(1) reject before any session table access.
	 * Already-blocked sources are dropped here; the session hot path
	 * is never touched for them.
	 */
	if (is_wan && src_block_check(key.src_ip)) {
		atomic64_inc(&pkts_dropped);
		return NF_DROP;
	}

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

	} else if (key.proto == IPPROTO_TCP) {
		/* tcp_is_syn == true: new TCP session */
		if (is_wan && src_dos_check(key.src_ip, IPPROTO_TCP)) {
			rcu_read_unlock();
			atomic64_inc(&pkts_dropped);
			return NF_DROP;
		}
		s = sess_lookup_or_create(&key, &dir);

	} else if (key.proto == IPPROTO_ICMP) {
		/*
		 * For ICMP error messages (type 3/11/12) sess_icmp_error_lookup()
		 * returns the parent TCP/UDP session — no new session, no rate
		 * check.  For non-error ICMP (echo etc.) it returns NULL and we
		 * fall through to create an ICMP-keyed session with rate limiting.
		 */
		s = sess_icmp_error_lookup(skb, &dir);
		if (!s) {
			/* Check for an existing ICMP session before rate-limiting. */
			s = sess_lookup_bidir(&key, &dir);
			if (!s) {
				if (is_wan && src_dos_check(key.src_ip, IPPROTO_ICMP)) {
					rcu_read_unlock();
					atomic64_inc(&pkts_dropped);
					return NF_DROP;
				}
				s = sess_lookup_or_create(&key, &dir);
			}
		}

	} else {
		/*
		 * UDP and other protocols: check for an existing session first.
		 * Existing sessions are exempt from rate limiting — we only want
		 * to limit the rate of new-session creation, not penalise flows
		 * that are already established.
		 */
		s = sess_lookup_bidir(&key, &dir);
		if (!s) {
			if (is_wan && src_dos_check(key.src_ip, key.proto)) {
				rcu_read_unlock();
				atomic64_inc(&pkts_dropped);
				return NF_DROP;
			}
			s = sess_lookup_or_create(&key, &dir);
		}
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

/* --- procfs: /proc/stargazer/pkt_forward_stats ---------------------------- */

static struct proc_dir_entry *proc_pf_stats;

static int pf_stats_show(struct seq_file *m, void *v)
{
	seq_printf(m,
		"pkts_forwarded=%lld\n"
		"pkts_dropped=%lld\n"
		"pkts_blocked=%lld\n"
		"pkts_syn_dropped=%lld\n"
		"pkts_udp_dropped=%lld\n"
		"pkts_icmp_dropped=%lld\n"
		"wan_ifindex=%u\n",
		atomic64_read(&pkts_forwarded),
		atomic64_read(&pkts_dropped),
		atomic64_read(&pkts_blocked),
		atomic64_read(&pkts_syn_dropped),
		atomic64_read(&pkts_udp_dropped),
		atomic64_read(&pkts_icmp_dropped),
		wan_ifindex);
	return 0;
}

static int pf_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, pf_stats_show, NULL);
}

static const struct proc_ops pf_stats_proc_ops = {
	.proc_open    = pf_stats_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

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

	get_random_bytes(&dos_hash_seed, sizeof(dos_hash_seed));

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

	/* Place stats file under /proc/stargazer/ (directory owned by session.ko).
	 * Failure is non-fatal — the module still functions without procfs. */
	proc_pf_stats = proc_create("pkt_forward_stats", 0444, sg_proc_root,
				    &pf_stats_proc_ops);
	if (!proc_pf_stats)
		pr_warn("pkt_forward: could not create /proc/stargazer/pkt_forward_stats\n");

	pr_info("pkt_forward: loaded (v%s) dos=%s syn=%u/%u udp=%u/%u"
		" icmp=%u/%u block_dur=%us\n",
		PKT_FWD_VERSION,
		wan_ifindex ? "on" : "off",
		syn_flood_thr,  syn_flood_burst,
		udp_flood_thr,  udp_flood_burst,
		icmp_flood_thr, icmp_flood_burst,
		src_block_dur);
	return 0;
}

static void __exit pkt_forward_exit(void)
{
	nf_unregister_net_hook(&init_net, &nf_forward_ops);
	nf_defrag_ipv4_disable(&init_net);
	if (proc_pf_stats)
		proc_remove(proc_pf_stats);
	pr_info("pkt_forward: unloaded (fwd=%lld drop=%lld block=%lld"
		" syn_drop=%lld udp_drop=%lld icmp_drop=%lld)\n",
		atomic64_read(&pkts_forwarded),
		atomic64_read(&pkts_dropped),
		atomic64_read(&pkts_blocked),
		atomic64_read(&pkts_syn_dropped),
		atomic64_read(&pkts_udp_dropped),
		atomic64_read(&pkts_icmp_dropped));
}

module_init(pkt_forward_init);
module_exit(pkt_forward_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Stargazer Team");
MODULE_DESCRIPTION("Packet forwarding module for BPI-R4 NGFW");
MODULE_VERSION(PKT_FWD_VERSION);
MODULE_SOFTDEP("pre: session nf_defrag_ipv4");
