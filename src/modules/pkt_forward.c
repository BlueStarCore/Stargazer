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
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/bitops.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>

#include "session.h"

#ifndef PKT_FWD_VERSION
#define PKT_FWD_VERSION "unknown"
#endif

/*
 * Packets belonging to SESS_DIRTY sessions are tagged with this skb->mark bit
 * so the iptables ESTABLISHED,RELATED rule (which has ! --mark 0x80) skips
 * them, forcing a full policy re-evaluation on the first post-rebuild packet.
 * The post_filter_hook clears the bit and the SESS_DIRTY flag after iptables
 * accepts the packet, returning the session to the fast path.
 */
#define STARGAZER_DIRTY_MARK	0x00000080u

/* Counters (atomic for SMP) */
static atomic64_t pkts_forwarded            = ATOMIC64_INIT(0);
static atomic64_t pkts_dropped              = ATOMIC64_INIT(0);
static atomic64_t pkts_blocked              = ATOMIC64_INIT(0);
static atomic64_t pkts_syn_dropped          = ATOMIC64_INIT(0); /* per-src SYN flood      */
static atomic64_t pkts_udp_dropped          = ATOMIC64_INIT(0); /* per-src UDP flood      */
static atomic64_t pkts_icmp_dropped         = ATOMIC64_INIT(0); /* per-src ICMP flood     */
static atomic64_t pkts_anomaly_dropped      = ATOMIC64_INIT(0); /* L3/L4 anomaly          */
static atomic64_t pkts_halfopen_src_dropped = ATOMIC64_INIT(0); /* per-src half-open cap  */
static atomic64_t pkts_global_syn_dropped   = ATOMIC64_INIT(0); /* global SYN cap         */
static atomic64_t pkts_global_udp_dropped   = ATOMIC64_INIT(0); /* global UDP cap         */
static atomic64_t pkts_pkt_rate_dropped     = ATOMIC64_INIT(0); /* per-src aggregate rate */
static atomic64_t pkts_icmp_err_dropped     = ATOMIC64_INIT(0); /* ICMP error rate        */
static atomic64_t pkts_scan_dropped         = ATOMIC64_INIT(0); /* port scan              */

/*
 * FortiGate-style per-source DoS protection.
 *
 * Architecture mirrors FortiGate's DoS policy:
 *   - Per-protocol token-bucket rate trackers detect flood onset.
 *   - Shared block list remembers violators for src_block_dur seconds so
 *     subsequent packets are rejected at the top of forward_hook() before
 *     touching the session table.
 *   - Rate checks apply to every interface whose ifindex bit is set in
 *     protected_ifmask, so protection is not limited to a single WAN port.
 *
 * Lock-free approximate hash arrays: collisions cause a slot to be taken
 * over by the displacing IP, which loses block/rate state and gets a fresh
 * burst allowance.  This is intentional — perfect accuracy is unnecessary
 * for flood detection, and no locking keeps the fast path contention-free.
 */
#define SRC_RATE_SLOTS   4096U   /* per-tracker array: ~64 KB each          */
#define SRC_BLOCK_SLOTS  65536U  /* shared block list: ~1 MB total           */

struct src_rate_slot {
	__be32         ip;
	s32            tokens;    /* token bucket fill level                  */
	unsigned long  last_ts;   /* jiffies at last refill                   */
};

struct src_block_slot {
	__be32         ip;
	u32            _pad;
	unsigned long  expires;   /* jiffies; 0 = slot empty                  */
} ____cacheline_aligned;

/* Per-source half-open (SYN) count — sliding-window counter */
#define HALFOPEN_WINDOW_SEC 120U

struct src_halfopen_slot {
	__be32         ip;
	u32            count;
	unsigned long  window_start;
};

/* Port scan detector — 32-bit bloom filter per source */
struct src_scan_slot {
	__be32         ip;
	u32            bloom;
	unsigned long  window_start;
};

static struct src_rate_slot      syn_rate[SRC_RATE_SLOTS];
static struct src_rate_slot      udp_rate[SRC_RATE_SLOTS];
static struct src_rate_slot      icmp_rate[SRC_RATE_SLOTS];
static struct src_rate_slot      pkt_rate[SRC_RATE_SLOTS];     /* aggregate pkts/s  */
static struct src_rate_slot      icmp_err_rate[SRC_RATE_SLOTS];/* ICMP type 3/11/12 */
static struct src_block_slot     src_block[SRC_BLOCK_SLOTS];
static struct src_halfopen_slot  src_halfopen[SRC_RATE_SLOTS];
static struct src_scan_slot      src_scan[SRC_RATE_SLOTS];

/* Global SYN token bucket — single bucket shared across all WAN sources */
static struct {
	s32           tokens;
	unsigned long last_ts;
} global_syn_bucket;
static DEFINE_SPINLOCK(global_syn_lock);

/* Global UDP token bucket — caps total UDP new-session rate across all sources */
static struct {
	s32           tokens;
	unsigned long last_ts;
} global_udp_bucket;
static DEFINE_SPINLOCK(global_udp_lock);

static u32 dos_hash_seed;

/* --- Module params -------------------------------------------------------- */

/* Bitmask of protected interface ifindices.
 * Bit N = 1 means packets arriving on ifindex N are subject to DoS checks.
 * Supports up to BITS_PER_LONG interfaces (64 on ARM64). */
static unsigned long protected_ifmask;
module_param(protected_ifmask, ulong, 0644);
MODULE_PARM_DESC(protected_ifmask,
	"Bitmask of protected ifindices; bit N protects ifindex N (0 = disabled)");

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

static unsigned int max_halfopen_per_src = 10;
module_param(max_halfopen_per_src, uint, 0644);
MODULE_PARM_DESC(max_halfopen_per_src,
	"Max half-open TCP sessions per source in 120s window (0=disabled, default: 10)");

static unsigned int global_syn_thr   = 5000;
static unsigned int global_syn_burst = 10000;
module_param(global_syn_thr,   uint, 0644);
module_param(global_syn_burst, uint, 0644);
MODULE_PARM_DESC(global_syn_thr,
	"Global SYN new-session rate cap, SYNs/s (0=disabled, default: 5000)");
MODULE_PARM_DESC(global_syn_burst,
	"Global SYN burst capacity (default: 10000)");

static unsigned int global_udp_thr   = 5000;
static unsigned int global_udp_burst = 10000;
module_param(global_udp_thr,   uint, 0644);
module_param(global_udp_burst, uint, 0644);
MODULE_PARM_DESC(global_udp_thr,
	"Global UDP new-session rate cap, sessions/s (0=disabled, default: 5000)");
MODULE_PARM_DESC(global_udp_burst,
	"Global UDP burst capacity (default: 10000)");

static unsigned int pkt_flood_thr   = 10000;
static unsigned int pkt_flood_burst = 20000;
module_param(pkt_flood_thr,   uint, 0644);
module_param(pkt_flood_burst, uint, 0644);
MODULE_PARM_DESC(pkt_flood_thr,
	"Per-source aggregate packet rate cap, pkts/s (0=disabled, default: 10000)");
MODULE_PARM_DESC(pkt_flood_burst,
	"Per-source aggregate packet rate burst (default: 20000)");

static unsigned int icmp_err_thr   = 50;
static unsigned int icmp_err_burst = 100;
module_param(icmp_err_thr,   uint, 0644);
module_param(icmp_err_burst, uint, 0644);
MODULE_PARM_DESC(icmp_err_thr,
	"ICMP error message rate limit per source, msgs/s (default: 50)");
MODULE_PARM_DESC(icmp_err_burst,
	"ICMP error rate burst capacity (default: 100)");

static unsigned int scan_threshold = 20;
static unsigned int scan_window    = 10;
module_param(scan_threshold, uint, 0644);
module_param(scan_window,    uint, 0644);
MODULE_PARM_DESC(scan_threshold,
	"Port scan: unique dst-port/IP combos per window before block (0=disabled, default: 20)");
MODULE_PARM_DESC(scan_window,
	"Port scan: bloom filter window in seconds (default: 10)");

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
 * counts, which is acceptable for flood detection.
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
		sl->ip      = src;
		sl->tokens  = (s32)burst - 1;
		sl->last_ts = now;
		return false;
	}

	elapsed = now - sl->last_ts;
	if (elapsed) {
		refill      = (s32)min_t(u64, (u64)elapsed * rate / HZ, burst);
		sl->tokens  = min(sl->tokens + refill, (s32)burst);
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

/* --- Anomaly detection helpers -------------------------------------------- */

/*
 * is_ip_anomaly - Check for IP-level protocol anomalies.
 * Applied to all interfaces; these packets are structurally invalid.
 * Returns true (drop) for: land attack, IP source routing (LSRR/SSRR).
 */
static bool is_ip_anomaly(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	/* Land attack: source == destination */
	if (iph->saddr == iph->daddr)
		return true;

	/* IP source routing options (LSRR=131, SSRR=137) — used to bypass ACLs */
	if (iph->ihl > 5) {
		const u8 *opt;
		int       optlen;

		/* Pull the full IP header including options into linear data */
		if (!pskb_may_pull(skb, (unsigned int)iph->ihl * 4))
			return false; /* can't verify options; pass through */
		iph    = ip_hdr(skb); /* re-fetch after potential realloc */
		opt    = (const u8 *)iph + sizeof(struct iphdr);
		optlen = iph->ihl * 4 - (int)sizeof(struct iphdr);
		int       i      = 0;

		while (i < optlen) {
			u8 type = opt[i];

			if (type == 0)   /* IPOPT_END */
				break;
			if (type == 1) { /* IPOPT_NOP */
				i++;
				continue;
			}
			if (type == 131 || type == 137)  /* LSRR / SSRR */
				return true;
			if (i + 1 >= optlen)
				break;
			i += opt[i + 1] ? opt[i + 1] : 1;
		}
	}

	return false;
}

/*
 * is_tcp_anomaly - Check for TCP flag-based attack patterns.
 * Returns true (drop) for: NULL scan, XMAS scan, FIN without ACK, SYN+data.
 * Caller must ensure extract_key() succeeded (TCP header already pulled).
 */
static bool is_tcp_anomaly(struct sk_buff *skb)
{
	struct iphdr  *iph  = ip_hdr(skb);
	struct tcphdr *tcph = tcp_hdr(skb);
	unsigned int   ip_hlen, tcp_hlen, tot_len;

	/* NULL scan: no TCP control bits set */
	if (!(tcph->fin | tcph->syn | tcph->rst | tcph->psh | tcph->ack | tcph->urg))
		return true;

	/* XMAS scan: FIN+URG+PSH simultaneously */
	if (tcph->fin && tcph->urg && tcph->psh)
		return true;

	/* FIN without ACK — invalid per RFC 793 */
	if (tcph->fin && !tcph->ack)
		return true;

	/* SYN with data payload — handshake SYNs carry no data */
	if (tcph->syn && !tcph->ack) {
		ip_hlen  = (unsigned int)iph->ihl * 4;
		tcp_hlen = (unsigned int)tcph->doff * 4;
		tot_len  = (unsigned int)ntohs(iph->tot_len);
		/* Guard against malformed tot_len (< sum of headers) */
		if (tcp_hlen >= 20 && tot_len > ip_hlen + tcp_hlen)
			return true;
	}

	return false;
}

/*
 * is_icmp_anomaly - Ping of Death: ICMP with anomalously large total length.
 * nf_defrag_ipv4 has already reassembled fragments; tot_len > 65500 bytes
 * indicates a crafted oversized echo that would overflow vulnerable stacks.
 */
static bool is_icmp_anomaly(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	return iph->protocol == IPPROTO_ICMP &&
	       ntohs(iph->tot_len) > 65500;
}

/*
 * icmp_is_error - Return true if this ICMP packet is an error type (3/11/12).
 * Used to select the ICMP error rate table before sess_icmp_error_lookup().
 */
static bool icmp_is_error(struct sk_buff *skb)
{
	struct iphdr   *iph;
	struct icmphdr *icmph;
	u8              type;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_ICMP)
		return false;
	if (!pskb_may_pull(skb, (unsigned int)iph->ihl * 4 +
			       sizeof(struct icmphdr)))
		return false;
	/* Re-fetch after pull */
	iph   = ip_hdr(skb);
	icmph = (struct icmphdr *)((u8 *)iph + iph->ihl * 4);
	type  = icmph->type;
	return type == ICMP_DEST_UNREACH  ||
	       type == ICMP_TIME_EXCEEDED ||
	       type == ICMP_PARAMETERPROB;
}

/*
 * src_halfopen_check - Per-source half-open TCP session sliding-window cap.
 *
 * Counts SYNs from a source IP within a HALFOPEN_WINDOW_SEC window.
 * Returns true (drop) when the count reaches max_halfopen_per_src.
 * Guards against low-rate SYN floods that stay under the token-bucket
 * threshold but accumulate half-open sessions over time.
 */
static bool src_halfopen_check(__be32 src)
{
	u32 idx = jhash_1word((__force u32)src, dos_hash_seed) % SRC_RATE_SLOTS;
	struct src_halfopen_slot *sl = &src_halfopen[idx];
	unsigned long now = jiffies;

	if (sl->ip != src) {
		sl->ip           = src;
		sl->count        = 1;
		sl->window_start = now;
		return false;
	}

	if (time_after(now, sl->window_start + HALFOPEN_WINDOW_SEC * HZ)) {
		sl->count        = 1;
		sl->window_start = now;
		return false;
	}

	if (sl->count >= max_halfopen_per_src) {
		src_block_add(src);
		atomic64_inc(&pkts_halfopen_src_dropped);
		return true;
	}
	sl->count++;
	return false;
}

/*
 * global_syn_check - Single shared token bucket for all WAN SYNs.
 *
 * A distributed SYN flood from many sources can stay under per-source
 * thresholds while overwhelming the session table.  This cap is the
 * last backstop before sess_lookup_or_create().
 * Returns true (drop) when the global bucket is empty.
 * Does NOT block individual sources — the source is not necessarily at fault.
 */
static bool global_syn_check(void)
{
	unsigned long now  = jiffies;
	unsigned long elapsed;
	s32           refill;
	bool          drop;

	spin_lock(&global_syn_lock);

	elapsed = now - global_syn_bucket.last_ts;
	if (elapsed) {
		refill = (s32)min_t(u64,
				    (u64)elapsed * global_syn_thr / HZ,
				    (u64)global_syn_burst);
		global_syn_bucket.tokens = min(
			global_syn_bucket.tokens + refill,
			(s32)global_syn_burst);
		global_syn_bucket.last_ts = now;
	}

	if (global_syn_bucket.tokens > 0) {
		global_syn_bucket.tokens--;
		drop = false;
	} else {
		drop = true;
	}

	spin_unlock(&global_syn_lock);

	if (drop)
		atomic64_inc(&pkts_global_syn_dropped);
	return drop;
}

/*
 * global_udp_check - Single shared token bucket for all WAN UDP new sessions.
 *
 * Per-source UDP rate limits stop single-source floods but cannot stop a
 * distributed flood where each source stays under its individual threshold.
 * This cap bounds the total rate of new UDP session creation regardless of
 * how many source IPs are involved.
 * Returns true (drop) when the global bucket is empty.
 * Does NOT block individual sources — the source is not necessarily at fault.
 */
static bool global_udp_check(void)
{
	unsigned long now  = jiffies;
	unsigned long elapsed;
	s32           refill;
	bool          drop;

	spin_lock(&global_udp_lock);

	elapsed = now - global_udp_bucket.last_ts;
	if (elapsed) {
		refill = (s32)min_t(u64,
				    (u64)elapsed * global_udp_thr / HZ,
				    (u64)global_udp_burst);
		global_udp_bucket.tokens = min(
			global_udp_bucket.tokens + refill,
			(s32)global_udp_burst);
		global_udp_bucket.last_ts = now;
	}

	if (global_udp_bucket.tokens > 0) {
		global_udp_bucket.tokens--;
		drop = false;
	} else {
		drop = true;
	}

	spin_unlock(&global_udp_lock);

	if (drop)
		atomic64_inc(&pkts_global_udp_dropped);
	return drop;
}

/*
 * src_scan_check - Port scan detection via 32-bit bloom filter.
 *
 * Each unique (dst_port, dst_ip) pair from a source hashes to one bit of a
 * 32-bit filter.  When hweight32(bloom) reaches scan_threshold the source is
 * flagged and blocked.  The filter resets after scan_window seconds.
 * Called for TCP SYNs only — each SYN to a new port/host sets one bloom bit.
 */
static bool src_scan_check(__be32 src, __be16 dst_port, __be32 dst_ip)
{
	u32 idx = jhash_1word((__force u32)src, dos_hash_seed) % SRC_RATE_SLOTS;
	struct src_scan_slot *sl = &src_scan[idx];
	unsigned long now = jiffies;
	u32 bit;

	if (sl->ip != src ||
	    time_after(now, sl->window_start +
			    (unsigned long)scan_window * HZ)) {
		sl->ip           = src;
		sl->bloom        = 0;
		sl->window_start = now;
	}

	bit = 1u << (jhash_2words((__force u32)dst_port,
				   (__force u32)dst_ip,
				   dos_hash_seed) & 31);
	sl->bloom |= bit;

	if (hweight32(sl->bloom) >= scan_threshold) {
		src_block_add(src);
		atomic64_inc(&pkts_scan_dropped);
		return true;
	}
	return false;
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
 * Processing pipeline (mirrors FortiGate's DoS policy order):
 *   [1]  IPv4 + L4 header validation
 *   [2]  L3/L4 anomaly detection (land attack, TCP NULL/XMAS/FIN-no-ACK/
 *        SYN+data, Ping of Death, IP source routing) — all interfaces
 *   [3]  DoS block list check (WAN-scoped, O(1) reject before session table)
 *   [4]  ICMP error rate limiter (WAN-scoped, type 3/11/12 only)
 *   [5]  Per-source aggregate packet rate (WAN-scoped, catches ACK/data floods)
 *   [6]  Global SYN cap (WAN-scoped, backstop for distributed SYN floods)
 *   [7]  Per-source half-open SYN cap (WAN-scoped, 120s sliding window)
 *   [8]  Port scan detection (WAN-scoped, bloom filter on SYNs)
 *   [9]  Session lookup / create with per-protocol rate limiting
 *   [10] SESS_BLOCKED policy enforcement
 *   [11] TCP state machine
 *   [12] Stats update
 */
static unsigned int forward_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct sess_key key;
	struct session *s;
	int dir = SESS_DIR_ORIG;
	bool tcp_is_syn = false;
	bool is_protected;

	/* [1] IPv4 + L4 validation */
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

	/* [2] L3/L4 anomaly detection — unconditional, all interfaces */
	if (is_ip_anomaly(skb) ||
	    (key.proto == IPPROTO_TCP && is_tcp_anomaly(skb)) ||
	    is_icmp_anomaly(skb)) {
		atomic64_inc(&pkts_anomaly_dropped);
		atomic64_inc(&pkts_dropped);
		return NF_DROP;
	}

	/*
	 * is_protected is evaluated once and reused below so the bitmask check
	 * is not repeated for every branch.  When protected_ifmask == 0 the entire
	 * DoS subsystem is disabled with a single branch.
	 */
	{
		unsigned int idx = state->in ? (unsigned int)state->in->ifindex : 0;
		is_protected = idx < BITS_PER_LONG &&
			       (READ_ONCE(protected_ifmask) >> idx) & 1UL;
	}

	/* [3] Block list: O(1) reject before any session table access */
	if (is_protected && src_block_check(key.src_ip)) {
		atomic64_inc(&pkts_dropped);
		return NF_DROP;
	}

	/* [4] ICMP error rate limiter: caps flood of crafted ICMP errors */
	if (is_protected && icmp_err_thr && icmp_is_error(skb) &&
	    src_rate_check(icmp_err_rate, key.src_ip,
			   icmp_err_thr, icmp_err_burst)) {
		src_block_add(key.src_ip);
		atomic64_inc(&pkts_icmp_err_dropped);
		atomic64_inc(&pkts_dropped);
		return NF_DROP;
	}

	/* [5] Per-source aggregate packet rate: ACK flood / data flood */
	if (is_protected && pkt_flood_thr &&
	    src_rate_check(pkt_rate, key.src_ip,
			   pkt_flood_thr, pkt_flood_burst)) {
		src_block_add(key.src_ip);
		atomic64_inc(&pkts_pkt_rate_dropped);
		atomic64_inc(&pkts_dropped);
		return NF_DROP;
	}

	/* [6–8] SYN-specific WAN defenses */
	if (is_protected && tcp_is_syn) {
		/* [6] Global SYN cap: distributed SYN flood from many sources */
		if (global_syn_thr && global_syn_check()) {
			atomic64_inc(&pkts_dropped);
			return NF_DROP;
		}

		/* [7] Per-source half-open cap: slow-rate single-source SYN flood */
		if (max_halfopen_per_src && src_halfopen_check(key.src_ip)) {
			atomic64_inc(&pkts_dropped);
			return NF_DROP;
		}

		/* [8] Port scan: bloom filter on unique (dst_port, dst_ip) combos */
		if (scan_threshold &&
		    src_scan_check(key.src_ip, key.dst_port, key.dst_ip)) {
			atomic64_inc(&pkts_dropped);
			return NF_DROP;
		}
	}

	rcu_read_lock();

	/* [9] Session lookup / create */
	if (key.proto == IPPROTO_TCP && !tcp_is_syn) {
		/*
		 * Stateful enforcement: non-SYN TCP must match an existing session.
		 * sess_lookup_bidir() never creates, so injected mid-stream packets
		 * with no session are dropped below.
		 * Asymmetric routing exception: if sess_asymmetric_mode is on, a
		 * non-SYN with no session is allowed to create one (pickup).
		 */
		s = sess_lookup_bidir(&key, &dir);
		if (!s && READ_ONCE(sess_asymmetric_mode))
			s = sess_lookup_or_create(&key, &dir);

	} else if (key.proto == IPPROTO_TCP) {
		/* tcp_is_syn == true: new TCP session */
		if (is_protected && src_dos_check(key.src_ip, IPPROTO_TCP)) {
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
			s = sess_lookup_bidir(&key, &dir);
			if (!s) {
				if (is_protected && src_dos_check(key.src_ip, IPPROTO_ICMP)) {
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
		 * to limit the rate of new-session creation.
		 */
		s = sess_lookup_bidir(&key, &dir);
		if (!s) {
			if (is_protected && src_dos_check(key.src_ip, key.proto)) {
				rcu_read_unlock();
				atomic64_inc(&pkts_dropped);
				return NF_DROP;
			}
			if (is_protected && key.proto == IPPROTO_UDP &&
			    global_udp_thr && global_udp_check()) {
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
		 * TCP non-SYN: mid-stream with no matching flow.
		 * TCP SYN / UDP / ICMP: session table full or kmalloc failed. */
		atomic64_inc(&pkts_dropped);
		return NF_DROP;
	}

	/* Record ingress/egress interface (set-once on the first packet).
	 * cmpxchg ensures only one CPU wins the race. */
	if (state->in && READ_ONCE(s->ifindex_in) == 0) {
		u32 ifin = (u32)state->in->ifindex;

		if (cmpxchg(&s->ifindex_in, 0u, ifin) == 0)
			WRITE_ONCE(s->ifindex_out,
				   state->out ? (u32)state->out->ifindex : 0u);
	}

	/* [10] SESS_BLOCKED: ML/policy enforcement */
	if (READ_ONCE(s->flags) & SESS_BLOCKED) {
		rcu_read_unlock();
		atomic64_inc(&pkts_blocked);
		return NF_DROP;
	}

	/* [10b] SESS_DIRTY: policy was rebuilt — tag packet so the iptables
	 * ESTABLISHED,RELATED rule skips it and policy rules re-evaluate it. */
	if (READ_ONCE(s->flags) & SESS_DIRTY)
		skb->mark |= STARGAZER_DIRTY_MARK;

	/* [11] TCP state machine */
	if (key.proto == IPPROTO_TCP) {
		unsigned int verdict = sess_tcp_check(s, skb, dir);

		if (verdict != NF_ACCEPT) {
			rcu_read_unlock();
			atomic64_inc(&pkts_dropped);
			return verdict;
		}
	}

	/* [12] Stats update */
	sess_update(s, skb, dir);

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
		"pkts_anomaly_dropped=%lld\n"
		"pkts_halfopen_src_dropped=%lld\n"
		"pkts_global_syn_dropped=%lld\n"
		"pkts_global_udp_dropped=%lld\n"
		"pkts_pkt_rate_dropped=%lld\n"
		"pkts_icmp_err_dropped=%lld\n"
		"pkts_scan_dropped=%lld\n"
		"protected_ifmask=%lu\n",
		atomic64_read(&pkts_forwarded),
		atomic64_read(&pkts_dropped),
		atomic64_read(&pkts_blocked),
		atomic64_read(&pkts_syn_dropped),
		atomic64_read(&pkts_udp_dropped),
		atomic64_read(&pkts_icmp_dropped),
		atomic64_read(&pkts_anomaly_dropped),
		atomic64_read(&pkts_halfopen_src_dropped),
		atomic64_read(&pkts_global_syn_dropped),
		atomic64_read(&pkts_global_udp_dropped),
		atomic64_read(&pkts_pkt_rate_dropped),
		atomic64_read(&pkts_icmp_err_dropped),
		atomic64_read(&pkts_scan_dropped),
		READ_ONCE(protected_ifmask));
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

/*
 * post_filter_hook — clears SESS_DIRTY after iptables has accepted a packet.
 *
 * Runs at NF_IP_PRI_FILTER + 1, so it only fires when iptables accepted the
 * packet (NF_DROP from iptables stops traversal; this hook is never reached).
 * It checks the STARGAZER_DIRTY_MARK bit set by forward_hook() to avoid a
 * session lookup on every non-dirty packet.
 */
static unsigned int post_filter_hook(void *priv, struct sk_buff *skb,
				     const struct nf_hook_state *state)
{
	struct sess_key key;
	struct session *s;
	int dir;

	if (!(skb->mark & STARGAZER_DIRTY_MARK))
		return NF_ACCEPT;

	skb->mark &= ~STARGAZER_DIRTY_MARK;

	if (extract_key(skb, &key) != 0)
		return NF_ACCEPT;

	rcu_read_lock();
	s = sess_lookup_bidir(&key, &dir);
	if (s) {
		spin_lock(&s->lock);
		s->flags &= ~SESS_DIRTY;
		spin_unlock(&s->lock);
	}
	rcu_read_unlock();

	return NF_ACCEPT;
}

static const struct nf_hook_ops nf_post_filter_ops = {
	.hook     = post_filter_hook,
	.pf       = NFPROTO_IPV4,
	.hooknum  = NF_INET_FORWARD,
	.priority = NF_IP_PRI_FILTER + 1,
};

static int __init pkt_forward_init(void)
{
	int ret;

	get_random_bytes(&dos_hash_seed, sizeof(dos_hash_seed));

	global_syn_bucket.tokens  = (s32)global_syn_burst;
	global_syn_bucket.last_ts = jiffies;

	global_udp_bucket.tokens  = (s32)global_udp_burst;
	global_udp_bucket.last_ts = jiffies;

	ret = nf_defrag_ipv4_enable(&init_net);
	if (ret < 0) {
		pr_err("pkt_forward: failed to enable IPv4 defrag (%d)\n", ret);
		return ret;
	}

	ret = nf_register_net_hook(&init_net, &nf_forward_ops);
	if (ret < 0) {
		nf_defrag_ipv4_disable(&init_net);
		pr_err("pkt_forward: forward hook registration failed (%d)\n", ret);
		return ret;
	}

	ret = nf_register_net_hook(&init_net, &nf_post_filter_ops);
	if (ret < 0) {
		nf_unregister_net_hook(&init_net, &nf_forward_ops);
		nf_defrag_ipv4_disable(&init_net);
		pr_err("pkt_forward: post-filter hook registration failed (%d)\n", ret);
		return ret;
	}

	/* Place stats file under /proc/stargazer/ (directory owned by session.ko).
	 * Failure is non-fatal — the module still functions without procfs. */
	proc_pf_stats = proc_create("pkt_forward_stats", 0444, sg_proc_root,
				    &pf_stats_proc_ops);
	if (!proc_pf_stats)
		pr_warn("pkt_forward: could not create /proc/stargazer/pkt_forward_stats\n");

	pr_info("pkt_forward: loaded (v%s) dos=%s syn=%u/%u udp=%u/%u"
		" icmp=%u/%u block_dur=%us halfopen_src=%u"
		" global_syn=%u/%u pktrate=%u/%u"
		" icmp_err=%u/%u scan=%u/%us\n",
		PKT_FWD_VERSION,
		READ_ONCE(protected_ifmask) ? "on" : "off",
		syn_flood_thr,   syn_flood_burst,
		udp_flood_thr,   udp_flood_burst,
		icmp_flood_thr,  icmp_flood_burst,
		src_block_dur,   max_halfopen_per_src,
		global_syn_thr,  global_syn_burst,
		pkt_flood_thr,   pkt_flood_burst,
		icmp_err_thr,    icmp_err_burst,
		scan_threshold,  scan_window);
	return 0;
}

static void __exit pkt_forward_exit(void)
{
	nf_unregister_net_hook(&init_net, &nf_post_filter_ops);
	nf_unregister_net_hook(&init_net, &nf_forward_ops);
	nf_defrag_ipv4_disable(&init_net);
	if (proc_pf_stats)
		proc_remove(proc_pf_stats);
	pr_info("pkt_forward: unloaded (fwd=%lld drop=%lld block=%lld"
		" syn=%lld udp=%lld icmp=%lld anomaly=%lld"
		" halfopen_src=%lld gsyn=%lld pktrate=%lld"
		" icmp_err=%lld scan=%lld)\n",
		atomic64_read(&pkts_forwarded),
		atomic64_read(&pkts_dropped),
		atomic64_read(&pkts_blocked),
		atomic64_read(&pkts_syn_dropped),
		atomic64_read(&pkts_udp_dropped),
		atomic64_read(&pkts_icmp_dropped),
		atomic64_read(&pkts_anomaly_dropped),
		atomic64_read(&pkts_halfopen_src_dropped),
		atomic64_read(&pkts_global_syn_dropped),
		atomic64_read(&pkts_pkt_rate_dropped),
		atomic64_read(&pkts_icmp_err_dropped),
		atomic64_read(&pkts_scan_dropped));
}

module_init(pkt_forward_init);
module_exit(pkt_forward_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Stargazer Team");
MODULE_DESCRIPTION("Packet forwarding module for BPI-R4 NGFW");
MODULE_VERSION(PKT_FWD_VERSION);
MODULE_SOFTDEP("pre: session nf_defrag_ipv4");
