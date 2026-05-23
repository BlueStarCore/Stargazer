// SPDX-License-Identifier: GPL-2.0-only
/*
 * session.c - Session tracking for Stargazer NGFW
 *
 * Copyright (C) 2026 Stargazer Team
 *
 * RCU-protected hash table for 5-tuple session lookup. Direction is
 * inferred by the first-packet-wins rule (see session.h): the packet
 * that creates the session defines the "original" direction; reversed
 * 5-tuple matches are accounted as "reply".
 *
 * Phase 2 wiring:
 *   - pkt_forward.ko calls sess_lookup_or_create()/sess_update() in
 *     the FORWARD hook to maintain the table on the data path.
 *   - Userspace reads /proc/stargazer/sessions for visibility.
 *   - A periodic reaper expires idle sessions.
 */

#include <linux/module.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/timekeeping.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/random.h>
#include <linux/icmp.h>
#include "session.h"

#ifndef SESS_VERSION
#define SESS_VERSION "unknown"
#endif

/* Hash table sizing */
#define SESSION_TABLE_BITS	10		/* 2^10 = 1024 buckets */
#define MAX_SESSIONS		65536

/*
 * GC scan parameters.
 *
 * SCAN_NORMAL covers the full 1024-bucket table in ~16 ticks (16 s).
 * SCAN_AGGRESSIVE covers it in ~4 ticks when above pf_adaptive_start.
 * LRU_EVICT_MAX caps the LRU-head sweep per tick to bound lock hold time.
 * EMERGENCY_SCAN_MAX caps the inline eviction scan in the packet create path
 * to prevent NIC-driver stalls under DDoS (bounded worst-case latency).
 */
#define GC_SCAN_NORMAL        64   /* buckets/tick at normal pressure          */
#define GC_SCAN_AGGRESSIVE   256   /* buckets/tick above pf_adaptive_start     */
#define GC_LRU_EVICT_MAX      32   /* max LRU-head evictions per GC tick       */
#define PF_EMERGENCY_SCAN_MAX 64   /* max LRU entries in inline emergency path */

/* All session idle timeouts — configurable at runtime via sysfs */

/* Hash table and its writer-side lock */
static DEFINE_HASHTABLE(sess_table, SESSION_TABLE_BITS);
static DEFINE_SPINLOCK(table_lock);

/*
 * LRU list: head = oldest session, tail = most-recently-used.
 *
 * lru_lock is intentionally separate from table_lock.  sess_update()
 * fires on every forwarded packet and moves the session to the LRU tail;
 * if it shared table_lock it would serialize against the GC's bucket
 * scan on every packet.  With a dedicated lru_lock, the packet path and
 * the GC path never block each other.
 *
 * Lock ordering rule: always acquire table_lock before lru_lock.
 * When only lru_lock is needed (sess_update), take it alone.
 */
static DEFINE_SPINLOCK(lru_lock);
static LIST_HEAD(sess_lru);

/* Randomized hash seed — initialized at module load from kernel RNG.
 * Prevents hash-bucket collision attacks (hash DoS). */
static u32 sess_hash_rnd;

/* Asymmetric routing mode: allow mid-stream TCP pickup for HA / ECMP paths. */
bool sess_asymmetric_mode = false;
module_param(sess_asymmetric_mode, bool, 0644);
MODULE_PARM_DESC(sess_asymmetric_mode,
		 "Allow mid-stream TCP pickup for asymmetric routing (default: N)");
EXPORT_SYMBOL_GPL(sess_asymmetric_mode);

/*
 * FreeBSD PF-style adaptive state thresholds.
 *
 * pf_max_states    — hard session cap; no new sessions above this count.
 * pf_adaptive_start— begin shrinking idle TTLs above this count.
 * pf_adaptive_end  — TTL → 0 when count reaches this (all idle sessions
 *                    become instant eviction candidates for the GC and the
 *                    inline emergency path).
 *
 * Defaults (0) are resolved in session_init() to 75% and 90% of
 * pf_max_states respectively so the ratios hold for any table size.
 * Override at load time: modprobe session pf_max_states=100000 \
 *                                         pf_adaptive_start=60000 \
 *                                         pf_adaptive_end=90000
 */
static unsigned int pf_max_states     = MAX_SESSIONS;
static unsigned int pf_adaptive_start;  /* resolved in init to 75% of max */
static unsigned int pf_adaptive_end;    /* resolved in init to 90% of max */
module_param(pf_max_states,     uint, 0444);
module_param(pf_adaptive_start, uint, 0644);
module_param(pf_adaptive_end,   uint, 0644);
MODULE_PARM_DESC(pf_max_states,     "Hard session table cap (default: MAX_SESSIONS)");
MODULE_PARM_DESC(pf_adaptive_start, "Begin TTL scaling above this count (default: 75% of max)");
MODULE_PARM_DESC(pf_adaptive_end,   "TTL crushed to 0 at this count (default: 90% of max)");

/* Counters */
static atomic_t   next_id              = ATOMIC_INIT(1);
static atomic64_t sess_created         = ATOMIC64_INIT(0);
static atomic64_t sess_active          = ATOMIC64_INIT(0);
static atomic64_t sess_expired         = ATOMIC64_INIT(0);
static atomic64_t pkts_invalid         = ATOMIC64_INIT(0); /* TCP state-machine drops */
static atomic64_t sess_pf_drops        = ATOMIC64_INIT(0); /* PF_DROP: table full + no eviction */
static atomic64_t sess_halfopen        = ATOMIC64_INIT(0); /* current half-open TCP sessions */
static atomic64_t sess_rejected_halfopen = ATOMIC64_INIT(0); /* dropped: half-open cap exceeded */

/*
 * Half-open TCP session cap — prevents SYN flood from filling the table.
 * Counts sessions in SYN_SENT, SYN_RECV, or SYN_SENT2 state.
 * Primary defense is the adaptive TTL (short base TTL + PF scaling);
 * this is a hard backstop.
 */
static unsigned int max_halfopen = 1024;
module_param(max_halfopen, uint, 0644);
MODULE_PARM_DESC(max_halfopen, "Max concurrent half-open TCP sessions (default: 1024)");

/*
 * Per-source established session cap — prevents a single IP from consuming
 * the entire session table with ESTABLISHED connections.
 */
static unsigned int max_est_per_src = 64;
module_param(max_est_per_src, uint, 0644);
MODULE_PARM_DESC(max_est_per_src,
	"Max ESTABLISHED sessions per source IP (0=disabled, default: 64)");

/*
 * Zero-window zombie protection — accelerates teardown of sessions where
 * TCP window stays at zero for longer than this threshold.
 */
static unsigned int zero_win_timeout = 60;
module_param(zero_win_timeout, uint, 0644);
MODULE_PARM_DESC(zero_win_timeout,
	"Seconds TCP window=0 before accelerated session teardown (0=disabled, default: 60)");

/* TCP per-state timeouts */
static unsigned int sess_tt_tcp_none       = 120;
static unsigned int sess_tt_tcp_syn_sent   = 120;
static unsigned int sess_tt_tcp_syn_recv   =  60;
static unsigned int sess_tt_tcp_est        = 3600;
static unsigned int sess_tt_tcp_fin_wait   = 120;
static unsigned int sess_tt_tcp_close_wait =  60;
static unsigned int sess_tt_tcp_last_ack   =  30;
static unsigned int sess_tt_tcp_time_wait  = 120;
static unsigned int sess_tt_tcp_close      =  10;
static unsigned int sess_tt_tcp_syn_sent2  =  60;
module_param(sess_tt_tcp_none,       uint, 0644);
module_param(sess_tt_tcp_syn_sent,   uint, 0644);
module_param(sess_tt_tcp_syn_recv,   uint, 0644);
module_param(sess_tt_tcp_est,        uint, 0644);
module_param(sess_tt_tcp_fin_wait,   uint, 0644);
module_param(sess_tt_tcp_close_wait, uint, 0644);
module_param(sess_tt_tcp_last_ack,   uint, 0644);
module_param(sess_tt_tcp_time_wait,  uint, 0644);
module_param(sess_tt_tcp_close,      uint, 0644);
module_param(sess_tt_tcp_syn_sent2,  uint, 0644);
MODULE_PARM_DESC(sess_tt_tcp_none,       "TCP pre-handshake timeout seconds (default: 120)");
MODULE_PARM_DESC(sess_tt_tcp_syn_sent,   "TCP SYN_SENT (half-open) timeout seconds (default: 120)");
MODULE_PARM_DESC(sess_tt_tcp_syn_recv,   "TCP SYN_RECV timeout seconds (default: 60)");
MODULE_PARM_DESC(sess_tt_tcp_est,        "TCP ESTABLISHED idle timeout seconds (default: 3600)");
MODULE_PARM_DESC(sess_tt_tcp_fin_wait,   "TCP FIN_WAIT timeout seconds (default: 120)");
MODULE_PARM_DESC(sess_tt_tcp_close_wait, "TCP CLOSE_WAIT timeout seconds (default: 60)");
MODULE_PARM_DESC(sess_tt_tcp_last_ack,   "TCP LAST_ACK timeout seconds (default: 30)");
MODULE_PARM_DESC(sess_tt_tcp_time_wait,  "TCP TIME_WAIT timeout seconds (default: 120)");
MODULE_PARM_DESC(sess_tt_tcp_close,      "TCP CLOSE (RST) timeout seconds (default: 10)");
MODULE_PARM_DESC(sess_tt_tcp_syn_sent2,  "TCP simultaneous-open timeout seconds (default: 60)");

/* Non-TCP protocol timeouts */
static unsigned int sess_tt_udp   = 180;
static unsigned int sess_tt_icmp  =  60;
static unsigned int sess_tt_other = 300;
module_param(sess_tt_udp,   uint, 0644);
module_param(sess_tt_icmp,  uint, 0644);
module_param(sess_tt_other, uint, 0644);
MODULE_PARM_DESC(sess_tt_udp,   "UDP session idle timeout seconds (default: 180)");
MODULE_PARM_DESC(sess_tt_icmp,  "ICMP session idle timeout seconds (default: 60)");
MODULE_PARM_DESC(sess_tt_other, "Other protocol session timeout seconds (default: 300)");

/* Per-source established session tracker (lock-free approximate, 4096 slots) */
#define SRC_EST_SLOTS 4096U

struct src_est_slot {
	__be32  ip;
	u32     count;   /* ESTABLISHED sessions currently active from this src */
};

static struct src_est_slot src_est_table[SRC_EST_SLOTS];
static u32 est_hash_seed;

static inline u32 src_est_idx(__be32 ip)
{
	return jhash_1word((__force u32)ip, est_hash_seed) % SRC_EST_SLOTS;
}

/* Increment per-src established count. Returns true if cap exceeded. */
static bool src_est_check_and_inc(__be32 ip)
{
	struct src_est_slot *sl = &src_est_table[src_est_idx(ip)];

	if (sl->ip != ip) {
		sl->ip    = ip;
		sl->count = 1;
		return false;
	}
	if (max_est_per_src && sl->count >= max_est_per_src)
		return true;
	sl->count++;
	return false;
}

/* Decrement per-src established count (called on session teardown). */
static void src_est_dec(__be32 ip)
{
	struct src_est_slot *sl = &src_est_table[src_est_idx(ip)];

	if (sl->ip == ip && sl->count > 0)
		sl->count--;
}

static atomic64_t sess_est_src_drops = ATOMIC64_INIT(0); /* per-src est cap hits */

static inline bool sess_is_halfopen(u8 state)
{
	return state == SESS_TCP_SYN_SENT  ||
	       state == SESS_TCP_SYN_RECV  ||
	       state == SESS_TCP_SYN_SENT2;
}

/* procfs handles */
struct proc_dir_entry *sg_proc_root;
EXPORT_SYMBOL_GPL(sg_proc_root);
static struct proc_dir_entry *proc_sessions;
static struct proc_dir_entry *proc_session_ctl;

/*
 * GC cursor and hysteresis state.
 * Written only from sess_reaper_fn — a single delayed_work item that
 * never executes concurrently with itself — so no lock is needed here.
 */
static bool     gc_aggressive;  /* hysteresis: true when active >= pf_adaptive_start */
static unsigned gc_idx;         /* incremental bucket cursor (0..NBUCKETS-1)          */

/* Single 1 Hz reaper — replaces the former slow + fast dual-reaper pair */
static void sess_reaper_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(sess_reaper, sess_reaper_fn);

/* Forward declarations */
static void sess_free_rcu(struct rcu_head *head);
static int  pf_purge_expired_states_emergency(void);

/* ---------------------------------------------------------------------- */
/* Helpers                                                                */
/* ---------------------------------------------------------------------- */

static inline u32 sess_hash(const struct sess_key *key)
{
	return jhash(key, sizeof(*key), sess_hash_rnd);
}

static inline bool sess_key_eq(const struct sess_key *a,
			       const struct sess_key *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

static inline void sess_reverse_key(struct sess_key *r,
				    const struct sess_key *k)
{
	r->src_ip   = k->dst_ip;
	r->dst_ip   = k->src_ip;
	r->src_port = k->dst_port;
	r->dst_port = k->src_port;
	r->proto    = k->proto;
}

static inline u32 tcp_state_timeout(u8 state)
{
	switch (state) {
	case SESS_TCP_NONE:        return READ_ONCE(sess_tt_tcp_none);
	case SESS_TCP_SYN_SENT:    return READ_ONCE(sess_tt_tcp_syn_sent);
	case SESS_TCP_SYN_RECV:    return READ_ONCE(sess_tt_tcp_syn_recv);
	case SESS_TCP_ESTABLISHED: return READ_ONCE(sess_tt_tcp_est);
	case SESS_TCP_FIN_WAIT:    return READ_ONCE(sess_tt_tcp_fin_wait);
	case SESS_TCP_CLOSE_WAIT:  return READ_ONCE(sess_tt_tcp_close_wait);
	case SESS_TCP_LAST_ACK:    return READ_ONCE(sess_tt_tcp_last_ack);
	case SESS_TCP_TIME_WAIT:   return READ_ONCE(sess_tt_tcp_time_wait);
	case SESS_TCP_CLOSE:       return READ_ONCE(sess_tt_tcp_close);
	case SESS_TCP_SYN_SENT2:   return READ_ONCE(sess_tt_tcp_syn_sent2);
	default:                   return READ_ONCE(sess_tt_tcp_none);
	}
}

static inline u32 sess_timeout_for_proto(u8 proto)
{
	switch (proto) {
	case IPPROTO_TCP:  return READ_ONCE(sess_tt_tcp_none);
	case IPPROTO_UDP:  return READ_ONCE(sess_tt_udp);
	case IPPROTO_ICMP: return READ_ONCE(sess_tt_icmp);
	default:           return READ_ONCE(sess_tt_other);
	}
}

/* ---------------------------------------------------------------------- */
/* Key extraction                                                         */
/* ---------------------------------------------------------------------- */

/**
 * extract_key - Fill 5-tuple key from an IPv4 skb
 *
 * For non-TCP/UDP protocols both ports are set to 0; this lets ICMP
 * and other protocols share the same hash with a stable key.
 */
int extract_key(struct sk_buff *skb, struct sess_key *key)
{
	struct iphdr *iph = ip_hdr(skb);

	if (!iph)
		return -EINVAL;

	key->src_ip = iph->saddr;
	key->dst_ip = iph->daddr;
	key->proto  = iph->protocol;
	key->src_port = 0;
	key->dst_port = 0;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
			return -EINVAL;
		key->src_port = tcp_hdr(skb)->source;
		key->dst_port = tcp_hdr(skb)->dest;
		break;

	case IPPROTO_UDP:
		if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr)))
			return -EINVAL;
		key->src_port = udp_hdr(skb)->source;
		key->dst_port = udp_hdr(skb)->dest;
		break;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(extract_key);

/* ---------------------------------------------------------------------- */
/* Lookup / create                                                        */
/* ---------------------------------------------------------------------- */

struct session *sess_lookup(const struct sess_key *key)
{
	struct session *s;
	u32 hash = sess_hash(key);

	hash_for_each_possible_rcu(sess_table, s, node, hash) {
		if (!sess_key_eq(&s->key, key))
			continue;

		/*
		 * Inline Emergency Cleanup — Technique 3 of 3.
		 *
		 * A dead session found on the hash chain is deleted here,
		 * on the packet thread, in O(1) — rather than waiting up to
		 * 1 s for the GC tick.  This prevents expired nodes from
		 * piling up in hot buckets and degrading lookup from O(1)
		 * toward O(k) between GC passes.
		 *
		 * Acquiring table_lock inside rcu_read_lock() is legal: RCU
		 * read-side critical sections can nest with spinlocks.
		 * hash_del_rcu() and call_rcu() are also safe inside RCU.
		 */
		if (ktime_compare(ktime_get(), READ_ONCE(s->expires_at)) >= 0) {
			spin_lock_bh(&table_lock);
			/*
			 * Re-check under the writer lock: another CPU may have
			 * refreshed expires_at between the lockless test above
			 * and this point.
			 */
			if (ktime_compare(ktime_get(), READ_ONCE(s->expires_at)) >= 0) {
				hash_del_rcu(&s->node);
				spin_lock(&lru_lock);	/* BH already off */
				list_del_init(&s->lru_node);
				spin_unlock(&lru_lock);
				atomic64_dec(&sess_active);
				atomic64_inc(&sess_expired);
				spin_unlock_bh(&table_lock);
				call_rcu(&s->rcu, sess_free_rcu);
				return NULL;
			}
			spin_unlock_bh(&table_lock);
		}
		return s;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(sess_lookup);

struct session *sess_lookup_bidir(const struct sess_key *key, int *dir_out)
{
	struct session *s;
	struct sess_key rkey;

	s = sess_lookup(key);
	if (s) {
		*dir_out = SESS_DIR_ORIG;
		return s;
	}

	sess_reverse_key(&rkey, key);
	s = sess_lookup(&rkey);
	if (s) {
		*dir_out = SESS_DIR_REPLY;
		return s;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(sess_lookup_bidir);

/* Allocate and initialize a session. Caller must insert into the table. */
static struct session *sess_alloc(const struct sess_key *key)
{
	struct session *s;
	ktime_t now;

	s = kzalloc(sizeof(*s), GFP_ATOMIC);
	if (!s)
		return NULL;

	now = ktime_get();
	memcpy(&s->key, key, sizeof(*key));
	s->id        = atomic_inc_return(&next_id);
	s->flags     = SESS_ACTIVE;
	s->ml_score  = 0;
	s->expires_at = ktime_add_ns(now,
		(u64)sess_timeout_for_proto(key->proto) * NSEC_PER_SEC);
	s->stats.first_seen   = now;
	s->stats.last_seen    = now;
	s->stats.len_orig.min = U32_MAX;
	s->stats.len_reply.min = U32_MAX;
	spin_lock_init(&s->lock);
	INIT_LIST_HEAD(&s->lru_node);
	return s;
}

/**
 * sess_lookup_or_create - First-packet-wins direction inference.
 *
 * Tries the key as-is (original direction), then reversed (reply
 * direction), then atomically inserts a new session. The race where
 * two CPUs both miss and try to create is resolved by re-checking
 * both directions under table_lock.
 *
 * Returns: session pointer + dir, or NULL on allocation failure /
 * table full. Pointer is valid only inside RCU read-side CS.
 */
struct session *sess_lookup_or_create(const struct sess_key *key,
				      int *dir_out)
{
	struct session *s;
	struct session *fresh;
	struct sess_key rkey;
	u32 hash;

	s = sess_lookup(key);
	if (s) {
		*dir_out = SESS_DIR_ORIG;
		return s;
	}

	sess_reverse_key(&rkey, key);
	s = sess_lookup(&rkey);
	if (s) {
		*dir_out = SESS_DIR_REPLY;
		return s;
	}

	/*
	 * Weapon 2 — Inline Emergency Eviction.
	 *
	 * When the table hits pf_max_states we do NOT wait for the next 1 Hz GC
	 * tick.  Instead we run pf_purge_expired_states_emergency() synchronously
	 * in this softirq context to harvest sessions whose TTLs were crushed by
	 * Weapon 1.  This has two outcomes:
	 *
	 *  freed > 0: Weapon 1 had pre-expired some sessions; we reclaimed them
	 *             and can proceed with the new session allocation below.
	 *
	 *  freed == 0: The table is saturated with active (non-expired) sessions —
	 *              either a legitimate burst or a DDoS that Weapon 1 hasn't
	 *              had time to crush yet.  We increment sess_pf_drops and
	 *              return NULL, which causes the caller (pkt_forward.ko) to
	 *              return NF_DROP — the packet is discarded at the NIC driver
	 *              layer without allocating any kernel state.
	 *
	 * Why inline and not a wakeup?  Context switches cost 10-50 µs on
	 * Cortex-A53.  Under a 1 Mpps SYN flood, waking a GC thread per-packet
	 * would burn 10-50 CPU-seconds per second in scheduler overhead alone.
	 * Running inline in the same softirq costs only the bounded scan time
	 * (~640 ns for PF_EMERGENCY_SCAN_MAX=64 entries) — no context switch,
	 * no cache thrash between stacks.
	 */
	/*
	 * Half-open cap: reject new TCP sessions when SYN_SENT/SYN_RECV/SYN_SENT2
	 * count reaches max_halfopen.  Checked before the table-full path so the
	 * caller gets a specific drop rather than a generic PF_DROP.
	 * Non-TCP and asymmetric-mode pickups are not subject to this limit.
	 */
	if (key->proto == IPPROTO_TCP &&
	    atomic64_read(&sess_halfopen) >= (s64)max_halfopen) {
		atomic64_inc(&sess_rejected_halfopen);
		return NULL;
	}

	if (atomic64_read(&sess_active) >= (s64)pf_max_states) {
		if (pf_purge_expired_states_emergency() == 0) {
			atomic64_inc(&sess_pf_drops);
			pr_warn_ratelimited(
				"session: PF_DROP table saturated (active=%lld drops=%lld)\n",
				atomic64_read(&sess_active),
				atomic64_read(&sess_pf_drops));
			return NULL;	/* → NF_DROP at the NIC driver */
		}
		/* At least one slot was freed; fall through to allocate. */
	}

	fresh = sess_alloc(key);
	if (!fresh)
		return NULL;

	hash = sess_hash(key);

	spin_lock_bh(&table_lock);

	/* Re-check capacity under the writer lock — another CPU may have filled
	 * the table between the lockless gate above and this point. */
	if (atomic64_read(&sess_active) >= (s64)pf_max_states) {
		spin_unlock_bh(&table_lock);
		kfree(fresh);
		atomic64_inc(&sess_pf_drops);
		return NULL;
	}

	/* Re-check half-open cap under the writer lock — same rationale as
	 * the pf_max_states re-check above: the lockless gate is a fast-path
	 * hint only; multiple CPUs can pass it simultaneously. */
	if (key->proto == IPPROTO_TCP &&
	    atomic64_read(&sess_halfopen) >= (s64)max_halfopen) {
		spin_unlock_bh(&table_lock);
		kfree(fresh);
		atomic64_inc(&sess_rejected_halfopen);
		return NULL;
	}

	/* Re-check both directions under the writer lock to handle the race
	 * where another CPU inserted a matching session between our lockless
	 * lookups and this point.  Use non-RCU walker inside the writer lock.
	 * Also verify the found session has not already expired — adaptive TTL
	 * scaling can crush TTLs to 0, and the GC may not have run yet.
	 */
	hash_for_each_possible(sess_table, s, node, hash) {
		if (sess_key_eq(&s->key, key) &&
		    ktime_compare(ktime_get(), READ_ONCE(s->expires_at)) < 0) {
			spin_unlock_bh(&table_lock);
			kfree(fresh);
			*dir_out = SESS_DIR_ORIG;
			return s;
		}
	}
	{
		u32 rhash = sess_hash(&rkey);

		hash_for_each_possible(sess_table, s, node, rhash) {
			if (sess_key_eq(&s->key, &rkey) &&
			    ktime_compare(ktime_get(), READ_ONCE(s->expires_at)) < 0) {
				spin_unlock_bh(&table_lock);
				kfree(fresh);
				*dir_out = SESS_DIR_REPLY;
				return s;
			}
		}
	}
	hash_add_rcu(sess_table, &fresh->node, hash);
	atomic64_inc(&sess_created);
	atomic64_inc(&sess_active);
	/* Link into LRU tail while table_lock is already held (lock order: table → lru). */
	spin_lock(&lru_lock);
	list_add_tail(&fresh->lru_node, &sess_lru);
	spin_unlock(&lru_lock);
	spin_unlock_bh(&table_lock);
	*dir_out = SESS_DIR_ORIG;
	return fresh;
}
EXPORT_SYMBOL_GPL(sess_lookup_or_create);

/* ---------------------------------------------------------------------- */
/* Update                                                                 */
/* ---------------------------------------------------------------------- */

static void update_pkt_len(struct sess_pkt_len *len, u32 pkt_len)
{
	if (pkt_len > len->max)
		len->max = pkt_len;
	if (pkt_len < len->min)
		len->min = pkt_len;
}

static void accumulate_tcp_flags(struct session *s, struct sk_buff *skb,
				 int dir)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph;
	u16 flags;

	if (iph->protocol != IPPROTO_TCP)
		return;
	/* TCP header is already linear — extract_key() and sess_tcp_check()
	 * both called pskb_may_pull before we get here.  Do NOT call
	 * pskb_may_pull here; this function runs under s->lock (spinlock). */
	tcph  = tcp_hdr(skb);

	/* tcp_flag_word() returns __be32; shift after be32_to_cpu for correct
	 * flags extraction on little-endian ARM64. */
	flags = (u16)(be32_to_cpu(tcp_flag_word(tcph)) >> 16);

	if (dir == SESS_DIR_ORIG) {
		s->stats.tcp_flags_orig |= flags;
		if (s->stats.pkts_orig == 1)
			s->stats.init_win_orig = ntohs(tcph->window);
	} else {
		s->stats.tcp_flags_reply |= flags;
	}
}

/* True if seq falls within [start, start+size) in TCP sequence space.
 * Uses u32 arithmetic so it handles wrap-around and scaled windows correctly. */
static inline bool tcp_in_window(u32 seq, u32 start, u32 size)
{
	return (u32)(seq - start) < size;
}

/* RFC 793 / RFC 7323 TCP option types — defined locally to avoid net/tcp.h */
#define SG_TCPOPT_EOL    0  /* end of option list */
#define SG_TCPOPT_NOP    1  /* no-operation (1 byte, no length field) */
#define SG_TCPOPT_WSCALE 3  /* window scale (RFC 7323), length = 3 */

/*
 * Parse the TCP window scale option from a SYN or SYN-ACK.
 * Caller must ensure the full TCP header including options is linear
 * (pskb_may_pull to iph->ihl*4 + tcph->doff*4) before calling.
 * Returns scale value 0..14, or 0 if option absent (no scaling).
 */
static u8 tcp_parse_wscale(const struct tcphdr *tcph)
{
	const u8 *opt = (const u8 *)tcph + sizeof(struct tcphdr);
	int optlen    = tcph->doff * 4 - (int)sizeof(struct tcphdr);
	int i = 0;

	while (i < optlen) {
		switch (opt[i]) {
		case SG_TCPOPT_EOL:
			return 0;
		case SG_TCPOPT_NOP:
			i++;
			continue;
		default:
			if (i + 1 >= optlen)
				return 0;
			if (opt[i] == SG_TCPOPT_WSCALE && opt[i + 1] == 3) {
				if (i + 2 >= optlen)
					return 0;
				/* RFC 7323: valid scale values are 0..14 */
				return min_t(u8, opt[i + 2], 14);
			}
			/* Skip unknown option — length field at opt[i+1] */
			i += opt[i + 1] ? opt[i + 1] : 1;
			continue;
		}
	}
	return 0;
}

unsigned int sess_tcp_check(struct session *s, struct sk_buff *skb, int dir)
{
	struct iphdr  *iph;
	struct tcphdr *tcph;
	u8  new_state;
	u8  wscale = 0;
	u32 seq, ack_seq;
	u16 win;

	iph = ip_hdr(skb);
	if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
		atomic64_inc(&pkts_invalid);
		return NF_DROP;
	}

	/* Re-fetch after pull — pskb_may_pull may reallocate the skb head */
	iph  = ip_hdr(skb);
	tcph = tcp_hdr(skb);

	/* Reject malformed TCP headers (doff < 5 means no room for mandatory
	 * 20-byte fixed header — these are forged or corrupt packets). */
	if (tcph->doff < 5) {
		atomic64_inc(&pkts_invalid);
		return NF_DROP;
	}

	/* SYN and SYN-ACK carry the window scale TCP option (RFC 7323).
	 * Pull the full TCP header to reach the options, then parse. */
	if (tcph->syn) {
		unsigned int full_hdr = (unsigned int)iph->ihl * 4 +
					(unsigned int)tcph->doff * 4;
		if (pskb_may_pull(skb, full_hdr)) {
			iph    = ip_hdr(skb);
			tcph   = tcp_hdr(skb);
			wscale = tcp_parse_wscale(tcph);
		}
	}

	seq     = ntohl(tcph->seq);
	ack_seq = ntohl(tcph->ack_seq);
	win     = ntohs(tcph->window);

	spin_lock(&s->lock);
	new_state = s->tcp_state;

	/* ── RST: validate sequence, then tear down ──────────────────── */
	if (tcph->rst) {
		/* A legitimate RST seq must fall within the peer's receive window.
		 * Apply the negotiated window scale before the range check.
		 * Skip validation if we haven't seen an ACK yet (ack_seq == 0). */
		u32 peer_ack = s->tcp_win[1 - dir].ack_seq;
		u32 peer_win = (u32)s->tcp_win[1 - dir].win
			       << s->tcp_win[1 - dir].scale;

		if (peer_ack != 0 && peer_win > 0 &&
		    !tcp_in_window(seq, peer_ack, peer_win)) {
			spin_unlock(&s->lock);
			atomic64_inc(&pkts_invalid);
			return NF_DROP;
		}
		new_state = SESS_TCP_CLOSE;
		goto apply;
	}

	/* ── State machine ───────────────────────────────────────────── */
	switch (s->tcp_state) {

	case SESS_TCP_NONE:
	case SESS_TCP_SYN_SENT:
		if (tcph->syn && !tcph->ack && dir == SESS_DIR_ORIG) {
			new_state = SESS_TCP_SYN_SENT;
			s->tcp_win[SESS_DIR_ORIG].scale = wscale;
		} else if (tcph->syn && !tcph->ack && dir == SESS_DIR_REPLY) {
			/* Simultaneous open: both sides sent SYN before receiving one */
			new_state = SESS_TCP_SYN_SENT2;
			s->tcp_win[SESS_DIR_REPLY].scale = wscale;
		} else if (tcph->syn && tcph->ack && dir == SESS_DIR_REPLY) {
			new_state = SESS_TCP_SYN_RECV;
			s->tcp_win[SESS_DIR_REPLY].scale = wscale;
		} else if (!tcph->syn && !tcph->rst && READ_ONCE(sess_asymmetric_mode)) {
			/* Asymmetric routing: data on half-open session — promote to ESTABLISHED */
			new_state = SESS_TCP_ESTABLISHED;
		}
		break;

	case SESS_TCP_SYN_SENT2:
		/* Both sides have sent SYN; the first SYN+ACK from either direction
		 * completes the handshake (RFC 793 simultaneous open). */
		if (tcph->syn && tcph->ack) {
			new_state = SESS_TCP_SYN_RECV;
			s->tcp_win[dir].scale = wscale;
		}
		break;

	case SESS_TCP_SYN_RECV:
		if (!tcph->syn && tcph->ack && !tcph->fin && dir == SESS_DIR_ORIG)
			new_state = SESS_TCP_ESTABLISHED;
		break;

	case SESS_TCP_ESTABLISHED:
		if (tcph->syn) {
			spin_unlock(&s->lock);
			atomic64_inc(&pkts_invalid);
			return NF_DROP;
		}
		if (tcph->fin)
			new_state = (dir == SESS_DIR_ORIG) ? SESS_TCP_FIN_WAIT
							    : SESS_TCP_CLOSE_WAIT;
		break;

	case SESS_TCP_FIN_WAIT:
		if (tcph->fin && dir == SESS_DIR_REPLY)
			new_state = SESS_TCP_TIME_WAIT;
		break;

	case SESS_TCP_CLOSE_WAIT:
		if (tcph->fin && dir == SESS_DIR_ORIG)
			new_state = SESS_TCP_LAST_ACK;
		break;

	case SESS_TCP_LAST_ACK:
		if (tcph->ack && dir == SESS_DIR_REPLY)
			new_state = SESS_TCP_CLOSE;
		break;

	case SESS_TCP_TIME_WAIT:
	case SESS_TCP_CLOSE:
		break;
	}

apply:
	if (tcph->ack) {
		s->tcp_win[dir].ack_seq = ack_seq;
		s->tcp_win[dir].win     = win;
	}

	/* Per-source ESTABLISHED cap — checked before any state side-effects.
	 * If the cap is hit we drop the completing ACK so the connection never
	 * leaves SYN_RECV; the session will expire on its normal half-open TTL. */
	if (new_state == SESS_TCP_ESTABLISHED &&
	    s->tcp_state != SESS_TCP_ESTABLISHED) {
		if (src_est_check_and_inc(s->key.src_ip)) {
			atomic64_inc(&sess_est_src_drops);
			spin_unlock(&s->lock);
			atomic64_inc(&pkts_invalid);
			return NF_DROP;
		}
	}

	if (new_state != s->tcp_state) {
		bool was_half = sess_is_halfopen(s->tcp_state);
		bool now_half = sess_is_halfopen(new_state);

		if (!was_half && now_half)
			atomic64_inc(&sess_halfopen);
		else if (was_half && !now_half)
			atomic64_dec(&sess_halfopen);

		/* Decrement per-src established count whenever we leave ESTABLISHED
		 * (FIN, RST, or any other state transition out of ESTABLISHED). */
		if (s->tcp_state == SESS_TCP_ESTABLISHED)
			src_est_dec(s->key.src_ip);

		WRITE_ONCE(s->tcp_state, new_state);
	}

	s->expires_at = ktime_add_ns(ktime_get(),
		(u64)tcp_state_timeout(new_state) * NSEC_PER_SEC);

	/* Zero-window zombie protection: if a side continuously advertises
	 * window=0, crush the session TTL to 5 s after zero_win_timeout seconds.
	 *
	 * Track which direction set zero_win_since so that only a non-zero
	 * window from THAT direction resets the timer.  Packets from the other
	 * direction (the sender, with its own non-zero window) must not reset
	 * the timer or an attacker controlling the sender side could keep the
	 * zombie alive indefinitely. */
	if (zero_win_timeout && new_state == SESS_TCP_ESTABLISHED) {
		if (win == 0) {
			if (!s->zero_win_since) {
				s->zero_win_since = ktime_get();
				s->zero_win_dir   = (u8)dir;
			} else if (ktime_to_ns(ktime_sub(ktime_get(),
							 s->zero_win_since)) >
				   (s64)zero_win_timeout * NSEC_PER_SEC) {
				s->expires_at = ktime_add_ns(ktime_get(),
							     5LL * NSEC_PER_SEC);
			}
		} else if (s->zero_win_since && (u8)dir == s->zero_win_dir) {
			/* The receiver advertises non-zero window: connection can recover */
			s->zero_win_since = 0;
		}
	}

	spin_unlock(&s->lock);
	return NF_ACCEPT;
}
EXPORT_SYMBOL_GPL(sess_tcp_check);

void sess_update(struct session *s, struct sk_buff *skb, int dir)
{
	ktime_t now = ktime_get();
	u32 len = skb->len;

	spin_lock(&s->lock);

	if (dir == SESS_DIR_ORIG) {
		s->stats.pkts_orig++;
		s->stats.bytes_orig += len;
		update_pkt_len(&s->stats.len_orig, len);
	} else {
		s->stats.pkts_reply++;
		s->stats.bytes_reply += len;
		update_pkt_len(&s->stats.len_reply, len);
	}

	accumulate_tcp_flags(s, skb, dir);

	if (s->stats.iat_count > 0)
		s->stats.iat_sum_ns +=
			ktime_to_ns(ktime_sub(now, s->stats.last_seen));
	s->stats.iat_count++;
	s->stats.last_seen = now;

	/* TCP expiry is managed by sess_tcp_check() which runs before this.
	 * Overwriting it here would reset the state-aware timeout to the
	 * generic baseline. */
	if (s->key.proto != IPPROTO_TCP)
		s->expires_at = ktime_add_ns(now,
			(u64)sess_timeout_for_proto(s->key.proto) * NSEC_PER_SEC);

	spin_unlock(&s->lock);

	/*
	 * LRU touch: move this session to the tail (most-recently-used).
	 * Guard with list_empty: the reaper calls list_del_init() before
	 * call_rcu(), leaving lru_node self-linked.  If sess_update() runs
	 * in the RCU window after eviction, list_empty() returns true and
	 * we skip the touch — preventing re-insertion of a to-be-freed
	 * session back into sess_lru (which would cause a double call_rcu).
	 */
	spin_lock_bh(&lru_lock);
	if (!list_empty(&s->lru_node))
		list_move_tail(&s->lru_node, &sess_lru);
	spin_unlock_bh(&lru_lock);
}
EXPORT_SYMBOL_GPL(sess_update);

/* ---------------------------------------------------------------------- */
/* Delete / reaper                                                        */
/* ---------------------------------------------------------------------- */

static void sess_free_rcu(struct rcu_head *head)
{
	struct session *s = container_of(head, struct session, rcu);

	if (s->key.proto == IPPROTO_TCP) {
		u8 state = READ_ONCE(s->tcp_state);

		/* Correct half-open counter for sessions evicted mid-handshake. */
		if (sess_is_halfopen(state))
			atomic64_dec(&sess_halfopen);

		/* Correct per-src established count for sessions reaped by GC
		 * while still ESTABLISHED (no FIN/RST was ever seen). */
		if (state == SESS_TCP_ESTABLISHED)
			src_est_dec(s->key.src_ip);
	}

	kfree(s);
}

void sess_delete(struct session *s)
{
	spin_lock_bh(&table_lock);
	/*
	 * Guard against being called on a session already removed by the GC
	 * reaper or inline expiry.  hlist_unhashed() is safe to test under
	 * table_lock: only code holding table_lock calls hash_del_rcu().
	 */
	if (hlist_unhashed(&s->node)) {
		spin_unlock_bh(&table_lock);
		return;
	}
	hash_del_rcu(&s->node);
	spin_lock(&lru_lock);		/* BH already disabled by table_lock */
	list_del_init(&s->lru_node);
	spin_unlock(&lru_lock);
	atomic64_dec(&sess_active);	/* inside table_lock: no window of inflated count */
	spin_unlock_bh(&table_lock);

	call_rcu(&s->rcu, sess_free_rcu);
}
EXPORT_SYMBOL_GPL(sess_delete);


/*
 * sess_base_timeout - Protocol / TCP-state idle timeout in seconds.
 */
static inline u32 sess_base_timeout(const struct session *s)
{
	if (s->key.proto == IPPROTO_TCP)
		return tcp_state_timeout(READ_ONCE(s->tcp_state));
	return sess_timeout_for_proto(s->key.proto);
}

/*
 * sess_pf_timeout - FreeBSD PF adaptive timeout scaling (Weapon 1).
 *
 * Implements the FreeBSD pf(4) formula:
 *   factor = (adaptive_end - current) / (adaptive_end - adaptive_start)
 *   effective_timeout = base_timeout * factor
 *
 * Behaviour across the three zones:
 *   current <= adaptive_start : factor = 1.0  → full base TTL (no pressure)
 *   current in (start, end)   : factor ∈ (0,1) → linearly shrinking TTL
 *   current >= adaptive_end   : factor = 0    → TTL crushed; session is an
 *                               immediate eviction candidate for both the 1 Hz
 *                               GC sweep and pf_purge_expired_states_emergency()
 *
 * TCP ESTABLISHED sessions are intentionally excluded from scaling.
 * Killing live connections during a SYN flood would harm legitimate users;
 * the attack targets are half-open states (SYN_SENT, SYN_RECV) whose base
 * TTLs are already short (60-120 s) and collapse to zero seconds first.
 *
 * Pure integer arithmetic — no floats (kernel constraint).
 */
static u32 sess_pf_timeout(const struct session *s, u64 active_cnt)
{
	u32 base = sess_base_timeout(s);

	/*
	 * ESTABLISHED connections survive TTL scaling.  Under a SYN flood the
	 * attacker controls half-open entries; scaling them out does not disrupt
	 * any established flow.
	 */
	if (s->key.proto == IPPROTO_TCP &&
	    READ_ONCE(s->tcp_state) == SESS_TCP_ESTABLISHED)
		return base;

	if (active_cnt <= (u64)pf_adaptive_start)
		return base;
	if (active_cnt >= (u64)pf_adaptive_end)
		return 0;		/* TTL crushed — evict on next sweep */

	/* Linear factor: (adaptive_end - active_cnt) / (adaptive_end - adaptive_start).
	 * Numerator and denominator are both < 2^17 for any sane configuration,
	 * so u32 arithmetic is safe without overflow risk. */
	return base * (pf_adaptive_end - (u32)active_cnt)
		     / (pf_adaptive_end - pf_adaptive_start);
}

/*
 * pf_purge_expired_states_emergency - Weapon 2: synchronous inline eviction.
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ WHY THIS EXISTS — Context-Switching Meltdown prevention                │
 * │                                                                         │
 * │ On a resource-constrained embedded CPU (Cortex-A53, single/dual core), │
 * │ the naive response to "table full" is to either:                        │
 * │  (a) Spin-poll the GC result — burns cycles, starves RX softirq.       │
 * │  (b) Wake the GC immediately — forces a context switch, adds ~10-50 µs │
 * │      of scheduler overhead per packet under flood; with 1Mpps SYN      │
 * │      flood that is 10-50 s of wasted CPU time per second.              │
 * │                                                                         │
 * │ This function avoids both by running inline in the packet thread:      │
 * │  - No context switch: runs in the same softirq context as the RX path. │
 * │  - Bounded cost: scans at most PF_EMERGENCY_SCAN_MAX LRU entries.      │
 * │  - Targets Weapon 1's output: sessions with eff==0 are the cheapest    │
 * │    to evict (no timeout comparison needed, just a pointer unlink).     │
 * │  - If nothing is evictable (table full of active flows), it returns 0  │
 * │    immediately and the caller signals PF_DROP to the NIC driver —      │
 * │    the packet is discarded before any state is allocated.              │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * Safe to call from softirq context, including inside rcu_read_lock():
 * spin_lock_bh() and call_rcu() are both valid inside an RCU read-side CS.
 * Must be called outside table_lock.
 * Returns the number of sessions freed (0 = table saturated → PF_DROP).
 */
static int pf_purge_expired_states_emergency(void)
{
	struct session *lru_s, *lru_tmp;
	ktime_t now        = ktime_get();
	u64  active_cnt    = (u64)atomic64_read(&sess_active);
	int  freed         = 0;
	int  scanned       = 0;

	spin_lock_bh(&table_lock);
	spin_lock(&lru_lock);		/* BH already off; table → lru order */

	/*
	 * Walk from the LRU head (oldest sessions).  Weapon 1 has been crushing
	 * TTLs as the table fills; the head is the most likely place to find
	 * sessions with eff == 0 or large idle_ns.
	 *
	 * We cap at PF_EMERGENCY_SCAN_MAX to bound worst-case latency: even at
	 * line-rate SYN flood, 64 pointer comparisons ≈ 640 ns on Cortex-A53 —
	 * negligible compared to a context switch.
	 */
	list_for_each_entry_safe(lru_s, lru_tmp, &sess_lru, lru_node) {
		u32 eff;
		s64 idle_ns;

		if (scanned++ >= PF_EMERGENCY_SCAN_MAX)
			break;

		eff     = sess_pf_timeout(lru_s, active_cnt);
		idle_ns = ktime_to_ns(ktime_sub(now,
				READ_ONCE(lru_s->stats.last_seen)));

		/*
		 * Two eviction conditions — both use Weapon 1's output:
		 *  1. eff == 0: TTL was crushed to zero by the scaling formula;
		 *     any idle duration qualifies, even idle_ns == 0.
		 *  2. idle_ns >= eff * NSEC_PER_SEC: TTL not yet zero but the
		 *     scaled timeout has already elapsed since last packet.
		 */
		if (eff != 0 && idle_ns < (s64)eff * NSEC_PER_SEC)
			continue;

		hash_del_rcu(&lru_s->node);
		list_del_init(&lru_s->lru_node);
		atomic64_dec(&sess_active);
		atomic64_inc(&sess_expired);
		call_rcu(&lru_s->rcu, sess_free_rcu);
		freed++;
	}

	spin_unlock(&lru_lock);
	spin_unlock_bh(&table_lock);

	return freed;
}

/*
 * sess_reaper_fn — Single 1 Hz GC.  The GC tick is NEVER shortened under
 * load.  Keeping it at a fixed 1 Hz eliminates context-switch pressure:
 * the scheduler wakes this workqueue exactly once per second regardless of
 * traffic rate, so the CPU does not burn interrupt/context-switch overhead
 * responding to load spikes.  All load-adaptive behaviour is inside the tick.
 *
 * Three interlocking techniques:
 *
 * Weapon 1a — Adaptive Timeout Scaling (sess_pf_timeout):
 *   Shrinks idle TTLs linearly from full (below adaptive_start) down to 0
 *   (at adaptive_end).  Half-open TCP entries (SYN_SENT/SYN_RECV) — the
 *   primary SYN-flood attack surface — collapse toward 0 first because their
 *   base TTLs (60-120 s) are much shorter than ESTABLISHED (3600 s).
 *   Result: the 1 Hz sweep can wipe thousands of stale half-open states in
 *   a single pass without touching any established connection.
 *
 * Weapon 1b — Incremental scanning (gc_idx cursor):
 *   Scans a fixed window per tick.  table_lock hold time is bounded to
 *   ~25 µs (NORMAL) or ~100 µs (AGGRESSIVE) — no head-of-line blocking
 *   for new-session creation on other CPUs even at 90% table fill.
 *
 * Weapon 1c — Hysteresis (gc_aggressive latch):
 *   Mode is set ON at pf_adaptive_start and cleared only at 85% of it.
 *   Prevents mode oscillation when the count hovers near the boundary,
 *   which would otherwise alternate between 64 and 256 buckets/tick on
 *   consecutive seconds — wasted work without actually draining.
 *
 * Weapon 2 (pf_purge_expired_states_emergency) is the on-demand partner:
 *   called from the packet creation path when current >= pf_max_states.
 */
static void sess_reaper_fn(struct work_struct *work)
{
	struct session    *s;
	struct hlist_node *tmp;
	unsigned int       b, end, scan_size;
	int                reaped = 0;
	ktime_t            now    = ktime_get();
	u64                active;

	active = (u64)atomic64_read(&sess_active);

	/*
	 * Hysteresis — Weapon 1c.
	 * Enter aggressive mode at pf_adaptive_start; stay until the count
	 * drops to 85% of that threshold.  The 15% band prevents oscillation
	 * when the table drains and refills near the boundary.
	 */
	if (active >= (u64)pf_adaptive_start)
		gc_aggressive = true;
	else if (active < (u64)pf_adaptive_start * 17 / 20)  /* ~85% */
		gc_aggressive = false;

	/*
	 * Incremental scan window — Weapon 1b.
	 * NORMAL  → 64 buckets/tick → full table in 16 s (normal pressure).
	 * AGGRESSIVE → 256 buckets/tick → full table in 4 s (under attack).
	 */
	scan_size = gc_aggressive ? GC_SCAN_AGGRESSIVE : GC_SCAN_NORMAL;
	end       = min(gc_idx + scan_size, 1u << SESSION_TABLE_BITS);

	spin_lock_bh(&table_lock);
	spin_lock(&lru_lock);	/* BH already disabled; obeys table → lru order */

	/* ── Phase 1: Incremental hash bucket scan ──────────────────── */
	for (b = gc_idx; b < end; b++) {
		hlist_for_each_entry_safe(s, tmp, &sess_table[b], node) {
			/*
			 * Weapon 1a: use the PF adaptive formula instead of the
			 * raw expires_at.  When active >= pf_adaptive_end, eff == 0
			 * and every idle_ns >= 0, so all non-ESTABLISHED sessions
			 * in this bucket are reaped in a single pass.
			 */
			u32 eff     = sess_pf_timeout(s, active);
			s64 idle_ns = ktime_to_ns(
				ktime_sub(now, READ_ONCE(s->stats.last_seen)));

			if (eff != 0 && idle_ns < (s64)eff * NSEC_PER_SEC)
				continue;

			hash_del_rcu(&s->node);
			list_del_init(&s->lru_node);
			atomic64_dec(&sess_active);
			atomic64_inc(&sess_expired);
			call_rcu(&s->rcu, sess_free_rcu);
			reaped++;
		}
	}

	/*
	 * Phase 2: LRU-head early eviction (aggressive mode only).
	 *
	 * Directly targets the oldest sessions (LRU head) without waiting for
	 * the scan cursor to reach their buckets.  Combined with the TTL
	 * scaling in Phase 1, this drains the attack surface in both
	 * temporal order (LRU) and spatial order (bucket window) simultaneously.
	 */
	if (gc_aggressive) {
		struct session *lru_s, *lru_tmp;
		int lru_cnt = 0;

		list_for_each_entry_safe(lru_s, lru_tmp, &sess_lru, lru_node) {
			u32 eff;
			s64 idle_ns;

			if (lru_cnt++ >= GC_LRU_EVICT_MAX)
				break;

			eff     = sess_pf_timeout(lru_s, active);
			idle_ns = ktime_to_ns(
				ktime_sub(now, READ_ONCE(lru_s->stats.last_seen)));

			if (eff != 0 && idle_ns < (s64)eff * NSEC_PER_SEC)
				continue;

			hash_del_rcu(&lru_s->node);
			list_del_init(&lru_s->lru_node);
			atomic64_dec(&sess_active);
			atomic64_inc(&sess_expired);
			call_rcu(&lru_s->rcu, sess_free_rcu);
			reaped++;
		}
	}

	spin_unlock(&lru_lock);
	spin_unlock_bh(&table_lock);

	gc_idx = (end >= (1u << SESSION_TABLE_BITS)) ? 0 : end;

	if (reaped)
		pr_debug("session: gc reaped=%d idx=%u active=%llu agg=%d\n",
			 reaped, gc_idx, active, gc_aggressive);

	/*
	 * Always reschedule at exactly HZ (1 second).
	 *
	 * Context-switch meltdown prevention: never shorten this delay under
	 * load.  On a Cortex-A53 @ 1.8 GHz, each forced context switch costs
	 * ~10-50 µs.  A naive "wake GC faster when table is full" scheme at
	 * 10 Hz under a 1 Mpps SYN flood = 10 extra wakeups/s × 50 µs = 500 µs
	 * of scheduler overhead per second — plus cache-thrash from switching
	 * between the GC stack and the RX-softirq stack.  One wakeup per second
	 * eliminates all of this: Weapon 1 (TTL scaling) and Weapon 2 (inline
	 * emergency eviction) absorb the load within the fixed tick cadence.
	 */
	schedule_delayed_work(&sess_reaper, HZ);
}

static void sess_flush_all(void)
{
	struct session *s;
	struct hlist_node *tmp;
	int bucket;

	spin_lock_bh(&table_lock);
	spin_lock(&lru_lock);		/* BH already disabled by table_lock */
	hash_for_each_safe(sess_table, bucket, tmp, s, node) {
		hash_del_rcu(&s->node);
		list_del_init(&s->lru_node);
		atomic64_dec(&sess_active);
		call_rcu(&s->rcu, sess_free_rcu);
	}
	spin_unlock(&lru_lock);
	spin_unlock_bh(&table_lock);
	/* Caller calls rcu_barrier() if it needs to wait for all frees to complete.
	 * session_exit() does; the runtime flush path (sess_ctl_write) does not. */
}

/* ---------------------------------------------------------------------- */
/* /proc/stargazer/session_ctl — control interface (write-only)           */
/* ---------------------------------------------------------------------- */

static ssize_t sess_ctl_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	char cmd[16];
	size_t len = min(count, sizeof(cmd) - 1);

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (copy_from_user(cmd, buf, len))
		return -EFAULT;
	cmd[len] = '\0';

	/* Strip trailing newline */
	if (len > 0 && cmd[len - 1] == '\n')
		cmd[--len] = '\0';

	if (strcmp(cmd, "flush") == 0) {
		sess_flush_all();
		return (ssize_t)count;
	}

	return -EINVAL;
}

static const struct proc_ops sess_ctl_proc_ops = {
	.proc_write  = sess_ctl_write,
	.proc_lseek  = noop_llseek,
};

/* ---------------------------------------------------------------------- */
/* ICMP error → parent session mapping                                    */
/* ---------------------------------------------------------------------- */

struct session *sess_icmp_error_lookup(struct sk_buff *skb, int *dir_out)
{
	struct iphdr   *iph;
	struct icmphdr *icmph;
	struct iphdr   *inner_iph;
	struct sess_key key;
	unsigned int    outer_hlen;
	unsigned int    inner_hlen;
	const u8       *inner_l4;

	iph        = ip_hdr(skb);
	outer_hlen = iph->ihl * 4;

	/* Pull outer IP + ICMP fixed header (8 bytes) */
	if (!pskb_may_pull(skb, outer_hlen + sizeof(struct icmphdr)))
		return NULL;

	iph   = ip_hdr(skb);
	icmph = (struct icmphdr *)((u8 *)iph + outer_hlen);

	/* Only error types embed the original header */
	if (icmph->type != ICMP_DEST_UNREACH &&
	    icmph->type != ICMP_TIME_EXCEEDED &&
	    icmph->type != ICMP_PARAMETERPROB)
		return NULL;

	/* Pull embedded IP header */
	if (!pskb_may_pull(skb, outer_hlen + sizeof(struct icmphdr) +
			       sizeof(struct iphdr)))
		return NULL;

	iph       = ip_hdr(skb);
	icmph     = (struct icmphdr *)((u8 *)iph + outer_hlen);
	inner_iph = (struct iphdr   *)((u8 *)icmph + sizeof(struct icmphdr));

	/* Reject malformed inner IP header before using ihl to compute offsets */
	if (inner_iph->ihl < 5)
		return NULL;

	inner_hlen = inner_iph->ihl * 4;

	/* RFC 792 guarantees at least 8 bytes of embedded L4 */
	if (!pskb_may_pull(skb, outer_hlen + sizeof(struct icmphdr) +
			       inner_hlen + 8))
		return NULL;

	/* Re-fetch all pointers — pskb_may_pull may have reallocated skb head */
	iph       = ip_hdr(skb);
	icmph     = (struct icmphdr *)((u8 *)iph + outer_hlen);
	inner_iph = (struct iphdr   *)((u8 *)icmph + sizeof(struct icmphdr));
	inner_l4  = (const u8       *) inner_iph + inner_iph->ihl * 4;

	key.src_ip   = inner_iph->saddr;
	key.dst_ip   = inner_iph->daddr;
	key.proto    = inner_iph->protocol;
	key.src_port = 0;
	key.dst_port = 0;

	/* First 8 bytes of embedded L4: src_port at [0], dst_port at [2] */
	if (key.proto == IPPROTO_TCP || key.proto == IPPROTO_UDP) {
		memcpy(&key.src_port, inner_l4,     sizeof(__be16));
		memcpy(&key.dst_port, inner_l4 + 2, sizeof(__be16));
	}

	/*
	 * Validate that the outer ICMP packet was delivered to the same host
	 * that sent the triggering packet.  A legitimate ICMP error is always
	 * addressed to the originator of the packet that caused the error, so
	 * outer dst_ip must equal the embedded src_ip.  Any mismatch means the
	 * ICMP packet is forged — drop it rather than letting an attacker
	 * manipulate sessions for flows they are not a party to.
	 */
	if (iph->daddr != key.src_ip)
		return NULL;

	/* The embedded header is in ORIG direction; the error arrived as REPLY.
	 * sess_lookup_bidir() handles both directions correctly. */
	return sess_lookup_bidir(&key, dir_out);
}
EXPORT_SYMBOL_GPL(sess_icmp_error_lookup);

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* /proc/stargazer/sessions                                               */
/* ---------------------------------------------------------------------- */

struct sess_seq_state {
	unsigned int bucket;
};

static struct session *sess_seq_first_in_bucket(struct sess_seq_state *st)
{
	while (st->bucket < HASH_SIZE(sess_table)) {
		struct hlist_node *n =
			rcu_dereference(hlist_first_rcu(&sess_table[st->bucket]));
		if (n)
			return hlist_entry(n, struct session, node);
		st->bucket++;
	}
	return NULL;
}

static struct session *sess_seq_next_in_bucket(struct session *cur)
{
	struct hlist_node *n =
		rcu_dereference(hlist_next_rcu(&cur->node));

	return n ? hlist_entry(n, struct session, node) : NULL;
}

static void *sess_seq_start(struct seq_file *seq, loff_t *pos)
	__acquires(RCU)
{
	struct sess_seq_state *st = seq->private;
	struct session *s;
	loff_t off;

	rcu_read_lock();

	if (*pos == 0)
		return SEQ_START_TOKEN;

	st->bucket = 0;
	s = sess_seq_first_in_bucket(st);
	for (off = 1; s && off < *pos; off++) {
		struct session *next = sess_seq_next_in_bucket(s);

		if (next) {
			s = next;
		} else {
			st->bucket++;
			s = sess_seq_first_in_bucket(st);
		}
	}
	return s;
}

static void *sess_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct sess_seq_state *st = seq->private;
	struct session *s;

	(*pos)++;

	if (v == SEQ_START_TOKEN) {
		st->bucket = 0;
		return sess_seq_first_in_bucket(st);
	}

	s = sess_seq_next_in_bucket(v);
	if (s)
		return s;

	st->bucket++;
	return sess_seq_first_in_bucket(st);
}

static void sess_seq_stop(struct seq_file *seq, void *v)
	__releases(RCU)
{
	rcu_read_unlock();
}

static int sess_seq_show(struct seq_file *seq, void *v)
{
	struct session *s;
	ktime_t now;
	s64 age_ms, ttl_ms;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq,
			"# Stargazer sessions  active=%lld created=%lld"
			" expired=%lld invalid=%lld pf_drops=%lld\n"
			"# halfopen=%lld rejected_halfopen=%lld max_halfopen=%u\n"
			"# est_src_drops=%lld max_est_per_src=%u"
			" zero_win_timeout=%u\n"
			"# pf_max=%u adaptive_start=%u adaptive_end=%u"
			" gc_aggressive=%d\n",
			atomic64_read(&sess_active),
			atomic64_read(&sess_created),
			atomic64_read(&sess_expired),
			atomic64_read(&pkts_invalid),
			atomic64_read(&sess_pf_drops),
			atomic64_read(&sess_halfopen),
			atomic64_read(&sess_rejected_halfopen),
			max_halfopen,
			atomic64_read(&sess_est_src_drops),
			max_est_per_src, zero_win_timeout,
			pf_max_states, pf_adaptive_start, pf_adaptive_end,
			READ_ONCE(gc_aggressive));
		seq_puts(seq,
			"# proto src dst id pkts(o/r) bytes(o/r) age_ms expire_ms ml flags tcp_state\n");
		return 0;
	}

	s = v;
	now = ktime_get();
	age_ms = ktime_to_ms(ktime_sub(now, s->stats.first_seen));
	ttl_ms = ktime_to_ms(ktime_sub(s->expires_at, now));

	seq_printf(seq,
		"proto=%u src=%pI4:%u dst=%pI4:%u id=%u"
		" pkts=%llu/%llu bytes=%llu/%llu"
		" age_ms=%lld expire_ms=%lld"
		" ml=%d flags=0x%x"
		" dev=%u/%u",
		s->key.proto,
		&s->key.src_ip, ntohs(s->key.src_port),
		&s->key.dst_ip, ntohs(s->key.dst_port),
		s->id,
		s->stats.pkts_orig, s->stats.pkts_reply,
		s->stats.bytes_orig, s->stats.bytes_reply,
		age_ms, ttl_ms,
		READ_ONCE(s->ml_score), READ_ONCE(s->flags),
		s->ifindex_in, s->ifindex_out);
	if (s->key.proto == IPPROTO_TCP)
		seq_printf(seq, " tcp_state=%u", READ_ONCE(s->tcp_state));
	seq_putc(seq, '\n');
	return 0;
}

static const struct seq_operations sess_seq_ops = {
	.start = sess_seq_start,
	.next  = sess_seq_next,
	.stop  = sess_seq_stop,
	.show  = sess_seq_show,
};

static int sess_proc_open(struct inode *inode, struct file *file)
{
	return seq_open_private(file, &sess_seq_ops,
				sizeof(struct sess_seq_state));
}

static const struct proc_ops sess_proc_ops = {
	.proc_open    = sess_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = seq_release_private,
};

/* ---------------------------------------------------------------------- */
/* Module init / exit                                                     */
/* ---------------------------------------------------------------------- */

static int __init session_init(void)
{
	hash_init(sess_table);
	get_random_bytes(&sess_hash_rnd, sizeof(sess_hash_rnd));
	get_random_bytes(&est_hash_seed, sizeof(est_hash_seed));

	/* Clamp and resolve PF adaptive thresholds.
	 * pf_max_states must not exceed the compile-time hash table capacity.
	 * pf_adaptive_start/end default to 75% / 90% of max if not overridden
	 * via module params (indicated by a zero value at load time). */
	if (pf_max_states == 0 || pf_max_states > MAX_SESSIONS)
		pf_max_states = MAX_SESSIONS;
	if (pf_adaptive_start == 0)
		pf_adaptive_start = pf_max_states * 3 / 4;   /* 75% */
	if (pf_adaptive_end == 0)
		pf_adaptive_end = pf_max_states * 9 / 10;    /* 90% */
	if (pf_adaptive_start >= pf_adaptive_end ||
	    pf_adaptive_end > pf_max_states) {
		pr_warn("session: invalid adaptive thresholds, using defaults\n");
		pf_adaptive_start = pf_max_states * 3 / 4;
		pf_adaptive_end   = pf_max_states * 9 / 10;
	}

	sg_proc_root = proc_mkdir("stargazer", NULL);
	if (!sg_proc_root) {
		pr_err("session: failed to create /proc/stargazer\n");
		return -ENOMEM;
	}

	proc_sessions = proc_create("sessions", 0444, sg_proc_root,
				    &sess_proc_ops);
	if (!proc_sessions) {
		pr_err("session: failed to create /proc/stargazer/sessions\n");
		proc_remove(sg_proc_root);
		sg_proc_root = NULL;
		return -ENOMEM;
	}

	proc_session_ctl = proc_create("session_ctl", 0200, sg_proc_root,
				       &sess_ctl_proc_ops);
	if (!proc_session_ctl) {
		pr_err("session: failed to create /proc/stargazer/session_ctl\n");
		proc_remove(proc_sessions);
		proc_remove(sg_proc_root);
		sg_proc_root = NULL;
		return -ENOMEM;
	}

	schedule_delayed_work(&sess_reaper, HZ);

	pr_info("session: loaded v%s buckets=%d gc=1Hz(norm=%d/agg=%d)"
		" pf_max=%u adaptive=%u/%u lru=yes\n",
		SESS_VERSION, 1 << SESSION_TABLE_BITS,
		GC_SCAN_NORMAL, GC_SCAN_AGGRESSIVE,
		pf_max_states, pf_adaptive_start, pf_adaptive_end);
	return 0;
}

static void __exit session_exit(void)
{
	cancel_delayed_work_sync(&sess_reaper);

	proc_remove(proc_session_ctl);
	proc_remove(proc_sessions);
	proc_remove(sg_proc_root);

	sess_flush_all();
	rcu_barrier(); /* wait for all call_rcu() frees before module memory unloads */

	pr_info("session: unloaded (created=%lld expired=%lld)\n",
		atomic64_read(&sess_created),
		atomic64_read(&sess_expired));
}

module_init(session_init);
module_exit(session_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Stargazer Team");
MODULE_DESCRIPTION("Session tracking for Stargazer NGFW");
MODULE_VERSION(SESS_VERSION);
