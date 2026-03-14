// SPDX-License-Identifier: GPL-2.0-only
/*
 * session.c - Session tracking for Stargazer NGFW
 *
 * Copyright (C) 2026 Stargazer Team
 *
 * RCU-protected hash table for high-performance 5-tuple session lookup.
 * Collects NetFlow-like statistics for ML feature extraction.
 *
 * Usage: loaded as a dependency by pkt_forward.ko. Exports sess_*() API
 * for session creation, lookup, update, and deletion.
 */

#include <linux/module.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/timekeeping.h>

#ifndef SESS_VERSION
#define SESS_VERSION "unknown"
#endif

/* Configuration */
#define SESSION_TABLE_BITS	10		/* 2^10 = 1024 buckets */
#define SESSION_TIMEOUT_SEC	300		/* 5 minutes idle timeout */
#define MAX_SESSIONS		65536		/* Max concurrent sessions */

/* Session key (5-tuple) */
struct sess_key {
	__be32	src_ip;
	__be32	dst_ip;
	__be16	src_port;
	__be16	dst_port;
	u8	proto;
} __packed;

/* Per-direction packet length stats */
struct sess_pkt_len {
	u32	max;
	u32	min;
};

/* Traffic statistics */
struct sess_stats {
	u64		pkts_fwd;		/* Client -> Server */
	u64		pkts_bwd;		/* Server -> Client */
	u64		bytes_fwd;
	u64		bytes_bwd;
	ktime_t		first_seen;
	ktime_t		last_seen;
	u64		iat_sum_ns;		/* Inter-arrival time sum */
	u32		iat_count;
	u16		tcp_flags_fwd;		/* Accumulated TCP flags */
	u16		tcp_flags_bwd;
	u32		init_win_fwd;		/* Initial TCP window */
	struct sess_pkt_len	len_fwd;
	struct sess_pkt_len	len_bwd;
};

/* Session entry */
struct session {
	struct hlist_node	node;
	struct sess_key		key;
	u32			id;
	u16			flags;
	struct sess_stats	stats;
	s32			ml_score;	/* Fixed-point: score * 1000 */
	ktime_t			expires_at;
	spinlock_t		lock;
	struct rcu_head		rcu;
};

/* Session flags */
#define SESS_ACTIVE	0x0001
#define SESS_MARKED	0x0002			/* Flagged by ML as suspicious */

/* Hash table and its global lock */
static DEFINE_HASHTABLE(sess_table, SESSION_TABLE_BITS);
static DEFINE_SPINLOCK(table_lock);

/* Counters */
static atomic_t next_id = ATOMIC_INIT(1);
static atomic64_t sess_created = ATOMIC64_INIT(0);
static atomic64_t sess_active = ATOMIC64_INIT(0);

static inline u32 sess_hash(const struct sess_key *key)
{
	return jhash(key, sizeof(*key), 0);
}

static inline bool sess_key_eq(const struct sess_key *a,
			       const struct sess_key *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

/**
 * extract_key - Extract 5-tuple session key from packet
 * @skb: socket buffer containing the packet
 * @key: output key structure to fill
 *
 * Parses IP header and transport header (TCP/UDP) to build a
 * 5-tuple key. For non-TCP/UDP protocols, ports are set to zero.
 *
 * Return: 0 on success, -EINVAL if headers are inaccessible
 */
int extract_key(struct sk_buff *skb, struct sess_key *key)
{
	struct iphdr *iph;

	iph = ip_hdr(skb);
	if (!iph)
		return -EINVAL;

	key->src_ip = iph->saddr;
	key->dst_ip = iph->daddr;
	key->proto = iph->protocol;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
			return -EINVAL;
		/* Re-fetch IP header — pskb_may_pull may reallocate skb data */
		iph = ip_hdr(skb);
		key->src_port = tcp_hdr(skb)->source;
		key->dst_port = tcp_hdr(skb)->dest;
		break;

	case IPPROTO_UDP:
		if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr)))
			return -EINVAL;
		iph = ip_hdr(skb);
		key->src_port = udp_hdr(skb)->source;
		key->dst_port = udp_hdr(skb)->dest;
		break;

	default:
		key->src_port = 0;
		key->dst_port = 0;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(extract_key);

/**
 * sess_lookup - Find session by 5-tuple key (RCU-safe)
 * @key: 5-tuple session key
 *
 * Performs O(1) hash lookup under RCU read-side protection.
 * Caller must hold rcu_read_lock().
 *
 * Return: session pointer or NULL if not found
 */
struct session *sess_lookup(const struct sess_key *key)
{
	struct session *s;
	u32 hash = sess_hash(key);

	hash_for_each_possible_rcu(sess_table, s, node, hash) {
		if (sess_key_eq(&s->key, key))
			return s;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(sess_lookup);

/**
 * sess_create - Allocate and insert a new session
 * @key: 5-tuple session key
 *
 * Creates a new session entry with GFP_ATOMIC allocation (safe in
 * softirq context). Refuses creation if the table is full.
 *
 * Return: new session pointer, or NULL on allocation failure / table full
 */
struct session *sess_create(const struct sess_key *key)
{
	struct session *s;
	ktime_t now = ktime_get();
	u32 hash;

	if (atomic64_read(&sess_active) >= MAX_SESSIONS) {
		pr_warn_ratelimited("session: table full (%d max)\n",
				    MAX_SESSIONS);
		return NULL;
	}

	s = kzalloc(sizeof(*s), GFP_ATOMIC);
	if (!s)
		return NULL;

	memcpy(&s->key, key, sizeof(*key));
	s->id = atomic_inc_return(&next_id);
	s->flags = SESS_ACTIVE;
	s->ml_score = 0;
	s->expires_at = ktime_add_ns(now,
				     (u64)SESSION_TIMEOUT_SEC * NSEC_PER_SEC);
	s->stats.first_seen = now;
	s->stats.last_seen = now;
	s->stats.len_fwd.min = U32_MAX;
	s->stats.len_bwd.min = U32_MAX;
	spin_lock_init(&s->lock);

	hash = sess_hash(key);
	spin_lock(&table_lock);
	hash_add_rcu(sess_table, &s->node, hash);
	spin_unlock(&table_lock);

	atomic64_inc(&sess_created);
	atomic64_inc(&sess_active);

	return s;
}
EXPORT_SYMBOL_GPL(sess_create);

/* Update per-direction packet length min/max */
static void update_pkt_len(struct sess_pkt_len *len, u32 pkt_len)
{
	if (pkt_len > len->max)
		len->max = pkt_len;
	if (pkt_len < len->min)
		len->min = pkt_len;
}

/* Accumulate TCP flags if the packet carries a TCP header */
static void accumulate_tcp_flags(struct sess_stats *stats,
				 struct sk_buff *skb, int dir)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph;

	if (iph->protocol != IPPROTO_TCP)
		return;

	if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
		return;

	tcph = tcp_hdr(skb);
	if (dir == 0) {
		stats->tcp_flags_fwd |= tcp_flag_word(tcph) >> 16;
		/* Capture initial window size on first forward packet */
		if (stats->pkts_fwd == 1)
			stats->init_win_fwd = ntohs(tcph->window);
	} else {
		stats->tcp_flags_bwd |= tcp_flag_word(tcph) >> 16;
	}
}

/**
 * sess_update - Update session statistics from a packet
 * @s: session to update
 * @skb: socket buffer containing the packet
 * @dir: direction — 0 = forward (client->server), 1 = backward
 *
 * Updates packet/byte counters, inter-arrival time, packet length
 * stats, and TCP flags. Resets the session expiry timer.
 * Caller does NOT need to hold any lock — this function locks internally.
 */
void sess_update(struct session *s, struct sk_buff *skb, int dir)
{
	ktime_t now = ktime_get();
	u32 len = skb->len;

	spin_lock(&s->lock);

	if (dir == 0) {
		s->stats.pkts_fwd++;
		s->stats.bytes_fwd += len;
		update_pkt_len(&s->stats.len_fwd, len);
	} else {
		s->stats.pkts_bwd++;
		s->stats.bytes_bwd += len;
		update_pkt_len(&s->stats.len_bwd, len);
	}

	accumulate_tcp_flags(&s->stats, skb, dir);

	/* Inter-arrival time tracking */
	if (s->stats.iat_count > 0)
		s->stats.iat_sum_ns += ktime_to_ns(ktime_sub(now,
							s->stats.last_seen));
	s->stats.iat_count++;
	s->stats.last_seen = now;

	/* Reset idle timeout */
	s->expires_at = ktime_add_ns(now,
				     (u64)SESSION_TIMEOUT_SEC * NSEC_PER_SEC);

	spin_unlock(&s->lock);
}
EXPORT_SYMBOL_GPL(sess_update);

/* RCU callback for deferred session free */
static void sess_free_rcu(struct rcu_head *head)
{
	struct session *s = container_of(head, struct session, rcu);

	kfree(s);
}

/**
 * sess_delete - Remove and free a session
 * @s: session to delete
 *
 * Removes the session from the hash table under the table lock,
 * then schedules deferred free via call_rcu().
 */
void sess_delete(struct session *s)
{
	spin_lock(&table_lock);
	hash_del_rcu(&s->node);
	spin_unlock(&table_lock);

	atomic64_dec(&sess_active);
	call_rcu(&s->rcu, sess_free_rcu);
}
EXPORT_SYMBOL_GPL(sess_delete);

/**
 * sess_get_or_create - Lookup existing session or create a new one
 * @key: 5-tuple session key
 *
 * Atomically looks up a session; if not found, creates one while
 * holding the table lock to prevent duplicate entries from
 * concurrent callers.
 *
 * Return: session pointer (existing or newly created), or NULL on error
 */
struct session *sess_get_or_create(const struct sess_key *key)
{
	struct session *s;
	u32 hash;
	ktime_t now;

	rcu_read_lock();
	s = sess_lookup(key);
	rcu_read_unlock();

	if (s)
		return s;

	/*
	 * Not found — create under table_lock to avoid a race where
	 * two CPUs both see NULL and insert duplicate sessions.
	 */
	if (atomic64_read(&sess_active) >= MAX_SESSIONS) {
		pr_warn_ratelimited("session: table full (%d max)\n",
				    MAX_SESSIONS);
		return NULL;
	}

	s = kzalloc(sizeof(*s), GFP_ATOMIC);
	if (!s)
		return NULL;

	now = ktime_get();
	memcpy(&s->key, key, sizeof(*key));
	s->id = atomic_inc_return(&next_id);
	s->flags = SESS_ACTIVE;
	s->expires_at = ktime_add_ns(now,
				     (u64)SESSION_TIMEOUT_SEC * NSEC_PER_SEC);
	s->stats.first_seen = now;
	s->stats.last_seen = now;
	s->stats.len_fwd.min = U32_MAX;
	s->stats.len_bwd.min = U32_MAX;
	spin_lock_init(&s->lock);

	hash = sess_hash(key);

	spin_lock(&table_lock);
	/* Re-check under lock to handle the race */
	{
		struct session *existing;

		hash_for_each_possible_rcu(sess_table, existing, node, hash) {
			if (sess_key_eq(&existing->key, key)) {
				spin_unlock(&table_lock);
				kfree(s);
				return existing;
			}
		}
		hash_add_rcu(sess_table, &s->node, hash);
	}
	spin_unlock(&table_lock);

	atomic64_inc(&sess_created);
	atomic64_inc(&sess_active);

	return s;
}
EXPORT_SYMBOL_GPL(sess_get_or_create);

/* Flush all sessions from the table (used during module unload) */
static void sess_flush_all(void)
{
	struct session *s;
	struct hlist_node *tmp;
	int bucket;

	spin_lock(&table_lock);
	hash_for_each_safe(sess_table, bucket, tmp, s, node) {
		hash_del_rcu(&s->node);
		atomic64_dec(&sess_active);
		call_rcu(&s->rcu, sess_free_rcu);
	}
	spin_unlock(&table_lock);

	/* Wait for all RCU callbacks to complete before returning */
	rcu_barrier();
}

static int __init session_init(void)
{
	hash_init(sess_table);
	pr_info("session: loaded (v%s, %d buckets, %ds timeout)\n",
		SESS_VERSION, 1 << SESSION_TABLE_BITS, SESSION_TIMEOUT_SEC);
	return 0;
}

static void __exit session_exit(void)
{
	sess_flush_all();
	pr_info("session: unloaded (created=%lld)\n",
		atomic64_read(&sess_created));
}

module_init(session_init);
module_exit(session_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stargazer Team");
MODULE_DESCRIPTION("Session tracking for Stargazer NGFW");
MODULE_VERSION(SESS_VERSION);
