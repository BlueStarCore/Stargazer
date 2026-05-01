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

#include "session.h"

#ifndef SESS_VERSION
#define SESS_VERSION "unknown"
#endif

/* Hash table sizing */
#define SESSION_TABLE_BITS	10		/* 2^10 = 1024 buckets */
#define MAX_SESSIONS		65536

/* Per-protocol idle timeouts (Phase 2.6 will add TCP-state-aware timeouts) */
#define SESS_TIMEOUT_TCP_SEC	3600
#define SESS_TIMEOUT_UDP_SEC	180
#define SESS_TIMEOUT_ICMP_SEC	60
#define SESS_TIMEOUT_OTHER_SEC	300

/* Reaper cadence */
#define SESS_REAPER_INTERVAL_SEC 30

/* Hash table and its writer-side lock */
static DEFINE_HASHTABLE(sess_table, SESSION_TABLE_BITS);
static DEFINE_SPINLOCK(table_lock);

/* Counters */
static atomic_t   next_id      = ATOMIC_INIT(1);
static atomic64_t sess_created = ATOMIC64_INIT(0);
static atomic64_t sess_active  = ATOMIC64_INIT(0);
static atomic64_t sess_expired = ATOMIC64_INIT(0);

/* procfs handles */
static struct proc_dir_entry *proc_root;
static struct proc_dir_entry *proc_sessions;

/* Reaper */
static void sess_reaper_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(sess_reaper, sess_reaper_fn);

/* ---------------------------------------------------------------------- */
/* Helpers                                                                */
/* ---------------------------------------------------------------------- */

static inline u32 sess_hash(const struct sess_key *key)
{
	return jhash(key, sizeof(*key), 0);
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

static inline u32 sess_timeout_for_proto(u8 proto)
{
	switch (proto) {
	case IPPROTO_TCP:  return SESS_TIMEOUT_TCP_SEC;
	case IPPROTO_UDP:  return SESS_TIMEOUT_UDP_SEC;
	case IPPROTO_ICMP: return SESS_TIMEOUT_ICMP_SEC;
	default:           return SESS_TIMEOUT_OTHER_SEC;
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
		if (sess_key_eq(&s->key, key))
			return s;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(sess_lookup);

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

	/* Capacity gate before allocating. */
	if (atomic64_read(&sess_active) >= MAX_SESSIONS) {
		pr_warn_ratelimited("session: table full (%d max)\n",
				    MAX_SESSIONS);
		return NULL;
	}

	fresh = sess_alloc(key);
	if (!fresh)
		return NULL;

	hash = sess_hash(key);

	spin_lock(&table_lock);
	/* Re-check both directions under the writer lock to handle the race
	 * where another CPU inserted a matching session between our lockless
	 * lookups and this point.
	 */
	hash_for_each_possible_rcu(sess_table, s, node, hash) {
		if (sess_key_eq(&s->key, key)) {
			spin_unlock(&table_lock);
			kfree(fresh);
			*dir_out = SESS_DIR_ORIG;
			return s;
		}
	}
	{
		u32 rhash = sess_hash(&rkey);

		hash_for_each_possible_rcu(sess_table, s, node, rhash) {
			if (sess_key_eq(&s->key, &rkey)) {
				spin_unlock(&table_lock);
				kfree(fresh);
				*dir_out = SESS_DIR_REPLY;
				return s;
			}
		}
	}
	hash_add_rcu(sess_table, &fresh->node, hash);
	spin_unlock(&table_lock);

	atomic64_inc(&sess_created);
	atomic64_inc(&sess_active);
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
	if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
		return;

	tcph  = tcp_hdr(skb);
	flags = tcp_flag_word(tcph) >> 16;

	if (dir == SESS_DIR_ORIG) {
		s->stats.tcp_flags_orig |= flags;
		if (s->stats.pkts_orig == 1)
			s->stats.init_win_orig = ntohs(tcph->window);
	} else {
		s->stats.tcp_flags_reply |= flags;
	}
}

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

	s->expires_at = ktime_add_ns(now,
		(u64)sess_timeout_for_proto(s->key.proto) * NSEC_PER_SEC);

	spin_unlock(&s->lock);
}
EXPORT_SYMBOL_GPL(sess_update);

/* ---------------------------------------------------------------------- */
/* Delete / reaper                                                        */
/* ---------------------------------------------------------------------- */

static void sess_free_rcu(struct rcu_head *head)
{
	struct session *s = container_of(head, struct session, rcu);

	kfree(s);
}

void sess_delete(struct session *s)
{
	spin_lock(&table_lock);
	hash_del_rcu(&s->node);
	spin_unlock(&table_lock);

	atomic64_dec(&sess_active);
	call_rcu(&s->rcu, sess_free_rcu);
}
EXPORT_SYMBOL_GPL(sess_delete);

static void sess_reaper_fn(struct work_struct *work)
{
	struct session *s;
	struct hlist_node *tmp;
	int bucket;
	int reaped = 0;
	ktime_t now = ktime_get();

	spin_lock_bh(&table_lock);
	hash_for_each_safe(sess_table, bucket, tmp, s, node) {
		if (ktime_compare(now, s->expires_at) >= 0) {
			hash_del_rcu(&s->node);
			atomic64_dec(&sess_active);
			atomic64_inc(&sess_expired);
			call_rcu(&s->rcu, sess_free_rcu);
			reaped++;
		}
	}
	spin_unlock_bh(&table_lock);

	if (reaped)
		pr_debug("session: reaped %d expired entries\n", reaped);

	schedule_delayed_work(&sess_reaper, SESS_REAPER_INTERVAL_SEC * HZ);
}

static void sess_flush_all(void)
{
	struct session *s;
	struct hlist_node *tmp;
	int bucket;

	spin_lock_bh(&table_lock);
	hash_for_each_safe(sess_table, bucket, tmp, s, node) {
		hash_del_rcu(&s->node);
		atomic64_dec(&sess_active);
		call_rcu(&s->rcu, sess_free_rcu);
	}
	spin_unlock_bh(&table_lock);

	rcu_barrier();
}

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
			"# Stargazer sessions  active=%lld created=%lld expired=%lld\n",
			atomic64_read(&sess_active),
			atomic64_read(&sess_created),
			atomic64_read(&sess_expired));
		seq_puts(seq,
			"# proto src dst id pkts(o/r) bytes(o/r) age_ms expire_ms ml flags\n");
		return 0;
	}

	s = v;
	now = ktime_get();
	age_ms = ktime_to_ms(ktime_sub(now, s->stats.first_seen));
	ttl_ms = ktime_to_ms(ktime_sub(s->expires_at, now));

	seq_printf(seq,
		"proto=%u src=%pI4:%u dst=%pI4:%u id=%u pkts=%llu/%llu bytes=%llu/%llu age_ms=%lld expire_ms=%lld ml=%d flags=0x%x\n",
		s->key.proto,
		&s->key.src_ip, ntohs(s->key.src_port),
		&s->key.dst_ip, ntohs(s->key.dst_port),
		s->id,
		s->stats.pkts_orig, s->stats.pkts_reply,
		s->stats.bytes_orig, s->stats.bytes_reply,
		age_ms, ttl_ms,
		s->ml_score, s->flags);
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

	proc_root = proc_mkdir("stargazer", NULL);
	if (!proc_root) {
		pr_err("session: failed to create /proc/stargazer\n");
		return -ENOMEM;
	}

	proc_sessions = proc_create("sessions", 0444, proc_root,
				    &sess_proc_ops);
	if (!proc_sessions) {
		pr_err("session: failed to create /proc/stargazer/sessions\n");
		proc_remove(proc_root);
		proc_root = NULL;
		return -ENOMEM;
	}

	schedule_delayed_work(&sess_reaper, SESS_REAPER_INTERVAL_SEC * HZ);

	pr_info("session: loaded (v%s, %d buckets, reaper=%ds)\n",
		SESS_VERSION, 1 << SESSION_TABLE_BITS,
		SESS_REAPER_INTERVAL_SEC);
	return 0;
}

static void __exit session_exit(void)
{
	cancel_delayed_work_sync(&sess_reaper);

	if (proc_sessions)
		proc_remove(proc_sessions);
	if (proc_root)
		proc_remove(proc_root);

	sess_flush_all();

	pr_info("session: unloaded (created=%lld expired=%lld)\n",
		atomic64_read(&sess_created),
		atomic64_read(&sess_expired));
}

module_init(session_init);
module_exit(session_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stargazer Team");
MODULE_DESCRIPTION("Session tracking for Stargazer NGFW");
MODULE_VERSION(SESS_VERSION);
