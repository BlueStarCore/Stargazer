// SPDX-License-Identifier: GPL-2.0-only
/*
 * session.c - Session tracking for Stargazer NGFW
 *
 * Copyright (C) 2026 Stargazer Team
 *
 * Hash table with RCU for high-performance 5-tuple session lookup.
 * Collects NetFlow-like statistics for ML feature extraction.
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

/* Configuration */
#define SESSION_TABLE_BITS  10              /* 2^10 = 1024 buckets */
#define SESSION_TIMEOUT_SEC 300             /* 5 minutes idle timeout */
#define MAX_SESSIONS        65536           /* Max concurrent sessions */

/* Session key (5-tuple) */
struct sess_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    u8     proto;
} __packed;

/* Traffic statistics */
struct sess_stats {
    u64     pkts_fwd;           /* Client -> Server */
    u64     pkts_bwd;           /* Server -> Client */
    u64     bytes_fwd;
    u64     bytes_bwd;
    ktime_t first_seen;
    ktime_t last_seen;
    u64     iat_sum_ns;         /* Inter-arrival time sum */
    u32     iat_count;
    u16     tcp_flags_fwd;
    u16     tcp_flags_bwd;
    u32     init_win_fwd;       /* Initial TCP window */
    u32     pkt_len_max_fwd;
    u32     pkt_len_min_fwd;
};

/* Session entry */
struct session {
    struct hlist_node   node;
    struct sess_key     key;
    u32                 id;
    u16                 flags;
    struct sess_stats   stats;
    s32                 ml_score;       /* Fixed-point: score * 1000 (avoid float) */
    ktime_t             expires_at;
    spinlock_t          lock;
    struct rcu_head     rcu;
};

/* Session flags */
#define SESS_ACTIVE     0x0001
#define SESS_MARKED     0x0002          /* Flagged by ML as suspicious */

/* Hash table */
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

static inline bool sess_key_eq(const struct sess_key *a, const struct sess_key *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

/*
 * extract_key - Extract 5-tuple from packet
 * @skb: Socket buffer
 * @key: Output key
 *
 * Returns 0 on success, -EINVAL on error
 */
int extract_key(struct sk_buff *skb, struct sess_key *key)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;

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
        tcph = tcp_hdr(skb);
        key->src_port = tcph->source;
        key->dst_port = tcph->dest;
        break;

    case IPPROTO_UDP:
        if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr)))
            return -EINVAL;
        udph = udp_hdr(skb);
        key->src_port = udph->source;
        key->dst_port = udph->dest;
        break;

    default:
        key->src_port = 0;
        key->dst_port = 0;
    }

    return 0;
}
EXPORT_SYMBOL_GPL(extract_key);

/*
 * sess_lookup - Find session by key (RCU-safe)
 * @key: 5-tuple key
 *
 * Returns session pointer or NULL. Caller must hold rcu_read_lock.
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

/*
 * sess_create - Create new session
 * @key: 5-tuple key
 *
 * Returns new session or NULL on failure
 */
struct session *sess_create(const struct sess_key *key)
{
    struct session *s;
    ktime_t now = ktime_get();
    u32 hash;

    if (atomic64_read(&sess_active) >= MAX_SESSIONS) {
        pr_warn_ratelimited("session: table full (%d)\n", MAX_SESSIONS);
        return NULL;
    }

    s = kzalloc(sizeof(*s), GFP_ATOMIC);
    if (!s)
        return NULL;

    memcpy(&s->key, key, sizeof(*key));
    s->id = atomic_inc_return(&next_id);
    s->flags = SESS_ACTIVE;
    s->ml_score = 0;
    s->expires_at = ktime_add_ns(now, (u64)SESSION_TIMEOUT_SEC * NSEC_PER_SEC);
    s->stats.first_seen = now;
    s->stats.last_seen = now;
    s->stats.pkt_len_min_fwd = U32_MAX;
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

/*
 * sess_update - Update session stats from packet
 * @s: Session
 * @skb: Packet
 * @dir: 0=forward, 1=backward
 */
void sess_update(struct session *s, struct sk_buff *skb, int dir)
{
    ktime_t now = ktime_get();
    u32 len = skb->len;
    struct iphdr *iph = ip_hdr(skb);

    spin_lock(&s->lock);

    if (dir == 0) {
        s->stats.pkts_fwd++;
        s->stats.bytes_fwd += len;
        if (len > s->stats.pkt_len_max_fwd)
            s->stats.pkt_len_max_fwd = len;
        if (len < s->stats.pkt_len_min_fwd)
            s->stats.pkt_len_min_fwd = len;

        if (iph->protocol == IPPROTO_TCP && s->stats.pkts_fwd == 1) {
            struct tcphdr *tcph = tcp_hdr(skb);
            s->stats.init_win_fwd = ntohs(tcph->window);
        }
    } else {
        s->stats.pkts_bwd++;
        s->stats.bytes_bwd += len;
    }

    /* Inter-arrival time */
    if (s->stats.iat_count > 0) {
        s->stats.iat_sum_ns += ktime_to_ns(ktime_sub(now, s->stats.last_seen));
    }
    s->stats.iat_count++;
    s->stats.last_seen = now;
    s->expires_at = ktime_add_ns(now, (u64)SESSION_TIMEOUT_SEC * NSEC_PER_SEC);

    spin_unlock(&s->lock);
}
EXPORT_SYMBOL_GPL(sess_update);

/* RCU callback for deferred free */
static void sess_free_rcu(struct rcu_head *head)
{
    struct session *s = container_of(head, struct session, rcu);
    kfree(s);
}

/*
 * sess_delete - Remove and free session
 * @s: Session to delete
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

/*
 * sess_get_or_create - Lookup or create session
 * @key: 5-tuple key
 *
 * Returns session (existing or new) or NULL on error
 */
struct session *sess_get_or_create(const struct sess_key *key)
{
    struct session *s;

    rcu_read_lock();
    s = sess_lookup(key);
    rcu_read_unlock();

    if (!s)
        s = sess_create(key);

    return s;
}
EXPORT_SYMBOL_GPL(sess_get_or_create);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stargazer Team");
MODULE_DESCRIPTION("Session tracking for NGFW");
MODULE_VERSION("@VERSION@");
