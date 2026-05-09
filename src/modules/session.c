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
#include <net/genetlink.h>

#include "session.h"
#include "sg_flow.h"

#ifndef SESS_VERSION
#define SESS_VERSION "unknown"
#endif

/* Hash table sizing */
#define SESSION_TABLE_BITS	10		/* 2^10 = 1024 buckets */
#define MAX_SESSIONS		65536

/* Non-TCP idle timeouts */
#define SESS_TIMEOUT_UDP_SEC	180
#define SESS_TIMEOUT_ICMP_SEC	60
#define SESS_TIMEOUT_OTHER_SEC	300

/* Per-state TCP timeouts (seconds) — indexed by SESS_TCP_* constants */
static const u32 tcp_timeouts[SESS_TCP_STATE_MAX] = {
	[SESS_TCP_NONE]        = 120,   /* before handshake completes   */
	[SESS_TCP_SYN_SENT]    = 120,   /* half-open; scanner bait      */
	[SESS_TCP_SYN_RECV]    =  60,   /* SYN-ACK sent, waiting ACK    */
	[SESS_TCP_ESTABLISHED] = 3600,  /* live connection              */
	[SESS_TCP_FIN_WAIT]    = 120,   /* graceful close in progress   */
	[SESS_TCP_CLOSE_WAIT]  =  60,
	[SESS_TCP_LAST_ACK]    =  30,
	[SESS_TCP_TIME_WAIT]   = 120,   /* RFC 793 2MSL                 */
	[SESS_TCP_CLOSE]       =  10,   /* RST — clean up fast          */
	[SESS_TCP_SYN_SENT2]   =  60,   /* simultaneous open            */
};

/* Reaper cadence */
#define SESS_REAPER_INTERVAL_SEC 30

/* Hash table and its writer-side lock */
static DEFINE_HASHTABLE(sess_table, SESSION_TABLE_BITS);
static DEFINE_SPINLOCK(table_lock);

/* Randomized hash seed — initialized at module load from kernel RNG.
 * Prevents hash-bucket collision attacks (hash DoS). */
static u32 sess_hash_rnd;

/* Asymmetric routing mode: allow mid-stream TCP pickup for HA / ECMP paths. */
bool sess_asymmetric_mode = false;
module_param(sess_asymmetric_mode, bool, 0644);
MODULE_PARM_DESC(sess_asymmetric_mode,
		 "Allow mid-stream TCP pickup for asymmetric routing (default: N)");
EXPORT_SYMBOL_GPL(sess_asymmetric_mode);

/* Counters */
static atomic_t   next_id      = ATOMIC_INIT(1);
static atomic64_t sess_created  = ATOMIC64_INIT(0);
static atomic64_t sess_active   = ATOMIC64_INIT(0);
static atomic64_t sess_expired  = ATOMIC64_INIT(0);
static atomic64_t pkts_invalid  = ATOMIC64_INIT(0); /* state machine drops */

/* procfs handles */
struct proc_dir_entry *sg_proc_root;
EXPORT_SYMBOL_GPL(sg_proc_root);
static struct proc_dir_entry *proc_sessions;
static struct proc_dir_entry *proc_session_ctl;

/* Reaper */
static void sess_reaper_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(sess_reaper, sess_reaper_fn);

/* Forward declaration — defined in the genl section, called from lookup/reaper */
static void sess_genl_notify(const struct session *s, enum sg_flow_cmd cmd);

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

static inline u32 sess_timeout_for_proto(u8 proto)
{
	switch (proto) {
	case IPPROTO_TCP:  return tcp_timeouts[SESS_TCP_NONE]; /* pre-handshake baseline */
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

	spin_lock_bh(&table_lock);

	/* Re-check capacity inside the lock — the lockless check above is only
	 * a fast-path hint; another CPU may have filled the table between then
	 * and now. */
	if (atomic64_read(&sess_active) >= MAX_SESSIONS) {
		spin_unlock_bh(&table_lock);
		kfree(fresh);
		pr_warn_ratelimited("session: table full (%d max)\n",
				    MAX_SESSIONS);
		return NULL;
	}

	/* Re-check both directions under the writer lock to handle the race
	 * where another CPU inserted a matching session between our lockless
	 * lookups and this point.  Use non-RCU walker inside the writer lock.
	 */
	hash_for_each_possible(sess_table, s, node, hash) {
		if (sess_key_eq(&s->key, key)) {
			spin_unlock_bh(&table_lock);
			kfree(fresh);
			*dir_out = SESS_DIR_ORIG;
			return s;
		}
	}
	{
		u32 rhash = sess_hash(&rkey);

		hash_for_each_possible(sess_table, s, node, rhash) {
			if (sess_key_eq(&s->key, &rkey)) {
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
	spin_unlock_bh(&table_lock);
	*dir_out = SESS_DIR_ORIG;

	/* Notify subscribers (flowd, ML daemon) that a new session exists.
	 * table_lock is released; fresh is in the hash table and immutable
	 * for key/id fields.  Called from softirq (forward hook) — GFP_ATOMIC. */
	sess_genl_notify(fresh, SG_FLOW_CMD_SESS_NEW);

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
	if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
		return NF_ACCEPT;

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

	if (new_state != s->tcp_state)
		WRITE_ONCE(s->tcp_state, new_state);

	s->expires_at = ktime_add_ns(ktime_get(),
		(u64)tcp_timeouts[new_state] * NSEC_PER_SEC);

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
	spin_lock_bh(&table_lock);
	hash_del_rcu(&s->node);
	spin_unlock_bh(&table_lock);

	atomic64_dec(&sess_active);
	call_rcu(&s->rcu, sess_free_rcu);
}
EXPORT_SYMBOL_GPL(sess_delete);

/*
 * Maximum sessions collected per reaper cycle for out-of-lock genl notification.
 * 64 × 8 bytes = 512 bytes on the stack — within the 1024-byte kernel limit.
 * Sessions beyond this limit are freed immediately (without genl notify).
 */
#define SESS_REAP_BATCH 64

static void sess_reaper_fn(struct work_struct *work)
{
	struct session *s;
	struct hlist_node *tmp;
	struct session *to_notify[SESS_REAP_BATCH];
	int bucket, i;
	int reaped = 0;
	ktime_t now = ktime_get();

	spin_lock_bh(&table_lock);
	hash_for_each_safe(sess_table, bucket, tmp, s, node) {
		if (ktime_compare(now, s->expires_at) >= 0) {
			hash_del_rcu(&s->node);
			atomic64_dec(&sess_active);
			atomic64_inc(&sess_expired);
			if (reaped < SESS_REAP_BATCH)
				to_notify[reaped] = s;
			else
				call_rcu(&s->rcu, sess_free_rcu); /* batch overflow */
			reaped++;
		}
	}
	spin_unlock_bh(&table_lock);

	/*
	 * Send SESS_EXPIRED notifications outside the spinlock.  The sessions
	 * are no longer reachable via the hash table (hash_del_rcu done) but
	 * their memory is still valid — call_rcu has not been called yet.
	 * Concurrent pkt_forward readers that already hold rcu_read_lock may
	 * still be running sess_update; individual u64 field reads on ARM64
	 * are atomic, so the stats snapshot is consistent enough for flow export.
	 */
	for (i = 0; i < min(reaped, SESS_REAP_BATCH); i++) {
		sess_genl_notify(to_notify[i], SG_FLOW_CMD_SESS_EXPIRED);
		call_rcu(&to_notify[i]->rcu, sess_free_rcu);
	}

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

	/* The embedded header is in ORIG direction; the error arrived as REPLY.
	 * sess_lookup_bidir() handles both directions correctly. */
	return sess_lookup_bidir(&key, dir_out);
}
EXPORT_SYMBOL_GPL(sess_icmp_error_lookup);

/* ---------------------------------------------------------------------- */
/* Generic Netlink family — flow event export and ML verdict receive      */
/* ---------------------------------------------------------------------- */

/*
 * Attribute policy — only incoming command attributes need validation.
 * SESS_BLOCK takes SESS_ID; SESS_SCORE takes SESS_ID + ML_SCORE.
 * Outgoing event attributes (stats, IPs, ports) are not validated here.
 */
static const struct nla_policy sg_flow_attr_policy[__SG_FLOW_ATTR_MAX] = {
	[SG_FLOW_ATTR_SESS_ID]  = { .type = NLA_U32 },
	[SG_FLOW_ATTR_ML_SCORE] = { .type = NLA_S32 },
};

static int sg_flow_cmd_block(struct sk_buff *skb, struct genl_info *info)
{
	struct session *s;
	u32 sess_id;
	int bucket;
	bool found = false;

	if (!info->attrs[SG_FLOW_ATTR_SESS_ID])
		return -EINVAL;

	sess_id = nla_get_u32(info->attrs[SG_FLOW_ATTR_SESS_ID]);

	rcu_read_lock();
	hash_for_each_rcu(sess_table, bucket, s, node) {
		if (s->id == sess_id) {
			/* Use per-session spinlock so the OR is atomic with respect
			 * to other flag writers (ML daemon, reaper). */
			spin_lock_bh(&s->lock);
			s->flags |= SESS_BLOCKED;
			spin_unlock_bh(&s->lock);
			found = true;
			break;
		}
	}
	rcu_read_unlock();

	return found ? 0 : -ENOENT;
}

static int sg_flow_cmd_score(struct sk_buff *skb, struct genl_info *info)
{
	struct session *s;
	u32 sess_id;
	s32 score;
	int bucket;
	bool found = false;

	if (!info->attrs[SG_FLOW_ATTR_SESS_ID] ||
	    !info->attrs[SG_FLOW_ATTR_ML_SCORE])
		return -EINVAL;

	sess_id = nla_get_u32(info->attrs[SG_FLOW_ATTR_SESS_ID]);
	score   = nla_get_s32(info->attrs[SG_FLOW_ATTR_ML_SCORE]);

	rcu_read_lock();
	hash_for_each_rcu(sess_table, bucket, s, node) {
		if (s->id == sess_id) {
			WRITE_ONCE(s->ml_score, score);
			found = true;
			break;
		}
	}
	rcu_read_unlock();

	return found ? 0 : -ENOENT;
}

static const struct genl_ops sg_flow_ops[] = {
	{
		.cmd   = SG_FLOW_CMD_SESS_BLOCK,
		.doit  = sg_flow_cmd_block,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd   = SG_FLOW_CMD_SESS_SCORE,
		.doit  = sg_flow_cmd_score,
		.flags = GENL_ADMIN_PERM,
	},
};

static const struct genl_multicast_group sg_flow_mcgrps[] = {
	{ .name = SG_FLOW_MCGRP_NAME },
};

static struct genl_family sg_flow_family __ro_after_init = {
	.name     = SG_FLOW_GENL_NAME,
	.version  = SG_FLOW_GENL_VERSION,
	.maxattr  = SG_FLOW_ATTR_MAX,
	.policy   = sg_flow_attr_policy,
	.ops      = sg_flow_ops,
	.n_ops    = ARRAY_SIZE(sg_flow_ops),
	.mcgrps   = sg_flow_mcgrps,
	.n_mcgrps = ARRAY_SIZE(sg_flow_mcgrps),
	.module   = THIS_MODULE,
};

/*
 * sess_genl_notify - Multicast a session event to all subscribers.
 *
 * For SESS_NEW: only the 5-tuple and ID are sent (stats are zero at create).
 * For SESS_EXPIRED: full stats snapshot is included.
 *
 * Called from softirq context (SESS_NEW via forward hook) and from workqueue
 * context (SESS_EXPIRED via reaper).  GFP_ATOMIC throughout.
 *
 * IP addresses and ports are sent in network byte order (raw copy from
 * sess_key).  Counters are sent in host byte order via nla_put_u64_64bit /
 * nla_put_u32.
 */
static void sess_genl_notify(const struct session *s, enum sg_flow_cmd cmd)
{
	struct sk_buff *skb;
	void *hdr;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!skb)
		return;

	hdr = genlmsg_put(skb, 0, 0, &sg_flow_family, 0, cmd);
	if (!hdr)
		goto free_skb;

	/* 5-tuple and session ID — immutable after creation, no lock needed */
	if (nla_put_u32(skb,  SG_FLOW_ATTR_SESS_ID,   s->id)           ||
	    nla_put_u8(skb,   SG_FLOW_ATTR_PROTO,      s->key.proto)    ||
	    nla_put_be32(skb, SG_FLOW_ATTR_SRC_IP,     s->key.src_ip)   ||
	    nla_put_be32(skb, SG_FLOW_ATTR_DST_IP,     s->key.dst_ip)   ||
	    nla_put_be16(skb, SG_FLOW_ATTR_SRC_PORT,   s->key.src_port) ||
	    nla_put_be16(skb, SG_FLOW_ATTR_DST_PORT,   s->key.dst_port))
		goto cancel;

	if (cmd == SG_FLOW_CMD_SESS_EXPIRED) {
		/*
		 * Stats snapshot without s->lock.  On ARM64 individual u64 reads
		 * are atomic; we may see a mix of pre/post last-packet values
		 * across fields, which is acceptable for flow export purposes.
		 */
		if (nla_put_u64_64bit(skb, SG_FLOW_ATTR_PKTS_ORIG,
				      s->stats.pkts_orig,    SG_FLOW_ATTR_UNSPEC) ||
		    nla_put_u64_64bit(skb, SG_FLOW_ATTR_PKTS_REPLY,
				      s->stats.pkts_reply,   SG_FLOW_ATTR_UNSPEC) ||
		    nla_put_u64_64bit(skb, SG_FLOW_ATTR_BYTES_ORIG,
				      s->stats.bytes_orig,   SG_FLOW_ATTR_UNSPEC) ||
		    nla_put_u64_64bit(skb, SG_FLOW_ATTR_BYTES_REPLY,
				      s->stats.bytes_reply,  SG_FLOW_ATTR_UNSPEC) ||
		    nla_put_u64_64bit(skb, SG_FLOW_ATTR_IAT_SUM_NS,
				      s->stats.iat_sum_ns,   SG_FLOW_ATTR_UNSPEC) ||
		    nla_put_u32(skb, SG_FLOW_ATTR_IAT_COUNT,
				s->stats.iat_count)                               ||
		    nla_put_u16(skb, SG_FLOW_ATTR_TCP_FLAGS_O,
				s->stats.tcp_flags_orig)                          ||
		    nla_put_u16(skb, SG_FLOW_ATTR_TCP_FLAGS_R,
				s->stats.tcp_flags_reply)                         ||
		    nla_put_u64_64bit(skb, SG_FLOW_ATTR_FIRST_SEEN_NS,
				      (u64)ktime_to_ns(s->stats.first_seen),
				      SG_FLOW_ATTR_UNSPEC)                        ||
		    nla_put_u64_64bit(skb, SG_FLOW_ATTR_LAST_SEEN_NS,
				      (u64)ktime_to_ns(s->stats.last_seen),
				      SG_FLOW_ATTR_UNSPEC)                        ||
		    nla_put_u8(skb,  SG_FLOW_ATTR_TCP_STATE,
			       READ_ONCE(s->tcp_state))                       ||
		    nla_put_s32(skb, SG_FLOW_ATTR_ML_SCORE,
				READ_ONCE(s->ml_score))                           ||
		    nla_put_u32(skb, SG_FLOW_ATTR_IFINDEX_IN,
				READ_ONCE(s->ifindex_in))                         ||
		    nla_put_u32(skb, SG_FLOW_ATTR_IFINDEX_OUT,
				READ_ONCE(s->ifindex_out))                        ||
		    nla_put_u32(skb, SG_FLOW_ATTR_LEN_ORIG_MIN,
				s->stats.len_orig.min)                            ||
		    nla_put_u32(skb, SG_FLOW_ATTR_LEN_ORIG_MAX,
				s->stats.len_orig.max)                            ||
		    nla_put_u32(skb, SG_FLOW_ATTR_LEN_REPLY_MIN,
				s->stats.len_reply.min)                           ||
		    nla_put_u32(skb, SG_FLOW_ATTR_LEN_REPLY_MAX,
				s->stats.len_reply.max))
			goto cancel;
	}

	genlmsg_end(skb, hdr);
	genlmsg_multicast_allns(&sg_flow_family, skb, 0, 0);
	return;

cancel:
	genlmsg_cancel(skb, hdr);
free_skb:
	nlmsg_free(skb);
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
			"# Stargazer sessions  active=%lld created=%lld expired=%lld invalid=%lld\n",
			atomic64_read(&sess_active),
			atomic64_read(&sess_created),
			atomic64_read(&sess_expired),
			atomic64_read(&pkts_invalid));
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

	schedule_delayed_work(&sess_reaper, SESS_REAPER_INTERVAL_SEC * HZ);

	int ret = genl_register_family(&sg_flow_family);
	if (ret < 0) {
		pr_err("session: genl_register_family failed (%d)\n", ret);
		cancel_delayed_work_sync(&sess_reaper);
		proc_remove(proc_session_ctl);
		proc_remove(proc_sessions);
		proc_remove(sg_proc_root);
		sg_proc_root = NULL;
		return ret;
	}

	pr_info("session: loaded (v%s, %d buckets, reaper=%ds, genl=%s)\n",
		SESS_VERSION, 1 << SESSION_TABLE_BITS,
		SESS_REAPER_INTERVAL_SEC, SG_FLOW_GENL_NAME);
	return 0;
}

static void __exit session_exit(void)
{
	/* Unregister genl first — no more notifications after this point */
	genl_unregister_family(&sg_flow_family);

	cancel_delayed_work_sync(&sess_reaper);

	if (proc_session_ctl)
		proc_remove(proc_session_ctl);
	if (proc_sessions)
		proc_remove(proc_sessions);
	if (sg_proc_root)
		proc_remove(sg_proc_root);

	sess_flush_all();
	rcu_barrier(); /* wait for all call_rcu() frees before module memory unloads */

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
