/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * session.h - Shared session-tracking interface for Stargazer NGFW
 *
 * Copyright (C) 2026 Stargazer Team
 *
 * Used by both session.ko (provider) and pkt_forward.ko (consumer).
 * Direction model follows the FortiOS / Linux conntrack convention:
 * the first packet that creates a session defines the "original"
 * direction; subsequent packets matching the reversed 5-tuple are
 * accounted as "reply".
 */

#ifndef _STARGAZER_SESSION_H
#define _STARGAZER_SESSION_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/rcupdate.h>

struct sk_buff;

/* 5-tuple session key. Packed so memcmp/jhash see no padding. */
struct sess_key {
	__be32	src_ip;
	__be32	dst_ip;
	__be16	src_port;
	__be16	dst_port;
	u8	proto;
} __packed;

/* Direction relative to the session's stored key */
#define SESS_DIR_ORIG	0	/* matches stored 5-tuple as-is */
#define SESS_DIR_REPLY	1	/* matches reversed 5-tuple */

/* Session flag bits */
#define SESS_ACTIVE	0x0001
#define SESS_BLOCKED	0x0002	/* drop further packets (set by ML/policy) */
#define SESS_MARKED	0x0004	/* flagged suspicious, still allowed */

/* Per-direction packet length min/max */
struct sess_pkt_len {
	u32	max;
	u32	min;
};

/* Traffic statistics — split per direction for ML feature extraction */
struct sess_stats {
	u64		pkts_orig;
	u64		pkts_reply;
	u64		bytes_orig;
	u64		bytes_reply;
	ktime_t		first_seen;
	ktime_t		last_seen;
	u64		iat_sum_ns;
	u32		iat_count;
	u16		tcp_flags_orig;
	u16		tcp_flags_reply;
	u32		init_win_orig;
	struct sess_pkt_len	len_orig;
	struct sess_pkt_len	len_reply;
};

/*
 * Session entry.
 *
 * Lifetime: allocated under spin_lock(table_lock), freed via call_rcu().
 * Pointers handed back to callers are valid ONLY inside an RCU read-side
 * critical section. Dereferencing after rcu_read_unlock() is undefined.
 */
struct session {
	struct hlist_node	node;
	struct sess_key		key;
	u32			id;
	u16			flags;
	u8			tcp_state;	/* reserved for Phase 2.6 */
	u8			_rsv;
	u32			policy_id;	/* reserved for Phase 3 */
	struct sess_stats	stats;
	s32			ml_score;	/* fixed-point score × 1000 */
	ktime_t			expires_at;
	spinlock_t		lock;
	struct rcu_head		rcu;
};

/*
 * Public API exported by session.ko.
 *
 * extract_key()           — fill sess_key from an skb (IPv4 + TCP/UDP).
 * sess_lookup()           — RCU-safe lookup; caller must hold rcu_read_lock().
 * sess_lookup_or_create() — same as lookup but creates a new session if no
 *                           match in either direction. Sets *dir_out.
 *                           Caller must hold rcu_read_lock() across both
 *                           the call and any subsequent dereference.
 * sess_update()           — update per-direction stats from a packet.
 * sess_delete()           — remove from table and schedule deferred free.
 */
int extract_key(struct sk_buff *skb, struct sess_key *key);

struct session *sess_lookup(const struct sess_key *key);

struct session *sess_lookup_or_create(const struct sess_key *key,
				      int *dir_out);

void sess_update(struct session *s, struct sk_buff *skb, int dir);

void sess_delete(struct session *s);

#endif /* _STARGAZER_SESSION_H */
