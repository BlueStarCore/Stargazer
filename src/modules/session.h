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
#include <linux/proc_fs.h>

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

/* TCP connection states — managed by sess_tcp_check() in the forward path */
#define SESS_TCP_NONE         0  /* no packet seen yet */
#define SESS_TCP_SYN_SENT     1  /* SYN from orig, awaiting SYN-ACK */
#define SESS_TCP_SYN_RECV     2  /* SYN-ACK from reply, awaiting final ACK */
#define SESS_TCP_ESTABLISHED  3  /* three-way handshake complete */
#define SESS_TCP_FIN_WAIT     4  /* FIN from orig (active close) */
#define SESS_TCP_CLOSE_WAIT   5  /* FIN from reply (passive close) */
#define SESS_TCP_LAST_ACK     6  /* FIN from orig after CLOSE_WAIT */
#define SESS_TCP_TIME_WAIT    7  /* both FINs exchanged */
#define SESS_TCP_CLOSE        8  /* RST seen or fully closed */
#define SESS_TCP_STATE_MAX    9

/*
 * Per-direction TCP window state — used by sess_tcp_check() to validate
 * RST sequence numbers and detect RST injection attacks.
 */
struct sess_tcp_win {
	u32  ack_seq;   /* last ACK sequence number seen FROM this direction */
	u16  win;       /* last advertised window FROM this direction (unscaled) */
	u8   scale;     /* window scale factor negotiated in SYN/SYN-ACK (0..14) */
	u8   _pad;
};

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
	u8			tcp_state;	/* SESS_TCP_* — see sess_tcp_check() */
	u8			_rsv;
	struct sess_tcp_win	tcp_win[2];	/* [SESS_DIR_ORIG/REPLY] RST validation */
	u32			ifindex_in;	/* ingress interface at session creation */
	u32			ifindex_out;	/* egress interface at session creation */
	u32			policy_id;	/* reserved for Phase 3 */
	struct sess_stats	stats;
	s32			ml_score;	/* fixed-point score × 1000 */
	ktime_t			expires_at;
	spinlock_t		lock;
	struct rcu_head		rcu;
};

/*
 * /proc/stargazer/ directory entry, exported so session_test.ko can place
 * its results in the same directory without re-creating it.
 */
extern struct proc_dir_entry *sg_proc_root;

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

/* Bidirectional lookup only — never creates. Returns NULL if not found. */
struct session *sess_lookup_bidir(const struct sess_key *key, int *dir_out);

struct session *sess_lookup_or_create(const struct sess_key *key,
				      int *dir_out);

/*
 * sess_tcp_check - Validate TCP state and drive the session state machine.
 *
 * Must be called from forward_hook inside rcu_read_lock(), BEFORE sess_update().
 * Returns NF_ACCEPT if the packet is valid for the current session state.
 * Returns NF_DROP for RST injection, SYN injection into ESTABLISHED, and
 * other state-machine violations.
 */
unsigned int sess_tcp_check(struct session *s, struct sk_buff *skb, int dir);

void sess_update(struct session *s, struct sk_buff *skb, int dir);

void sess_delete(struct session *s);

#endif /* _STARGAZER_SESSION_H */
