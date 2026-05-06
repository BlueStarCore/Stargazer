/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * sg_flow.h - Generic Netlink family definitions for Stargazer flow export
 *
 * Copyright (C) 2026 Stargazer Team
 *
 * Shared between kernel (session.ko) and userspace (sg-flowd, sg-mld).
 * session.ko registers the "sg_flow" genl family and multicasts two events:
 *
 *   SESS_NEW     — emitted when a session is created (5-tuple + ID only)
 *   SESS_EXPIRED — emitted when the reaper expires a session (full stats)
 *
 * Userspace daemons subscribe to the "sg_flow_events" multicast group and
 * receive these events.  They may also send two commands back to the kernel:
 *
 *   SESS_BLOCK — set SESS_BLOCKED on the named session (pkt_forward drops it)
 *   SESS_SCORE — write ml_score on the named session (Phase 4 ML daemon)
 *
 * All IP addresses and ports in SESS_NEW / SESS_EXPIRED attributes are in
 * network byte order (as stored in sess_key).  All counters are host byte
 * order (as stored in sess_stats).
 */

#ifndef _SG_FLOW_H
#define _SG_FLOW_H

#define SG_FLOW_GENL_NAME    "sg_flow"
#define SG_FLOW_GENL_VERSION  1
#define SG_FLOW_MCGRP_NAME   "sg_flow_events"

enum sg_flow_cmd {
	SG_FLOW_CMD_UNSPEC,
	SG_FLOW_CMD_SESS_NEW,		/* kernel → userspace: session created   */
	SG_FLOW_CMD_SESS_EXPIRED,	/* kernel → userspace: session expired   */
	SG_FLOW_CMD_SESS_BLOCK,		/* userspace → kernel: set SESS_BLOCKED  */
	SG_FLOW_CMD_SESS_SCORE,		/* userspace → kernel: write ml_score    */
	__SG_FLOW_CMD_MAX,
};
#define SG_FLOW_CMD_MAX (__SG_FLOW_CMD_MAX - 1)

enum sg_flow_attr {
	SG_FLOW_ATTR_UNSPEC,
	SG_FLOW_ATTR_SESS_ID,		/* u32  — unique session ID              */
	SG_FLOW_ATTR_PROTO,		/* u8   — IP protocol                    */
	SG_FLOW_ATTR_SRC_IP,		/* be32 — source IPv4 (network byte ord) */
	SG_FLOW_ATTR_DST_IP,		/* be32 — dest IPv4   (network byte ord) */
	SG_FLOW_ATTR_SRC_PORT,		/* be16 — source port (network byte ord) */
	SG_FLOW_ATTR_DST_PORT,		/* be16 — dest port   (network byte ord) */
	SG_FLOW_ATTR_PKTS_ORIG,		/* u64  — packets, orig direction         */
	SG_FLOW_ATTR_PKTS_REPLY,	/* u64  — packets, reply direction        */
	SG_FLOW_ATTR_BYTES_ORIG,	/* u64  — bytes, orig direction           */
	SG_FLOW_ATTR_BYTES_REPLY,	/* u64  — bytes, reply direction          */
	SG_FLOW_ATTR_IAT_SUM_NS,	/* u64  — sum of inter-arrival times (ns) */
	SG_FLOW_ATTR_IAT_COUNT,		/* u32  — IAT sample count               */
	SG_FLOW_ATTR_TCP_FLAGS_O,	/* u16  — OR of all TCP flags, orig      */
	SG_FLOW_ATTR_TCP_FLAGS_R,	/* u16  — OR of all TCP flags, reply     */
	SG_FLOW_ATTR_FIRST_SEEN_NS,	/* u64  — ktime of first packet (ns)     */
	SG_FLOW_ATTR_LAST_SEEN_NS,	/* u64  — ktime of last packet (ns)      */
	SG_FLOW_ATTR_TCP_STATE,		/* u8   — SESS_TCP_* final state         */
	SG_FLOW_ATTR_ML_SCORE,		/* s32  — ML score × 1000                */
	SG_FLOW_ATTR_IFINDEX_IN,	/* u32  — ingress interface index        */
	SG_FLOW_ATTR_IFINDEX_OUT,	/* u32  — egress interface index         */
	SG_FLOW_ATTR_LEN_ORIG_MIN,	/* u32  — min packet length, orig        */
	SG_FLOW_ATTR_LEN_ORIG_MAX,	/* u32  — max packet length, orig        */
	SG_FLOW_ATTR_LEN_REPLY_MIN,	/* u32  — min packet length, reply       */
	SG_FLOW_ATTR_LEN_REPLY_MAX,	/* u32  — max packet length, reply       */
	__SG_FLOW_ATTR_MAX,
};
#define SG_FLOW_ATTR_MAX (__SG_FLOW_ATTR_MAX - 1)

#endif /* _SG_FLOW_H */
