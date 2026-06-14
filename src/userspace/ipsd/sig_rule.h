/* SPDX-License-Identifier: MIT */
/*
 * sig_rule.h - Signature rule (ET OPEN / Snort subset) for stargazer-ipsd.
 *
 * Each rule may have several `content`s. We load ONE "fast pattern" (the
 * longest content → most selective) of each rule into a shared Aho-Corasick
 * automaton for FAST PREFILTERING; when the fast pattern hits, sig_match()
 * VERIFIES the whole rule against the payload (every content, in the correct
 * order, with correct offset/depth/nocase) plus proto/port/flags before
 * concluding. This is exactly how Snort uses an MPM:
 * fast_pattern (prefilter) → full rule evaluation.
 *
 * Supported field subset (enough to load real ET OPEN rules):
 *   header : action proto src sport -> dst dport
 *   option : msg, content (with |hex| and \escape), nocase, offset, depth,
 *            flags, sid, rev.
 *
 * P0 — Fidelity classification instead of "silently ignoring":
 *   Narrowing fields NOT yet supported (pcre, distance, within, byte_test/jump,
 *   isdataat, dsize, urilen, flowbits, http_*) are no longer dropped silently.
 *   When encountered, the rule is CLAMPED to fidelity = SIG_FID_ALERT (ALERT
 *   only, never DROP) because we cannot evaluate the narrowing condition →
 *   avoids false blocks from "a partial match counts as enough". Content-only
 *   rules (every keyword supported) keep SIG_FID_FULL → may DROP. Reputation/
 *   IP-list rules (no content, no selector) are DROPPED (catch-all). Real
 *   coverage is counted in sig_load_stats.
 */
#ifndef SG_SIG_RULE_H
#define SG_SIG_RULE_H

#include <stdint.h>
#include <stddef.h>
#include "ac.h"

#define SIG_MAX_CONTENT 8
#define SIG_CONTENT_MAX 1024   /* max bytes for one content (after decode) */
#define SIG_MSG_MAX     128
#define SIG_MAX_BYTEOP  4      /* P3 — byte_test/byte_jump count per rule */

/* P5 — flowbits */
#define SIG_MAX_FLOWBITS  1024 /* max global flowbit flags                  */
#define SIG_FB_NAME_MAX   64
#define SIG_MAX_FB_RULE   6    /* flowbits operations per rule              */
#define SIG_FB_WORDS      (SIG_MAX_FLOWBITS / 64)   /* = 16 (bitset/flow)   */

enum sig_action { SIG_ALERT = 0, SIG_DROP = 1 };          /* DROP > ALERT */
enum sig_proto  { SIG_PROTO_ANY = 0, SIG_PROTO_TCP, SIG_PROTO_UDP, SIG_PROTO_ICMP };

/* P0 — fidelity: whether a rule may DROP or only ALERT. */
enum sig_fidelity { SIG_FID_FULL = 0, SIG_FID_ALERT = 1 };

/* P6 — flow keyword (filter by direction/state; cheap, uses available data). */
#define SIG_FLOW_ESTABLISHED 0x01   /* require an established connection    */
#define SIG_FLOW_TO_SERVER   0x02   /* client→server direction only        */
#define SIG_FLOW_TO_CLIENT   0x04   /* server→client direction only        */

/* P6 — sticky buffers: content matches on a protocol REGION (not raw payload).
 * http_uri/header/method/body (request to_server), tls.sni (ClientHello). */
enum sig_buf {
	SIG_BUF_RAW = 0,        /* reassembled stream (default)   */
	SIG_BUF_HTTP_METHOD,
	SIG_BUF_HTTP_URI,
	SIG_BUF_HTTP_HEADER,
	SIG_BUF_HTTP_BODY,
	SIG_BUF_TLS_SNI,
	SIG_NBUF
};
struct match_buffers;   /* full definition in proto_buf.h */

/* Bitmask of narrowing keywords NOT yet supported (set in sig_rule.has_unsup
 * for counting/logging). P2 supports distance/within/dsize now → no longer
 * capped (SIG_U_RELATIVE unused; SIG_U_DSIZE only for isdataat/urilen). */
enum sig_unsup {
	SIG_U_PCRE     = 1u << 0,   /* pcre                          */
	SIG_U_BYTEOP   = 1u << 1,   /* byte_test / byte_jump         */
	SIG_U_RELATIVE = 1u << 2,   /* (P2: distance/within supported — unused) */
	SIG_U_DSIZE    = 1u << 3,   /* isdataat / urilen             */
	SIG_U_FLOWBITS = 1u << 4,   /* flowbits                      */
	SIG_U_HTTPBUF  = 1u << 5,   /* http_* sticky buffers         */
};

/* TCP flag bits — MATCH how pkt_forward.ko encodes them (ml->tcp_flags). */
#define SIG_TCP_FIN 0x01
#define SIG_TCP_SYN 0x02
#define SIG_TCP_RST 0x04
#define SIG_TCP_PSH 0x08
#define SIG_TCP_ACK 0x10
#define SIG_TCP_URG 0x20

struct sig_content {
	uint8_t *data;   /* decoded bytes (owned, malloc'd) */
	int      len;
	int      nocase; /* 1 = case-insensitive            */
	int      offset; /* start searching at this byte; -1 = unset (ABSOLUTE) */
	int      depth;  /* search only within `depth` bytes from offset; -1 = unset */
	/* P2 — RELATIVE positioning from the END of the previous content (relative=1 → ignore offset/depth) */
	int      distance; /* offset from end of previous match (may be negative); -1 = unset */
	int      within;   /* match within `within` bytes from end of previous match; -1 = unset */
	uint8_t  relative; /* 1 if content uses distance/within */
	uint8_t  buffer;   /* P6 — enum sig_buf (match region; RAW = default) */
};

/*
 * P3 — byte_test / byte_jump: read binary fields per protocol structure
 * (length/value) — unlocks DNS/SMB/RPC rules. Interleaved with content in
 * order: `after_content` = number of contents parsed BEFORE this op → verify
 * preserves the interleave order. Every N-byte read is BOUNDS-CHECKED first
 * (a classic attack point).
 */
/*
 * P5 — flowbits: multi-packet/multi-rule per-flow state.
 *   isset/isnotset : match CONDITION (check bit before verdict) — REQUIRES the
 *                    flow to be tracked (fb != NULL); not tracked → treated as
 *                    NOT satisfied → no match (fail-safe, avoids false-drop).
 *   set/unset/toggle: side effect AFTER the rule matches.
 *   noalert         : rule only sets a flag, emits no verdict of its own.
 */
enum sig_fb_op { SIG_FB_ISSET = 0, SIG_FB_ISNOTSET, SIG_FB_SET,
		 SIG_FB_UNSET, SIG_FB_TOGGLE };

struct sig_flowbit {
	uint8_t  op;        /* enum sig_fb_op       */
	int16_t  flag_id;   /* index into the ruleset's flag table */
};

/* Per-flow flag bitset (stored in the flow pool in main.c). */
struct flowbit_state { uint64_t bits[SIG_FB_WORDS]; };

enum sig_byteop_kind { SIG_BYTE_TEST = 0, SIG_BYTE_JUMP = 1 };

struct sig_byteop {
	uint8_t  kind;        /* enum sig_byteop_kind                    */
	uint8_t  nbytes;      /* 1..8 — width of the field to read       */
	uint8_t  relative;    /* 1 = offset measured from end of prev match */
	uint8_t  little;      /* 1 = little-endian, 0 = big-endian       */
	uint8_t  negate;      /* byte_test: negate the comparison result */
	char     oper;        /* byte_test: '<' '>' '=' '&' '|'          */
	int32_t  value;       /* byte_test: comparison value             */
	int32_t  offset;      /* read position (from cursor if relative) */
	int32_t  multiplier;  /* byte_jump: multiply the read value (default 1)*/
	int32_t  post_offset; /* byte_jump: add after jumping            */
	int      after_content; /* which content this op follows         */
};

/*
 * Port list: n_dport == 0 means any port; n_dport > 0 means match any port in
 * the list.  Populated from literal ports or from Snort variable expansion
 * (e.g. $HTTP_PORTS → {80,8080,8000,8008}).  Source IP/dest IP variables
 * ($HOME_NET, $EXTERNAL_NET, …) are NOT resolved — they are silently treated
 * as "any"; this is a known MVP limitation noted in the thesis.
 */
#define SIG_DPORT_MAX 8

struct sig_rule {
	uint32_t sid, rev;
	int      action;             /* EFFECTIVE action for the flow's profile
				      * (SIG_ALERT/SIG_DROP); set from the profile
				      * maps, reset to base_action on each reload */
	int      base_action;        /* the rule's own default action (from the table
				      * line) — what `action` falls back to            */
	int      proto;              /* SIG_PROTO_*            */
	uint16_t dport_list[SIG_DPORT_MAX]; /* destination port list */
	uint8_t  n_dport;            /* 0 = any port           */
	uint8_t  flags_set;          /* required TCP flags (0 = ignore) */
	struct sig_content content[SIG_MAX_CONTENT];
	int      n_content;
	int      fast;               /* index of content used as fast pattern; -1 = none */
	int      dsize_min;          /* P2 — dsize: payload length ≥ (>=0), -1 = unset */
	int      dsize_max;          /* P2 — dsize: payload length ≤ (>=0), -1 = unset */
	struct sig_byteop byteop[SIG_MAX_BYTEOP];  /* P3 */
	int      n_byteop;
	struct sig_flowbit flowbits[SIG_MAX_FB_RULE];  /* P5 */
	int      n_fb;
	void    *pcre;               /* P4 — pcre2_code* (NULL if none/!HAVE_PCRE) */
	uint8_t  pcre_relative;      /* P4 — R modifier: match from end of prev content */
	uint8_t  pcre_buffer;        /* P4 — enum sig_buf for pcre (U/H…); RAW default */
	uint8_t  fb_noalert;         /* P5 — only set a flag, no alert       */
	uint8_t  flow_flags;         /* P6 — SIG_FLOW_* (0 = unconstrained)  */
	uint8_t  fidelity;           /* enum sig_fidelity (FULL=may DROP)   */
	uint8_t  has_unsup;          /* bitmask sig_unsup (for counting/log) */
	uint32_t prof_mask;          /* per-policy scoping: bitmask of profiles
				      * containing the rule (bit i = profile id i+1,
				      * set from the per-profile selection maps). 0 =
				      * in no active profile → inert when a flow has a
				      * profile; matches all when prof_id==0 (legacy). */
	uint32_t prof_drop_mask;     /* per-profile ACTION: bit i set = profile id
				      * i+1 wants this rule to DROP; bit clear (with
				      * the prof_mask bit set) = ALERT. Resolved per the
				      * flow's prof_id by sig_eff_action() — so two
				      * profiles can give the same sid different actions. */
	char     msg[SIG_MSG_MAX];
};

/* Effective action for rule r under the flow's profile.
 *   prof_id 0 (IPS off / unmarked flow) → the rule's own base action (legacy,
 *     fail-safe match-all).
 *   prof_id 1..31 → what THAT profile selected: DROP if its prof_drop_mask bit is
 *     set, else ALERT. (Membership is enforced separately in verify_rule; a
 *     non-member rule never reaches here for that flow.) */
static inline int sig_eff_action(const struct sig_rule *r, int prof_id)
{
	if (prof_id < 1 || prof_id > 31)
		return r->action;                  /* legacy / unmarked */
	uint32_t bit = 1u << (prof_id - 1);
	if (!(r->prof_mask & bit))
		return r->action;                  /* not scoped to this profile */
	return (r->prof_drop_mask & bit) ? SIG_DROP : SIG_ALERT;
}

/*
 * The engine ONLY has content-based signatures (L2). Rules without content
 * (only proto/dport/flags) are NO LONGER loaded (the "L1 signature" layer was
 * removed) — they are SKIPPED and counted separately. Flow-level anomalies
 * (SYN-flood/port-scan) are handled by flow_rule_match_builtin (L1-builtin),
 * independently of signatures.
 */
struct sig_ruleset {
	/* L2: payload rules (Aho-Corasick) */
	struct sig_rule    *rules;
	int                 n_rules, cap_rules;
	struct ac_automaton ac;
	int                 built;
	/* sid → rule index, open-addressed hash (built by sig_build). Lets the
	 * per-profile maps resolve a sid back to its rule without scanning. */
	int32_t            *sid_index;     /* size sid_index_cap; -1 = empty slot */
	int                 sid_index_cap; /* power of two */
	/* P5 — global flowbits flag-name table (interned at load time) */
	char    (*fb_names)[SIG_FB_NAME_MAX];
	uint8_t  *fb_ever_set;        /* was the flag ever set/toggled by a rule? */
	int       n_fb_names, cap_fb_names;
};

/* Flow context for the verify step (caller fills from packet/conntrack). */
struct flow_ctx {
	uint8_t  proto;       /* SIG_PROTO_* */
	uint16_t dport;
	uint8_t  tcp_flags;   /* combination of SIG_TCP_* */
	uint8_t  established; /* P6 — bidirectional traffic seen (proxy established) */
	uint8_t  to_server;  /* P6 — 1 = client→server direction, 0 = server→client */
	uint8_t  prof_id;    /* flow's IPS profile id (1..31, from skb mark/NFQA_MARK);
			      * 0 = unknown → apply every rule (fail-safe). */
	const struct flowbit_state *fb;  /* P5 — flow's flag bitset; NULL = not tracked */
	const struct match_buffers *bufs; /* P6 — protocol regions; NULL = RAW only */
};

int  sig_ruleset_init(struct sig_ruleset *rs);

/*
 * Parse + add ONE rule. Return codes (P0):
 *   SIG_LINE_FULL  ( 0) — loaded, fidelity FULL (may DROP).
 *   SIG_LINE_ALERT ( 2) — loaded, CLAMPED to ALERT (has unsupported narrowing keyword).
 *   SIG_LINE_BLANK ( 1) — empty/comment line.
 *   SIG_LINE_SKIP_UNSUP (3) — dropped: content too weak + unsupported keyword remains.
 *   SIG_LINE_SKIP_REP   (4) — dropped: reputation/IP-list/catch-all (matches every flow).
 *   SIG_LINE_ERROR (-1) — syntax error.
 */
#define SIG_LINE_FULL        0
#define SIG_LINE_BLANK       1
#define SIG_LINE_ERROR     (-1)
#define SIG_LINE_ALERT       2
#define SIG_LINE_SKIP_UNSUP  3
#define SIG_LINE_SKIP_REP    4
#define SIG_LINE_SKIP_NOCONTENT 5   /* rule with no content → dropped (L1 signature removed) */
#define SIG_LINE_SKIP_NOSID  6   /* rule with no sid keyword → dropped (malformed/untraceable, causes FP) */

int  sig_parse_line(struct sig_ruleset *rs, const char *line);

/* Statistics for one file load (real coverage — must NOT be hidden, P0). */
struct sig_load_stats {
	int loaded;              /* total loaded = loaded_full + loaded_alert  */
	int skipped;             /* total skipped lines (all reasons)          */
	int errors;              /* syntax-error lines                         */
	int loaded_full;         /* loaded + qualifies → MAY DROP              */
	int loaded_alert;        /* loaded but CLAMPED to ALERT (missing narrowing keyword)*/
	int skipped_unsupported; /* dropped: only unsupported keyword / too weak */
	int skipped_reputation;  /* dropped: reputation/IP-list/catch-all      */
	int skipped_no_content;  /* dropped: rule with no content (L1 signature removed)*/
	int skipped_no_sid;      /* dropped: rule with no sid keyword (malformed/FP)*/
};

/* Load an entire .rules file (supports `#` comments and `\` line continuation).
 * `st` may be NULL. Returns the number of rules loaded, -1 on file open error. */
int  sig_load_file(struct sig_ruleset *rs, const char *path,
		   struct sig_load_stats *st);

/* Build the Aho-Corasick automaton from fast patterns. Call after loading rules. */
int  sig_build(struct sig_ruleset *rs);

/*
 * Apply the per-profile SELECTION maps to a built ruleset, WITHOUT rebuilding
 * the automaton: reset every rule to inert (prof_mask=0, action=base_action),
 * then for each "<profid>.rules" file in prof_dir set the rule's profile bit and
 * (first-profile-wins) effective action by sid. Cheap — call on a scope change
 * (SIGUSR2). Returns 0 on OK, -1 if prof_dir cannot be opened.
 */
int  sig_load_profile_maps(struct sig_ruleset *rs, const char *prof_dir);

/* Match a payload. Returns the index of the highest-priority rule (DROP before
 * ALERT), -1 if no match. Use rs->rules[idx] to read action/msg/sid. */
int  sig_match(const struct sig_ruleset *rs, const uint8_t *payload, size_t len,
	       const struct flow_ctx *fc);

/*
 * FULLY verify one rule (index into rs->rules) against a buffer (e.g. a
 * reassembled TCP stream): proto/dport/flags + every content in order +
 * offset/depth. Used when the streaming AC reports a fast-pattern hit to
 * confirm it on the stream. Returns 1 on match, 0 otherwise (including an
 * out-of-range rule_idx). Does NOT apply fidelity-cap (caller handles it).
 */
int  sig_verify(const struct sig_ruleset *rs, int rule_idx,
		const uint8_t *buf, int len, const struct flow_ctx *fc);

/*
 * P5 — apply the flowbits side effects (set/unset/toggle) of a matched rule to
 * the flow's bitset. Call AFTER the rule has verified as a match. fb may be
 * NULL (not tracked → skip).
 */
void sig_flowbits_apply(const struct sig_rule *r, struct flowbit_state *fb);

void sig_ruleset_free(struct sig_ruleset *rs);

#endif /* SG_SIG_RULE_H */
