/* SPDX-License-Identifier: MIT */
/*
 * reass.h - Bidirectional TCP stream reassembly + streaming Aho-Corasick feed (P1).
 *
 * Why needed: per-packet matching is evaded by SPLITTING content across 2
 * segments, by packet STUFFING, or by REORDERING. We reassemble the stream by
 * seq, then feed the new CONTIGUOUS BYTES into AC in streaming mode (keeping
 * node state → no re-scan) so a pattern spanning multiple segments is still
 * caught, and offset/depth/distance are computed by position WITHIN THE STREAM
 * (not within the packet).
 *
 * Scope / window: each direction inspects at most K = cap CONTIGUOUS bytes
 * (default REASS_MAX_BYTES). Past K → enough inspected, caller offloads (sets
 * connmark INSPECTED).
 *
 * Anti-attack (MANDATORY — never silently let through):
 *   - Data piling up behind ONE gap that is never filled (> REASS_GAP_LIMIT
 *     bytes) → anomaly → fail-closed (caller blocks the flow). Defends against
 *     the "hold a gap to drain the buffer / evade inspection" trick.
 *   - Overlapping segment with different data: first-wins (the byte that
 *     ARRIVES FIRST wins) — consistent, defends against overwrite tricks to
 *     slip past signatures.
 *   - All seq arithmetic is wrap-safe ((int32_t)(a-b)); bytes outside the
 *     window are clamped.
 *
 * UDP/ICMP have no stream → caller matches the packet payload directly (not via reass).
 */
#ifndef SG_REASS_H
#define SG_REASS_H

#include <stdint.h>
#include <stddef.h>
#include "ac.h"

#define REASS_MAX_BYTES   16384   /* K: inspection window per direction (configurable later) */
#define REASS_GAP_LIMIT    4096   /* data piled behind a gap past this → fail   */

enum reass_dir_id { REASS_TO_SERVER = 0, REASS_TO_CLIENT = 1 };

/* Return values of reass_segment. */
#define REASS_OK          0
#define REASS_FAILCLOSED (-1)     /* over-limit gap / overload → block flow     */

/*
 * Callback when an AC fast-pattern hits on the REASSEMBLED STREAM.
 *   rule_id : pattern id (== rule index in the ruleset).
 *   end_off : offset (within the stream, 0-based) of the LAST byte of the pattern.
 *   dir     : REASS_TO_SERVER / REASS_TO_CLIENT.
 * Return nonzero to stop feeding early (e.g. a DROP verdict already exists).
 */
typedef int (*reass_match_cb)(int rule_id, uint64_t end_off, int dir, void *ctx);

/* One direction of the stream. */
struct reass_dir {
	uint8_t  *buf;        /* linear window [base_seq, base_seq+cap)            */
	uint8_t  *filled;     /* received-byte bitmap ((cap+7)/8 bytes)            */
	uint32_t  cap;        /* = K                                              */
	uint32_t  base_seq;   /* seq corresponding to buf[0]                      */
	uint32_t  next_off;   /* [0,next_off) is CONTIGUOUS (fed up to here)       */
	uint32_t  max_off;    /* highest offset+1 written (to measure gap)        */
	uint32_t  scanned;    /* fed AC up to this offset (== next_off after feed) */
	uint32_t  scan_limit; /* P1 — only feed AC up to this offset (tx budget); =cap by default */
	int32_t   ac_state;   /* streaming DFA node (0 = root)                    */
	uint8_t   have_base;  /* base_seq set from the first segment?             */
};

struct reass_flow {
	const struct ac_automaton *ac;   /* automaton shared across the ruleset    */
	struct reass_dir dir[2];
	uint8_t  failed;                 /* fail-closed (gap/overload)            */
};

/*
 * Initialize a reassembly flow. cap_bytes=0 → use REASS_MAX_BYTES.
 * ac may be NULL (reassemble only, no feed — rarely used). Returns 0 / -1 (out of memory).
 */
int  reass_flow_init(struct reass_flow *rf, const struct ac_automaton *ac,
		     uint32_t cap_bytes);

/*
 * Load one TCP segment of direction `dir`. seq = seq number of the FIRST
 * payload byte. Placed at the correct position, feeds the NEW contiguous part
 * into AC (via cb). Idempotent w.r.t. retransmit/overlap (first-wins). Returns
 * REASS_OK or REASS_FAILCLOSED. Once fail-closed, every subsequent call returns
 * REASS_FAILCLOSED (sticky).
 */
int  reass_segment(struct reass_flow *rf, int dir, uint32_t seq,
		   const uint8_t *data, uint32_t len,
		   reass_match_cb cb, void *ctx);

/*
 * Swap the automaton (ruleset hot-reload): the old node-state is meaningless
 * under the new automaton. Reset ac_state=0 + scanned=0 per direction, then
 * RE-SCAN the reassembled stream [0,next_off) with the new `ac` (catch new
 * patterns over existing bytes). Keep buffer/filled/next_off + the failed flag.
 * cb/ctx receive matches during the re-scan (may be NULL). The caller MUST call
 * this when it detects the ruleset changed, BEFORE feeding new segments
 * (otherwise it derefs the old node index on the new automaton → wrong/UAF).
 */
void reass_flow_rebind(struct reass_flow *rf, const struct ac_automaton *ac,
		       reass_match_cb cb, void *ctx);

/*
 * P1 re-arm — DROP `n` contiguous bytes at the HEAD of direction `dir`'s window
 * (transaction inspected → free it so RAM stays flat even with keep-alive over
 * thousands of requests). Slides buffer + bitmap + base_seq; n is clamped to
 * ≤ next_off. reset_ac=1 → start a NEW transaction: reset node-state + re-scan
 * the remainder with `cb` (content does not match across the transaction
 * boundary — matching Suricata per-transaction semantics).
 */
void reass_consume(struct reass_flow *rf, int dir, uint32_t n, int reset_ac,
		   reass_match_cb cb, void *ctx);

/*
 * P1 intelligent-mode — set the AC feed limit (offset window) for direction
 * `dir`: bytes ≥ limit are NOT inspected (skip body past budget without AC
 * cost). RAISING the limit → immediately feed the buffered part in
 * [scanned, min(next_off,limit)) (so bytes that arrived before the budget
 * decision are still inspected). Reset to cap on a new transaction
 * (reass_consume reset_ac). limit is clamped to ≤ cap.
 */
void reass_set_scan_limit(struct reass_flow *rf, int dir, uint32_t limit,
			  reass_match_cb cb, void *ctx);

/*
 * Pointer to the reassembled stream of direction `dir` + the CONTIGUOUS length
 * (for verifying rules over the stream). *contig_len = next_off. Returns NULL
 * if dir is invalid.
 */
const uint8_t *reass_dir_buf(const struct reass_flow *rf, int dir,
			     uint32_t *contig_len);

/* Total inspected (contiguous) bytes across BOTH directions. Used as the final
 * ML-checkpoint fallback (compare with REASS_MAX_BYTES) and to offload. */
uint32_t reass_inspected_bytes(const struct reass_flow *rf);

void reass_flow_free(struct reass_flow *rf);

#endif /* SG_REASS_H */
