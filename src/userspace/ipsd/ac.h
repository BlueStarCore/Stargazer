/* SPDX-License-Identifier: MIT */
/*
 * ac.h - Aho-Corasick multi-pattern matcher for stargazer-ipsd.
 *
 * Detects MANY patterns at once in a single payload scan: O(n + Σ|pattern| +
 * #match), INDEPENDENT of the rule count at scan time — this is why this
 * family of algorithms is used by Snort/Suricata for signature payload
 * matching (Aho & Corasick, CACM 1975).
 *
 * Self-written, no dependencies, statically linkable against musl. Uses a
 * SPARSE automaton: each node stores only the trie edges that exist (CSR,
 * sorted by byte) plus a failure link; on a miss the search follows fail links
 * (classic Aho-Corasick). This keeps a node to ~tens of bytes instead of the
 * ~1 KB of a dense 256-way DFA, so the all-rules automaton fits in a few MB.
 * Search stays amortized-linear (total fail-hops <= text length).
 *
 * Binary-safe: every API takes a pointer + length, does not rely on the '\0'
 * terminator.
 */
#ifndef SG_AC_H
#define SG_AC_H

#include <stdint.h>
#include <stddef.h>

#define AC_ALPHABET 256

/* One trie edge: byte c -> child node `to`. Edges of a node are stored
 * contiguously in ac->edges[node.edge_first .. +node.edge_n], sorted by `c`. */
struct ac_edge {
	uint8_t c;
	int32_t to;
};

struct ac_node {
	int32_t fail;        /* failure link — followed at RUNTIME on a goto miss */
	int32_t out;         /* id of pattern ENDING at this node, -1 if none      */
	int32_t out_link;    /* nearest output node along the fail chain, -1 if none */
	int32_t edge_first;  /* index of this node's first edge in ac->edges, -1    */
	int32_t edge_n;      /* number of edges (sorted by byte)                    */
};

struct ac_automaton {
	struct ac_node *nodes;     int32_t n_nodes, cap_nodes;
	struct ac_edge *edges;     int32_t n_edges, cap_edges;  /* CSR, valid after build */
	void           *bscratch;  /* per-node growable edge lists, build-time only   */
	int             nocase;    /* 1 = case-insensitive */
	int             built;     /* is the automaton frozen (CSR) yet?             */
};

/* Initialize an empty automaton (root only). Returns 0 on OK, -1 if out of memory. */
int  ac_init(struct ac_automaton *ac, int nocase);

/*
 * Add a pattern (pat[0..len)) bound to identifier id (>= 0). Must be called
 * BEFORE ac_build(). Returns 0 on OK, -1 on error (already built / bad
 * argument / out of memory). Two patterns with identical content point to the
 * same final node → only the last id is kept (duplicate handling should happen
 * at the rule layer).
 */
int  ac_add_pattern(struct ac_automaton *ac, const uint8_t *pat, int len, int id);

/* Compute failure-links + output-links via BFS, then freeze the edges into the
 * CSR arrays. Returns 0/-1. */
int  ac_build(struct ac_automaton *ac);

/*
 * Scan text[0..len). For each matching pattern, call on_match(id, end_pos,
 * ctx), where end_pos is the (0-based) index of the LAST byte of the pattern
 * in text. on_match returns non-zero to stop early. Returns the total match
 * count (or -1 if not built).
 */
int  ac_search(const struct ac_automaton *ac, const uint8_t *text, size_t len,
	       int (*on_match)(int id, size_t end_pos, void *ctx), void *ctx);

/*
 * STREAMING scan: continue from state *state (0 = root) across multiple feeds
 * WITHOUT rescanning from the start — used for TCP stream reassembly (feed more
 * whenever new contiguous bytes arrive). *state is preserved between calls
 * (in/out).
 *   stream_off : offset (within the STREAM) of text[0] → on_match receives
 *                end_off as the position of the LAST byte of the pattern WITHIN
 *                THE STREAM (needed to verify offset/depth/distance/within).
 * on_match returns non-zero to stop early. Returns the total match count (or -1
 * if not built / state NULL). Aho-Corasick is inherently streaming: the current
 * node is the entire state.
 */
int  ac_search_stream(const struct ac_automaton *ac, int32_t *state,
		      const uint8_t *text, size_t len, uint64_t stream_off,
		      int (*on_match)(int id, uint64_t end_off, void *ctx),
		      void *ctx);

/* Free memory and reset the automaton to the empty state (ac_init can be called again). */
void ac_free(struct ac_automaton *ac);

#endif /* SG_AC_H */
