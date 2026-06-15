/* SPDX-License-Identifier: MIT */
/*
 * ac.c - Aho-Corasick multi-pattern matcher (see ac.h).
 *
 * SPARSE design:
 *   1) ac_add_pattern : build the trie, storing per node only the edges that
 *                       exist (a small sorted list in build-time scratch).
 *   2) ac_build       : BFS to compute failure-links + output-links, then
 *                       FREEZE the per-node edge lists into one CSR array
 *                       (ac->edges), sorted by byte for binary-search lookup.
 *   3) ac_search*     : one step per byte; on a missing edge follow fail links
 *                       (classic Aho-Corasick — no dense DFA, no 256-way table).
 *
 * "A buffer is always checked": every malloc/realloc checks for NULL; search
 * reads exactly len bytes; norm() is applied both on add and on search so
 * nocase stays consistent.
 */
#include "ac.h"

#include <stdlib.h>
#include <string.h>

/* Build-time only: a node's growable, byte-sorted edge list. Freed by ac_build
 * once the edges are flattened into the CSR (ac->edges). */
struct ac_bnode {
	struct ac_edge *e;
	int32_t         n, cap;
};

/* Normalize a character: fold upper→lower when nocase (only A–Z, leaves bytes > 127 / binary untouched). */
static inline uint8_t ac_norm(int nocase, uint8_t c){
	return (nocase && c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
}

/* Allocate a new node (already initialized), return its index. -1 if out of
 * memory. Grows the node array AND the build-scratch edge-list array together. */
static int ac_new_node(struct ac_automaton *ac){
	if (ac->n_nodes == ac->cap_nodes) {
		int32_t ncap = ac->cap_nodes ? ac->cap_nodes * 2 : 256;
		struct ac_node *p = realloc(ac->nodes, (size_t)ncap * sizeof(*p));
		if (!p)
			return -1;
		ac->nodes = p;
		struct ac_bnode *bp = realloc(ac->bscratch,
					      (size_t)ncap * sizeof(struct ac_bnode));
		if (!bp)
			return -1;
		ac->bscratch = bp;
		memset(&((struct ac_bnode *)ac->bscratch)[ac->cap_nodes], 0,
		       (size_t)(ncap - ac->cap_nodes) * sizeof(struct ac_bnode));
		ac->cap_nodes = ncap;
	}
	struct ac_node *n = &ac->nodes[ac->n_nodes];
	n->fail = -1;
	n->out = -1;
	n->out_link = -1;
	n->edge_first = -1;
	n->edge_n = 0;
	/* bscratch[n_nodes] is already zeroed (above or in ac_init's memset). */
	return ac->n_nodes++;
}

int ac_init(struct ac_automaton *ac, int nocase){
	memset(ac, 0, sizeof(*ac));
	ac->nocase = nocase ? 1 : 0;
	return ac_new_node(ac) == 0 ? 0 : -1;   /* node 0 = root */
}

/* Build-time goto: child of node u on byte c, or -1. Binary search (sorted). */
static int32_t bgoto(struct ac_automaton *ac, int32_t u, uint8_t c){
	struct ac_bnode *b = &((struct ac_bnode *)ac->bscratch)[u];
	int lo = 0, hi = b->n - 1;
	while (lo <= hi) {
		int mid = (lo + hi) >> 1;
		if (b->e[mid].c == c) return b->e[mid].to;
		if (b->e[mid].c <  c) lo = mid + 1; else hi = mid - 1;
	}
	return -1;
}

/* Build-time: insert edge u --c--> v keeping the list sorted by byte. 0/-1. */
static int bedge_add(struct ac_automaton *ac, int32_t u, uint8_t c, int32_t v){
	struct ac_bnode *b = &((struct ac_bnode *)ac->bscratch)[u];
	if (b->n == b->cap) {
		int32_t nc = b->cap ? b->cap * 2 : 4;
		struct ac_edge *p = realloc(b->e, (size_t)nc * sizeof(*p));
		if (!p)
			return -1;
		b->e = p;
		b->cap = nc;
	}
	int pos = 0;
	while (pos < b->n && b->e[pos].c < c) pos++;
	memmove(&b->e[pos + 1], &b->e[pos],
		(size_t)(b->n - pos) * sizeof(b->e[0]));
	b->e[pos].c = c;
	b->e[pos].to = v;
	b->n++;
	return 0;
}

int ac_add_pattern(struct ac_automaton *ac, const uint8_t *pat, int len, int id){
	int32_t u = 0;   /* start from root */
	if (ac->built || !pat || len <= 0 || id < 0)
		return -1;
	for (int i = 0; i < len; i++) {
		uint8_t c = ac_norm(ac->nocase, pat[i]);
		int32_t v = bgoto(ac, u, c);
		if (v == -1) {
			v = ac_new_node(ac);          /* may realloc nodes + bscratch */
			if (v < 0) return -1;
			if (bedge_add(ac, u, c, v) != 0) return -1;
		}
		u = v;
	}
	ac->nodes[u].out = id;   /* pattern ends at this node */
	return 0;
}

/* Build-time goto with fail fallback: from s, read c; follow fail links until an
 * edge on c exists, else land on root. Used only while computing fail links. */
static int32_t bgoto_fail(struct ac_automaton *ac, int32_t s, uint8_t c){
	for (;;) {
		int32_t nx = bgoto(ac, s, c);
		if (nx != -1) return nx;
		if (s == 0) return 0;
		s = ac->nodes[s].fail;
	}
}

int ac_build(struct ac_automaton *ac){
	if (ac->built)
		return 0;

	int32_t *queue = malloc((size_t)ac->n_nodes * sizeof(int32_t));
	if (!queue && ac->n_nodes > 0)
		return -1;
	int head = 0, tail = 0;

	/* Depth 1: direct children of the root have fail = root. */
	struct ac_bnode *bscr = (struct ac_bnode *)ac->bscratch;
	for (int i = 0; i < bscr[0].n; i++) {
		int32_t v = bscr[0].e[i].to;
		ac->nodes[v].fail = 0;
		ac->nodes[v].out_link = (ac->nodes[0].out != -1) ? 0
				       : ac->nodes[0].out_link;   /* = -1 (root) */
		queue[tail++] = v;
	}

	/* BFS: fail link of each child = goto(fail(u), c) with fail fallback. */
	while (head < tail) {
		int32_t u = queue[head++];
		int32_t f = ac->nodes[u].fail;
		for (int i = 0; i < bscr[u].n; i++) {
			uint8_t c = bscr[u].e[i].c;
			int32_t v = bscr[u].e[i].to;
			int32_t vf = bgoto_fail(ac, f, c);
			ac->nodes[v].fail = vf;
			ac->nodes[v].out_link =
				(ac->nodes[vf].out != -1) ? vf
							  : ac->nodes[vf].out_link;
			queue[tail++] = v;
		}
	}
	free(queue);

	/* FREEZE: flatten the per-node edge lists into one CSR array. */
	int32_t total = 0;
	for (int32_t u = 0; u < ac->n_nodes; u++)
		total += bscr[u].n;
	struct ac_edge *edges = NULL;
	if (total > 0) {
		edges = malloc((size_t)total * sizeof(*edges));
		if (!edges)
			return -1;
	}
	int32_t off = 0;
	for (int32_t u = 0; u < ac->n_nodes; u++) {
		ac->nodes[u].edge_first = off;
		ac->nodes[u].edge_n = bscr[u].n;
		if (bscr[u].n)
			memcpy(&edges[off], bscr[u].e,
			       (size_t)bscr[u].n * sizeof(*edges));
		off += bscr[u].n;
		free(bscr[u].e);
	}
	free(bscr);
	ac->bscratch = NULL;
	ac->edges = edges;
	ac->n_edges = ac->cap_edges = total;
	ac->built = 1;
	return 0;
}

/* Runtime goto over the CSR edges: child of node s on byte c, or -1. */
static int32_t ac_goto(const struct ac_automaton *ac, int32_t s, uint8_t c){
	const struct ac_node *n = &ac->nodes[s];
	const struct ac_edge *e = &ac->edges[n->edge_first];
	int lo = 0, hi = n->edge_n - 1;
	while (lo <= hi) {
		int mid = (lo + hi) >> 1;
		if (e[mid].c == c) return e[mid].to;
		if (e[mid].c <  c) lo = mid + 1; else hi = mid - 1;
	}
	return -1;
}

int ac_search(const struct ac_automaton *ac, const uint8_t *text, size_t len,
	      int (*on_match)(int, size_t, void *), void *ctx){
	if (!ac->built)
		return -1;
	int32_t st = 0;   /* root */
	int hits = 0;
	for (size_t i = 0; i < len; i++) {
		uint8_t c = ac_norm(ac->nocase, text[i]);
		int32_t nx;
		while ((nx = ac_goto(ac, st, c)) == -1 && st != 0)
			st = ac->nodes[st].fail;
		st = (nx >= 0) ? nx : 0;
		for (int32_t t = st; t != -1; t = ac->nodes[t].out_link)
			if (ac->nodes[t].out != -1) {
				hits++;
				if (on_match && on_match(ac->nodes[t].out, i, ctx))
					return hits;
			}
	}
	return hits;
}

int ac_search_stream(const struct ac_automaton *ac, int32_t *state,
		     const uint8_t *text, size_t len, uint64_t stream_off,
		     int (*on_match)(int, uint64_t, void *), void *ctx)
{
	if (!ac->built || !state)
		return -1;
	int32_t st = (*state >= 0 && *state < ac->n_nodes) ? *state : 0;
	int hits = 0;
	for (size_t i = 0; i < len; i++) {
		uint8_t c = ac_norm(ac->nocase, text[i]);
		int32_t nx;
		while ((nx = ac_goto(ac, st, c)) == -1 && st != 0)
			st = ac->nodes[st].fail;
		st = (nx >= 0) ? nx : 0;
		for (int32_t t = st; t != -1; t = ac->nodes[t].out_link)
			if (ac->nodes[t].out != -1) {
				hits++;
				if (on_match &&
				    on_match(ac->nodes[t].out, stream_off + i, ctx)) {
					*state = st;
					return hits;
				}
			}
	}
	*state = st;
	return hits;
}

void ac_free(struct ac_automaton *ac)
{
	free(ac->nodes);
	free(ac->edges);
	if (ac->bscratch) {   /* build never finished → free per-node lists */
		struct ac_bnode *b = ac->bscratch;
		for (int32_t u = 0; u < ac->n_nodes; u++)
			free(b[u].e);
		free(b);
	}
	memset(ac, 0, sizeof(*ac));
}
