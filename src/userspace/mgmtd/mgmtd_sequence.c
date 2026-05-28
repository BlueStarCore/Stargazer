/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_sequence.c — Sequence-based rule ordering for firewall & NAT
 *
 * Maps sequence numbers to iptables chain positions.
 *
 * Key insight: sequence number != iptables position.
 * Higher sequence = higher priority = checked first in iptables.
 * Sequences can have gaps (1, 3, 40) and disabled entries don't
 * occupy kernel positions.  Position is computed by counting enabled
 * entries with a HIGHER sequence number (they go before us).
 *
 * For NAT, SNAT and DNAT go to different chains (POSTROUTING vs
 * PREROUTING), so the filter_key/filter_val parameters let callers
 * count only entries of the same nat type.
 *
 * Example (firewall_policy, base_offset=2):
 *   seq=40 enable  → kernel pos 2 (0 above + 2) — checked first
 *   seq=3  enable  → kernel pos 3 (1 above + 2)
 *   seq=2  disable → not in kernel
 *   seq=1  enable  → kernel pos 4 (2 above + 2) — checked last
 *
 * Rotation algorithm (replaces old seq_shift inflate approach):
 *   When moving entry from old_seq to new_seq, entries in the
 *   affected range rotate by ±1.  Total sequence set stays bounded.
 */

#include "mgmtd_sequence.h"
#include "mgmtd_apply.h"
#include "sg_db.h"
#include "sg_validate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Orderable type registry ────────────────────────────────────────── */

const char *SEQ_ORDERABLE_TYPES[] = {
	"firewall_policy",
	"network_nat",
	/* Add new orderable types here — all seq_* functions and
	 * stargazer-mgmtd.c checks use this array automatically. */
	NULL
};

int seq_type_is_orderable(const char *type)
{
	if (!type) return 0;
	for (int i = 0; SEQ_ORDERABLE_TYPES[i]; i++) {
		if (strcmp(type, SEQ_ORDERABLE_TYPES[i]) == 0)
			return 1;
	}
	return 0;
}

/* ── seq_get_max ────────────────────────────────────────────────────── */

int seq_get_max(const char *type)
{
	/* Single SQL query instead of N sg_db_get_val() calls */
	char *max_str = sg_db_get_max_int(type, "sequence");
	int result = max_str ? atoi(max_str) : 0;
	free(max_str);
	return result;
}

/* ── seq_auto_assign ────────────────────────────────────────────────── */

int seq_auto_assign(const char *type, char *data, size_t data_sz)
{
	/* Already has a sequence? Don't overwrite. */
	if (sg_kv_has_key(data, "sequence"))
		return 0;

	int next = seq_get_max(type) + 1;

	char suffix[32];
	int slen = snprintf(suffix, sizeof(suffix), "sequence=%d\n", next);

	size_t cur_len = strlen(data);
	if (cur_len + (size_t)slen + 1 > data_sz)
		return -1;

	memcpy(data + cur_len, suffix, (size_t)slen + 1);
	return 0;
}

/* seq_compute_position — REMOVED.
 * No longer needed with atomic iptables-restore rebuild.
 * Rule ordering is now implicit in the generated ruleset
 * (sg_db_list_ordered returns entries in sequence DESC order,
 * and rebuild appends them with -A in that order). */

/* ── Internal helpers ───────────────────────────────────────────────── */

struct seq_entry {
	char  id[64];
	int   seq;
};

static int seq_cmp_asc(const void *a, const void *b)
{
	return ((const struct seq_entry *)a)->seq -
	       ((const struct seq_entry *)b)->seq;
}

static int seq_cmp_desc(const void *a, const void *b)
{
	return ((const struct seq_entry *)b)->seq -
	       ((const struct seq_entry *)a)->seq;
}

/*
 * Collect non-builtin entries whose sequence falls in [lo, hi].
 * Skips exclude_id.  Caller must free(*out) when done — even if
 * the returned count is 0, *out may still be a valid allocation.
 *
 * Returns: number of entries collected (>= 0), or -1 on malloc failure.
 */
static int collect_seq_range(const char *type, int lo, int hi,
			     const char *exclude_id,
			     struct seq_entry **out)
{
	*out = NULL;

	char *list = sg_db_list(type);
	if (!list)
		return 0;

	size_t cap = 32;
	struct seq_entry *entries = malloc(cap * sizeof(*entries));
	if (!entries) {
		free(list);
		return -1;
	}

	int n = 0;
	char *saveptr = NULL;

	for (char *tok = strtok_r(list, "\n", &saveptr);
	     tok;
	     tok = strtok_r(NULL, "\n", &saveptr)) {
		if (exclude_id && strcmp(tok, exclude_id) == 0)
			continue;

		/* Builtin entries are pinned — never rotate them */
		char *bi = sg_db_get_val(type, tok, "builtin");
		int is_builtin = (bi && strcmp(bi, "yes") == 0);
		free(bi);
		if (is_builtin)
			continue;

		char *seq_str = sg_db_get_val(type, tok, "sequence");
		if (!seq_str)
			continue;

		int seq = atoi(seq_str);
		free(seq_str);

		if (seq >= lo && seq <= hi) {
			if ((size_t)n >= cap) {
				cap *= 2;
				struct seq_entry *nb = realloc(
					entries, cap * sizeof(*entries));
				if (!nb) {
					/* Alloc failure: abort rather than
					 * rotate an incomplete set */
					free(entries);
					free(list);
					*out = NULL;
					return -1;
				}
				entries = nb;
			}
			snprintf(entries[n].id,
				 sizeof(entries[n].id), "%s", tok);
			entries[n].seq = seq;
			n++;
		}
	}

	free(list);
	*out = entries;
	return n;
}


/* ── seq_rotate ─────────────────────────────────────────────────────── *
 *
 * When an entry moves from old_seq to new_seq, the entries in between
 * rotate to fill the gap.  No sequence inflation — the set of
 * sequence values remains the same, just reassigned.
 *
 * Move UP (old_seq < new_seq, higher priority):
 *   Entries in (old_seq, new_seq] each shift -1
 *   Source entry takes new_seq.
 *
 *   Example: A=1, B=2, C=3.  Move A → seq=3:
 *     B(2) → 1, C(3) → 2, A → 3.  Result: B=1, C=2, A=3.
 *
 * Move DOWN (old_seq > new_seq, lower priority):
 *   Entries in [new_seq, old_seq) each shift +1
 *   Source entry takes new_seq.
 *
 *   Example: A=1, B=2, C=3.  Move C → seq=1:
 *     A(1) → 2, B(2) → 3, C → 1.  Result: C=1, A=2, B=3.
 *
 * Sort order matters to avoid intermediate collisions:
 *   delta=-1: process ascending  (lowest first, each frees slot for next)
 *   delta=+1: process descending (highest first, each frees slot for next)
 */
int seq_rotate(const char *type, int old_seq, int new_seq,
	       const char *exclude_id)
{
	if (old_seq == new_seq)
		return 0;

	int moving_up = (new_seq > old_seq);
	int lo, hi, delta;

	if (moving_up) {
		lo = old_seq + 1;
		hi = new_seq;
		delta = -1;
	} else {
		lo = new_seq;
		hi = old_seq - 1;
		delta = +1;
	}

	struct seq_entry *entries = NULL;
	int n = collect_seq_range(type, lo, hi, exclude_id, &entries);

	if (n <= 0) {
		free(entries);
		return 0;
	}

	qsort(entries, (size_t)n, sizeof(entries[0]),
	      moving_up ? seq_cmp_asc : seq_cmp_desc);

	int rotated = 0;
	for (int i = 0; i < n; i++) {
		char val[16];
		snprintf(val, sizeof(val), "%d", entries[i].seq + delta);
		if (sg_db_set_val(type, entries[i].id, "sequence", val) == 0)
			rotated++;
	}

	free(entries);
	return rotated;
}

/* ── seq_insert_at ──────────────────────────────────────────────────── */

int seq_insert_at(const char *type, int target_seq, const char *exclude_id)
{
	struct seq_entry *entries = NULL;
	int n = collect_seq_range(type, target_seq, 9999, exclude_id, &entries);

	if (n <= 0) {
		free(entries);
		return 0;
	}

	/* Shift highest first to avoid intermediate collisions */
	qsort(entries, (size_t)n, sizeof(entries[0]), seq_cmp_desc);

	int shifted = 0;
	for (int i = 0; i < n; i++) {
		char val[16];
		snprintf(val, sizeof(val), "%d", entries[i].seq + 1);
		if (sg_db_set_val(type, entries[i].id, "sequence", val) == 0)
			shifted++;
	}

	free(entries);
	return shifted;
}
