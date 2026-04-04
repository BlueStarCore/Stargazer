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
 */

#include "mgmtd_sequence.h"
#include "mgmtd_apply.h"
#include "sg_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── seq_get_max ─────────────────────────────────────────────────────────── */

int seq_get_max(const char *type)
{
	char *list = sg_db_list(type);
	if (!list)
		return 0;

	int max_seq = 0;
	char *saveptr = NULL;

	for (char *tok = strtok_r(list, "\n", &saveptr);
	     tok;
	     tok = strtok_r(NULL, "\n", &saveptr)) {
		char *seq_str = sg_db_get_val(type, tok, "sequence");
		if (seq_str) {
			int seq = atoi(seq_str);
			if (seq > max_seq)
				max_seq = seq;
			free(seq_str);
		}
	}

	free(list);
	return max_seq;
}

/* ── seq_auto_assign ─────────────────────────────────────────────────────── */

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

/* ── seq_has_collision ───────────────────────────────────────────────────── */

int seq_has_collision(const char *type, int seq, const char *exclude_id)
{
	char *list = sg_db_list(type);
	if (!list)
		return 0;

	int found = 0;
	char *saveptr = NULL;

	for (char *tok = strtok_r(list, "\n", &saveptr);
	     tok;
	     tok = strtok_r(NULL, "\n", &saveptr)) {
		if (exclude_id && strcmp(tok, exclude_id) == 0)
			continue;

		char *seq_str = sg_db_get_val(type, tok, "sequence");
		if (seq_str) {
			if (atoi(seq_str) == seq)
				found = 1;
			free(seq_str);
		}
		if (found)
			break;
	}

	free(list);
	return found;
}

/* ── seq_shift ───────────────────────────────────────────────────────────── *
 *
 * When a new entry takes a sequence already occupied, shift the
 * existing entry (and everything above it) UP by +1.
 *
 * Higher sequence = higher priority = checked first.
 * Shifting up = promoting existing entries, so the NEW entry
 * (which keeps the original sequence) has lower priority than
 * the entries that were already there.
 *
 * Builtin entries are never shifted (pinned in place).
 *
 * Process highest-first so each +1 doesn't collide with the next.
 * Example: existing 3, 4, 5.  New entry takes seq=4.
 *   Shift 5→6, then 4→5.
 *   Result: 3, 5, 6.  Gap at 4 is now free for the new entry.
 *   New entry at 4 has lower priority than old-4 (now 5).
 */

/* Helper: collect (id, sequence) pairs for sorting */
struct seq_entry {
	char  id[64];
	int   seq;
};

static int seq_entry_cmp_desc(const void *a, const void *b)
{
	const struct seq_entry *ea = a;
	const struct seq_entry *eb = b;
	return eb->seq - ea->seq;	/* descending */
}

int seq_shift(const char *type, int new_seq, const char *exclude_id)
{
	char *list = sg_db_list(type);
	if (!list)
		return 0;

	/* Collect entries with sequence >= new_seq (dynamic array) */
	size_t cap = 64;
	struct seq_entry *entries = malloc(cap * sizeof(*entries));
	if (!entries) { free(list); return 0; }
	int nentries = 0;
	char *saveptr = NULL;

	for (char *tok = strtok_r(list, "\n", &saveptr);
	     tok;
	     tok = strtok_r(NULL, "\n", &saveptr)) {
		if (exclude_id && strcmp(tok, exclude_id) == 0)
			continue;

		/* Never shift builtin entries — they are pinned */
		char *bi = sg_db_get_val(type, tok, "builtin");
		if (bi && strcmp(bi, "yes") == 0) {
			free(bi);
			continue;
		}
		free(bi);

		char *seq_str = sg_db_get_val(type, tok, "sequence");
		if (!seq_str)
			continue;

		int seq = atoi(seq_str);
		free(seq_str);

		if (seq >= new_seq) {
			if ((size_t)nentries >= cap) {
				cap *= 2;
				struct seq_entry *nb = realloc(
					entries, cap * sizeof(*entries));
				if (!nb) break;
				entries = nb;
			}
			snprintf(entries[nentries].id,
				 sizeof(entries[nentries].id), "%s", tok);
			entries[nentries].seq = seq;
			nentries++;
		}
	}

	free(list);

	if (nentries == 0) {
		free(entries);
		return 0;
	}

	/* Sort descending — shift highest first so each +1 doesn't
	 * collide with the entry above it. */
	qsort(entries, (size_t)nentries, sizeof(entries[0]),
	      seq_entry_cmp_desc);

	int shifted = 0;
	for (int i = 0; i < nentries; i++) {
		char new_val[16];
		snprintf(new_val, sizeof(new_val), "%d", entries[i].seq + 1);
		if (sg_db_set_val(type, entries[i].id, "sequence",
				  new_val) == 0)
			shifted++;
	}

	free(entries);
	return shifted;
}
