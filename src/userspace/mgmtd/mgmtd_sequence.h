/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_sequence.h — Sequence-based rule ordering for firewall & NAT
 *
 * Sequence numbers determine the kernel chain position for each rule.
 * Policy IDs remain permanent identifiers — sequence is separate.
 *
 * Position computation:
 *   iptables position = count(enabled entries with seq > mine) + base_offset
 *   Higher sequence = higher priority = checked first in iptables.
 *   Gaps in sequence are fine (1, 3, 40 → positions 4, 3, 2 in FORWARD).
 *   Disabled entries don't occupy kernel positions.
 */

#ifndef MGMTD_SEQUENCE_H
#define MGMTD_SEQUENCE_H

#include <stddef.h>

/*
 * Registry: which config types support sequence ordering.
 * NULL-terminated array — add new orderable types here only.
 */
extern const char *SEQ_ORDERABLE_TYPES[];

/*
 * Check if a config type supports sequence ordering.
 * Returns 1 if orderable, 0 otherwise.
 */
int seq_type_is_orderable(const char *type);

/*
 * Auto-assign sequence = max(existing) + 1.
 * Appends "sequence=N\n" to data buffer if no "sequence=" key exists.
 * Returns 0 on success, -1 if buffer too small.
 */
int seq_auto_assign(const char *type, char *data, size_t data_sz);

/*
 * Auto-assign a stable connmark id: cmkid = max(existing) + 1.
 * Appends "cmkid=N\n" to data buffer if no "cmkid=" key exists.
 * Used by firewall_policy so live flows can be stamped with the owning
 * policy and re-evaluated on policy change. Returns 0 / -1 (buffer too small).
 */
int cmkid_auto_assign(const char *type, char *data, size_t data_sz);

/*
 * Rotate sequences in the affected range when moving an entry.
 *
 * Moving UP   (old_seq < new_seq): entries in (old_seq, new_seq] get -1
 * Moving DOWN (old_seq > new_seq): entries in [new_seq, old_seq) get +1
 *
 * No-op when old_seq == new_seq.  Builtin entries are never moved.
 * Processes entries in safe order to avoid intermediate collisions.
 * Returns number of entries rotated.
 */
int seq_rotate(const char *type, int old_seq, int new_seq,
	       const char *exclude_id);

/*
 * Get highest sequence number for a type.
 * Returns 0 if no entries have a sequence key.
 */
int seq_get_max(const char *type);

/*
 * Shift all non-builtin entries with sequence >= target_seq up by 1
 * to make room for a new entry being inserted at target_seq.
 * Skips exclude_id.  Returns number of entries shifted.
 */
int seq_insert_at(const char *type, int target_seq, const char *exclude_id);

#endif /* MGMTD_SEQUENCE_H */
