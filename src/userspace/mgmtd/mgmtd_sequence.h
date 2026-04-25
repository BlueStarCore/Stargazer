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
 * Check if any entry (excluding exclude_id) has the given sequence.
 * Returns 1 if collision exists, 0 if the slot is free.
 */
int seq_has_collision(const char *type, int seq, const char *exclude_id);

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

#endif /* MGMTD_SEQUENCE_H */
