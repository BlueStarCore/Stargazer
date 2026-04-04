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
 * Shift entries with sequence >= new_seq upward by 1.
 * Skips exclude_id.  Processes highest-first to avoid collision.
 * Only called when an actual collision exists.
 * Returns number of entries shifted.
 */
int seq_shift(const char *type, int new_seq, const char *exclude_id);

/*
 * Get highest sequence number for a type.
 * Returns 0 if no entries have a sequence key.
 */
int seq_get_max(const char *type);

#endif /* MGMTD_SEQUENCE_H */
