/* SPDX-License-Identifier: MIT */
/*
 * ml_scan.h - per-flow ML support:
 *   1) per-flow Init_Win_bytes_forward cache (captured at SYN via NFQUEUE; the
 *      conntrack dump does NOT carry this window) — a HIGH-weight model feature.
 *   2) record scored flows at the CHECKPOINT to /run/stargazer-ipsd.scores
 *      (execute diagnose ips scores). No more polling thread — ML scores inline
 *      at the checkpoint min(N,K,T) inside process_packet.
 */
#ifndef SG_ML_SCAN_H
#define SG_ML_SCAN_H

#include <stdint.h>

/* ---- cache Init_Win_bytes_forward ---- */
void    ml_iwin_put(uint8_t proto, uint32_t sip, uint32_t dip,
		    uint16_t sp, uint16_t dp, int32_t win);
int32_t ml_iwin_get(uint8_t proto, uint32_t sip, uint32_t dip,
		    uint16_t sp, uint16_t dp);

/* ---- record scored flows (RAM ring → /run) ---- */
void ml_record_score(uint8_t proto, uint32_t sip, uint32_t dip,
		     uint16_t sp, uint16_t dp,
		     uint32_t pkts, uint32_t syn, uint32_t ack,
		     int32_t iwin, double score);
/* Push the ring to /run/stargazer-ipsd.scores (called periodically from the main loop). */
void ml_scores_flush(void);

#endif /* SG_ML_SCAN_H */
