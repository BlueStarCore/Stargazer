/* SPDX-License-Identifier: MIT */
/*
 * ml_scan.h - hỗ trợ ML per-flow:
 *   1) cache Init_Win_bytes_forward theo flow (bắt ở SYN qua NFQUEUE; conntrack
 *      dump KHÔNG có window này) — feature trọng số CAO của model.
 *   2) ghi điểm các flow đã chấm tại CHECKPOINT ra /run/stargazer-ipsd.scores
 *      (execute diagnose ips scores). Không còn thread polling — ML chấm
 *      inline tại checkpoint min(N,K,T) trong process_packet.
 */
#ifndef SG_ML_SCAN_H
#define SG_ML_SCAN_H

#include <stdint.h>

/* ---- cache Init_Win_bytes_forward ---- */
void    ml_iwin_put(uint8_t proto, uint32_t sip, uint32_t dip,
		    uint16_t sp, uint16_t dp, int32_t win);
int32_t ml_iwin_get(uint8_t proto, uint32_t sip, uint32_t dip,
		    uint16_t sp, uint16_t dp);

/* ---- ghi điểm flow đã chấm (ring RAM → /run) ---- */
void ml_record_score(uint8_t proto, uint32_t sip, uint32_t dip,
		     uint16_t sp, uint16_t dp,
		     uint32_t pkts, uint32_t syn, uint32_t ack,
		     int32_t iwin, double score);
/* Đẩy ring ra /run/stargazer-ipsd.scores (gọi định kỳ từ main loop). */
void ml_scores_flush(void);

#endif /* SG_ML_SCAN_H */
