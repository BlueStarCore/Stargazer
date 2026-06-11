/* SPDX-License-Identifier: MIT */
/*
 * http_tx.h - Máy trạng thái transaction HTTP request cho re-arm (P1).
 *
 * Vận hành trên dòng to_server đã ghép (reass). Mỗi transaction: parse request
 * line + header → đọc Content-Length → soi tới `tx_budget` byte → BỎ phần thân
 * còn lại (skip) → consume (trượt cửa sổ) → re-arm transaction kế. Nhờ vậy:
 *   - SOI MỌI transaction keep-alive (exploit ở request #N vẫn bắt) — KHÔNG cap
 *     số transaction tích lũy (lỗ hổng đã research, không firewall nào làm).
 *   - RAM phẳng: transaction xong → free ngay (trượt cửa sổ).
 *   - `live_tx` = số tx pipelined ĐỒNG THỜI chưa xong; vượt MAX_LIVE_TX → anomaly
 *     (KHÔNG thả fast-path) — chống DoS pipelining.
 * Tín hiệu ra mỗi step: want_watch (giữ IPS_WATCH), want_inspected (thả khi
 * Connection: close / non-HTTP / hết), anomaly (fail-closed).
 */
#ifndef SG_HTTP_TX_H
#define SG_HTTP_TX_H

#include <stdint.h>
#include "reass.h"

#define HTTP_MAX_HEADER   8192   /* header lớn hơn → anomaly (header flood)   */
#define HTTP_MAX_LIVE_TX  256    /* tx pipelined đồng thời tối đa (DoS guard) */

enum http_proto { HTX_UNKNOWN = 0, HTX_HTTP, HTX_NONHTTP };

struct http_tx {
	int      proto;        /* enum http_proto                              */
	int      tx_open;      /* đã đếm live_tx cho tx đang parse?            */
	uint32_t live_tx;      /* tx pipelined đồng thời chưa hoàn tất         */
	uint32_t skip;         /* byte thân còn phải bỏ qua (SKIP_BODY)        */
	uint32_t tx_budget;    /* byte soi mỗi transaction (mặc định = cap)     */
	/* tín hiệu ra (đặt lại mỗi step) */
	int want_watch;
	int want_inspected;
	int anomaly;
};

/* budget = byte soi mỗi tx; 0 → mặc định (REASS_MAX_BYTES). */
void http_tx_init(struct http_tx *h, uint32_t budget);

/*
 * Tiến máy trạng thái trên dòng to_server của `rf`. Gọi sau reass_segment
 * (chiều to_server). cb/ctx để nhận match khi re-scan transaction mới.
 */
void http_tx_step(struct http_tx *h, struct reass_flow *rf,
		  reass_match_cb cb, void *ctx);

#endif /* SG_HTTP_TX_H */
