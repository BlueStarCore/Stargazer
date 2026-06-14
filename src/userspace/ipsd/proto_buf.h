/* SPDX-License-Identifier: MIT */
/*
 * proto_buf.h - Trích "sticky buffer" giao thức từ dòng đã ghép (P6).
 *
 * Nhiều luật ET gắn content vào VÙNG cụ thể (http_uri, http_header, …,
 * tls.sni) thay vì payload thô → match chính xác hơn, ít báo nhầm. Ta parse
 * dòng đã ghép một lần thành các vùng rồi cho verify khớp content trên đúng
 * vùng. Parser tối thiểu, BOUNDS-CHECK mọi truy cập.
 *
 * Phạm vi: HTTP REQUEST (to_server): method, uri, header, body. TLS SNI từ
 * ClientHello (tái dùng tls_clienthello). HTTP response chưa làm.
 */
#ifndef SG_PROTO_BUF_H
#define SG_PROTO_BUF_H

#include <stdint.h>
#include "sig_rule.h"   /* enum sig_buf, SIG_NBUF */

struct match_buffers {
	const uint8_t *b[SIG_NBUF];
	int            len[SIG_NBUF];
	char           sni[256];   /* lưu SNI; b[SIG_BUF_TLS_SNI] trỏ vào đây */
};

/* Đặt buffer RAW = dòng đã ghép; mọi vùng khác rỗng. */
void bufs_init_raw(struct match_buffers *mb, const uint8_t *raw, int len);

/*
 * Trích các vùng từ `stream[0..len)` (dòng to_server đã ghép). Nhận diện
 * HTTP request (method SP uri SP HTTP/…CRLF headers CRLF CRLF body) và TLS
 * ClientHello (record 0x16). Vùng không có → b[]=NULL,len[]=0.
 */
void bufs_extract(struct match_buffers *mb, const uint8_t *stream, int len);

#endif /* SG_PROTO_BUF_H */
