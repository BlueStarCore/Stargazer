/* SPDX-License-Identifier: MIT */
/*
 * tls_clienthello.h - Parse SNI từ TLS ClientHello (bước "PEEK" của SSL
 *                     inspection — xem docs/ips-master-plan.md, chương SSL).
 *
 * Đây là bước RUNTIME ĐẦU TIÊN của stargazer-ssld: trước khi quyết định
 * BYPASS (splice — relay thô) hay INSPECT (bump — MITM giải mã), proxy đọc
 * ClientHello (vẫn cleartext kể cả TLS 1.3, trừ khi có ECH) để lấy SNI rồi
 * tra bypass list. KHÔNG cần OpenSSL — chỉ parse byte thuần, bounds-check từng
 * bước; input độc/cụt KHÔNG được làm crash.
 *
 * Cùng module này tái dùng cho:
 *   - SNI-based signature matching (content trên buffer tls.sni).
 *   - FQDN wildcard Phase 3 (DNS/SNI snooping).
 *
 * Tham chiếu: RFC 8446 §4.1.2 (ClientHello), RFC 6066 §3 (server_name).
 */
#ifndef SG_TLS_CLIENTHELLO_H
#define SG_TLS_CLIENTHELLO_H

#include <stdint.h>
#include <stddef.h>

/* host_name tối đa: RFC 1035 giới hạn FQDN 253 ký tự + NUL. */
#define TLS_SNI_MAX 256

enum tls_ch_result {
	TLS_CH_OK        =  0,  /* parse xong; has_sni cho biết có SNI hay không */
	TLS_CH_NEED_MORE =  1,  /* buffer bị cắt giữa chừng — cần thêm byte      */
	TLS_CH_NOT_CH    =  2,  /* không phải TLS handshake ClientHello          */
	TLS_CH_MALFORMED = -1,  /* cấu trúc sai (cố tình hoặc hỏng)             */
};

struct tls_clienthello {
	char     sni[TLS_SNI_MAX]; /* host_name, NUL-terminated; "" nếu không có */
	int      has_sni;          /* 1 nếu tìm thấy SNI host_name               */
	uint16_t legacy_version;   /* client_version trong ClientHello (vd 0x0303)*/
	uint16_t record_len;       /* độ dài record TLS (để biết khung handshake) */
};

/*
 * Parse một (hoặc đầu một) TLS record chứa ClientHello.
 *
 * Trả:
 *   TLS_CH_OK        + điền *out (has_sni=0/1)
 *   TLS_CH_NEED_MORE nếu buf chưa đủ để đọc hết phần cần thiết
 *   TLS_CH_NOT_CH    nếu byte đầu không phải handshake/ClientHello
 *   TLS_CH_MALFORMED nếu độ dài lồng nhau vô lý (vượt biên record/buffer)
 *
 * `out` luôn được zero-init trước khi parse; an toàn khi truyền buf=NULL.
 * Hàm KHÔNG ghi quá out->sni[TLS_SNI_MAX-1]; SNI dài hơn → MALFORMED
 * (host_name hợp lệ không bao giờ vượt 253).
 */
enum tls_ch_result tls_parse_clienthello(const uint8_t *buf, size_t len,
					 struct tls_clienthello *out);

/* Tên kết quả để log/test. */
const char *tls_ch_result_str(enum tls_ch_result r);

#endif /* SG_TLS_CLIENTHELLO_H */
