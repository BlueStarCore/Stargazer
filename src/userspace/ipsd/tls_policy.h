/* SPDX-License-Identifier: MIT */
/*
 * tls_policy.h - Quyết định SPLICE (relay thô) hay BUMP (MITM giải mã) cho một
 *                flow TLS, dựa trên SNI (xem tls_clienthello.h) + bypass list.
 *
 * Đây là "não" của SSL inspection — stage runtime ngay sau bước PEEK:
 *
 *     ClientHello ──peek──► SNI ──tls_policy_decide()──► BUMP / SPLICE
 *
 * Triết lý: inspect MẶC ĐỊNH (BUMP) mọi flow, TRỪ những domain trong bypass
 * list (banking, app pin-cert, danh mục riêng tư) → SPLICE. Sai ở đây gây hậu
 * quả thật: bump nhầm app pin-cert = ĐỨT kết nối của người dùng; vì vậy bypass
 * list là bắt buộc, không phải tùy chọn.
 *
 * Quy tắc match domain (case-insensitive):
 *   - "bank.com"    : khớp CHÍNH XÁC "bank.com".
 *   - "*.bank.com"  : khớp mọi subdomain "x.bank.com", "a.b.bank.com" — KHÔNG
 *                     khớp chính "bank.com" (đúng ngữ nghĩa wildcard TLS/DNS).
 * Thêm cả hai mục nếu muốn phủ luôn apex lẫn subdomain.
 *
 * KHÔNG cần OpenSSL/mbedTLS — chỉ so chuỗi; host-test được.
 */
#ifndef SG_TLS_POLICY_H
#define SG_TLS_POLICY_H

#include <stddef.h>

enum tls_action {
	TLS_BUMP   = 0,   /* MITM: giải mã + đưa plaintext vào IPS engine */
	TLS_SPLICE = 1,   /* relay TCP thô, KHÔNG giải mã (chỉ metadata/ML) */
};

/* Chính sách khi flow TLS KHÔNG có SNI (ECH, client cũ, hoặc cố tình giấu). */
enum tls_no_sni_policy {
	TLS_NO_SNI_BUMP   = 0,  /* mặc định an toàn: vẫn inspect */
	TLS_NO_SNI_SPLICE = 1,  /* nới: không SNI thì cho qua (ít an toàn hơn) */
};

struct tls_policy {
	char   **patterns;          /* bypass list (sở hữu, malloc)            */
	int      n, cap;
	int      default_bump;      /* 1 = mặc định BUMP (inspect-all-trừ-list) */
	int      no_sni;            /* enum tls_no_sni_policy                   */
};

/* Khởi tạo rỗng: default BUMP (inspect tất cả), no-SNI → BUMP. */
void tls_policy_init(struct tls_policy *p);

/*
 * Thêm một pattern vào bypass list ("bank.com" hoặc "*.bank.com").
 * Chuẩn hóa: lowercase, bỏ dấu '.' thừa ở đầu/cuối. Trả 0 nếu thêm được,
 * -1 nếu OOM hoặc pattern rỗng/không hợp lệ.
 */
int tls_policy_add_bypass(struct tls_policy *p, const char *pattern);

/*
 * Quyết định cho một flow. `sni` là host_name từ tls_clienthello (có thể NULL/
 * rỗng nếu has_sni==0). Trả TLS_BUMP hoặc TLS_SPLICE.
 *   - has_sni==0           → theo p->no_sni.
 *   - SNI khớp bypass list → TLS_SPLICE.
 *   - còn lại              → TLS_BUMP nếu default_bump, ngược lại TLS_SPLICE.
 */
enum tls_action tls_policy_decide(const struct tls_policy *p,
				  const char *sni, int has_sni);

/* Có khớp bypass list không (tách riêng để test/log). 1=khớp, 0=không. */
int tls_policy_is_bypassed(const struct tls_policy *p, const char *sni);

void tls_policy_free(struct tls_policy *p);

const char *tls_action_str(enum tls_action a);

#endif /* SG_TLS_POLICY_H */
