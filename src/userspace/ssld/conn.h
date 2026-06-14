/* SPDX-License-Identifier: MIT */
/*
 * conn.h - Xử lý MỘT kết nối client bị chuyển hướng vào ssld.
 *
 * Vòng đời:
 *   1. origdst_get         : tìm đích gốc (SO_ORIGINAL_DST)
 *   2. PEEK ClientHello    : MSG_PEEK (KHÔNG tiêu thụ — để nguyên cho bước sau)
 *   3. tls_policy_decide   : BUMP hay SPLICE theo SNI + bypass list
 *   4a. SPLICE : connect đích gốc → relay_pump thô (ClientHello còn trong socket
 *                được relay tự nhiên)
 *   4b. BUMP   : bump_run terminate+giải mã+soi (SSL_accept đọc ClientHello)
 */
#ifndef SG_SSLD_CONN_H
#define SG_SSLD_CONN_H

#include "tls_policy.h"
#include "ca.h"
#include "certcache.h"

struct sig_ruleset;   /* ../ipsd/sig_rule.h — fwd decl */

/* Hạn mức đọc-dồn (peek) ClientHello trước khi bỏ cuộc parse. */
#define CONN_HELLO_MAX 16384

/* Ngữ cảnh dùng chung cho mọi kết nối (chỉ đọc trong conn). */
struct ssld_ctx {
	const struct tls_policy *pol;
	struct ca_ctx           *ca;       /* NULL → chỉ SPLICE (không bump) */
	struct certcache        *cc;
	struct sig_ruleset      *rules;    /* NULL → bump không soi payload  */
	int                      verify_upstream;
	int                      no_ipc;         /* P4: 1 = soi per-chunk, không IPC */
	int                      ipc_failclosed; /* P4: 1 = IPC lỗi → chặn flow */
};

struct ssld_stats {
	unsigned long n_total;
	unsigned long n_splice;
	unsigned long n_bump;
	unsigned long n_error;
};

/*
 * Xử lý trọn vẹn một kết nối; ĐÓNG client_fd trước khi trả về.
 * An toàn để chạy trong thread riêng mỗi kết nối.
 */
void ssld_handle_conn(int client_fd, const struct ssld_ctx *ctx,
		      struct ssld_stats *st);

#endif /* SG_SSLD_CONN_H */
