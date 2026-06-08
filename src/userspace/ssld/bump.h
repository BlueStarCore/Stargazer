/* SPDX-License-Identifier: MIT */
/*
 * bump.h - MITM một flow TLS: terminate phía client (cert forge theo SNI),
 *          mở TLS ra server thật, giải mã, soi plaintext, mã hóa lại.
 *
 *   client ──TLS(cert giả)── ssld ──TLS(thật)── server
 *                              │
 *                         plaintext → inspect()
 *
 * FAIL-CLOSED: nếu verify_upstream và cert server THẬT không hợp lệ → KHÔNG
 * forge cert hợp lệ che lỗi; đóng kết nối (client tự thấy hỏng). Đây là tính
 * chất an ninh sống còn — nếu không, ta vô tình tước cảnh báo cert của user.
 */
#ifndef SG_SSLD_BUMP_H
#define SG_SSLD_BUMP_H

#include "ca.h"
#include "certcache.h"
#include <netinet/in.h>

struct bump_cfg {
	struct ca_ctx    *ca;
	struct certcache *cc;
	int               verify_upstream;   /* 1 = fail-closed nếu cert server lỗi */

	/*
	 * Soi plaintext đã giải mã. to_server=1 (client→server) hoặc 0
	 * (server→client). Trả 0 = cho qua, 1 = CHẶN (drop flow). NULL = không soi.
	 */
	int  (*inspect)(const unsigned char *data, int len, int to_server,
			void *ud);
	void  *inspect_ud;
};

/*
 * Chạy MITM cho một kết nối. `sni` lấy từ peek ClientHello (NULL nếu không có
 * — khi đó forge theo IP đích, ít khớp, dễ cảnh báo cert). client_fd phải VẪN
 * còn nguyên ClientHello trong buffer (conn.c dùng MSG_PEEK). bump_run ĐÓNG
 * client_fd trước khi trả về (consume). Trả 0 nếu phiên kết thúc bình thường,
 * -1 nếu lỗi/fail-closed.
 */
int bump_run(int client_fd, const char *sni, const struct sockaddr_in *dst,
	     const struct bump_cfg *cfg);

#endif /* SG_SSLD_BUMP_H */
