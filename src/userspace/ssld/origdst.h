/* SPDX-License-Identifier: MIT */
/*
 * origdst.h - Lấy địa chỉ ĐÍCH GỐC của một kết nối đã bị chuyển hướng vào ssld.
 *
 * Khi iptables REDIRECT/DNAT đẩy flow TLS vào cổng nghe của ssld, socket phía
 * kernel còn nhớ đích thật qua SO_ORIGINAL_DST (netfilter). ssld cần đích này
 * để mở kết nối ra server thật (cả splice lẫn bump).
 *
 * (TPROXY là cách khác — socket IP_TRANSPARENT giữ luôn đích gốc, đọc bằng
 *  getsockname; sẽ bổ sung khi chọn TPROXY ở mgmtd. MVP dùng SO_ORIGINAL_DST.)
 */
#ifndef SG_SSLD_ORIGDST_H
#define SG_SSLD_ORIGDST_H

#include <netinet/in.h>

/*
 * Điền *out bằng đích gốc (IPv4) của client_fd. Trả 0 nếu lấy được, -1 nếu
 * không (không bị REDIRECT, hoặc IPv6 — chưa hỗ trợ).
 */
int origdst_get(int client_fd, struct sockaddr_in *out);

#endif /* SG_SSLD_ORIGDST_H */
