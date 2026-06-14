/* SPDX-License-Identifier: MIT */
/*
 * relay.h - Bơm byte hai chiều giữa hai socket (đường SPLICE của ssld).
 *
 * SPLICE = relay TCP thô KHÔNG giải mã: client <─relay_pump─> server thật.
 * Dùng cho flow TLS được bypass (banking/pinned app) và là nền của đường BUMP
 * sau này (sau khi giải mã, hai nửa plaintext cũng được bơm qua nhau).
 *
 * MVP: poll trên hai đầu đọc + ghi-chặn (write_all) sang đầu kia. Giới hạn đã
 * biết: ghi-chặn có thể deadlock nếu CẢ HAI buffer gửi đầy cùng lúc (hiếm với
 * traffic thường); bản sản phẩm cần non-blocking + buffer mỗi chiều — ghi
 * "future work". Xử lý đúng half-close (một chiều FIN, chiều kia còn data).
 */
#ifndef SG_SSLD_RELAY_H
#define SG_SSLD_RELAY_H

#include <stddef.h>

#define RELAY_BUF_SIZE 16384

/*
 * Bơm dữ liệu hai chiều giữa fd `a` và fd `b` cho tới khi cả hai chiều đóng
 * (EOF/lỗi). Khi một chiều EOF, shutdown(SHUT_WR) đầu kia để truyền FIN, vẫn
 * tiếp tục chiều còn lại (half-close). KHÔNG đóng a/b — caller tự close.
 * Trả 0 khi kết thúc bình thường, -1 nếu lỗi poll không hồi phục được.
 */
int relay_pump(int a, int b);

/*
 * Ghi đủ `len` byte ra fd (lặp qua ghi từng phần, bỏ qua EINTR).
 * Trả 0 nếu ghi đủ, -1 nếu lỗi/đối tác đóng. Export để conn.c forward buffered
 * ClientHello trước khi vào relay.
 */
int relay_write_all(int fd, const void *buf, size_t len);

#endif /* SG_SSLD_RELAY_H */
