/* SPDX-License-Identifier: MIT */
/*
 * sig_reload.h - hot-reload ruleset mà không cần dừng NFQUEUE loop.
 *
 * Kiến trúc theo Snort README.reload:
 *   - Luồng reload BUILD ruleset mới trong khi luồng NFQUEUE vẫn dùng bản cũ.
 *   - Khi bản mới sẵn sàng → SWAP dưới write-lock → free bản cũ SAU khi swap.
 *   - Không bao giờ có cửa sổ "0 rule active".
 *   - Ruleset mới lỗi → rollback, bản cũ tiếp tục chạy.
 *   - SIGUSR1 báo hiệu reload qua self-pipe (async-signal-safe).
 */
#ifndef SG_SIG_RELOAD_H
#define SG_SIG_RELOAD_H

#define _GNU_SOURCE   /* pthread_rwlock_t on older glibc */
#include "sig_rule.h"
#include <pthread.h>

struct sig_reload {
	struct sig_ruleset  *active;          /* ruleset đang chạy (không bao giờ NULL sau init) */
	struct sig_ruleset  *pending;         /* đang build trong reload thread; NULL khi rảnh   */
	pthread_rwlock_t     rwlock;          /* readers = sig_reload_match(); writer = swap      */
	pthread_mutex_t      spawn_lock;      /* bảo vệ thread + pending + rules_path            */
	pthread_t            thread;          /* handle reload thread; 0 = rảnh                  */
	int                  pipe_rd;         /* self-pipe: NFQUEUE loop poll                    */
	int                  pipe_wr;         /* self-pipe: signal handler ghi                   */
	char                 rules_path[256]; /* path nạp khi có SIGUSR1                         */
	int                  last_result;     /* kết quả reload gần nhất: 0=ok, -1=lỗi           */
	unsigned long        reload_count;
	unsigned long        reload_errors;
};

/*
 * Khởi tạo: nạp ruleset ban đầu từ rules_path, mở self-pipe,
 * đăng ký SIGUSR1 handler. Trả 0/-1.
 */
int  sig_reload_init(struct sig_reload *sr, const char *rules_path);

/*
 * Gọi từ NFQUEUE loop khi pipe_rd readable (SIGUSR1 đến). Khởi động
 * reload thread nếu chưa chạy; drain pipe. Trả 0=bắt đầu, 1=đang
 * reload rồi (bỏ qua), -1=lỗi.
 */
int  sig_reload_handle_signal(struct sig_reload *sr);

/*
 * Drop-in replacement cho sig_match(): rdlock → sig_match → unlock.
 * Caller KHÔNG được giữ lock trước khi gọi.
 */
int  sig_reload_match(struct sig_reload *sr, const uint8_t *payload,
		      size_t len, const struct flow_ctx *fc);

/*
 * Trigger reload trực tiếp (không cần signal) — dùng cho IPC handler
 * khi operator chạy "execute ips update file <path>". Async (trả về ngay).
 */
int  sig_reload_trigger(struct sig_reload *sr, const char *new_path);

/*
 * Block cho đến khi reload thread xong. Trả 0=thành công, -1=lỗi/rollback.
 */
int  sig_reload_wait(struct sig_reload *sr);

/* Giải phóng: join thread, free cả hai ruleset, destroy lock. Idempotent. */
void sig_reload_free(struct sig_reload *sr);

#endif /* SG_SIG_RELOAD_H */
