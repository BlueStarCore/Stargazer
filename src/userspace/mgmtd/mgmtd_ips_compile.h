/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_ips_compile.h — Biên dịch ruleset IPS theo category (Phase B).
 *
 * Kho signature global tổ chức theo category file: <repo>/<cat>.rules
 * (vd repo/scan.rules, repo/web.rules). Một profile chọn tập category qua
 * field `categories` ("all" hoặc "scan,web,malware"). Hàm compile ghép các
 * file category được chọn thành MỘT ruleset đầu ra (profile hoặc active).
 *
 * Thuần I/O (dirent/stdio) — KHÔNG phụ thuộc DB/mgmtd → host-test được.
 */
#ifndef MGMTD_IPS_COMPILE_H
#define MGMTD_IPS_COMPILE_H

#include <stddef.h>

/*
 * Ghép các category đã chọn từ repo_dir vào out_path.
 *
 *   repo_dir   : thư mục chứa <category>.rules
 *   categories : "all" → mọi *.rules trong repo; hoặc danh sách "a,b,c"
 *                (mỗi mục → repo_dir/<mục>.rules; thiếu file thì bỏ qua).
 *   out_path   : file ruleset đầu ra (ghi đè).
 *
 * Trả số file category đã ghép (>=0), -1 nếu lỗi mở out_path / repo.
 * out_path luôn có header comment + nội dung các category (kể cả 0 file →
 * file rỗng hợp lệ, ipsd -C sẽ báo 0 rule).
 */
int ips_compile_categories(const char *repo_dir, const char *categories,
			   const char *out_path);

/* ── FortiGate-style filter compile (Yêu cầu mới) ─────────────────────── */

enum ips_filter_type   { IPS_FT_CATEGORY = 0, IPS_FT_SIGNATURE = 1 };
enum ips_filter_action { IPS_FA_DEFAULT  = 0, IPS_FA_BLOCK, IPS_FA_ALERT,
			 IPS_FA_PASS };

struct ips_filter {
	int  type;          /* enum ips_filter_type   */
	char value[128];    /* tên category hoặc SID  */
	int  action;        /* enum ips_filter_action */
};

/*
 * Compile ruleset của một profile TỪ danh sách filter vào out_path.
 *   - filter category: ghép repo/<value>.rules, GHI ĐÈ action mỗi rule theo
 *     filter.action (default=giữ nguyên, block=drop, alert=alert, pass=pass).
 *   - filter signature: tìm rule có `sid:<value>;` trong toàn repo, ghi ra
 *     với action override.
 * Trả số dòng RULE đã ghi (>=0), -1 nếu lỗi mở out_path/repo.
 */
int ips_compile_filters(const char *repo_dir, const struct ips_filter *filters,
			int n_filters, const char *out_path);

/*
 * Liệt kê signature trong repo dưới dạng JSON array (cho bảng "Add Signatures"
 * kiểu FortiGate). Mỗi entry: {sid,name,category,action,cve}. Parse từng rule
 * lấy action (token đầu), msg:"..." (name), sid:N;, reference:cve,...
 * Ghi vào buf (cap), trả độ dài (>=0) hoặc -1. Cắt an toàn nếu gần đầy cap.
 */
/* allowed: array of category name strings (repo filename stem, e.g. "botcc").
 * Only entries whose category appears in allowed[] are included.
 * Pass allowed=NULL / n_allowed=0 to include everything. */
int ips_catalog_to_json(const char *repo_dir, char *buf, size_t cap,
                        const char *const *allowed, int n_allowed);

#endif /* MGMTD_IPS_COMPILE_H */
