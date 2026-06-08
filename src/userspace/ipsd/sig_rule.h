/* SPDX-License-Identifier: MIT */
/*
 * sig_rule.h - Signature rule (ET OPEN / Snort subset) cho stargazer-ipsd.
 *
 * Mỗi rule có thể có nhiều `content`. Ta nạp MỘT "fast pattern" (content dài
 * nhất → chọn lọc cao nhất) của từng rule vào một Aho-Corasick chung để LỌC
 * NHANH; khi fast pattern trúng, sig_match() VERIFY lại toàn bộ rule trên
 * payload (mọi content, đúng thứ tự, đúng offset/depth/nocase) cộng
 * proto/port/flags rồi mới kết luận. Đây đúng cách Snort dùng MPM:
 * fast_pattern (prefilter) → full rule evaluation.
 *
 * Subset field hỗ trợ (đủ để nạp rule ET OPEN thật):
 *   header : action proto src sport -> dst dport
 *   option : msg, content (kèm |hex| và \escape), nocase, offset, depth,
 *            flags, sid, rev.
 * Field chưa hỗ trợ (pcre, distance, within, byte_test, flowbits…) bị bỏ qua
 * (rule vẫn nạp được phần content). Đây là giới hạn MVP, ghi rõ trong báo cáo.
 */
#ifndef SG_SIG_RULE_H
#define SG_SIG_RULE_H

#include <stdint.h>
#include <stddef.h>
#include "ac.h"

#define SIG_MAX_CONTENT 8
#define SIG_CONTENT_MAX 1024   /* byte tối đa cho một content (sau decode) */
#define SIG_MSG_MAX     128

enum sig_action { SIG_ALERT = 0, SIG_DROP = 1 };          /* DROP > ALERT */
enum sig_proto  { SIG_PROTO_ANY = 0, SIG_PROTO_TCP, SIG_PROTO_UDP, SIG_PROTO_ICMP };

/* Bit cờ TCP — KHỚP cách pkt_forward.ko mã hoá (ml->tcp_flags). */
#define SIG_TCP_FIN 0x01
#define SIG_TCP_SYN 0x02
#define SIG_TCP_RST 0x04
#define SIG_TCP_PSH 0x08
#define SIG_TCP_ACK 0x10
#define SIG_TCP_URG 0x20

struct sig_content {
	uint8_t *data;   /* byte đã decode (sở hữu, malloc) */
	int      len;
	int      nocase; /* 1 = không phân biệt hoa/thường  */
	int      offset; /* bắt đầu tìm từ byte này; -1 = không đặt */
	int      depth;  /* chỉ tìm trong `depth` byte kể từ offset; -1 = không đặt */
};

struct sig_rule {
	uint32_t sid, rev;
	int      action;             /* SIG_ALERT / SIG_DROP   */
	int      proto;              /* SIG_PROTO_*            */
	uint16_t dport;              /* 0 = any               */
	uint8_t  flags_set;          /* cờ TCP bắt buộc set (0 = bỏ qua) */
	struct sig_content content[SIG_MAX_CONTENT];
	int      n_content;
	int      fast;               /* index content làm fast pattern; -1 = không có */
	char     msg[SIG_MSG_MAX];
};

/*
 * L1 flow-rule: rule không có content (chỉ proto/dport/flags).
 * Khớp dựa trên thống kê flow (struct flow_stats trong flow_rule.h),
 * KHÔNG cần payload. Được nạp từ rule_gen hoặc file rule không có content.
 * Snort gọi đây là "non-payload detection rules".
 */
struct sig_flow_rule {
	uint32_t sid, rev;
	int      action;        /* SIG_ALERT / SIG_DROP */
	uint8_t  proto;         /* SIG_PROTO_* */
	uint16_t dport;         /* 0 = any */
	uint8_t  flags_set;     /* cờ TCP phải set trong tcp_flags_fwd (0 = bỏ qua) */
	char     msg[SIG_MSG_MAX];
};

struct sig_ruleset {
	/* L2: payload rules (Aho-Corasick) */
	struct sig_rule    *rules;
	int                 n_rules, cap_rules;
	struct ac_automaton ac;
	int                 built;
	/* L1: flow-stat rules (no payload, từ rule_gen hoặc file) */
	struct sig_flow_rule *l1_rules;
	int                   n_l1, cap_l1;
};

/* Ngữ cảnh flow cho bước verify (caller điền từ gói/conntrack). */
struct flow_ctx {
	uint8_t  proto;      /* SIG_PROTO_* */
	uint16_t dport;
	uint8_t  tcp_flags;  /* tổ hợp SIG_TCP_* */
};

int  sig_ruleset_init(struct sig_ruleset *rs);

/* Parse + thêm MỘT rule. Trả 0 nếu thêm được, 1 nếu dòng bỏ qua (rỗng/comment/
 * không có content), -1 nếu rule lỗi cú pháp. */
int  sig_parse_line(struct sig_ruleset *rs, const char *line);

/* Thống kê một lần nạp file (tùy chọn). */
struct sig_load_stats {
	int loaded;   /* rule có content, nạp thành công        */
	int skipped;  /* dòng rỗng/comment/rule không có content */
	int errors;   /* dòng sai cú pháp                        */
};

/* Nạp cả file .rules (hỗ trợ comment `#` và nối dòng bằng `\`). `st` có thể
 * NULL. Trả số rule nạp thành công, -1 nếu mở file lỗi. */
int  sig_load_file(struct sig_ruleset *rs, const char *path,
		   struct sig_load_stats *st);

/* Dựng Aho-Corasick từ fast pattern. Gọi sau khi nạp xong rule. */
int  sig_build(struct sig_ruleset *rs);

/* Khớp payload. Trả index rule ưu tiên cao nhất (DROP trước ALERT), -1 nếu
 * không khớp. Dùng rs->rules[idx] để đọc action/msg/sid. */
int  sig_match(const struct sig_ruleset *rs, const uint8_t *payload, size_t len,
	       const struct flow_ctx *fc);

void sig_ruleset_free(struct sig_ruleset *rs);

/*
 * Khớp L1 user-defined flow rules (không payload — chỉ proto/dport/flags_set
 * so với tcp_flags_fwd tích lũy). Trả index l1_rules[] hoặc -1.
 * Caller cần include "flow_rule.h" để có struct flow_stats.
 */
struct flow_stats;   /* forward declaration — định nghĩa đầy đủ ở flow_rule.h */
int sig_flow_match(const struct sig_ruleset *rs, const struct flow_ctx *fc,
		   const struct flow_stats *fs);

#endif /* SG_SIG_RULE_H */
