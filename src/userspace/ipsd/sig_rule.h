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
 *
 * P0 — Phân loại độ trung thực (fidelity) thay cho "bỏ qua âm thầm":
 *   Field thu hẹp CHƯA hỗ trợ (pcre, distance, within, byte_test/jump,
 *   isdataat, dsize, urilen, flowbits, http_*) KHÔNG còn bị bỏ lặng. Khi gặp
 *   chúng, rule bị KẸP fidelity = SIG_FID_ALERT (chỉ ALERT, không bao giờ
 *   DROP) vì ta không kiểm được điều kiện thu hẹp → tránh chặn nhầm do
 *   "khớp một phần coi như đủ". Rule chỉ-content (mọi keyword đều hỗ trợ) giữ
 *   SIG_FID_FULL → được DROP. Rule reputation/IP-list (không content, không
 *   selector) bị BỎ (catch-all). Độ phủ thật đếm trong sig_load_stats.
 */
#ifndef SG_SIG_RULE_H
#define SG_SIG_RULE_H

#include <stdint.h>
#include <stddef.h>
#include "ac.h"

#define SIG_MAX_CONTENT 8
#define SIG_CONTENT_MAX 1024   /* byte tối đa cho một content (sau decode) */
#define SIG_MSG_MAX     128
#define SIG_MAX_BYTEOP  4      /* P3 — số byte_test/byte_jump mỗi rule */

/* P5 — flowbits */
#define SIG_MAX_FLOWBITS  1024 /* số cờ flowbits toàn cục tối đa            */
#define SIG_FB_NAME_MAX   64
#define SIG_MAX_FB_RULE   6    /* số thao tác flowbits mỗi rule             */
#define SIG_FB_WORDS      (SIG_MAX_FLOWBITS / 64)   /* = 16 (bitset/flow)   */

enum sig_action { SIG_ALERT = 0, SIG_DROP = 1 };          /* DROP > ALERT */
enum sig_proto  { SIG_PROTO_ANY = 0, SIG_PROTO_TCP, SIG_PROTO_UDP, SIG_PROTO_ICMP };

/* P0 — fidelity: rule có được phép DROP hay chỉ ALERT. */
enum sig_fidelity { SIG_FID_FULL = 0, SIG_FID_ALERT = 1 };

/* P6 — flow: keyword (lọc theo hướng/trạng thái; rẻ, dùng dữ liệu sẵn có). */
#define SIG_FLOW_ESTABLISHED 0x01   /* yêu cầu kết nối đã established       */
#define SIG_FLOW_TO_SERVER   0x02   /* chỉ chiều client→server             */
#define SIG_FLOW_TO_CLIENT   0x04   /* chỉ chiều server→client             */

/* P6 — sticky buffers: content khớp trên VÙNG giao thức (không phải payload thô).
 * http_uri/header/method/body (request to_server), tls.sni (ClientHello). */
enum sig_buf {
	SIG_BUF_RAW = 0,        /* dòng đã ghép (mặc định)        */
	SIG_BUF_HTTP_METHOD,
	SIG_BUF_HTTP_URI,
	SIG_BUF_HTTP_HEADER,
	SIG_BUF_HTTP_BODY,
	SIG_BUF_TLS_SNI,
	SIG_NBUF
};
struct match_buffers;   /* định nghĩa đầy đủ ở proto_buf.h */

/* Bitmask keyword thu hẹp CHƯA hỗ trợ (gắn vào sig_rule.has_unsup để đếm/log).
 * P2 đã hỗ trợ distance/within/dsize → KHÔNG còn cap (SIG_U_RELATIVE bỏ dùng;
 * SIG_U_DSIZE chỉ còn cho isdataat/urilen). */
enum sig_unsup {
	SIG_U_PCRE     = 1u << 0,   /* pcre                          */
	SIG_U_BYTEOP   = 1u << 1,   /* byte_test / byte_jump         */
	SIG_U_RELATIVE = 1u << 2,   /* (P2: distance/within đã hỗ trợ — không dùng) */
	SIG_U_DSIZE    = 1u << 3,   /* isdataat / urilen             */
	SIG_U_FLOWBITS = 1u << 4,   /* flowbits                      */
	SIG_U_HTTPBUF  = 1u << 5,   /* http_* sticky buffers         */
};

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
	int      offset; /* bắt đầu tìm từ byte này; -1 = không đặt (TUYỆT ĐỐI) */
	int      depth;  /* chỉ tìm trong `depth` byte kể từ offset; -1 = không đặt */
	/* P2 — định vị TƯƠNG ĐỐI so với CUỐI content trước (relative=1 → bỏ offset/depth) */
	int      distance; /* lệch so với cuối match trước (có thể âm); -1 = không đặt */
	int      within;   /* khớp trong `within` byte kể từ cuối match trước; -1 = không đặt */
	uint8_t  relative; /* 1 nếu content dùng distance/within */
	uint8_t  buffer;   /* P6 — enum sig_buf (vùng khớp; RAW = mặc định) */
};

/*
 * P3 — byte_test / byte_jump: đọc trường nhị phân theo cấu trúc giao thức
 * (độ dài/giá trị) — mở khóa luật DNS/SMB/RPC. Xen kẽ content theo thứ tự:
 * `after_content` = số content đã parse TRƯỚC op này → verify interleave đúng
 * thứ tự. Mọi lần đọc N byte BOUNDS-CHECK trước (điểm tấn công kinh điển).
 */
/*
 * P5 — flowbits: trạng thái đa-gói/đa-luật theo flow.
 *   isset/isnotset : ĐIỀU KIỆN match (kiểm bit trước verdict) — YÊU CẦU flow
 *                    đang được track (fb != NULL); không track → coi như KHÔNG
 *                    thoả → không match (fail-safe, tránh false-drop).
 *   set/unset/toggle: tác dụng phụ SAU khi rule khớp.
 *   noalert         : rule chỉ set cờ, không tự sinh verdict.
 */
enum sig_fb_op { SIG_FB_ISSET = 0, SIG_FB_ISNOTSET, SIG_FB_SET,
		 SIG_FB_UNSET, SIG_FB_TOGGLE };

struct sig_flowbit {
	uint8_t  op;        /* enum sig_fb_op       */
	int16_t  flag_id;   /* index trong bảng cờ của ruleset */
};

/* Bitset cờ per-flow (lưu trong pool flow ở main.c). */
struct flowbit_state { uint64_t bits[SIG_FB_WORDS]; };

enum sig_byteop_kind { SIG_BYTE_TEST = 0, SIG_BYTE_JUMP = 1 };

struct sig_byteop {
	uint8_t  kind;        /* enum sig_byteop_kind                    */
	uint8_t  nbytes;      /* 1..8 — độ rộng trường đọc               */
	uint8_t  relative;    /* 1 = offset tính từ cuối match trước     */
	uint8_t  little;      /* 1 = little-endian, 0 = big-endian       */
	uint8_t  negate;      /* byte_test: phủ định kết quả so sánh     */
	char     oper;        /* byte_test: '<' '>' '=' '&' '|'          */
	int32_t  value;       /* byte_test: giá trị so sánh              */
	int32_t  offset;      /* vị trí đọc (từ cursor nếu relative)     */
	int32_t  multiplier;  /* byte_jump: nhân giá trị đọc (mặc định 1)*/
	int32_t  post_offset; /* byte_jump: cộng sau khi nhảy            */
	int      after_content; /* op này nằm sau content thứ mấy        */
};

/*
 * Port list: n_dport == 0 means any port; n_dport > 0 means match any port in
 * the list.  Populated from literal ports or from Snort variable expansion
 * (e.g. $HTTP_PORTS → {80,8080,8000,8008}).  Source IP/dest IP variables
 * ($HOME_NET, $EXTERNAL_NET, …) are NOT resolved — they are silently treated
 * as "any"; this is a known MVP limitation noted in the thesis.
 */
#define SIG_DPORT_MAX 8

struct sig_rule {
	uint32_t sid, rev;
	int      action;             /* SIG_ALERT / SIG_DROP   */
	int      proto;              /* SIG_PROTO_*            */
	uint16_t dport_list[SIG_DPORT_MAX]; /* destination port list */
	uint8_t  n_dport;            /* 0 = any port           */
	uint8_t  flags_set;          /* cờ TCP bắt buộc set (0 = bỏ qua) */
	struct sig_content content[SIG_MAX_CONTENT];
	int      n_content;
	int      fast;               /* index content làm fast pattern; -1 = không có */
	int      dsize_min;          /* P2 — dsize: độ dài payload ≥ (>=0), -1 = không đặt */
	int      dsize_max;          /* P2 — dsize: độ dài payload ≤ (>=0), -1 = không đặt */
	struct sig_byteop byteop[SIG_MAX_BYTEOP];  /* P3 */
	int      n_byteop;
	struct sig_flowbit flowbits[SIG_MAX_FB_RULE];  /* P5 */
	int      n_fb;
	void    *pcre;               /* P4 — pcre2_code* (NULL nếu không có/!HAVE_PCRE) */
	uint8_t  pcre_relative;      /* P4 — modifier R: match từ cuối content trước */
	uint8_t  pcre_buffer;        /* P4 — enum sig_buf cho pcre (U/H…); RAW mặc định */
	uint8_t  fb_noalert;         /* P5 — chỉ set cờ, không tự alert     */
	uint8_t  flow_flags;         /* P6 — SIG_FLOW_* (0 = không ràng buộc) */
	uint8_t  fidelity;           /* enum sig_fidelity (FULL=được DROP)  */
	uint8_t  has_unsup;          /* bitmask sig_unsup (để đếm/log)      */
	uint32_t prof_mask;          /* per-policy scoping: bitmask profile chứa rule
				      * (bit i = profile id i, gắn lúc compile bằng
				      * `sgprof:i;`). 0 = chưa tag → áp mọi flow
				      * (fail-safe / back-compat).                 */
	char     msg[SIG_MSG_MAX];
};

/*
 * Engine CHỈ còn signature dựa-content (L2). Rule không content (chỉ proto/
 * dport/flags) KHÔNG còn được nạp (tầng "L1 signature" đã bỏ) — chúng bị SKIP
 * và đếm riêng. Anomaly flow-level (SYN-flood/port-scan) do flow_rule_match_
 * builtin (L1-builtin) lo, độc lập với signature.
 */
struct sig_ruleset {
	/* L2: payload rules (Aho-Corasick) */
	struct sig_rule    *rules;
	int                 n_rules, cap_rules;
	struct ac_automaton ac;
	int                 built;
	/* P5 — bảng tên cờ flowbits toàn cục (intern lúc nạp) */
	char    (*fb_names)[SIG_FB_NAME_MAX];
	uint8_t  *fb_ever_set;        /* cờ có bao giờ được 1 rule set/toggle? */
	int       n_fb_names, cap_fb_names;
};

/* Ngữ cảnh flow cho bước verify (caller điền từ gói/conntrack). */
struct flow_ctx {
	uint8_t  proto;       /* SIG_PROTO_* */
	uint16_t dport;
	uint8_t  tcp_flags;   /* tổ hợp SIG_TCP_* */
	uint8_t  established; /* P6 — đã thấy traffic 2 chiều (proxy established) */
	uint8_t  to_server;  /* P6 — 1 = chiều client→server, 0 = server→client */
	uint8_t  prof_id;    /* IPS profile id của flow (1..31, từ skb mark/NFQA_MARK);
			      * 0 = không rõ → áp mọi rule (fail-safe). */
	const struct flowbit_state *fb;  /* P5 — bitset cờ của flow; NULL = không track */
	const struct match_buffers *bufs; /* P6 — vùng giao thức; NULL = chỉ RAW */
};

int  sig_ruleset_init(struct sig_ruleset *rs);

/*
 * Parse + thêm MỘT rule. Mã trả (P0):
 *   SIG_LINE_FULL  ( 0) — nạp, fidelity FULL (được DROP).
 *   SIG_LINE_ALERT ( 2) — nạp, KẸP ALERT (có keyword thu hẹp chưa hỗ trợ).
 *   SIG_LINE_BLANK ( 1) — dòng rỗng/comment.
 *   SIG_LINE_SKIP_UNSUP (3) — bỏ: content quá yếu + còn keyword chưa hỗ trợ.
 *   SIG_LINE_SKIP_REP   (4) — bỏ: reputation/IP-list/catch-all (match mọi flow).
 *   SIG_LINE_ERROR (-1) — lỗi cú pháp.
 */
#define SIG_LINE_FULL        0
#define SIG_LINE_BLANK       1
#define SIG_LINE_ERROR     (-1)
#define SIG_LINE_ALERT       2
#define SIG_LINE_SKIP_UNSUP  3
#define SIG_LINE_SKIP_REP    4
#define SIG_LINE_SKIP_NOCONTENT 5   /* rule không content → bỏ (đã gỡ L1 signature) */
#define SIG_LINE_SKIP_NOSID  6   /* rule không keyword sid → bỏ (malformed/không truy vết, gây FP) */

int  sig_parse_line(struct sig_ruleset *rs, const char *line);

/* Thống kê một lần nạp file (độ phủ thật — KHÔNG được giấu, P0). */
struct sig_load_stats {
	int loaded;              /* tổng rule nạp = loaded_full + loaded_alert */
	int skipped;             /* tổng dòng bỏ (mọi lý do)                   */
	int errors;              /* dòng sai cú pháp                           */
	int loaded_full;         /* nạp + đủ điều kiện → ĐƯỢC DROP             */
	int loaded_alert;        /* nạp nhưng KẸP ALERT (thiếu keyword thu hẹp)*/
	int skipped_unsupported; /* bỏ: chỉ còn keyword chưa hỗ trợ / quá yếu  */
	int skipped_reputation;  /* bỏ: reputation/IP-list/catch-all           */
	int skipped_no_content;  /* bỏ: rule không content (đã gỡ L1 signature)*/
	int skipped_no_sid;      /* bỏ: rule không keyword sid (malformed/FP)  */
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

/*
 * Verify ĐẦY ĐỦ một rule (index trong rs->rules) trên buffer (vd dòng TCP đã
 * ghép): proto/dport/flags + mọi content đúng thứ tự + offset/depth. Dùng khi
 * streaming AC báo fast-pattern trúng để xác nhận trên dòng. Trả 1 nếu khớp,
 * 0 nếu không (kể cả rule_idx ngoài phạm vi). KHÔNG áp fidelity-cap (caller lo).
 */
int  sig_verify(const struct sig_ruleset *rs, int rule_idx,
		const uint8_t *buf, int len, const struct flow_ctx *fc);

/*
 * P5 — áp tác dụng phụ flowbits (set/unset/toggle) của rule khớp vào bitset của
 * flow. Gọi SAU khi rule đã verify khớp. fb có thể NULL (không track → bỏ qua).
 */
void sig_flowbits_apply(const struct sig_rule *r, struct flowbit_state *fb);

void sig_ruleset_free(struct sig_ruleset *rs);

#endif /* SG_SIG_RULE_H */
