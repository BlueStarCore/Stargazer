/* SPDX-License-Identifier: MIT */
/*
 * ac.h - Aho-Corasick multi-pattern matcher cho stargazer-ipsd.
 *
 * Dò NHIỀU pattern cùng lúc trong một lần quét payload: O(n + Σ|pattern| +
 * #match), KHÔNG phụ thuộc số rule lúc quét — đây là lý do họ thuật toán này
 * được Snort/Suricata dùng cho signature payload (Aho & Corasick, CACM 1975).
 *
 * Tự viết, không dependency, link tĩnh musl được. Dùng DFA ĐẦY ĐỦ: sau khi
 * ac_build(), mỗi node có đủ 256 cạnh next[] nên vòng lặp search chỉ là một
 * phép chuyển trạng thái mỗi byte (không phải đi theo fail-link lúc chạy).
 *
 * Binary-safe: mọi API nhận con trỏ + độ dài, không dựa vào ký tự '\0'.
 */
#ifndef SG_AC_H
#define SG_AC_H

#include <stdint.h>
#include <stddef.h>

#define AC_ALPHABET 256

struct ac_node {
	int32_t next[AC_ALPHABET]; /* goto/DFA: -1 khi đang build, đủ sau ac_build */
	int32_t fail;              /* failure link (chỉ dùng lúc build)            */
	int32_t out;               /* id pattern KẾT THÚC tại node này, -1 nếu không */
	int32_t out_link;          /* node output gần nhất theo fail-link, -1 nếu không */
};

struct ac_automaton {
	struct ac_node *nodes;
	int32_t         n_nodes;   /* số node đang dùng        */
	int32_t         cap_nodes; /* sức chứa đã cấp phát     */
	int             nocase;    /* 1 = không phân biệt hoa/thường */
	int             built;    /*đã xây xong state machine hay chua? => tranh anh huong den cac đường nhảy*/ 
};

/* Khởi tạo automaton rỗng (chỉ có root). Trả 0 nếu OK, -1 nếu hết bộ nhớ. */
int  ac_init(struct ac_automaton *ac, int nocase);

/*
 * Thêm một pattern (pat[0..len)) gắn với định danh id (>= 0). Phải gọi TRƯỚC
 * ac_build(). Trả 0 nếu OK, -1 nếu lỗi (đã build / tham số sai / hết bộ nhớ).
 * Hai pattern trùng nội dung sẽ trỏ cùng node cuối → chỉ giữ id sau cùng
 * (xử lý trùng nên làm ở tầng rule).
 */
int  ac_add_pattern(struct ac_automaton *ac, const uint8_t *pat, int len, int id);

/* Dựng failure-link + DFA goto + output-link bằng BFS. Trả 0/-1. */
int  ac_build(struct ac_automaton *ac);

/*
 * Quét text[0..len). Với mỗi pattern khớp, gọi on_match(id, end_pos, ctx),
 * trong đó end_pos là chỉ số (0-based) của byte CUỐI của pattern trong text.
 * on_match trả khác 0 để dừng sớm. Trả về tổng số match (hoặc -1 nếu chưa build).
 */
int  ac_search(const struct ac_automaton *ac, const uint8_t *text, size_t len,
	       int (*on_match)(int id, size_t end_pos, void *ctx), void *ctx);

/* Giải phóng bộ nhớ, đưa automaton về trạng thái rỗng (gọi lại ac_init được). */
void ac_free(struct ac_automaton *ac);

#endif /* SG_AC_H */
