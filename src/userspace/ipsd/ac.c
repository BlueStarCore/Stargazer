/* SPDX-License-Identifier: MIT */
/*
 * ac.c - Aho-Corasick multi-pattern matcher (xem ac.h).
 *
 * Ba bước:
 *   1) ac_add_pattern  : dựng cây tiền tố (trie) từ các pattern.
 *   2) ac_build        : BFS để (a) tính failure-link, (b) biến trie thành DFA
 *                        đầy đủ (điền mọi cạnh trống), (c) gắn output-link.
 *   3) ac_search       : chạy text qua DFA, mỗi byte một bước.
 *
 * "A buffer is always checked": mọi malloc/realloc kiểm NULL; search chỉ đọc
 * đúng len byte; norm() áp cả lúc add lẫn lúc search để nocase nhất quán.
 */
#include "ac.h"

#include <stdlib.h>
#include <string.h>

/* Chuan hoa ky tu: Hạ hoa→thường khi nocase (chỉ A–Z, không đụng byte > 127 / nhị phân). */
static inline uint8_t ac_norm(int nocase, uint8_t c){
	return (nocase && c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;

}
/* Cấp một node mới (đã init), trả index. -1 nếu hết bộ nhớ. */
static int ac_new_node(struct ac_automaton *ac){

	struct ac_node *n;
	if(ac->n_nodes == ac->cap_nodes ){
		int32_t ncap = ac->cap_nodes ? ac->cap_nodes*2:256;	//Nếu chưa có gì (0), nó cấp phát 256 node đầu tiên.
		struct ac_node *p = realloc(ac->nodes, (size_t)ncap*sizeof(*p));
		if(!p)
			return -1; 
		ac->nodes = p;
		ac->cap_nodes = ncap;
	}
	n =&ac->nodes[ac->n_nodes];		//n sẽ trỏ đến vị trí trống tiếp theo trong mảng nodes
	for(int i =0 ; i< AC_ALPHABET; i++)	
		n->next[i] = -1;			//Đặt tất cả 256 nhánh con (next) về -1
	n->fail = -1;
	n->out = -1;
	n->out_link = -1;
	return ac->n_nodes++;

}
int ac_init(struct ac_automaton *ac, int nocase){
	memset(ac, 0, sizeof(*ac));
	ac->nocase = nocase ? 1 : 0;
	return ac_new_node(ac) == 0 ? 0 : -1; //node 0 = root
}
/*xây dựng một Cây tiền tố (Trie)
Logic: 
       1. Bắt đầu từ gốc (ID 0).
       2. Với mỗi chữ cái trong từ khóa, kiểm tra xem đã có "nhánh" nào cho chữ cái đó chưa.
       3. Nếu chưa có, xây nhánh mới (ac_new_node).
       4. Cập nhật vị trí hiện tại u tiến sâu hơn vào trong cây.
*/
int ac_add_pattern(struct ac_automaton *ac, const uint8_t *pat, int len, int id ){
	int32_t u = 0; /* bắt đầu từ root */
	if(ac->built || !pat || len <=0 || id <0)		//Nếu máy đã được "xây xong" (đã gọi hàm ac_build), Đảm bảo từ khóa tồn tại, chiều dài dương và ID không âm
		return -1;
	for(int i = 0; i < len; i++){
		uint8_t c = ac_norm(ac->nocase, pat[i]);	// Chuẩn hóa ký tự
		if (ac->nodes[u].next[c] == -1) { // Nếu chưa có đường đi cho ký tự c
			int v = ac_new_node(ac);     // Tạo một node (trạm) mới
			if (v < 0) return -1;
			ac->nodes[u].next[c] = v;
		}
		u = ac->nodes[u].next[c];        // Nhảy tới node con để xử lý ký tự tiếp theo
	}
	ac->nodes[u].out = id;                  /* pattern kết thúc tại node này */
	return 0;
}
int ac_build(struct ac_automaton *ac){
	int32_t *queue;
	int      head = 0, tail = 0;
	if(ac->built) 
		return 0;
	//Chuan bi hang doi cho thuat toan BFS
	queue = malloc((size_t)ac->n_nodes * sizeof(int32_t));
	if (!queue)
		return -1;
	/* Duyet tang 1/Độ sâu 1 (ngay truc tiep duoi node root): cạnh trống của root quay về chính root (DFA self-loop);
	 * con trực tiếp của root có fail = root. */
	for (int c = 0; c < AC_ALPHABET; c++) {
		int32_t v = ac->nodes[0].next[c];

		if (v == -1) {
			ac->nodes[0].next[c] = 0;
		} else {
			ac->nodes[v].fail = 0;
			queue[tail++]     = v;
		}
	}
	/*BFS Loop*/
	while (head < tail) {
		int32_t u = queue[head++];
		int32_t f = ac->nodes[u].fail;

		for (int c = 0; c < AC_ALPHABET; c++) {
			int32_t v = ac->nodes[u].next[c];

			if (v == -1) {
				/* DFA goto: đọc c ở u mà không có cạnh → đi theo fail */
				ac->nodes[u].next[c] = ac->nodes[f].next[c];
			} else {
				int32_t vf = ac->nodes[f].next[c];   /* đã là DFA goto hợp lệ */

				ac->nodes[v].fail     = vf;
				ac->nodes[v].out_link =
					(ac->nodes[vf].out != -1) ? vf
								  : ac->nodes[vf].out_link;
				queue[tail++] = v;
			}
		}
	}
	free(queue);
	ac->built = 1;
	return 0;
}
int ac_search(const struct ac_automaton *ac, const uint8_t *text, size_t len,
	      int (*on_match)(int, size_t, void *), void *ctx){
	int32_t st   = 0;                       /* trạng thái hiện tại = root */
	int     hits = 0;						//đếm số lần tìm thấy từ khóa

	if (!ac->built)
		return -1;
for (size_t i = 0; i < len; i++) {      /* vòng lặp quét văn bản*/
		uint8_t c = ac_norm(ac->nocase, text[i]);

		st = ac->nodes[st].next[c];     /* sau build luôn != -1 */

		/* Đi theo output-link để liệt kê MỌI pattern kết thúc tại i. */
		for (int32_t t = st; t != -1; t = ac->nodes[t].out_link) {
			if (ac->nodes[t].out != -1) {
				hits++;
				if (on_match && on_match(ac->nodes[t].out, i, ctx))
					return hits;    /* caller yêu cầu dừng sớm */
			}
		}
	}
	return hits;
}

void ac_free(struct ac_automaton *ac)
{
	free(ac->nodes);
	memset(ac, 0, sizeof(*ac));
}