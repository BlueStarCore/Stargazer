/* SPDX-License-Identifier: MIT */
/*
 * reass.h - Ráp dòng TCP 2 chiều + feed streaming Aho-Corasick (P1).
 *
 * Vì sao cần: match per-packet bị né bằng cách CẮT content qua 2 segment, NHỒI
 * gói, hoặc ĐẢO thứ tự. Ta ráp lại dòng theo seq rồi feed phần BYTE LIÊN TỤC
 * mới vào AC ở chế độ streaming (giữ state node → không quét lại) nên pattern
 * vắt qua nhiều segment vẫn bắt được, và offset/depth/distance tính theo vị trí
 * TRONG DÒNG (không phải trong gói).
 *
 * Phạm vi / cửa sổ: mỗi chiều soi tối đa K = cap byte LIÊN TỤC (mặc định
 * REASS_MAX_BYTES). Hết K → đã soi đủ, caller offload (đặt connmark INSPECTED).
 *
 * Chống tấn công (BẮT BUỘC — không âm thầm cho qua):
 *   - Dữ liệu chất đống sau MỘT lỗ trống mãi không lấp (> REASS_GAP_LIMIT byte)
 *     → bất thường → fail-closed (caller block flow). Chống mánh "giữ lỗ trống
 *     vắt kiệt buffer / né soi".
 *   - Overlap segment khác dữ liệu: first-wins (byte ĐẾN TRƯỚC thắng) — nhất
 *     quán, chống mánh chèn-đè để qua mặt chữ ký.
 *   - Mọi số học seq wrap-safe ((int32_t)(a-b)); bytes ngoài cửa sổ bị clamp.
 *
 * UDP/ICMP không có stream → caller match thẳng payload gói (không qua reass).
 */
#ifndef SG_REASS_H
#define SG_REASS_H

#include <stdint.h>
#include <stddef.h>
#include "ac.h"

#define REASS_MAX_BYTES   16384   /* K: cửa sổ soi mỗi chiều (cấu hình sau)     */
#define REASS_GAP_LIMIT    4096   /* dữ liệu chất sau lỗ trống quá mức → fail   */

enum reass_dir_id { REASS_TO_SERVER = 0, REASS_TO_CLIENT = 1 };

/* Trả của reass_segment. */
#define REASS_OK          0
#define REASS_FAILCLOSED (-1)     /* lỗ trống quá hạn / quá tải → block flow    */

/*
 * Callback khi AC fast-pattern trúng trên DÒNG ĐÃ GHÉP.
 *   rule_id : id pattern (== index rule trong ruleset).
 *   end_off : offset (trong dòng, 0-based) của byte CUỐI pattern.
 *   dir     : REASS_TO_SERVER / REASS_TO_CLIENT.
 * Trả khác 0 để dừng feed sớm (vd đã có verdict DROP).
 */
typedef int (*reass_match_cb)(int rule_id, uint64_t end_off, int dir, void *ctx);

/* Một chiều của dòng. */
struct reass_dir {
	uint8_t  *buf;        /* cửa sổ tuyến tính [base_seq, base_seq+cap)        */
	uint8_t  *filled;     /* bitmap byte đã nhận ((cap+7)/8 byte)              */
	uint32_t  cap;        /* = K                                              */
	uint32_t  base_seq;   /* seq ứng với buf[0]                               */
	uint32_t  next_off;   /* [0,next_off) đã LIÊN TỤC (đã/được feed tới đây)   */
	uint32_t  max_off;    /* offset+1 cao nhất đã ghi (để đo gap)             */
	uint32_t  scanned;    /* đã feed AC tới offset này (== next_off sau feed)  */
	uint32_t  scan_limit; /* P1 — chỉ feed AC tới offset này (budget tx); =cap mặc định */
	int32_t   ac_state;   /* node DFA streaming (0 = root)                    */
	uint8_t   have_base;  /* base_seq đã đặt từ segment đầu?                  */
};

struct reass_flow {
	const struct ac_automaton *ac;   /* automaton dùng chung của ruleset      */
	struct reass_dir dir[2];
	uint8_t  failed;                 /* đã fail-closed (lỗ trống/quá tải)     */
};

/*
 * Khởi tạo flow reassembly. cap_bytes=0 → dùng REASS_MAX_BYTES.
 * ac có thể NULL (chỉ ráp, không feed — hiếm dùng). Trả 0 / -1 (hết bộ nhớ).
 */
int  reass_flow_init(struct reass_flow *rf, const struct ac_automaton *ac,
		     uint32_t cap_bytes);

/*
 * Nạp một segment TCP của chiều `dir`. seq = seq number của byte payload ĐẦU.
 * Ráp vào đúng vị trí, feed phần liên tục MỚI vào AC (qua cb). Idempotent với
 * retransmit/overlap (first-wins). Trả REASS_OK hoặc REASS_FAILCLOSED.
 * Sau khi đã fail-closed, mọi lần gọi tiếp trả REASS_FAILCLOSED (sticky).
 */
int  reass_segment(struct reass_flow *rf, int dir, uint32_t seq,
		   const uint8_t *data, uint32_t len,
		   reass_match_cb cb, void *ctx);

/*
 * Đổi automaton (hot-reload ruleset): node-state cũ vô nghĩa với automaton mới.
 * Reset ac_state=0 + scanned=0 mỗi chiều rồi RE-SCAN lại dòng đã ghép [0,next_off)
 * bằng `ac` mới (bắt pattern mới trên byte đã có). Giữ nguyên buffer/filled/
 * next_off + cờ failed. cb/ctx để nhận match khi re-scan (có thể NULL).
 * Caller PHẢI gọi khi phát hiện ruleset đổi, TRƯỚC khi feed segment mới (nếu
 * không sẽ deref node index cũ trên automaton mới → sai/UAF).
 */
void reass_flow_rebind(struct reass_flow *rf, const struct ac_automaton *ac,
		       reass_match_cb cb, void *ctx);

/*
 * P1 re-arm — BỎ `n` byte liên tục ở ĐẦU cửa sổ chiều `dir` (transaction đã
 * soi xong → free để RAM phẳng dù keep-alive nghìn request). Trượt buffer +
 * bitmap + base_seq; n bị kẹp ≤ next_off. reset_ac=1 → bắt đầu transaction
 * MỚI: reset node-state + re-scan phần còn lại bằng `cb` (content không khớp
 * vắt qua ranh giới transaction — đúng ngữ nghĩa Suricata per-transaction).
 */
void reass_consume(struct reass_flow *rf, int dir, uint32_t n, int reset_ac,
		   reass_match_cb cb, void *ctx);

/*
 * P1 intelligent-mode — đặt giới hạn feed AC (offset window) cho chiều `dir`:
 * byte ≥ limit KHÔNG được soi (bỏ qua thân quá budget mà không tốn AC). NÂNG
 * limit → feed ngay phần đã đệm trong [scanned, min(next_off,limit)) (để byte
 * tới trước khi quyết budget vẫn được soi). Reset về cap khi sang transaction
 * mới (reass_consume reset_ac). limit kẹp ≤ cap.
 */
void reass_set_scan_limit(struct reass_flow *rf, int dir, uint32_t limit,
			  reass_match_cb cb, void *ctx);

/*
 * Con trỏ tới dòng đã ghép của chiều `dir` + độ dài LIÊN TỤC (cho verify rule
 * trên dòng). *contig_len = next_off. Trả NULL nếu dir sai.
 */
const uint8_t *reass_dir_buf(const struct reass_flow *rf, int dir,
			     uint32_t *contig_len);

/* Tổng byte đã soi (liên tục) cả 2 chiều — caller so với K để offload. */
uint32_t reass_inspected_bytes(const struct reass_flow *rf);

void reass_flow_free(struct reass_flow *rf);

#endif /* SG_REASS_H */
