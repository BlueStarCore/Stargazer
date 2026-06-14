/* SPDX-License-Identifier: MIT */
/*
 * reass.c - Ráp dòng TCP 2 chiều + feed streaming Aho-Corasick (xem reass.h).
 *
 * Mỗi chiều: một cửa sổ tuyến tính [base_seq, base_seq+cap) + bitmap byte đã
 * nhận. Segment được đặt theo offset = seq - base_seq (wrap-safe). Vùng LIÊN
 * TỤC từ 0 (next_off) lớn tới đâu thì feed phần mới vào AC tới đó (streaming,
 * giữ node state). "A buffer is always checked": mọi ghi clamp vào [0,cap).
 */
#include "reass.h"

#include <stdlib.h>
#include <string.h>

/* Telemetry: tổng byte đã feed vào AC (main.c đọc qua extern để chẩn đoán
 * "ac_raw=0" — phân biệt reass không feed vs AC không trúng). */
unsigned long g_reass_fed;

/* ---- bitmap byte-đã-nhận ------------------------------------------------- */
static inline int bit_get(const uint8_t *bm, uint32_t i)
{
	return (bm[i >> 3] >> (i & 7)) & 1;
}
static inline void bit_set(uint8_t *bm, uint32_t i)
{
	bm[i >> 3] |= (uint8_t)(1u << (i & 7));
}
static inline void bit_clear(uint8_t *bm, uint32_t i)
{
	bm[i >> 3] &= (uint8_t)~(1u << (i & 7));
}

/* ---- trampoline để chèn `dir` vào callback người dùng -------------------- */
struct feed_ctx {
	reass_match_cb cb;
	void          *ctx;
	int            dir;
};
static int feed_trampoline(int id, uint64_t end_off, void *p)
{
	struct feed_ctx *f = p;
	return f->cb ? f->cb(id, end_off, f->dir, f->ctx) : 0;
}

/* ---- API ----------------------------------------------------------------- */

int reass_flow_init(struct reass_flow *rf, const struct ac_automaton *ac,
		    uint32_t cap_bytes)
{
	memset(rf, 0, sizeof(*rf));
	rf->ac = ac;
	uint32_t cap = cap_bytes ? cap_bytes : REASS_MAX_BYTES;

	for (int i = 0; i < 2; i++) {
		struct reass_dir *d = &rf->dir[i];
		d->cap        = cap;
		d->scan_limit = cap;            /* mặc định: soi tới hết cửa sổ */
		d->ac_state   = 0;
		d->buf      = malloc(cap);
		d->filled   = calloc(((size_t)cap + 7) / 8, 1);
		if (!d->buf || !d->filled) {
			reass_flow_free(rf);
			return -1;
		}
	}
	return 0;
}

int reass_segment(struct reass_flow *rf, int dir, uint32_t seq,
		  const uint8_t *data, uint32_t len,
		  reass_match_cb cb, void *ctx)
{
	if (!rf || dir < 0 || dir > 1 || !data)
		return REASS_FAILCLOSED;
	if (rf->failed)
		return REASS_FAILCLOSED;            /* sticky */

	struct reass_dir *d = &rf->dir[dir];
	if (!d->buf || !d->filled)
		return REASS_FAILCLOSED;
	if (len == 0)
		return REASS_OK;

	if (!d->have_base) {
		d->base_seq  = seq;
		d->have_base = 1;
	}

	/* offset trong cửa sổ (wrap-safe). */
	int64_t soff = (int32_t)(seq - d->base_seq);
	const uint8_t *p = data;
	uint32_t l = len;

	/* Segment bắt đầu TRƯỚC base (retransmit cũ) → clip phần đầu. */
	if (soff < 0) {
		uint64_t skip = (uint64_t)(-soff);
		if (skip >= l)
			return REASS_OK;            /* toàn bộ trước base → bỏ */
		p   += skip;
		l   -= (uint32_t)skip;
		soff = 0;
	}

	/* Ngoài cửa sổ K. */
	if ((uint64_t)soff >= d->cap) {
		/* Còn lỗ trống trong cửa sổ mà data đã vượt K quá xa → bất thường. */
		if (d->next_off < d->cap &&
		    (uint64_t)soff - d->next_off > REASS_GAP_LIMIT) {
			rf->failed = 1;
			return REASS_FAILCLOSED;
		}
		return REASS_OK;                    /* phần sau K → offload */
	}

	/* Ghi byte chưa có (first-wins: byte đến trước thắng). */
	uint32_t base = (uint32_t)soff;
	uint32_t end  = base + l;
	if (end > d->cap)
		end = d->cap;
	for (uint32_t o = base; o < end; o++) {
		if (!bit_get(d->filled, o)) {
			d->buf[o] = p[o - base];
			bit_set(d->filled, o);
		}
	}
	if (end > d->max_off)
		d->max_off = end;

	/* Mở rộng vùng liên tục [0,next_off). */
	while (d->next_off < d->cap && bit_get(d->filled, d->next_off))
		d->next_off++;

	/* Feed phần LIÊN TỤC MỚI vào AC (streaming, giữ node state) — CHỈ tới
	 * scan_limit (P1: bỏ qua thân quá budget, không tốn AC). */
	uint32_t feed_to = (d->next_off < d->scan_limit) ? d->next_off
							 : d->scan_limit;
	if (rf->ac && feed_to > d->scanned) {
		struct feed_ctx fctx = { cb, ctx, dir };
		g_reass_fed += (feed_to - d->scanned);   /* telemetry: byte feed vào AC */
		ac_search_stream(rf->ac, &d->ac_state,
				 d->buf + d->scanned,
				 feed_to - d->scanned,
				 d->scanned,            /* stream_off (trong dòng) */
				 feed_trampoline, &fctx);
		d->scanned = feed_to;
	}

	/* Lỗ trống quá hạn: còn trống trong cửa sổ nhưng data chất sau quá nhiều. */
	if (d->next_off < d->cap &&
	    d->max_off - d->next_off > REASS_GAP_LIMIT) {
		rf->failed = 1;
		return REASS_FAILCLOSED;
	}
	return REASS_OK;
}

void reass_flow_rebind(struct reass_flow *rf, const struct ac_automaton *ac,
		       reass_match_cb cb, void *ctx)
{
	if (!rf)
		return;
	rf->ac = ac;
	for (int dir = 0; dir < 2; dir++) {
		struct reass_dir *d = &rf->dir[dir];
		d->ac_state   = 0;      /* node index cũ vô nghĩa với automaton mới */
		d->scanned    = 0;
		d->scan_limit = d->cap; /* re-scan toàn bộ cửa sổ với ruleset mới */
		if (ac && d->buf && d->next_off > 0) {
			struct feed_ctx fctx = { cb, ctx, dir };
			ac_search_stream(ac, &d->ac_state, d->buf, d->next_off,
					 0, feed_trampoline, &fctx);
			d->scanned = d->next_off;
		}
	}
}

void reass_consume(struct reass_flow *rf, int dir, uint32_t n, int reset_ac,
		   reass_match_cb cb, void *ctx)
{
	if (!rf || dir < 0 || dir > 1)
		return;
	struct reass_dir *d = &rf->dir[dir];
	if (!d->buf)
		return;
	if (n > d->next_off)
		n = d->next_off;            /* chỉ bỏ phần liên tục đã có */

	if (n > 0) {
		uint32_t keep = (d->max_off > n) ? d->max_off - n : 0;
		if (keep > 0)
			memmove(d->buf, d->buf + n, keep);
		/* trượt bitmap xuống n bit */
		for (uint32_t o = 0; o < keep; o++) {
			if (bit_get(d->filled, o + n)) bit_set(d->filled, o);
			else                           bit_clear(d->filled, o);
		}
		for (uint32_t o = keep; o < d->max_off; o++)
			bit_clear(d->filled, o);

		d->base_seq += n;
		d->next_off  = (d->next_off > n) ? d->next_off - n : 0;
		d->max_off   = keep;
		d->scanned   = (d->scanned > n) ? d->scanned - n : 0;
		d->scan_limit = (d->scan_limit > n) ? d->scan_limit - n : 0;
	}

	if (reset_ac) {
		d->ac_state   = 0;
		d->scanned    = 0;
		d->scan_limit = d->cap;     /* transaction mới: soi tự do tới khi đặt budget */
		if (rf->ac && d->next_off > 0) {
			struct feed_ctx fctx = { cb, ctx, dir };
			ac_search_stream(rf->ac, &d->ac_state, d->buf,
					 d->next_off, 0, feed_trampoline, &fctx);
			d->scanned = d->next_off;
		}
	}
}

void reass_set_scan_limit(struct reass_flow *rf, int dir, uint32_t limit,
			  reass_match_cb cb, void *ctx)
{
	if (!rf || dir < 0 || dir > 1)
		return;
	struct reass_dir *d = &rf->dir[dir];
	if (limit > d->cap) limit = d->cap;
	d->scan_limit = limit;

	/* Nâng limit → soi nốt phần đã đệm trong giới hạn mới. */
	uint32_t feed_to = (d->next_off < d->scan_limit) ? d->next_off
							 : d->scan_limit;
	if (rf->ac && feed_to > d->scanned) {
		struct feed_ctx fctx = { cb, ctx, dir };
		ac_search_stream(rf->ac, &d->ac_state, d->buf + d->scanned,
				 feed_to - d->scanned, d->scanned,
				 feed_trampoline, &fctx);
		d->scanned = feed_to;
	}
}

const uint8_t *reass_dir_buf(const struct reass_flow *rf, int dir,
			     uint32_t *contig_len)
{
	if (!rf || dir < 0 || dir > 1)
		return NULL;
	if (contig_len)
		*contig_len = rf->dir[dir].next_off;
	return rf->dir[dir].buf;
}

uint32_t reass_inspected_bytes(const struct reass_flow *rf)
{
	if (!rf)
		return 0;
	return rf->dir[0].next_off + rf->dir[1].next_off;
}

void reass_flow_free(struct reass_flow *rf)
{
	if (!rf)
		return;
	for (int i = 0; i < 2; i++) {
		free(rf->dir[i].buf);
		free(rf->dir[i].filled);
		rf->dir[i].buf    = NULL;
		rf->dir[i].filled = NULL;
	}
	rf->ac = NULL;
}
