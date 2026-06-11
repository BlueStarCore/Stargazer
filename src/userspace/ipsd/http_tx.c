/* SPDX-License-Identifier: MIT */
/*
 * http_tx.c - Máy trạng thái transaction HTTP request (xem http_tx.h).
 *
 * Mọi truy cập buffer bounds-check; số học độ dài clamp. Nguyên tắc: SOI MỌI
 * transaction (không cap tích lũy), free ngay khi xong (RAM phẳng), vượt
 * concurrency → anomaly (không thả).
 */
#include "http_tx.h"

#include <string.h>

static const char *const METHODS[] = {
	"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS",
	"CONNECT", "TRACE", "PATCH", NULL
};

/* Độ dài method nếu buf bắt đầu bằng "METHOD " hợp lệ, 0 nếu không. */
static int method_len(const uint8_t *b, uint32_t len)
{
	for (int i = 0; METHODS[i]; i++) {
		uint32_t m = (uint32_t)strlen(METHODS[i]);
		if (len > m && memcmp(b, METHODS[i], m) == 0 && b[m] == ' ')
			return (int)m;
	}
	return 0;
}

/* body_start (offset sau CRLFCRLF / LFLF), -1 nếu chưa thấy. */
static int find_header_end(const uint8_t *b, uint32_t len)
{
	for (uint32_t i = 0; i + 1 < len; i++) {
		if (b[i] == '\n' && b[i + 1] == '\n')
			return (int)(i + 2);
		if (i + 3 < len && b[i] == '\r' && b[i + 1] == '\n' &&
		    b[i + 2] == '\r' && b[i + 3] == '\n')
			return (int)(i + 4);
	}
	return -1;
}

/* Tìm key (case-insensitive) trong [0,len); trả vị trí NGAY SAU key, -1 nếu không. */
static int ci_find(const uint8_t *b, uint32_t len, const char *key)
{
	uint32_t kl = (uint32_t)strlen(key);
	if (kl == 0 || len < kl)
		return -1;
	for (uint32_t i = 0; i + kl <= len; i++) {
		uint32_t j = 0;
		for (; j < kl; j++) {
			uint8_t c = b[i + j];
			if (c >= 'A' && c <= 'Z') c = (uint8_t)(c + 32);
			uint8_t k = (uint8_t)key[j];
			if (k >= 'A' && k <= 'Z') k = (uint8_t)(k + 32);
			if (c != k) break;
		}
		if (j == kl)
			return (int)(i + kl);
	}
	return -1;
}

static uint64_t parse_content_length(const uint8_t *b, uint32_t hlen)
{
	int p = ci_find(b, hlen, "content-length:");
	if (p < 0)
		return 0;
	uint32_t i = (uint32_t)p;
	while (i < hlen && (b[i] == ' ' || b[i] == '\t')) i++;
	uint64_t v = 0;
	int got = 0;
	while (i < hlen && b[i] >= '0' && b[i] <= '9') {
		v = v * 10 + (uint64_t)(b[i] - '0');
		got = 1;
		i++;
		if (v > 0xFFFFFFFFULL) { v = 0xFFFFFFFFULL; break; }  /* clamp */
	}
	return got ? v : 0;
}

static int has_conn_close(const uint8_t *b, uint32_t hlen)
{
	int p = ci_find(b, hlen, "connection:");
	if (p < 0)
		return 0;
	uint32_t i = (uint32_t)p, eol = hlen;
	for (uint32_t j = i; j < hlen; j++)
		if (b[j] == '\n') { eol = j; break; }
	return ci_find(b + i, (eol > i) ? eol - i : 0, "close") >= 0;
}

/* So tiền tố (case-insensitive) b[0..len) bắt đầu bằng pfx? */
static int ci_prefix(const uint8_t *b, uint32_t len, const char *pfx)
{
	uint32_t pl = (uint32_t)strlen(pfx);
	if (len < pl) return 0;
	for (uint32_t i = 0; i < pl; i++) {
		uint8_t c = b[i]; if (c >= 'A' && c <= 'Z') c = (uint8_t)(c + 32);
		uint8_t k = (uint8_t)pfx[i]; if (k >= 'A' && k <= 'Z') k = (uint8_t)(k + 32);
		if (c != k) return 0;
	}
	return 1;
}

/* Số byte soi đầu thân khi offload-tĩnh (header + ít magic rồi bỏ thân). */
#define STATIC_BODY_SCAN 512

/*
 * Intelligent-mode (always-on): Content-Type là loại TĨNH-nhị-phân + magic byte
 * KHỚP → cho offload thân sớm (soi header + magic, bỏ phần thân nặng). KHÔNG tin
 * Content-Type mù quáng: magic không khớp loại khai → soi đủ. need_more=1: chưa
 * đủ byte magic để quyết → caller chờ (fail-safe, không offload khi chưa chắc).
 */
static int static_offload_ok(const uint8_t *b, uint32_t hlen, uint32_t body_start,
			     uint32_t contig, int *need_more)
{
	*need_more = 0;
	int p = ci_find(b, hlen, "content-type:");
	if (p < 0) return 0;                       /* thiếu → soi đủ */
	uint32_t i = (uint32_t)p;
	while (i < hlen && (b[i] == ' ' || b[i] == '\t')) i++;

	static const struct { const char *ct; const char *magic; int mlen; } TBL[] = {
		{ "image/png",  "\x89PNG",       4 },
		{ "image/jpeg", "\xff\xd8\xff",  3 },
		{ "image/gif",  "GIF8",          4 },
	};
	for (int k = 0; k < 3; k++) {
		if (!ci_prefix(b + i, hlen - i, TBL[k].ct))
			continue;
		uint32_t need = body_start + (uint32_t)TBL[k].mlen;
		if (contig < need) { *need_more = 1; return 0; }   /* chờ magic */
		return memcmp(b + body_start, TBL[k].magic,
			      (size_t)TBL[k].mlen) == 0;            /* khớp magic? */
	}
	return 0;                                  /* loại khác → soi đủ */
}

void http_tx_init(struct http_tx *h, uint32_t budget)
{
	memset(h, 0, sizeof(*h));
	h->tx_budget = budget ? budget : REASS_MAX_BYTES;
}

void http_tx_step(struct http_tx *h, struct reass_flow *rf,
		  reass_match_cb cb, void *ctx)
{
	h->want_watch = 0;
	h->want_inspected = 0;
	if (h->anomaly)
		return;
	if (h->proto == HTX_NONHTTP) {
		h->want_inspected = 1;   /* không HTTP → soi như payload thô + thả */
		return;
	}

	/* Mô hình TUẦN TỰ: xử lý 1 tx/lần, free trước khi sang tx kế → không có tx
	 * đồng thời. `processed` đếm tx trong MỘT step (bound vòng lặp + chống
	 * request-flood trong 1 cửa sổ); vượt MAX → anomaly (KHÔNG thả). */
	int processed = 0;

	for (;;) {
		uint32_t contig;
		const uint8_t *buf = reass_dir_buf(rf, REASS_TO_SERVER, &contig);
		if (!buf)
			return;

		/* SKIP_BODY: bỏ thân quá budget (consume không soi) */
		if (h->skip > 0) {
			uint32_t take = (contig < h->skip) ? contig : h->skip;
			if (take > 0) {
				int last = (take == h->skip);
				reass_consume(rf, REASS_TO_SERVER, take, last, cb, ctx);
				h->skip -= take;
			}
			if (h->skip > 0) { h->want_watch = 1; return; }
			continue;                            /* thân xong → parse tx kế */
		}

		if (contig == 0) { h->want_watch = 1; return; }

		/* Phân loại non-HTTP: đủ byte mà không bắt đầu bằng method. */
		if (!h->tx_open && method_len(buf, contig) == 0) {
			if (contig >= 8) { h->proto = HTX_NONHTTP;
					   h->want_inspected = 1; return; }
			h->want_watch = 1; return;
		}
		h->proto = HTX_HTTP;

		int bs = find_header_end(buf, contig);
		if (bs < 0) {
			if (contig > HTTP_MAX_HEADER) { h->anomaly = 1; return; }
			h->want_watch = 1; return;          /* header chưa đủ */
		}
		uint32_t body_start = (uint32_t)bs;

		h->tx_open = 1;

		uint64_t cl = parse_content_length(buf, body_start);
		int conn_close = has_conn_close(buf, body_start);
		uint64_t tx_total = (uint64_t)body_start + cl;

		/* Intelligent-mode (2 pha): budget mặc định = K; HẠ khi chắc lành-
		 * tĩnh (Content-Type + magic). Pha 1: nếu chưa đủ byte để check
		 * magic → KẸP scan tới cửa sổ peek (không soi thân vội) + chờ. */
		uint32_t eff_budget = h->tx_budget;
		if (cl > 0) {
			int need_more = 0;
			int isstatic = static_offload_ok(buf, body_start,
					body_start, contig, &need_more);
			if (need_more) {
				reass_set_scan_limit(rf, REASS_TO_SERVER,
					body_start + 16, cb, ctx);  /* chỉ soi magic */
				h->want_watch = 1; return;
			}
			if (isstatic)
				eff_budget = body_start + STATIC_BODY_SCAN;
		}

		uint64_t scan_target = (tx_total < eff_budget)
				     ? tx_total : eff_budget;
		/* Đặt giới hạn feed AC = scan_target (NÂNG → soi nốt phần đệm trong
		 * giới hạn; byte thân quá budget không bao giờ bị soi). */
		reass_set_scan_limit(rf, REASS_TO_SERVER,
				     (uint32_t)scan_target, cb, ctx);
		if (contig < scan_target) { h->want_watch = 1; return; }  /* chờ budget */

		/* budget đã soi (reass auto-scan tới contig). Chốt transaction. */
		h->tx_open = 0;
		if (++processed > HTTP_MAX_LIVE_TX) {   /* request-flood 1 cửa sổ */
			h->live_tx = (uint32_t)processed;
			h->anomaly = 1;
			return;
		}
		h->live_tx = (uint32_t)processed;

		if (tx_total <= contig) {
			reass_consume(rf, REASS_TO_SERVER,
				      (uint32_t)tx_total, 1, cb, ctx);
			if (conn_close) { h->want_inspected = 1; return; }
			continue;                            /* keep-alive → tx kế */
		}

		/* tx lớn hơn budget/cửa sổ → consume phần đã soi, skip thân còn lại */
		reass_consume(rf, REASS_TO_SERVER, contig, 1, cb, ctx);
		h->skip = (uint32_t)(tx_total - contig);
		h->want_watch = 1;
		return;
	}
}
