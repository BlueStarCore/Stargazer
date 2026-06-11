/* SPDX-License-Identifier: MIT */
/*
 * http_tx_test.c - Unit test re-arm transaction HTTP, chạy HOST.
 *
 *   cc -O2 -Wall -Wextra -fsanitize=address,undefined \
 *      -o /tmp/http_tx_test ac.c reass.c http_tx.c http_tx_test.c && /tmp/http_tx_test
 */
#include "http_tx.h"
#include "ac.h"

#include <stdio.h>
#include <string.h>

static int g_failed;
static void check(int cond, const char *name)
{
	printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
	if (!cond) g_failed++;
}

struct collected { int n; int ids[128]; };
static int on_m(int id, uint64_t end, int dir, void *ctx)
{
	(void)end; (void)dir;
	struct collected *c = ctx;
	if (c->n < 128) c->ids[c->n++] = id;
	return 0;
}
static int has_id(const struct collected *c, int id)
{
	for (int i = 0; i < c->n; i++) if (c->ids[i] == id) return 1;
	return 0;
}

#define BASE 1000u

int main(void)
{
	struct ac_automaton ac;
	ac_init(&ac, 0);
	ac_add_pattern(&ac, (const uint8_t *)"EXPLOIT", 7, 0);
	ac_build(&ac);

	printf("T1 keep-alive 60 request: exploit ở #50 VẪN bắt (không cap tích lũy):\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct http_tx h; http_tx_init(&h, 0);
		struct collected c = {0};
		uint32_t seq = BASE;
		for (int i = 0; i < 60; i++) {
			char req[128];
			int n = snprintf(req, sizeof(req),
				i == 50 ? "GET /EXPLOIT%d HTTP/1.1\r\nHost: x\r\n\r\n"
					: "GET /page%d HTTP/1.1\r\nHost: x\r\n\r\n", i);
			reass_segment(&rf, REASS_TO_SERVER, seq,
				      (const uint8_t *)req, (uint32_t)n, on_m, &c);
			http_tx_step(&h, &rf, on_m, &c);
			seq += (uint32_t)n;
		}
		check(has_id(&c, 0), "EXPLOIT ở request #50 được bắt");
		check(h.anomaly == 0, "không anomaly");
		uint32_t cl; reass_dir_buf(&rf, REASS_TO_SERVER, &cl);
		check(cl < 256, "RAM phẳng: cửa sổ nhỏ sau 60 tx");
		reass_flow_free(&rf);
	}

	printf("T2 thân lớn quá budget → skip, request kế VẪN soi:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct http_tx h; http_tx_init(&h, 256);   /* budget nhỏ để ép skip */
		struct collected c = {0};
		uint32_t seq = BASE;

		/* POST có thân 4000 byte (vượt budget 256) */
		char hdr[128];
		int hn = snprintf(hdr, sizeof(hdr),
			"POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 4000\r\n\r\n");
		reass_segment(&rf, REASS_TO_SERVER, seq, (const uint8_t *)hdr,
			      (uint32_t)hn, on_m, &c);
		http_tx_step(&h, &rf, on_m, &c);
		seq += (uint32_t)hn;
		/* gửi thân 4000 byte (sẽ bị skip dần) */
		char body[1000]; memset(body, 'A', sizeof(body));
		for (int k = 0; k < 4; k++) {
			reass_segment(&rf, REASS_TO_SERVER, seq,
				      (const uint8_t *)body, 1000, on_m, &c);
			http_tx_step(&h, &rf, on_m, &c);
			seq += 1000;
		}
		/* request kế chứa EXPLOIT */
		char nxt[128];
		int nn = snprintf(nxt, sizeof(nxt),
			"GET /EXPLOIT HTTP/1.1\r\nHost: x\r\n\r\n");
		reass_segment(&rf, REASS_TO_SERVER, seq, (const uint8_t *)nxt,
			      (uint32_t)nn, on_m, &c);
		http_tx_step(&h, &rf, on_m, &c);
		check(has_id(&c, 0), "request sau thân-lớn vẫn soi → EXPLOIT bắt");
		check(h.skip == 0, "skip về 0 sau khi drain thân");
		reass_flow_free(&rf);
	}

	printf("T3 Connection: close → want_inspected (thả):\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct http_tx h; http_tx_init(&h, 0);
		struct collected c = {0};
		const char *req = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
		reass_segment(&rf, REASS_TO_SERVER, BASE, (const uint8_t *)req,
			      (uint32_t)strlen(req), on_m, &c);
		http_tx_step(&h, &rf, on_m, &c);
		check(h.want_inspected == 1, "Connection: close → want_inspected");
		reass_flow_free(&rf);
	}

	printf("T4 non-HTTP → want_inspected:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct http_tx h; http_tx_init(&h, 0);
		struct collected c = {0};
		const char *bin = "\x01\x02\x03\x04SSHSTUFF";
		reass_segment(&rf, REASS_TO_SERVER, BASE, (const uint8_t *)bin, 12,
			      on_m, &c);
		http_tx_step(&h, &rf, on_m, &c);
		check(h.proto == HTX_NONHTTP && h.want_inspected == 1,
		      "không phải HTTP → NONHTTP + thả");
		reass_flow_free(&rf);
	}

	printf("T5 request-flood > MAX_LIVE_TX trong 1 cửa sổ → anomaly:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct http_tx h; http_tx_init(&h, 0);
		struct collected c = {0};
		/* nhồi nhiều request tí hon vào 1 segment */
		char big[8192]; int off = 0;
		for (int i = 0; i < HTTP_MAX_LIVE_TX + 5 && off < (int)sizeof(big) - 20; i++)
			off += snprintf(big + off, sizeof(big) - off, "GET / HTTP/1.0\r\n\r\n");
		reass_segment(&rf, REASS_TO_SERVER, BASE, (const uint8_t *)big,
			      (uint32_t)off, on_m, &c);
		http_tx_step(&h, &rf, on_m, &c);
		check(h.anomaly == 1, "flood request → anomaly (không thả)");
		reass_flow_free(&rf);
	}

	printf("T6 header flood (không kết thúc) → anomaly:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct http_tx h; http_tx_init(&h, 0);
		struct collected c = {0};
		char hdr[9000]; memset(hdr, 'a', sizeof(hdr));
		memcpy(hdr, "GET /", 5);
		reass_segment(&rf, REASS_TO_SERVER, BASE, (const uint8_t *)hdr,
			      sizeof(hdr), on_m, &c);
		http_tx_step(&h, &rf, on_m, &c);
		check(h.anomaly == 1, "header > HTTP_MAX_HEADER không kết thúc → anomaly");
		reass_flow_free(&rf);
	}

	printf("T7 intelligent-mode: image/png + magic ĐÚNG → offload thân sớm:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct http_tx h; http_tx_init(&h, 0);   /* budget K mặc định */
		struct collected c = {0};
		uint32_t seq = BASE;
		const char *hdr = "POST /u HTTP/1.1\r\nHost: x\r\n"
			"Content-Type: image/png\r\nContent-Length: 4000\r\n\r\n";
		int hn = (int)strlen(hdr);
		reass_segment(&rf, REASS_TO_SERVER, seq, (const uint8_t *)hdr,
			      (uint32_t)hn, on_m, &c);
		http_tx_step(&h, &rf, on_m, &c);
		seq += (uint32_t)hn;
		/* thân: magic PNG đầu, EXPLOIT chôn ở offset 2000 (> budget 512) */
		uint8_t body[4000]; memset(body, 'A', sizeof(body));
		memcpy(body, "\x89PNG", 4);
		memcpy(body + 2000, "EXPLOIT", 7);
		reass_segment(&rf, REASS_TO_SERVER, seq, body, sizeof(body), on_m, &c);
		http_tx_step(&h, &rf, on_m, &c);
		check(!has_id(&c, 0),
		      "EXPLOIT giấu sâu trong ảnh tĩnh → bị bỏ (offload, giới hạn honesty)");
		reass_flow_free(&rf);
	}

	printf("T8 chống khai man: Content-Type image nhưng magic SAI → soi đủ:\n");
	{
		struct reass_flow rf; reass_flow_init(&rf, &ac, 0);
		struct http_tx h; http_tx_init(&h, 0);
		struct collected c = {0};
		uint32_t seq = BASE;
		const char *hdr = "POST /u HTTP/1.1\r\nHost: x\r\n"
			"Content-Type: image/png\r\nContent-Length: 4000\r\n\r\n";
		int hn = (int)strlen(hdr);
		reass_segment(&rf, REASS_TO_SERVER, seq, (const uint8_t *)hdr,
			      (uint32_t)hn, on_m, &c);
		http_tx_step(&h, &rf, on_m, &c);
		seq += (uint32_t)hn;
		uint8_t body[4000]; memset(body, 'A', sizeof(body));
		memcpy(body, "MZ", 2);                 /* magic KHÔNG phải PNG */
		memcpy(body + 2000, "EXPLOIT", 7);
		reass_segment(&rf, REASS_TO_SERVER, seq, body, sizeof(body), on_m, &c);
		http_tx_step(&h, &rf, on_m, &c);
		check(has_id(&c, 0),
		      "khai image nhưng magic sai → soi đủ → EXPLOIT vẫn bắt");
		reass_flow_free(&rf);
	}

	ac_free(&ac);
	printf("\n%s (%d test thất bại)\n",
	       g_failed ? "=== CÓ LỖI ===" : "=== TẤT CẢ PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
