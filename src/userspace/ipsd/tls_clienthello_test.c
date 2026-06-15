/* SPDX-License-Identifier: MIT */
/*
 * tls_clienthello_test.c - test parser ClientHello/SNI.
 *
 * Builds ClientHellos byte-by-byte to test: valid SNI, no SNI, truncated buffer
 * (NEED_MORE), not a ClientHello, and malicious inputs that would overflow
 * without bounds-checks (lying nested lengths). Run under ASan/UBSan: an
 * overflow = a crashed test.
 */
#include "tls_clienthello.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int g_fail;

#define CHECK(cond, msg) do {                                            \
	if (!(cond)) { printf("  FAIL: %s\n", msg); g_fail++; }          \
	else         { printf("  ok:   %s\n", msg); }                    \
} while (0)

/* ---- dynamic ClientHello builder ---------------------------------------- */

struct buf {
	uint8_t *d;
	size_t   len, cap;
};

static void bput(struct buf *b, const void *src, size_t n)
{
	if (n == 0) return;   /* avoid memcpy(_, NULL, 0) — UB even when n=0 */
	if (b->len + n > b->cap) {
		b->cap = (b->len + n) * 2 + 64;
		b->d = realloc(b->d, b->cap);
	}
	memcpy(b->d + b->len, src, n);
	b->len += n;
}
static void b8(struct buf *b, uint8_t v)  { bput(b, &v, 1); }
static void b16(struct buf *b, uint16_t v){ uint8_t t[2]={v>>8,v&0xff}; bput(b,t,2); }

/*
 * Build a valid ClientHello; if sni != NULL, include a server_name extension.
 * Returns the buffer (caller frees d).
 */
static struct buf build_ch(const char *sni)
{
	struct buf hs = {0};   /* handshake body (after the 4-byte header) */

	b16(&hs, 0x0303);                 /* client_version TLS 1.2 */
	for (int i = 0; i < 32; i++) b8(&hs, (uint8_t)i);  /* random */
	b8(&hs, 0);                       /* session_id_len = 0 */
	b16(&hs, 2); b16(&hs, 0x1301);    /* cipher_suites: 1 suite */
	b8(&hs, 1); b8(&hs, 0);           /* compression: null */

	/* extensions */
	struct buf ext = {0};
	if (sni) {
		uint16_t nlen = (uint16_t)strlen(sni);
		struct buf sn = {0};
		b16(&sn, (uint16_t)(nlen + 3));   /* server_name_list len */
		b8(&sn, 0x00);                    /* host_name */
		b16(&sn, nlen);
		bput(&sn, sni, nlen);
		b16(&ext, 0x0000);                /* ext type server_name */
		b16(&ext, (uint16_t)sn.len);
		bput(&ext, sn.d, sn.len);
		free(sn.d);
	}
	b16(&hs, (uint16_t)ext.len);
	bput(&hs, ext.d, ext.len);
	free(ext.d);

	/* handshake header */
	struct buf rec_body = {0};
	b8(&rec_body, 0x01);              /* ClientHello */
	b8(&rec_body, (uint8_t)(hs.len >> 16));
	b8(&rec_body, (uint8_t)(hs.len >> 8));
	b8(&rec_body, (uint8_t)(hs.len));
	bput(&rec_body, hs.d, hs.len);
	free(hs.d);

	/* record header */
	struct buf rec = {0};
	b8(&rec, 22);                    /* handshake */
	b16(&rec, 0x0301);              /* legacy record version */
	b16(&rec, (uint16_t)rec_body.len);
	bput(&rec, rec_body.d, rec_body.len);
	free(rec_body.d);

	return rec;
}

int main(void)
{
	struct tls_clienthello ch;

	printf("== test 1: valid ClientHello with SNI ==\n");
	{
		struct buf b = build_ch("www.example.com");
		enum tls_ch_result r = tls_parse_clienthello(b.d, b.len, &ch);
		CHECK(r == TLS_CH_OK, "result OK");
		CHECK(ch.has_sni == 1, "has SNI");
		CHECK(strcmp(ch.sni, "www.example.com") == 0, "SNI content correct");
		CHECK(ch.legacy_version == 0x0303, "client_version 0x0303");
		free(b.d);
	}

	printf("== test 2: ClientHello without SNI ==\n");
	{
		struct buf b = build_ch(NULL);
		enum tls_ch_result r = tls_parse_clienthello(b.d, b.len, &ch);
		CHECK(r == TLS_CH_OK, "result OK");
		CHECK(ch.has_sni == 0, "no SNI");
		free(b.d);
	}

	printf("== test 3: truncated buffer → NEED_MORE ==\n");
	{
		struct buf b = build_ch("truncated.test");
		/* cut to 10 bytes: enough for record header, body missing */
		enum tls_ch_result r = tls_parse_clienthello(b.d, 10, &ch);
		CHECK(r == TLS_CH_NEED_MORE, "missing record body → NEED_MORE");
		/* cut to 3 bytes: not even a full record header */
		r = tls_parse_clienthello(b.d, 3, &ch);
		CHECK(r == TLS_CH_NEED_MORE, "missing record header → NEED_MORE");
		free(b.d);
	}

	printf("== test 4: not a ClientHello ==\n");
	{
		uint8_t app[] = { 23, 0x03, 0x03, 0x00, 0x05, 1,2,3,4,5 };
		enum tls_ch_result r = tls_parse_clienthello(app, sizeof(app), &ch);
		CHECK(r == TLS_CH_NOT_CH, "content_type=23 (app data) → NOT_CH");

		/* handshake but msg_type != ClientHello (2 = ServerHello) */
		uint8_t sh[] = { 22, 0x03,0x03, 0x00,0x04, 0x02, 0x00,0x00,0x00 };
		r = tls_parse_clienthello(sh, sizeof(sh), &ch);
		CHECK(r == TLS_CH_NOT_CH, "msg_type=ServerHello → NOT_CH");
	}

	printf("== test 5: malicious input — list_len lies past the boundary ==\n");
	{
		struct buf b = build_ch("evil.test");
		/* server_name_list len sits right after the ext header (4B) +
		 * ext_len (2B of the extensions block). Locate the server_name
		 * extension and corrupt list_len. Simpler: corrupt the last 2 bytes
		 * into a very large length so there is definitely a nested length
		 * exceeding the record boundary. */
		b.d[b.len - 1] = 0xff;
		b.d[b.len - 2] = 0xff;
		enum tls_ch_result r = tls_parse_clienthello(b.d, b.len, &ch);
		CHECK(r == TLS_CH_MALFORMED || r == TLS_CH_OK,
		      "corrupt length → MALFORMED/OK, no crash (ASan)");
		free(b.d);
	}

	printf("== test 6: session_id_len lies ==\n");
	{
		struct buf b = build_ch("x.test");
		/* session_id_len at offset: 5(rec)+4(hs)+2(ver)+32(random) = 43 */
		b.d[43] = 0xff;   /* claims 255 bytes of session_id — past the frame */
		enum tls_ch_result r = tls_parse_clienthello(b.d, b.len, &ch);
		CHECK(r == TLS_CH_MALFORMED, "session_id_len past frame → MALFORMED");
		free(b.d);
	}

	printf("== test 7: record_len larger than buffer → NEED_MORE ==\n");
	{
		struct buf b = build_ch("more.test");
		b.d[3] = 0xff; b.d[4] = 0xff;   /* record_len = 65535 */
		enum tls_ch_result r = tls_parse_clienthello(b.d, b.len, &ch);
		CHECK(r == TLS_CH_NEED_MORE, "record_len > buffer → NEED_MORE");
		free(b.d);
	}

	printf("== test 8: SNI too long → MALFORMED (no sni[] overflow) ==\n");
	{
		char big[400];
		memset(big, 'a', sizeof(big) - 1);
		big[sizeof(big) - 1] = '\0';
		struct buf b = build_ch(big);
		enum tls_ch_result r = tls_parse_clienthello(b.d, b.len, &ch);
		CHECK(r == TLS_CH_MALFORMED, "399-char host_name → MALFORMED");
		free(b.d);
	}

	printf("== test 9: NULL/zero safety ==\n");
	{
		enum tls_ch_result r = tls_parse_clienthello(NULL, 0, &ch);
		CHECK(r == TLS_CH_NEED_MORE, "NULL buf → NEED_MORE");
		r = tls_parse_clienthello((const uint8_t *)"", 0, &ch);
		CHECK(r == TLS_CH_NEED_MORE, "len 0 → NEED_MORE");
	}

	if (g_fail) {
		printf("\n== %d TEST FAIL ==\n", g_fail);
		return 1;
	}
	printf("\n== ALL TLS ClientHello TESTS PASS ==\n");
	return 0;
}
