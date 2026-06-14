/* SPDX-License-Identifier: MIT */
/*
 * proto_buf.c - Extract protocol sticky buffers (see proto_buf.h).
 *
 * "A buffer is always checked": every stream-read index is bounds-checked;
 * undefined regions are left NULL/0 (verify treats them as no-match → fail-safe).
 */
#include "proto_buf.h"
#include "tls_clienthello.h"

#include <string.h>
#include <stdio.h>

void bufs_init_raw(struct match_buffers *mb, const uint8_t *raw, int len)
{
	memset(mb, 0, sizeof(*mb));
	mb->b[SIG_BUF_RAW]   = raw;
	mb->len[SIG_BUF_RAW] = (len > 0) ? len : 0;
}

/* Valid method = uppercase A-Z (avoids mistaking binary for HTTP). */
static int is_http_method(const uint8_t *s, int n)
{
	if (n < 3 || n > 12) return 0;
	for (int i = 0; i < n; i++)
		if (s[i] < 'A' || s[i] > 'Z') return 0;
	return 1;
}

void bufs_extract(struct match_buffers *mb, const uint8_t *s, int len)
{
	if (!s || len <= 0)
		return;

	/* ---- TLS ClientHello? record handshake = 0x16 ---- */
	if (s[0] == 0x16) {
		struct tls_clienthello ch;
		if (tls_parse_clienthello(s, (size_t)len, &ch) == TLS_CH_OK &&
		    ch.has_sni) {
			snprintf(mb->sni, sizeof(mb->sni), "%s", ch.sni);
			mb->b[SIG_BUF_TLS_SNI]   = (const uint8_t *)mb->sni;
			mb->len[SIG_BUF_TLS_SNI] = (int)strlen(mb->sni);
		}
		return;   /* TLS → not HTTP */
	}

	/* ---- HTTP request: METHOD SP URI SP HTTP/x CRLF headers CRLF CRLF body */
	int sp1 = -1;
	for (int i = 0; i < len && i < 16; i++)
		if (s[i] == ' ') { sp1 = i; break; }
	if (sp1 <= 0 || !is_http_method(s, sp1))
		return;
	mb->b[SIG_BUF_HTTP_METHOD]   = s;
	mb->len[SIG_BUF_HTTP_METHOD] = sp1;

	int us = sp1 + 1, sp2 = -1;
	for (int i = us; i < len; i++)
		if (s[i] == ' ' || s[i] == '\r' || s[i] == '\n') { sp2 = i; break; }
	if (sp2 < 0)
		return;
	if (sp2 > us) {
		mb->b[SIG_BUF_HTTP_URI]   = s + us;
		mb->len[SIG_BUF_HTTP_URI] = sp2 - us;
	}

	/* end of request line */
	int eol = -1;
	for (int i = sp2; i < len; i++)
		if (s[i] == '\n') { eol = i; break; }
	if (eol < 0)
		return;
	int hstart = eol + 1;

	/* header/body boundary: CRLFCRLF or LFLF */
	int hend = -1, bstart = -1;
	for (int i = hstart; i < len - 1; i++) {
		if (s[i] == '\n' && s[i + 1] == '\n') {
			hend = i; bstart = i + 2; break;
		}
		if (i + 3 < len && s[i] == '\r' && s[i + 1] == '\n' &&
		    s[i + 2] == '\r' && s[i + 3] == '\n') {
			hend = i; bstart = i + 4; break;
		}
	}
	if (hend < 0) {
		/* no header terminator seen yet → header = the remainder */
		if (len > hstart) {
			mb->b[SIG_BUF_HTTP_HEADER]   = s + hstart;
			mb->len[SIG_BUF_HTTP_HEADER] = len - hstart;
		}
		return;
	}
	if (hend > hstart) {
		mb->b[SIG_BUF_HTTP_HEADER]   = s + hstart;
		mb->len[SIG_BUF_HTTP_HEADER] = hend - hstart;
	}
	if (len > bstart) {
		mb->b[SIG_BUF_HTTP_BODY]   = s + bstart;
		mb->len[SIG_BUF_HTTP_BODY] = len - bstart;
	}
}
