/* SPDX-License-Identifier: MIT */
/*
 * proto_buf.h - Extract protocol "sticky buffers" from the reassembled stream (P6).
 *
 * Many ET rules attach content to a specific REGION (http_uri, http_header, …,
 * tls.sni) instead of the raw payload → more precise matching, fewer false
 * positives. We parse the reassembled stream once into regions, then let verify
 * match content against the correct region. Minimal parser, BOUNDS-CHECK every
 * access.
 *
 * Scope: HTTP REQUEST (to_server): method, uri, header, body. TLS SNI from
 * ClientHello (reuses tls_clienthello). HTTP response not done yet.
 */
#ifndef SG_PROTO_BUF_H
#define SG_PROTO_BUF_H

#include <stdint.h>
#include "sig_rule.h"   /* enum sig_buf, SIG_NBUF */

struct match_buffers {
	const uint8_t *b[SIG_NBUF];
	int            len[SIG_NBUF];
	char           sni[256];   /* stores SNI; b[SIG_BUF_TLS_SNI] points here */
};

/* Set the RAW buffer = reassembled stream; all other regions empty. */
void bufs_init_raw(struct match_buffers *mb, const uint8_t *raw, int len);

/*
 * Extract regions from `stream[0..len)` (reassembled to_server stream).
 * Recognizes HTTP request (method SP uri SP HTTP/…CRLF headers CRLF CRLF body)
 * and TLS ClientHello (record 0x16). Absent region → b[]=NULL,len[]=0.
 */
void bufs_extract(struct match_buffers *mb, const uint8_t *stream, int len);

#endif /* SG_PROTO_BUF_H */
