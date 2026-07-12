/* SPDX-License-Identifier: MIT */
/*
 * tls_clienthello.h - Parse the SNI from a TLS ClientHello (the "PEEK" step of
 *                     SSL inspection — see docs/ips-master-plan.md, SSL chapter).
 *
 * This is the FIRST RUNTIME step of stargazer-ssld: before deciding between
 * BYPASS (splice — raw relay) and INSPECT (bump — MITM decrypt), the proxy reads
 * the ClientHello (still cleartext even in TLS 1.3, unless ECH is in use) to
 * extract the SNI and then look it up in the bypass list. No OpenSSL needed —
 * just plain byte parsing, bounds-checked at every step; malicious/truncated
 * input must NOT crash it.
 *
 * The same module is reused for:
 *   - SNI-based signature matching (content matched against the tls.sni buffer).
 *   - FQDN wildcard Phase 3 (DNS/SNI snooping).
 *
 * References: RFC 8446 §4.1.2 (ClientHello), RFC 6066 §3 (server_name).
 */
#ifndef SG_TLS_CLIENTHELLO_H
#define SG_TLS_CLIENTHELLO_H

#include <stdint.h>
#include <stddef.h>

/* Max host_name: RFC 1035 limits an FQDN to 253 chars + NUL. */
#define TLS_SNI_MAX 256

enum tls_ch_result {
	TLS_CH_OK        =  0,  /* parse done; has_sni says whether an SNI exists */
	TLS_CH_NEED_MORE =  1,  /* buffer cut off mid-stream — need more bytes    */
	TLS_CH_NOT_CH    =  2,  /* not a TLS handshake ClientHello                */
	TLS_CH_MALFORMED = -1,  /* bad structure (deliberate or corrupt)         */
};

struct tls_clienthello {
	char     sni[TLS_SNI_MAX]; /* host_name, NUL-terminated; "" if none        */
	int      has_sni;          /* 1 if an SNI host_name was found              */
	uint16_t legacy_version;   /* client_version in the ClientHello (e.g 0x0303)*/
	uint16_t record_len;       /* TLS record length (gives the handshake frame)*/
};

/*
 * Parse one (or the start of one) TLS record containing a ClientHello.
 *
 * Returns:
 *   TLS_CH_OK        + fills *out (has_sni=0/1)
 *   TLS_CH_NEED_MORE if buf is not yet enough to read all the required parts
 *   TLS_CH_NOT_CH    if the first byte is not a handshake/ClientHello
 *   TLS_CH_MALFORMED if a nested length is nonsensical (exceeds the record/buffer)
 *
 * `out` is always zero-initialized before parsing; safe to pass buf=NULL.
 * The function NEVER writes past out->sni[TLS_SNI_MAX-1]; a longer SNI →
 * MALFORMED (a valid host_name never exceeds 253).
 */
enum tls_ch_result tls_parse_clienthello(const uint8_t *buf, size_t len,
					 struct tls_clienthello *out);

/* Result name for logging/tests. */
const char *tls_ch_result_str(enum tls_ch_result r);

#endif /* SG_TLS_CLIENTHELLO_H */
