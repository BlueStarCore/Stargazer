/* SPDX-License-Identifier: MIT */
/*
 * certcache.h - Forge + cache leaf certs by SNI (signed by the local CA).
 *
 * Each bumped domain needs a fake leaf cert with CN/SAN = that domain, signed by
 * the CA. Forging on every handshake is too expensive -> cache by SNI. Use ONE
 * shared leaf keypair for all certs (like mitmproxy/sslsplit) to avoid
 * generating a key per domain.
 *
 * If the real server cert (upstream) is available, mirror notBefore/notAfter so
 * the fake cert looks valid in time. Thread-safe (mutex) since multiple
 * conn-threads look up concurrently.
 */
#ifndef SG_SSLD_CERTCACHE_H
#define SG_SSLD_CERTCACHE_H

#include "ca.h"
#include <openssl/x509.h>
#include <openssl/evp.h>

struct certcache;

/* Create the cache (up to `max` entries, LRU evict). Generates the shared leaf
 * keypair. */
struct certcache *certcache_new(struct ca_ctx *ca, int max);

/*
 * Get (forge if not cached) the leaf cert for `sni`. `upstream` may be NULL (do
 * not mirror validity -> use the 1-year default). Returns 0 + fills
 * out_cert/out_key (does NOT bump the ref - it lives with the cache, use it in
 * SSL_CTX right away then done; the cache holds the ref). Returns -1 on error.
 */
int certcache_get(struct certcache *cc, const char *sni, X509 *upstream,
		  X509 **out_cert, EVP_PKEY **out_key);

void certcache_free(struct certcache *cc);

#endif /* SG_SSLD_CERTCACHE_H */
