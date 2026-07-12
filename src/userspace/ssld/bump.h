/* SPDX-License-Identifier: MIT */
/*
 * bump.h - MITM a single TLS flow: terminate on the client side (cert forged by
 *          SNI), open TLS to the real server, decrypt, inspect plaintext,
 *          re-encrypt.
 *
 *   client ──TLS(fake cert)── ssld ──TLS(real)── server
 *                              │
 *                         plaintext → inspect()
 *
 * FAIL-CLOSED: if verify_upstream is set and the REAL server cert is invalid ->
 * do NOT forge a valid cert that hides the error; close the connection (the
 * client sees the failure itself). This is a vital security property - otherwise
 * we would inadvertently strip the user's cert warning.
 */
#ifndef SG_SSLD_BUMP_H
#define SG_SSLD_BUMP_H

#include "ca.h"
#include "certcache.h"
#include <netinet/in.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

struct bump_cfg {
	struct ca_ctx    *ca;
	struct certcache *cc;
	int               verify_upstream;   /* 1 = fail-closed if server cert errors */

	/*
	 * Reverse mode ("Protect SSL Server", inbound deep inspection): present the
	 * REAL server cert+key to the client instead of forging via the CA — so an
	 * external client sees a valid certificate (no CA install needed). When
	 * reverse=1, srv_cert/srv_key are used and `upstream` (if non-NULL) overrides
	 * the TLS#2 target with the real backend. Forward mode (reverse=0) uses ca/cc.
	 */
	int                       reverse;
	X509                     *srv_cert;
	STACK_OF(X509)           *srv_chain;  /* intermediate chain (may be NULL) */
	EVP_PKEY                 *srv_key;
	const struct sockaddr_in *upstream;  /* reverse backend; NULL = original dst */

	/*
	 * Inspect decrypted plaintext. to_server=1 (client->server) or 0
	 * (server->client). Returns 0 = pass, 1 = BLOCK (drop flow). NULL = no
	 * inspection.
	 */
	int  (*inspect)(const unsigned char *data, int len, int to_server,
			void *ud);
	void  *inspect_ud;

	/*
	 * Called when inspect() returns DROP (prevent): write the block page
	 * (HTTP 403) to the CLIENT before closing - FortiGate-style. client_ssl is an
	 * `SSL *` (passed as void* so bump.h does not depend on OpenSSL). NULL =
	 * close directly, no page.
	 */
	void (*on_block)(void *client_ssl, void *ud);
};

/*
 * Run MITM for one connection. `sni` comes from the peeked ClientHello (NULL if
 * absent - then forge by the destination IP, which matches poorly and easily
 * triggers a cert warning). client_fd must STILL have the ClientHello in its
 * buffer (conn.c uses MSG_PEEK). bump_run CLOSES client_fd before returning
 * (consumes it). Returns 0 if the session ended normally, -1 on
 * error/fail-closed.
 */
int bump_run(int client_fd, const char *sni, const struct sockaddr_in *dst,
	     const struct bump_cfg *cfg);

#endif /* SG_SSLD_BUMP_H */
