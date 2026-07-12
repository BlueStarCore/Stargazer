/* SPDX-License-Identifier: MIT */
/*
 * revmap.h - Reverse SSL-inspection ("Protect SSL Server") map.
 *
 * Forward bump forges a leaf signed by the local CA (client must trust the CA).
 * For INBOUND traffic (external client -> internal server) the external client
 * does not trust our CA, so we instead present the REAL server certificate +
 * private key and terminate the TLS session as a reverse proxy:
 *
 *   external client ──TLS#1 (REAL server cert)── ssld ──TLS#2── internal server
 *                                                 │
 *                                            plaintext → inspect()
 *
 * Each entry maps the original destination the client targeted (the VIP, from
 * SO_ORIGINAL_DST) — optionally narrowed by SNI — to a loaded cert/key pair and
 * the real backend address to re-encrypt toward.
 *
 * Config file (one entry per line; '#'/blank ignored):
 *   <vip>:<vport>  <cert.pem>  <key.pem>  <backend_ip>:<bport>  [sni]
 * '-' or omitted sni = match any SNI for that VIP.
 */
#ifndef SG_SSLD_REVMAP_H
#define SG_SSLD_REVMAP_H

#include <stdint.h>
#include <netinet/in.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

struct rev_server {
	uint32_t vip;            /* network order; 0 = match any dst IP   */
	uint16_t vport;          /* network order; 0 = match any dst port */
	char     sni[256];       /* "" = match any SNI                    */
	X509    *cert;           /* REAL server leaf certificate          */
	STACK_OF(X509) *chain;   /* intermediate CA certs (may be NULL) — sent so the
				  * client can build the chain to a trusted root  */
	EVP_PKEY *key;           /* REAL server private key               */
	struct sockaddr_in backend;   /* real server to re-encrypt toward */
};

struct revmap {
	struct rev_server *e;
	int n, cap;
};

/* Load the reverse-server map from `path`. Returns a heap revmap* (free with
 * revmap_free) or NULL if the file is missing/empty/all-invalid. Entries whose
 * cert/key cannot be read or do not match each other are skipped (logged). */
struct revmap *revmap_load(const char *path);

/* First entry matching the original destination (network-order ip/port) and,
 * if the entry pins an SNI, the SNI. NULL = no protected server for this flow. */
const struct rev_server *revmap_match(const struct revmap *m,
				      uint32_t dst_ip, uint16_t dst_port,
				      const char *sni);

void revmap_free(struct revmap *m);

#endif /* SG_SSLD_REVMAP_H */
