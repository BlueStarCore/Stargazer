/* SPDX-License-Identifier: MIT */
/*
 * ca.h - Local CA for SSL inspection (forge certs signed by this CA).
 *
 * The CA private key is the HIGHEST-RISK ASSET of this feature: a leak means an
 * attacker can impersonate every HTTPS site in the organization. Store the key
 * 0600, root-only. The public cert must be installed into the trust store of
 * EVERY client for bump not to raise cert errors.
 *
 * Generates an EC P-256 key (lighter + faster than RSA on ARM), self-signed,
 * CA:TRUE.
 */
#ifndef SG_SSLD_CA_H
#define SG_SSLD_CA_H

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <stddef.h>

struct ca_ctx {
	X509     *cert;   /* CA cert (self-signed)        */
	EVP_PKEY *key;    /* CA private key               */
};

/*
 * Load the CA from cert_path/key_path if both exist; if missing, GENERATE a new
 * one and write it to the two paths (key mode 0600). Returns 0 on OK, -1 on
 * error.
 */
int  ca_load_or_create(struct ca_ctx *ca,
		       const char *cert_path, const char *key_path);

/* Export the CA cert as PEM into buf (for clients to download and install).
 * Returns the length, -1 on error. */
int  ca_export_cert_pem(const struct ca_ctx *ca, char *buf, size_t cap);

void ca_free(struct ca_ctx *ca);

#endif /* SG_SSLD_CA_H */
