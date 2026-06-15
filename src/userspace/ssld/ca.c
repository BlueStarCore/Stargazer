/* SPDX-License-Identifier: MIT */
/*
 * ca.c - Local CA (see ca.h).
 */
#define _POSIX_C_SOURCE 200809L   /* fdopen with -std=c11 */
#include "ca.h"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>   /* flock - serialize CA creation across multiple ssld */
#include <sys/stat.h>   /* mkdir - create the CA dir if missing on persistent storage */
#include <sys/types.h>

#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#define CA_CN     "Stargazer SSL Inspection CA"
#define CA_DAYS   (3650L * 24 * 3600)   /* 10 years */

/* Add an X509v3 extension to the cert (self-issued: issuer==subject). */
static int add_ext(X509 *cert, int nid, const char *value)
{
	X509V3_CTX ctx;
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return -1;
	int rc = X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);
	return rc == 1 ? 0 : -1;
}

/* Load PEM cert + key. Returns 0 if both could be read. */
static int ca_load(struct ca_ctx *ca, const char *cert_path, const char *key_path)
{
	FILE *cf = fopen(cert_path, "r");
	FILE *kf = fopen(key_path, "r");
	if (!cf || !kf) {
		if (cf) fclose(cf);
		if (kf) fclose(kf);
		return -1;
	}
	ca->cert = PEM_read_X509(cf, NULL, NULL, NULL);
	ca->key  = PEM_read_PrivateKey(kf, NULL, NULL, NULL);
	fclose(cf);
	fclose(kf);
	if (!ca->cert || !ca->key) {
		ca_free(ca);
		return -1;
	}
	return 0;
}

/* mkdir -p the directory containing file_path (mode 0700). The CA directory
 * (/etc/stargazer/ssl) may not exist yet on persistent storage -> ca_save's
 * fopen would ENOENT and the CA would never be written to disk (ssld still runs
 * with the CA in RAM, but clients can't fetch the cert to install -> MITM is
 * broken). Create it ahead of time so ca_save can write. Ignore EEXIST at each
 * level. */
static void ensure_parent_dir(const char *file_path)
{
	char dir[512];
	snprintf(dir, sizeof(dir), "%s", file_path);
	char *slash = strrchr(dir, '/');
	if (!slash || slash == dir)
		return;
	*slash = '\0';
	for (char *p = dir + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(dir, 0700);
			*p = '/';
		}
	}
	mkdir(dir, 0700);
}

/* Write cert (0644) + key (0600) to disk. Returns 0 on OK. */
static int ca_save(const struct ca_ctx *ca,
		   const char *cert_path, const char *key_path)
{
	ensure_parent_dir(cert_path);   /* /etc/stargazer/ssl may not exist yet */
	FILE *cf = fopen(cert_path, "w");
	if (!cf)
		return -1;
	int ok = PEM_write_X509(cf, ca->cert);
	fclose(cf);
	if (!ok)
		return -1;

	/* key: create with 0600 right at open() so it's never exposed in a race window */
	int fd = open(key_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	FILE *kf = fdopen(fd, "w");
	if (!kf) {
		close(fd);
		return -1;
	}
	ok = PEM_write_PrivateKey(kf, ca->key, NULL, NULL, 0, NULL, NULL);
	fclose(kf);
	return ok ? 0 : -1;
}

/* Generate a new CA: EC P-256, self-signed, CA:TRUE. */
static int ca_create(struct ca_ctx *ca)
{
	memset(ca, 0, sizeof(*ca));

	ca->key = EVP_EC_gen("prime256v1");
	if (!ca->key)
		return -1;

	ca->cert = X509_new();
	if (!ca->cert)
		goto err;

	X509_set_version(ca->cert, 2);   /* X509v3 */

	/* random positive 64-bit serial */
	{
		unsigned char rnd[8];
		if (RAND_bytes(rnd, sizeof(rnd)) != 1)
			goto err;
		rnd[0] &= 0x7f;
		BIGNUM *bn = BN_bin2bn(rnd, sizeof(rnd), NULL);
		if (!bn)
			goto err;
		ASN1_INTEGER *serial = X509_get_serialNumber(ca->cert);
		BN_to_ASN1_INTEGER(bn, serial);
		BN_free(bn);
	}

	X509_gmtime_adj(X509_getm_notBefore(ca->cert), 0);
	X509_gmtime_adj(X509_getm_notAfter(ca->cert), CA_DAYS);

	if (X509_set_pubkey(ca->cert, ca->key) != 1)
		goto err;

	/* subject == issuer (self-signed) */
	X509_NAME *name = X509_get_subject_name(ca->cert);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				   (const unsigned char *)CA_CN, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
				   (const unsigned char *)"Stargazer NGFW",
				   -1, -1, 0);
	if (X509_set_issuer_name(ca->cert, name) != 1)
		goto err;

	if (add_ext(ca->cert, NID_basic_constraints, "critical,CA:TRUE") < 0)
		goto err;
	if (add_ext(ca->cert, NID_key_usage,
		    "critical,keyCertSign,cRLSign") < 0)
		goto err;
	if (add_ext(ca->cert, NID_subject_key_identifier, "hash") < 0)
		goto err;

	if (X509_sign(ca->cert, ca->key, EVP_sha256()) == 0)
		goto err;

	return 0;
err:
	ca_free(ca);
	return -1;
}

int ca_load_or_create(struct ca_ctx *ca,
		      const char *cert_path, const char *key_path)
{
	memset(ca, 0, sizeof(*ca));

	if (ca_load(ca, cert_path, key_path) == 0)
		return 0;                       /* CA already exists - reuse it */

	/* Multiple ssld (one per profile) may start at once when the CA does not yet
	 * exist -> a RACE creating different CAs (the client trusts CA-A but ssld-B
	 * signs with CA-B -> cert warning). Serialize with flock: the first instance
	 * creates it, later instances (waiting on the lock) reload the just-created
	 * CA -> the WHOLE system shares ONE CA. */
	char lock_path[512];
	snprintf(lock_path, sizeof(lock_path), "%s.lock", key_path);
	int lfd = open(lock_path, O_CREAT | O_RDWR, 0600);
	if (lfd >= 0)
		flock(lfd, LOCK_EX);

	/* Re-check under the lock: another instance may have just finished creating it. */
	if (ca_load(ca, cert_path, key_path) == 0) {
		if (lfd >= 0) { flock(lfd, LOCK_UN); close(lfd); }
		return 0;
	}

	int rc = 0;
	if (ca_create(ca) < 0) {
		rc = -1;
	} else if (ca_save(ca, cert_path, key_path) < 0) {
		/* CA created in RAM but NOT written to disk -> clients can't fetch the
		 * cert to install, so every bump flow would raise a cert error. Treat
		 * this as a failure so ssld runs splice-only (pass-through) instead of
		 * bumping with a CA that can't be trusted - more honest, fails safe. */
		fprintf(stderr, "ca: ERROR could not write CA to %s/%s: %m - "
			"splice-only\n", cert_path, key_path);
		rc = -1;
	}
	if (lfd >= 0) { flock(lfd, LOCK_UN); close(lfd); }
	return rc;
}

int ca_export_cert_pem(const struct ca_ctx *ca, char *buf, size_t cap)
{
	if (!ca || !ca->cert || !buf || cap == 0)
		return -1;
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio)
		return -1;
	int rc = -1;
	if (PEM_write_bio_X509(bio, ca->cert) == 1) {
		BUF_MEM *bm = NULL;
		BIO_get_mem_ptr(bio, &bm);
		if (bm && bm->length < cap) {
			memcpy(buf, bm->data, bm->length);
			buf[bm->length] = '\0';
			rc = (int)bm->length;
		}
	}
	BIO_free(bio);
	return rc;
}

void ca_free(struct ca_ctx *ca)
{
	if (!ca)
		return;
	if (ca->cert) { X509_free(ca->cert); ca->cert = NULL; }
	if (ca->key)  { EVP_PKEY_free(ca->key); ca->key = NULL; }
}
