/* SPDX-License-Identifier: MIT */
/*
 * ca.c - Local CA (xem ca.h).
 */
#define _POSIX_C_SOURCE 200809L   /* fdopen với -std=c11 */
#include "ca.h"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#define CA_CN     "Stargazer SSL Inspection CA"
#define CA_DAYS   (3650L * 24 * 3600)   /* 10 năm */

/* Thêm một extension X509v3 vào cert (self-issued: issuer==subject). */
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

/* Nạp PEM cert + key. Trả 0 nếu cả hai đọc được. */
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

/* Ghi cert (0644) + key (0600) ra đĩa. Trả 0 nếu OK. */
static int ca_save(const struct ca_ctx *ca,
		   const char *cert_path, const char *key_path)
{
	FILE *cf = fopen(cert_path, "w");
	if (!cf)
		return -1;
	int ok = PEM_write_X509(cf, ca->cert);
	fclose(cf);
	if (!ok)
		return -1;

	/* key: tạo với 0600 ngay từ open() để không lộ trong cửa sổ race */
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

/* Sinh CA mới: EC P-256, self-signed, CA:TRUE. */
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

	/* serial ngẫu nhiên 64-bit dương */
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
		return 0;                       /* đã có CA — dùng lại */

	if (ca_create(ca) < 0)
		return -1;

	if (ca_save(ca, cert_path, key_path) < 0) {
		/* không lưu được vẫn dùng được trong phiên, nhưng cảnh báo */
		fprintf(stderr, "ca: CẢNH BÁO không ghi được CA ra %s/%s: %m\n",
			cert_path, key_path);
	}
	return 0;
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
