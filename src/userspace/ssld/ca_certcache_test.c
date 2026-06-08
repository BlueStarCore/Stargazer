/* SPDX-License-Identifier: MIT */
/*
 * ca_certcache_test.c - test sinh CA + forge leaf + kiểm chuỗi tin cậy.
 *
 * Bằng chứng cốt lõi: leaf forge ra PHẢI verify được tới CA (đúng như client
 * đã cài CA sẽ thấy), và SAN/CN khớp SNI. Cũng kiểm cache hit + LRU evict.
 */
#include "ca.h"
#include "certcache.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/x509v3.h>

static int g_fail;
#define CHECK(c, m) do { if (!(c)) { printf("  FAIL: %s\n", m); g_fail++; } \
			 else printf("  ok:   %s\n", m); } while (0)

/* Verify `leaf` chains tới `ca`. Trả 1 nếu hợp lệ. */
static int verify_chain(X509 *leaf, X509 *ca)
{
	X509_STORE *store = X509_STORE_new();
	X509_STORE_add_cert(store, ca);
	X509_STORE_CTX *ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(ctx, store, leaf, NULL);
	int ok = X509_verify_cert(ctx);
	if (!ok)
		printf("    verify err: %s\n",
		       X509_verify_cert_error_string(
			       X509_STORE_CTX_get_error(ctx)));
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	return ok == 1;
}

/* SAN có chứa dNSName == want? */
static int has_san(X509 *crt, const char *want)
{
	int found = 0;
	GENERAL_NAMES *gens = X509_get_ext_d2i(crt, NID_subject_alt_name,
					       NULL, NULL);
	if (!gens)
		return 0;
	for (int i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
		GENERAL_NAME *g = sk_GENERAL_NAME_value(gens, i);
		if (g->type == GEN_DNS) {
			const char *s = (const char *)
				ASN1_STRING_get0_data(g->d.dNSName);
			if (s && strcmp(s, want) == 0)
				found = 1;
		}
	}
	GENERAL_NAMES_free(gens);
	return found;
}

int main(void)
{
	char cpath[] = "/tmp/sg_ca_test_cert.pem";
	char kpath[] = "/tmp/sg_ca_test_key.pem";
	unlink(cpath); unlink(kpath);

	printf("== test 1: sinh CA mới ==\n");
	struct ca_ctx ca;
	CHECK(ca_load_or_create(&ca, cpath, kpath) == 0, "ca_load_or_create");
	CHECK(ca.cert && ca.key, "có cert + key");
	{
		char pem[4096];
		int n = ca_export_cert_pem(&ca, pem, sizeof(pem));
		CHECK(n > 0 && strstr(pem, "BEGIN CERTIFICATE"), "export PEM");
	}

	printf("== test 2: nạp lại CA từ đĩa (persist) ==\n");
	{
		struct ca_ctx ca2;
		CHECK(ca_load_or_create(&ca2, cpath, kpath) == 0, "nạp lại");
		/* serial CA phải giống → cùng một CA, không sinh mới */
		CHECK(X509_cmp(ca.cert, ca2.cert) == 0, "cùng CA cert (persist)");
		ca_free(&ca2);
	}

	printf("== test 3: forge leaf + verify chuỗi tới CA ==\n");
	struct certcache *cc = certcache_new(&ca, 4);
	CHECK(cc != NULL, "certcache_new");
	{
		X509 *crt; EVP_PKEY *key;
		CHECK(certcache_get(cc, "www.example.com", NULL, &crt, &key) == 0,
		      "forge www.example.com");
		CHECK(verify_chain(crt, ca.cert), "leaf verify tới CA");
		CHECK(has_san(crt, "www.example.com"), "SAN dNSName khớp SNI");
	}

	printf("== test 4: cache hit trả cùng cert ==\n");
	{
		X509 *a, *b; EVP_PKEY *ka, *kb;
		certcache_get(cc, "cache.test", NULL, &a, &ka);
		certcache_get(cc, "cache.test", NULL, &b, &kb);
		CHECK(a == b, "cùng con trỏ cert (hit)");
		CHECK(ka == kb, "cùng leaf key chung");
	}

	printf("== test 5: LRU evict khi quá max ==\n");
	{
		/* max=4; đã có www.example.com, cache.test (2). Thêm 4 nữa → evict. */
		X509 *c; EVP_PKEY *k;
		const char *names[] = {"a.test","b.test","c.test","d.test"};
		for (int i = 0; i < 4; i++)
			CHECK(certcache_get(cc, names[i], NULL, &c, &k) == 0,
			      names[i]);
		/* vẫn forge được domain mới sau evict, verify vẫn đúng */
		CHECK(certcache_get(cc, "new.test", NULL, &c, &k) == 0,
		      "forge sau evict");
		CHECK(verify_chain(c, ca.cert), "leaf sau evict vẫn verify");
	}

	certcache_free(cc);
	ca_free(&ca);
	unlink(cpath); unlink(kpath);

	if (g_fail) { printf("\n== %d TEST FAIL ==\n", g_fail); return 1; }
	printf("\n== TẤT CẢ ca/certcache TEST PASS ==\n");
	return 0;
}
