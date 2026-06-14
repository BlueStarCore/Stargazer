/* SPDX-License-Identifier: MIT */
/*
 * certcache.c - Forge + cache leaf cert (xem certcache.h).
 */
#include "certcache.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#define LEAF_DAYS (365L * 24 * 3600)

struct cc_entry {
	char        sni[256];
	X509       *cert;
	EVP_PKEY   *key;     /* trỏ leaf key chung (không free riêng) */
	unsigned    lru;     /* tem dùng gần nhất để evict */
};

struct certcache {
	struct ca_ctx   *ca;
	EVP_PKEY        *leaf_key;   /* keypair chung cho mọi leaf */
	struct cc_entry *ent;
	int              n, max;
	unsigned         tick;
	pthread_mutex_t  lock;
};

struct certcache *certcache_new(struct ca_ctx *ca, int max)
{
	if (!ca || max < 1)
		return NULL;
	struct certcache *cc = calloc(1, sizeof(*cc));
	if (!cc)
		return NULL;
	cc->ca  = ca;
	cc->max = max;
	cc->ent = calloc((size_t)max, sizeof(*cc->ent));
	cc->leaf_key = EVP_EC_gen("prime256v1");
	if (!cc->ent || !cc->leaf_key) {
		certcache_free(cc);
		return NULL;
	}
	pthread_mutex_init(&cc->lock, NULL);
	return cc;
}

/* Forge leaf mới CN/SAN=sni, ký bằng CA. Trả X509* (caller sở hữu) hoặc NULL. */
static X509 *forge(struct certcache *cc, const char *sni, X509 *upstream)
{
	X509 *crt = X509_new();
	if (!crt)
		return NULL;

	X509_set_version(crt, 2);

	/* serial ngẫu nhiên */
	unsigned char rnd[16];
	if (RAND_bytes(rnd, sizeof(rnd)) != 1)
		goto err;
	rnd[0] &= 0x7f;
	BIGNUM *bn = BN_bin2bn(rnd, sizeof(rnd), NULL);
	if (!bn)
		goto err;
	BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(crt));
	BN_free(bn);

	/* thời hạn: mirror upstream nếu có, không thì 1 năm */
	if (upstream) {
		X509_set1_notBefore(crt, X509_get0_notBefore(upstream));
		X509_set1_notAfter(crt, X509_get0_notAfter(upstream));
	} else {
		X509_gmtime_adj(X509_getm_notBefore(crt), 0);
		X509_gmtime_adj(X509_getm_notAfter(crt), LEAF_DAYS);
	}

	if (X509_set_pubkey(crt, cc->leaf_key) != 1)
		goto err;

	/* subject CN = sni; issuer = CA subject */
	X509_NAME *subj = X509_get_subject_name(crt);
	X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
				   (const unsigned char *)sni, -1, -1, 0);
	if (X509_set_issuer_name(crt,
		X509_get_subject_name(cc->ca->cert)) != 1)
		goto err;

	/* extensions: SAN dNSName=sni + basicConstraints CA:FALSE + EKU server */
	X509V3_CTX ctx;
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, cc->ca->cert, crt, NULL, NULL, 0);

	char san[300];
	snprintf(san, sizeof(san), "DNS:%s", sni);
	struct { int nid; const char *val; } exts[] = {
		{ NID_basic_constraints,       "critical,CA:FALSE" },
		{ NID_key_usage,               "critical,digitalSignature,keyEncipherment" },
		{ NID_ext_key_usage,           "serverAuth" },
		{ NID_subject_alt_name,        san },
	};
	for (size_t i = 0; i < sizeof(exts)/sizeof(exts[0]); i++) {
		X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, &ctx,
							 exts[i].nid,
							 exts[i].val);
		if (!ex)
			goto err;
		int rc = X509_add_ext(crt, ex, -1);
		X509_EXTENSION_free(ex);
		if (rc != 1)
			goto err;
	}

	/* ký bằng CA key */
	if (X509_sign(crt, cc->ca->key, EVP_sha256()) == 0)
		goto err;

	return crt;
err:
	X509_free(crt);
	return NULL;
}

int certcache_get(struct certcache *cc, const char *sni, X509 *upstream,
		  X509 **out_cert, EVP_PKEY **out_key)
{
	if (!cc || !sni || !*sni || !out_cert || !out_key)
		return -1;

	pthread_mutex_lock(&cc->lock);
	cc->tick++;

	/* hit? */
	for (int i = 0; i < cc->n; i++) {
		if (strcmp(cc->ent[i].sni, sni) == 0) {
			cc->ent[i].lru = cc->tick;
			*out_cert = cc->ent[i].cert;
			*out_key  = cc->ent[i].key;
			pthread_mutex_unlock(&cc->lock);
			return 0;
		}
	}

	/* miss → forge */
	X509 *crt = forge(cc, sni, upstream);
	if (!crt) {
		pthread_mutex_unlock(&cc->lock);
		return -1;
	}

	/* chọn slot: trống, hoặc evict LRU */
	int slot;
	if (cc->n < cc->max) {
		slot = cc->n++;
	} else {
		slot = 0;
		for (int i = 1; i < cc->n; i++)
			if (cc->ent[i].lru < cc->ent[slot].lru)
				slot = i;
		X509_free(cc->ent[slot].cert);   /* key chung — không free */
	}

	snprintf(cc->ent[slot].sni, sizeof(cc->ent[slot].sni), "%s", sni);
	cc->ent[slot].cert = crt;
	cc->ent[slot].key  = cc->leaf_key;
	cc->ent[slot].lru  = cc->tick;

	*out_cert = crt;
	*out_key  = cc->leaf_key;
	pthread_mutex_unlock(&cc->lock);
	return 0;
}

void certcache_free(struct certcache *cc)
{
	if (!cc)
		return;
	if (cc->ent) {
		for (int i = 0; i < cc->n; i++)
			if (cc->ent[i].cert)
				X509_free(cc->ent[i].cert);
		free(cc->ent);
	}
	if (cc->leaf_key)
		EVP_PKEY_free(cc->leaf_key);
	pthread_mutex_destroy(&cc->lock);
	free(cc);
}
