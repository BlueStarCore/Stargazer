/* SPDX-License-Identifier: MIT */
/*
 * revmap.c - Reverse SSL-inspection server map (see revmap.h).
 */
#include "revmap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/pem.h>

/* Parse "<ipv4>:<port>" into network-order ip + port. Returns 0 on success. */
static int parse_ipport(const char *tok, uint32_t *ip, uint16_t *port)
{
	const char *colon = strrchr(tok, ':');
	if (!colon)
		return -1;
	size_t hlen = (size_t)(colon - tok);
	char host[64];
	if (hlen == 0 || hlen >= sizeof(host))
		return -1;
	memcpy(host, tok, hlen);
	host[hlen] = '\0';

	struct in_addr a;
	if (inet_pton(AF_INET, host, &a) != 1)
		return -1;
	int p = atoi(colon + 1);
	if (p <= 0 || p > 65535)
		return -1;
	*ip = a.s_addr;
	*port = htons((uint16_t)p);
	return 0;
}

/* Load + pair-check a cert/key PEM. On success returns 0 and fills cert,key. */
static int load_certkey(const char *cpath, const char *kpath,
			X509 **cert, STACK_OF(X509) **chain, EVP_PKEY **key)
{
	*cert = NULL;
	*chain = NULL;
	*key = NULL;

	FILE *cf = fopen(cpath, "r");
	if (cf) {
		*cert = PEM_read_X509(cf, NULL, NULL, NULL);   /* leaf = first cert */
		/* Any further certs in the PEM = intermediate chain. Real-world certs
		 * ship leaf+intermediates; without these an external client cannot build
		 * the chain to a trusted root → cert error even with the right leaf. */
		X509 *ic;
		while ((ic = PEM_read_X509(cf, NULL, NULL, NULL)) != NULL) {
			if (!*chain)
				*chain = sk_X509_new_null();
			if (!*chain || !sk_X509_push(*chain, ic)) {
				X509_free(ic);
				break;
			}
		}
		fclose(cf);
	}
	FILE *kf = fopen(kpath, "r");
	if (kf) { *key = PEM_read_PrivateKey(kf, NULL, NULL, NULL); fclose(kf); }

	if (!*cert || !*key) {
		fprintf(stderr, "revmap: cannot read cert(%s)/key(%s)\n", cpath, kpath);
		goto fail;
	}
	/* fail-closed: a mismatched cert/key would break every handshake */
	if (X509_check_private_key(*cert, *key) != 1) {
		fprintf(stderr, "revmap: cert/key do not match (%s, %s)\n", cpath, kpath);
		goto fail;
	}
	return 0;
fail:
	if (*cert)  { X509_free(*cert); *cert = NULL; }
	if (*chain) { sk_X509_pop_free(*chain, X509_free); *chain = NULL; }
	if (*key)   { EVP_PKEY_free(*key); *key = NULL; }
	return -1;
}

struct revmap *revmap_load(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return NULL;

	struct revmap *m = calloc(1, sizeof(*m));
	if (!m) { fclose(f); return NULL; }

	char line[1024];
	while (fgets(line, sizeof(line), f)) {
		char *s = line;
		while (*s == ' ' || *s == '\t') s++;
		if (*s == '#' || *s == '\n' || *s == '\r' || *s == '\0')
			continue;

		char vip[128], cert[256], key[256], backend[128], sni[256] = "";
		int got = sscanf(s, "%127s %255s %255s %127s %255s",
				 vip, cert, key, backend, sni);
		if (got < 4) {
			fprintf(stderr, "revmap: malformed line: %s", s);
			continue;
		}

		struct rev_server rs;
		memset(&rs, 0, sizeof(rs));
		if (parse_ipport(vip, &rs.vip, &rs.vport) < 0) {
			fprintf(stderr, "revmap: bad vip '%s'\n", vip);
			continue;
		}
		uint32_t bip; uint16_t bport;
		if (parse_ipport(backend, &bip, &bport) < 0) {
			fprintf(stderr, "revmap: bad backend '%s'\n", backend);
			continue;
		}
		rs.backend.sin_family = AF_INET;
		rs.backend.sin_addr.s_addr = bip;
		rs.backend.sin_port = bport;
		if (got >= 5 && sni[0] && strcmp(sni, "-") != 0)
			snprintf(rs.sni, sizeof(rs.sni), "%s", sni);

		if (load_certkey(cert, key, &rs.cert, &rs.chain, &rs.key) < 0) {
			fprintf(stderr, "revmap: skip %s (cert/key invalid)\n", vip);
			continue;
		}

		if (m->n == m->cap) {
			int nc = m->cap ? m->cap * 2 : 4;
			struct rev_server *ne = realloc(m->e, (size_t)nc * sizeof(*ne));
			if (!ne) {
				X509_free(rs.cert);
				if (rs.chain) sk_X509_pop_free(rs.chain, X509_free);
				EVP_PKEY_free(rs.key);
				break;
			}
			m->e = ne;
			m->cap = nc;
		}
		m->e[m->n++] = rs;
		fprintf(stderr, "revmap: protect %s%s%s (cert ok)\n", vip,
			rs.sni[0] ? " sni=" : "", rs.sni);
	}
	fclose(f);

	if (m->n == 0) {
		revmap_free(m);
		return NULL;
	}
	return m;
}

const struct rev_server *revmap_match(const struct revmap *m,
				      uint32_t dst_ip, uint16_t dst_port,
				      const char *sni)
{
	if (!m)
		return NULL;
	for (int i = 0; i < m->n; i++) {
		const struct rev_server *e = &m->e[i];
		if (e->vip && e->vip != dst_ip)
			continue;
		if (e->vport && e->vport != dst_port)
			continue;
		if (e->sni[0] && (!sni || strcmp(e->sni, sni) != 0))
			continue;
		return e;
	}
	return NULL;
}

void revmap_free(struct revmap *m)
{
	if (!m)
		return;
	for (int i = 0; i < m->n; i++) {
		if (m->e[i].cert)  X509_free(m->e[i].cert);
		if (m->e[i].chain) sk_X509_pop_free(m->e[i].chain, X509_free);
		if (m->e[i].key)   EVP_PKEY_free(m->e[i].key);
	}
	free(m->e);
	free(m);
}
