/* SPDX-License-Identifier: MIT */
/*
 * tls_policy.h - Decide SPLICE (raw relay) or BUMP (MITM decrypt) for a TLS
 *                flow, based on the SNI (see tls_clienthello.h) + bypass list.
 *
 * This is the "brain" of SSL inspection — the runtime stage right after PEEK:
 *
 *     ClientHello ──peek──► SNI ──tls_policy_decide()──► BUMP / SPLICE
 *
 * Philosophy: inspect BY DEFAULT (BUMP) every flow, EXCEPT domains in the bypass
 * list (banking, cert-pinning apps, privacy-sensitive categories) → SPLICE.
 * Getting this wrong has real consequences: wrongly bumping a cert-pinning app
 * = a BROKEN connection for the user; so the bypass list is mandatory, not
 * optional.
 *
 * Domain match rules (case-insensitive):
 *   - "bank.com"    : matches EXACTLY "bank.com".
 *   - "*.bank.com"  : matches every subdomain "x.bank.com", "a.b.bank.com" — but
 *                     NOT "bank.com" itself (correct TLS/DNS wildcard semantics).
 * Add both entries if you want to cover the apex as well as subdomains.
 *
 * No OpenSSL/mbedTLS needed — just string comparison; host-testable.
 */
#ifndef SG_TLS_POLICY_H
#define SG_TLS_POLICY_H

#include <stddef.h>

enum tls_action {
	TLS_BUMP   = 0,   /* MITM: decrypt + feed plaintext into the IPS engine */
	TLS_SPLICE = 1,   /* raw TCP relay, NO decrypt (metadata/ML only) */
};

/* Policy when a TLS flow has NO SNI (ECH, old client, or deliberately hidden). */
enum tls_no_sni_policy {
	TLS_NO_SNI_BUMP   = 0,  /* safe default: still inspect */
	TLS_NO_SNI_SPLICE = 1,  /* relaxed: no SNI means let it pass (less safe) */
};

struct tls_policy {
	char   **patterns;          /* bypass list (owned, malloc)             */
	int      n, cap;
	int      default_bump;      /* 1 = default BUMP (inspect-all-except-list)*/
	int      no_sni;            /* enum tls_no_sni_policy                   */
};

/* Empty init: default BUMP (inspect everything), no-SNI → BUMP. */
void tls_policy_init(struct tls_policy *p);

/*
 * Add a pattern to the bypass list ("bank.com" or "*.bank.com").
 * Normalizes: lowercase, strip stray leading/trailing '.'. Returns 0 on success,
 * -1 on OOM or an empty/invalid pattern.
 */
int tls_policy_add_bypass(struct tls_policy *p, const char *pattern);

/*
 * Decide for one flow. `sni` is the host_name from tls_clienthello (may be NULL/
 * empty if has_sni==0). Returns TLS_BUMP or TLS_SPLICE.
 *   - has_sni==0            → follow p->no_sni.
 *   - SNI matches bypass list → TLS_SPLICE.
 *   - otherwise             → TLS_BUMP if default_bump, else TLS_SPLICE.
 */
enum tls_action tls_policy_decide(const struct tls_policy *p,
				  const char *sni, int has_sni);

/* Does it match the bypass list (split out for tests/logging). 1=match, 0=no. */
int tls_policy_is_bypassed(const struct tls_policy *p, const char *sni);

void tls_policy_free(struct tls_policy *p);

const char *tls_action_str(enum tls_action a);

#endif /* SG_TLS_POLICY_H */
