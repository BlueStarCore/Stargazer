/* SPDX-License-Identifier: MIT */
/*
 * tls_policy.c - Decide SPLICE/BUMP from the SNI + bypass list (see header).
 */
#define _POSIX_C_SOURCE 200809L   /* strdup (POSIX.1-2008) with -std=c11 */
#include "tls_policy.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Compare two strings, case-insensitive. */
static int ci_eq(const char *a, const char *b)
{
	for (; *a && *b; a++, b++)
		if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
			return 0;
	return *a == '\0' && *b == '\0';
}

/*
 * Does host end with ".suffix" (case-insensitive)?
 * Used for wildcards: "*.bank.com" → suffix="bank.com", host must match
 * "<something>.bank.com". host == suffix (no preceding label) → NO match.
 */
static int ci_dotsuffix(const char *host, const char *suffix)
{
	size_t hl = strlen(host), sl = strlen(suffix);
	if (hl <= sl + 1)              /* need at least "x." before the suffix */
		return 0;
	if (host[hl - sl - 1] != '.')  /* boundary must be a '.' */
		return 0;
	return ci_eq(host + hl - sl, suffix);
}

/* Normalize a pattern into buf: lowercase, strip stray leading/trailing '.' (keep '*.'). */
static int normalize(const char *in, char *buf, size_t cap)
{
	if (!in)
		return -1;
	/* skip leading whitespace */
	while (*in == ' ' || *in == '\t')
		in++;

	size_t n = 0;
	for (; *in; in++) {
		char c = *in;
		if (c == ' ' || c == '\t')
			break;                       /* stop at whitespace */
		if (n + 1 >= cap)
			return -1;                   /* too long */
		buf[n++] = (char)tolower((unsigned char)c);
	}
	/* strip trailing stray '.' (but leave "*." alone) */
	while (n > 0 && buf[n - 1] == '.')
		n--;
	buf[n] = '\0';
	if (n == 0)
		return -1;
	/* empty "*." ("*." or "*") → meaningless */
	if (!strcmp(buf, "*") || !strcmp(buf, "*."))
		return -1;
	return 0;
}

void tls_policy_init(struct tls_policy *p)
{
	memset(p, 0, sizeof(*p));
	p->default_bump = 1;            /* inspect-all-except-list */
	p->no_sni       = TLS_NO_SNI_BUMP;
}

int tls_policy_add_bypass(struct tls_policy *p, const char *pattern)
{
	char norm[300];
	if (normalize(pattern, norm, sizeof(norm)) < 0)
		return -1;

	if (p->n == p->cap) {
		int nc = p->cap ? p->cap * 2 : 16;
		char **np = realloc(p->patterns, (size_t)nc * sizeof(*np));
		if (!np)
			return -1;
		p->patterns = np;
		p->cap = nc;
	}
	char *dup = strdup(norm);
	if (!dup)
		return -1;
	p->patterns[p->n++] = dup;
	return 0;
}

int tls_policy_is_bypassed(const struct tls_policy *p, const char *sni)
{
	if (!p || !sni || !*sni)
		return 0;

	for (int i = 0; i < p->n; i++) {
		const char *pat = p->patterns[i];
		if (pat[0] == '*' && pat[1] == '.') {
			if (ci_dotsuffix(sni, pat + 2))
				return 1;
		} else {
			if (ci_eq(sni, pat))
				return 1;
		}
	}
	return 0;
}

enum tls_action tls_policy_decide(const struct tls_policy *p,
				  const char *sni, int has_sni)
{
	if (!has_sni || !sni || !*sni)
		return (p->no_sni == TLS_NO_SNI_SPLICE) ? TLS_SPLICE : TLS_BUMP;

	if (tls_policy_is_bypassed(p, sni))
		return TLS_SPLICE;

	return p->default_bump ? TLS_BUMP : TLS_SPLICE;
}

void tls_policy_free(struct tls_policy *p)
{
	if (!p)
		return;
	for (int i = 0; i < p->n; i++)
		free(p->patterns[i]);
	free(p->patterns);
	memset(p, 0, sizeof(*p));
}

const char *tls_action_str(enum tls_action a)
{
	return a == TLS_SPLICE ? "SPLICE" : "BUMP";
}
