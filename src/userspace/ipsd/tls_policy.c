/* SPDX-License-Identifier: MIT */
/*
 * tls_policy.c - Quyết định SPLICE/BUMP theo SNI + bypass list (xem header).
 */
#define _POSIX_C_SOURCE 200809L   /* strdup (POSIX.1-2008) với -std=c11 */
#include "tls_policy.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* So sánh hai chuỗi, không phân biệt hoa/thường. */
static int ci_eq(const char *a, const char *b)
{
	for (; *a && *b; a++, b++)
		if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
			return 0;
	return *a == '\0' && *b == '\0';
}

/*
 * host kết thúc bằng ".suffix" (so không phân biệt hoa/thường)?
 * Dùng cho wildcard: "*.bank.com" → suffix="bank.com", cần host khớp
 * "<gì đó>.bank.com". host == suffix (không có nhãn trước) → KHÔNG khớp.
 */
static int ci_dotsuffix(const char *host, const char *suffix)
{
	size_t hl = strlen(host), sl = strlen(suffix);
	if (hl <= sl + 1)              /* cần ít nhất "x." trước suffix */
		return 0;
	if (host[hl - sl - 1] != '.')  /* ranh giới phải là dấu '.' */
		return 0;
	return ci_eq(host + hl - sl, suffix);
}

/* Chuẩn hóa pattern vào buf: lowercase, bỏ '.' thừa đầu/cuối (giữ '*.'). */
static int normalize(const char *in, char *buf, size_t cap)
{
	if (!in)
		return -1;
	/* bỏ khoảng trắng đầu */
	while (*in == ' ' || *in == '\t')
		in++;

	size_t n = 0;
	for (; *in; in++) {
		char c = *in;
		if (c == ' ' || c == '\t')
			break;                       /* dừng ở khoảng trắng */
		if (n + 1 >= cap)
			return -1;                   /* quá dài */
		buf[n++] = (char)tolower((unsigned char)c);
	}
	/* bỏ '.' thừa ở cuối (nhưng không đụng "*.") */
	while (n > 0 && buf[n - 1] == '.')
		n--;
	buf[n] = '\0';
	if (n == 0)
		return -1;
	/* "*." trống ("*." hoặc "*") → vô nghĩa */
	if (!strcmp(buf, "*") || !strcmp(buf, "*."))
		return -1;
	return 0;
}

void tls_policy_init(struct tls_policy *p)
{
	memset(p, 0, sizeof(*p));
	p->default_bump = 1;            /* inspect-all-trừ-list */
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
