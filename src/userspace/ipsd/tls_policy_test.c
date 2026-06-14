/* SPDX-License-Identifier: MIT */
/*
 * tls_policy_test.c - test the SPLICE/BUMP decision from the SNI + bypass list.
 */
#include "tls_policy.h"

#include <stdio.h>

static int g_fail;

#define CHECK(cond, msg) do {                                            \
	if (!(cond)) { printf("  FAIL: %s\n", msg); g_fail++; }          \
	else         { printf("  ok:   %s\n", msg); }                    \
} while (0)

int main(void)
{
	printf("== test 1: default — inspect everything when list is empty ==\n");
	{
		struct tls_policy p;
		tls_policy_init(&p);
		CHECK(tls_policy_decide(&p, "anything.com", 1) == TLS_BUMP,
		      "empty list → BUMP");
		tls_policy_free(&p);
	}

	printf("== test 2: exact match → SPLICE ==\n");
	{
		struct tls_policy p;
		tls_policy_init(&p);
		CHECK(tls_policy_add_bypass(&p, "bank.com") == 0, "add bank.com");
		CHECK(tls_policy_decide(&p, "bank.com", 1) == TLS_SPLICE,
		      "bank.com → SPLICE");
		CHECK(tls_policy_decide(&p, "www.bank.com", 1) == TLS_BUMP,
		      "www.bank.com does NOT match exact → BUMP");
		CHECK(tls_policy_decide(&p, "evilbank.com", 1) == TLS_BUMP,
		      "evilbank.com no match → BUMP");
		tls_policy_free(&p);
	}

	printf("== test 3: wildcard *.x → matches subdomain, NOT apex ==\n");
	{
		struct tls_policy p;
		tls_policy_init(&p);
		tls_policy_add_bypass(&p, "*.bank.com");
		CHECK(tls_policy_decide(&p, "www.bank.com", 1) == TLS_SPLICE,
		      "www.bank.com → SPLICE");
		CHECK(tls_policy_decide(&p, "a.b.bank.com", 1) == TLS_SPLICE,
		      "a.b.bank.com → SPLICE (multi-level)");
		CHECK(tls_policy_decide(&p, "bank.com", 1) == TLS_BUMP,
		      "bank.com (apex) does NOT match *.bank.com → BUMP");
		CHECK(tls_policy_decide(&p, "notbank.com", 1) == TLS_BUMP,
		      "notbank.com → BUMP");
		CHECK(tls_policy_decide(&p, "xbank.com", 1) == TLS_BUMP,
		      "xbank.com (missing '.' boundary) → BUMP");
		tls_policy_free(&p);
	}

	printf("== test 4: case-insensitive ==\n");
	{
		struct tls_policy p;
		tls_policy_init(&p);
		tls_policy_add_bypass(&p, "Bank.COM");
		tls_policy_add_bypass(&p, "*.Secure.IO");
		CHECK(tls_policy_decide(&p, "BANK.com", 1) == TLS_SPLICE,
		      "BANK.com matches Bank.COM");
		CHECK(tls_policy_decide(&p, "API.secure.io", 1) == TLS_SPLICE,
		      "API.secure.io matches *.Secure.IO");
		tls_policy_free(&p);
	}

	printf("== test 5: no-SNI policy ==\n");
	{
		struct tls_policy p;
		tls_policy_init(&p);
		CHECK(tls_policy_decide(&p, NULL, 0) == TLS_BUMP,
		      "no SNI, default → BUMP");
		p.no_sni = TLS_NO_SNI_SPLICE;
		CHECK(tls_policy_decide(&p, NULL, 0) == TLS_SPLICE,
		      "no SNI, policy SPLICE → SPLICE");
		CHECK(tls_policy_decide(&p, "", 1) == TLS_SPLICE,
		      "empty SNI treated as no-SNI");
		tls_policy_free(&p);
	}

	printf("== test 6: default_bump=0 (only inspect domains in list) ==\n");
	{
		struct tls_policy p;
		tls_policy_init(&p);
		p.default_bump = 0;          /* invert: default SPLICE */
		tls_policy_add_bypass(&p, "inspect-me.com");
		/* note: the list semantics are a "bypass list", so a domain in the
		 * list still SPLICEs; default_bump=0 means domains OUTSIDE the list
		 * also SPLICE → effectively inspection off. Verify that behavior. */
		CHECK(tls_policy_decide(&p, "other.com", 1) == TLS_SPLICE,
		      "outside list + default_bump=0 → SPLICE");
		CHECK(tls_policy_decide(&p, "inspect-me.com", 1) == TLS_SPLICE,
		      "in bypass list always SPLICE");
		tls_policy_free(&p);
	}

	printf("== test 7: normalization + bad patterns ==\n");
	{
		struct tls_policy p;
		tls_policy_init(&p);
		CHECK(tls_policy_add_bypass(&p, "  Trailing.Dot.com.  ") == 0,
		      "add pattern with whitespace + trailing dot");
		CHECK(tls_policy_decide(&p, "trailing.dot.com", 1) == TLS_SPLICE,
		      "matches after normalization");
		CHECK(tls_policy_add_bypass(&p, "") == -1, "empty pattern → error");
		CHECK(tls_policy_add_bypass(&p, "*") == -1, "pattern '*' → error");
		CHECK(tls_policy_add_bypass(&p, "*.") == -1, "pattern '*.' → error");
		CHECK(tls_policy_add_bypass(&p, NULL) == -1, "NULL pattern → error");
		tls_policy_free(&p);
	}

	printf("== test 8: many patterns, clean free (ASan) ==\n");
	{
		struct tls_policy p;
		tls_policy_init(&p);
		for (int i = 0; i < 100; i++) {
			char buf[64];
			snprintf(buf, sizeof(buf), "*.domain%d.example", i);
			tls_policy_add_bypass(&p, buf);
		}
		CHECK(tls_policy_decide(&p, "a.domain42.example", 1) == TLS_SPLICE,
		      "matches 1 of 100 patterns");
		CHECK(tls_policy_decide(&p, "a.domain999.example", 1) == TLS_BUMP,
		      "no match → BUMP");
		tls_policy_free(&p);   /* ASan leak check */
	}

	if (g_fail) {
		printf("\n== %d TEST FAIL ==\n", g_fail);
		return 1;
	}
	printf("\n== ALL TLS policy TESTS PASS ==\n");
	return 0;
}
