/* SPDX-License-Identifier: MIT */
/*
 * ac_test.c - Unit test for Aho-Corasick, runs on the HOST (native gcc).
 *
 *   gcc -O2 -Wall -Wextra -o /tmp/ac_test ac.c ac_test.c && /tmp/ac_test
 *
 * "Tests verify real behavior": each test checks the exact expected set of
 * (id, end_pos), not just the count. Returns 0 if all PASS, 1 if any FAIL.
 */
#include "ac.h"

#include <stdio.h>
#include <string.h>

static int g_failed;

/* ---- match collector via callback --------------------------------------- */
struct match  { int id; size_t end; };
struct collector { struct match m[128]; int n; };

static int collect(int id, size_t end, void *ctx)
{
	struct collector *c = ctx;

	if (c->n < (int)(sizeof(c->m) / sizeof(c->m[0]))) {
		c->m[c->n].id  = id;
		c->m[c->n].end = end;
		c->n++;
	}
	return 0;                               /* no early stop */
}

/* is (id, end) present in the collected set? */
static int has(const struct collector *c, int id, size_t end)
{
	for (int i = 0; i < c->n; i++)
		if (c->m[i].id == id && c->m[i].end == end)
			return 1;
	return 0;
}

static void check(int cond, const char *name)
{
	printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
	if (!cond)
		g_failed++;
}

#define ADD(ac, s, id)  ac_add_pattern((ac), (const uint8_t *)(s), (int)strlen(s), (id))
#define RUN(ac, txt, col) \
	ac_search((ac), (const uint8_t *)(txt), strlen(txt), collect, (col))

/* ---- T1: classic example he/she/his/hers ------------------------------- */
static void t_classic(void)
{
	struct ac_automaton ac;
	struct collector    col = { .n = 0 };
	int total;

	printf("T1 classic he/she/his/hers on \"ushers\":\n");
	ac_init(&ac, 0);
	ADD(&ac, "he", 0);
	ADD(&ac, "she", 1);
	ADD(&ac, "his", 2);
	ADD(&ac, "hers", 3);
	ac_build(&ac);

	total = RUN(&ac, "ushers", &col);       /* u s h e r s = idx 0..5 */
	check(total == 3, "total 3 matches");
	check(has(&col, 0, 3), "he ends @3");
	check(has(&col, 1, 3), "she ends @3");
	check(has(&col, 3, 5), "hers ends @5");
	check(!has(&col, 2, 2) && !has(&col, 2, 5), "his does NOT appear");
	ac_free(&ac);
}

/* ---- T2: pattern is a prefix of another pattern + overlap --------------- */
static void t_overlap(void)
{
	struct ac_automaton ac;
	struct collector    col = { .n = 0 };
	int total;

	printf("T2 overlap ab/abc/bc on \"abc\":\n");
	ac_init(&ac, 0);
	ADD(&ac, "ab", 0);
	ADD(&ac, "abc", 1);
	ADD(&ac, "bc", 2);
	ac_build(&ac);

	total = RUN(&ac, "abc", &col);          /* a b c = idx 0..2 */
	check(total == 3, "total 3 matches");
	check(has(&col, 0, 1), "ab @1");
	check(has(&col, 1, 2), "abc @2");
	check(has(&col, 2, 2), "bc @2 (via fail-link)");
	ac_free(&ac);
}

/* ---- T3: nocase vs case-sensitive -------------------------------------- */
static void t_case(void)
{
	struct ac_automaton ac;
	struct collector    col = { .n = 0 };

	printf("T3a nocase \"union\"/\"select\" on \"... UNION SELECT ...\":\n");
	ac_init(&ac, 1);                        /* nocase = 1 */
	ADD(&ac, "union", 0);
	ADD(&ac, "select", 1);
	ac_build(&ac);
	RUN(&ac, "id=1 UNION SELECT pwd", &col);
	check(has(&col, 0, 9),  "UNION matches when nocase (@9)");
	check(has(&col, 1, 16), "SELECT matches when nocase (@16)");
	ac_free(&ac);

	printf("T3b case-sensitive \"ABC\" does NOT match \"abc\":\n");
	col.n = 0;
	ac_init(&ac, 0);                        /* nocase = 0 */
	ADD(&ac, "ABC", 0);
	ac_build(&ac);
	check(RUN(&ac, "abc", &col) == 0, "0 matches on case mismatch");
	ac_free(&ac);
}

/* ---- T4: edges — empty payload, pattern longer than text --------------- */
static void t_edges(void)
{
	struct ac_automaton ac;
	struct collector    col = { .n = 0 };

	printf("T4a empty payload:\n");
	ac_init(&ac, 0);
	ADD(&ac, "abc", 0);
	ac_build(&ac);
	check(ac_search(&ac, (const uint8_t *)"", 0, collect, &col) == 0,
	      "len=0 → 0 matches, no crash");

	printf("T4b pattern longer than text:\n");
	col.n = 0;
	check(RUN(&ac, "ab", &col) == 0, "\"abc\" does not match \"ab\"");
	ac_free(&ac);
}

/* ---- T5: binary-safe (byte 0x00 in both pattern and text) -------------- */
static void t_binary(void)
{
	struct ac_automaton ac;
	struct collector    col = { .n = 0 };
	const uint8_t       pat[]  = { 0x00, 0x01, 0xFF };
	const uint8_t       text[] = { 0x41, 0x00, 0x01, 0xFF, 0x42 }; /* A \0 \1 \xff B */
	int total;

	printf("T5 binary-safe (contains 0x00):\n");
	ac_init(&ac, 0);
	ac_add_pattern(&ac, pat, (int)sizeof(pat), 7);
	ac_build(&ac);

	total = ac_search(&ac, text, sizeof(text), collect, &col);
	check(total == 1, "exactly 1 match even with 0x00");
	check(has(&col, 7, 3), "binary pattern ends @3 (uses len, not strlen)");
	ac_free(&ac);
}

int main(void)
{
	t_classic();
	t_overlap();
	t_case();
	t_edges();
	t_binary();

	printf("\n%s (%d tests failed)\n",
	       g_failed ? "=== ERRORS ===" : "=== ALL PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
