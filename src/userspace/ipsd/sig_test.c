/* SPDX-License-Identifier: MIT */
/*
 * sig_test.c - Unit test cho parser rule + khớp payload, chạy trên HOST.
 *
 *   gcc -O2 -Wall -Wextra -fsanitize=address,undefined \
 *       -o /tmp/sig_test ac.c sig_rule.c sig_test.c && /tmp/sig_test
 */
#include "sig_rule.h"

#include <stdio.h>
#include <string.h>

static int g_failed;

static void check(int cond, const char *name)
{
	printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
	if (!cond) g_failed++;
}

/* Ruleset chính dùng cho phần lớn test. */
static const char *RULES[] = {
	"alert tcp any any -> any 80 (msg:\"SQLi UNION SELECT\"; "
		"content:\"UNION\"; nocase; content:\"SELECT\"; nocase; sid:2008538; rev:5;)",
	"drop tcp any any -> any 4444 (msg:\"bind shell magic\"; "
		"content:\"|de ad be ef|\"; sid:9001; rev:1;)",
	"alert tcp any any -> any 22 (msg:\"SSH banner\"; content:\"SSH-\"; sid:7001;)",
	"# day la comment, phai bo qua",
	"alert tcp any any -> any any (msg:\"offset test\"; content:\"abc\"; "
		"offset:2; depth:3; sid:1234;)",
	"alert tcp any any -> any any (msg:\"syn flag\"; flags:S; content:\"x\"; sid:5;)",
};

static void build_main(struct sig_ruleset *rs)
{
	sig_ruleset_init(rs);
	for (size_t i = 0; i < sizeof(RULES) / sizeof(RULES[0]); i++)
		sig_parse_line(rs, RULES[i]);
	sig_build(rs);
}

static int run(struct sig_ruleset *rs, const char *s, uint8_t proto,
	       uint16_t dport, uint8_t flags)
{
	struct flow_ctx fc = { .proto = proto, .dport = dport, .tcp_flags = flags };
	return sig_match(rs, (const uint8_t *)s, strlen(s), &fc);
}

int main(void)
{
	struct sig_ruleset rs;
	build_main(&rs);

	printf("T1 parse:\n");
	check(rs.n_rules == 5, "5 rule nạp (comment bị bỏ)");
	check(rs.rules[0].n_content == 2, "rule SQLi có 2 content");
	check(rs.rules[0].action == SIG_ALERT, "SQLi = alert");
	check(rs.rules[0].dport == 80, "SQLi dport 80");
	check(rs.rules[0].sid == 2008538, "sid đọc đúng");
	check(rs.rules[0].content[0].nocase == 1, "content đầu nocase");
	check(rs.rules[0].fast == 1, "fast pattern = SELECT (dài hơn)");
	check(strstr(rs.rules[0].msg, "SQLi") != NULL, "msg lưu đúng");

	printf("T2 khớp đúng port + đúng thứ tự content:\n");
	check(run(&rs, "GET /a?id=1 UNION SELECT pass FROM tbl", SIG_PROTO_TCP, 80, 0)
	      == 0, "SQLi @dport80 → rule 0");

	printf("T3 sai port → không khớp:\n");
	check(run(&rs, "GET /a?id=1 UNION SELECT pass", SIG_PROTO_TCP, 443, 0)
	      == -1, "cùng payload nhưng dport 443 → -1");

	printf("T4 sai thứ tự content → không khớp:\n");
	check(run(&rs, "SELECT first then UNION later", SIG_PROTO_TCP, 80, 0)
	      == -1, "SELECT trước UNION → không khớp (ép thứ tự)");

	printf("T5 nocase:\n");
	check(run(&rs, "q=1 union select 0", SIG_PROTO_TCP, 80, 0)
	      == 0, "chữ thường vẫn khớp khi nocase");

	printf("T6 content nhị phân |hex|:\n");
	{
		uint8_t p[] = { 0x01, 0x02, 0xde, 0xad, 0xbe, 0xef, 0x03 };
		struct flow_ctx fc = { SIG_PROTO_TCP, 4444, 0 };
		int idx = sig_match(&rs, p, sizeof(p), &fc);
		check(idx == 1 && rs.rules[idx].action == SIG_DROP,
		      "deadbeef @dport4444 → rule DROP");
	}

	printf("T7 offset/depth:\n");
	check(run(&rs, "zzabc", SIG_PROTO_TCP, 8080, 0) >= 0,
	      "abc tại offset 2 → khớp");
	check(run(&rs, "abczz", SIG_PROTO_TCP, 8080, 0) == -1,
	      "abc tại offset 0 (ngoài cửa sổ) → không khớp");

	printf("T8 cờ TCP (flags:S):\n");
	{
		int with_syn = run(&rs, "x", SIG_PROTO_TCP, 8080, SIG_TCP_SYN);
		int no_syn   = run(&rs, "x", SIG_PROTO_TCP, 8080, SIG_TCP_ACK);
		check(with_syn >= 0 && rs.rules[with_syn].sid == 5, "có SYN → khớp rule flags:S");
		check(no_syn == -1, "không SYN → không khớp");
	}

	sig_ruleset_free(&rs);

	printf("T9 ưu tiên DROP > ALERT:\n");
	{
		struct sig_ruleset p;
		sig_ruleset_init(&p);
		sig_parse_line(&p, "alert tcp any any -> any any (msg:\"a\"; content:\"AAA\"; sid:100;)");
		sig_parse_line(&p, "drop tcp any any -> any any (msg:\"d\"; content:\"BBB\"; sid:101;)");
		sig_build(&p);
		int idx = run(&p, "xxAAAyyBBBzz", SIG_PROTO_TCP, 1234, 0);
		check(idx >= 0 && p.rules[idx].action == SIG_DROP,
		      "trúng cả ALERT lẫn DROP → trả DROP");
		sig_ruleset_free(&p);
	}

	printf("\n%s (%d test thất bại)\n",
	       g_failed ? "=== CÓ LỖI ===" : "=== TẤT CẢ PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
