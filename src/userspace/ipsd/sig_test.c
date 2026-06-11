/* SPDX-License-Identifier: MIT */
/*
 * sig_test.c - Unit test cho parser rule + khớp payload, chạy trên HOST.
 *
 *   gcc -O2 -Wall -Wextra -fsanitize=address,undefined \
 *       -o /tmp/sig_test ac.c sig_rule.c sig_test.c && /tmp/sig_test
 */
#include "sig_rule.h"
#include "proto_buf.h"

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
	check(rs.rules[0].n_dport == 1 && rs.rules[0].dport_list[0] == 80,
	      "SQLi dport 80");
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

	/* ── P0: phân loại fidelity + an toàn lúc nạp ── */
	printf("T10 fidelity-cap (content + keyword chưa hỗ trợ → ALERT):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		/* content đủ mạnh nhưng có isdataat (chưa hỗ trợ) → nạp, KẸP ALERT
		 * dù action drop. (isdataat luôn unsupported, độc lập HAVE_PCRE.) */
		int rc = sig_parse_line(&p,
			"drop tcp any any -> any any (msg:\"unsup rule\"; "
			"content:\"EVILPAYLOAD\"; isdataat:50,relative; sid:300;)");
		check(rc == SIG_LINE_ALERT, "rule có isdataat → trả SIG_LINE_ALERT");
		check(p.n_rules == 1, "vẫn nạp (1 L2 rule)");
		check(p.rules[0].fidelity == SIG_FID_ALERT, "fidelity = ALERT");
		check(p.rules[0].has_unsup & SIG_U_DSIZE, "has_unsup gắn bit DSIZE");
		check(p.rules[0].action == SIG_DROP, "action GỐC vẫn SIG_DROP (giữ)");
		sig_ruleset_free(&p);
	}

	printf("T11 reputation/catch-all (không content, không selector) → BỎ:\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		int rc = sig_parse_line(&p,
			"alert ip any any -> any any (msg:\"ET CNC IP\"; "
			"reference:url,x; sid:400;)");
		check(rc == SIG_LINE_SKIP_REP, "catch-all → SIG_LINE_SKIP_REP");
		check(p.n_rules == 0, "KHÔNG nạp (không L2)");
		sig_ruleset_free(&p);
	}

	printf("T12 rule KHÔNG content (đã gỡ L1 signature) → BỎ:\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		int rc = sig_parse_line(&p,
			"alert tcp any any -> any 22 (msg:\"ssh flood\"; "
			"flags:S; sid:401;)");
		check(rc == SIG_LINE_SKIP_NOCONTENT,
		      "có selector nhưng không content → SKIP_NOCONTENT");
		check(p.n_rules == 0, "KHÔNG nạp (engine chỉ còn content L2)");
		sig_ruleset_free(&p);
	}

	printf("T13 content quá yếu + keyword chưa hỗ trợ → BỎ (unsupported):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		int rc = sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"weak\"; "
			"content:\"ab\"; isdataat:10,relative; sid:402;)");
		check(rc == SIG_LINE_SKIP_UNSUP, "content≤2 + isdataat → SKIP_UNSUP");
		check(p.n_rules == 0, "không nạp");
		sig_ruleset_free(&p);
	}

	printf("T14 hex hỏng → bỏ content đó, không crash:\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		/* |de ad be| ok nhưng |zz| sai → content thứ 2 bị bỏ, content 1 còn */
		sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"badhex\"; "
			"content:\"GOODCONTENT\"; content:\"|zz|\"; sid:403;)");
		check(p.n_rules == 1, "rule vẫn nạp (1 content hợp lệ)");
		check(p.rules[0].n_content == 1, "content hex hỏng bị bỏ");
		sig_ruleset_free(&p);
	}

	printf("T15 coverage stats từ sig_load_file:\n");
	{
		const char *tmp = "/tmp/sg_p0_rules.rules";
		FILE *f = fopen(tmp, "w");
		if (f) {
			fputs("alert tcp any any -> any 80 (msg:\"ok\"; content:\"GETME\"; sid:1;)\n", f);
			fputs("drop tcp any any -> any any (msg:\"unsup\"; content:\"PAYLOADX\"; isdataat:30,relative; sid:2;)\n", f);
			fputs("alert ip any any -> any any (msg:\"rep\"; sid:3;)\n", f);
			fputs("# comment\n", f);
			fclose(f);
			struct sig_ruleset p; sig_ruleset_init(&p);
			struct sig_load_stats st;
			sig_load_file(&p, tmp, &st);
			check(st.loaded == 2, "loaded=2 (full+alert)");
			check(st.loaded_full == 1, "loaded_full=1");
			check(st.loaded_alert == 1, "loaded_alert=1 (isdataat-cap)");
			check(st.skipped_reputation == 1, "skipped_reputation=1");
			sig_ruleset_free(&p);
			remove(tmp);
		}
	}

	/* ── P2: distance/within/dsize ── */
	printf("T16 distance/within (định vị tương đối):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"rel\"; "
			"content:\"AB\"; content:\"CD\"; distance:2; within:4; sid:600;)");
		sig_build(&p);
		/* CD ở offset 4: cách cuối AB (=2) đúng 2 byte → khớp */
		check(run(&p, "ABxxCDyy", SIG_PROTO_TCP, 80, 0) == 0,
		      "CD đúng vị trí (distance 2) → khớp");
		/* CD ngay sau AB (distance 0 < 2) → ngoài cửa sổ → không khớp */
		check(run(&p, "ABCDxxxx", SIG_PROTO_TCP, 80, 0) == -1,
		      "CD sai vị trí (quá gần) → không khớp");
		sig_ruleset_free(&p);
	}

	printf("T17 dsize (độ dài payload):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"big\"; "
			"content:\"X\"; dsize:>5; sid:601;)");
		sig_build(&p);
		check(run(&p, "Xyyyyyy", SIG_PROTO_TCP, 80, 0) == 0,
		      "payload 7>5 byte → khớp");
		check(run(&p, "Xyy", SIG_PROTO_TCP, 80, 0) == -1,
		      "payload 3 byte (≤5) → dsize fail → không khớp");
		sig_ruleset_free(&p);
	}

	printf("T18 distance/dsize KHÔNG còn ALERT-cap (P2 đã hỗ trợ):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		int rc = sig_parse_line(&p,
			"drop tcp any any -> any any (msg:\"full\"; "
			"content:\"AAAA\"; content:\"BBBB\"; distance:0; "
			"dsize:>3; sid:602;)");
		check(rc == SIG_LINE_FULL, "rule distance+dsize → SIG_LINE_FULL");
		check(p.rules[0].fidelity == SIG_FID_FULL, "fidelity FULL (được DROP)");
		check(p.rules[0].dsize_min == 4, "dsize:>3 → min=4");
		sig_ruleset_free(&p);
	}

	/* ── P3: byte_test / byte_jump ── */
	printf("T19 byte_test (đọc trường 2 byte, so sánh):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		int rc = sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"bt\"; content:\"AB\"; "
			"byte_test:2,=,256,0,relative; sid:700;)");
		check(rc == SIG_LINE_FULL, "byte_test → SIG_LINE_FULL (đã hỗ trợ)");
		sig_build(&p);
		struct flow_ctx fc = { SIG_PROTO_TCP, 80, 0 };
		uint8_t ok[]  = { 'A','B', 0x01,0x00 };   /* field=256 → khớp */
		uint8_t bad[] = { 'A','B', 0x00,0x05 };   /* field=5 → không   */
		check(sig_match(&p, ok,  sizeof(ok),  &fc) == 0, "field==256 → khớp");
		check(sig_match(&p, bad, sizeof(bad), &fc) == -1, "field!=256 → không khớp");
		sig_ruleset_free(&p);
	}

	printf("T20 byte_jump (nhảy qua trường độ dài rồi khớp content):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"bj\"; content:\"LEN\"; "
			"byte_jump:1,0,relative; content:\"X\"; distance:0; within:1; "
			"sid:701;)");
		sig_build(&p);
		struct flow_ctx fc = { SIG_PROTO_TCP, 80, 0 };
		uint8_t ok[]  = { 'L','E','N', 0x02, 'Z','Z','X' }; /* nhảy 2 → X@6 */
		uint8_t bad[] = { 'L','E','N', 0x00, 'Z','Z','X' }; /* nhảy 0 → X sai chỗ */
		check(sig_match(&p, ok,  sizeof(ok),  &fc) == 0, "jump đúng → X tại vị trí → khớp");
		check(sig_match(&p, bad, sizeof(bad), &fc) == -1, "jump sai → X lệch → không khớp");
		sig_ruleset_free(&p);
	}

	printf("T21 byte_test/jump offset khổng lồ → bounds-check, không crash:\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"oob\"; content:\"AB\"; "
			"byte_test:4,>,0,1000; sid:702;)");
		sig_build(&p);
		struct flow_ctx fc = { SIG_PROTO_TCP, 80, 0 };
		uint8_t pl[] = { 'A','B','x','x' };
		check(sig_match(&p, pl, sizeof(pl), &fc) == -1,
		      "đọc ngoài buffer → fail-closed, không khớp/crash");
		sig_ruleset_free(&p);
	}

	/* ── P6: flow keyword ── */
	printf("T22 flow:established,to_server (lọc hướng/trạng thái):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"flow\"; content:\"GET\"; "
			"flow:established,to_server; sid:800;)");
		sig_build(&p);
		const uint8_t *pl = (const uint8_t *)"GET /x";
		size_t pn = 6;
		struct flow_ctx est_srv = { SIG_PROTO_TCP, 80, 0, 1, 1 };
		struct flow_ctx not_est = { SIG_PROTO_TCP, 80, 0, 0, 1 };
		struct flow_ctx to_cli  = { SIG_PROTO_TCP, 80, 0, 1, 0 };
		check(sig_match(&p, pl, pn, &est_srv) == 0,  "established+to_server → khớp");
		check(sig_match(&p, pl, pn, &not_est) == -1, "chưa established → không khớp");
		check(sig_match(&p, pl, pn, &to_cli)  == -1, "chiều to_client → không khớp");
		sig_ruleset_free(&p);
	}

	/* ── P5: flowbits ── */
	printf("T23 flowbits (set/noalert + isset đa-gói):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		sig_parse_line(&p,   /* rule 0: set cờ + noalert */
			"alert tcp any any -> any 80 (msg:\"setter\"; content:\"SET\"; "
			"flowbits:set,evil; flowbits:noalert; sid:900;)");
		sig_parse_line(&p,   /* rule 1: isset cờ */
			"alert tcp any any -> any 80 (msg:\"trig\"; content:\"TRIG\"; "
			"flowbits:isset,evil; sid:901;)");
		sig_build(&p);
		check(p.rules[0].n_fb == 1 && p.rules[0].fb_noalert == 1,
		      "rule0: 1 op set + noalert");
		check(p.rules[1].n_fb == 1, "rule1: 1 op isset");
		check(p.rules[1].fidelity == SIG_FID_FULL,
		      "isset trên cờ CÓ setter → FULL (được DROP)");

		struct flowbit_state fb; memset(&fb, 0, sizeof(fb));
		struct flow_ctx fc  = { SIG_PROTO_TCP, 80, 0, 1, 1, &fb };
		struct flow_ctx fcn = { SIG_PROTO_TCP, 80, 0, 1, 1, NULL };
		check(sig_verify(&p, 1, (const uint8_t *)"xTRIGx", 6, &fc) == 0,
		      "isset chưa set → không match");
		sig_flowbits_apply(&p.rules[0], &fb);   /* set evil */
		check(sig_verify(&p, 1, (const uint8_t *)"xTRIGx", 6, &fc) == 1,
		      "sau khi set → isset match");
		check(sig_verify(&p, 1, (const uint8_t *)"xTRIGx", 6, &fcn) == 0,
		      "fb=NULL (không track) → fail-safe, không match");
		sig_ruleset_free(&p);
	}

	printf("T24 flowbits lan truyền: isnotset cờ KHÔNG ai set → ALERT-cap:\n");
	{
		struct sig_ruleset q; sig_ruleset_init(&q);
		sig_parse_line(&q,
			"drop tcp any any -> any 80 (msg:\"orphan\"; content:\"AAAA\"; "
			"flowbits:isnotset,never_set; sid:902;)");
		sig_build(&q);
		check(q.rules[0].fidelity == SIG_FID_ALERT,
		      "isnotset cờ mồ côi → KẸP ALERT (tránh false-drop)");
		sig_ruleset_free(&q);
	}

	/* ── P6: sticky buffers (http_uri / tls_sni) ── */
	printf("T25 http_uri buffer (content khớp trong URI, không phải body):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		sig_parse_line(&p,
			"alert tcp any any -> any 80 (msg:\"uri\"; content:\"/admin\"; "
			"http_uri; sid:1000;)");
		check(p.rules[0].content[0].buffer == SIG_BUF_HTTP_URI,
		      "content gắn buffer http_uri");
		sig_build(&p);
		struct flow_ctx fc; memset(&fc, 0, sizeof fc);
		fc.proto = SIG_PROTO_TCP; fc.dport = 80; fc.to_server = 1;

		const char *r1 = "GET /admin/x HTTP/1.1\r\nHost: a\r\n\r\nbody";
		struct match_buffers mb1;
		bufs_init_raw(&mb1, (const uint8_t *)r1, (int)strlen(r1));
		bufs_extract(&mb1, (const uint8_t *)r1, (int)strlen(r1));
		check(mb1.len[SIG_BUF_HTTP_METHOD] == 3, "method='GET' (3 byte)");
		fc.bufs = &mb1;
		check(sig_verify(&p, 0, (const uint8_t *)r1, (int)strlen(r1), &fc) == 1,
		      "/admin trong URI → match");

		const char *r2 = "GET /home HTTP/1.1\r\nHost: a\r\n\r\n/admin";
		struct match_buffers mb2;
		bufs_init_raw(&mb2, (const uint8_t *)r2, (int)strlen(r2));
		bufs_extract(&mb2, (const uint8_t *)r2, (int)strlen(r2));
		fc.bufs = &mb2;
		check(sig_verify(&p, 0, (const uint8_t *)r2, (int)strlen(r2), &fc) == 0,
		      "/admin chỉ trong body → http_uri KHÔNG match");
		sig_ruleset_free(&p);
	}

	printf("T26 tls_sni buffer (content khớp trong SNI):\n");
	{
		struct sig_ruleset q; sig_ruleset_init(&q);
		sig_parse_line(&q,
			"alert tls any any -> any any (msg:\"sni\"; content:\"evil.com\"; "
			"tls_sni; sid:1001;)");
		check(q.rules[0].content[0].buffer == SIG_BUF_TLS_SNI,
		      "content gắn buffer tls_sni");
		sig_build(&q);
		struct match_buffers mb; memset(&mb, 0, sizeof mb);
		struct flow_ctx fc; memset(&fc, 0, sizeof fc);
		fc.proto = SIG_PROTO_ANY; fc.to_server = 1; fc.bufs = &mb;

		mb.b[SIG_BUF_TLS_SNI]   = (const uint8_t *)"login.evil.com";
		mb.len[SIG_BUF_TLS_SNI] = 14;
		check(sig_verify(&q, 0, (const uint8_t *)"x", 1, &fc) == 1,
		      "SNI chứa evil.com → match");
		mb.b[SIG_BUF_TLS_SNI]   = (const uint8_t *)"safe.com";
		mb.len[SIG_BUF_TLS_SNI] = 8;
		check(sig_verify(&q, 0, (const uint8_t *)"x", 1, &fc) == 0,
		      "SNI khác → không match");
		sig_ruleset_free(&q);
	}

	/* ── P4: pcre ── */
#ifdef HAVE_PCRE
	printf("T27 pcre (HAVE_PCRE): khớp regex + chống ReDoS:\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		int rc = sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"pcre\"; content:\"id=\"; "
			"pcre:\"/id=\\d+/\"; sid:900;)");
		check(rc == SIG_LINE_FULL, "pcre rule → FULL (được DROP)");
		check(p.rules[0].pcre != NULL, "regex đã compile");
		sig_build(&p);
		check(run(&p, "x id=12345 y", SIG_PROTO_TCP, 80, 0) == 0,
		      "/id=\\d+/ khớp 'id=12345'");
		check(run(&p, "x id=abc y", SIG_PROTO_TCP, 80, 0) == -1,
		      "'id=abc' → \\d+ trượt → không khớp");
		sig_ruleset_free(&p);
	}
	printf("T28 pcre regex ác (catastrophic backtracking) → cắt theo limit:\n");
	{
		struct sig_ruleset q; sig_ruleset_init(&q);
		sig_parse_line(&q,
			"alert tcp any any -> any any (msg:\"redos\"; content:\"a\"; "
			"pcre:\"/(a+)+$/\"; sid:901;)");
		sig_build(&q);
		char bad[64]; memset(bad, 'a', 60); bad[60] = 'X'; bad[61] = '\0';
		/* không có match-limit → treo; có limit → trả nhanh, no-match */
		check(run(&q, bad, SIG_PROTO_TCP, 80, 0) == -1,
		      "regex ác bị cắt theo match-limit (không treo)");
		sig_ruleset_free(&q);
	}
#else
	printf("T27 pcre (!HAVE_PCRE): rule pcre KẸP ALERT (sanctioned-off):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		int rc = sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"pcre\"; "
			"content:\"GOODCONTENT\"; pcre:\"/x/\"; sid:900;)");
		check(rc == SIG_LINE_ALERT, "pcre rule → ALERT-cap (không build pcre)");
		check(p.rules[0].fidelity == SIG_FID_ALERT, "fidelity ALERT");
		sig_ruleset_free(&p);
	}
#endif

	printf("\n%s (%d test thất bại)\n",
	       g_failed ? "=== CÓ LỖI ===" : "=== TẤT CẢ PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
