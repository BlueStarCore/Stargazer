/* SPDX-License-Identifier: MIT */
/*
 * sig_test.c - Unit test for the rule parser + payload matching, runs on the HOST.
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

/* Main ruleset used by most tests. */
static const char *RULES[] = {
	"alert tcp any any -> any 80 (msg:\"SQLi UNION SELECT\"; "
		"content:\"UNION\"; nocase; content:\"SELECT\"; nocase; sid:2008538; rev:5;)",
	"drop tcp any any -> any 4444 (msg:\"bind shell magic\"; "
		"content:\"|de ad be ef|\"; sid:9001; rev:1;)",
	"alert tcp any any -> any 22 (msg:\"SSH banner\"; content:\"SSH-\"; sid:7001;)",
	"# this is a comment, must be ignored",
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
	check(rs.n_rules == 5, "5 rules loaded (comment skipped)");
	check(rs.rules[0].n_content == 2, "SQLi rule has 2 contents");
	check(rs.rules[0].action == SIG_ALERT, "SQLi = alert");
	check(rs.rules[0].n_dport == 1 && rs.rules[0].dport_list[0] == 80,
	      "SQLi dport 80");
	check(rs.rules[0].sid == 2008538, "sid read correctly");
	check(rs.rules[0].content[0].nocase == 1, "first content nocase");
	check(rs.rules[0].fast == 1, "fast pattern = SELECT (longer)");
	check(strstr(rs.rules[0].msg, "SQLi") != NULL, "msg stored correctly");

	printf("T2 match with correct port + correct content order:\n");
	check(run(&rs, "GET /a?id=1 UNION SELECT pass FROM tbl", SIG_PROTO_TCP, 80, 0)
	      == 0, "SQLi @dport80 → rule 0");

	printf("T3 wrong port → no match:\n");
	check(run(&rs, "GET /a?id=1 UNION SELECT pass", SIG_PROTO_TCP, 443, 0)
	      == -1, "same payload but dport 443 → -1");

	printf("T4 wrong content order → no match:\n");
	check(run(&rs, "SELECT first then UNION later", SIG_PROTO_TCP, 80, 0)
	      == -1, "SELECT before UNION → no match (order enforced)");

	printf("T5 nocase:\n");
	check(run(&rs, "q=1 union select 0", SIG_PROTO_TCP, 80, 0)
	      == 0, "lowercase still matches when nocase");

	printf("T6 binary content |hex|:\n");
	{
		uint8_t p[] = { 0x01, 0x02, 0xde, 0xad, 0xbe, 0xef, 0x03 };
		struct flow_ctx fc = { SIG_PROTO_TCP, 4444, 0 };
		int idx = sig_match(&rs, p, sizeof(p), &fc);
		check(idx == 1 && rs.rules[idx].action == SIG_DROP,
		      "deadbeef @dport4444 → rule DROP");
	}

	printf("T7 offset/depth:\n");
	check(run(&rs, "zzabc", SIG_PROTO_TCP, 8080, 0) >= 0,
	      "abc at offset 2 → match");
	check(run(&rs, "abczz", SIG_PROTO_TCP, 8080, 0) == -1,
	      "abc at offset 0 (outside window) → no match");

	printf("T8 TCP flags (flags:S):\n");
	{
		int with_syn = run(&rs, "x", SIG_PROTO_TCP, 8080, SIG_TCP_SYN);
		int no_syn   = run(&rs, "x", SIG_PROTO_TCP, 8080, SIG_TCP_ACK);
		check(with_syn >= 0 && rs.rules[with_syn].sid == 5, "SYN set → matches flags:S rule");
		check(no_syn == -1, "no SYN → no match");
	}

	sig_ruleset_free(&rs);

	printf("T9 priority DROP > ALERT:\n");
	{
		struct sig_ruleset p;
		sig_ruleset_init(&p);
		sig_parse_line(&p, "alert tcp any any -> any any (msg:\"a\"; content:\"AAA\"; sid:100;)");
		sig_parse_line(&p, "drop tcp any any -> any any (msg:\"d\"; content:\"BBB\"; sid:101;)");
		sig_build(&p);
		int idx = run(&p, "xxAAAyyBBBzz", SIG_PROTO_TCP, 1234, 0);
		check(idx >= 0 && p.rules[idx].action == SIG_DROP,
		      "hits both ALERT and DROP → returns DROP");
		sig_ruleset_free(&p);
	}

	/* ── P0: fidelity classification + load-time safety ── */
	printf("T10 fidelity-cap (content + unsupported keyword → ALERT):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		/* content strong enough but has isdataat (unsupported) → loaded, CLAMPED
		 * to ALERT despite drop action. (isdataat always unsupported, independent
		 * of HAVE_PCRE.) */
		int rc = sig_parse_line(&p,
			"drop tcp any any -> any any (msg:\"unsup rule\"; "
			"content:\"EVILPAYLOAD\"; isdataat:50,relative; sid:300;)");
		check(rc == SIG_LINE_ALERT, "rule with isdataat → returns SIG_LINE_ALERT");
		check(p.n_rules == 1, "still loaded (1 L2 rule)");
		check(p.rules[0].fidelity == SIG_FID_ALERT, "fidelity = ALERT");
		check(p.rules[0].has_unsup & SIG_U_DSIZE, "has_unsup has DSIZE bit set");
		check(p.rules[0].action == SIG_DROP, "ORIGINAL action stays SIG_DROP (kept)");
		sig_ruleset_free(&p);
	}

	printf("T11 reputation/catch-all (no content, no selector) → DROPPED:\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		int rc = sig_parse_line(&p,
			"alert ip any any -> any any (msg:\"ET CNC IP\"; "
			"reference:url,x; sid:400;)");
		check(rc == SIG_LINE_SKIP_REP, "catch-all → SIG_LINE_SKIP_REP");
		check(p.n_rules == 0, "NOT loaded (no L2)");
		sig_ruleset_free(&p);
	}

	printf("T12 rule with NO content (L1 signature removed) → DROPPED:\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		int rc = sig_parse_line(&p,
			"alert tcp any any -> any 22 (msg:\"ssh flood\"; "
			"flags:S; sid:401;)");
		check(rc == SIG_LINE_SKIP_NOCONTENT,
		      "has selector but no content → SKIP_NOCONTENT");
		check(p.n_rules == 0, "NOT loaded (engine only has L2 content)");
		sig_ruleset_free(&p);
	}

	printf("T13 content too weak + unsupported keyword → DROPPED (unsupported):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		int rc = sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"weak\"; "
			"content:\"ab\"; isdataat:10,relative; sid:402;)");
		check(rc == SIG_LINE_SKIP_UNSUP, "content≤2 + isdataat → SKIP_UNSUP");
		check(p.n_rules == 0, "not loaded");
		sig_ruleset_free(&p);
	}

	printf("T14 bad hex → drop that content, no crash:\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		/* |de ad be| ok but |zz| bad → 2nd content dropped, content 1 remains */
		sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"badhex\"; "
			"content:\"GOODCONTENT\"; content:\"|zz|\"; sid:403;)");
		check(p.n_rules == 1, "rule still loaded (1 valid content)");
		check(p.rules[0].n_content == 1, "bad-hex content dropped");
		sig_ruleset_free(&p);
	}

	printf("T15 coverage stats from sig_load_file:\n");
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
	printf("T16 distance/within (relative positioning):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"rel\"; "
			"content:\"AB\"; content:\"CD\"; distance:2; within:4; sid:600;)");
		sig_build(&p);
		/* CD at offset 4: exactly 2 bytes from end of AB (=2) → match */
		check(run(&p, "ABxxCDyy", SIG_PROTO_TCP, 80, 0) == 0,
		      "CD at correct position (distance 2) → match");
		/* CD right after AB (distance 0 < 2) → outside window → no match */
		check(run(&p, "ABCDxxxx", SIG_PROTO_TCP, 80, 0) == -1,
		      "CD at wrong position (too close) → no match");
		sig_ruleset_free(&p);
	}

	printf("T17 dsize (payload length):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"big\"; "
			"content:\"X\"; dsize:>5; sid:601;)");
		sig_build(&p);
		check(run(&p, "Xyyyyyy", SIG_PROTO_TCP, 80, 0) == 0,
		      "payload 7>5 bytes → match");
		check(run(&p, "Xyy", SIG_PROTO_TCP, 80, 0) == -1,
		      "payload 3 bytes (≤5) → dsize fail → no match");
		sig_ruleset_free(&p);
	}

	printf("T18 distance/dsize NO LONGER ALERT-capped (P2 supported):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		int rc = sig_parse_line(&p,
			"drop tcp any any -> any any (msg:\"full\"; "
			"content:\"AAAA\"; content:\"BBBB\"; distance:0; "
			"dsize:>3; sid:602;)");
		check(rc == SIG_LINE_FULL, "rule distance+dsize → SIG_LINE_FULL");
		check(p.rules[0].fidelity == SIG_FID_FULL, "fidelity FULL (may DROP)");
		check(p.rules[0].dsize_min == 4, "dsize:>3 → min=4");
		sig_ruleset_free(&p);
	}

	/* ── P3: byte_test / byte_jump ── */
	printf("T19 byte_test (read a 2-byte field, compare):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		int rc = sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"bt\"; content:\"AB\"; "
			"byte_test:2,=,256,0,relative; sid:700;)");
		check(rc == SIG_LINE_FULL, "byte_test → SIG_LINE_FULL (supported)");
		sig_build(&p);
		struct flow_ctx fc = { SIG_PROTO_TCP, 80, 0 };
		uint8_t ok[]  = { 'A','B', 0x01,0x00 };   /* field=256 → match */
		uint8_t bad[] = { 'A','B', 0x00,0x05 };   /* field=5 → no      */
		check(sig_match(&p, ok,  sizeof(ok),  &fc) == 0, "field==256 → match");
		check(sig_match(&p, bad, sizeof(bad), &fc) == -1, "field!=256 → no match");
		sig_ruleset_free(&p);
	}

	printf("T20 byte_jump (jump over a length field then match content):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"bj\"; content:\"LEN\"; "
			"byte_jump:1,0,relative; content:\"X\"; distance:0; within:1; "
			"sid:701;)");
		sig_build(&p);
		struct flow_ctx fc = { SIG_PROTO_TCP, 80, 0 };
		uint8_t ok[]  = { 'L','E','N', 0x02, 'Z','Z','X' }; /* jump 2 → X@6 */
		uint8_t bad[] = { 'L','E','N', 0x00, 'Z','Z','X' }; /* jump 0 → X wrong place */
		check(sig_match(&p, ok,  sizeof(ok),  &fc) == 0, "correct jump → X in position → match");
		check(sig_match(&p, bad, sizeof(bad), &fc) == -1, "wrong jump → X off → no match");
		sig_ruleset_free(&p);
	}

	printf("T21 byte_test/jump huge offset → bounds-check, no crash:\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"oob\"; content:\"AB\"; "
			"byte_test:4,>,0,1000; sid:702;)");
		sig_build(&p);
		struct flow_ctx fc = { SIG_PROTO_TCP, 80, 0 };
		uint8_t pl[] = { 'A','B','x','x' };
		check(sig_match(&p, pl, sizeof(pl), &fc) == -1,
		      "read out of buffer → fail-closed, no match/crash");
		sig_ruleset_free(&p);
	}

	/* ── P6: flow keyword ── */
	printf("T22 flow:established,to_server (filter direction/state):\n");
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
		check(sig_match(&p, pl, pn, &est_srv) == 0,  "established+to_server → match");
		check(sig_match(&p, pl, pn, &not_est) == -1, "not established → no match");
		check(sig_match(&p, pl, pn, &to_cli)  == -1, "to_client direction → no match");
		sig_ruleset_free(&p);
	}

	/* ── P5: flowbits ── */
	printf("T23 flowbits (set/noalert + multi-packet isset):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		sig_parse_line(&p,   /* rule 0: set flag + noalert */
			"alert tcp any any -> any 80 (msg:\"setter\"; content:\"SET\"; "
			"flowbits:set,evil; flowbits:noalert; sid:900;)");
		sig_parse_line(&p,   /* rule 1: isset flag */
			"alert tcp any any -> any 80 (msg:\"trig\"; content:\"TRIG\"; "
			"flowbits:isset,evil; sid:901;)");
		sig_build(&p);
		check(p.rules[0].n_fb == 1 && p.rules[0].fb_noalert == 1,
		      "rule0: 1 set op + noalert");
		check(p.rules[1].n_fb == 1, "rule1: 1 isset op");
		check(p.rules[1].fidelity == SIG_FID_FULL,
		      "isset on a flag WITH a setter → FULL (may DROP)");

		struct flowbit_state fb; memset(&fb, 0, sizeof(fb));
		struct flow_ctx fc  = { SIG_PROTO_TCP, 80, 0, 1, 1, &fb };
		struct flow_ctx fcn = { SIG_PROTO_TCP, 80, 0, 1, 1, NULL };
		check(sig_verify(&p, 1, (const uint8_t *)"xTRIGx", 6, &fc) == 0,
		      "isset not yet set → no match");
		sig_flowbits_apply(&p.rules[0], &fb);   /* set evil */
		check(sig_verify(&p, 1, (const uint8_t *)"xTRIGx", 6, &fc) == 1,
		      "after set → isset matches");
		check(sig_verify(&p, 1, (const uint8_t *)"xTRIGx", 6, &fcn) == 0,
		      "fb=NULL (not tracked) → fail-safe, no match");
		sig_ruleset_free(&p);
	}

	printf("T24 flowbits propagation: isnotset on a flag NOBODY sets → ALERT-cap:\n");
	{
		struct sig_ruleset q; sig_ruleset_init(&q);
		sig_parse_line(&q,
			"drop tcp any any -> any 80 (msg:\"orphan\"; content:\"AAAA\"; "
			"flowbits:isnotset,never_set; sid:902;)");
		sig_build(&q);
		check(q.rules[0].fidelity == SIG_FID_ALERT,
		      "isnotset on an orphan flag → CLAMP ALERT (avoid false-drop)");
		sig_ruleset_free(&q);
	}

	/* ── P6: sticky buffers (http_uri / tls_sni) ── */
	printf("T25 http_uri buffer (content matches in URI, not body):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		sig_parse_line(&p,
			"alert tcp any any -> any 80 (msg:\"uri\"; content:\"/admin\"; "
			"http_uri; sid:1000;)");
		check(p.rules[0].content[0].buffer == SIG_BUF_HTTP_URI,
		      "content tagged http_uri buffer");
		sig_build(&p);
		struct flow_ctx fc; memset(&fc, 0, sizeof fc);
		fc.proto = SIG_PROTO_TCP; fc.dport = 80; fc.to_server = 1;

		const char *r1 = "GET /admin/x HTTP/1.1\r\nHost: a\r\n\r\nbody";
		struct match_buffers mb1;
		bufs_init_raw(&mb1, (const uint8_t *)r1, (int)strlen(r1));
		bufs_extract(&mb1, (const uint8_t *)r1, (int)strlen(r1));
		check(mb1.len[SIG_BUF_HTTP_METHOD] == 3, "method='GET' (3 bytes)");
		fc.bufs = &mb1;
		check(sig_verify(&p, 0, (const uint8_t *)r1, (int)strlen(r1), &fc) == 1,
		      "/admin in URI → match");

		const char *r2 = "GET /home HTTP/1.1\r\nHost: a\r\n\r\n/admin";
		struct match_buffers mb2;
		bufs_init_raw(&mb2, (const uint8_t *)r2, (int)strlen(r2));
		bufs_extract(&mb2, (const uint8_t *)r2, (int)strlen(r2));
		fc.bufs = &mb2;
		check(sig_verify(&p, 0, (const uint8_t *)r2, (int)strlen(r2), &fc) == 0,
		      "/admin only in body → http_uri does NOT match");
		sig_ruleset_free(&p);
	}

	printf("T26 tls_sni buffer (content matches in SNI):\n");
	{
		struct sig_ruleset q; sig_ruleset_init(&q);
		sig_parse_line(&q,
			"alert tls any any -> any any (msg:\"sni\"; content:\"evil.com\"; "
			"tls_sni; sid:1001;)");
		check(q.rules[0].content[0].buffer == SIG_BUF_TLS_SNI,
		      "content tagged tls_sni buffer");
		sig_build(&q);
		struct match_buffers mb; memset(&mb, 0, sizeof mb);
		struct flow_ctx fc; memset(&fc, 0, sizeof fc);
		fc.proto = SIG_PROTO_ANY; fc.to_server = 1; fc.bufs = &mb;

		mb.b[SIG_BUF_TLS_SNI]   = (const uint8_t *)"login.evil.com";
		mb.len[SIG_BUF_TLS_SNI] = 14;
		check(sig_verify(&q, 0, (const uint8_t *)"x", 1, &fc) == 1,
		      "SNI contains evil.com → match");
		mb.b[SIG_BUF_TLS_SNI]   = (const uint8_t *)"safe.com";
		mb.len[SIG_BUF_TLS_SNI] = 8;
		check(sig_verify(&q, 0, (const uint8_t *)"x", 1, &fc) == 0,
		      "different SNI → no match");
		sig_ruleset_free(&q);
	}

	/* ── P4: pcre ── */
#ifdef HAVE_PCRE
	printf("T27 pcre (HAVE_PCRE): regex match + ReDoS protection:\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		int rc = sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"pcre\"; content:\"id=\"; "
			"pcre:\"/id=\\d+/\"; sid:900;)");
		check(rc == SIG_LINE_FULL, "pcre rule → FULL (may DROP)");
		check(p.rules[0].pcre != NULL, "regex compiled");
		sig_build(&p);
		check(run(&p, "x id=12345 y", SIG_PROTO_TCP, 80, 0) == 0,
		      "/id=\\d+/ matches 'id=12345'");
		check(run(&p, "x id=abc y", SIG_PROTO_TCP, 80, 0) == -1,
		      "'id=abc' → \\d+ fails → no match");
		sig_ruleset_free(&p);
	}
	printf("T28 malicious pcre regex (catastrophic backtracking) → cut by limit:\n");
	{
		struct sig_ruleset q; sig_ruleset_init(&q);
		sig_parse_line(&q,
			"alert tcp any any -> any any (msg:\"redos\"; content:\"a\"; "
			"pcre:\"/(a+)+$/\"; sid:901;)");
		sig_build(&q);
		char bad[64]; memset(bad, 'a', 60); bad[60] = 'X'; bad[61] = '\0';
		/* without a match-limit → hangs; with limit → returns fast, no-match */
		check(run(&q, bad, SIG_PROTO_TCP, 80, 0) == -1,
		      "malicious regex cut by match-limit (no hang)");
		sig_ruleset_free(&q);
	}
#else
	printf("T27 pcre (!HAVE_PCRE): pcre rule CLAMPED to ALERT (sanctioned-off):\n");
	{
		struct sig_ruleset p; sig_ruleset_init(&p);
		int rc = sig_parse_line(&p,
			"alert tcp any any -> any any (msg:\"pcre\"; "
			"content:\"GOODCONTENT\"; pcre:\"/x/\"; sid:900;)");
		check(rc == SIG_LINE_ALERT, "pcre rule → ALERT-cap (pcre not built)");
		check(p.rules[0].fidelity == SIG_FID_ALERT, "fidelity ALERT");
		sig_ruleset_free(&p);
	}
#endif

	printf("\n%s (%d tests failed)\n",
	       g_failed ? "=== FAILURES ===" : "=== ALL PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
