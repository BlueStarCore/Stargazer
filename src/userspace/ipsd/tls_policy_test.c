/* SPDX-License-Identifier: MIT */
/*
 * tls_policy_test.c - test quyết định SPLICE/BUMP theo SNI + bypass list.
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
	printf("== test 1: default — inspect tất cả khi list rỗng ==\n");
	{
		struct tls_policy p;
		tls_policy_init(&p);
		CHECK(tls_policy_decide(&p, "anything.com", 1) == TLS_BUMP,
		      "list rỗng → BUMP");
		tls_policy_free(&p);
	}

	printf("== test 2: exact match → SPLICE ==\n");
	{
		struct tls_policy p;
		tls_policy_init(&p);
		CHECK(tls_policy_add_bypass(&p, "bank.com") == 0, "thêm bank.com");
		CHECK(tls_policy_decide(&p, "bank.com", 1) == TLS_SPLICE,
		      "bank.com → SPLICE");
		CHECK(tls_policy_decide(&p, "www.bank.com", 1) == TLS_BUMP,
		      "www.bank.com KHÔNG khớp exact → BUMP");
		CHECK(tls_policy_decide(&p, "evilbank.com", 1) == TLS_BUMP,
		      "evilbank.com không khớp → BUMP");
		tls_policy_free(&p);
	}

	printf("== test 3: wildcard *.x → khớp subdomain, KHÔNG khớp apex ==\n");
	{
		struct tls_policy p;
		tls_policy_init(&p);
		tls_policy_add_bypass(&p, "*.bank.com");
		CHECK(tls_policy_decide(&p, "www.bank.com", 1) == TLS_SPLICE,
		      "www.bank.com → SPLICE");
		CHECK(tls_policy_decide(&p, "a.b.bank.com", 1) == TLS_SPLICE,
		      "a.b.bank.com → SPLICE (đa cấp)");
		CHECK(tls_policy_decide(&p, "bank.com", 1) == TLS_BUMP,
		      "bank.com (apex) KHÔNG khớp *.bank.com → BUMP");
		CHECK(tls_policy_decide(&p, "notbank.com", 1) == TLS_BUMP,
		      "notbank.com → BUMP");
		CHECK(tls_policy_decide(&p, "xbank.com", 1) == TLS_BUMP,
		      "xbank.com (thiếu ranh giới '.') → BUMP");
		tls_policy_free(&p);
	}

	printf("== test 4: case-insensitive ==\n");
	{
		struct tls_policy p;
		tls_policy_init(&p);
		tls_policy_add_bypass(&p, "Bank.COM");
		tls_policy_add_bypass(&p, "*.Secure.IO");
		CHECK(tls_policy_decide(&p, "BANK.com", 1) == TLS_SPLICE,
		      "BANK.com khớp Bank.COM");
		CHECK(tls_policy_decide(&p, "API.secure.io", 1) == TLS_SPLICE,
		      "API.secure.io khớp *.Secure.IO");
		tls_policy_free(&p);
	}

	printf("== test 5: no-SNI policy ==\n");
	{
		struct tls_policy p;
		tls_policy_init(&p);
		CHECK(tls_policy_decide(&p, NULL, 0) == TLS_BUMP,
		      "no SNI, mặc định → BUMP");
		p.no_sni = TLS_NO_SNI_SPLICE;
		CHECK(tls_policy_decide(&p, NULL, 0) == TLS_SPLICE,
		      "no SNI, policy SPLICE → SPLICE");
		CHECK(tls_policy_decide(&p, "", 1) == TLS_SPLICE,
		      "SNI rỗng coi như no-SNI");
		tls_policy_free(&p);
	}

	printf("== test 6: default_bump=0 (chỉ inspect domain trong list) ==\n");
	{
		struct tls_policy p;
		tls_policy_init(&p);
		p.default_bump = 0;          /* đảo: mặc định SPLICE */
		tls_policy_add_bypass(&p, "inspect-me.com");
		/* lưu ý: ngữ nghĩa list là "bypass list" nên domain trong list vẫn
		 * SPLICE; default_bump=0 nghĩa domain NGOÀI list cũng SPLICE →
		 * thực tế tắt inspect. Kiểm đúng hành vi đó. */
		CHECK(tls_policy_decide(&p, "other.com", 1) == TLS_SPLICE,
		      "ngoài list + default_bump=0 → SPLICE");
		CHECK(tls_policy_decide(&p, "inspect-me.com", 1) == TLS_SPLICE,
		      "trong bypass list luôn SPLICE");
		tls_policy_free(&p);
	}

	printf("== test 7: chuẩn hóa + pattern lỗi ==\n");
	{
		struct tls_policy p;
		tls_policy_init(&p);
		CHECK(tls_policy_add_bypass(&p, "  Trailing.Dot.com.  ") == 0,
		      "thêm pattern có khoảng trắng + dấu chấm cuối");
		CHECK(tls_policy_decide(&p, "trailing.dot.com", 1) == TLS_SPLICE,
		      "khớp sau khi chuẩn hóa");
		CHECK(tls_policy_add_bypass(&p, "") == -1, "pattern rỗng → lỗi");
		CHECK(tls_policy_add_bypass(&p, "*") == -1, "pattern '*' → lỗi");
		CHECK(tls_policy_add_bypass(&p, "*.") == -1, "pattern '*.' → lỗi");
		CHECK(tls_policy_add_bypass(&p, NULL) == -1, "pattern NULL → lỗi");
		tls_policy_free(&p);
	}

	printf("== test 8: nhiều pattern, free sạch (ASan) ==\n");
	{
		struct tls_policy p;
		tls_policy_init(&p);
		for (int i = 0; i < 100; i++) {
			char buf[64];
			snprintf(buf, sizeof(buf), "*.domain%d.example", i);
			tls_policy_add_bypass(&p, buf);
		}
		CHECK(tls_policy_decide(&p, "a.domain42.example", 1) == TLS_SPLICE,
		      "khớp 1 trong 100 pattern");
		CHECK(tls_policy_decide(&p, "a.domain999.example", 1) == TLS_BUMP,
		      "không khớp → BUMP");
		tls_policy_free(&p);   /* ASan kiểm leak */
	}

	if (g_fail) {
		printf("\n== %d TEST FAIL ==\n", g_fail);
		return 1;
	}
	printf("\n== TẤT CẢ TLS policy TEST PASS ==\n");
	return 0;
}
