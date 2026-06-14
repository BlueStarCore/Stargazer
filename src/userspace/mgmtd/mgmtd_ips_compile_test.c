/* SPDX-License-Identifier: MIT */
/* Host test cho ips_compile_categories — dựng repo tạm, kiểm ghép category. */
#define _POSIX_C_SOURCE 200809L
#include "mgmtd_ips_compile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fail;
#define CHECK(c, m) do { if (!(c)) { printf("  FAIL: %s\n", m); g_fail++; } \
			 else printf("  ok:   %s\n", m); } while (0)

static void write_file(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");
	if (f) { fputs(content, f); fclose(f); }
}

/* file out có chứa substr? */
static int file_contains(const char *path, const char *substr)
{
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	char buf[65536];
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	buf[n] = '\0';
	fclose(f);
	return strstr(buf, substr) != NULL;
}

int main(void)
{
	char repo[] = "/tmp/sg_ips_repo_XXXXXX";
	if (!mkdtemp(repo)) { perror("mkdtemp"); return 2; }
	char p[512];

	snprintf(p, sizeof(p), "%s/scan.rules", repo);
	write_file(p, "alert tcp any any -> any any (msg:\"SCAN rule\"; sid:1;)\n");
	snprintf(p, sizeof(p), "%s/web.rules", repo);
	write_file(p, "alert tcp any any -> any 80 (msg:\"WEB rule\"; sid:2;)\n");
	snprintf(p, sizeof(p), "%s/malware.rules", repo);
	write_file(p, "alert tcp any any -> any any (msg:\"MALWARE rule\"; sid:3;)\n");

	char out[] = "/tmp/sg_ips_out.rules";

	printf("== test 1: categories='scan,web' ghép đúng 2 file ==\n");
	{
		int n = ips_compile_categories(repo, "scan,web", out);
		CHECK(n == 2, "ghép 2 category");
		CHECK(file_contains(out, "SCAN rule"), "có rule scan");
		CHECK(file_contains(out, "WEB rule"), "có rule web");
		CHECK(!file_contains(out, "MALWARE rule"), "KHÔNG có malware (không chọn)");
	}

	printf("== test 2: categories='all' ghép mọi file ==\n");
	{
		int n = ips_compile_categories(repo, "all", out);
		CHECK(n == 3, "ghép cả 3 category");
		CHECK(file_contains(out, "SCAN rule") &&
		      file_contains(out, "WEB rule") &&
		      file_contains(out, "MALWARE rule"), "đủ 3 rule");
	}

	printf("== test 3: category thiếu file → bỏ qua, không lỗi ==\n");
	{
		int n = ips_compile_categories(repo, "scan,nosuch", out);
		CHECK(n == 1, "chỉ ghép scan (nosuch bỏ qua)");
		CHECK(file_contains(out, "SCAN rule"), "có scan");
	}

	printf("== test 4: khoảng trắng trong list ==\n");
	{
		int n = ips_compile_categories(repo, " scan , web ", out);
		CHECK(n == 2, "trim khoảng trắng OK");
	}

	printf("== test 5: out_path không ghi được → -1 ==\n");
	{
		int n = ips_compile_categories(repo, "scan",
					       "/nonexistent_dir/x.rules");
		CHECK(n == -1, "out path lỗi → -1");
	}

	printf("== test 6 (P7): category + action=block → rewrite drop ==\n");
	{
		struct ips_filter f[] = {
			{ IPS_FT_CATEGORY, "scan", IPS_FA_BLOCK },
		};
		int n = ips_compile_filters(repo, f, 1, out);
		CHECK(n == 1, "ghi 1 rule từ scan");
		CHECK(file_contains(out, "drop tcp"), "action block → drop");
		CHECK(!file_contains(out, "alert tcp"), "không còn alert gốc");
	}

	printf("== test 7 (P7): signature + action=pass → KHÔNG ghi (whitelist) ==\n");
	{
		struct ips_filter f[] = {
			{ IPS_FT_SIGNATURE, "1", IPS_FA_PASS },
		};
		int n = ips_compile_filters(repo, f, 1, out);
		CHECK(n == 0, "pass → không ghi rule nào");
		CHECK(!file_contains(out, "sid:1;"), "sid:1 bị loại khỏi profile");
	}

	printf("== test 8 (P7): precedence signature override > category ==\n");
	{
		/* category scan (action alert) chứa sid:1; override sid:1 = block.
		 * sid:1 phải ra DROP, ghi ĐÚNG 1 lần (không alert). */
		struct ips_filter f[] = {
			{ IPS_FT_CATEGORY,  "scan", IPS_FA_ALERT },
			{ IPS_FT_SIGNATURE, "1",    IPS_FA_BLOCK },
		};
		int n = ips_compile_filters(repo, f, 2, out);
		CHECK(n == 1, "sid:1 ghi đúng 1 lần (precedence dedup)");
		CHECK(file_contains(out, "drop tcp"), "sid:1 theo override block → drop");
		CHECK(!file_contains(out, "alert tcp"), "KHÔNG ghi bản category alert");
	}

	printf("== test 9: catalog JSON liệt kê signature ==\n");
	{
		/* rule có msg + cve để kiểm parse */
		snprintf(p, sizeof(p), "%s/web.rules", repo);
		write_file(p, "alert tcp any any -> any 80 (msg:\"ET WEB SQLi\"; "
			      "reference:cve,2008-1234; sid:2002; rev:3;)\n");
		char jbuf[8192];
		int tr = 0;
		int n = ips_catalog_to_json(repo, jbuf, sizeof(jbuf), NULL, 0, NULL, &tr);
		CHECK(n > 0, "catalog trả JSON");
		CHECK(strstr(jbuf, "\"sid\":2002") != NULL, "có sid 2002");
		CHECK(strstr(jbuf, "ET WEB SQLi") != NULL, "có name (msg)");
		CHECK(strstr(jbuf, "CVE-2008-1234") != NULL, "có CVE parse");
		CHECK(strstr(jbuf, "\"category\":\"web\"") != NULL, "category=web");
		CHECK(jbuf[0] == '[' && jbuf[n-1] == ']', "JSON array hợp lệ");
		CHECK(tr == 0, "không truncated (buffer đủ)");
	}

	printf("== test 10 (P7-search): lọc query chỉ trả entry khớp ==\n");
	{
		int tr = 0;
		char jbuf[8192];
		/* repo có scan(sid1), web(sid2002 'ET WEB SQLi'), malware(sid3) */
		ips_catalog_to_json(repo, jbuf, sizeof(jbuf), NULL, 0, "SQLi", &tr);
		CHECK(strstr(jbuf, "\"sid\":2002") != NULL, "khớp 'SQLi' → có sid 2002");
		CHECK(strstr(jbuf, "\"sid\":1,") == NULL && strstr(jbuf, "\"sid\":3,") == NULL,
		      "không khớp → loại sid khác");
		/* query theo sid */
		ips_catalog_to_json(repo, jbuf, sizeof(jbuf), NULL, 0, "2002", &tr);
		CHECK(strstr(jbuf, "\"sid\":2002") != NULL, "khớp theo sid");
	}

	/* dọn */
	snprintf(p, sizeof(p), "%s/scan.rules", repo); unlink(p);
	snprintf(p, sizeof(p), "%s/web.rules", repo); unlink(p);
	snprintf(p, sizeof(p), "%s/malware.rules", repo); unlink(p);
	rmdir(repo);
	unlink(out);

	if (g_fail) { printf("\n== %d FAIL ==\n", g_fail); return 1; }
	printf("\n== TẤT CẢ ips_compile TEST PASS ==\n");
	return 0;
}
