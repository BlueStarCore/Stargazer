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

	printf("== test 6: filter category ghép rule, GIỮ action gốc (không override) ==\n");
	{
		struct ips_filter f[] = {
			{ IPS_FT_CATEGORY, "scan" },
		};
		int n = ips_compile_filters(repo, f, 1, out);
		CHECK(n == 1, "ghi 1 rule từ scan");
		CHECK(file_contains(out, "alert tcp"), "giữ action gốc (alert)");
		CHECK(!file_contains(out, "drop tcp"), "KHÔNG override action");
	}

	printf("== test 7: filter signature theo SID, giữ action gốc ==\n");
	{
		struct ips_filter f[] = {
			{ IPS_FT_SIGNATURE, "2" },
		};
		int n = ips_compile_filters(repo, f, 1, out);
		CHECK(n == 1, "tìm + ghi đúng 1 rule sid:2");
		CHECK(file_contains(out, "alert tcp") && file_contains(out, "sid:2;"),
		      "sid:2 giữ action gốc (alert)");
		CHECK(!file_contains(out, "sid:1;"), "không lấy sid khác");
	}

	printf("== test 8: nhiều filter kết hợp, đều giữ action gốc ==\n");
	{
		struct ips_filter f[] = {
			{ IPS_FT_CATEGORY,  "web" },
			{ IPS_FT_SIGNATURE, "1"   },
		};
		int n = ips_compile_filters(repo, f, 2, out);
		CHECK(n == 2, "web(1) + sid:1(1) = 2 rule");
		CHECK(file_contains(out, "sid:1;"), "có sid:1");
		CHECK(!file_contains(out, "drop tcp"), "KHÔNG override (đều alert gốc)");
	}

	printf("== test 9: catalog JSON liệt kê signature ==\n");
	{
		/* rule có msg + cve để kiểm parse */
		snprintf(p, sizeof(p), "%s/web.rules", repo);
		write_file(p, "alert tcp any any -> any 80 (msg:\"ET WEB SQLi\"; "
			      "reference:cve,2008-1234; sid:2002; rev:3;)\n");
		char jbuf[8192];
		int n = ips_catalog_to_json(repo, jbuf, sizeof(jbuf), NULL, 0);
		CHECK(n > 0, "catalog trả JSON");
		CHECK(strstr(jbuf, "\"sid\":2002") != NULL, "có sid 2002");
		CHECK(strstr(jbuf, "ET WEB SQLi") != NULL, "có name (msg)");
		CHECK(strstr(jbuf, "CVE-2008-1234") != NULL, "có CVE parse");
		CHECK(strstr(jbuf, "\"category\":\"web\"") != NULL, "category=web");
		CHECK(jbuf[0] == '[' && jbuf[n-1] == ']', "JSON array hợp lệ");
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
