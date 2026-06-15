/* SPDX-License-Identifier: MIT */
/* Host test for ips_compile_categories — build a temp repo, verify category merge. */
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

/* does the output file contain substr? */
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

	printf("== test 1: categories='scan,web' merges exactly 2 files ==\n");
	{
		int n = ips_compile_categories(repo, "scan,web", out);
		CHECK(n == 2, "merged 2 categories");
		CHECK(file_contains(out, "SCAN rule"), "has scan rule");
		CHECK(file_contains(out, "WEB rule"), "has web rule");
		CHECK(!file_contains(out, "MALWARE rule"), "NO malware (not selected)");
	}

	printf("== test 2: categories='all' merges every file ==\n");
	{
		int n = ips_compile_categories(repo, "all", out);
		CHECK(n == 3, "merged all 3 categories");
		CHECK(file_contains(out, "SCAN rule") &&
		      file_contains(out, "WEB rule") &&
		      file_contains(out, "MALWARE rule"), "all 3 rules present");
	}

	printf("== test 3: category with missing file → skipped, no error ==\n");
	{
		int n = ips_compile_categories(repo, "scan,nosuch", out);
		CHECK(n == 1, "only scan merged (nosuch skipped)");
		CHECK(file_contains(out, "SCAN rule"), "has scan");
	}

	printf("== test 4: whitespace in the list ==\n");
	{
		int n = ips_compile_categories(repo, " scan , web ", out);
		CHECK(n == 2, "whitespace trim OK");
	}

	printf("== test 5: out_path not writable → -1 ==\n");
	{
		int n = ips_compile_categories(repo, "scan",
					       "/nonexistent_dir/x.rules");
		CHECK(n == -1, "out path error → -1");
	}

	printf("== test 6 (P7): category + action=block → rewrite drop ==\n");
	{
		struct ips_filter f[] = {
			{ IPS_FT_CATEGORY, "scan", IPS_FA_BLOCK },
		};
		int n = ips_compile_filters(repo, f, 1, out);
		CHECK(n == 1, "wrote 1 rule from scan");
		CHECK(file_contains(out, "drop tcp"), "action block → drop");
		CHECK(!file_contains(out, "alert tcp"), "no original alert left");
	}

	printf("== test 7 (P7): signature + action=pass → NOT written (whitelist) ==\n");
	{
		struct ips_filter f[] = {
			{ IPS_FT_SIGNATURE, "1", IPS_FA_PASS },
		};
		int n = ips_compile_filters(repo, f, 1, out);
		CHECK(n == 0, "pass → no rule written");
		CHECK(!file_contains(out, "sid:1;"), "sid:1 excluded from profile");
	}

	printf("== test 8 (P7): precedence signature override > category ==\n");
	{
		/* category scan (action alert) contains sid:1; override sid:1 = block.
		 * sid:1 must come out as DROP, written EXACTLY once (no alert). */
		struct ips_filter f[] = {
			{ IPS_FT_CATEGORY,  "scan", IPS_FA_ALERT },
			{ IPS_FT_SIGNATURE, "1",    IPS_FA_BLOCK },
		};
		int n = ips_compile_filters(repo, f, 2, out);
		CHECK(n == 1, "sid:1 written exactly once (precedence dedup)");
		CHECK(file_contains(out, "drop tcp"), "sid:1 follows override block → drop");
		CHECK(!file_contains(out, "alert tcp"), "category alert version NOT written");
	}

	printf("== test 9: catalog JSON lists signatures ==\n");
	{
		/* rule with msg + cve to verify parsing */
		snprintf(p, sizeof(p), "%s/web.rules", repo);
		write_file(p, "alert tcp any any -> any 80 (msg:\"ET WEB SQLi\"; "
			      "reference:cve,2008-1234; sid:2002; rev:3;)\n");
		char jbuf[8192];
		int tr = 0;
		int n = ips_catalog_to_json(repo, jbuf, sizeof(jbuf), NULL, 0, NULL, &tr);
		CHECK(n > 0, "catalog returns JSON");
		CHECK(strstr(jbuf, "\"sid\":2002") != NULL, "has sid 2002");
		CHECK(strstr(jbuf, "ET WEB SQLi") != NULL, "has name (msg)");
		CHECK(strstr(jbuf, "CVE-2008-1234") != NULL, "has CVE parsed");
		CHECK(strstr(jbuf, "\"category\":\"web\"") != NULL, "category=web");
		CHECK(jbuf[0] == '[' && jbuf[n-1] == ']', "valid JSON array");
		CHECK(tr == 0, "not truncated (buffer large enough)");
	}

	printf("== test 10 (P7-search): query filter returns only matching entries ==\n");
	{
		int tr = 0;
		char jbuf[8192];
		/* repo has scan(sid1), web(sid2002 'ET WEB SQLi'), malware(sid3) */
		ips_catalog_to_json(repo, jbuf, sizeof(jbuf), NULL, 0, "SQLi", &tr);
		CHECK(strstr(jbuf, "\"sid\":2002") != NULL, "matches 'SQLi' → has sid 2002");
		CHECK(strstr(jbuf, "\"sid\":1,") == NULL && strstr(jbuf, "\"sid\":3,") == NULL,
		      "no match → other sids excluded");
		/* query by sid */
		ips_catalog_to_json(repo, jbuf, sizeof(jbuf), NULL, 0, "2002", &tr);
		CHECK(strstr(jbuf, "\"sid\":2002") != NULL, "matches by sid");
	}

	/* cleanup */
	snprintf(p, sizeof(p), "%s/scan.rules", repo); unlink(p);
	snprintf(p, sizeof(p), "%s/web.rules", repo); unlink(p);
	snprintf(p, sizeof(p), "%s/malware.rules", repo); unlink(p);
	rmdir(repo);
	unlink(out);

	if (g_fail) { printf("\n== %d FAIL ==\n", g_fail); return 1; }
	printf("\n== ALL ips_compile TESTS PASS ==\n");
	return 0;
}
