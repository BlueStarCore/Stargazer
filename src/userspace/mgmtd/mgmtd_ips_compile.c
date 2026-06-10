/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_ips_compile.c — Ghép ruleset theo category (xem header).
 */
#define _POSIX_C_SOURCE 200809L
#include "mgmtd_ips_compile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <strings.h>   /* strcasecmp */

/* Đuôi ".rules"? */
static int has_rules_ext(const char *name)
{
	size_t n = strlen(name);
	return n > 6 && strcasecmp(name + n - 6, ".rules") == 0;
}

/* Ghép nội dung repo_dir/<base> vào fp. Trả 1 nếu ghép được, 0 nếu thiếu file. */
static int append_file(FILE *fp, const char *repo_dir, const char *base)
{
	char path[512];
	int n = snprintf(path, sizeof(path), "%s/%s", repo_dir, base);
	if (n <= 0 || n >= (int)sizeof(path))
		return 0;

	FILE *in = fopen(path, "r");
	if (!in)
		return 0;

	fprintf(fp, "\n# ===== category: %s =====\n", base);
	char buf[8192];
	size_t r;
	while ((r = fread(buf, 1, sizeof(buf), in)) > 0)
		fwrite(buf, 1, r, fp);
	fclose(in);
	return 1;
}

/* Trim khoảng trắng đầu/cuối token (in-place, trả con trỏ đã trim). */
static char *trim(char *s)
{
	while (*s == ' ' || *s == '\t') s++;
	char *e = s + strlen(s);
	while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\n'))
		*--e = '\0';
	return s;
}

int ips_compile_categories(const char *repo_dir, const char *categories,
			   const char *out_path)
{
	if (!repo_dir || !categories || !out_path)
		return -1;

	FILE *fp = fopen(out_path, "w");
	if (!fp)
		return -1;

	fprintf(fp, "# Stargazer IPS compiled ruleset (categories: %s)\n",
		categories);

	int merged = 0;

	if (strcmp(categories, "all") == 0) {
		/* mọi *.rules trong repo (sắp xếp để ổn định) */
		DIR *d = opendir(repo_dir);
		if (!d) {
			fclose(fp);
			return -1;
		}
		/* gom tên, sort, ghép */
		char names[128][256];
		int cnt = 0;
		struct dirent *de;
		while ((de = readdir(d)) != NULL && cnt < 128) {
			if (has_rules_ext(de->d_name))
				snprintf(names[cnt++], 256, "%s", de->d_name);
		}
		closedir(d);
		/* sort đơn giản (n nhỏ) cho output deterministic */
		for (int i = 0; i < cnt; i++)
			for (int j = i + 1; j < cnt; j++)
				if (strcmp(names[i], names[j]) > 0) {
					char t[256];
					memcpy(t, names[i], 256);
					memcpy(names[i], names[j], 256);
					memcpy(names[j], t, 256);
				}
		for (int i = 0; i < cnt; i++)
			merged += append_file(fp, repo_dir, names[i]);
	} else {
		/* danh sách "a,b,c" → repo/<a>.rules ... */
		char *list = strdup(categories);
		if (!list) {
			fclose(fp);
			return -1;
		}
		char *sp = NULL;
		for (char *tok = strtok_r(list, ",", &sp);
		     tok; tok = strtok_r(NULL, ",", &sp)) {
			char *cat = trim(tok);
			if (!*cat)
				continue;
			char base[140];
			snprintf(base, sizeof(base), "%s.rules", cat);
			merged += append_file(fp, repo_dir, base);
		}
		free(list);
	}

	fclose(fp);
	return merged;
}

/* ── FortiGate-style filter compile + action override ─────────────────── */

/* Tên action override theo enum, NULL nếu = default (giữ nguyên). */
static const char *action_word(int action)
{
	switch (action) {
	case IPS_FA_BLOCK: return "drop";
	case IPS_FA_ALERT: return "alert";
	case IPS_FA_PASS:  return "pass";
	default:           return NULL;   /* default → giữ action gốc */
	}
}

/*
 * Ghi một dòng rule ra fp, GHI ĐÈ action token đầu nếu cần.
 * Dòng comment (#) / rỗng → copy nguyên. Trả 1 nếu ghi một RULE, 0 nếu không.
 */
static int write_rule_line(FILE *fp, const char *line, int action)
{
	const char *p = line;
	while (*p == ' ' || *p == '\t') p++;
	if (*p == '\0' || *p == '\n' || *p == '#') {
		/* comment/blank — chỉ copy nếu là blank giữ định dạng, bỏ comment */
		return 0;
	}

	const char *newact = action_word(action);
	if (!newact) {
		/* default: giữ nguyên dòng */
		fputs(line, fp);
		if (line[strlen(line) - 1] != '\n')
			fputc('\n', fp);
		return 1;
	}

	/* override: thay token action đầu tiên (tới khoảng trắng) */
	const char *sp = p;
	while (*sp && *sp != ' ' && *sp != '\t') sp++;
	/* sp trỏ sau action word; phần còn lại từ sp */
	fprintf(fp, "%s%s", newact, sp);
	if (sp[strlen(sp) - 1] != '\n')
		fputc('\n', fp);
	return 1;
}

/* Ghép repo/<base>, ghi đè action mỗi rule. Trả số rule ghi. */
static int append_rules_rewrite(FILE *fp, const char *repo_dir,
				const char *base, int action)
{
	char path[512];
	if (snprintf(path, sizeof(path), "%s/%s", repo_dir, base) >= (int)sizeof(path))
		return 0;
	FILE *in = fopen(path, "r");
	if (!in)
		return 0;
	int n = 0, cont = 0;
	char line[8192];
	while (fgets(line, sizeof(line), in)) {
		if (cont) {
			/* dòng nối tiếp của rule trước → copy nguyên, không rewrite */
			fputs(line, fp);
		} else {
			n += write_rule_line(fp, line, action);
		}
		/* dòng kết thúc bằng '\' (trước \n) → dòng sau là nối tiếp */
		size_t l = strlen(line);
		while (l && (line[l-1] == '\n' || line[l-1] == '\r')) l--;
		cont = (l > 0 && line[l-1] == '\\');
	}
	fclose(in);
	return n;
}

/* Tìm rule có sid:<value>; trong mọi *.rules của repo, ghi với override. */
static int append_sid_rewrite(FILE *fp, const char *repo_dir,
			      const char *sid, int action)
{
	char needle[160];
	snprintf(needle, sizeof(needle), "sid:%s;", sid);

	DIR *d = opendir(repo_dir);
	if (!d)
		return 0;
	int n = 0;
	struct dirent *de;
	while ((de = readdir(d)) != NULL) {
		if (!has_rules_ext(de->d_name))
			continue;
		char path[512];
		if (snprintf(path, sizeof(path), "%s/%s", repo_dir, de->d_name)
		    >= (int)sizeof(path))
			continue;
		FILE *in = fopen(path, "r");
		if (!in)
			continue;
		char line[8192];
		while (fgets(line, sizeof(line), in)) {
			if (strstr(line, needle))
				n += write_rule_line(fp, line, action);
		}
		fclose(in);
	}
	closedir(d);
	return n;
}

/* ── Catalog: liệt kê signature từ repo (JSON) ───────────────────────── */

/* Tìm value của key:"..." trong line → out (đã unquote). Trả 1 nếu thấy. */
static int extract_quoted(const char *line, const char *key,
			  char *out, size_t cap)
{
	const char *p = strstr(line, key);
	if (!p)
		return 0;
	p += strlen(key);
	if (*p != '"')
		return 0;
	p++;
	size_t n = 0;
	while (*p && *p != '"' && n + 1 < cap) {
		if (*p == '\\' && p[1]) p++;   /* bỏ escape */
		out[n++] = *p++;
	}
	out[n] = '\0';
	return 1;
}

/* Tìm token sau "key" tới ký tự dừng (; , khoảng trắng) → out. */
static int extract_token(const char *line, const char *key, char stop,
			 char *out, size_t cap)
{
	const char *p = strstr(line, key);
	if (!p)
		return 0;
	p += strlen(key);
	size_t n = 0;
	while (*p && *p != stop && *p != ' ' && *p != ';' && n + 1 < cap)
		out[n++] = *p++;
	out[n] = '\0';
	return n > 0;
}

/* Ghi chuỗi JSON-escaped vào buf tại *pos (cap). */
static void json_str(char *buf, size_t *pos, size_t cap, const char *s)
{
	for (const char *p = s; *p && *pos + 8 < cap; p++) {
		char c = *p;
		if (c == '"' || c == '\\') { buf[(*pos)++] = '\\'; buf[(*pos)++] = c; }
		else if ((unsigned char)c >= 0x20)   buf[(*pos)++] = c;
	}
}

int ips_catalog_to_json(const char *repo_dir, char *buf, size_t cap,
                        const char *const *allowed, int n_allowed)
{
	if (!repo_dir || !buf || cap < 4)
		return -1;
	DIR *d = opendir(repo_dir);
	if (!d)
		return -1;

	size_t pos = 0;
	buf[pos++] = '[';
	int first = 1;

	struct dirent *de;
	while ((de = readdir(d)) != NULL) {
		if (!has_rules_ext(de->d_name))
			continue;
		char cat[128];
		snprintf(cat, sizeof(cat), "%.*s",
			 (int)(strlen(de->d_name) - 6), de->d_name);  /* bỏ .rules */

		/* Filter: skip categories not in the allowed list */
		if (allowed && n_allowed > 0) {
			int found = 0;
			for (int ai = 0; ai < n_allowed; ai++) {
				if (allowed[ai] && strcmp(cat, allowed[ai]) == 0) {
					found = 1;
					break;
				}
			}
			if (!found)
				continue;
		}

		char path[512];
		if (snprintf(path, sizeof(path), "%s/%s", repo_dir, de->d_name)
		    >= (int)sizeof(path))
			continue;
		FILE *in = fopen(path, "r");
		if (!in)
			continue;

		char line[8192];
		while (fgets(line, sizeof(line), in)) {
			const char *q = line;
			while (*q == ' ' || *q == '\t') q++;
			if (*q == '#' || *q == '\0' || *q == '\n')
				continue;

			char sid[32], name[256], action[16], cve[32] = "", classtype[64] = "", ref_url[128] = "";
			/* action = token đầu */
			{
				size_t n = 0;
				while (q[n] && q[n] != ' ' && n < sizeof(action) - 1) {
					action[n] = q[n]; n++;
				}
				action[n] = '\0';
			}
			if (!extract_token(line, "sid:", ';', sid, sizeof(sid)))
				continue;   /* không có sid → bỏ */
			if (!extract_quoted(line, "msg:", name, sizeof(name)))
				snprintf(name, sizeof(name), "sid %s", sid);
			extract_token(line, "reference:cve,", ';', cve, sizeof(cve));
			extract_token(line, "classtype:", ';', classtype, sizeof(classtype));
			extract_token(line, "reference:url,", ';', ref_url, sizeof(ref_url));

			/* dừng nếu sắp đầy buf (chừa chỗ đóng]) */
			if (pos + strlen(name) + 200 > cap)
				break;

			if (!first) buf[pos++] = ',';
			first = 0;
			pos += (size_t)snprintf(buf + pos, cap - pos,
				"{\"sid\":%s,\"category\":\"%s\",\"action\":\"%s\",",
				sid, cat, action);
			pos += (size_t)snprintf(buf + pos, cap - pos, "\"name\":\"");
			json_str(buf, &pos, cap, name);
			pos += (size_t)snprintf(buf + pos, cap - pos, "\"");
			if (classtype[0]) {
				pos += (size_t)snprintf(buf + pos, cap - pos,
					",\"classtype\":\"%s\"", classtype);
			}
			if (cve[0]) {
				pos += (size_t)snprintf(buf + pos, cap - pos,
					",\"cve\":\"CVE-%s\"", cve);
			}
			/* info: combine CVE + ref URL into one field */
			if (cve[0] || ref_url[0]) {
				pos += (size_t)snprintf(buf + pos, cap - pos, ",\"info\":\"");
				if (cve[0]) {
					pos += (size_t)snprintf(buf + pos, cap - pos,
						"CVE-%s", cve);
					if (ref_url[0])
						pos += (size_t)snprintf(buf + pos, cap - pos, " ");
				}
				if (ref_url[0])
					json_str(buf, &pos, cap, ref_url);
				pos += (size_t)snprintf(buf + pos, cap - pos, "\"");
			}
			if (pos + 4 < cap) buf[pos++] = '}';
		}
		fclose(in);
	}
	closedir(d);

	if (pos + 2 < cap) buf[pos++] = ']';
	buf[pos] = '\0';
	return (int)pos;
}

int ips_compile_filters(const char *repo_dir, const struct ips_filter *filters,
			int n_filters, const char *out_path)
{
	if (!repo_dir || !out_path || (n_filters > 0 && !filters))
		return -1;

	FILE *fp = fopen(out_path, "w");
	if (!fp)
		return -1;
	fprintf(fp, "# Stargazer IPS compiled ruleset (%d filter)\n", n_filters);

	int rules = 0;
	for (int i = 0; i < n_filters; i++) {
		const struct ips_filter *f = &filters[i];
		if (f->type == IPS_FT_CATEGORY) {
			char base[140];
			snprintf(base, sizeof(base), "%s.rules", f->value);
			fprintf(fp, "\n# filter: category %s action=%d\n",
				f->value, f->action);
			rules += append_rules_rewrite(fp, repo_dir, base,
						      f->action);
		} else { /* IPS_FT_SIGNATURE */
			fprintf(fp, "\n# filter: signature %s action=%d\n",
				f->value, f->action);
			rules += append_sid_rewrite(fp, repo_dir, f->value,
						    f->action);
		}
	}

	fclose(fp);
	return rules;
}
