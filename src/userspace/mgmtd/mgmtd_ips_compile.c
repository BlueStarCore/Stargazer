/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_ips_compile.c — Merge ruleset by category (see header).
 */
#define _POSIX_C_SOURCE 200809L
#include "mgmtd_ips_compile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <strings.h>   /* strcasecmp */

/* Has ".rules" extension? */
static int has_rules_ext(const char *name)
{
	size_t n = strlen(name);
	return n > 6 && strcasecmp(name + n - 6, ".rules") == 0;
}

/* Append the contents of repo_dir/<base> to fp. Returns 1 if appended, 0 if file missing. */
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

/* Trim leading/trailing whitespace from a token (in-place, returns trimmed pointer). */
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
		/* every *.rules in the repo (sorted for stability) */
		DIR *d = opendir(repo_dir);
		if (!d) {
			fclose(fp);
			return -1;
		}
		/* collect names, sort, merge */
		char names[128][256];
		int cnt = 0;
		struct dirent *de;
		while ((de = readdir(d)) != NULL && cnt < 128) {
			if (has_rules_ext(de->d_name))
				snprintf(names[cnt++], 256, "%s", de->d_name);
		}
		closedir(d);
		/* simple sort (small n) for deterministic output */
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
		/* list "a,b,c" → repo/<a>.rules ... */
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

/* ── FortiGate IPS sensor: per-entry ACTION (P7) ──────────────────────── */

/* Forward (full definition below — used for extracting the sid). */
static int extract_token(const char *line, const char *key, char stop,
			 char *out, size_t cap);

/* Map override sid → action (from filter type=signature). Small (admin-selected by hand). */
struct sid_override { char sid[32]; int action; };

/* Find the override action for a sid; returns -1 if none. */
static int override_for_sid(const struct sid_override *ov, int n_ov,
			    const char *sid)
{
	for (int i = 0; i < n_ov; i++)
		if (!strcmp(ov[i].sid, sid))
			return ov[i].action;
	return -1;
}

/* New action token per enum; NULL = default (keep original token). */
static const char *action_word(int action)
{
	switch (action) {
	case IPS_FA_BLOCK: return "drop";
	case IPS_FA_ALERT: return "alert";
	default:           return NULL;   /* default → keep original action */
	}
}

/*
 * Write a rule line, REWRITE the first action token per `action`.
 *   pass    → do NOT write (excludes the rule from the profile).
 *   default → keep as-is.   block→"drop".   alert→"alert".
 * Comment (#) / blank lines → skipped. Returns 1 if a RULE was written, 0 otherwise.
 */
static int write_rule_line(FILE *fp, const char *line, int action)
{
	const char *p = line;
	while (*p == ' ' || *p == '\t') p++;
	if (*p == '\0' || *p == '\n' || *p == '#')
		return 0;                  /* comment/blank — skip */
	if (action == IPS_FA_PASS)
		return 0;                  /* pass → whitelist, not written */

	const char *newact = action_word(action);
	if (!newact) {                     /* default: keep line as-is */
		fputs(line, fp);
		if (line[strlen(line) - 1] != '\n')
			fputc('\n', fp);
		return 1;
	}
	/* replace first token (up to whitespace) with newact, keep the rest */
	const char *sp = p;
	while (*sp && *sp != ' ' && *sp != '\t') sp++;
	fprintf(fp, "%s%s", newact, sp);
	if (sp[strlen(sp) - 1] != '\n')
		fputc('\n', fp);
	return 1;
}

/*
 * Merge repo/<base> with the category's action. Precedence: a rule whose sid is in the
 * override map (signature filter) → SKIPPED here (append_sid will write it with the
 * signature action). Returns the number of rules written.
 */
static int append_rules(FILE *fp, const char *repo_dir, const char *base,
			int action, const struct sid_override *ov, int n_ov)
{
	char path[512];
	if (snprintf(path, sizeof(path), "%s/%s", repo_dir, base) >= (int)sizeof(path))
		return 0;
	FILE *in = fopen(path, "r");
	if (!in)
		return 0;
	int n = 0, cont = 0, skip_cont = 0;
	char line[8192];
	while (fgets(line, sizeof(line), in)) {
		if (cont) {
			if (!skip_cont) fputs(line, fp); /* continuation of a written rule */
		} else {
			char sid[32];
			skip_cont = 0;
			/* Precedence: sid with a signature override → skip in category */
			if (extract_token(line, "sid:", ';', sid, sizeof(sid)) &&
			    override_for_sid(ov, n_ov, sid) >= 0) {
				skip_cont = 1;           /* also skip the continuation line */
			} else {
				n += write_rule_line(fp, line, action);
			}
		}
		size_t l = strlen(line);
		while (l && (line[l-1] == '\n' || line[l-1] == '\r')) l--;
		cont = (l > 0 && line[l-1] == '\\');
	}
	fclose(in);
	return n;
}

/* Find the rule with sid:<value>; in the repo, write it with the signature override action. */
static int append_sid(FILE *fp, const char *repo_dir, const char *sid,
		      int action)
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

/* ── Catalog: list signatures from the repo (JSON) ───────────────────── */

/* Find the value of key:"..." in line → out (unquoted). Returns 1 if found. */
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
		if (*p == '\\' && p[1]) p++;   /* skip escape */
		out[n++] = *p++;
	}
	out[n] = '\0';
	return 1;
}

/* Find the token after "key" up to a stop character (; , whitespace) → out. */
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

/* Write a JSON-escaped string into buf at *pos (cap). */
static void json_str(char *buf, size_t *pos, size_t cap, const char *s)
{
	for (const char *p = s; *p && *pos + 8 < cap; p++) {
		char c = *p;
		if (c == '"' || c == '\\') { buf[(*pos)++] = '\\'; buf[(*pos)++] = c; }
		else if ((unsigned char)c >= 0x20)   buf[(*pos)++] = c;
	}
}

/* Case-insensitive strstr (for catalog search). */
static const char *ci_strstr(const char *hay, const char *needle)
{
	if (!needle || !needle[0]) return hay;
	if (!hay) return NULL;
	size_t nl = strlen(needle);
	for (const char *h = hay; *h; h++) {
		size_t i = 0;
		for (; i < nl; i++) {
			char a = h[i], b = needle[i];
			if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
			if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
			if (!h[i] || a != b) break;
		}
		if (i == nl) return h;
	}
	return NULL;
}

int ips_catalog_to_json(const char *repo_dir, char *buf, size_t cap,
                        const char *const *allowed, int n_allowed,
                        const char *query, int *truncated)
{
	if (truncated) *truncated = 0;
	if (!repo_dir || !buf || cap < 4)
		return -1;
	int has_q = (query && query[0]);
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
			 (int)(strlen(de->d_name) - 6), de->d_name);  /* strip .rules */

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
			/* action = first token */
			{
				size_t n = 0;
				while (q[n] && q[n] != ' ' && n < sizeof(action) - 1) {
					action[n] = q[n]; n++;
				}
				action[n] = '\0';
			}
			if (!extract_token(line, "sid:", ';', sid, sizeof(sid)))
				continue;   /* no sid → skip */
			if (!extract_quoted(line, "msg:", name, sizeof(name)))
				snprintf(name, sizeof(name), "sid %s", sid);
			extract_token(line, "reference:cve,", ';', cve, sizeof(cve));
			extract_token(line, "classtype:", ';', classtype, sizeof(classtype));
			extract_token(line, "reference:url,", ';', ref_url, sizeof(ref_url));

			/* SEARCH server-side: only entries matching the keyword (sid/name/
			 * category/cve/classtype) are emitted → compact response, not
			 * truncated in the middle of the search results. */
			if (has_q &&
			    !ci_strstr(sid, query) && !ci_strstr(name, query) &&
			    !ci_strstr(cat, query) && !ci_strstr(cve, query) &&
			    !ci_strstr(classtype, query))
				continue;

			/*
			 * Reserve enough for all fixed overhead per entry:
			 *   sid/cat/action prefix  ~200
			 *   name content           strlen(name)
			 *   classtype field        ~80
			 *   cve field              ~45
			 *   info field             ~150
			 *   closing "}" + "]"      ~4
			 * Total non-name overhead: ~480 → use 512 as safe margin.
			 */
			if (pos + strlen(name) + 512 > cap) {
				if (truncated) *truncated = 1;
				fclose(in);
				goto done;     /* out of room → stop entirely */
			}

#define JAPPEND(...) do { \
	int _n = snprintf(buf + pos, cap - pos, __VA_ARGS__); \
	if (_n > 0) pos += (_n < (int)(cap - pos)) ? (size_t)_n : (cap - pos - 1); \
} while (0)

			if (!first) buf[pos++] = ',';
			first = 0;
			JAPPEND("{\"sid\":%s,\"category\":\"%s\",\"action\":\"%s\",",
				sid, cat, action);
			JAPPEND("\"name\":\"");
			json_str(buf, &pos, cap, name);
			JAPPEND("\"");
			if (classtype[0])
				JAPPEND(",\"classtype\":\"%s\"", classtype);
			if (cve[0])
				JAPPEND(",\"cve\":\"CVE-%s\"", cve);
			if (cve[0] || ref_url[0]) {
				JAPPEND(",\"info\":\"");
				if (cve[0]) {
					JAPPEND("CVE-%s", cve);
					if (ref_url[0]) JAPPEND(" ");
				}
				if (ref_url[0])
					json_str(buf, &pos, cap, ref_url);
				JAPPEND("\"");
			}
			if (pos + 4 < cap) buf[pos++] = '}';
#undef JAPPEND
		}
		fclose(in);
	}
done:
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

	/* P7 precedence — build the override map sid→action from filter type=signature
	 * (most specific, wins over category). */
	struct sid_override ov[256];
	int n_ov = 0;
	for (int i = 0; i < n_filters && n_ov < (int)(sizeof(ov)/sizeof(ov[0])); i++) {
		if (filters[i].type != IPS_FT_SIGNATURE)
			continue;
		size_t vl = strlen(filters[i].value);
		if (vl >= sizeof(ov[n_ov].sid))      /* a valid sid is always short */
			continue;
		memcpy(ov[n_ov].sid, filters[i].value, vl + 1);
		ov[n_ov].action = filters[i].action;
		n_ov++;
	}

	int rules = 0;
	/* Pass 1: category — write rules with the category action, SKIP sids with an override. */
	for (int i = 0; i < n_filters; i++) {
		const struct ips_filter *f = &filters[i];
		if (f->type != IPS_FT_CATEGORY)
			continue;
		char base[140];
		snprintf(base, sizeof(base), "%s.rules", f->value);
		fprintf(fp, "\n# filter: category %s action=%d\n", f->value, f->action);
		rules += append_rules(fp, repo_dir, base, f->action, ov, n_ov);
	}
	/* Pass 2: signature override — write the specific sid with its own action. */
	for (int i = 0; i < n_filters; i++) {
		const struct ips_filter *f = &filters[i];
		if (f->type != IPS_FT_SIGNATURE)
			continue;
		fprintf(fp, "\n# filter: signature %s action=%d\n", f->value, f->action);
		rules += append_sid(fp, repo_dir, f->value, f->action);
	}

	fclose(fp);
	return rules;
}
