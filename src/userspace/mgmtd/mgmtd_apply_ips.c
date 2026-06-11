/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_ips.c — Biên dịch + nạp ruleset IPS theo profile/filter (Phase B
 * + FortiGate-style filter).
 *
 * Kho global : /etc/stargazer/ips/repo/<category>.rules
 * Per-profile: /etc/stargazer/ips/profiles/<name>.rules
 *              compile từ bảng security_ips-filter (chọn category/signature;
 *              action giữ nguyên theo rule), hoặc fallback field `categories`
 *              nếu profile chưa có filter nào.
 * Active     : /etc/stargazer/ips/rules/active.rules = NỐI ruleset của các
 *              profile đang được policy accept dùng.
 *
 * rebuild_ips_active(): compile từng profile enable → verify ipsd -C → atomic
 * swap active.rules → SIGUSR1 ipsd (hot-reload không gián đoạn).
 *
 * GIỚI HẠN: ipsd 1 queue/1 ruleset → active = nối các profile in-use; chưa
 * phân biệt per-flow theo policy (bước sau: ipsd chọn ruleset theo connmark).
 */
#define _POSIX_C_SOURCE 200809L
#include "mgmtd_apply.h"
#include "mgmtd_ips_compile.h"
#include "sg_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>

#define IPS_REPO_DIR   "/etc/stargazer/ips/repo"
#define IPS_PROF_DIR   "/etc/stargazer/ips/profiles"
#define IPS_ACTIVE     "/etc/stargazer/ips/rules/active.rules"
#define IPS_ACTIVE_TMP "/etc/stargazer/ips/rules/.active.rules.tmp"
#define IPSD_BIN       "/sbin/stargazer-ipsd"
#define MAX_FILTERS    256

/* Verify ruleset bằng ipsd -C. Trả 0 nếu hợp lệ (exit 0). */
static int ips_verify(const char *path)
{
	const char *argv[] = { IPSD_BIN, "-C", "-r", path, "-n", NULL };
	int code = -1;
	char *out = pipe_exec_stdin(argv, "", 0, &code);
	free(out);
	return code == 0 ? 0 : -1;
}

static int parse_filter_type(const char *s)
{
	return (s && strcmp(s, "signature") == 0) ? IPS_FT_SIGNATURE
						  : IPS_FT_CATEGORY;
}

/*
 * Gom filter (status=enable) thuộc `profile` vào out[]. Trả số filter.
 * Chỉ CHỌN luật (type/value); action giữ nguyên theo từng rule.
 */
static int gather_filters(const char *profile, struct ips_filter *out, int max)
{
	char *list = sg_db_list("security_ips-filter");
	if (!list)
		return 0;
	int n = 0;
	char *sp = NULL;
	for (char *id = strtok_r(list, "\n", &sp); id && n < max;
	     id = strtok_r(NULL, "\n", &sp)) {
		char *pf  = sg_db_get_val("security_ips-filter", id, "profile");
		char *st  = sg_db_get_val("security_ips-filter", id, "status");
		char *ty  = sg_db_get_val("security_ips-filter", id, "type");
		char *va  = sg_db_get_val("security_ips-filter", id, "value");

		if (pf && strcmp(pf, profile) == 0 &&
		    (!st || strcmp(st, "disable") != 0) && va && va[0]) {
			out[n].type   = parse_filter_type(ty);
			snprintf(out[n].value, sizeof(out[n].value), "%s", va);
			n++;
		}
		free(pf); free(st); free(ty); free(va);
	}
	free(list);
	return n;
}

/*
 * Compile MỘT profile → profiles/<name>.rules. Ưu tiên bảng filter; nếu profile
 * chưa có filter nào → fallback field `categories` (back-compat Phase B).
 * Trả số rule, -1 nếu lỗi.
 */
static int compile_one_profile(const char *name, char *out_path, size_t opcap)
{
	snprintf(out_path, opcap, "%s/%s.rules", IPS_PROF_DIR, name);

	struct ips_filter filters[MAX_FILTERS];
	int nf = gather_filters(name, filters, MAX_FILTERS);

	if (nf > 0) {
		int r = ips_compile_filters(IPS_REPO_DIR, filters, nf, out_path);
		mgmt_log("INFO", "ips: profile '%s' compiled từ %d filter → %d rule",
			 name, nf, r);
		return r;
	}

	/* fallback: categories */
	char *cat = sg_db_get_val("security_ips-profile", name, "categories");
	int r = ips_compile_categories(IPS_REPO_DIR,
				       (cat && cat[0]) ? cat : "all", out_path);
	mgmt_log("INFO", "ips: profile '%s' compiled từ categories '%s' → %d rule",
		 name, (cat && cat[0]) ? cat : "all", r);
	free(cat);
	return r;
}

/* Nối nội dung file path vào dst. Trả 1 nếu nối được. */
static int append_file_to(FILE *dst, const char *path)
{
	FILE *in = fopen(path, "r");
	if (!in)
		return 0;
	char buf[8192];
	size_t r;
	while ((r = fread(buf, 1, sizeof(buf), in)) > 0)
		fwrite(buf, 1, r, dst);
	fclose(in);
	return 1;
}

/* Ghi /etc/stargazer/ips/.update.conf cho cron (ips-update-cron.sh) đọc —
 * tránh cron phải gọi ipc-cli (vấn đề auth). Liệt kê tất cả enabled ruleset
 * từ bảng security_ips-ruleset. */
static void ips_write_update_conf(void)
{
	char *en = sg_db_get_val("security_ips", "0", "auto-update");
	FILE *f  = fopen("/etc/stargazer/ips/.update.conf", "w");
	if (!f) { free(en); return; }

	fprintf(f, "enabled=%s\n", (en && en[0]) ? en : "disable");
	free(en);

	/* Liệt kê enabled entries từ security_ips-ruleset */
	char *ids = sg_db_list("security_ips-ruleset");
	int count = 0;
	if (ids) {
		char *sp = NULL;
		for (char *id = strtok_r(ids, "\n", &sp); id;
		     id = strtok_r(NULL, "\n", &sp)) {
			char *ena = sg_db_get_val("security_ips-ruleset", id, "enabled");
			char *url = sg_db_get_val("security_ips-ruleset", id, "url");
			if (ena && strcmp(ena, "enable") == 0 && url && url[0])
				fprintf(f, "url_%d=%s\n", count++, url);
			free(ena);
			free(url);
		}
		free(ids);
	}
	fprintf(f, "url_count=%d\n", count);
	fclose(f);
}

sg_status_t rebuild_ips_active(char *result, size_t rsize)
{
	mkdir(IPS_PROF_DIR, 0700);   /* đảm bảo tồn tại (no-op nếu có) */
	ips_write_update_conf();     /* đồng bộ conf cho cron */

	/* [1] compile từng profile enable → profiles/<name>.rules */
	char *plist = sg_db_list("security_ips-profile");
	if (plist) {
		char *sp = NULL;
		for (char *id = strtok_r(plist, "\n", &sp); id;
		     id = strtok_r(NULL, "\n", &sp)) {
			char *st = sg_db_get_val("security_ips-profile", id, "status");
			if (st && strcmp(st, "enable") == 0) {
				char op[512];
				compile_one_profile(id, op, sizeof(op));
			}
			free(st);
		}
		free(plist);
	}

	/* [2] active.rules tạm = NỐI ruleset của profile được policy accept dùng */
	FILE *tmp = fopen(IPS_ACTIVE_TMP, "w");
	if (!tmp) {
		snprintf(result, rsize, "IPS: cannot open active tmp");
		return SG_ERR_SYSTEM_FAIL;
	}
	fprintf(tmp, "# Stargazer IPS active ruleset (union các profile in-use)\n");

	int used = 0;
	char *fpl = sg_db_list("firewall_policy");
	if (fpl) {
		/* tránh nối trùng cùng một profile nhiều lần */
		char seen[64][64];
		int nseen = 0;
		char *sp = NULL;
		for (char *id = strtok_r(fpl, "\n", &sp); id;
		     id = strtok_r(NULL, "\n", &sp)) {
			char *act = sg_db_get_val("firewall_policy", id, "action");
			char *ipp = sg_db_get_val("firewall_policy", id, "ips-profile");
			char *pst = sg_db_get_val("firewall_policy", id, "status");
			int accept = act && (strcmp(act, "accept") == 0 ||
					     strcmp(act, "allow") == 0);
			int enabled = !pst || strcmp(pst, "disable") != 0;
			if (accept && enabled && ipp && ipp[0] &&
			    strcmp(ipp, "none") != 0) {
				/* profile enable? + chưa nối? */
				char *pstat = sg_db_get_val("security_ips-profile",
							    ipp, "status");
				int dup = 0;
				for (int i = 0; i < nseen; i++)
					if (strcmp(seen[i], ipp) == 0) dup = 1;
				if (pstat && strcmp(pstat, "enable") == 0 && !dup) {
					char pp[512];
					snprintf(pp, sizeof(pp), "%s/%s.rules",
						 IPS_PROF_DIR, ipp);
					if (append_file_to(tmp, pp)) {
						used++;
						if (nseen < 64)
							snprintf(seen[nseen++], 64,
								 "%s", ipp);
					}
				}
				free(pstat);
			}
			free(act); free(ipp); free(pst);
		}
		free(fpl);
	}
	fclose(tmp);

	if (used == 0) {
		/* không profile in-use → không đụng active.rules cũ (an toàn) */
		remove(IPS_ACTIVE_TMP);
		snprintf(result, rsize,
			 "IPS: no profile in use, active ruleset unchanged");
		return SG_OK;
	}

	/* [3] verify ipsd -C — ruleset hỏng KHÔNG swap (fail-closed) */
	if (ips_verify(IPS_ACTIVE_TMP) != 0) {
		mgmt_log("ERROR", "ips: ipsd -C báo active ruleset không hợp lệ "
			 "— giữ bản cũ");
		remove(IPS_ACTIVE_TMP);
		snprintf(result, rsize, "IPS active failed syntax check");
		return SG_ERR_SYSTEM_FAIL;
	}

	/* [4] atomic swap + hot-reload */
	if (rename(IPS_ACTIVE_TMP, IPS_ACTIVE) != 0) {
		mgmt_log("ERROR", "ips: rename active thất bại: %m");
		remove(IPS_ACTIVE_TMP);
		snprintf(result, rsize, "IPS active swap failed");
		return SG_ERR_SYSTEM_FAIL;
	}

	pid_t pid = supervisor_get_pid("stargazer-ipsd");
	if (pid > 0) {
		kill(pid, SIGUSR1);
		mgmt_log("INFO", "ips: active.rules rebuilt (%d profile) → "
			 "SIGUSR1 ipsd (pid %d) hot-reload", used, (int)pid);
	} else {
		mgmt_log("INFO", "ips: active.rules rebuilt (%d profile); ipsd "
			 "chưa chạy", used);
	}

	snprintf(result, rsize, "IPS active rebuilt (%d profile in use)", used);
	return SG_OK;
}

/*
 * run_ips_update_now — download rulesets and rebuild active.rules.
 *
 * ids_csv: comma-separated ruleset IDs to download (e.g. "et-botcc,et-dos").
 *   Non-NULL/non-empty → download only those specific IDs (manual UI trigger).
 *   NULL or empty      → download all entries that have last-downloaded set
 *                        (cron auto-update: refresh previously downloaded sets).
 */
sg_status_t run_ips_update_now(const char *ids_csv, char *result, size_t rsize)
{
	static const char *UPD = "/usr/libexec/stargazer/ips-update.sh";
	char *ids = sg_db_list("security_ips-ruleset");
	int   updated = 0, errors = 0;
	size_t pos = 0;

	if (!ids) {
		snprintf(result, rsize, "No rulesets configured");
		return SG_OK;
	}

	/* Build wanted-ID set from ids_csv */
	char csv_copy[1024] = "";
	if (ids_csv && ids_csv[0])
		snprintf(csv_copy, sizeof(csv_copy), "%s", ids_csv);

	char *sp = NULL;
	for (char *id = strtok_r(ids, "\n", &sp); id;
	     id = strtok_r(NULL, "\n", &sp)) {

		/* Filter: if ids_csv given, only process matching IDs */
		if (csv_copy[0]) {
			int found = 0;
			char tmp[1024];
			snprintf(tmp, sizeof(tmp), "%s", csv_copy);
			char *tp = NULL;
			for (char *tok = strtok_r(tmp, ",", &tp); tok;
			     tok = strtok_r(NULL, ",", &tp)) {
				/* trim whitespace */
				while (*tok == ' ') tok++;
				char *end = tok + strlen(tok) - 1;
				while (end > tok && *end == ' ') *end-- = '\0';
				if (strcmp(id, tok) == 0) { found = 1; break; }
			}
			if (!found) continue;
		} else {
			/* Cron mode: only refresh previously downloaded entries */
			char *lastdl = sg_db_get_val("security_ips-ruleset", id,
						     "last-downloaded");
			int has = lastdl && lastdl[0];
			free(lastdl);
			if (!has) continue;
		}

		char *url = sg_db_get_val("security_ips-ruleset", id, "url");
		if (!url || !url[0]) { free(url); continue; }

		/* Derive category: basename(url), strip "emerging-" prefix, ".rules" suffix */
		const char *base = strrchr(url, '/');
		base = base ? base + 1 : url;
		char cat[128];
		snprintf(cat, sizeof(cat), "%s", base);
		/* strip .rules suffix */
		char *dot = strrchr(cat, '.');
		if (dot && strcmp(dot, ".rules") == 0) *dot = '\0';
		/* strip leading "emerging-" */
		const char *catname = cat;
		if (strncmp(cat, "emerging-", 9) == 0) catname = cat + 9;

		const char *argv[] = { UPD, url, catname, NULL };
		char *out = safe_exec(argv);
		int n = snprintf(result + pos, rsize - pos, "[%s] %s\n",
				 catname, out ? out : "error");
		if (n > 0 && (size_t)n < rsize - pos) pos += (size_t)n;
		if (!out) {
			errors++;
		} else {
			updated++;
			if (strstr(out, "Success:") || strstr(out, "unchanged")) {
				time_t t = time(NULL);
				struct tm *tm_info = gmtime(&t);
				char ts[32];
				strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M UTC", tm_info);
				sg_db_set_val("security_ips-ruleset", id, "last-downloaded", ts);
			}
		}
		free(out);
		free(url);
	}
	free(ids);

	/* Rebuild active ruleset after all downloads */
	char rb[256];
	rebuild_ips_active(rb, sizeof(rb));
	int n = snprintf(result + pos, rsize - pos, "%s\n", rb);
	if (n > 0 && (size_t)n < rsize - pos) pos += (size_t)n;

	if (errors > 0)
		return SG_ERR_SYSTEM_FAIL;
	(void)updated;
	return SG_OK;
}

/*
 * ips_rulesets_reload_custom — scan /etc/stargazer/ips/custom/ for .xml files
 * and upsert each as a security_ips-ruleset entry.
 *
 * XML format (simple):
 *   <ruleset>
 *     <description>My Custom Rules</description>
 *     <url>http://server/custom.rules</url>
 *   </ruleset>
 *
 * The entry ID (name) is derived from the filename minus ".xml".
 */
#define IPS_CUSTOM_DIR "/etc/stargazer/ips/custom"

static int xml_extract(const char *buf, const char *tag,
		       char *out, size_t outsz)
{
	char open[64], close[64];
	snprintf(open,  sizeof(open),  "<%s>",  tag);
	snprintf(close, sizeof(close), "</%s>", tag);
	const char *s = strstr(buf, open);
	if (!s) return 0;
	s += strlen(open);
	const char *e = strstr(s, close);
	if (!e) return 0;
	size_t len = (size_t)(e - s);
	if (len >= outsz) len = outsz - 1;
	memcpy(out, s, len);
	out[len] = '\0';
	/* trim whitespace */
	char *p = out;
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
	if (p != out) memmove(out, p, strlen(p) + 1);
	char *end = out + strlen(out);
	while (end > out && (end[-1] == ' ' || end[-1] == '\t' ||
			     end[-1] == '\n' || end[-1] == '\r')) *--end = '\0';
	return 1;
}

sg_status_t ips_rulesets_reload_custom(char *result, size_t rsize)
{
	mkdir(IPS_CUSTOM_DIR, 0755);
	DIR *d = opendir(IPS_CUSTOM_DIR);
	if (!d) {
		snprintf(result, rsize, "Custom ruleset dir not found: " IPS_CUSTOM_DIR);
		return SG_OK;
	}

	size_t pos = 0;
	int imported = 0;
	struct dirent *de;

	while ((de = readdir(d)) != NULL) {
		const char *nm = de->d_name;
		size_t nlen = strlen(nm);
		if (nlen < 5 || strcmp(nm + nlen - 4, ".xml") != 0)
			continue;

		char path[512];
		snprintf(path, sizeof(path), "%s/%s", IPS_CUSTOM_DIR, nm);

		/* Read file */
		FILE *fp = fopen(path, "r");
		if (!fp) continue;
		char xmlbuf[4096] = "";
		fread(xmlbuf, 1, sizeof(xmlbuf) - 1, fp);
		fclose(fp);

		/* Derive ID from filename (strip .xml) */
		char id[128];
		size_t idlen = nlen - 4;
		if (idlen >= sizeof(id)) idlen = sizeof(id) - 1;
		memcpy(id, nm, idlen);
		id[idlen] = '\0';

		char desc[256] = "", url[512] = "";
		xml_extract(xmlbuf, "description", desc, sizeof(desc));
		xml_extract(xmlbuf, "url",         url,  sizeof(url));

		if (!url[0]) {
			int n = snprintf(result + pos, rsize - pos,
					 "[%s] skipped: no <url> found\n", id);
			if (n > 0 && (size_t)n < rsize - pos) pos += (size_t)n;
			continue;
		}
		if (!desc[0]) snprintf(desc, sizeof(desc), "%s", id);

		/* Upsert — preserve existing enabled/last-downloaded */
		char *existing = sg_db_get("security_ips-ruleset", id);
		char ena[16] = "disable";
		char lastdl[32] = "";
		if (existing) {
			char *ev = sg_db_get_val("security_ips-ruleset", id, "enabled");
			char *lv = sg_db_get_val("security_ips-ruleset", id, "last-downloaded");
			if (ev) { snprintf(ena, sizeof(ena), "%s", ev); free(ev); }
			if (lv) { snprintf(lastdl, sizeof(lastdl), "%s", lv); free(lv); }
			free(existing);
		}

		char data[1024];
		int n2 = snprintf(data, sizeof(data),
			"description=%s\nurl=%s\nenabled=%s\n"
			"builtin=no\nlast-downloaded=%s\n",
			desc, url, ena, lastdl);
		if (n2 > 0 && (size_t)n2 < sizeof(data))
			sg_db_set("security_ips-ruleset", id, data);

		int n = snprintf(result + pos, rsize - pos,
				 "[%s] imported: %s\n", id, desc);
		if (n > 0 && (size_t)n < rsize - pos) pos += (size_t)n;
		imported++;
	}
	closedir(d);

	if (imported == 0) {
		snprintf(result + pos, rsize - pos,
			 "No XML files found in " IPS_CUSTOM_DIR
			 " — copy *.xml files there and reload again.");
	} else {
		snprintf(result + pos, rsize - pos,
			 "Imported %d custom ruleset(s).", imported);
	}
	return SG_OK;
}
