/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_ips.c — Compile + load the IPS ruleset per profile/filter (Phase B
 * + FortiGate-style filter).
 *
 * Global repo: /etc/stargazer/ips/repo/<category>.rules
 * Per-profile: /etc/stargazer/ips/profiles/<name>.rules
 *              compiled from the security_ips-filter table (category/signature +
 *              per-entry action, FortiGate-style, P7), or fall back to the
 *              `categories` field if the profile has no filters.
 * Active     : /etc/stargazer/ips/rules/active.rules = CONCATENATION of the
 *              rulesets of every profile in use by an accept policy.
 *
 * rebuild_ips_active(): compile each enabled profile → verify with ipsd -C →
 * atomic swap active.rules → SIGUSR1 ipsd (uninterrupted hot-reload).
 *
 * LIMITATION: ipsd has 1 queue / 1 ruleset → active = concatenation of the
 * in-use profiles; per-flow distinction by policy not yet supported (later step:
 * ipsd selects a ruleset by connmark).
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
#include <unistd.h>
#include <sys/stat.h>

#define IPS_BASE_DIR   "/etc/stargazer/ips"
#define IPS_REPO_DIR   "/etc/stargazer/ips/repo"
#define IPS_PROF_DIR   "/etc/stargazer/ips/profiles"
#define IPS_RULES_DIR  "/etc/stargazer/ips/rules"
#define IPS_ACTIVE     "/etc/stargazer/ips/rules/active.rules"
#define IPS_ACTIVE_TMP "/etc/stargazer/ips/rules/.active.rules.tmp"
#define IPSD_BIN       "/sbin/stargazer-ipsd"
#define MAX_FILTERS    256

/* Byte-compare two files without loading them (active.rules can be tens of MB).
 * Returns 1 if identical, 0 otherwise (including if either cannot be opened). */
static int files_equal(const char *a, const char *b)
{
	FILE *fa = fopen(a, "rb");
	FILE *fb = fopen(b, "rb");
	int eq = 1;
	if (!fa || !fb)
		eq = 0;
	while (eq) {
		char ba[8192], bb[8192];
		size_t na = fread(ba, 1, sizeof(ba), fa);
		size_t nb = fread(bb, 1, sizeof(bb), fb);
		if (na != nb || memcmp(ba, bb, na) != 0) { eq = 0; break; }
		if (na == 0) break;   /* both at EOF, all equal */
	}
	if (fa) fclose(fa);
	if (fb) fclose(fb);
	return eq;
}

/* P7 — action per-entry (FortiGate). */
static int parse_filter_action(const char *s)
{
	if (!s) return IPS_FA_DEFAULT;
	if (!strcmp(s, "block")) return IPS_FA_BLOCK;
	if (!strcmp(s, "alert")) return IPS_FA_ALERT;
	if (!strcmp(s, "pass"))  return IPS_FA_PASS;
	return IPS_FA_DEFAULT;
}

/*
 * Gather the enabled filters belonging to a profile into out[]. Filters are nested
 * children keyed "<profid>/<seq>", so we select by id prefix (no profile field).
 * Each child sets either `rule` (a SID → signature) or `category`, plus a per-entry
 * action. `profid` is the profile's numeric id. Returns the filter count.
 */
static int gather_filters(const char *profid, struct ips_filter *out, int max)
{
	char *list = sg_db_list("security_ips-filter");
	if (!list)
		return 0;
	char pfx[24];
	int plen = snprintf(pfx, sizeof(pfx), "%s/", profid);   /* "<profid>/" */
	int n = 0;
	char *sp = NULL;
	for (char *id = strtok_r(list, "\n", &sp); id && n < max;
	     id = strtok_r(NULL, "\n", &sp)) {
		if (strncmp(id, pfx, (size_t)plen) != 0)
			continue;                              /* not our child */
		char *st  = sg_db_get_val("security_ips-filter", id, "status");
		char *ru  = sg_db_get_val("security_ips-filter", id, "rule");
		char *ca  = sg_db_get_val("security_ips-filter", id, "category");
		char *ac  = sg_db_get_val("security_ips-filter", id, "action");

		if ((!st || strcmp(st, "disable") != 0)) {
			if (ru && ru[0]) {              /* signature (SID) */
				out[n].type   = IPS_FT_SIGNATURE;
				out[n].action = parse_filter_action(ac);
				snprintf(out[n].value, sizeof(out[n].value), "%s", ru);
				n++;
			} else if (ca && ca[0]) {       /* category */
				out[n].type   = IPS_FT_CATEGORY;
				out[n].action = parse_filter_action(ac);
				snprintf(out[n].value, sizeof(out[n].value), "%s", ca);
				n++;
			}
		}
		free(st); free(ru); free(ca); free(ac);
	}
	free(list);
	return n;
}

/*
 * Compile ONE profile → profiles/<name>.rules. Prefer the filter table; if the
 * profile has no filters → fall back to the `categories` field (Phase B
 * back-compat). Returns the rule count, -1 on error.
 */
static int compile_one_profile(const char *name, char *out_path, size_t opcap)
{
	snprintf(out_path, opcap, "%s/%s.rules", IPS_PROF_DIR, name);

	struct ips_filter filters[MAX_FILTERS];
	int nf = gather_filters(name, filters, MAX_FILTERS);

	/* Signature filters are per-sid action OVERRIDES layered on a category base.
	 * If the profile defines its base via the `categories` field (no category-type
	 * filter) but adds signature filters, inject the categories as category filters
	 * so the overrides overlay the full selection — otherwise ips_compile_filters
	 * would emit ONLY the listed sids and silently drop every other rule (the
	 * profile collapses, and even the overridden sid loses its default alert). */
	int have_cat = 0;
	for (int i = 0; i < nf; i++)
		if (filters[i].type == IPS_FT_CATEGORY) { have_cat = 1; break; }
	if (nf > 0 && !have_cat) {
		char *cat = sg_db_get_val("security_ips-profile", name, "categories");
		char tmp[1024];
		snprintf(tmp, sizeof(tmp), "%s", (cat && cat[0]) ? cat : "all");
		char *sp = NULL;
		for (char *c = strtok_r(tmp, ",", &sp); c && nf < MAX_FILTERS;
		     c = strtok_r(NULL, ",", &sp)) {
			while (*c == ' ' || *c == '\t') c++;
			char *e = c + strlen(c);
			while (e > c && (e[-1] == ' ' || e[-1] == '\t')) *--e = '\0';
			if (!*c) continue;
			filters[nf].type   = IPS_FT_CATEGORY;
			filters[nf].action = IPS_FA_DEFAULT;   /* base keeps each rule's action */
			snprintf(filters[nf].value, sizeof(filters[nf].value), "%s", c);
			nf++;
		}
		free(cat);
	}

	if (nf > 0) {
		int r = ips_compile_filters(IPS_REPO_DIR, filters, nf, out_path);
		mgmt_log("INFO", "ips: profile '%s' compiled from %d filter(s) → %d rule(s)",
			 name, nf, r);
		return r;
	}

	/* fallback: categories */
	char *cat = sg_db_get_val("security_ips-profile", name, "categories");
	int r = ips_compile_categories(IPS_REPO_DIR,
				       (cat && cat[0]) ? cat : "all", out_path);
	mgmt_log("INFO", "ips: profile '%s' compiled from categories '%s' → %d rule(s)",
		 name, (cat && cat[0]) ? cat : "all", r);
	free(cat);
	return r;
}

int ips_profile_bit(const char *name)
{
	if (!name || !*name)
		return -1;
	char *list = sg_db_list("security_ips-profile");
	if (!list)
		return -1;
	int bit = -1, idx = 0;
	char *sp = NULL;
	for (char *id = strtok_r(list, "\n", &sp); id;
	     id = strtok_r(NULL, "\n", &sp)) {
		char *st = sg_db_get_val("security_ips-profile", id, "status");
		int en = st && strcmp(st, "enable") == 0;
		free(st);
		if (!en)
			continue;
		if (idx > 30)
			break;                  /* out of bits for the uint32 mask */
		if (strcmp(id, name) == 0) { bit = idx; break; }
		idx++;
	}
	free(list);
	return bit;
}

/* Extract the sid from a Suricata rule line; 0 if none. */
static uint32_t line_sid(const char *line)
{
	const char *s = strstr(line, "sid:");
	return s ? (uint32_t)strtoul(s + 4, NULL, 10) : 0;
}


/* Write /etc/stargazer/ips/.update.conf for cron (ips-update-cron.sh) to read —
 * avoids cron having to call ipc-cli (auth issue). Carries the scheduled-update
 * spec (source of truth = the WebUI Schedule tab / the security_ips cron-* keys)
 * plus every enabled ruleset URL. The static crontab runs the wrapper every
 * minute; the wrapper matches these five cron fields against the current time
 * and fires the download only on a match. */
static void ips_write_update_conf(void)
{
	FILE *f = fopen("/etc/stargazer/ips/.update.conf", "w");
	if (!f) return;

	/* Cron schedule fields (mirror the validation defaults in sg_validate.c). */
	static const struct { const char *key, *label, *dflt; } cf[] = {
		{ "cron-enabled", "cron_enabled", "disable" },
		{ "cron-minutes", "cron_min",     "0" },
		{ "cron-hours",   "cron_hour",    "0" },
		{ "cron-dom",     "cron_dom",     "*" },
		{ "cron-months",  "cron_mon",     "*" },
		{ "cron-dow",     "cron_dow",     "*" },
	};
	for (size_t i = 0; i < sizeof(cf) / sizeof(cf[0]); i++) {
		char *v = sg_db_get_val("security_ips", "0", cf[i].key);
		fprintf(f, "%s=%s\n", cf[i].label, (v && v[0]) ? v : cf[i].dflt);
		free(v);
	}

	/* CSV of enabled ruleset IDs. The wrapper hands this straight to
	 * SG_CMD_IPS_UPDATE_NOW — the SAME path the WebUI "Update Now" button
	 * uses (run_ips_update_now) — so a scheduled run downloads, stamps
	 * last-downloaded (the GUI "LAST UPDATED" column), and hot-reloads
	 * identically to a manual update. No per-URL shell loop / category
	 * derivation needed on the device. */
	char csv[1024];
	size_t cpos = 0;
	csv[0] = '\0';
	char *ids = sg_db_list("security_ips-ruleset");
	if (ids) {
		char *sp = NULL;
		for (char *id = strtok_r(ids, "\n", &sp); id;
		     id = strtok_r(NULL, "\n", &sp)) {
			char *ena = sg_db_get_val("security_ips-ruleset", id, "enabled");
			char *url = sg_db_get_val("security_ips-ruleset", id, "url");
			if (ena && strcmp(ena, "enable") == 0 && url && url[0]) {
				int n = snprintf(csv + cpos, sizeof(csv) - cpos,
						 "%s%s", cpos ? "," : "", id);
				if (n > 0 && (size_t)n < sizeof(csv) - cpos)
					cpos += (size_t)n;
			}
			free(ena);
			free(url);
		}
		free(ids);
	}
	fprintf(f, "ids=%s\n", csv);
	fclose(f);
}

/* The profile id IS the entry id (numeric-id table, like firewall_policy). It
 * drives the scope bit, the iptables MARK/connmark, and the map filename
 * <id>.rules. `id` is the profile's entry id (or a ref to it). Returns 1..31, or
 * -1 if not a valid profile id. */
int ips_profid(const char *id)
{
	if (!id || !*id)
		return -1;
	int n = atoi(id);
	return (n >= 1 && n <= 31) ? n : -1;
}

/* Build profiles/<profid>.rules = "sid action" for one profile. Reuses
 * compile_one_profile (resolves categories/filters → rule text with the
 * effective action) into a temp full-text file, then projects it to the
 * sid→action map and drops the heavy intermediate. Returns rule count, -1 err. */
	static int compile_profile_map(const char *name)
	{
		int profid = ips_profid(name);
		if (profid < 1)
			return -1;

		char text[512];                         /* intermediate profiles/<name>.rules */
		int n = compile_one_profile(name, text, sizeof(text));
		if (n < 0)
			return -1;

		char map[512], maptmp[600];
		snprintf(map,    sizeof(map),    "%s/%04d.rules", IPS_PROF_DIR, profid);
		snprintf(maptmp, sizeof(maptmp), "%s/.%04d.tmp",  IPS_PROF_DIR, profid);

		FILE *in  = fopen(text, "r");
		FILE *out = fopen(maptmp, "w");
		if (in && out) {
			char line[16384];
			while (fgets(line, sizeof(line), in)) {
				uint32_t sid = line_sid(line);
				if (!sid) continue;
				const char *p = line;
				while (*p == ' ' || *p == '\t') p++;
				/* effective action = first token (drop→block, else alert) */
				const char *act = (strncmp(p, "drop", 4) == 0) ? "block" : "alert";
				fprintf(out, "%u %s\n", sid, act);
			}
		}
		if (in)  fclose(in);
		if (out) fclose(out);
		rename(maptmp, map);            /* atomic publish of the map */
		remove(text);                   /* drop the heavy full-text intermediate */
		return n;
	}

/* Signature of a profile's selection: its category/filter definition + the rule
 * TABLE generation (active.rules mtime). rebuild_ips_scope skips a profile whose
 * map is already current — so a policy change or an unrelated edit recompiles
 * nothing, and a download (table mtime changes) recompiles every profile. */
static void profile_sig(const char *name, char *out, size_t cap)
{
	unsigned long long h = 1469598103934665603ULL;   /* FNV-1a */
#define SIG_MIX(s) do { for (const char *q = (s); q && *q; q++) { \
		h ^= (unsigned char)*q; h *= 1099511628211ULL; } } while (0)
	char *catv = sg_db_get_val("security_ips-profile", name, "categories");
	SIG_MIX(name); SIG_MIX("|"); SIG_MIX(catv ? catv : "all"); SIG_MIX("|");
	free(catv);

	char *fl = sg_db_list("security_ips-filter");
	if (fl) {
		char pfx[24];
		int plen = snprintf(pfx, sizeof(pfx), "%s/", name);  /* "<profid>/" */
		char *sp = NULL;
		for (char *id = strtok_r(fl, "\n", &sp); id;
		     id = strtok_r(NULL, "\n", &sp)) {
			if (strncmp(id, pfx, (size_t)plen) != 0)
				continue;                       /* not our child */
			char *ru = sg_db_get_val("security_ips-filter", id, "rule");
			char *ca = sg_db_get_val("security_ips-filter", id, "category");
			char *ac = sg_db_get_val("security_ips-filter", id, "action");
			char *stt = sg_db_get_val("security_ips-filter", id, "status");
			SIG_MIX(id);            SIG_MIX(":");   /* seq makes it order-stable */
			SIG_MIX(ru ? ru : "");  SIG_MIX(":");
			SIG_MIX(ca ? ca : "");  SIG_MIX(":");
			SIG_MIX(ac ? ac : "");  SIG_MIX(":");
			SIG_MIX(stt ? stt : ""); SIG_MIX(";");
			free(ru); free(ca); free(ac); free(stt);
		}
		free(fl);
	}
	struct stat stt;
	long mt = (stat(IPS_ACTIVE, &stt) == 0) ? (long)stt.st_mtime : 0;
	char mbuf[40];
	snprintf(mbuf, sizeof(mbuf), "|t%ld", mt);
	SIG_MIX(mbuf);
#undef SIG_MIX
	snprintf(out, cap, "%016llx", h);
}

/* Order-independent signature of the repo .rules files (each file's
 * name+mtime+size, XORed). Lets rebuild_ips_table skip the merge ENTIRELY when
 * the downloaded rules are unchanged — so a normal boot does NO recompile (it
 * just loads the persisted active.rules). */
static void repo_sig(char *out, size_t cap)
{
	unsigned long long h = 1469598103934665603ULL;
	DIR *d = opendir(IPS_REPO_DIR);
	if (d) {
		struct dirent *de;
		while ((de = readdir(d))) {
			const char *dot = strrchr(de->d_name, '.');
			if (!dot || strcmp(dot, ".rules") != 0) continue;
			char p[512];
			snprintf(p, sizeof(p), "%s/%s", IPS_REPO_DIR, de->d_name);
			struct stat stt;
			if (stat(p, &stt) != 0) continue;
			unsigned long long e = 1469598103934665603ULL;
			for (const char *q = de->d_name; *q; q++) {
				e ^= (unsigned char)*q; e *= 1099511628211ULL;
			}
			e ^= (unsigned long long)stt.st_mtime * 1099511628211ULL;
			e ^= (unsigned long long)stt.st_size;
			h ^= e;                 /* XOR → independent of readdir order */
		}
		closedir(d);
	}
	snprintf(out, cap, "%016llx", h);
}

/* Rebuild active.rules (the TABLE = all repo rules). Skipped (no merge at all)
 * when the repo is unchanged. Signals SIGUSR1 (full table reload → AC rebuild)
 * ONLY when the content actually changed. */
static sg_status_t rebuild_ips_table(char *result, size_t rsize)
{
	mkdir(IPS_BASE_DIR,  0700);
	mkdir(IPS_REPO_DIR,  0700);
	mkdir(IPS_PROF_DIR,  0700);
	mkdir(IPS_RULES_DIR, 0700);

	/* Fast path (the common case, incl. EVERY boot): repo unchanged + table
	 * present → skip the whole merge. */
	char sig[24], oldsig[24] = "", sigp[512];
	repo_sig(sig, sizeof(sig));
	snprintf(sigp, sizeof(sigp), "%s/.repo.sig", IPS_RULES_DIR);
	FILE *sf = fopen(sigp, "r");
	if (sf) {
		if (fgets(oldsig, sizeof(oldsig), sf)) {
			char *nl = strchr(oldsig, '\n'); if (nl) *nl = '\0';
		}
		fclose(sf);
	}
	if (strcmp(oldsig, sig) == 0 && access(IPS_ACTIVE, R_OK) == 0) {
		snprintf(result, rsize, "table unchanged (cached)");
		return SG_OK;
	}

	int n = ips_compile_categories(IPS_REPO_DIR, "all", IPS_ACTIVE_TMP);
	if (n < 0) {
		snprintf(result, rsize, "IPS: cannot build rule table");
		return SG_ERR_SYSTEM_FAIL;
	}
	int reloaded = 0;
	if (files_equal(IPS_ACTIVE_TMP, IPS_ACTIVE)) {
		remove(IPS_ACTIVE_TMP);     /* repo touched but content identical */
	} else {
		if (rename(IPS_ACTIVE_TMP, IPS_ACTIVE) != 0) {
			mgmt_log("ERROR", "ips: rename of table failed: %m");
			remove(IPS_ACTIVE_TMP);
			snprintf(result, rsize, "IPS table swap failed");
			return SG_ERR_SYSTEM_FAIL;
		}
		pid_t pid = supervisor_get_pid("stargazer-ipsd");
		if (pid > 0) kill(pid, SIGUSR1);   /* table changed → AC rebuild */
		mgmt_log("INFO", "ips: rule table rebuilt (%d rule) → SIGUSR1 ipsd", n);
		ssld_sync();                       /* ssld reloads the table on restart */
		reloaded = 1;
	}
	/* Persist the repo signature so the next call (e.g. boot) can skip. */
	FILE *w = fopen(sigp, "w");
	if (w) { fprintf(w, "%s\n", sig); fclose(w); }
	snprintf(result, rsize, reloaded ? "table rebuilt (%d rule)"
					 : "table content unchanged (%d rule)", n);
	return SG_OK;
}

/* Rebuild the per-profile selection maps. Only profiles whose signature changed
 * are recompiled; maps of removed/disabled profiles are pruned. Signals SIGUSR2
 * (cheap scope reload, NO AC rebuild) ONLY when something changed. */
static sg_status_t rebuild_ips_scope(char *result, size_t rsize)
{
	mkdir(IPS_PROF_DIR, 0700);
	ips_write_update_conf();

	int valid[32] = {0};
	int changed = 0, nprof = 0;
	char *list = sg_db_list("security_ips-profile");
	if (list) {
		char *sp = NULL;
		for (char *id = strtok_r(list, "\n", &sp); id;
		     id = strtok_r(NULL, "\n", &sp)) {
			char *st = sg_db_get_val("security_ips-profile", id, "status");
			int en = !st || strcmp(st, "disable") != 0;
			free(st);
			if (!en) continue;
			int profid = ips_profid(id);
			if (profid < 1) continue;
			valid[profid] = 1; nprof++;

			char sig[24], old[24] = "", sigp[512], mapp[512];
			profile_sig(id, sig, sizeof(sig));
			snprintf(sigp, sizeof(sigp), "%s/%04d.sig",   IPS_PROF_DIR, profid);
			snprintf(mapp, sizeof(mapp), "%s/%04d.rules", IPS_PROF_DIR, profid);
			FILE *sf = fopen(sigp, "r");
			if (sf) {
				if (fgets(old, sizeof(old), sf)) {
					char *nl = strchr(old, '\n'); if (nl) *nl = '\0';
				}
				fclose(sf);
			}
			if (strcmp(old, sig) == 0 && access(mapp, R_OK) == 0)
				continue;               /* map already current → skip */
			if (compile_profile_map(id) >= 0) {
				FILE *w = fopen(sigp, "w");
				if (w) { fprintf(w, "%s\n", sig); fclose(w); }
				changed++;
			}
		}
		free(list);
	}

	/* Sweep the profile dir: keep ONLY the canonical map/sig of an ENABLED
	 * profile (exactly "%04d.rules" / "%04d.sig"). Everything else is removed:
	 *   - canonical map of a now-disabled profid → real scope change (counts,
	 *     SIGUSR2 below).
	 *   - non-canonical orphans → old full-text "<name>.rules" or un-padded
	 *     "<id>.rules" left over from a previous storage format; ipsd never reads
	 *     them, so this is pure disk cleanup (does NOT count as a scope change).
	 * The old sscanf("%d.%s") prune could not tell "1.rules" (orphan) from
	 * "0001.rules" (current) — both parse to profid 1 — so those 28 MB
	 * intermediates leaked and filled the config partition. */
	int orphans = 0;
	DIR *d = opendir(IPS_PROF_DIR);
	if (d) {
		struct dirent *de;
		while ((de = readdir(d))) {
			const char *nm = de->d_name;
			if (nm[0] == '.')             /* ".", "..", ".NNNN.tmp" */
				continue;
			size_t nl = strlen(nm);
			int rulesig = (nl > 6 && strcmp(nm + nl - 6, ".rules") == 0) ||
				      (nl > 4 && strcmp(nm + nl - 4, ".sig")   == 0);
			if (!rulesig)
				continue;

			/* canonical = exactly NNNN.rules (10 ch) or NNNN.sig (8 ch),
			 * the first 4 characters all digits. */
			int canon = (nl == 10 && strcmp(nm + 4, ".rules") == 0) ||
				    (nl == 8  && strcmp(nm + 4, ".sig")   == 0);
			int pid = 0;
			if (canon)
				for (int i = 0; i < 4; i++) {
					if (nm[i] < '0' || nm[i] > '9') {
						canon = 0; break;
					}
					pid = pid * 10 + (nm[i] - '0');
				}

			if (canon && pid >= 1 && pid <= 31 && valid[pid])
				continue;            /* current profile's file → keep */

			char p[512];
			snprintf(p, sizeof(p), "%s/%s", IPS_PROF_DIR, nm);
			remove(p);
			if (canon && pid >= 1 && pid <= 31)
				changed++;           /* disabled profid → scope change */
			else
				orphans++;           /* leaked old-format file → cleanup */
		}
		closedir(d);
	}
	if (orphans)
		mgmt_log("INFO", "ips: swept %d orphan profile file(s)", orphans);

	if (changed) {
		pid_t pid = supervisor_get_pid("stargazer-ipsd");
		if (pid > 0) kill(pid, SIGUSR2);    /* scope changed → cheap reload */
		mgmt_log("INFO", "ips: profile maps rebuilt (%d profile, %d changed) "
			 "→ SIGUSR2 ipsd", nprof, changed);
	}
	snprintf(result, rsize, "scope (%d profile, %d changed)", nprof, changed);
	return SG_OK;
}

sg_status_t rebuild_ips_active(char *result, size_t rsize)
{
	/* TABLE (heavy; only when the repo/download changed → files_equal skip)
	 * then per-profile SCOPE maps (cheap; only changed profiles recompile).
	 * Profile/policy edits leave the table unchanged → no SIGUSR1/AC rebuild;
	 * only changed profiles emit SIGUSR2. */
	char tr[256] = "", sc[256] = "";
	rebuild_ips_table(tr, sizeof(tr));
	rebuild_ips_scope(sc, sizeof(sc));

	/* Phase 4 Stage 2: sync the kernel ML-HTTPS hook (LOCAL_IN) with ml-https. */
	{
		char *ml = sg_db_get_val("security_ips", "0", "ml-https");
		int on = ml && strcmp(ml, "enable") == 0;
		free(ml);
		FILE *pf = fopen("/sys/module/pkt_forward/parameters/"
				 "ml_account_local", "w");
		if (pf) { fputc(on ? '1' : '0', pf); fclose(pf); }
	}

	snprintf(result, rsize, "IPS rebuilt: %s; %s", tr, sc);
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
	char  failed[512] = "";        /* names of rulesets that failed to download (for the message) */
	size_t fpos = 0;
	char  reason[256] = "";        /* the FIRST error reason (extracted from the script) */

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
		/* Error = the script failed to run (out NULL) OR the script printed
		 * "ERROR" (download failed / empty file / verify broken). The details
		 * already went to ips-update.log; here we only collect names to report
		 * to the user. */
		int ok = (out && !strstr(out, "ERROR"));
		if (!ok) {
			errors++;
			int fn = snprintf(failed + fpos, sizeof(failed) - fpos,
					  "%s%s", fpos ? ", " : "", catname);
			if (fn > 0 && (size_t)fn < sizeof(failed) - fpos)
				fpos += (size_t)fn;
			/* Extract the first ERROR line as the displayed reason (no
			 * internet / wrong DNS / broken syntax / empty file…). */
			if (!reason[0]) {
				const char *e = out ? strstr(out, "ERROR") : NULL;
				if (e)
					snprintf(reason, sizeof(reason), "%.*s",
						 (int)strcspn(e, "\n"), e);
				else
					snprintf(reason, sizeof(reason),
						 "could not run the download script");
			}
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

	/* Clear notification for the user (toast in the UI). */
	if (errors > 0) {
		snprintf(result, rsize,
			 "Failed to download %d ruleset(s) (%s): %s. %d ruleset(s) OK.",
			 errors, failed[0] ? failed : "?",
			 reason[0] ? reason : "check network / source URL", updated);
		return SG_ERR_SYSTEM_FAIL;
	}
	snprintf(result, rsize, "Updated %d ruleset(s) successfully.", updated);
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
