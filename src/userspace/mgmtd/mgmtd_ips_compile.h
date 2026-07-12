/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_ips_compile.h — Compile IPS ruleset by category (Phase B).
 *
 * The global signature store is organized into per-category files: <repo>/<cat>.rules
 * (e.g. repo/scan.rules, repo/web.rules). A profile selects a set of categories via
 * the `categories` field ("all" or "scan,web,malware"). The compile function merges
 * the selected category files into ONE output ruleset (per-profile or active).
 *
 * Pure I/O (dirent/stdio) — does NOT depend on DB/mgmtd → host-testable.
 */
#ifndef MGMTD_IPS_COMPILE_H
#define MGMTD_IPS_COMPILE_H

#include <stddef.h>

/*
 * Merge the selected categories from repo_dir into out_path.
 *
 *   repo_dir   : directory containing <category>.rules
 *   categories : "all" → every *.rules in the repo; or a list "a,b,c"
 *                (each entry → repo_dir/<entry>.rules; a missing file is skipped).
 *   out_path   : output ruleset file (overwritten).
 *
 * Returns the number of category files merged (>=0), -1 on failure to open out_path / repo.
 * out_path always has a header comment + the category contents (even 0 files →
 * a valid empty file, ipsd -C will report 0 rules).
 */
int ips_compile_categories(const char *repo_dir, const char *categories,
			   const char *out_path);

/* ── FortiGate IPS sensor: filter compile + per-entry ACTION (P7) ──────── */

enum ips_filter_type   { IPS_FT_CATEGORY = 0, IPS_FT_SIGNATURE = 1 };
enum ips_filter_action { IPS_FA_DEFAULT = 0, IPS_FA_BLOCK, IPS_FA_ALERT,
			 IPS_FA_PASS };

struct ips_filter {
	int  type;          /* enum ips_filter_type   */
	char value[128];    /* category name or SID   */
	int  action;        /* enum ips_filter_action (P7) */
};

/*
 * Compile a profile's ruleset FROM a filter list into out_path (P7).
 * Each entry carries a per-entry action; when writing a rule, REWRITE the first action token:
 *   default → keep the rule's original action.   block → "drop".   alert → "alert".
 *   pass    → do NOT write the rule (whitelist, excluded from the profile).
 * Precedence (like FortiGate): signature override > category > default — a sid with a
 * filter type=signature uses that action, even when the sid is inside a category.
 * A partial-match rule (P0 fidelity ALERT), even if block, is still clamped to ALERT by
 * ipsd at runtime (no false-DROP).
 * Returns the number of RULE lines written (>=0), -1 on failure to open out_path/repo.
 */
int ips_compile_filters(const char *repo_dir, const struct ips_filter *filters,
			int n_filters, const char *out_path);

/*
 * List the signatures in the repo as a JSON array (for the FortiGate-style
 * "Add Signatures" table). Each entry: {sid,name,category,action,cve}. Parse each rule
 * to get the action (first token), msg:"..." (name), sid:N;, reference:cve,...
 * Write into buf (cap), return the length (>=0) or -1. Truncate safely if near the cap.
 */
/* allowed: array of category name strings (repo filename stem, e.g. "botcc").
 * Only entries whose category appears in allowed[] are included.
 * Pass allowed=NULL / n_allowed=0 to include everything.
 *
 * query: text filter (case-insensitive) — only entries with `query` in sid/name/
 * category/cve are emitted. NULL/"" = no filter. Because the IPC response is limited
 * to 64KB, a large ruleset must be SEARCHed server-side; *truncated is set to 1 if there
 * are still matching entries but no room left (the frontend prompts "narrow the keyword"). */
int ips_catalog_to_json(const char *repo_dir, char *buf, size_t cap,
                        const char *const *allowed, int n_allowed,
                        const char *query, int *truncated);

#endif /* MGMTD_IPS_COMPILE_H */
