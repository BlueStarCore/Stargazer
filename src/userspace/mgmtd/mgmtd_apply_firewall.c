/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_firewall.c — Atomic FORWARD chain rebuild
 *
 * On any firewall_policy change (create, update, delete, move),
 * the entire FORWARD chain is rebuilt from the DB and loaded
 * atomically via iptables-restore --noflush.
 *
 * Flow:
 *   1. Flush FORWARD chain (policy DROP catches all traffic)
 *   2. Read ALL firewall_policy entries from DB in sequence order
 *   3. Generate iptables-restore script in memory:
 *        *filter
 *        -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
 *        -A FORWARD ... (highest sequence first = highest priority)
 *        COMMIT
 *   4. Pipe to iptables-restore --noflush (atomic kernel load)
 *
 * Higher sequence = higher priority = earlier in the chain.
 * Disabled entries are skipped (not in kernel).
 * The FORWARD chain policy (DROP) is set at boot by init_firewall()
 * and is NOT touched by this rebuild — only the rules change.
 *
 * Fields used:
 *   srcintf  — source interface ("any" → omit -i)
 *   dstintf  — destination interface ("any" → omit -o)
 *   srcaddr  — source CIDR ("all"/"any" → omit -s)
 *   dstaddr  — destination CIDR ("all"/"any" → omit -d)
 *   action   — "accept"/"allow" → ACCEPT; "deny" → REJECT; "drop" → DROP
 *   status   — "disable" → skip rule entirely
 *   sequence — priority (higher = checked first)
 */

#include "mgmtd_apply.h"
#include "mgmtd_dynbuf.h"
#include "sg_db.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Address / Service resolution ───────────────────────────────────────── */

/*
 * resolve_address — Resolve a policy/NAT address field to a CIDR string.
 *
 * Returns:
 *   pointer to out  — resolved CIDR (caller uses it)
 *   NULL            — match-all (0.0.0.0/0), omit -s/-d flag
 *   "SKIP"          — object not found, skip the entire rule (fail-closed)
 */
const char *resolve_address(const char *val, char *out, size_t outsz)
{
	if (!val || !val[0])
		return NULL;

	/* "any" and "all" are match-all keywords — no DB lookup needed */
	if (strcmp(val, "any") == 0 || strcmp(val, "all") == 0)
		return NULL;

	/* Raw CIDR passthrough (backward compat for NAT legacy data) */
	if (sg_is_cidr(val)) {
		if (strcmp(val, "0.0.0.0/0") == 0)
			return NULL;  /* match-all → omit flag */
		snprintf(out, outsz, "%s", val);
		return out;
	}

	/* Look up firewall_address entry */
	char *data = sg_db_get("firewall_address", val);
	if (!data) {
		mgmt_log("ERROR", "resolve_address: '%s' not found", val);
		return "SKIP";
	}

	char subnet[VALBUFSZ];
	extract_val(data, "subnet", subnet, sizeof(subnet));
	free(data);

	if (!subnet[0] || !sg_is_cidr(subnet)) {
		mgmt_log("ERROR", "resolve_address: '%s' invalid subnet",
			 val);
		return "SKIP";
	}

	/* 0.0.0.0/0 = match-all → omit flag for cleaner rules */
	if (strcmp(subnet, "0.0.0.0/0") == 0)
		return NULL;

	snprintf(out, outsz, "%s", subnet);
	return out;
}

/*
 * resolve_service — Look up a firewall_service entry.
 *
 * Returns:
 *   0  = match-all (no service filter)
 *   1  = resolved, proto_out and port_out filled
 *  -1  = not found (dangling ref — skip rule, fail-closed)
 */
static int resolve_service(const char *val,
			   char *proto_out, size_t psz,
			   char *port_out, size_t ptsz)
{
	proto_out[0] = '\0';
	port_out[0] = '\0';

	if (!val || !val[0])
		return 0;

	char *data = sg_db_get("firewall_service", val);
	if (!data) {
		mgmt_log("ERROR", "resolve_service: '%s' not found", val);
		return -1;
	}

	extract_val(data, "protocol", proto_out, psz);
	extract_val(data, "port-range", port_out, ptsz);
	free(data);

	if (!proto_out[0]) {
		mgmt_log("ERROR", "resolve_service: '%s' no protocol", val);
		return -1;
	}

	/* protocol=all means no filtering */
	if (strcmp(proto_out, "all") == 0)
		return 0;

	return 1;
}

/* ── Helpers ────────────────────────────────────────────────────────────── */

static const char *action_to_target(const char *action)
{
	if (strcmp(action, "accept") == 0 || strcmp(action, "allow") == 0)
		return "ACCEPT";
	if (strcmp(action, "deny") == 0)
		return "REJECT";
	return "DROP";
}

/* ── Rebuild ─────────────────────────────────────────────────────────────── */

/*
 * connmark_supported - probe once whether iptables can use the connmark
 * match + CONNMARK target (needs CONFIG_NF_CONNTRACK_MARK + xt_connmark).
 * Result is cached. When available we re-evaluate only the affected live flows
 * on a policy change via a connmark "generation" tag; when not, we fall back to
 * flushing the whole conntrack table.
 */
static int connmark_supported(void)
{
	static int cached = -1;
	if (cached >= 0)
		return cached;

	const char *newc[]   = {"iptables", "-N", "SG_CMK_PROBE", NULL};
	const char *addc[]   = {"iptables", "-A", "SG_CMK_PROBE",
				"-m", "connmark", "--mark", "0/0xff",
				"-j", "CONNMARK", "--set-xmark", "0/0xff", NULL};
	const char *flushc[] = {"iptables", "-F", "SG_CMK_PROBE", NULL};
	const char *delc[]   = {"iptables", "-X", "SG_CMK_PROBE", NULL};

	ipt_exec(newc);
	cached = (ipt_exec(addc) == 0) ? 1 : 0;
	ipt_exec(flushc);
	ipt_exec(delc);

	mgmt_log("INFO", "connmark %s; policy changes %s",
		 cached ? "available" : "unavailable",
		 cached ? "re-evaluate only affected live flows"
			: "flush conntrack (fallback)");
	return cached;
}

/*
 * Policy generation tag, carried in connmark bits 0-7 (values 1..255). Bumped
 * on each FORWARD rebuild so live flows re-traverse the new policy: still-
 * allowed flows get re-stamped with the new gen and continue uninterrupted;
 * flows the new policy denies fall through to DROP. In-memory only (resets to
 * 1 on mgmtd restart — harmless, flows simply re-evaluate once).
 */
#define SG_CMK_MASK 0xFFu
static unsigned int fwd_policy_gen = 1;

sg_status_t rebuild_forward_chain(char *result, size_t rsize)
{
	struct dynbuf buf;
	if (dbuf_init(&buf, 4096) < 0) {
		snprintf(result, rsize, "Out of memory");
		return SG_ERR_SYSTEM_FAIL;
	}

	int cmk = connmark_supported();
	if (cmk)
		fwd_policy_gen = (fwd_policy_gen % 255) + 1;  /* 1..255, skip 0 */

	/* Header */
	dbuf_append(&buf, "*filter\n", 8);

	/* Foundation rules (conntrack-stateful):
	 *   - drop packets conntrack cannot associate with a valid flow (INVALID),
	 *     replacing the stateful validation that session.ko used to perform;
	 *   - fast-path accept of established/related return traffic. */
	{
		const char *inv = "-A FORWARD -m conntrack --ctstate INVALID -j DROP\n";
		dbuf_append(&buf, inv, strlen(inv));
		if (cmk)
			/* Only flows tagged with the CURRENT generation take the
			 * fast-path; stale-gen and NEW flows fall through to the
			 * policy rules below for (re-)evaluation. */
			dbuf_printf(&buf,
				"-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED"
				" -m connmark --mark 0x%x/0x%x -j ACCEPT\n",
				fwd_policy_gen, SG_CMK_MASK);
		else
			dbuf_printf(&buf,
				"-A FORWARD -m conntrack"
				" --ctstate ESTABLISHED,RELATED -j ACCEPT\n");
	}

	/* Read all policies ordered by sequence DESC (highest first) */
	char *list = sg_db_list_ordered("firewall_policy", "sequence");
	int rule_count = 0;

	if (list) {
		char *saveptr = NULL;
		for (char *id = strtok_r(list, "\n", &saveptr);
		     id;
		     id = strtok_r(NULL, "\n", &saveptr)) {

			char *data = sg_db_get("firewall_policy", id);
			if (!data)
				continue;

			char srcintf[VALBUFSZ], dstintf[VALBUFSZ];
			char srcaddr[VALBUFSZ], dstaddr[VALBUFSZ];
			char action[VALBUFSZ], status[VALBUFSZ];
			char service[VALBUFSZ];

			extract_val(data, "srcintf",  srcintf,  sizeof(srcintf));
			extract_val(data, "dstintf",  dstintf,  sizeof(dstintf));
			extract_val(data, "srcaddr",  srcaddr,  sizeof(srcaddr));
			extract_val(data, "dstaddr",  dstaddr,  sizeof(dstaddr));
			extract_val(data, "action",   action,   sizeof(action));
			extract_val(data, "status",   status,   sizeof(status));
			extract_val(data, "service",  service,  sizeof(service));

			free(data);

			if (strcmp(status, "disable") == 0)
				continue;

			const char *target = action_to_target(action);

			/* Build rule line */
			size_t rule_start = buf.used;
			dbuf_printf(&buf, "-A FORWARD");

			if (srcintf[0] && strcmp(srcintf, "any") != 0)
				dbuf_printf(&buf, " -i %s", srcintf);
			if (dstintf[0] && strcmp(dstintf, "any") != 0)
				dbuf_printf(&buf, " -o %s", dstintf);
			/* Resolve address objects */
			{
				char resolved[VALBUFSZ];
				const char *src = resolve_address(
					srcaddr, resolved, sizeof(resolved));
				if (src && strcmp(src, "SKIP") == 0)
					goto skip_rule;
				if (src)
					dbuf_printf(&buf, " -s %s", src);
			}
			{
				char resolved[VALBUFSZ];
				const char *dst = resolve_address(
					dstaddr, resolved, sizeof(resolved));
				if (dst && strcmp(dst, "SKIP") == 0)
					goto skip_rule;
				if (dst)
					dbuf_printf(&buf, " -d %s", dst);
			}

			/* Resolve service object */
			char svc_proto[VALBUFSZ];
			svc_proto[0] = '\0';
			{
				char svc_port[VALBUFSZ];
				int svc_rc = resolve_service(service,
					svc_proto, sizeof(svc_proto),
					svc_port, sizeof(svc_port));
				if (svc_rc < 0)
					goto skip_rule;
				if (svc_rc == 1 && svc_proto[0]) {
					dbuf_printf(&buf, " -p %s", svc_proto);
					/* ICMP has no ports */
					if (svc_port[0] &&
					    strcmp(svc_proto, "icmp") != 0)
						dbuf_printf(&buf, " --dport %s",
							    svc_port);
				}
			}

			/*
			 * deny → REJECT: TCP gets RST so the sender fails
			 * immediately; everything else gets ICMP port-unreachable.
			 *
			 * When the service is "any" (svc_proto empty) we cannot
			 * know the protocol at rule-build time, so we split into
			 * two rules: a TCP-specific rule with --reject-with
			 * tcp-reset, followed by a catch-all for the rest.
			 * The prefix is copied to a stack buffer before the first
			 * dbuf_printf because that call may reallocate buf.data.
			 */
			if (strcmp(target, "REJECT") == 0 &&
			    svc_proto[0] == '\0') {
				size_t plen = buf.used - rule_start;
				char saved_pfx[256];
				if (plen < sizeof(saved_pfx)) {
					memcpy(saved_pfx, buf.data + rule_start,
					       plen);
					dbuf_printf(&buf,
						" -p tcp"
						" -j REJECT"
						" --reject-with tcp-reset\n");
					rule_count++;
					dbuf_append(&buf, saved_pfx, plen);
					dbuf_printf(&buf, " -j REJECT\n");
					rule_count++;
				} else {
					/* Safety: prefix overflowed — emit plain REJECT */
					dbuf_printf(&buf, " -j REJECT\n");
					rule_count++;
				}
			} else if (strcmp(target, "REJECT") == 0 &&
				   strcmp(svc_proto, "tcp") == 0) {
				dbuf_printf(&buf,
					" -j REJECT --reject-with tcp-reset\n");
				rule_count++;
			} else {
				/*
				 * For ACCEPT rules (when connmark is available), prepend a
				 * CONNMARK rule that stamps the current policy generation on
				 * the flow so its subsequent packets take the fast-path.
				 * Uses the same saved_pfx technique as the REJECT split.
				 * DENY/DROP flows are never stamped, so on a policy change
				 * they keep falling through to their drop until they expire.
				 */
				if (strcmp(target, "ACCEPT") == 0 && cmk) {
					size_t plen = buf.used - rule_start;
					char saved_pfx[256];
					if (plen < sizeof(saved_pfx)) {
						memcpy(saved_pfx,
						       buf.data + rule_start, plen);
						dbuf_printf(&buf,
							" -j CONNMARK --set-xmark"
							" 0x%x/0x%x\n",
							fwd_policy_gen, SG_CMK_MASK);
						rule_count++;
						dbuf_append(&buf, saved_pfx, plen);
					}
				}
				dbuf_printf(&buf, " -j %s\n", target);
				rule_count++;
			}
			continue; /* success — skip the rollback below */
		skip_rule:
			buf.used = rule_start; /* roll back partial -A FORWARD write */
		}
		free(list);
	}

	dbuf_append(&buf, "COMMIT\n", 7);

	/* Flush FORWARD chain.  During this brief window the chain
	 * policy (DROP) catches all forwarded traffic — fail-closed. */
	const char *flush[] = {"iptables", "-F", "FORWARD", NULL};
	ipt_exec(flush);

	/* Atomic restore — only adds to FORWARD (--noflush keeps
	 * INPUT and OUTPUT untouched). */
	const char *restore[] = {"iptables-restore", "--noflush", NULL};
	int exit_code = 0;
	char *out = pipe_exec_stdin(restore, buf.data, buf.used, &exit_code);

	if (exit_code != 0) {
		mgmt_log("ERROR", "rebuild_forward_chain: iptables-restore "
			 "failed (exit %d): %s", exit_code,
			 out ? out : "");
		free(out);
		free(buf.data);
		/* Recovery: at minimum restore the ESTABLISHED,RELATED rule */
		flush_forward_chain();
		snprintf(result, rsize, "FORWARD chain rebuild failed");
		return SG_ERR_SYSTEM_FAIL;
	}

	free(out);
	free(buf.data);

	/* Apply the policy change to live flows. With connmark, the generation
	 * bump at the top already forces every live flow to re-traverse the new
	 * policy on its next packet — still-allowed flows re-stamp and continue,
	 * only denied flows drop (surgical; management/allowed flows untouched).
	 * Without connmark, fall back to flushing the whole conntrack table. */
	if (!cmk)
		conntrack_flush_all();

	snprintf(result, rsize, "FORWARD chain rebuilt (%d rules)", rule_count);
	return SG_OK;
}

/*
 * validate_firewall_policy — field validation only, no kernel changes.
 * Used by CFG_APPLY (test run) so it doesn't duplicate rules.
 */
sg_status_t validate_firewall_policy(const char *id, const char *data,
				     char *result, size_t rsize)
{
	char action[VALBUFSZ], srcintf[VALBUFSZ], dstintf[VALBUFSZ];

	extract_val(data, "action",  action,  sizeof(action));
	extract_val(data, "srcintf", srcintf, sizeof(srcintf));
	extract_val(data, "dstintf", dstintf, sizeof(dstintf));

	if (action[0] == '\0') {
		snprintf(result, rsize, "Missing 'action'");
		return SG_ERR_MISSING_ARG;
	}

	if (strcmp(action, "accept") != 0 && strcmp(action, "allow") != 0 &&
	    strcmp(action, "deny")   != 0 && strcmp(action, "drop")  != 0) {
		snprintf(result, rsize, "Invalid action '%s' (accept/deny/drop)",
			 action);
		return SG_ERR_INVALID_VAL;
	}

	if (srcintf[0] && strcmp(srcintf, "any") != 0 &&
	    !sg_is_iface_name(srcintf)) {
		snprintf(result, rsize, "Invalid srcintf '%s'", srcintf);
		return SG_ERR_INVALID_VAL;
	}

	if (dstintf[0] && strcmp(dstintf, "any") != 0 &&
	    !sg_is_iface_name(dstintf)) {
		snprintf(result, rsize, "Invalid dstintf '%s'", dstintf);
		return SG_ERR_INVALID_VAL;
	}

	/* Enforce unique policy name across all firewall_policy entries.
	 * Skip the check when id is empty (defensive) or name is not set. */
	if (id && id[0]) {
		char name[VALBUFSZ];
		extract_val(data, "name", name, sizeof(name));
		if (name[0]) {
			char *matches = sg_db_find_referencing(
				"firewall_policy", "name", name);
			if (matches) {
				int dup = 0;
				char *copy = strdup(matches);
				if (!copy) {
					free(matches);
					snprintf(result, rsize, "Out of memory");
					return SG_ERR_SYSTEM_FAIL;
				}
				char *sp   = NULL;
				for (char *t = strtok_r(copy, "\n", &sp);
				     t; t = strtok_r(NULL, "\n", &sp)) {
					/* sg_db_find_referencing returns "type:id" */
					const char *colon = strchr(t, ':');
					const char *found_id = colon ? colon + 1 : t;
					if (found_id[0] && strcmp(found_id, id) != 0) {
						dup = 1;
						break;
					}
				}
				free(copy);
				free(matches);
				if (dup) {
					snprintf(result, rsize,
						 "Policy name '%s' is already in use",
						 name);
					return SG_ERR_INVALID_VAL;
				}
			}
		}
	}

	snprintf(result, rsize, "Policy %s validated", id ? id : "");
	return SG_OK;
}

