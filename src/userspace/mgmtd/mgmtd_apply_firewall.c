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
 *   action   — "accept"/"allow" → ACCEPT; "deny"/"drop" → DROP
 *   status   — "disable" → skip rule entirely
 *   sequence — priority (higher = checked first)
 */

#include "mgmtd_apply.h"
#include "mgmtd_dynbuf.h"
#include "sg_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
	return "DROP";
}

/* ── Rebuild ─────────────────────────────────────────────────────────────── */

sg_status_t rebuild_forward_chain(char *result, size_t rsize)
{
	struct dynbuf buf;
	if (dbuf_init(&buf, 4096) < 0) {
		snprintf(result, rsize, "Out of memory");
		return SG_ERR_SYSTEM_FAIL;
	}

	/* Header */
	dbuf_append(&buf, "*filter\n", 8);

	/* Foundation rule: allow established/related return traffic */
	{
		const char *est = "-A FORWARD -m conntrack"
			" --ctstate ESTABLISHED,RELATED -j ACCEPT\n";
		dbuf_append(&buf, est, strlen(est));
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
			{
				char svc_proto[VALBUFSZ], svc_port[VALBUFSZ];
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

			dbuf_printf(&buf, " -j %s\n", target);
			rule_count++;
		skip_rule:
			;
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
	(void)id;
	char action[VALBUFSZ], srcintf[VALBUFSZ], dstintf[VALBUFSZ];

	extract_val(data, "action",  action,  sizeof(action));
	extract_val(data, "srcintf", srcintf, sizeof(srcintf));
	extract_val(data, "dstintf", dstintf, sizeof(dstintf));

	if (action[0] == '\0') {
		snprintf(result, rsize, "Missing 'action'");
		return SG_ERR_MISSING_ARG;
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

	snprintf(result, rsize, "Policy %s validated", id);
	return SG_OK;
}

