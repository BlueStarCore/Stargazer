/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_firewall.c — Apply handler for firewall_policy
 *
 * Translates firewall_policy DB entries to iptables FORWARD rules.
 * Fields used:
 *   srcintf  — source interface ("any" → omit -i)
 *   dstintf  — destination interface ("any" → omit -o)
 *   srcaddr  — source address CIDR ("all"/"any" or non-CIDR → omit -s)
 *   dstaddr  — destination address CIDR ("all"/"any" or non-CIDR → omit -d)
 *   action   — "accept"/"allow" → ACCEPT; "deny"/"drop" → DROP
 *   status   — "disable" → skip rule entirely
 */

#include "mgmtd_apply.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Build iptables argv for a FORWARD rule.  op is "-A" or "-D". */
static int build_forward_argv(const char *op,
			      const char *srcintf, const char *dstintf,
			      const char *srcaddr, const char *dstaddr,
			      const char *target,
			      const char *argv[], int max_argc)
{
	int ac = 0;

	if (ac + 4 > max_argc) return -1;
	argv[ac++] = "iptables";
	argv[ac++] = op;
	argv[ac++] = "FORWARD";

	if (srcintf[0] && strcmp(srcintf, "any") != 0) {
		if (ac + 2 > max_argc) return -1;
		argv[ac++] = "-i";
		argv[ac++] = srcintf;
	}
	if (dstintf[0] && strcmp(dstintf, "any") != 0) {
		if (ac + 2 > max_argc) return -1;
		argv[ac++] = "-o";
		argv[ac++] = dstintf;
	}
	/* Only use -s/-d when the value is a valid CIDR — skip address
	 * object references and the catch-all "all"/"any" values. */
	if (srcaddr[0] &&
	    strcmp(srcaddr, "all") != 0 && strcmp(srcaddr, "any") != 0 &&
	    sg_is_cidr(srcaddr)) {
		if (ac + 2 > max_argc) return -1;
		argv[ac++] = "-s";
		argv[ac++] = srcaddr;
	}
	if (dstaddr[0] &&
	    strcmp(dstaddr, "all") != 0 && strcmp(dstaddr, "any") != 0 &&
	    sg_is_cidr(dstaddr)) {
		if (ac + 2 > max_argc) return -1;
		argv[ac++] = "-d";
		argv[ac++] = dstaddr;
	}

	if (ac + 3 > max_argc) return -1;
	argv[ac++] = "-j";
	argv[ac++] = target;
	argv[ac]   = NULL;
	return ac;
}

sg_status_t apply_firewall_policy(const char *id, const char *data,
				   char *result, size_t rsize)
{
	char srcintf[VALBUFSZ], dstintf[VALBUFSZ];
	char srcaddr[VALBUFSZ], dstaddr[VALBUFSZ];
	char action[VALBUFSZ],  status[VALBUFSZ];

	extract_val(data, "srcintf", srcintf, sizeof(srcintf));
	extract_val(data, "dstintf", dstintf, sizeof(dstintf));
	extract_val(data, "srcaddr", srcaddr, sizeof(srcaddr));
	extract_val(data, "dstaddr", dstaddr, sizeof(dstaddr));
	extract_val(data, "action",  action,  sizeof(action));
	extract_val(data, "status",  status,  sizeof(status));

	if (strcmp(status, "disable") == 0) {
		snprintf(result, rsize, "Policy %s disabled.", id);
		return SG_OK;
	}

	const char *target =
		(strcmp(action, "accept") == 0 || strcmp(action, "allow") == 0)
		? "ACCEPT" : "DROP";

	const char *argv[24];
	if (build_forward_argv("-A", srcintf, dstintf, srcaddr, dstaddr,
			       target, argv, 24) < 0) {
		snprintf(result, rsize, "Policy %s: too many rule args.", id);
		return SG_ERR_INVALID_ARG;
	}

	if (ipt_exec(argv) != 0) {
		snprintf(result, rsize, "Policy %s: iptables FORWARD rule failed.", id);
		return SG_ERR_SYSTEM_FAIL;
	}

	snprintf(result, rsize, "Policy %s applied (%s).", id, target);
	return SG_OK;
}

void unapply_firewall_policy(const char *id, const char *data)
{
	char srcintf[VALBUFSZ], dstintf[VALBUFSZ];
	char srcaddr[VALBUFSZ], dstaddr[VALBUFSZ];
	char action[VALBUFSZ],  status[VALBUFSZ];

	(void)id;

	extract_val(data, "srcintf", srcintf, sizeof(srcintf));
	extract_val(data, "dstintf", dstintf, sizeof(dstintf));
	extract_val(data, "srcaddr", srcaddr, sizeof(srcaddr));
	extract_val(data, "dstaddr", dstaddr, sizeof(dstaddr));
	extract_val(data, "action",  action,  sizeof(action));
	extract_val(data, "status",  status,  sizeof(status));

	if (strcmp(status, "disable") == 0)
		return; /* rule was never added */

	const char *target =
		(strcmp(action, "accept") == 0 || strcmp(action, "allow") == 0)
		? "ACCEPT" : "DROP";

	const char *argv[24];
	if (build_forward_argv("-D", srcintf, dstintf, srcaddr, dstaddr,
			       target, argv, 24) < 0)
		return;

	free(safe_exec(argv));
}
