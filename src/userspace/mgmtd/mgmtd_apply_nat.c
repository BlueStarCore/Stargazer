/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_nat.c — Apply handler for network_nat
 *
 * Extracted from stargazer-mgmtd.c for parallel development.
 * Owner: Member B (NAT enhancements)
 */

#include "mgmtd_apply.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

sg_status_t apply_nat(const char *id, const char *data,
		      char *result, size_t rsize)
{
	char nattype[VALBUFSZ], srcintf[VALBUFSZ], dstport[VALBUFSZ];
	char mapped_ip[VALBUFSZ], mapped_port[VALBUFSZ], status[VALBUFSZ];
	extract_val(data, "type", nattype, sizeof(nattype));
	extract_val(data, "srcintf", srcintf, sizeof(srcintf));
	extract_val(data, "dstport", dstport, sizeof(dstport));
	extract_val(data, "mapped-ip", mapped_ip, sizeof(mapped_ip));
	extract_val(data, "mapped-port", mapped_port, sizeof(mapped_port));
	extract_val(data, "status", status, sizeof(status));

	/* Validate inputs */
	if (srcintf[0] && !sg_is_iface_name(srcintf)) {
		snprintf(result, rsize, "Invalid srcintf '%s'.", srcintf);
		return SG_ERR_INVALID_VAL;
	}
	if (mapped_ip[0] && !sg_is_ipv4(mapped_ip)) {
		snprintf(result, rsize, "Invalid mapped-ip '%s'.", mapped_ip);
		return SG_ERR_INVALID_VAL;
	}
	if (dstport[0] && !sg_is_uint_range(dstport, 1, 65535)) {
		snprintf(result, rsize, "Invalid dstport '%s'.", dstport);
		return SG_ERR_INVALID_VAL;
	}
	if (mapped_port[0] && !sg_is_uint_range(mapped_port, 1, 65535)) {
		snprintf(result, rsize, "Invalid mapped-port '%s'.", mapped_port);
		return SG_ERR_INVALID_VAL;
	}

	if (strcmp(status, "disable") == 0) {
		snprintf(result, rsize, "NAT rule %s disabled.", id);
		return SG_OK;
	}
	if (strcmp(nattype, "snat") == 0 && srcintf[0]) {
		/* Check if rule already exists before adding */
		const char *chk[] = {"iptables", "-t", "nat", "-C", "POSTROUTING",
				     "-o", srcintf, "-j", "MASQUERADE", NULL};
		char *out = safe_exec(chk);
		int exists = 0;
		/* -C returns empty output when rule exists, error text when not */
		if (out && out[0] == '\0') exists = 1;
		free(out);

		if (!exists) {
			const char *a[] = {"iptables", "-t", "nat", "-A", "POSTROUTING",
					   "-o", srcintf, "-j", "MASQUERADE", NULL};
			free(safe_exec(a));
		}
		snprintf(result, rsize, "SNAT rule %s applied.", id);
	} else if (strcmp(nattype, "dnat") == 0 && dstport[0] && mapped_ip[0]) {
		char target[VALBUFSZ * 2 + 4];
		if (mapped_port[0])
			snprintf(target, sizeof(target), "%s:%s", mapped_ip, mapped_port);
		else
			snprintf(target, sizeof(target), "%s", mapped_ip);

		/* Check if rule already exists before adding */
		const char *chk[] = {"iptables", "-t", "nat", "-C", "PREROUTING",
				     "-p", "tcp", "--dport", dstport,
				     "-j", "DNAT", "--to-destination", target, NULL};
		char *out = safe_exec(chk);
		int exists = (out && out[0] == '\0');
		free(out);

		if (!exists) {
			const char *a[] = {"iptables", "-t", "nat", "-A", "PREROUTING",
					   "-p", "tcp", "--dport", dstport,
					   "-j", "DNAT", "--to-destination", target, NULL};
			free(safe_exec(a));
		}
		snprintf(result, rsize, "DNAT rule %s applied.", id);
	}
	return SG_OK;
}
