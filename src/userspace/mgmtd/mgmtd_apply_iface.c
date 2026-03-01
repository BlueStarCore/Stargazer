/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_iface.c — Apply handlers for system_settings + system_interface
 *
 * Extracted from stargazer-mgmtd.c for parallel development.
 */

#define _GNU_SOURCE
#include "mgmtd_apply.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

sg_status_t apply_settings(const char *id, const char *data,
			   char *result, size_t rsize)
{
	(void)id;
	char hostname[VALBUFSZ], ipfwd[VALBUFSZ];
	extract_val(data, "hostname", hostname, sizeof(hostname));
	extract_val(data, "ip-forward", ipfwd, sizeof(ipfwd));

	if (hostname[0]) {
		if (!sg_is_safe_id(hostname)) {
			snprintf(result, rsize, "Invalid hostname '%s'.", hostname);
			return SG_ERR_INVALID_VAL;
		}
		/* Use sethostname() syscall — no shell (VULN-09) */
		if (sethostname(hostname, strlen(hostname)) != 0) {
			snprintf(result, rsize, "sethostname failed: %s", strerror(errno));
			return SG_ERR_SYSTEM_FAIL;
		}
		FILE *fp = fopen("/etc/hostname", "w");
		if (fp) { fprintf(fp, "%s\n", hostname); fclose(fp); }
	}
	if (strcmp(ipfwd, "enable") == 0) {
		FILE *fp = fopen("/proc/sys/net/ipv4/ip_forward", "w");
		if (fp) { fprintf(fp, "1\n"); fclose(fp); }
	} else if (strcmp(ipfwd, "disable") == 0) {
		FILE *fp = fopen("/proc/sys/net/ipv4/ip_forward", "w");
		if (fp) { fprintf(fp, "0\n"); fclose(fp); }
	}

	snprintf(result, rsize, "System settings applied.");
	return SG_OK;
}

/* ── allowaccess iptables rules ──────────────────────────────────────── */

/*
 * apply_allowaccess — Create per-interface iptables chain for management
 * access control.  Each interface gets a chain "SG_IN_<iface>" with rules
 * matching the configured services (ping, ssh, https, http, snmp, telnet)
 * and a final DROP to block all other inbound management traffic.
 */
static int apply_allowaccess(const char *iface, const char *services)
{
	/* Build chain name: SG_IN_<iface> (truncated to fit iptables limit) */
	char chain[32];
	int errors = 0;
	snprintf(chain, sizeof(chain), "SG_IN_%s", iface);

	/* Create chain (ignore error if it already exists) */
	const char *cr[] = {"iptables", "-N", chain, NULL};
	free(safe_exec(cr));

	/* Flush existing rules in the chain */
	const char *fl[] = {"iptables", "-F", chain, NULL};
	if (ipt_exec(fl) != 0) {
		mgmt_log("ERROR", "allowaccess: failed to flush chain %s", chain);
		errors++;
	}

	/* Remove old jump rule from INPUT (ignore error if absent) */
	const char *dj[] = {"iptables", "-D", "INPUT",
			    "-i", iface, "-j", chain, NULL};
	free(safe_exec(dj));

	/* Add fresh jump rule in INPUT */
	const char *aj[] = {"iptables", "-A", "INPUT",
			    "-i", iface, "-j", chain, NULL};
	if (ipt_exec(aj) != 0) {
		mgmt_log("ERROR", "allowaccess: failed to add INPUT jump for %s",
			 iface);
		errors++;
	}

	/* Parse space-separated service tokens and add rules */
	if (services && services[0]) {
		/* Work on a copy since strtok modifies the string */
		char buf[VALBUFSZ];
		snprintf(buf, sizeof(buf), "%s", services);

		char *saveptr = NULL;
		for (char *tok = strtok_r(buf, " ", &saveptr);
		     tok;
		     tok = strtok_r(NULL, " ", &saveptr)) {

			if (strcmp(tok, "ping") == 0) {
				const char *a[] = {"iptables", "-A", chain,
					"-p", "icmp", "--icmp-type",
					"echo-request", "-j", "ACCEPT", NULL};
				if (ipt_exec(a) != 0) errors++;
			} else if (strcmp(tok, "ssh") == 0) {
				const char *a[] = {"iptables", "-A", chain,
					"-p", "tcp", "--dport", "22",
					"-j", "ACCEPT", NULL};
				if (ipt_exec(a) != 0) errors++;
			} else if (strcmp(tok, "https") == 0) {
				const char *a[] = {"iptables", "-A", chain,
					"-p", "tcp", "--dport", "443",
					"-j", "ACCEPT", NULL};
				if (ipt_exec(a) != 0) errors++;
			} else if (strcmp(tok, "http") == 0) {
				const char *a[] = {"iptables", "-A", chain,
					"-p", "tcp", "--dport", "80",
					"-j", "ACCEPT", NULL};
				if (ipt_exec(a) != 0) errors++;
			} else if (strcmp(tok, "snmp") == 0) {
				const char *a[] = {"iptables", "-A", chain,
					"-p", "udp", "--dport", "161",
					"-j", "ACCEPT", NULL};
				if (ipt_exec(a) != 0) errors++;
			} else if (strcmp(tok, "telnet") == 0) {
				const char *a[] = {"iptables", "-A", chain,
					"-p", "tcp", "--dport", "23",
					"-j", "ACCEPT", NULL};
				if (ipt_exec(a) != 0) errors++;
			}
		}
	}

	/* Default DROP at end of chain */
	const char *dr[] = {"iptables", "-A", chain, "-j", "DROP", NULL};
	if (ipt_exec(dr) != 0) {
		mgmt_log("ERROR", "allowaccess: failed to add default DROP for %s",
			 chain);
		errors++;
	}

	if (errors > 0)
		mgmt_log("ERROR", "allowaccess: %d iptables rule(s) failed for %s",
			 errors, iface);
	return errors == 0 ? 0 : -1;
}

sg_status_t apply_interface(const char *id, const char *data,
			    char *result, size_t rsize)
{
	char ip[VALBUFSZ], status[VALBUFSZ], mtu[VALBUFSZ], desc[VALBUFSZ];
	char allowaccess[VALBUFSZ];
	extract_val(data, "ip", ip, sizeof(ip));
	extract_val(data, "status", status, sizeof(status));
	extract_val(data, "mtu", mtu, sizeof(mtu));
	extract_val(data, "description", desc, sizeof(desc));
	extract_val(data, "allowaccess", allowaccess, sizeof(allowaccess));

	/* Validate inputs */
	if (!sg_is_iface_name(id)) {
		snprintf(result, rsize, "Invalid interface '%s'.", id);
		return SG_ERR_INVALID_VAL;
	}
	if (!iface_exists(id)) {
		snprintf(result, rsize,
			 "Interface '%s' not present, skipping.", id);
		return SG_ERR_NOT_FOUND;
	}
	if (ip[0] && !sg_is_cidr(ip)) {
		snprintf(result, rsize, "Invalid IP '%s'.", ip);
		return SG_ERR_INVALID_VAL;
	}
	if (mtu[0]) {
		int min_mtu, max_mtu;
		read_iface_mtu_limits(id, &min_mtu, &max_mtu);
		if (!sg_is_uint_range(mtu, min_mtu, max_mtu)) {
			snprintf(result, rsize,
				 "MTU '%s' out of range (%d-%d) for %s.",
				 mtu, min_mtu, max_mtu, id);
			return SG_ERR_INVALID_VAL;
		}
	}
	if (allowaccess[0] && !sg_is_access_services(allowaccess)) {
		snprintf(result, rsize,
			 "Invalid allowaccess '%s'.", allowaccess);
		return SG_ERR_INVALID_VAL;
	}

	if (ip[0]) {
		const char *a1[] = {"ip", "addr", "flush", "dev", id, NULL};
		free(safe_exec(a1));
		const char *a2[] = {"ip", "addr", "add", ip, "dev", id, NULL};
		free(safe_exec(a2));
	}
	if (strcmp(status, "up") == 0) {
		const char *a[] = {"ip", "link", "set", id, "up", NULL};
		free(safe_exec(a));
	} else if (strcmp(status, "down") == 0) {
		const char *a[] = {"ip", "link", "set", id, "down", NULL};
		free(safe_exec(a));
	}
	if (mtu[0]) {
		const char *a[] = {"ip", "link", "set", id, "mtu", mtu, NULL};
		free(safe_exec(a));
	}

	/* Apply allowaccess iptables rules */
	if (apply_allowaccess(id, allowaccess) != 0) {
		snprintf(result, rsize,
			 "Interface %s configured, but some firewall rules failed.",
			 id);
		return SG_OK;  /* non-fatal: interface is configured */
	}

	snprintf(result, rsize, "Interface %s configured.", id);
	return SG_OK;
}
