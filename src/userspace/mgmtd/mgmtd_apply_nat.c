/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_nat.c — Atomic NAT chain rebuild
 *
 * On any network_nat change, both PREROUTING (DNAT) and POSTROUTING
 * (SNAT) chains are rebuilt from the DB and loaded atomically via
 * iptables-restore --noflush.
 *
 * Higher sequence = higher priority = earlier in the chain.
 * Disabled entries are skipped.
 *
 * SNAT (overload):
 *   -A POSTROUTING [-s srcaddr] [-d dstaddr] -o <srcintf> -j MASQUERADE
 *
 * DNAT:
 *   -A PREROUTING [-s srcaddr] [-d dstaddr] [-i dstintf]
 *       [-p proto [--dport port]] -j DNAT --to-destination ip[:port]
 *
 * protocol=tcp+udp generates two separate rules (one per protocol),
 * matching OpenWrt fw3 / Shorewall behavior.
 */

#include "mgmtd_apply.h"
#include "mgmtd_dynbuf.h"
#include "sg_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Helpers ────────────────────────────────────────────────────────────── */

static int is_any_or_all(const char *val)
{
	return !val[0] ||
	       strcmp(val, "any") == 0 ||
	       strcmp(val, "all") == 0;
}

/*
 * Append optional -s/-d flags.  Same pattern as firewall rebuild
 * (mgmtd_apply_firewall.c): skip "any"/"all", validate CIDR before use.
 */
static void append_addr_match(struct dynbuf *buf,
			      const char *flag,
			      const char *addr)
{
	if (!is_any_or_all(addr) && sg_is_cidr(addr))
		dbuf_printf(buf, " %s %s", flag, addr);
}

/*
 * Emit one DNAT rule line for a single protocol.
 * Called once for tcp/udp, twice for tcp+udp.
 */
/* srcintf = incoming interface for DNAT (PREROUTING -i) */
static void emit_dnat_rule(struct dynbuf *buf,
			   const char *srcaddr, const char *dstaddr,
			   const char *srcintf, const char *proto,
			   const char *dstport,
			   const char *mapped_ip, const char *mapped_port)
{
	dbuf_printf(buf, "-A PREROUTING");
	append_addr_match(buf, "-s", srcaddr);
	append_addr_match(buf, "-d", dstaddr);
	if (!is_any_or_all(srcintf))
		dbuf_printf(buf, " -i %s", srcintf);
	if (proto) {
		dbuf_printf(buf, " -p %s", proto);
		if (dstport[0])
			dbuf_printf(buf, " --dport %s", dstport);
	}
	if (mapped_port[0])
		dbuf_printf(buf, " -j DNAT --to-destination %s:%s\n",
			    mapped_ip, mapped_port);
	else
		dbuf_printf(buf, " -j DNAT --to-destination %s\n",
			    mapped_ip);
}

/* ── Rebuild ─────────────────────────────────────────────────────────────── */

sg_status_t rebuild_nat_chains(char *result, size_t rsize)
{
	struct dynbuf buf;
	if (dbuf_init(&buf, 4096) < 0) {
		snprintf(result, rsize, "Out of memory");
		return SG_ERR_SYSTEM_FAIL;
	}

	dbuf_append(&buf, "*nat\n", 5);

	/* Read all NAT entries ordered by sequence DESC (highest first) */
	char *list = sg_db_list_ordered("network_nat", "sequence");
	int snat_count = 0, dnat_count = 0;

	if (list) {
		char *saveptr = NULL;
		for (char *id = strtok_r(list, "\n", &saveptr);
		     id;
		     id = strtok_r(NULL, "\n", &saveptr)) {

			char *data = sg_db_get("network_nat", id);
			if (!data)
				continue;

			char nattype[VALBUFSZ], srcintf[VALBUFSZ];
			char dstintf[VALBUFSZ], protocol[VALBUFSZ];
			char srcaddr[VALBUFSZ], dstaddr[VALBUFSZ];
			char dstport[VALBUFSZ], mapped_ip[VALBUFSZ];
			char mapped_port[VALBUFSZ], status[VALBUFSZ];

			extract_val(data, "type",        nattype,     sizeof(nattype));
			extract_val(data, "srcintf",     srcintf,     sizeof(srcintf));
			extract_val(data, "dstintf",     dstintf,     sizeof(dstintf));
			extract_val(data, "protocol",    protocol,    sizeof(protocol));
			extract_val(data, "srcaddr",     srcaddr,     sizeof(srcaddr));
			extract_val(data, "dstaddr",     dstaddr,     sizeof(dstaddr));
			extract_val(data, "dstport",     dstport,     sizeof(dstport));
			extract_val(data, "mapped-ip",   mapped_ip,   sizeof(mapped_ip));
			extract_val(data, "mapped-port", mapped_port, sizeof(mapped_port));
			extract_val(data, "status",      status,      sizeof(status));

			free(data);

			if (strcmp(status, "disable") == 0)
				continue;

			/* Backward compat: old entries without protocol */
			if (!protocol[0])
				snprintf(protocol, sizeof(protocol), "all");

			/* ── SNAT (overload / MASQUERADE) ───────────── */
			/* dstintf = outgoing interface → -o (POSTROUTING)
			 * srcintf not usable in POSTROUTING (-i ignored) */
			if (strcmp(nattype, "snat") == 0 &&
			    !is_any_or_all(dstintf)) {
				dbuf_printf(&buf, "-A POSTROUTING");
				append_addr_match(&buf, "-s", srcaddr);
				append_addr_match(&buf, "-d", dstaddr);
				dbuf_printf(&buf, " -o %s", dstintf);
				dbuf_printf(&buf, " -j MASQUERADE\n");
				snat_count++;
				continue;
			}

			/* ── DNAT ───────────────────────────────────── */
			/* srcintf = incoming interface → -i (PREROUTING) */
			if (strcmp(nattype, "dnat") == 0 && mapped_ip[0]) {
				if (strcmp(protocol, "tcp+udp") == 0) {
					/* Two separate rules (OpenWrt pattern) */
					emit_dnat_rule(&buf, srcaddr, dstaddr,
						       srcintf, "tcp",
						       dstport,
						       mapped_ip, mapped_port);
					emit_dnat_rule(&buf, srcaddr, dstaddr,
						       srcintf, "udp",
						       dstport,
						       mapped_ip, mapped_port);
					dnat_count += 2;
				} else if (strcmp(protocol, "all") == 0) {
					/* No -p flag, match all protocols
					 * (1:1 NAT — dstport ignored) */
					emit_dnat_rule(&buf, srcaddr, dstaddr,
						       srcintf, NULL,
						       dstport,
						       mapped_ip, mapped_port);
					dnat_count++;
				} else {
					/* tcp or udp */
					emit_dnat_rule(&buf, srcaddr, dstaddr,
						       srcintf, protocol,
						       dstport,
						       mapped_ip, mapped_port);
					dnat_count++;
				}
				continue;
			}
		}
		free(list);
	}

	dbuf_append(&buf, "COMMIT\n", 7);

	/* Flush both NAT chains.  During this window, no NAT translation
	 * happens — traffic passes un-translated (not dropped). */
	flush_nat_rules();

	/* Atomic restore */
	const char *restore[] = {"iptables-restore", "--noflush", NULL};
	int exit_code = 0;
	char *out = pipe_exec_stdin(restore, buf.data, buf.used, &exit_code);

	if (exit_code != 0) {
		mgmt_log("ERROR", "rebuild_nat_chains: iptables-restore "
			 "failed (exit %d): %s", exit_code,
			 out ? out : "");
		free(out);
		free(buf.data);
		snprintf(result, rsize, "NAT chain rebuild failed");
		return SG_ERR_SYSTEM_FAIL;
	}

	free(out);
	free(buf.data);

	snprintf(result, rsize, "NAT chains rebuilt (%d SNAT, %d DNAT)",
		 snat_count, dnat_count);
	return SG_OK;
}

/* ── Validation ─────────────────────────────────────────────────────────── */

sg_status_t validate_nat(const char *id, const char *data,
			 char *result, size_t rsize)
{
	char srcintf[VALBUFSZ], dstintf[VALBUFSZ];
	char srcaddr[VALBUFSZ], dstaddr[VALBUFSZ];
	char protocol[VALBUFSZ], dstport[VALBUFSZ];
	char mapped_ip[VALBUFSZ], mapped_port[VALBUFSZ];

	extract_val(data, "srcintf",     srcintf,     sizeof(srcintf));
	extract_val(data, "dstintf",     dstintf,     sizeof(dstintf));
	extract_val(data, "srcaddr",     srcaddr,     sizeof(srcaddr));
	extract_val(data, "dstaddr",     dstaddr,     sizeof(dstaddr));
	extract_val(data, "protocol",    protocol,    sizeof(protocol));
	extract_val(data, "dstport",     dstport,     sizeof(dstport));
	extract_val(data, "mapped-ip",   mapped_ip,   sizeof(mapped_ip));
	extract_val(data, "mapped-port", mapped_port, sizeof(mapped_port));

	if (srcintf[0] && !is_any_or_all(srcintf) &&
	    !sg_is_iface_name(srcintf)) {
		snprintf(result, rsize, "Invalid srcintf '%s'", srcintf);
		return SG_ERR_INVALID_VAL;
	}
	if (dstintf[0] && !is_any_or_all(dstintf) &&
	    !sg_is_iface_name(dstintf)) {
		snprintf(result, rsize, "Invalid dstintf '%s'", dstintf);
		return SG_ERR_INVALID_VAL;
	}
	if (srcaddr[0] && !is_any_or_all(srcaddr) &&
	    !sg_is_cidr(srcaddr)) {
		snprintf(result, rsize, "Invalid srcaddr '%s'", srcaddr);
		return SG_ERR_INVALID_VAL;
	}
	if (dstaddr[0] && !is_any_or_all(dstaddr) &&
	    !sg_is_cidr(dstaddr)) {
		snprintf(result, rsize, "Invalid dstaddr '%s'", dstaddr);
		return SG_ERR_INVALID_VAL;
	}
	if (mapped_ip[0] && !sg_is_ipv4(mapped_ip)) {
		snprintf(result, rsize, "Invalid mapped-ip '%s'", mapped_ip);
		return SG_ERR_INVALID_VAL;
	}
	if (dstport[0] && !sg_is_uint_range(dstport, 1, 65535)) {
		snprintf(result, rsize, "Invalid dstport '%s'", dstport);
		return SG_ERR_INVALID_VAL;
	}
	if (mapped_port[0] && !sg_is_uint_range(mapped_port, 1, 65535)) {
		snprintf(result, rsize, "Invalid mapped-port '%s'", mapped_port);
		return SG_ERR_INVALID_VAL;
	}

	/* Cross-field: --dport requires -p tcp or -p udp */
	if (dstport[0] && protocol[0] && strcmp(protocol, "all") == 0) {
		snprintf(result, rsize,
			 "dstport requires protocol tcp, udp, or tcp+udp");
		return SG_ERR_INVALID_VAL;
	}

	/* Type-specific required fields */
	char nattype[VALBUFSZ];
	extract_val(data, "type", nattype, sizeof(nattype));

	if (strcmp(nattype, "snat") == 0 && is_any_or_all(dstintf)) {
		snprintf(result, rsize,
			 "SNAT requires a real outgoing interface (dstintf)");
		return SG_ERR_MISSING_ARG;
	}
	if (strcmp(nattype, "dnat") == 0 && !mapped_ip[0]) {
		snprintf(result, rsize,
			 "DNAT requires mapped-ip (destination address)");
		return SG_ERR_MISSING_ARG;
	}

	snprintf(result, rsize, "NAT %s validated", id);
	return SG_OK;
}
