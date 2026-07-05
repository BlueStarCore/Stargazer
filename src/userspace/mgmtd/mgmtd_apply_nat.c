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
 *   -A POSTROUTING [-s srcaddr] [-d dstaddr] -o <dstintf> -j MASQUERADE
 *
 * DNAT:
 *   -A PREROUTING [-s srcaddr] [-d dstaddr] [-i srcintf]
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
 * nat_addr_is_fqdn_obj — true if `val` names a fqdn-type firewall_address.
 *
 * NAT needs a fixed IP/subnet; an fqdn object is an ipset of rotating DNS
 * answers, which has no meaning as a NAT source/destination. The apply
 * path already skips such a rule fail-closed, but that is silent — reject
 * it here (config time) so the user is told instead of finding a dead
 * port-forward later. Keywords and raw CIDRs are never fqdn objects.
 */
static int nat_addr_is_fqdn_obj(const char *val)
{
	if (is_any_or_all(val) || sg_is_cidr(val))
		return 0;
	char *data = sg_db_get("firewall_address", val);
	if (!data)
		return 0;	/* missing/dangling ref reported elsewhere */
	char atype[VALBUFSZ];
	extract_val(data, "type", atype, sizeof(atype));
	free(data);
	return strcmp(atype, "fqdn") == 0;
}

/*
 * Append optional -s/-d flags.  Same pattern as firewall rebuild
 * (mgmtd_apply_firewall.c): skip "any"/"all", validate CIDR before use.
 */
/* Returns 0 if the flag was appended (or match-all, no flag needed).
 * Returns -1 if the address object was not found (dangling ref) —
 * caller must discard the entire rule, fail-closed. */
static int append_addr_match(struct dynbuf *buf,
			     const char *flag,
			     const char *addr)
{
	char resolved[VALBUFSZ];
	const char *cidr = resolve_address(addr, resolved,
					   sizeof(resolved));
	if (cidr && strcmp(cidr, "SKIP") == 0) {
		mgmt_log("ERROR", "append_addr_match: '%s' not found, skipping rule",
			 addr);
		return -1;
	}
	if (cidr)
		dbuf_printf(buf, " %s %s", flag, cidr);
	return 0;
}

/*
 * Emit one DNAT rule line for a single protocol.
 * Called once for tcp/udp, twice for tcp+udp.
 *
 * Returns 0 on success, -1 if an address object was not found.
 * On -1 the partial rule is rolled back so the buffer stays clean.
 */
/* srcintf = incoming interface for DNAT (PREROUTING -i) */
static int emit_dnat_rule(struct dynbuf *buf,
			  const char *srcaddr, const char *dstaddr,
			  const char *srcintf, const char *proto,
			  const char *dstport,
			  const char *mapped_ip, const char *mapped_port)
{
	size_t rule_start = buf->used;

	dbuf_printf(buf, "-A PREROUTING");
	if (append_addr_match(buf, "-s", srcaddr) < 0)
		goto skip;
	if (append_addr_match(buf, "-d", dstaddr) < 0)
		goto skip;
	if (!is_any_or_all(srcintf))
		dbuf_printf(buf, " -i %s", srcintf);
	if (proto) {
		dbuf_printf(buf, " -p %s", proto);
		if (dstport[0])
			dbuf_printf(buf, " --dport %s", dstport);
	}
	/* Port translation only with a protocol: for proto=all (1:1 NAT) a
	 * ":port" target is invalid and would abort the whole nat rebuild, so
	 * emit a plain destination even if mapped_port is set on a stray
	 * entry. validate_nat rejects this combination at config time. */
	if (proto && mapped_port[0])
		dbuf_printf(buf, " -j DNAT --to-destination %s:%s\n",
			    mapped_ip, mapped_port);
	else
		dbuf_printf(buf, " -j DNAT --to-destination %s\n",
			    mapped_ip);
	return 0;

skip:
	buf->used = rule_start; /* roll back partial -A PREROUTING write */
	return -1;
}

/* ── Proxy-ARP for DNAT VIPs ─────────────────────────────────────────────────
 *
 * A DNAT rule can target a "floating" public IP (VIP) the firewall does not
 * own — e.g. WAN is 203.0.0.1/24 but the port-forward is on 203.0.0.10.
 * iptables DNAT only rewrites L3; nothing answers ARP for the VIP, so a client
 * on the srcintf segment cannot even reach it (must add a static route/ARP by
 * hand). FortiGate-style NGFWs make the box respond for the VIP. We do the
 * reliable Linux equivalent for a same-subnet VIP: assign it as a /32 secondary
 * address on the incoming interface so the box answers ARP (RTN_LOCAL). Plain
 * proxy-ARP does NOT work here — the kernel only proxies when the VIP routes out
 * a *different* device, which a same-subnet VIP does not. PREROUTING DNAT still
 * runs before the routing decision, so traffic to the VIP is forwarded, not
 * delivered locally.
 *
 * Only /32 host VIPs on a concrete srcintf are handled (a subnet dstaddr is a
 * misconfiguration — it would also make the DNAT swallow the box's own IP — and
 * is skipped). The set we assigned is tracked in /run/sg-nat-vips (tmpfs) so a
 * later rebuild removes VIPs a rule change dropped.
 */
#define NAT_VIP_STATE "/run/sg-nat-vips"

/* Returns the exit code of `ip addr <verb> <vipcidr> dev <dev>` (0 = applied). */
static int ip_addr_op(const char *verb, const char *vipcidr, const char *dev)
{
	const char *argv[] = { "ip", "addr", verb, vipcidr, "dev", dev, NULL };
	int rc = 0;
	char *out = pipe_exec_stdin(argv, "", 0, &rc);
	free(out);
	return rc;
}

static void apply_nat_vips(void)
{
	/* 1. Remove the VIPs assigned by the previous apply. */
	FILE *sf = fopen(NAT_VIP_STATE, "r");
	if (sf) {
		char line[160];
		while (fgets(line, sizeof(line), sf)) {
			char vip[64], dev[VALBUFSZ];
			if (sscanf(line, "%63s %127s", vip, dev) == 2)
				ip_addr_op("del", vip, dev);
		}
		fclose(sf);
	}

	/* 2. Assign the VIP of every enabled /32-dstaddr DNAT rule and record it. */
	FILE *nf = fopen(NAT_VIP_STATE ".tmp", "w");
	char *list = sg_db_list("network_nat");
	if (list) {
		char *sp = NULL;
		for (char *id = strtok_r(list, "\n", &sp); id;
		     id = strtok_r(NULL, "\n", &sp)) {
			char *data = sg_db_get("network_nat", id);
			if (!data)
				continue;
			char nattype[VALBUFSZ], srcintf[VALBUFSZ];
			char dstaddr[VALBUFSZ], status[VALBUFSZ];
			extract_val(data, "type",    nattype, sizeof(nattype));
			extract_val(data, "srcintf", srcintf, sizeof(srcintf));
			extract_val(data, "dstaddr", dstaddr, sizeof(dstaddr));
			extract_val(data, "status",  status,  sizeof(status));
			free(data);

			if (strcmp(nattype, "dnat") != 0)   continue;
			if (strcmp(status, "disable") == 0) continue;
			if (is_any_or_all(srcintf))         continue; /* need a real iface */

			/* dstaddr must resolve to a single host (/32 or bare IP). */
			char resolved[VALBUFSZ];
			const char *cidr = resolve_address(dstaddr, resolved,
							   sizeof(resolved));
			if (!cidr || strcmp(cidr, "SKIP") == 0)
				continue;
			const char *slash = strchr(cidr, '/');
			if (slash && strcmp(slash, "/32") != 0)
				continue;                     /* subnet dstaddr → skip */

			char vipcidr[80];
			if (slash)
				snprintf(vipcidr, sizeof(vipcidr), "%s", cidr);
			else
				snprintf(vipcidr, sizeof(vipcidr), "%s/32", cidr);

			/* Only record (for later cleanup) a VIP we actually added.
			 * If it already exists — e.g. dstaddr IS the WAN IP (a
			 * port-forward on the box's own address) — `ip addr add`
			 * fails "File exists"; we must NOT record it, or the next
			 * rebuild's `ip addr del` would strip the interface's real
			 * IP. Such a VIP already answers ARP, so nothing to do. */
			if (ip_addr_op("add", vipcidr, srcintf) == 0) {
				if (nf)
					fprintf(nf, "%s %s\n", vipcidr, srcintf);
				mgmt_log("INFO", "nat: VIP %s bound on %s for DNAT "
					 "reachability", vipcidr, srcintf);
			}
		}
		free(list);
	}
	if (nf)
		fclose(nf);
	rename(NAT_VIP_STATE ".tmp", NAT_VIP_STATE);
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
				size_t snat_start = buf.used;
				dbuf_printf(&buf, "-A POSTROUTING");
				if (append_addr_match(&buf, "-s", srcaddr) < 0 ||
				    append_addr_match(&buf, "-d", dstaddr) < 0) {
					buf.used = snat_start; /* roll back partial write */
					continue;
				}
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
					if (emit_dnat_rule(&buf, srcaddr, dstaddr,
							   srcintf, "tcp",
							   dstport,
							   mapped_ip, mapped_port) == 0)
						dnat_count++;
					if (emit_dnat_rule(&buf, srcaddr, dstaddr,
							   srcintf, "udp",
							   dstport,
							   mapped_ip, mapped_port) == 0)
						dnat_count++;
				} else if (strcmp(protocol, "all") == 0) {
					/* No -p flag, match all protocols
					 * (1:1 NAT — dstport ignored) */
					if (emit_dnat_rule(&buf, srcaddr, dstaddr,
							   srcintf, NULL,
							   dstport,
							   mapped_ip, mapped_port) == 0)
						dnat_count++;
				} else {
					/* tcp or udp */
					if (emit_dnat_rule(&buf, srcaddr, dstaddr,
							   srcintf, protocol,
							   dstport,
							   mapped_ip, mapped_port) == 0)
						dnat_count++;
				}
				continue;
			}
		}
		free(list);
	}

	/* SSL inspection: REDIRECT forwarded HTTPS into stargazer-ssld.
	 * Emitted into the same *nat restore so the table stays atomic.
	 * No-op if no accept policy binds an enabled ssl-inspection-profile. */
	emit_ssl_steering(&buf);

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

	/* DNAT VIPs → bind as /32 secondary IPs so the box answers ARP for a
	 * floating public IP that the port-forward targets (route-mode DNAT). */
	apply_nat_vips();

	/* Steering applied → sync the ssld lifecycle (start/stop/restart per
	 * security_ssl-inspection-profile). Placed AFTER restore so ssld is
	 * listening as soon as the rules exist. */
	ssld_sync();

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
	    !sg_is_cidr(srcaddr) && !sg_is_safe_id(srcaddr)) {
		snprintf(result, rsize, "Invalid srcaddr '%s'", srcaddr);
		return SG_ERR_INVALID_VAL;
	}
	if (dstaddr[0] && !is_any_or_all(dstaddr) &&
	    !sg_is_cidr(dstaddr) && !sg_is_safe_id(dstaddr)) {
		snprintf(result, rsize, "Invalid dstaddr '%s'", dstaddr);
		return SG_ERR_INVALID_VAL;
	}
	if (nat_addr_is_fqdn_obj(srcaddr)) {
		snprintf(result, rsize,
			 "NAT cannot use fqdn address object '%s' — use an "
			 "IP/subnet (fqdn objects are for firewall policy)",
			 srcaddr);
		return SG_ERR_INVALID_VAL;
	}
	if (nat_addr_is_fqdn_obj(dstaddr)) {
		snprintf(result, rsize,
			 "NAT cannot use fqdn address object '%s' — use an "
			 "IP/subnet (fqdn objects are for firewall policy)",
			 dstaddr);
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
	/* Cross-field: port translation needs a protocol. protocol=all with a
	 * mapped-port would emit "--to-destination IP:PORT" without -p, which
	 * iptables rejects — failing the whole atomic nat rebuild. Reject it
	 * here (and emit_dnat_rule drops the port for proto=all defensively). */
	if (mapped_port[0] && protocol[0] && strcmp(protocol, "all") == 0) {
		snprintf(result, rsize,
			 "mapped-port requires protocol tcp, udp, or tcp+udp");
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
