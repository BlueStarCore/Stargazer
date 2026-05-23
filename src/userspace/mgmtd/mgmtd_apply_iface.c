/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_iface.c — Apply handlers for system_settings + system_interface
 *
 * Extracted from stargazer-mgmtd.c for parallel development.
 */

#define _GNU_SOURCE
#include "mgmtd_apply.h"
#include "mgmtd_internal.h"
#include "sg_db.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* IFF_LOWER_UP (0x10000) is in <linux/if.h>, which conflicts with <net/if.h>
 * on glibc systems.  Define it directly — it is a stable kernel ABI constant. */
#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000
#endif

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

/* ── udhcpc lifecycle (via supervisor) ──────────────────────────────── */

/*
 * Kill any orphan udhcpc processes for this interface by scanning /proc.
 * Called before starting a new supervised instance to ensure clean state.
 * Orphans arise when mgmtd is restarted without a clean shutdown.
 */
static void dhcpc_kill_orphans(const char *iface)
{
	DIR *pd = opendir("/proc");
	if (!pd)
		return;

	struct dirent *pe;
	while ((pe = readdir(pd)) != NULL) {
		/* Only numeric entries are PIDs */
		if (pe->d_name[0] < '1' || pe->d_name[0] > '9')
			continue;

		char cmdpath[280];
		snprintf(cmdpath, sizeof(cmdpath), "/proc/%s/cmdline",
			 pe->d_name);
		int fd = open(cmdpath, O_RDONLY);
		if (fd < 0)
			continue;

		/* Read cmdline (NUL-separated argv) */
		char buf[512];
		ssize_t n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n <= 0)
			continue;
		buf[n] = '\0';

		/* Check: argv[0] contains "udhcpc" */
		if (!strstr(buf, "udhcpc"))
			continue;

		/* Scan remaining args for "-i <iface>" */
		int found_i = 0;
		for (ssize_t i = 0; i < n; ) {
			const char *arg = buf + i;
			size_t alen = strlen(arg);
			if (strcmp(arg, "-i") == 0)
				found_i = 1;
			else if (found_i && strcmp(arg, iface) == 0) {
				pid_t pid = (pid_t)atoi(pe->d_name);
				kill(pid, SIGTERM);
				mgmt_log("INFO",
					 "dhcpc_stop: killed orphan udhcpc"
					 " pid %d on %s", (int)pid, iface);
				break;
			} else {
				found_i = 0;
			}
			i += (ssize_t)alen + 1;
			if (i >= n) break;
		}
	}
	closedir(pd);
}

/* Stop udhcpc for this interface: supervisor + any orphans */
static void dhcpc_stop(const char *iface)
{
	char name[80];
	snprintf(name, sizeof(name), "udhcpc.%s", iface);
	supervisor_stop(name);
	dhcpc_kill_orphans(iface);
}

/*
 * Start a supervised udhcpc for this interface.
 *
 * Uses -f (foreground) instead of -b: mgmtd is the direct parent,
 * SIGCHLD gives instant crash detection + automatic restart.
 * The supervisor handles fd safety, signal reset, and setsid.
 */
static void dhcpc_start(const char *iface)
{
	char name[80];
	snprintf(name, sizeof(name), "udhcpc.%s", iface);
	const char *argv[] = {
		"/sbin/udhcpc", "-i", iface,
		"-f",           /* foreground — mgmtd is direct parent   */
		"-t", "0",      /* unlimited DISCOVER retries (no exit)  */
		"-T", "3",      /* 3s per-packet timeout                 */
		"-A", "20",     /* 20s between retry rounds              */
		"-s", "/usr/share/udhcpc/default.script",
		NULL
	};
	supervisor_start(name, argv, SRC_CONFIG,
			 "system_interface", iface, "mode", "dhcp");
}

/*
 * Check if any enabled DHCP server pool is bound to this interface.
 * Returns 1 if a conflict exists, 0 if clear.
 */
static int
iface_has_dhcpd_pool(const char *iface)
{
	char *list = sg_db_list("network_dhcp-server");
	if (!list)
		return 0;

	int found = 0;
	char *saveptr = NULL;
	char *tok = strtok_r(list, "\n", &saveptr);
	while (tok) {
		char *pool_iface = sg_db_get_val("network_dhcp-server",
						 tok, "interface");
		if (pool_iface) {
			if (strcmp(pool_iface, iface) == 0) {
				char *pool_status = sg_db_get_val(
					"network_dhcp-server",
					tok, "status");
				/* Schema default for status is "enable",
				 * so NULL (no explicit key) = enabled */
				if (!pool_status ||
				    strcmp(pool_status, "enable") == 0)
					found = 1;
				free(pool_status);
			}
			free(pool_iface);
		}
		if (found)
			break;
		tok = strtok_r(NULL, "\n", &saveptr);
	}
	free(list);
	return found;
}

sg_status_t apply_interface(const char *id, const char *data,
			    char *result, size_t rsize)
{
	char mode[VALBUFSZ], ip[VALBUFSZ], status[VALBUFSZ];
	char mtu[VALBUFSZ], desc[VALBUFSZ], allowaccess[VALBUFSZ];
	char sys_flag[VALBUFSZ];
	extract_val(data, "mode", mode, sizeof(mode));
	extract_val(data, "ip", ip, sizeof(ip));
	extract_val(data, "status", status, sizeof(status));
	extract_val(data, "mtu", mtu, sizeof(mtu));
	extract_val(data, "description", desc, sizeof(desc));
	extract_val(data, "allowaccess", allowaccess, sizeof(allowaccess));
	extract_val(data, "system", sys_flag, sizeof(sys_flag));

	/* Default mode to static if not set */
	if (!mode[0])
		snprintf(mode, sizeof(mode), "static");

	/* Only "static" and "dhcp" are valid modes */
	if (strcmp(mode, "static") != 0 && strcmp(mode, "dhcp") != 0) {
		snprintf(result, rsize, "Invalid mode '%s' (use static or dhcp).",
			 mode);
		return SG_ERR_INVALID_VAL;
	}

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
	/* 0.0.0.0/0 is the sentinel "no IP assigned" for static interfaces.
	 * Normalise it to empty so the ip addr add step is skipped below. */
	if (strcmp(ip, "0.0.0.0/0") == 0)
		ip[0] = '\0';

	if (strcmp(mode, "static") == 0 && ip[0] && !sg_is_cidr(ip)) {
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

	/* Reject DHCP client mode if an active DHCP server pool exists
	 * on this interface — cannot be both client and server. */
	if (strcmp(mode, "dhcp") == 0 && iface_has_dhcpd_pool(id)) {
		snprintf(result, rsize,
			 "Interface %s has active DHCP server pool.", id);
		return SG_ERR_IN_USE;
	}

	/* Always stop existing udhcpc first — mode may have changed */
	dhcpc_stop(id);

	/* Link state.
	 * DSA master interfaces (system=yes) must never go admin-down:
	 * bringing the master down makes all slave ports lowerlayerdown,
	 * causing the kernel operstate to diverge from the configured state
	 * of every downstream port.  Always force them admin-up. */
	if (strcmp(sys_flag, "yes") == 0) {
		const char *a[] = {"ip", "link", "set", id, "up", NULL};
		char *out = safe_exec(a);
		if (out && out[0])
			mgmt_log("WARN", "ip link set %s up (system iface): %s",
				 id, out);
		free(out);
	} else if (strcmp(status, "up") == 0) {
		const char *a[] = {"ip", "link", "set", id, "up", NULL};
		char *out = safe_exec(a);
		if (out && out[0])
			mgmt_log("ERROR", "ip link set %s up: %s", id, out);
		free(out);
	} else if (strcmp(status, "down") == 0) {
		const char *a[] = {"ip", "link", "set", id, "down", NULL};
		free(safe_exec(a));
	}

	/* MTU */
	if (mtu[0]) {
		const char *a[] = {"ip", "link", "set", id, "mtu", mtu, NULL};
		char *out = safe_exec(a);
		if (out && out[0]) {
			snprintf(result, rsize,
				 "MTU %s failed on %s: %s", mtu, id, out);
			free(out);
			return SG_ERR_SYSTEM_FAIL;
		}
		free(out);
	}

	/* Address: DHCP or static
	 * For static mode, try adding new IP before flushing to minimize
	 * connection drop on management interface changes. */
	if (strcmp(mode, "dhcp") == 0) {
		/* Flush any static IP before starting DHCP */
		const char *a1[] = {"ip", "addr", "flush", "dev", id, NULL};
		free(safe_exec(a1));
	} else {
		/* Static mode: flush then assign.  Flush first avoids stale
		 * addresses surviving a mode change; a brief IP-less window
		 * is acceptable since the firewall is already enforcing policy. */
		const char *a_flush[] = {"ip", "addr", "flush", "dev", id, NULL};
		free(safe_exec(a_flush));
		if (ip[0]) {
			const char *a_add[] = {"ip", "addr", "add", ip,
					       "dev", id, NULL};
			char *out = safe_exec(a_add);
			if (out && out[0]) {
				snprintf(result, rsize,
					 "IP %s failed on %s: %s", ip, id, out);
				free(out);
				return SG_ERR_SYSTEM_FAIL;
			}
			free(out);
		}
	}

	/* Apply allowaccess iptables rules */
	if (apply_allowaccess(id, allowaccess) != 0) {
		snprintf(result, rsize,
			 "Firewall access rules failed for %s.", id);
		return SG_ERR_SYSTEM_FAIL;
	}

	/* DHCP replies (router UDP/67 → client UDP/68) arrive as INPUT on
	 * this interface and would be dropped by the allowaccess chain's
	 * default DROP.  Insert an explicit ACCEPT before that DROP so
	 * udhcpc can receive OFFER/ACK packets.
	 *
	 * udhcpc is started AFTER this rule is in place — eliminates the
	 * race where a fast OFFER/ACK could arrive while the chain still
	 * has only the default DROP. */
	if (strcmp(mode, "dhcp") == 0) {
		char dhcp_chain[32];
		snprintf(dhcp_chain, sizeof(dhcp_chain), "SG_IN_%s", id);
		const char *dhcp_rule[] = {
			"iptables", "-I", dhcp_chain, "1",
			"-p", "udp", "--sport", "67", "--dport", "68",
			"-j", "ACCEPT", NULL
		};
		if (ipt_exec(dhcp_rule) != 0)
			mgmt_log("ERROR",
				 "apply_interface: DHCP ACCEPT rule failed for %s"
				 " — udhcpc replies will be dropped", id);

		/* Start udhcpc now that the ACCEPT rule is installed */
		if (strcmp(status, "down") != 0)
			dhcpc_start(id);
	}

	/* Signal webd to rebind listeners (allowaccess may have changed).
	 * Best-effort: if webd isn't running yet (boot), this is a no-op. */
	{
		pid_t wpid = supervisor_get_pid("webd");
		if (wpid > 0)
			kill(wpid, SIGHUP);
	}

	snprintf(result, rsize, "Interface %s configured (%s).", id, mode);
	return SG_OK;
}

/* Write a single value to a sysfs module parameter file. Returns 0 on success. */
static int write_sysfs_param(const char *module, const char *param,
			     const char *val)
{
	char path[160];
	snprintf(path, sizeof(path),
		 "/sys/module/%s/parameters/%s", module, param);
	FILE *fp = fopen(path, "w");
	if (!fp)
		return -1;
	fprintf(fp, "%s\n", val);
	fclose(fp);
	return 0;
}

/*
 * Read the current protected_ifmask, set or clear bit for ifindex, write back.
 * Safe to call concurrently only if the caller serialises — mgmtd is
 * single-threaded so the read-modify-write is not subject to a TOCTOU race.
 * Returns 0 on success, -1 if ifindex is out of range.
 */
static int update_protected_ifmask(unsigned int ifindex, int set)
{
	/* unsigned long is 64 bits on ARM64; shifting by >= 64 is undefined. */
	if (ifindex >= (unsigned int)(sizeof(unsigned long) * 8)) {
		mgmt_log("ERROR",
			 "update_protected_ifmask: ifindex %u exceeds bitmask width",
			 ifindex);
		return -1;
	}
	unsigned long mask = 0;
	FILE *fp = fopen("/sys/module/pkt_forward/parameters/protected_ifmask", "r");
	if (fp) {
		fscanf(fp, "%lu", &mask);
		fclose(fp);
	}
	if (set)
		mask |=  (1UL << ifindex);
	else
		mask &= ~(1UL << ifindex);
	char val[32];
	snprintf(val, sizeof(val), "%lu", mask);
	write_sysfs_param("pkt_forward", "protected_ifmask", val);
	return 0;
}

sg_status_t apply_dos_policy(const char *id, const char *data,
			     char *result, size_t rsize)
{
	char iface[VALBUFSZ], status[VALBUFSZ];
	char syn_thr[VALBUFSZ],  syn_burst[VALBUFSZ];
	char udp_thr[VALBUFSZ],  udp_burst[VALBUFSZ];
	char icmp_thr[VALBUFSZ], icmp_burst[VALBUFSZ];
	char block_dur[VALBUFSZ];
	char halfopen_src[VALBUFSZ];
	char gsyn_thr[VALBUFSZ],  gsyn_burst[VALBUFSZ];
	char gudp_thr[VALBUFSZ],  gudp_burst[VALBUFSZ];
	char anti_spoof[VALBUFSZ];
	char per_src_limit[VALBUFSZ];
	char adaptive_to[VALBUFSZ];
	char zero_win[VALBUFSZ];
	char pkt_thr[VALBUFSZ],  pkt_burst[VALBUFSZ];
	char icmp_err_thr[VALBUFSZ], icmp_err_burst[VALBUFSZ];
	char scan_thr[VALBUFSZ], scan_win[VALBUFSZ];

	extract_val(data, "interface",             iface,          sizeof(iface));
	extract_val(data, "status",                status,         sizeof(status));
	extract_val(data, "syn-flood-threshold",   syn_thr,        sizeof(syn_thr));
	extract_val(data, "syn-flood-burst",       syn_burst,      sizeof(syn_burst));
	extract_val(data, "udp-flood-threshold",   udp_thr,        sizeof(udp_thr));
	extract_val(data, "udp-flood-burst",       udp_burst,      sizeof(udp_burst));
	extract_val(data, "icmp-flood-threshold",  icmp_thr,       sizeof(icmp_thr));
	extract_val(data, "icmp-flood-burst",      icmp_burst,     sizeof(icmp_burst));
	extract_val(data, "block-duration",        block_dur,      sizeof(block_dur));
	extract_val(data, "halfopen-per-src",      halfopen_src,   sizeof(halfopen_src));
	extract_val(data, "global-syn-threshold",  gsyn_thr,       sizeof(gsyn_thr));
	extract_val(data, "global-syn-burst",      gsyn_burst,     sizeof(gsyn_burst));
	extract_val(data, "global-udp-threshold",  gudp_thr,       sizeof(gudp_thr));
	extract_val(data, "global-udp-burst",      gudp_burst,     sizeof(gudp_burst));
	extract_val(data, "anti-spoofing",         anti_spoof,     sizeof(anti_spoof));
	extract_val(data, "per-src-session-limit", per_src_limit,  sizeof(per_src_limit));
	extract_val(data, "adaptive-timeout",      adaptive_to,    sizeof(adaptive_to));
	extract_val(data, "zero-window-timeout",   zero_win,       sizeof(zero_win));
	extract_val(data, "pkt-rate-threshold",    pkt_thr,        sizeof(pkt_thr));
	extract_val(data, "pkt-rate-burst",        pkt_burst,      sizeof(pkt_burst));
	extract_val(data, "icmp-err-threshold",    icmp_err_thr,   sizeof(icmp_err_thr));
	extract_val(data, "icmp-err-burst",        icmp_err_burst, sizeof(icmp_err_burst));
	extract_val(data, "scan-threshold",        scan_thr,       sizeof(scan_thr));
	extract_val(data, "scan-window",           scan_win,       sizeof(scan_win));

	if (!iface[0]) {
		snprintf(result, rsize, "'interface' not set.");
		return SG_ERR_MISSING_ARG;
	}
	if (!sg_is_iface_name(iface)) {
		snprintf(result, rsize, "Invalid interface '%s'.", iface);
		return SG_ERR_INVALID_VAL;
	}

	/* Remove any existing rpfilter rule for this interface before re-applying */
	const char *rpf_del[] = {
		"iptables", "-t", "raw", "-D", "PREROUTING",
		"-i", iface, "-m", "rpfilter", "--invert", "-j", "DROP", NULL
	};
	free(safe_exec(rpf_del));  /* ignore error — rule may not exist */

	/* Disabled: clear this interface's bit from the protected mask. */
	if (strcmp(status, "disable") == 0) {
		char dis_path[256];
		unsigned int dis_idx = 0;
		snprintf(dis_path, sizeof(dis_path),
			 "/sys/class/net/%s/ifindex", iface);
		FILE *dis_fp = fopen(dis_path, "r");
		if (!dis_fp) {
			/*
			 * Interface no longer exists — cannot determine the ifindex,
			 * so the protection bit cannot be cleared from the kernel mask.
			 * Report the problem; operator must reload the module or
			 * re-enable then disable the policy once the interface exists.
			 */
			mgmt_log("WARN",
				 "DoS policy '%s': interface '%s' not found; "
				 "kernel protection bit may remain set.", id, iface);
			snprintf(result, rsize,
				 "Warning: interface '%s' not found; "
				 "kernel protection bit may remain set.", iface);
			return SG_ERR_NOT_FOUND;
		}
		fscanf(dis_fp, "%u", &dis_idx);
		fclose(dis_fp);
		update_protected_ifmask(dis_idx, 0);
		/*
		 * Reset session.ko caps only when no interface remains protected.
		 * These caps are global (not per-interface); with multiple policies
		 * active the most-recently-applied value is in effect.
		 */
		unsigned long remaining = 0;
		FILE *mfp = fopen(
			"/sys/module/pkt_forward/parameters/protected_ifmask", "r");
		if (mfp) { fscanf(mfp, "%lu", &remaining); fclose(mfp); }
		if (remaining == 0) {
			write_sysfs_param("session", "max_est_per_src",  "0");
			write_sysfs_param("session", "zero_win_timeout", "0");
		}
		snprintf(result, rsize, "DoS policy '%s' disabled.", id);
		return SG_OK;
	}

	/* Resolve interface index */
	char ifindex_path[256];
	snprintf(ifindex_path, sizeof(ifindex_path),
		 "/sys/class/net/%s/ifindex", iface);
	FILE *ifp = fopen(ifindex_path, "r");
	if (!ifp) {
		snprintf(result, rsize,
			 "DoS policy '%s': interface '%s' not present.", id, iface);
		return SG_ERR_NOT_FOUND;
	}
	char ifindex_str[16] = "0";
	if (fgets(ifindex_str, sizeof(ifindex_str), ifp))
		ifindex_str[strcspn(ifindex_str, "\n")] = '\0';
	fclose(ifp);

	/* Set this interface's bit in the protected mask. */
	unsigned int this_ifindex = (unsigned int)strtoul(ifindex_str, NULL, 10);
	if (update_protected_ifmask(this_ifindex, 1) != 0) {
		snprintf(result, rsize,
			 "DoS policy '%s': ifindex %u exceeds bitmask width; "
			 "too many interfaces.", id, this_ifindex);
		return SG_ERR_INVALID_VAL;
	}

	/* Write pkt_forward.ko module params via sysfs */
	struct { const char *param; const char *val; } pf_params[] = {
		{ "syn_flood_thr",        syn_thr[0]       ? syn_thr       : "200"   },
		{ "syn_flood_burst",      syn_burst[0]     ? syn_burst     : "400"   },
		{ "udp_flood_thr",        udp_thr[0]       ? udp_thr       : "1000"  },
		{ "udp_flood_burst",      udp_burst[0]     ? udp_burst     : "2000"  },
		{ "icmp_flood_thr",       icmp_thr[0]      ? icmp_thr      : "100"   },
		{ "icmp_flood_burst",     icmp_burst[0]    ? icmp_burst    : "200"   },
		{ "src_block_dur",        block_dur[0]     ? block_dur     : "30"    },
		{ "max_halfopen_per_src", halfopen_src[0]  ? halfopen_src  : "10"    },
		{ "global_syn_thr",       gsyn_thr[0]      ? gsyn_thr      : "5000"  },
		{ "global_syn_burst",     gsyn_burst[0]    ? gsyn_burst    : "10000" },
		{ "global_udp_thr",       gudp_thr[0]      ? gudp_thr      : "5000"  },
		{ "global_udp_burst",     gudp_burst[0]    ? gudp_burst    : "10000" },
		{ "pkt_flood_thr",        pkt_thr[0]       ? pkt_thr       : "10000" },
		{ "pkt_flood_burst",      pkt_burst[0]     ? pkt_burst     : "20000" },
		{ "icmp_err_thr",         icmp_err_thr[0]  ? icmp_err_thr  : "50"    },
		{ "icmp_err_burst",       icmp_err_burst[0]? icmp_err_burst: "100"   },
		{ "scan_threshold",       scan_thr[0]      ? scan_thr      : "20"    },
		{ "scan_window",          scan_win[0]      ? scan_win      : "10"    },
		{ NULL, NULL }
	};

	int written = 0, total = 0;
	for (int i = 0; pf_params[i].param; i++) {
		total++;
		if (write_sysfs_param("pkt_forward", pf_params[i].param,
				      pf_params[i].val) == 0)
			written++;
	}

	/* Write session.ko module params via sysfs */
	if (per_src_limit[0])
		write_sysfs_param("session", "max_est_per_src", per_src_limit);
	if (zero_win[0])
		write_sysfs_param("session", "zero_win_timeout", zero_win);

	/* Adaptive timeout: read the actual pf_max_states from sysfs so the
	 * computed thresholds are correct regardless of the configured table size. */
	if (strcmp(adaptive_to, "disable") == 0 ||
	    strcmp(adaptive_to, "enable")  == 0) {
		unsigned int max_states = 65536;
		FILE *mfp = fopen("/sys/module/session/parameters/pf_max_states", "r");
		if (mfp) {
			char ms_buf[16];
			if (fgets(ms_buf, sizeof(ms_buf), mfp))
				max_states = (unsigned int)strtoul(ms_buf, NULL, 10);
			fclose(mfp);
		}
		if (max_states == 0)
			max_states = 65536;

		char thresh_str[16];
		if (strcmp(adaptive_to, "disable") == 0) {
			/* Disable: set start = max so the scaling band is never entered */
			snprintf(thresh_str, sizeof(thresh_str), "%u", max_states);
		} else {
			/* Enable: restore default 75%-of-max start */
			snprintf(thresh_str, sizeof(thresh_str), "%u",
				 max_states * 3 / 4);
		}
		write_sysfs_param("session", "pf_adaptive_start", thresh_str);
	}

	/* Anti-spoofing: rpfilter drops packets whose source IP has no reverse
	 * route via the ingress interface (RFC 3704 / BCP38 uRPF lite). */
	if (strcmp(anti_spoof, "enable") == 0) {
		const char *rpf_add[] = {
			"iptables", "-t", "raw", "-A", "PREROUTING",
			"-i", iface, "-m", "rpfilter", "--invert", "-j", "DROP", NULL
		};
		if (ipt_exec(rpf_add) != 0)
			mgmt_log("ERROR",
				 "apply_dos_policy: rpfilter rule failed for %s", iface);
	}

	if (written == 0) {
		snprintf(result, rsize,
			 "DoS policy '%s' saved (pkt_forward not loaded; params apply on module load).",
			 id);
	} else if (written < total) {
		snprintf(result, rsize,
			 "DoS policy '%s' partially applied on %s (%d/%d params written).",
			 id, iface, written, total);
		return SG_ERR_SYSTEM_FAIL;
	} else {
		snprintf(result, rsize, "DoS policy '%s' applied on %s (ifindex=%s).",
			 id, iface, ifindex_str);
	}
	return SG_OK;
}

/*
 * handle_netlink_link_event — process one RTM_NEWLINK message.
 *
 * When a DHCP interface loses carrier (IFF_LOWER_UP clears):
 *   - stop udhcpc and flush the stale lease IP immediately
 * When a DHCP interface gains carrier (IFF_LOWER_UP sets):
 *   - start udhcpc if not already running
 */
void handle_netlink_link_event(int nl_fd)
{
	char buf[4096];
	ssize_t n = recv(nl_fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (n <= 0)
		return;

	for (struct nlmsghdr *nh = (struct nlmsghdr *)buf;
	     NLMSG_OK(nh, (unsigned)n);
	     nh = NLMSG_NEXT(nh, n)) {

		if (nh->nlmsg_type != RTM_NEWLINK)
			continue;

		struct ifinfomsg *ifi = NLMSG_DATA(nh);
		if (ifi->ifi_flags & IFF_LOOPBACK)
			continue;

		/* Extract interface name */
		char iface[IFNAMSIZ] = "";
		struct rtattr *rta = IFLA_RTA(ifi);
		int rta_len = (int)IFLA_PAYLOAD(nh);
		for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
			if (rta->rta_type == IFLA_IFNAME) {
				snprintf(iface, sizeof(iface), "%s",
					 (char *)RTA_DATA(rta));
				break;
			}
		}
		if (!iface[0])
			continue;

		/* Only act on DHCP client interfaces */
		char *mode = sg_db_get_val("system_interface", iface, "mode");
		int is_dhcp = mode && strcmp(mode, "dhcp") == 0;
		free(mode);
		if (!is_dhcp)
			continue;

		int carrier_up = (ifi->ifi_flags & IFF_LOWER_UP) != 0;

		if (!carrier_up) {
			mgmt_log("INFO",
				 "carrier lost on %s (dhcp) — flushing lease",
				 iface);
			dhcpc_stop(iface);
			const char *flush[] = {
				"ip", "addr", "flush", "dev", iface, NULL
			};
			free(safe_exec(flush));
			char sf[80];
			snprintf(sf, sizeof(sf), "/var/run/dhcp-status.%s",
				 iface);
			remove(sf);
		} else {
			char supname[80];
			snprintf(supname, sizeof(supname), "udhcpc.%s", iface);
			if (supervisor_get_pid(supname) <= 0) {
				mgmt_log("INFO",
					 "carrier on %s (dhcp) — starting udhcpc",
					 iface);
				dhcpc_start(iface);
			}
		}
	}
}

/* ── apply_session_ttl ──────────────────────────────────────────────────── */

sg_status_t apply_session_ttl(const char *id, const char *data,
			      char *result, size_t rsize)
{
	(void)id;

	static const struct { const char *key; const char *param; const char *def; } map[] = {
		{ "tcp-none",        "sess_tt_tcp_none",       "120"  },
		{ "tcp-syn-sent",    "sess_tt_tcp_syn_sent",   "120"  },
		{ "tcp-syn-recv",    "sess_tt_tcp_syn_recv",   "60"   },
		{ "tcp-established", "sess_tt_tcp_est",        "3600" },
		{ "tcp-fin-wait",    "sess_tt_tcp_fin_wait",   "120"  },
		{ "tcp-close-wait",  "sess_tt_tcp_close_wait", "60"   },
		{ "tcp-last-ack",    "sess_tt_tcp_last_ack",   "30"   },
		{ "tcp-time-wait",   "sess_tt_tcp_time_wait",  "120"  },
		{ "tcp-close",       "sess_tt_tcp_close",      "10"   },
		{ "tcp-syn-sent2",   "sess_tt_tcp_syn_sent2",  "60"   },
		{ "udp",             "sess_tt_udp",            "180"  },
		{ "icmp",            "sess_tt_icmp",           "60"   },
		{ "other",           "sess_tt_other",          "300"  },
		{ NULL, NULL, NULL }
	};

	for (int i = 0; map[i].key; i++) {
		char val[VALBUFSZ];
		extract_val(data, map[i].key, val, sizeof(val));
		write_sysfs_param("session", map[i].param,
				  val[0] ? val : map[i].def);
	}

	snprintf(result, rsize, "Session timeouts applied.");
	return SG_OK;
}
