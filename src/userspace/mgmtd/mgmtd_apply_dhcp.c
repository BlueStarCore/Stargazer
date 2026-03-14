/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_dhcp.c — Apply handler for network_dhcp-server
 *
 * Manages BusyBox udhcpd lifecycle: generates config, starts/stops daemon.
 * Each DHCP pool gets its own udhcpd instance with a dedicated config,
 * pidfile, and lease file under /var/run/.
 *
 * Firewall: inserts an INPUT rule to allow UDP/67 (BOOTP server) on the
 * pool's interface.  Without this, the default DROP policy blocks all
 * DHCP DISCOVER packets from clients.
 */

#define _GNU_SOURCE
#include "mgmtd_apply.h"
#include "sg_db.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* ── IP helpers ────────────────────────────────────────────────────────── */

/*
 * Parse "A.B.C.D" into a host-order uint32_t.
 * Caller must have already validated with sg_is_ipv4().
 */
static uint32_t
ip4_to_u32(const char *s)
{
	unsigned a, b, c, d;
	if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
		return 0;
	return (a << 24) | (b << 16) | (c << 8) | d;
}

/* ── Path helpers ──────────────────────────────────────────────────────── */

static void
dhcpd_conf_path(const char *id, char *buf, size_t sz)
{
	snprintf(buf, sz, "/var/run/udhcpd-%s.conf", id);
}

static void
dhcpd_pid_path(const char *id, char *buf, size_t sz)
{
	snprintf(buf, sz, "/var/run/udhcpd-%s.pid", id);
}

static void
dhcpd_lease_path(const char *id, char *buf, size_t sz)
{
	snprintf(buf, sz, "/var/run/udhcpd-%s.leases", id);
}

/* ── Firewall helpers ──────────────────────────────────────────────────── */

/*
 * Add INPUT rule to allow DHCP requests (UDP/67) on an interface.
 * Inserted at top of INPUT so it's evaluated before the SG_IN_<iface>
 * per-interface chain (which ends with DROP).
 */
static void
dhcpd_fw_add(const char *iface)
{
	const char *argv[] = {"iptables", "-I", "INPUT",
			      "-i", iface,
			      "-p", "udp", "--dport", "67",
			      "-j", "ACCEPT", NULL};
	if (ipt_exec(argv) != 0)
		mgmt_log("ERROR",
			 "dhcpd: failed to add INPUT ACCEPT for UDP/67 on %s",
			 iface);
	else
		mgmt_log("INFO", "dhcpd: allowed UDP/67 on %s", iface);
}

/*
 * Remove INPUT rule for DHCP on an interface.
 * Ignores errors (rule may not exist if pool was never started).
 */
static void
dhcpd_fw_del(const char *iface)
{
	const char *argv[] = {"iptables", "-D", "INPUT",
			      "-i", iface,
			      "-p", "udp", "--dport", "67",
			      "-j", "ACCEPT", NULL};
	free(safe_exec(argv));
}

/* ── Process identity helper ───────────────────────────────────────────── */

/*
 * Verify that pid belongs to a process named 'expected_name'.
 * Reads /proc/<pid>/comm to prevent killing a recycled PID.
 */
static int
pid_is_process(pid_t pid, const char *expected_name)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
	FILE *fp = fopen(path, "r");
	if (!fp)
		return 0;
	char comm[64];
	if (!fgets(comm, sizeof(comm), fp)) {
		fclose(fp);
		return 0;
	}
	fclose(fp);
	char *nl = strchr(comm, '\n');
	if (nl) *nl = '\0';
	return strcmp(comm, expected_name) == 0;
}

/* ── Daemon lifecycle ─────────────────────────────────────────────────── */

/*
 * Read the interface name from an existing udhcpd conf file.
 * Returns 1 if found, 0 if not.
 */
static int
dhcpd_read_conf_iface(const char *conf_path, char *out, size_t outsz)
{
	FILE *fp = fopen(conf_path, "r");
	if (!fp)
		return 0;

	char line[256];
	int found = 0;
	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "interface", 9) == 0 &&
		    (line[9] == '\t' || line[9] == ' ')) {
			const char *val = line + 9;
			while (*val == '\t' || *val == ' ')
				val++;
			char *nl = strchr(val, '\n');
			if (nl)
				*nl = '\0';
			size_t vlen = strlen(val);
			if (vlen >= outsz)
				vlen = outsz - 1;
			memcpy(out, val, vlen);
			out[vlen] = '\0';
			found = 1;
			break;
		}
	}
	fclose(fp);
	return found;
}

/*
 * Stop any running udhcpd for this pool.
 * Reads the old conf to find the interface and remove its firewall rule.
 * Cleans up config, pidfile, and lease files.
 */
static void
dhcpd_stop(const char *id)
{
	char pf[128];
	dhcpd_pid_path(id, pf, sizeof(pf));

	FILE *fp = fopen(pf, "r");
	if (fp) {
		char line[32];
		if (fgets(line, sizeof(line), fp)) {
			pid_t pid = (pid_t)atoi(line);
			if (pid > 1 && pid_is_process(pid, "udhcpd")) {
				kill(pid, SIGTERM);
				/* Wait up to 3s for exit to avoid
				 * EADDRINUSE on immediate restart */
				for (int i = 0; i < 30; i++) {
					if (kill(pid, 0) != 0)
						break;
					usleep(100000);
				}
				if (kill(pid, 0) == 0) {
					mgmt_log("WARN",
						 "dhcpd: pid %d did not exit,"
						 " sending SIGKILL",
						 (int)pid);
					kill(pid, SIGKILL);
				}
			} else if (pid > 1) {
				mgmt_log("WARN",
					 "dhcpd: pid %d is not udhcpd,"
					 " not killing", (int)pid);
			}
		}
		fclose(fp);
		unlink(pf);
	}

	/* Read interface from conf before deleting — needed to remove
	 * the firewall rule that was added when this pool started. */
	char cf[128];
	dhcpd_conf_path(id, cf, sizeof(cf));
	char old_iface[VALBUFSZ] = {0};
	if (dhcpd_read_conf_iface(cf, old_iface, sizeof(old_iface)) &&
	    old_iface[0])
		dhcpd_fw_del(old_iface);
	unlink(cf);

	char lf[128];
	dhcpd_lease_path(id, lf, sizeof(lf));
	unlink(lf);

	mgmt_log("INFO", "dhcpd: stopped pool %s", id);
}

/*
 * Check if another DHCP pool is already serving the same interface.
 * Scans /var/run/udhcpd-*.conf files (skipping our own pool).
 * Returns 1 if a conflict exists, 0 if clear.
 */
static int
dhcpd_iface_conflict(const char *id, const char *iface)
{
	DIR *dir = opendir("/var/run");
	if (!dir)
		return 0;

	struct dirent *ent;
	int conflict = 0;

	while ((ent = readdir(dir)) != NULL) {
		if (strncmp(ent->d_name, "udhcpd-", 7) != 0)
			continue;
		size_t nlen = strlen(ent->d_name);
		if (nlen < 12 ||
		    strcmp(ent->d_name + nlen - 5, ".conf") != 0)
			continue;

		/* Extract pool ID from filename: udhcpd-<id>.conf */
		char other_id[128];
		size_t id_len = nlen - 7 - 5;
		if (id_len == 0 || id_len >= sizeof(other_id))
			continue;
		memcpy(other_id, ent->d_name + 7, id_len);
		other_id[id_len] = '\0';

		if (strcmp(other_id, id) == 0)
			continue;

		char path[280];
		snprintf(path, sizeof(path), "/var/run/%s", ent->d_name);
		char found_iface[VALBUFSZ] = {0};
		if (dhcpd_read_conf_iface(path, found_iface,
					  sizeof(found_iface)) &&
		    strcmp(found_iface, iface) == 0) {
			conflict = 1;
			mgmt_log("WARN",
				 "dhcpd: pool %s conflicts with pool %s"
				 " (both on %s)",
				 id, other_id, iface);
			break;
		}
	}
	closedir(dir);
	return conflict;
}

/*
 * Generate /var/run/udhcpd-<id>.conf and start udhcpd.
 * Returns 0 on success, -1 on failure.
 */
static int
dhcpd_start(const char *id,
	    const char *iface, const char *start_ip,
	    const char *end_ip, const char *netmask,
	    const char *gateway, const char *dns,
	    const char *domain, const char *lease_time)
{
	char cf[128], pf[128], lf[128];
	dhcpd_conf_path(id, cf, sizeof(cf));
	dhcpd_pid_path(id, pf, sizeof(pf));
	dhcpd_lease_path(id, lf, sizeof(lf));

	FILE *fp = fopen(cf, "w");
	if (!fp) {
		mgmt_log("ERROR", "dhcpd: cannot write %s: %s",
			 cf, strerror(errno));
		return -1;
	}

	fprintf(fp, "start\t%s\n", start_ip);
	fprintf(fp, "end\t%s\n", end_ip);
	fprintf(fp, "interface\t%s\n", iface);
	fprintf(fp, "opt\tsubnet\t%s\n", netmask);
	if (gateway[0])
		fprintf(fp, "opt\trouter\t%s\n", gateway);
	if (dns[0])
		fprintf(fp, "opt\tdns\t%s\n", dns);
	if (domain[0])
		fprintf(fp, "opt\tdomain\t%s\n", domain);
	fprintf(fp, "opt\tlease\t%s\n", lease_time);
	fprintf(fp, "pidfile\t%s\n", pf);
	fprintf(fp, "lease_file\t%s\n", lf);

	fclose(fp);

	/* udhcpd requires lease file to exist before starting */
	fp = fopen(lf, "a");
	if (fp)
		fclose(fp);

	/* Start udhcpd via fork+exec with fd safety.
	 * Close ALL inherited fds to prevent leaking database/socket
	 * to udhcpd, which listens on untrusted network ports.
	 * udhcpd daemonizes immediately (parent exits fast). */
	pid_t dpid = fork();
	if (dpid < 0) {
		mgmt_log("ERROR", "dhcpd: fork failed for pool %s: %s",
			 id, strerror(errno));
		unlink(cf);
		unlink(lf);
		return -1;
	}
	if (dpid == 0) {
		/* Child: close ALL inherited fds */
		long maxfd = sysconf(_SC_OPEN_MAX);
		if (maxfd < 0) maxfd = 1024;
		for (int fd = 3; fd < (int)maxfd; fd++)
			close(fd);
		int devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			if (devnull > STDERR_FILENO)
				close(devnull);
		}
		execl("/usr/sbin/udhcpd", "udhcpd", cf, (char *)NULL);
		_exit(127);
	}
	/* Parent: wait for udhcpd parent to exit (it double-forks).
	 * This blocks briefly but udhcpd daemonizes immediately,
	 * unlike udhcpc which waits for a lease first. */
	int wstatus;
	waitpid(dpid, &wstatus, 0);
	if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
		mgmt_log("ERROR", "dhcpd: udhcpd failed for pool %s (exit %d)",
			 id, WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1);
		unlink(cf);
		unlink(lf);
		return -1;
	}

	mgmt_log("INFO", "dhcpd: started pool %s on %s (%s-%s)",
		 id, iface, start_ip, end_ip);
	return 0;
}

/* ── Public: teardown for CFG_DEL ─────────────────────────────────────── */

void
unapply_dhcp(const char *id)
{
	dhcpd_stop(id);
}

/* ── Apply handler ────────────────────────────────────────────────────── */

sg_status_t
apply_dhcp(const char *id, const char *data,
	   char *result, size_t rsize)
{
	char iface[VALBUFSZ], start_ip[VALBUFSZ], end_ip[VALBUFSZ];
	char netmask[VALBUFSZ], gateway[VALBUFSZ], dns[VALBUFSZ];
	char domain[VALBUFSZ], lease_time[VALBUFSZ], status[VALBUFSZ];

	extract_val(data, "interface",   iface,      sizeof(iface));
	extract_val(data, "start-ip",    start_ip,   sizeof(start_ip));
	extract_val(data, "end-ip",      end_ip,     sizeof(end_ip));
	extract_val(data, "netmask",     netmask,    sizeof(netmask));
	extract_val(data, "gateway",     gateway,    sizeof(gateway));
	extract_val(data, "dns-server",  dns,        sizeof(dns));
	extract_val(data, "domain-name", domain,     sizeof(domain));
	extract_val(data, "lease-time",  lease_time, sizeof(lease_time));
	extract_val(data, "status",      status,     sizeof(status));

	/* Always stop existing daemon first — config may have changed.
	 * This also removes the old firewall rule (reads interface from
	 * the old conf file before deleting it). */
	dhcpd_stop(id);

	/* ── Validate fields (even when disabling) ─────────────────────
	 * The CLI sends CFG_APPLY before CFG_SET.  CFG_SET runs
	 * validate_cfg_data() which checks required fields.  If we
	 * skip validation here for status=disable, apply succeeds but
	 * the subsequent CFG_SET fails — confusing "applied but failed
	 * to save" warning.  Validate consistently so apply and save
	 * agree on whether the config is valid. */

	/* Required fields */
	if (!iface[0] || !start_ip[0] || !end_ip[0] || !netmask[0]) {
		snprintf(result, rsize,
			 "DHCP pool %s: missing required fields "
			 "(interface, start-ip, end-ip, netmask).", id);
		return SG_ERR_MISSING_ARG;
	}

	/* Format validation */
	if (!sg_is_iface_name(iface)) {
		snprintf(result, rsize,
			 "DHCP pool %s: invalid interface '%s'.", id, iface);
		return SG_ERR_INVALID_VAL;
	}
	if (!sg_is_ipv4(start_ip)) {
		snprintf(result, rsize,
			 "DHCP pool %s: invalid start-ip '%s'.", id, start_ip);
		return SG_ERR_INVALID_VAL;
	}
	if (!sg_is_ipv4(end_ip)) {
		snprintf(result, rsize,
			 "DHCP pool %s: invalid end-ip '%s'.", id, end_ip);
		return SG_ERR_INVALID_VAL;
	}
	if (!sg_is_ipv4(netmask)) {
		snprintf(result, rsize,
			 "DHCP pool %s: invalid netmask '%s'.", id, netmask);
		return SG_ERR_INVALID_VAL;
	}
	if (gateway[0] && !sg_is_ipv4(gateway)) {
		snprintf(result, rsize,
			 "DHCP pool %s: invalid gateway '%s'.", id, gateway);
		return SG_ERR_INVALID_VAL;
	}
	if (dns[0] && !sg_is_ipv4(dns)) {
		snprintf(result, rsize,
			 "DHCP pool %s: invalid dns-server '%s'.", id, dns);
		return SG_ERR_INVALID_VAL;
	}

	/* Subnet validation: start and end must be in the same network,
	 * and start must not be greater than end. */
	uint32_t s = ip4_to_u32(start_ip);
	uint32_t e = ip4_to_u32(end_ip);
	uint32_t m = ip4_to_u32(netmask);

	if ((s & m) != (e & m)) {
		snprintf(result, rsize,
			 "DHCP pool %s: start-ip and end-ip are not in the "
			 "same subnet (mask %s).", id, netmask);
		return SG_ERR_INVALID_VAL;
	}
	if (s > e) {
		snprintf(result, rsize,
			 "DHCP pool %s: start-ip is greater than end-ip.",
			 id);
		return SG_ERR_INVALID_VAL;
	}

	/* Gateway must be in the same subnet as the pool range */
	if (gateway[0]) {
		uint32_t g = ip4_to_u32(gateway);
		if ((g & m) != (s & m)) {
			snprintf(result, rsize,
				 "DHCP pool %s: gateway %s is not in subnet "
				 "(mask %s).", id, gateway, netmask);
			return SG_ERR_INVALID_VAL;
		}
	}

	/* Check for IP range overlap with other enabled pools */
	{
		char *plist = sg_db_list("network_dhcp-server");
		if (plist) {
			char *sp = NULL;
			char *pt = strtok_r(plist, "\n", &sp);
			int overlap = 0;
			while (pt && !overlap) {
				if (strcmp(pt, id) == 0) {
					pt = strtok_r(NULL, "\n", &sp);
					continue;
				}
				char *os = sg_db_get_val("network_dhcp-server",
							 pt, "status");
				if (os && strcmp(os, "disable") == 0) {
					free(os);
					pt = strtok_r(NULL, "\n", &sp);
					continue;
				}
				free(os);
				char *o_start = sg_db_get_val(
					"network_dhcp-server", pt, "start-ip");
				char *o_end = sg_db_get_val(
					"network_dhcp-server", pt, "end-ip");
				if (o_start && o_end &&
				    sg_is_ipv4(o_start) && sg_is_ipv4(o_end)) {
					uint32_t os32 = ip4_to_u32(o_start);
					uint32_t oe32 = ip4_to_u32(o_end);
					if (s <= oe32 && os32 <= e)
						overlap = 1;
				}
				free(o_start);
				free(o_end);
				if (overlap)
					mgmt_log("WARN",
						 "dhcpd: pool %s range overlaps"
						 " with pool %s", id, pt);
				pt = strtok_r(NULL, "\n", &sp);
			}
			free(plist);
			if (overlap) {
				snprintf(result, rsize,
					 "DHCP pool %s: IP range overlaps"
					 " with another pool.", id);
				return SG_ERR_IN_USE;
			}
		}
	}

	/* Default lease time if not set */
	if (!lease_time[0])
		snprintf(lease_time, sizeof(lease_time), "86400");

	/* ── Disabled pool: validated but not started ──────────────────
	 * All field validation passed, so the subsequent CFG_SET will
	 * also succeed.  No runtime state to create. */
	if (strcmp(status, "disable") == 0) {
		snprintf(result, rsize, "DHCP pool %s disabled.", id);
		return SG_OK;
	}

	/* ── Enable-only checks (need live system state) ───────────── */
	if (!iface_exists(iface)) {
		snprintf(result, rsize,
			 "DHCP pool %s: interface '%s' not found.", id, iface);
		return SG_ERR_NOT_FOUND;
	}

	/* Reject if the interface is configured as a DHCP client —
	 * an interface cannot be both a DHCP client and server. */
	{
		char *iface_mode = sg_db_get_val("system_interface",
						 iface, "mode");
		if (iface_mode) {
			int is_dhcp = (strcmp(iface_mode, "dhcp") == 0);
			free(iface_mode);
			if (is_dhcp) {
				snprintf(result, rsize,
					 "DHCP pool %s: interface %s is "
					 "configured as a DHCP client.",
					 id, iface);
				return SG_ERR_IN_USE;
			}
		}
	}

	/* Check that no other pool is already serving this interface.
	 * udhcpd binds UDP/67 per-interface — two instances on the same
	 * interface would fail with EADDRINUSE. */
	if (dhcpd_iface_conflict(id, iface)) {
		snprintf(result, rsize,
			 "DHCP pool %s: another pool is already active on %s.",
			 id, iface);
		return SG_ERR_IN_USE;
	}

	/* Open firewall for DHCP requests on this interface */
	dhcpd_fw_add(iface);

	/* Start daemon */
	if (dhcpd_start(id, iface, start_ip, end_ip, netmask,
			gateway, dns, domain, lease_time) != 0) {
		dhcpd_fw_del(iface);
		snprintf(result, rsize,
			 "DHCP pool %s: failed to start udhcpd.", id);
		return SG_ERR_SYSTEM_FAIL;
	}

	snprintf(result, rsize, "DHCP pool %s enabled on %s.", id, iface);
	return SG_OK;
}
