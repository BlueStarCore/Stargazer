/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_diag.c — System diagnostics, debug state, and history handlers
 *
 * Reads /proc, /sys, and config files on behalf of the sandboxed CLI.
 * The CLI cannot open files after sandbox activation — all file reads
 * are proxied through these IPC handlers.
 *
 * Permission requirements:
 *   - Diagnostics (640-645, 650-652): "monitor" permission
 *   - Debug state (660-662): "admin" permission
 *   - History save (663): any authenticated user
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "mgmtd_internal.h"
#include "mgmtd_apply.h"
#include "mgmtd_dynbuf.h"
#include "mgmtd_ips_compile.h"   /* ips_catalog_to_json */

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

/* ── Helpers ───────────────────────────────────────────────────────────── */

/* Append formatted text to buf at *pos, respecting bufsz. */
static void buf_appendf(char *buf, size_t bufsz, size_t *pos,
			const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));

static void buf_appendf(char *buf, size_t bufsz, size_t *pos,
			const char *fmt, ...)
{
	if (*pos >= bufsz - 1)
		return;
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(buf + *pos, bufsz - *pos, fmt, ap);
	va_end(ap);
	if (n > 0 && (size_t)n < bufsz - *pos)
		*pos += (size_t)n;
}

/* Read entire small file into buf. Returns bytes read or -1. */
static ssize_t read_small_file(const char *path, char *buf, size_t bufsz)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	size_t total = 0;
	while (total < bufsz - 1) {
		ssize_t n = read(fd, buf + total, bufsz - 1 - total);
		if (n <= 0)
			break;
		total += (size_t)n;
	}
	buf[total] = '\0';
	close(fd);
	return (ssize_t)total;
}

/* ── SG_CMD_DIAG_CPU (640) ─────────────────────────────────────────────── */

int handle_diag_cpu(int client_fd, const char *user,
		    const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	char resp[SG_RESPONSE_MAX];
	size_t pos = 0;

	/* Read /proc/stat — cpu lines */
	char stat_buf[4096];
	if (read_small_file("/proc/stat", stat_buf, sizeof(stat_buf)) > 0) {
		const char *p = stat_buf;
		while (*p) {
			const char *eol = strchr(p, '\n');
			size_t llen = eol ? (size_t)(eol - p) : strlen(p);

			if (llen >= 3 && strncmp(p, "cpu", 3) == 0 &&
			    (p[3] == ' ' || isdigit((unsigned char)p[3]))) {
				buf_appendf(resp, sizeof(resp), &pos,
					    "%.*s\n", (int)llen, p);
			}

			if (!eol)
				break;
			p = eol + 1;
		}
	}

	/* Per-core current frequency (kHz) from cpufreq, when the
	 * governor exposes it. Emitted as cpufreq<N>=<khz>; cores
	 * without a cpufreq node are simply omitted. */
	for (int c = 0; c < 64; c++) {
		char fpath[128], fbuf[32];
		snprintf(fpath, sizeof(fpath),
			 "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq",
			 c);
		if (read_small_file(fpath, fbuf, sizeof(fbuf)) <= 0) {
			snprintf(fpath, sizeof(fpath),
				 "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_cur_freq",
				 c);
			if (read_small_file(fpath, fbuf, sizeof(fbuf)) <= 0)
				continue;
		}
		size_t fl = strlen(fbuf);
		while (fl > 0 && (fbuf[fl-1] == '\n' || fbuf[fl-1] == '\r'))
			fbuf[--fl] = '\0';
		buf_appendf(resp, sizeof(resp), &pos,
			    "cpufreq%d=%s\n", c, fbuf);
	}

	/* Read thermal zones with type names */
	char path[128], tbuf[32], ttype[64];
	for (int z = 0; z < 16; z++) {
		snprintf(path, sizeof(path),
			 "/sys/class/thermal/thermal_zone%d/temp", z);
		if (read_small_file(path, tbuf, sizeof(tbuf)) > 0) {
			size_t len = strlen(tbuf);
			while (len > 0 && (tbuf[len-1] == '\n' || tbuf[len-1] == '\r'))
				tbuf[--len] = '\0';

			/* Read zone type for a meaningful label */
			ttype[0] = '\0';
			snprintf(path, sizeof(path),
				 "/sys/class/thermal/thermal_zone%d/type", z);
			if (read_small_file(path, ttype, sizeof(ttype)) > 0) {
				len = strlen(ttype);
				while (len > 0 && (ttype[len-1] == '\n' || ttype[len-1] == '\r'))
					ttype[--len] = '\0';
			}

			buf_appendf(resp, sizeof(resp), &pos,
				    "thermal_zone%d=%s type=%s\n",
				    z, tbuf, ttype[0] ? ttype : "unknown");
		}
	}

	/* hwmon sensors (chips not exposed as thermal_zone) */
	for (int hw = 0; hw < 16; hw++) {
		char hpath[128], hname[64];
		snprintf(hpath, sizeof(hpath),
			 "/sys/class/hwmon/hwmon%d/name", hw);
		if (read_small_file(hpath, hname, sizeof(hname)) <= 0)
			continue;
		size_t hlen = strlen(hname);
		while (hlen > 0 && (hname[hlen-1] == '\n' || hname[hlen-1] == '\r'))
			hname[--hlen] = '\0';

		for (int ti = 1; ti <= 8; ti++) {
			char tpath[128];
			snprintf(tpath, sizeof(tpath),
				 "/sys/class/hwmon/hwmon%d/temp%d_input", hw, ti);
			if (read_small_file(tpath, tbuf, sizeof(tbuf)) <= 0)
				break;
			size_t tlen = strlen(tbuf);
			while (tlen > 0 && (tbuf[tlen-1] == '\n' || tbuf[tlen-1] == '\r'))
				tbuf[--tlen] = '\0';

			/* Label if available, else use chip name */
			char tlabel[64];
			snprintf(tpath, sizeof(tpath),
				 "/sys/class/hwmon/hwmon%d/temp%d_label", hw, ti);
			if (read_small_file(tpath, tlabel, sizeof(tlabel)) > 0) {
				tlen = strlen(tlabel);
				while (tlen > 0 && (tlabel[tlen-1] == '\n' || tlabel[tlen-1] == '\r'))
					tlabel[--tlen] = '\0';
			} else {
				snprintf(tlabel, sizeof(tlabel), "%.50s-temp%d",
					 hname, ti);
			}

			buf_appendf(resp, sizeof(resp), &pos,
				    "hwmon=%s temp=%s\n", tlabel, tbuf);
		}
	}

	/* Parse /proc/cpuinfo — single pass for core count + MHz */
	int cores = 0;
	int mhz_val = 0;
	char cpuinfo[8192];
	if (read_small_file("/proc/cpuinfo", cpuinfo, sizeof(cpuinfo)) > 0) {
		char *line = cpuinfo;
		while (*line) {
			char *nl = strchr(line, '\n');
			if (!nl) nl = line + strlen(line);

			if (strncmp(line, "processor", 9) == 0)
				cores++;
			else if (mhz_val == 0 &&
				 (strncmp(line, "cpu MHz", 7) == 0 ||
				  strncmp(line, "BogoMIPS", 8) == 0)) {
				const char *colon = memchr(line, ':',
							   (size_t)(nl - line));
				if (colon)
					mhz_val = (int)strtol(colon + 1, NULL, 10);
			}

			line = *nl ? nl + 1 : nl;
		}
	}
	buf_appendf(resp, sizeof(resp), &pos,
		    "cpu_cores=%d\n", cores > 0 ? cores : 1);
	buf_appendf(resp, sizeof(resp), &pos,
		    "cpu_mhz=%d\n", mhz_val);

	/* Load average from /proc/loadavg (first 3 fields: 1m 5m 15m) */
	char lavg[128];
	if (read_small_file("/proc/loadavg", lavg, sizeof(lavg)) > 0) {
		char *nl2 = strchr(lavg, '\n');
		if (nl2) *nl2 = '\0';
		int spaces = 0;
		for (char *c = lavg; *c; c++) {
			if (*c == ' ' && ++spaces == 3) { *c = '\0'; break; }
		}
		buf_appendf(resp, sizeof(resp), &pos, "loadavg=%s\n", lavg);
	}

	send_ok(client_fd, NULL, pos > 0 ? resp : NULL);
	return 0;
}

/* ── SG_CMD_DIAG_RAM (641) ─────────────────────────────────────────────── */

int handle_diag_ram(int client_fd, const char *user,
		    const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	char meminfo[2048];
	if (read_small_file("/proc/meminfo", meminfo, sizeof(meminfo)) < 0) {
		mgmt_log("ERROR", "diag_ram: cannot read /proc/meminfo: %s",
			 strerror(errno));
		send_error(client_fd, SG_ERR_IO_FAIL,
			   "cannot read memory information");
		return 0;
	}

	long mt = 0, mf = 0, ma = 0, buf = 0, cached = 0, slab = 0;
	long st = 0, sf = 0;
	const char *p = meminfo;
	while (*p) {
		if (strncmp(p, "MemTotal:", 9) == 0)
			mt = atol(p + 9);
		else if (strncmp(p, "MemFree:", 8) == 0)
			mf = atol(p + 8);
		else if (strncmp(p, "MemAvailable:", 13) == 0)
			ma = atol(p + 13);
		else if (strncmp(p, "Buffers:", 8) == 0)
			buf = atol(p + 8);
		else if (strncmp(p, "Cached:", 7) == 0)
			cached = atol(p + 7);
		else if (strncmp(p, "Slab:", 5) == 0)
			slab = atol(p + 5);
		else if (strncmp(p, "SwapTotal:", 10) == 0)
			st = atol(p + 10);
		else if (strncmp(p, "SwapFree:", 9) == 0)
			sf = atol(p + 9);
		const char *nl = strchr(p, '\n');
		if (!nl) break;
		p = nl + 1;
	}

	char resp[512];
	snprintf(resp, sizeof(resp),
		 "MemTotal=%ld\nMemFree=%ld\nMemAvailable=%ld\n"
		 "Buffers=%ld\nCached=%ld\nSlab=%ld\n"
		 "SwapTotal=%ld\nSwapFree=%ld\n",
		 mt, mf, ma, buf, cached, slab, st, sf);
	send_ok(client_fd, NULL, resp);
	return 0;
}

/* ── SG_CMD_DIAG_DISK (642) ────────────────────────────────────────────── */

int handle_diag_disk(int client_fd, const char *user,
		     const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	char resp[1024];
	size_t pos = 0;

	/* eMMC total size from sysfs (512-byte sectors) */
	unsigned long long emmc_bytes = 0;
	const char *blk_paths[] = {
		"/sys/block/mmcblk0/size",
		"/sys/block/mmcblk1/size",
		NULL
	};
	const char *emmc_dev = "none";
	for (int i = 0; blk_paths[i]; i++) {
		char sbuf[64];
		if (read_small_file(blk_paths[i], sbuf, sizeof(sbuf)) > 0) {
			emmc_bytes = strtoull(sbuf, NULL, 10) * 512ULL;
			/* Extract device name from path */
			emmc_dev = (i == 0) ? "/dev/mmcblk0" : "/dev/mmcblk1";
			break;
		}
	}
	int n = snprintf(resp + pos, sizeof(resp) - pos,
			 "emmc_dev=%s\nemmc_bytes=%llu\n",
			 emmc_dev, emmc_bytes);
	if (n > 0) pos += (size_t)n;

	/* sgdata partition: /etc/stargazer */
	struct statvfs sv;
	if (statvfs("/etc/stargazer", &sv) == 0) {
		n = snprintf(resp + pos, sizeof(resp) - pos,
			     "sgdata_blocks=%lu\nsgdata_bfree=%lu\n"
			     "sgdata_bavail=%lu\nsgdata_frsize=%lu\n",
			     (unsigned long)sv.f_blocks,
			     (unsigned long)sv.f_bfree,
			     (unsigned long)sv.f_bavail,
			     (unsigned long)sv.f_frsize);
		if (n > 0) pos += (size_t)n;
	} else {
		n = snprintf(resp + pos, sizeof(resp) - pos,
			     "sgdata_blocks=0\n");
		if (n > 0) pos += (size_t)n;
	}

	/* sglogs partition: /etc/stargazer/logs */
	if (statvfs("/etc/stargazer/logs", &sv) == 0) {
		/* Only report if it's a different device than sgdata */
		struct statvfs sv2;
		int different = 1;
		if (statvfs("/etc/stargazer", &sv2) == 0 &&
		    sv.f_blocks == sv2.f_blocks &&
		    sv.f_frsize == sv2.f_frsize)
			different = 0;
		if (different) {
			n = snprintf(resp + pos, sizeof(resp) - pos,
				     "sglogs_blocks=%lu\nsglogs_bfree=%lu\n"
				     "sglogs_bavail=%lu\nsglogs_frsize=%lu\n",
				     (unsigned long)sv.f_blocks,
				     (unsigned long)sv.f_bfree,
				     (unsigned long)sv.f_bavail,
				     (unsigned long)sv.f_frsize);
			if (n > 0) pos += (size_t)n;
		}
	}

	send_ok(client_fd, NULL, resp);
	return 0;
}

/* ── SG_CMD_SSL_CACERT (683) ───────────────────────────────────────────── */

/*
 * Return the CA cert (PEM) for the client to download and install into its
 * trust store. Only the public CERT is returned — NEVER the private key. The
 * CA is generated by stargazer-ssld at /etc/stargazer/ssl/ca-cert.pem when SSL
 * inspection is first enabled.
 */
int handle_ssl_cacert(int client_fd, const char *user,
		      const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "configure")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "configure permission required");
		return 0;
	}

	char pem[8192];
	ssize_t n = read_small_file("/etc/stargazer/ssl/ca-cert.pem",
				    pem, sizeof(pem));
	if (n <= 0) {
		/* A not-yet-generated CA is a NORMAL STATE (no deep profile has
		 * been enabled yet) — NOT a backend error. Return OK with empty
		 * output so the UI can gently show "CA not created" without raising
		 * a red banner. The CLI prints its own hint. */
		send_ok(client_fd, NULL, "");
		return 0;
	}
	send_ok(client_fd, NULL, pem);
	return 0;
}

/* ── SG_CMD_SSL_DIAG (694) — SSL inspection diagnostics (debug device) ───── */

int handle_ssl_diag(int client_fd, const char *user,
		    const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED, "monitor required");
		return 0;
	}

	char resp[8192]; size_t pos = 0; int n;
#define ADD(...) do { n = snprintf(resp+pos, sizeof(resp)-pos, __VA_ARGS__); \
		      if (n > 0) pos += (size_t)n; } while (0)
#define SSL_PROF "security_ssl-inspection-profile"
#define SSL_PORT_BASE_DIAG 8443   /* ssld profile #i listens on BASE+i (matches ssld_sync) */

	/* ── Infrastructure shared by every profile ──────────────────────── */
	int bin_ok = access("/sbin/stargazer-ssld", X_OK) == 0;
	struct stat stt;
	int ca_ok = stat("/etc/stargazer/ssl/ca-cert.pem", &stt) == 0 && stt.st_size > 0;
	long long ca_sz = ca_ok ? (long long)stt.st_size : 0;

	/* Count root CAs in the trust store (number of "BEGIN CERTIFICATE" lines). */
	int trust = 0;
	FILE *tf = fopen("/etc/ssl/certs/ca-certificates.crt", "r");
	if (tf) {
		char line[256];
		while (fgets(line, sizeof(line), tf))
			if (strstr(line, "BEGIN CERTIFICATE")) trust++;
		fclose(tf);
	}

	/* Current steering table (nat PREROUTING) for cross-checking. */
	const char *ipt[] = {"iptables", "-t", "nat", "-S", "PREROUTING", NULL};
	char *natr = safe_exec(ipt);

	ADD("=== SSL Inspection ===\n");
	ADD("ssld_binary=%s\n", bin_ok ? "present" : "MISSING");
	ADD("ca_cert=%s", ca_ok ? "present" : "MISSING");
	if (ca_ok) ADD(" (%lld bytes)", ca_sz);
	ADD("\n");
	ADD("trust_store=/etc/ssl/certs/ca-certificates.crt (%d root CA)\n", trust);

	/* ── List each profile + its ssld ────────────────────────────────── */
	int n_active = 0, n_running_bad = 0;
	char *list = sg_db_list(SSL_PROF);
	if (list) {
		int idx = 0;            /* same port-assignment order as ssld_sync */
		char *sp = NULL;
		for (char *id = strtok_r(list, "\n", &sp); id;
		     id = strtok_r(NULL, "\n", &sp)) {
			int builtin = strcmp(id, "no-inspection") == 0;
			char *st   = sg_db_get_val(SSL_PROF, id, "status");
			char *mode = sg_db_get_val(SSL_PROF, id, "inspection-mode");
			char *nosni= sg_db_get_val(SSL_PROF, id, "no-sni");
			char *untr = sg_db_get_val(SSL_PROF, id, "untrusted-server-cert");
			char *exmpt= sg_db_get_val(SSL_PROF, id, "exempt");
			int en   = !builtin && st && !strcmp(st, "enable");
			int deep = mode && !strcmp(mode, "deep");

			ADD("\n[profile %s]%s\n", id, builtin ? " (builtin)" : "");
			if (builtin) {
				ADD("  inspection=none (traffic passes through, no decryption)\n");
			} else {
				ADD("  status=%s\n", en ? "enable" : "disable");
				ADD("  inspection_mode=%s\n", mode ? mode : "certificate");
				ADD("  no_sni=%s\n", nosni ? nosni : "bump");
				ADD("  untrusted_server_cert=%s\n", untr ? untr : "block");
				int ex = 0;
				if (exmpt && *exmpt) {
					ex = 1;
					for (const char *p = exmpt; *p; p++)
						if (*p == ',' || *p == ' ') ex++;
				}
				ADD("  exempt_count=%d\n", ex);

				if (en) {
					int port = SSL_PORT_BASE_DIAG + idx;
					char child[128];
					snprintf(child, sizeof(child),
						 "stargazer-ssld-%s", id);
					pid_t pid = supervisor_get_pid(child);
					ADD("  listen_port=%d\n", port);
					ADD("  ssld_running=%s", pid > 0 ? "yes" : "no");
					if (pid > 0) ADD(" (pid %d)", (int)pid);
					ADD("\n");
					n_active++;
					if (pid <= 0 || (deep && !ca_ok)) n_running_bad++;
				}
			}
			if (en) idx++;
			free(st); free(mode); free(nosni); free(untr); free(exmpt);
		}
		free(list);
	}

	/* ── Which policy uses which profile ─────────────────────────────── */
	ADD("\n--- firewall policies using an SSL profile ---\n");
	int n_steer_pol = 0;
	char *plist = sg_db_list("firewall_policy");
	if (plist) {
		char *sp = NULL;
		for (char *pid = strtok_r(plist, "\n", &sp); pid;
		     pid = strtok_r(NULL, "\n", &sp)) {
			char *prof = sg_db_get_val("firewall_policy", pid, "ssl-profile");
			char *act  = sg_db_get_val("firewall_policy", pid, "action");
			char *pst  = sg_db_get_val("firewall_policy", pid, "status");
			if (prof && *prof && strcmp(prof, "no-inspection") != 0) {
				int on = act && !strcmp(act, "accept") &&
					 pst && !strcmp(pst, "enable");
				ADD("  policy %s -> %s%s\n", pid, prof,
				    on ? "" : " (policy disabled/deny — not steered)");
				if (on) n_steer_pol++;
			}
			free(prof); free(act); free(pst);
		}
		free(plist);
	}
	if (n_steer_pol == 0)
		ADD("  (no policy uses SSL inspection — all are no-inspection)\n");

	/* ── Actual steering rule in nat PREROUTING ──────────────────────── */
	int steer = natr && strstr(natr, "REDIRECT") != NULL;
	ADD("\nsteering_rule=%s\n", steer ? "present" : "absent");
	if (steer) {
		char *sp = NULL;
		for (char *l = strtok_r(natr, "\n", &sp); l;
		     l = strtok_r(NULL, "\n", &sp))
			if (strstr(l, "REDIRECT")) ADD("  rule=%.180s\n", l);
	}
	free(natr);

	/* ── Diagnostics ─────────────────────────────────────────────────── */
	ADD("\n--- diagnostics ---\n");
	if (!bin_ok)
		ADD("[!] ssld binary MISSING /sbin/stargazer-ssld → every inspecting "
		    "profile will BREAK (steering points to a port nobody listens on). "
		    "Rebuild/reinstall the rootfs.\n");
	if (n_active == 0) {
		ADD("[i] No profile is ENABLED — only no-inspection, traffic passes "
		    "through. Safe, no decryption.\n");
	} else {
		if (n_running_bad > 0)
			ADD("[!] %d profile(s) ENABLED but ssld is not running or deep is "
			    "missing its CA → HTTPS through that profile may break. Check "
			    "the mgmtd log; re-enable so ssld generates its CA.\n", n_running_bad);
		if (n_steer_pol == 0)
			ADD("[!] Profile(s) ENABLED but NO policy assigns them → ssld runs "
			    "but no traffic is steered into it. Assign the ssl-profile to a "
			    "firewall policy.\n");
		else if (!steer)
			ADD("[!] A policy assigns a profile but NO REDIRECT was found in nat "
			    "PREROUTING → 443 traffic does not reach ssld. Re-apply the firewall.\n");
		if (!ca_ok)
			ADD("[!] NO CA yet (/etc/stargazer/ssl/ca-cert.pem) → deep mode runs "
			    "SPLICE-only (no decryption). Enable a deep profile once so "
			    "ssld generates its CA.\n");
		if (bin_ok && n_running_bad == 0 && n_steer_pol > 0 && steer)
			ADD("[OK] Operational: %d profile(s) running, %d policy steering, steering present.\n",
			    n_active, n_steer_pol);
		if (ca_ok)
			ADD("[i] Export the CA (execute system ssl-ca-cert) + install it on "
			    "clients so deep mode does not raise red cert warnings.\n");
	}

	send_ok(client_fd, NULL, resp);
	return 0;
#undef ADD
#undef SSL_PROF
#undef SSL_PORT_BASE_DIAG
}

/* ── SG_CMD_IPS_STATUS (684) ───────────────────────────────────────────── */

int handle_ips_status(int client_fd, const char *user,
		      const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED, "monitor required");
		return 0;
	}

	char resp[2048];
	size_t pos = 0;
	int n;

	/* Read config from the DB */
	char *status = sg_db_get_val("security_ips", "0", "status");
	char *mode   = sg_db_get_val("security_ips", "0", "mode");
	char *snapb  = sg_db_get_val("security_ips", "0", "snapshot-bytes");
	n = snprintf(resp + pos, sizeof(resp) - pos,
		     "status=%s\nmode=%s\nsnapshot_bytes=%s\n",
		     status ? status : "disable",
		     mode   ? mode   : "prevent",
		     snapb  ? snapb  : "16384");
	free(status); free(mode); free(snapb);
	if (n > 0) pos += (size_t)n;

	/* Is ipsd running — ask the SUPERVISOR (mgmtd manages ipsd itself so it
	 * knows the exact PID). pidof is unreliable: depends on PATH + truncates
	 * comm to 15 characters. */
	int running = (supervisor_get_pid("stargazer-ipsd") > 0);
	n = snprintf(resp + pos, sizeof(resp) - pos,
		     "ipsd_running=%s\n",
		     running ? "yes" : "no");
	if (n > 0) pos += (size_t)n;

	/*
	 * Diagnosing "ipsd not running" needs NO shell (the firewall only has a CLI):
	 *   ipsd_binary=missing → firmware did not install the binary → rebuild/reflash.
	 *   active_rules=0      → profile compiled empty → ipsd exits immediately
	 *                         (sig_reload_init loaded=0). Fix the profile so it has rules.
	 *   active_rules=-1     → no active.rules yet (no profile attached to a policy).
	 */
	n = snprintf(resp + pos, sizeof(resp) - pos, "ipsd_binary=%s\n",
		     access("/sbin/stargazer-ipsd", X_OK) == 0 ? "present"
							      : "missing");
	if (n > 0) pos += (size_t)n;

	int nrules = -1;
	FILE *ar = fopen("/etc/stargazer/ips/rules/active.rules", "r");
	if (ar) {
		nrules = 0;
		char l[8192];
		while (fgets(l, sizeof(l), ar)) {
			const char *p = l;
			while (*p == ' ' || *p == '\t') p++;
			if (*p && *p != '#' && *p != '\n') nrules++;
		}
		fclose(ar);
	}
	n = snprintf(resp + pos, sizeof(resp) - pos, "active_rules=%d\n", nrules);
	if (n > 0) pos += (size_t)n;

	/* P0 — real ruleset coverage (written by ipsd at load time): loaded_full/alert/skip…
	 * key=value file, appended verbatim to the response. Missing file (ipsd has not
	 * loaded yet) → skip; the UI shows "—". */
	FILE *sf = fopen("/run/stargazer-ipsd.stats", "r");
	if (sf) {
		char line[128];
		while (fgets(line, sizeof(line), sf)) {
			size_t ll = strlen(line);
			if (ll + 1 < sizeof(resp) - pos) {
				memcpy(resp + pos, line, ll);
				pos += ll;
			}
		}
		fclose(sf);
	}

	/* Runtime NFQUEUE telemetry (ipsd writes it every loop) — diagnosing "ipsd
	 * running but traffic stalled" needs NO shell. pkt_seen=0 → the kernel is not
	 * delivering packets. */
	FILE *rf = fopen("/run/stargazer-ipsd.rt", "r");
	if (rf) {
		char line[128];
		while (fgets(line, sizeof(line), rf)) {
			size_t ll = strlen(line);
			if (ll + 1 < sizeof(resp) - pos) {
				memcpy(resp + pos, line, ll);
				pos += ll;
			}
		}
		fclose(rf);
	}

	/* Alert log line count — counted directly (the device's busybox lacks the wc applet). */
	int alert_lines = 0;
	FILE *af = fopen("/etc/stargazer/logs/ips-alert.log", "r");
	if (af) {
		int c;
		while ((c = fgetc(af)) != EOF)
			if (c == '\n') alert_lines++;
		fclose(af);
	}
	n = snprintf(resp + pos, sizeof(resp) - pos,
		     "alert_log_lines=%d", alert_lines);
	if (n > 0) pos += (size_t)n;

	/* Dump the actual NFQUEUE rules in FORWARD — pins down byte-window
	 * (connbytes-mode bytes) vs fallback (ctstate NEW SYN-only). If you see
	 * "ctstate NEW" → connbytes_supported() returned false → investigate why
	 * iptables -m connbytes failed even though the kernel supports it. If you
	 * see "connbytes ... bytes" but tcp_payload is still 0 → a different problem. */
	const char *ipt[] = {"iptables", "-S", "FORWARD", NULL};
	char *fwd = safe_exec(ipt);
	if (fwd) {
		char *sp = NULL;
		for (char *l = strtok_r(fwd, "\n", &sp); l;
		     l = strtok_r(NULL, "\n", &sp)) {
			if (!strstr(l, "NFQUEUE")) continue;
			n = snprintf(resp + pos, sizeof(resp) - pos,
				     "\nnfq_rule=%.200s", l);
			if (n > 0 && (size_t)n < sizeof(resp) - pos)
				pos += (size_t)n;
		}
		free(fwd);
	}

	send_ok(client_fd, NULL, resp);
	return 0;
}

/* ── SG_CMD_IPS_ALERTS (685) ───────────────────────────────────────────── */

/* Read the last N lines of a file with a direct fopen (NO tail fork — `tail`/PATH
 * are unavailable in safe_exec's child on the device → would return empty).
 * Returns a malloc'd string or NULL if the file is missing/empty. Reads the last
 * 256KB at most. */
static char *read_last_lines(const char *path, int nlines)
{
	FILE *f = fopen(path, "r");
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	if (sz <= 0) { fclose(f); return NULL; }
	long cap = 256 * 1024;
	if (sz > cap) { fseek(f, -cap, SEEK_END); sz = cap; }
	else          { fseek(f, 0, SEEK_SET); }
	char *buf = malloc((size_t)sz + 1);
	if (!buf) { fclose(f); return NULL; }
	size_t got = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	buf[got] = '\0';
	if (got == 0) { free(buf); return NULL; }

	/* Keep the last nlines lines: skip the first (total '\n' − nlines) lines. */
	int total_nl = 0;
	for (size_t i = 0; i < got; i++) if (buf[i] == '\n') total_nl++;
	int skip = total_nl - nlines;
	if (skip > 0) {
		int seen = 0;
		for (size_t i = 0; i < got; i++) {
			if (buf[i] == '\n' && ++seen == skip) {
				memmove(buf, buf + i + 1, got - i);
				break;
			}
		}
	}
	return buf;
}

int handle_ips_alerts(int client_fd, const char *user,
		      const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED, "monitor required");
		return 0;
	}

	/* Number of lines to view — default 20 */
	char nlines_s[16] = "20";
	if (payload && payload[0])
		extract_val(payload, "lines", nlines_s, sizeof(nlines_s));
	int nlines = atoi(nlines_s);
	if (nlines < 1 || nlines > 1000) nlines = 20;

	char *out = read_last_lines("/etc/stargazer/logs/ips-alert.log", nlines);
	if (!out || !out[0]) {
		send_ok(client_fd, NULL, "(no alerts yet)\n");
		free(out);
		return 0;
	}
	send_ok(client_fd, NULL, out);
	free(out);
	return 0;
}

/* ── SG_CMD_IPS_ALERTS_CLEAR (692) — truncate ips-alert.log ───────────
 * Must run in mgmtd (root): /etc/stargazer/logs is 0700 root, webd (uid 900)
 * cannot write it — previously webd did its own open(O_TRUNC) → silent failure,
 * the UI reported a FALSE success. Moved into mgmtd so the truncate really happens. */
int handle_ips_alerts_clear(int client_fd, const char *user,
			    const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr; (void)payload;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED, "admin required");
		return 0;
	}

	const char *path = "/etc/stargazer/logs/ips-alert.log";
	int fd = open(path, O_WRONLY | O_TRUNC | O_CREAT, 0640);
	if (fd < 0) {
		send_error(client_fd, SG_ERR_INTERNAL, "could not clear alert log");
		return 0;
	}
	close(fd);
	mgmt_log("INFO", "ips-alert.log cleared by %s", user ? user : "?");
	send_ok(client_fd, NULL, "alert log cleared\n");
	return 0;
}

/* ── SG_CMD_IPS_SCORES (693) — per-flow ML scores from ipsd's dump loop ───
 * ipsd writes /run/stargazer-ipsd.scores (tmp+rename) every few seconds. Read
 * it directly with fopen (no fork). */
int handle_ips_scores(int client_fd, const char *user,
		      const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED, "monitor required");
		return 0;
	}

	char nlines_s[16] = "100";
	if (payload && payload[0])
		extract_val(payload, "lines", nlines_s, sizeof(nlines_s));
	int nlines = atoi(nlines_s);
	if (nlines < 1 || nlines > 2000) nlines = 100;

	char *out = read_last_lines("/run/stargazer-ipsd.scores", nlines);
	if (!out || !out[0]) {
		send_ok(client_fd, NULL,
			"(no scores yet — ipsd not running, or no flow has enough packets)\n");
		free(out);
		return 0;
	}
	send_ok(client_fd, NULL, out);
	free(out);
	return 0;
}

/* ── SG_CMD_IPS_UPDATE_LOG (691) — tail ips-update.log ──────────────── */

int handle_ips_update_log(int client_fd, const char *user,
			  const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr; (void)payload;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED, "monitor required");
		return 0;
	}

	char *out = read_last_lines("/etc/stargazer/logs/ips-update.log", 100);
	if (!out || !out[0]) {
		send_ok(client_fd, NULL, "(ips-update.log is empty — no downloads yet)\n");
		free(out);
		return 0;
	}
	send_ok(client_fd, NULL, out);
	free(out);
	return 0;
}

/* ── SG_CMD_IPS_ALERTS_JSON (689) — parse alert log → JSON array ─────── */

int handle_ips_alerts_json(int client_fd, const char *user,
			   const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED, "monitor required");
		return 0;
	}

	char nlines_s[16] = "100";
	if (payload && payload[0])
		extract_val(payload, "lines", nlines_s, sizeof(nlines_s));
	int nlines = atoi(nlines_s);
	if (nlines < 1 || nlines > 5000) nlines = 100;

	/* Read directly with fopen (no tail fork — busybox lacks the applet). */
	char *raw = read_last_lines("/etc/stargazer/logs/ips-alert.log", nlines);
	if (!raw || !raw[0]) {
		free(raw);
		send_ok(client_fd, NULL, "[]");
		return 0;
	}

	/* Allocate output buffer: each line → ~300 bytes JSON, add 64 overhead */
	size_t cap = (size_t)nlines * 320 + 64;
	char *json = malloc(cap);
	if (!json) { free(raw); send_ok(client_fd, NULL, "[]"); return 0; }

	size_t pos = 0;
	json[pos++] = '[';
	int first = 1;

	char *p = raw;
	while (*p) {
		char *nl = strchr(p, '\n');
		size_t llen = nl ? (size_t)(nl - p) : strlen(p);
		if (llen == 0) { p = nl ? nl + 1 : p + llen; continue; }

		/* Format: ts_date ts_time verdict proto=N src=IP:PORT dst=IP:PORT
		 *         reason=STR score=FLOAT sid=N msg=STR */
		char ts[24]="", verdict[8]="", src[48]="", dst[48]="";
		char reason[24]="", msg_rest[256]="";
		unsigned proto = 0;
		unsigned sport = 0, dport = 0;
		double   score = -1.0;
		unsigned sid   = 0;

		/* Parse: first two tokens are date + time, third is verdict,
		 * rest are key=value except msg= which may contain spaces */
		char line[512];
		size_t cp = llen < sizeof(line)-1 ? llen : sizeof(line)-1;
		memcpy(line, p, cp); line[cp] = '\0';

		char date[12]="", timebuf[10]="";
		sscanf(line, "%11s %9s %7s", date, timebuf, verdict);
		snprintf(ts, sizeof(ts), "%s %s", date, timebuf);

		/* Parse key=value tokens after first 3 tokens */
		char *kv = line;
		int tok = 0;
		while (*kv) {
			while (*kv == ' ') kv++;
			char *end = kv; while (*end && *end != ' ') end++;
			if (tok >= 3) {
				/* key=value */
				char *eq = memchr(kv, '=', (size_t)(end - kv));
				if (eq) {
					*eq = '\0'; *end = '\0';
					const char *key = kv, *val = eq + 1;
					if (strcmp(key, "proto") == 0)       proto = (unsigned)atoi(val);
					else if (strcmp(key, "src") == 0) {
						const char *c = strrchr(val, ':');
						if (c) {
							size_t ilen = (size_t)(c - val);
							if (ilen >= sizeof(src)) ilen = sizeof(src)-1;
							memcpy(src, val, ilen); src[ilen] = '\0';
							sport = (unsigned)atoi(c+1);
						} else {
							snprintf(src, sizeof(src), "%s", val);
						}
					} else if (strcmp(key, "dst") == 0) {
						const char *c = strrchr(val, ':');
						if (c) {
							size_t ilen = (size_t)(c - val);
							if (ilen >= sizeof(dst)) ilen = sizeof(dst)-1;
							memcpy(dst, val, ilen); dst[ilen] = '\0';
							dport = (unsigned)atoi(c+1);
						} else {
							snprintf(dst, sizeof(dst), "%s", val);
						}
					} else if (strcmp(key, "reason") == 0) snprintf(reason, sizeof(reason), "%s", val);
					else if (strcmp(key, "score") == 0)  score = (val[0] == 'n') ? -1.0 : atof(val);
					else if (strcmp(key, "sid") == 0)    sid   = (unsigned)atoi(val);
					else if (strcmp(key, "msg") == 0)    snprintf(msg_rest, sizeof(msg_rest), "%s", val);
					*end = ' '; *eq = '=';
				}
			}
			tok++;
			kv = *end ? end + 1 : end;
		}

		/* ML-ANOMALY placeholder */
		const char *sid_str = "0";
		char sid_buf[16];
		if (sid == 0 && (strncmp(reason, "ml-", 3) == 0 ||
				 strcmp(reason, "ml-block") == 0 ||
				 strcmp(reason, "ml-alert") == 0)) {
			sid_str = "ML-ANOMALY";
		} else {
			snprintf(sid_buf, sizeof(sid_buf), "%u", sid);
			sid_str = sid_buf;
		}

		/* Label when a rule has no msg: only call it "ML anomaly" when reason is
		 * ML — do NOT infer it from sid==0 (a signature rule missing the sid
		 * keyword is also 0). */
		int is_ml = (strncmp(reason, "ml-", 3) == 0);
		const char *msg_disp = msg_rest[0] ? msg_rest :
				(is_ml ? "ML anomaly detection" : "signature match (no msg)");

		if (!first) {
			if (pos + 2 < cap) { json[pos++] = ','; json[pos++] = '\n'; }
		}
		first = 0;

		int n = snprintf(json + pos, cap - pos,
			"{\"ts\":\"%s\",\"verdict\":\"%s\",\"proto\":%u,"
			"\"src\":\"%s\",\"sport\":%u,\"dst\":\"%s\",\"dport\":%u,"
			"\"reason\":\"%s\",\"score\":%.3f,\"sid\":\"%s\",\"msg\":\"%s\"}",
			ts, verdict, proto,
			src, sport, dst, dport,
			reason, score, sid_str, msg_disp);
		if (n > 0 && (size_t)n < cap - pos) pos += (size_t)n;

		p = nl ? nl + 1 : p + llen;
	}
	free(raw);

	if (pos + 2 < cap) { json[pos++] = ']'; json[pos] = '\0'; }
	send_ok(client_fd, NULL, json);
	free(json);
	return 0;
}

/* ── SG_CMD_IPS_SIGNATURES (686) ───────────────────────────────────────── */

int handle_ips_signatures(int client_fd, const char *user,
			  const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "configure")) {
		send_error(client_fd, SG_ERR_PERM_DENIED, "configure required");
		return 0;
	}

	/* Server-side SEARCH: filter keyword (the IPC response is limited to 64KB). */
	char q[128] = "";
	if (payload && payload[0])
		extract_val(payload, "q", q, sizeof(q));

	/*
	 * CACHE for the NO-keyword case (opening the Rules / Add-Signatures tab) —
	 * this is the IPS page's heaviest request: 1 + 2N DB queries (N rulesets) +
	 * reading/parsing the repo. mgmtd is a resident process with a single-threaded
	 * accept loop, so a static cache is safe and needs no lock.
	 *
	 * Key = mtime(repo dir) + mtime(DB file). Every change bumps one of the two:
	 * downloading a ruleset (mv the file into the repo + set last-downloaded in the
	 * DB), or deleting/editing a ruleset (DB write). → the cache never serves stale
	 * data. A request WITH a keyword is always computed fresh (not cached).
	 */
	static char  *sigcache;          /* JSON response no-query (NUL-term) */
	static time_t sc_repo_s, sc_db_s;
	static long   sc_repo_n, sc_db_n;
	int    q_empty = (q[0] == '\0');
	time_t r_s = 0, d_s = 0; long r_n = 0, d_n = 0;
	if (q_empty) {
		struct stat st;
		if (stat("/etc/stargazer/ips/repo", &st) == 0) {
			r_s = st.st_mtim.tv_sec; r_n = st.st_mtim.tv_nsec;
		}
		if (stat(SG_DB_PATH, &st) == 0) {
			d_s = st.st_mtim.tv_sec; d_n = st.st_mtim.tv_nsec;
		}
		if (sigcache && sc_repo_s == r_s && sc_repo_n == r_n &&
		    sc_db_s == d_s && sc_db_n == d_n) {
			send_ok(client_fd, NULL, sigcache);  /* cache hit → immediate */
			return 0;
		}
	}

	/*
	 * Build allowed-category list from DB entries that have been
	 * downloaded (last-downloaded is non-empty).  Derive the category
	 * name from the URL the same way run_ips_update_now does:
	 *   basename(url) → strip ".rules" → strip leading "emerging-"
	 * Only files whose stem is in this list appear in the catalog.
	 */
#define MAX_ALLOWED 64
	char  cat_bufs[MAX_ALLOWED][128];
	const char *allowed[MAX_ALLOWED];
	int n_allowed = 0;

	char *ids = sg_db_list("security_ips-ruleset");
	if (ids) {
		char *sp = NULL;
		for (char *id = strtok_r(ids, "\n", &sp);
		     id && n_allowed < MAX_ALLOWED;
		     id = strtok_r(NULL, "\n", &sp)) {
			char *lastdl = sg_db_get_val("security_ips-ruleset", id,
						     "last-downloaded");
			if (!lastdl || !lastdl[0]) { free(lastdl); continue; }
			free(lastdl);
			char *url = sg_db_get_val("security_ips-ruleset", id, "url");
			if (!url || !url[0]) { free(url); continue; }
			/* basename */
			const char *base = strrchr(url, '/');
			base = base ? base + 1 : url;
			snprintf(cat_bufs[n_allowed], 128, "%s", base);
			/* strip .rules */
			char *dot = strrchr(cat_bufs[n_allowed], '.');
			if (dot && strcmp(dot, ".rules") == 0) *dot = '\0';
			/* strip leading "emerging-" */
			const char *cat = cat_bufs[n_allowed];
			if (strncmp(cat, "emerging-", 9) == 0) cat += 9;
			if (cat != cat_bufs[n_allowed])
				memmove(cat_bufs[n_allowed], cat, strlen(cat) + 1);
			allowed[n_allowed] = cat_bufs[n_allowed];
			n_allowed++;
			free(url);
		}
		free(ids);
	}
#undef MAX_ALLOWED

	if (n_allowed == 0) {
		static const char EMPTY[] =
			"{\"items\":[],\"categories\":[],\"truncated\":0}";
		if (q_empty) {
			free(sigcache);
			sigcache = strdup(EMPTY);
			sc_repo_s = r_s; sc_repo_n = r_n;
			sc_db_s = d_s; sc_db_n = d_n;
		}
		send_ok(client_fd, NULL, EMPTY);
		return 0;
	}

	/* The FULL category list (every downloaded ruleset) for the Filter dropdown —
	 * taken from allowed[] (DB), NOT subject to the catalog items' 64KB limit.
	 * 64 cats × ~128 chars + quotes/commas < 9 KB. */
	char catj[9216];
	size_t cj = 0;
	cj += (size_t)snprintf(catj + cj, sizeof(catj) - cj, ",\"categories\":[");
	for (int i = 0; i < n_allowed; i++) {
		const char *c = allowed[i];
		cj += (size_t)snprintf(catj + cj, sizeof(catj) - cj, "%s\"",
				       i ? "," : "");
		/* category = stem filename (safe) — only block JSON-breaking chars */
		for (const char *s = c; *s && cj + 2 < sizeof(catj); s++)
			if (*s != '"' && *s != '\\' && (unsigned char)*s >= 0x20)
				catj[cj++] = *s;
		if (cj + 1 < sizeof(catj)) catj[cj++] = '"';
	}
	if (cj + 1 < sizeof(catj)) catj[cj++] = ']';
	catj[cj] = '\0';

	char *json = malloc(SG_RESPONSE_MAX);
	if (!json) {
		send_error(client_fd, SG_ERR_SYSTEM_FAIL, "Out of memory");
		return 0;
	}
	/* Wrap into an object {items, categories, truncated}. truncated tells the
	 * frontend when catalog items were cut (large ruleset → "narrow your keyword").
	 * categories is always complete. Reserve = len(catj) + len(",\"truncated\":N}")
	 * + margin. */
	int trunc = 0;
	const char *PFX = "{\"items\":";
	size_t off = strlen(PFX);
	size_t reserve = cj + 32;
	memcpy(json, PFX, off);
	int n = ips_catalog_to_json("/etc/stargazer/ips/repo", json + off,
				    SG_RESPONSE_MAX - off - reserve, allowed, n_allowed,
				    q[0] ? q : NULL, &trunc);
	if (n < 0) {
		free(json);
		send_ok(client_fd, NULL, "{\"items\":[],\"categories\":[],\"truncated\":0}");
		return 0;
	}
	off += (size_t)n;
	memcpy(json + off, catj, cj); off += cj;
	off += (size_t)snprintf(json + off, SG_RESPONSE_MAX - off,
				",\"truncated\":%d}", trunc);
	if (q_empty) {            /* store cache (json is NUL-terminated at off) */
		free(sigcache);
		sigcache = strdup(json);
		sc_repo_s = r_s; sc_repo_n = r_n;
		sc_db_s = d_s; sc_db_n = d_n;
	}
	send_ok(client_fd, NULL, json);
	free(json);
	return 0;
}

/* ── SG_CMD_DIAG_IFACE_STATS (643) ────────────────────────────────────── */

int handle_diag_iface_stats(int client_fd, const char *user,
			    const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	char resp[SG_RESPONSE_MAX];
	size_t pos = 0;

	/* /proc/net/dev */
	char netdev[4096];
	if (read_small_file("/proc/net/dev", netdev, sizeof(netdev)) > 0) {
		const char *p = netdev;
		/* Skip 2 header lines */
		for (int h = 0; h < 2 && *p; h++) {
			const char *nl = strchr(p, '\n');
			if (!nl) break;
			p = nl + 1;
		}
		while (*p) {
			const char *eol = strchr(p, '\n');
			size_t llen = eol ? (size_t)(eol - p) : strlen(p);
			if (llen > 0) {
				/* Extract iface name */
				const char *s = p;
				while (*s == ' ') s++;
				const char *colon = memchr(s, ':', llen - (size_t)(s - p));
				if (colon) {
					char iname[32];
					size_t nlen = (size_t)(colon - s);
					if (nlen >= sizeof(iname))
						nlen = sizeof(iname) - 1;
					memcpy(iname, s, nlen);
					iname[nlen] = '\0';

					/* Skip lo */
					if (strcmp(iname, "lo") != 0) {
						/* /proc/net/dev fields after colon:
						 * rx: bytes packets errs drop fifo frame compressed multicast
						 * tx: bytes packets errs drop fifo colls carrier compressed */
						const char *fp = colon + 1;
						while (*fp == ' ') fp++;
						unsigned long long rx_bytes = strtoull(fp, NULL, 10);
						unsigned long long vals[16];
						vals[0] = rx_bytes;
						for (int f = 1; f < 16; f++) {
							while (*fp && *fp != ' ' && *fp != '\n') fp++;
							while (*fp == ' ') fp++;
							vals[f] = strtoull(fp, NULL, 10);
						}
						/* vals: 0=rx_bytes 1=rx_pkts 2=rx_errs 3=rx_drop
						 *       8=tx_bytes 9=tx_pkts 10=tx_errs 11=tx_drop */

						buf_appendf(resp, sizeof(resp), &pos,
							    "iface=%s rx_bytes=%llu tx_bytes=%llu"
							    " rx_pkts=%llu tx_pkts=%llu"
							    " rx_errs=%llu tx_errs=%llu"
							    " rx_drop=%llu tx_drop=%llu",
							    iname, vals[0], vals[8],
							    vals[1], vals[9],
							    vals[2], vals[10],
							    vals[3], vals[11]);

						/* Link speed */
						char spath[128], sbuf[64];
						snprintf(spath, sizeof(spath),
							 "/sys/class/net/%s/speed", iname);
						if (read_small_file(spath, sbuf, sizeof(sbuf)) > 0) {
							size_t slen = strlen(sbuf);
							while (slen > 0 && (sbuf[slen-1] == '\n' || sbuf[slen-1] == '\r'))
								sbuf[--slen] = '\0';
							buf_appendf(resp, sizeof(resp), &pos,
								    " speed=%s", sbuf);
						}

						/* Operstate (up/down) */
						snprintf(spath, sizeof(spath),
							 "/sys/class/net/%s/operstate", iname);
						if (read_small_file(spath, sbuf, sizeof(sbuf)) > 0) {
							size_t slen = strlen(sbuf);
							while (slen > 0 && (sbuf[slen-1] == '\n' || sbuf[slen-1] == '\r'))
								sbuf[--slen] = '\0';
							buf_appendf(resp, sizeof(resp), &pos,
								    " state=%s", sbuf);
						}

						/* MAC address */
						snprintf(spath, sizeof(spath),
							 "/sys/class/net/%s/address", iname);
						if (read_small_file(spath, sbuf, sizeof(sbuf)) > 0) {
							size_t slen = strlen(sbuf);
							while (slen > 0 && (sbuf[slen-1] == '\n' || sbuf[slen-1] == '\r'))
								sbuf[--slen] = '\0';
							buf_appendf(resp, sizeof(resp), &pos,
								    " mac=%s", sbuf);
						}

						/* MTU */
						snprintf(spath, sizeof(spath),
							 "/sys/class/net/%s/mtu", iname);
						if (read_small_file(spath, sbuf, sizeof(sbuf)) > 0) {
							size_t slen = strlen(sbuf);
							while (slen > 0 && (sbuf[slen-1] == '\n' || sbuf[slen-1] == '\r'))
								sbuf[--slen] = '\0';
							buf_appendf(resp, sizeof(resp), &pos,
								    " mtu=%s", sbuf);
						}

						buf_appendf(resp, sizeof(resp), &pos, "\n");
					}
				}
			}
			if (!eol) break;
			p = eol + 1;
		}
	}

	send_ok(client_fd, NULL, pos > 0 ? resp : NULL);
	return 0;
}

/* ── SG_CMD_DIAG_PROCTOP (644) ─────────────────────────────────────────── */

int handle_diag_proctop(int client_fd, const char *user,
			const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	char resp[SG_RESPONSE_MAX];
	size_t pos = 0;

	/* CPU aggregate from /proc/stat */
	char stat_buf[2048];
	if (read_small_file("/proc/stat", stat_buf, sizeof(stat_buf)) > 0) {
		const char *p = stat_buf;
		const char *eol = strchr(p, '\n');
		if (eol && strncmp(p, "cpu ", 4) == 0)
			buf_appendf(resp, sizeof(resp), &pos,
				    "%.*s\n", (int)(eol - p), p);
	}

	/* Memory */
	char meminfo[2048];
	if (read_small_file("/proc/meminfo", meminfo, sizeof(meminfo)) > 0) {
		long mt = 0, ma = 0;
		const char *p = meminfo;
		while (*p) {
			if (strncmp(p, "MemTotal:", 9) == 0)
				mt = atol(p + 9);
			else if (strncmp(p, "MemAvailable:", 13) == 0)
				ma = atol(p + 13);
			const char *nl = strchr(p, '\n');
			if (!nl) break;
			p = nl + 1;
		}
		buf_appendf(resp, sizeof(resp), &pos,
			    "mem_total_kb=%ld\nmem_avail_kb=%ld\n", mt, ma);
	}

	/* Uptime */
	char uptbuf[64];
	if (read_small_file("/proc/uptime", uptbuf, sizeof(uptbuf)) > 0) {
		size_t len = strlen(uptbuf);
		while (len > 0 && (uptbuf[len-1] == '\n' || uptbuf[len-1] == '\r'))
			uptbuf[--len] = '\0';
		buf_appendf(resp, sizeof(resp), &pos, "uptime=%s\n", uptbuf);
	}

	/* Load average */
	char lavg[64];
	if (read_small_file("/proc/loadavg", lavg, sizeof(lavg)) > 0) {
		size_t len = strlen(lavg);
		while (len > 0 && (lavg[len-1] == '\n' || lavg[len-1] == '\r'))
			lavg[--len] = '\0';
		buf_appendf(resp, sizeof(resp), &pos, "loadavg=%s\n", lavg);
	}

	/* Process list */
	DIR *dir = opendir("/proc");
	if (dir) {
		struct dirent *ent;
		while ((ent = readdir(dir)) != NULL) {
			if (!isdigit((unsigned char)ent->d_name[0]))
				continue;

			char path[280], pbuf[512];
			snprintf(path, sizeof(path),
				 "/proc/%s/stat", ent->d_name);
			if (read_small_file(path, pbuf, sizeof(pbuf)) <= 0)
				continue;

			int pid = atoi(pbuf);
			const char *lp = strchr(pbuf, '(');
			const char *rp = strrchr(pbuf, ')');
			if (!lp || !rp || rp <= lp)
				continue;

			char comm[64];
			size_t clen = (size_t)(rp - lp - 1);
			if (clen >= sizeof(comm))
				clen = sizeof(comm) - 1;
			memcpy(comm, lp + 1, clen);
			comm[clen] = '\0';

			const char *pp = rp + 1;
			while (*pp == ' ') pp++;
			char state = *pp ? *pp : '?';

			/* Skip to field 14 (utime) */
			for (int f = 4; f <= 13 && *pp; f++) {
				while (*pp && *pp != ' ') pp++;
				while (*pp == ' ') pp++;
			}
			unsigned long utime = strtoul(pp, NULL, 10);
			while (*pp && *pp != ' ') pp++;
			while (*pp == ' ') pp++;
			unsigned long stime = strtoul(pp, NULL, 10);

			/* Skip to field 23 (vsize) */
			for (int f = 16; f <= 22 && *pp; f++) {
				while (*pp && *pp != ' ') pp++;
				while (*pp == ' ') pp++;
			}
			unsigned long vsize = strtoul(pp, NULL, 10);

			/* Read VmRSS from /proc/<pid>/status (in kB).
			 * This is more reliable than field 24 of
			 * /proc/<pid>/stat (pages) which requires
			 * knowing the page size. */
			long rss_kb = 0;
			{
				char spath[280], sbuf[2048];
				snprintf(spath, sizeof(spath),
					 "/proc/%s/status", ent->d_name);
				if (read_small_file(spath, sbuf,
						    sizeof(sbuf)) > 0) {
					const char *vr = strstr(sbuf,
							"VmRSS:");
					if (vr)
						rss_kb = atol(vr + 6);
				}
			}

			buf_appendf(resp, sizeof(resp), &pos,
				    "proc=%d %s %c %lu %lu %lu %ld\n",
				    pid, comm, state,
				    utime, stime, vsize, rss_kb);

			/* Check remaining space */
			if (pos >= sizeof(resp) - 200)
				break;
		}
		closedir(dir);
	}

	send_ok(client_fd, NULL, pos > 0 ? resp : NULL);
	return 0;
}

/* ── SG_CMD_DIAG_THERMAL (645) ─────────────────────────────────────────── */

int handle_diag_thermal(int client_fd, const char *user,
			const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	char resp[1024];
	size_t pos = 0;
	char path[128], tbuf[32];

	for (int z = 0; z < 16; z++) {
		snprintf(path, sizeof(path),
			 "/sys/class/thermal/thermal_zone%d/temp", z);
		if (read_small_file(path, tbuf, sizeof(tbuf)) > 0) {
			size_t len = strlen(tbuf);
			while (len > 0 && (tbuf[len-1] == '\n' || tbuf[len-1] == '\r'))
				tbuf[--len] = '\0';
			buf_appendf(resp, sizeof(resp), &pos,
				    "thermal_zone%d=%s\n", z, tbuf);
		}
	}

	send_ok(client_fd, NULL, pos > 0 ? resp : NULL);
	return 0;
}

/* ── SG_CMD_DIAG_DISK_HEALTH (646) ─────────────────────────────────────── */

int handle_diag_disk_health(int client_fd, const char *user,
			    const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	char resp[2048];
	size_t pos = 0;

	/* --- sgdata: /etc/stargazer --- */
	int sgdata_mounted = 0;
	char sgdata_fstype[32] = "unknown";
	{
		/* Parse /proc/mounts for /etc/stargazer */
		char mounts[4096];
		if (read_small_file("/proc/mounts", mounts, sizeof(mounts)) > 0) {
			const char *p = mounts;
			while (*p) {
				const char *eol = strchr(p, '\n');
				size_t llen = eol ? (size_t)(eol - p) : strlen(p);

				/* Fields: device mountpoint fstype ... */
				const char *f1 = p;
				while (f1 < p + llen && *f1 != ' ') f1++;
				if (f1 < p + llen) f1++;
				const char *f2 = f1;
				while (f2 < p + llen && *f2 != ' ') f2++;
				size_t mplen = (size_t)(f2 - f1);

				if (mplen == 14 &&
				    strncmp(f1, "/etc/stargazer", 14) == 0 &&
				    (f2 >= p + llen || *f2 == ' ')) {
					sgdata_mounted = 1;
					if (f2 < p + llen) {
						const char *f3 = f2 + 1;
						const char *f3e = f3;
						while (f3e < p + llen && *f3e != ' ')
							f3e++;
						size_t tlen = (size_t)(f3e - f3);
						if (tlen >= sizeof(sgdata_fstype))
							tlen = sizeof(sgdata_fstype) - 1;
						memcpy(sgdata_fstype, f3, tlen);
						sgdata_fstype[tlen] = '\0';
					}
				}

				if (!eol) break;
				p = eol + 1;
			}
		}
	}

	buf_appendf(resp, sizeof(resp), &pos,
		    "sgdata_mounted=%d\nsgdata_fstype=%s\n",
		    sgdata_mounted, sgdata_fstype);

	/* sgdata writable — touch + remove temp file */
	int sgdata_writable = 0;
	if (sgdata_mounted) {
		const char *tmp = "/etc/stargazer/.health_check";
		int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd >= 0) {
			sgdata_writable = 1;
			close(fd);
			unlink(tmp);
		}
	}
	buf_appendf(resp, sizeof(resp), &pos,
		    "sgdata_writable=%d\n", sgdata_writable);

	/* sgdata usage percentage */
	struct statvfs sv;
	int sgdata_pct_used = -1;
	if (sgdata_mounted && statvfs("/etc/stargazer", &sv) == 0 &&
	    sv.f_blocks > 0) {
		unsigned long used = sv.f_blocks - sv.f_bfree;
		sgdata_pct_used = (int)((used * 100) / sv.f_blocks);
	}
	buf_appendf(resp, sizeof(resp), &pos,
		    "sgdata_pct_used=%d\n", sgdata_pct_used);

	/* sgdata DB file exists */
	int sgdata_db_exists = (access("/etc/stargazer/stargazer.db",
				       F_OK) == 0) ? 1 : 0;
	buf_appendf(resp, sizeof(resp), &pos,
		    "sgdata_db_exists=%d\n", sgdata_db_exists);

	/* --- sglogs: /etc/stargazer/logs --- */
	int sglogs_mounted = 0;
	char sglogs_fstype[32] = "unknown";
	{
		char mounts[4096];
		if (read_small_file("/proc/mounts", mounts, sizeof(mounts)) > 0) {
			const char *p = mounts;
			while (*p) {
				const char *eol = strchr(p, '\n');
				size_t llen = eol ? (size_t)(eol - p) : strlen(p);

				const char *f1 = p;
				while (f1 < p + llen && *f1 != ' ') f1++;
				if (f1 < p + llen) f1++;
				const char *f2 = f1;
				while (f2 < p + llen && *f2 != ' ') f2++;
				size_t mplen = (size_t)(f2 - f1);

				if (mplen == 19 &&
				    strncmp(f1, "/etc/stargazer/logs", 19) == 0 &&
				    (f2 >= p + llen || *f2 == ' ')) {
					sglogs_mounted = 1;
					if (f2 < p + llen) {
						const char *f3 = f2 + 1;
						const char *f3e = f3;
						while (f3e < p + llen && *f3e != ' ')
							f3e++;
						size_t tlen = (size_t)(f3e - f3);
						if (tlen >= sizeof(sglogs_fstype))
							tlen = sizeof(sglogs_fstype) - 1;
						memcpy(sglogs_fstype, f3, tlen);
						sglogs_fstype[tlen] = '\0';
					}
				}

				if (!eol) break;
				p = eol + 1;
			}
		}
	}

	buf_appendf(resp, sizeof(resp), &pos,
		    "sglogs_mounted=%d\nsglogs_fstype=%s\n",
		    sglogs_mounted, sglogs_fstype);

	/* sglogs writable */
	int sglogs_writable = 0;
	if (sglogs_mounted) {
		const char *tmp = "/etc/stargazer/logs/.health_check";
		int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd >= 0) {
			sglogs_writable = 1;
			close(fd);
			unlink(tmp);
		}
	}
	buf_appendf(resp, sizeof(resp), &pos,
		    "sglogs_writable=%d\n", sglogs_writable);

	/* sglogs usage percentage */
	int sglogs_pct_used = -1;
	if (sglogs_mounted && statvfs("/etc/stargazer/logs", &sv) == 0 &&
	    sv.f_blocks > 0) {
		unsigned long used = sv.f_blocks - sv.f_bfree;
		sglogs_pct_used = (int)((used * 100) / sv.f_blocks);
	}
	buf_appendf(resp, sizeof(resp), &pos,
		    "sglogs_pct_used=%d\n", sglogs_pct_used);

	/* --- eMMC block device --- */
	unsigned long long emmc_bytes = 0;
	const char *emmc_dev = "none";
	{
		char sbuf[64];
		if (read_small_file("/sys/block/mmcblk0/size",
				    sbuf, sizeof(sbuf)) > 0) {
			emmc_bytes = strtoull(sbuf, NULL, 10) * 512ULL;
			emmc_dev = "/dev/mmcblk0";
		}
	}
	buf_appendf(resp, sizeof(resp), &pos,
		    "emmc_dev=%s\nemmc_bytes=%llu\n",
		    emmc_dev, emmc_bytes);

	send_ok(client_fd, NULL, resp);
	return 0;
}

/* ── Helper: strip trailing newlines/whitespace ────────────────────────── */

static void strip_trailing(char *s)
{
	size_t len = strlen(s);
	while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' ||
			   s[len - 1] == ' '))
		s[--len] = '\0';
}

/* ── Helper: find mount point for a device from /proc/mounts ──────────── */

/*
 * Parse /proc/mounts and collect mount points for /dev/<devname>.
 * Appends comma-separated mount points to buf at *pos.
 * Returns count of mounts found.
 */
static int collect_mounts(const char *devname, char *buf, size_t bufsz,
			  size_t *pos)
{
	char mounts[8192];
	if (read_small_file("/proc/mounts", mounts, sizeof(mounts)) <= 0)
		return 0;

	char devpath[128];
	snprintf(devpath, sizeof(devpath), "/dev/%s", devname);
	size_t dplen = strlen(devpath);

	int count = 0;
	const char *p = mounts;
	while (*p) {
		const char *eol = strchr(p, '\n');
		size_t llen = eol ? (size_t)(eol - p) : strlen(p);

		/* Match device field */
		if (llen > dplen && strncmp(p, devpath, dplen) == 0 &&
		    p[dplen] == ' ') {
			/* Extract mount point (second field) */
			const char *mp = p + dplen + 1;
			const char *mpe = mp;
			while (mpe < p + llen && *mpe != ' ')
				mpe++;
			size_t mplen = (size_t)(mpe - mp);

			if (count > 0)
				buf_appendf(buf, bufsz, pos, ",");
			buf_appendf(buf, bufsz, pos, "%.*s", (int)mplen, mp);
			count++;
		}

		if (!eol) break;
		p = eol + 1;
	}
	return count;
}

/* ── Helper: find mount point + fstype for a device ───────────────────── */

static void get_mount_info(const char *devname, char *mp_out, size_t mpsz,
			   char *fs_out, size_t fssz)
{
	mp_out[0] = '\0';
	fs_out[0] = '\0';

	char mounts[8192];
	if (read_small_file("/proc/mounts", mounts, sizeof(mounts)) <= 0)
		return;

	char devpath[128];
	snprintf(devpath, sizeof(devpath), "/dev/%s", devname);
	size_t dplen = strlen(devpath);

	const char *p = mounts;
	while (*p) {
		const char *eol = strchr(p, '\n');
		size_t llen = eol ? (size_t)(eol - p) : strlen(p);

		if (llen > dplen && strncmp(p, devpath, dplen) == 0 &&
		    p[dplen] == ' ') {
			/* mount point */
			const char *mp = p + dplen + 1;
			const char *mpe = mp;
			while (mpe < p + llen && *mpe != ' ')
				mpe++;
			size_t mplen = (size_t)(mpe - mp);
			if (mplen >= mpsz) mplen = mpsz - 1;
			memcpy(mp_out, mp, mplen);
			mp_out[mplen] = '\0';

			/* fstype (third field) */
			if (mpe < p + llen) {
				const char *fs = mpe + 1;
				const char *fse = fs;
				while (fse < p + llen && *fse != ' ')
					fse++;
				size_t fslen = (size_t)(fse - fs);
				if (fslen >= fssz) fslen = fssz - 1;
				memcpy(fs_out, fs, fslen);
				fs_out[fslen] = '\0';
			}
			return;
		}

		if (!eol) break;
		p = eol + 1;
	}
}

/* ── SG_CMD_DISK_LIST (647) ────────────────────────────────────────────── */

int handle_disk_list(int client_fd, const char *user,
		     const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	char resp[SG_RESPONSE_MAX];
	size_t pos = 0;

	DIR *dir = opendir("/sys/block");
	if (!dir) {
		send_error(client_fd, SG_ERR_IO_FAIL,
			   "cannot read /sys/block");
		return 0;
	}

	struct dirent *ent;
	while ((ent = readdir(dir)) != NULL) {
		const char *name = ent->d_name;

		/* Skip . .. loop* ram* and names that are too long */
		if (name[0] == '.')
			continue;
		if (strncmp(name, "loop", 4) == 0)
			continue;
		if (strncmp(name, "ram", 3) == 0)
			continue;
		if (strlen(name) > 64)
			continue;

		/* Read size (512-byte sectors) */
		char path[128], sbuf[64];
		snprintf(path, sizeof(path), "/sys/block/%.64s/size", name);
		unsigned long long size_bytes = 0;
		if (read_small_file(path, sbuf, sizeof(sbuf)) > 0)
			size_bytes = strtoull(sbuf, NULL, 10) * 512ULL;

		/* Read model if available */
		char model[128] = "";
		snprintf(path, sizeof(path),
			 "/sys/block/%.64s/device/model", name);
		if (read_small_file(path, model, sizeof(model)) > 0)
			strip_trailing(model);

		/* Collect mount points */
		buf_appendf(resp, sizeof(resp), &pos,
			    "dev=%s size_bytes=%llu model=%s mounts=",
			    name, size_bytes,
			    model[0] ? model : "(none)");

		size_t mnt_start = pos;
		/* List partitions under /sys/block/<dev>/ */
		char bpath[128];
		snprintf(bpath, sizeof(bpath), "/sys/block/%.64s", name);
		DIR *pdir = opendir(bpath);
		if (pdir) {
			struct dirent *pent;
			while ((pent = readdir(pdir)) != NULL) {
				if (strlen(pent->d_name) > 64)
					continue;
				/* Partition dirs start with the device name */
				if (strncmp(pent->d_name, name,
					    strlen(name)) != 0)
					continue;
				if (strcmp(pent->d_name, name) == 0)
					continue;
				/* Check it has a 'size' file (is a partition) */
				char pspath[196];
				snprintf(pspath, sizeof(pspath),
					 "/sys/block/%.64s/%.64s/size",
					 name, pent->d_name);
				if (access(pspath, F_OK) == 0) {
					if (pos > mnt_start)
						buf_appendf(resp, sizeof(resp),
							    &pos, ",");
					collect_mounts(pent->d_name,
						       resp,
						       sizeof(resp),
						       &pos);
				}
			}
			closedir(pdir);
		}

		/* Also check whole-device mounts */
		{
			size_t before = pos;
			if (pos > mnt_start)
				buf_appendf(resp, sizeof(resp), &pos, ",");
			collect_mounts(name, resp, sizeof(resp), &pos);
			/* Remove trailing comma if no mounts were added */
			if (pos == before + 1 && resp[before] == ',')
				resp[pos = before] = '\0';
		}

		if (pos == mnt_start)
			buf_appendf(resp, sizeof(resp), &pos, "(none)");

		buf_appendf(resp, sizeof(resp), &pos, "\n");

		if (pos >= sizeof(resp) - 512)
			break;
	}
	closedir(dir);

	send_ok(client_fd, NULL, pos > 0 ? resp : "No block devices found.\n");
	return 0;
}

/* ── SG_CMD_DISK_INFO (648) ────────────────────────────────────────────── */

int handle_disk_info(int client_fd, const char *user,
		     const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	if (!payload || !payload[0]) {
		send_error(client_fd, SG_ERR_MISSING_ARG,
			   "device name required");
		return 0;
	}

	/* Validate: alnum + underscore only, max 64 chars (prevent path traversal) */
	size_t plen = strlen(payload);
	if (plen > 64) {
		send_error(client_fd, SG_ERR_INVALID_ARG,
			   "device name too long");
		return 0;
	}
	for (const char *p = payload; *p; p++) {
		if (!isalnum((unsigned char)*p) && *p != '_') {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "invalid device name (alnum/underscore only)");
			return 0;
		}
	}

	char resp[SG_RESPONSE_MAX];
	size_t pos = 0;

	/* Check if whole disk */
	char syspath[128];
	snprintf(syspath, sizeof(syspath), "/sys/block/%.64s", payload);
	struct stat st;
	int is_disk = (stat(syspath, &st) == 0 && S_ISDIR(st.st_mode));

	if (is_disk) {
		/* ── Whole disk info ── */
		buf_appendf(resp, sizeof(resp), &pos,
			    "type=disk\ndev=%s\n", payload);

		/* Size */
		char path[128], sbuf[64];
		snprintf(path, sizeof(path),
			 "/sys/block/%.64s/size", payload);
		if (read_small_file(path, sbuf, sizeof(sbuf)) > 0) {
			unsigned long long bytes =
				strtoull(sbuf, NULL, 10) * 512ULL;
			buf_appendf(resp, sizeof(resp), &pos,
				    "size_bytes=%llu\n", bytes);
		}

		/* Model */
		char val[128];
		snprintf(path, sizeof(path),
			 "/sys/block/%.64s/device/model", payload);
		if (read_small_file(path, val, sizeof(val)) > 0) {
			strip_trailing(val);
			buf_appendf(resp, sizeof(resp), &pos,
				    "model=%s\n", val);
		}

		/* Serial */
		snprintf(path, sizeof(path),
			 "/sys/block/%.64s/device/serial", payload);
		if (read_small_file(path, val, sizeof(val)) > 0) {
			strip_trailing(val);
			buf_appendf(resp, sizeof(resp), &pos,
				    "serial=%s\n", val);
		}

		/* Removable */
		snprintf(path, sizeof(path),
			 "/sys/block/%.64s/removable", payload);
		if (read_small_file(path, sbuf, sizeof(sbuf)) > 0) {
			strip_trailing(sbuf);
			buf_appendf(resp, sizeof(resp), &pos,
				    "removable=%s\n", sbuf);
		}

		/* Read-only */
		snprintf(path, sizeof(path),
			 "/sys/block/%.64s/ro", payload);
		if (read_small_file(path, sbuf, sizeof(sbuf)) > 0) {
			strip_trailing(sbuf);
			buf_appendf(resp, sizeof(resp), &pos,
				    "ro=%s\n", sbuf);
		}

		/* List partitions */
		DIR *pdir = opendir(syspath);
		if (pdir) {
			struct dirent *pent;
			while ((pent = readdir(pdir)) != NULL) {
				if (strlen(pent->d_name) > 64)
					continue;
				if (strncmp(pent->d_name, payload,
					    plen) != 0)
					continue;
				if (strcmp(pent->d_name, payload) == 0)
					continue;

				char pspath[196];
				snprintf(pspath, sizeof(pspath),
					 "/sys/block/%.64s/%.64s/size",
					 payload, pent->d_name);
				if (read_small_file(pspath, sbuf,
						    sizeof(sbuf)) <= 0)
					continue;

				unsigned long long pbytes =
					strtoull(sbuf, NULL, 10) * 512ULL;

				char mp[256], fs[64];
				get_mount_info(pent->d_name, mp, sizeof(mp),
					       fs, sizeof(fs));

				buf_appendf(resp, sizeof(resp), &pos,
					    "partition=%s size_bytes=%llu"
					    " mount=%s fstype=%s\n",
					    pent->d_name, pbytes,
					    mp[0] ? mp : "(none)",
					    fs[0] ? fs : "(none)");
			}
			closedir(pdir);
		}
	} else {
		/* Partition: find parent in /sys/block */
		int found = 0;
		DIR *bdir = opendir("/sys/block");
		if (bdir) {
			struct dirent *bent;
			while ((bent = readdir(bdir)) != NULL) {
				if (bent->d_name[0] == '.')
					continue;
				if (strlen(bent->d_name) > 64)
					continue;
				char pspath[196];
				snprintf(pspath, sizeof(pspath),
					 "/sys/block/%.64s/%.64s/size",
					 bent->d_name, payload);
				char sbuf[64];
				if (read_small_file(pspath, sbuf,
						    sizeof(sbuf)) <= 0)
					continue;

				found = 1;
				unsigned long long pbytes =
					strtoull(sbuf, NULL, 10) * 512ULL;

				buf_appendf(resp, sizeof(resp), &pos,
					    "type=partition\ndev=%s\n"
					    "parent=%s\nsize_bytes=%llu\n",
					    payload, bent->d_name, pbytes);

				/* Start offset */
				snprintf(pspath, sizeof(pspath),
					 "/sys/block/%.64s/%.64s/start",
					 bent->d_name, payload);
				if (read_small_file(pspath, sbuf,
						    sizeof(sbuf)) > 0) {
					strip_trailing(sbuf);
					buf_appendf(resp, sizeof(resp), &pos,
						    "start_sector=%s\n",
						    sbuf);
				}

				/* Mount + fstype */
				char mp[256], fs[64];
				get_mount_info(payload, mp, sizeof(mp),
					       fs, sizeof(fs));
				buf_appendf(resp, sizeof(resp), &pos,
					    "mount=%s\nfstype=%s\n",
					    mp[0] ? mp : "(none)",
					    fs[0] ? fs : "(none)");
				break;
			}
			closedir(bdir);
		}

		if (!found) {
			send_error(client_fd, SG_ERR_NOT_FOUND,
				   "device or partition not found in sysfs");
			return 0;
		}
	}

	/* Run blkid for UUID/LABEL/TYPE */
	char devpath[128];
	snprintf(devpath, sizeof(devpath), "/dev/%s", payload);
	const char *argv[] = {"blkid", devpath, NULL};
	char *blkid_out = safe_exec(argv);
	if (blkid_out && blkid_out[0]) {
		strip_trailing(blkid_out);
		buf_appendf(resp, sizeof(resp), &pos,
			    "blkid=%s\n", blkid_out);
	}
	free(blkid_out);

	send_ok(client_fd, NULL, pos > 0 ? resp : NULL);
	return 0;
}

/* ── SG_CMD_DISK_SMART (649) ──────────────────────────────────────────── */

int handle_disk_smart(int client_fd, const char *user,
		      const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	char resp[2048];
	size_t pos = 0;
	char val[128];

	/* life_time: two hex values (typeA typeB), 0x01-0x0A = 0-100% wear */
	if (read_small_file("/sys/block/mmcblk0/device/life_time",
			    val, sizeof(val)) > 0) {
		strip_trailing(val);
		buf_appendf(resp, sizeof(resp), &pos,
			    "life_time=%s\n", val);
	} else {
		buf_appendf(resp, sizeof(resp), &pos,
			    "life_time=unavailable\n");
	}

	/* pre_eol_info: 0x01=normal, 0x02=warning, 0x03=urgent */
	if (read_small_file("/sys/block/mmcblk0/device/pre_eol_info",
			    val, sizeof(val)) > 0) {
		strip_trailing(val);
		buf_appendf(resp, sizeof(resp), &pos,
			    "pre_eol_info=%s\n", val);
	} else {
		buf_appendf(resp, sizeof(resp), &pos,
			    "pre_eol_info=unavailable\n");
	}

	/* Device name */
	if (read_small_file("/sys/block/mmcblk0/device/name",
			    val, sizeof(val)) > 0) {
		strip_trailing(val);
		buf_appendf(resp, sizeof(resp), &pos, "name=%s\n", val);
	}

	/* Firmware revision */
	if (read_small_file("/sys/block/mmcblk0/device/fwrev",
			    val, sizeof(val)) > 0) {
		strip_trailing(val);
		buf_appendf(resp, sizeof(resp), &pos, "fwrev=%s\n", val);
	}

	/* Manufacturing date */
	if (read_small_file("/sys/block/mmcblk0/device/date",
			    val, sizeof(val)) > 0) {
		strip_trailing(val);
		buf_appendf(resp, sizeof(resp), &pos, "date=%s\n", val);
	}

	/* Card type */
	if (read_small_file("/sys/block/mmcblk0/device/type",
			    val, sizeof(val)) > 0) {
		strip_trailing(val);
		buf_appendf(resp, sizeof(resp), &pos, "type=%s\n", val);
	}

	/* Total size for reference */
	char sbuf[64];
	if (read_small_file("/sys/block/mmcblk0/size",
			    sbuf, sizeof(sbuf)) > 0) {
		unsigned long long bytes =
			strtoull(sbuf, NULL, 10) * 512ULL;
		buf_appendf(resp, sizeof(resp), &pos,
			    "size_bytes=%llu\n", bytes);
	}

	send_ok(client_fd, NULL, pos > 0 ? resp : "eMMC not found.\n");
	return 0;
}

/* ── nf_conntrack readers ───────────────────────────────────────────────────
 *
 * Connection state lives in the kernel's nf_conntrack. These read
 * /proc/net/nf_conntrack (file IO) and "clear" flushes via netlink in-process —
 * the firewall never shells out to system commands.
 */

/* Recognised L4 protocol names — anchors parsing whether or not the line
 * carries the legacy "ipv4 2 " L3 prefix. */
static const char *ct_l4_name(const char *t)
{
	if (!strcmp(t, "tcp") || !strcmp(t, "udp") || !strcmp(t, "icmp") ||
	    !strcmp(t, "icmpv6") || !strcmp(t, "udplite") ||
	    !strcmp(t, "sctp") || !strcmp(t, "dccp") || !strcmp(t, "gre"))
		return t;
	return NULL;
}

/* connmark layout — MUST match mgmtd_apply_firewall.c. A permitted flow is
 * stamped with its policy's cmkid in bits 8-31; bit 0 is the DIRTY flag. */
#define SG_CMK_DIRTY            0x00000001u
#define SG_CMK_PID_SHIFT        8
#define SG_CMK_PID_MASK         0xFFFFFF00u  /* cmkid occupies bits 8-31 */

/*
 * cmkid → policy display-name map, built once per session dump so the
 * per-line parse does no SQL. `name` is the policy's friendly name, or its
 * DB id when unnamed.
 */
struct ct_pol {
	unsigned cmkid;
	char     name[64];
};

/*
 * ct_policy_map_build - snapshot firewall_policy cmkid→name pairs.
 * Returns the entry count (>= 0); *out is malloc'd and the caller frees it
 * (even when the count is 0). Returns -1 on allocation failure.
 */
static int ct_policy_map_build(struct ct_pol **out)
{
	*out = NULL;

	char *list = sg_db_list("firewall_policy");
	if (!list)
		return 0;

	size_t cap = 16, n = 0;
	struct ct_pol *arr = malloc(cap * sizeof(*arr));
	if (!arr) {
		free(list);
		return -1;
	}

	char *sp = NULL;
	for (char *id = strtok_r(list, "\n", &sp); id;
	     id = strtok_r(NULL, "\n", &sp)) {
		char *cmk = sg_db_get_val("firewall_policy", id, "cmkid");
		if (!cmk)
			continue;               /* never stamped → not in map */
		unsigned cmkid = (unsigned)atoi(cmk);
		free(cmk);
		if (cmkid == 0)
			continue;

		if (n >= cap) {
			cap *= 2;
			struct ct_pol *nb = realloc(arr, cap * sizeof(*arr));
			if (!nb) {
				free(arr);
				free(list);
				return -1;
			}
			arr = nb;
		}
		arr[n].cmkid = cmkid;
		char *name = sg_db_get_val("firewall_policy", id, "name");
		snprintf(arr[n].name, sizeof(arr[n].name), "%s",
			 (name && name[0]) ? name : id);
		free(name);
		n++;
	}
	free(list);
	*out = arr;
	return (int)n;
}

/* Resolve a connmark's cmkid to a policy name; "-" if unstamped or stale
 * (a deleted policy's stamp is cleared by the next dirty-all re-eval). */
static const char *ct_policy_name(const struct ct_pol *map, int n,
				  unsigned cmkid)
{
	if (cmkid == 0)
		return "-";
	for (int i = 0; i < n; i++)
		if (map[i].cmkid == cmkid)
			return map[i].name;
	return "-";
}

/*
 * Per-flow in/out interface map. conntrack does NOT track interfaces; the
 * pkt_forward FORWARD hook records the original-direction ingress/egress
 * ifindex into the NF_CT_EXT_ML extension, which is only reachable via
 * ctnetlink (CTA_ML), not /proc. ct_iface_map_build() dumps it once per
 * session listing, keyed by the original 5-tuple so ct_emit_line() (which
 * parses /proc) can overlay it.
 */
struct ct_iface_ent {
	char     key[80];
	uint16_t iif;
	uint16_t oif;
};

/* Build the flow key shared by the /proc and ctnetlink sides: it must be
 * byte-identical from both, so both call this one formatter. */
static void ct_flow_key(char *buf, size_t sz, const char *proto,
			const char *src, unsigned sport,
			const char *dst, unsigned dport)
{
	snprintf(buf, sz, "%s|%s|%u|%s|%u", proto, src, sport, dst, dport);
}

/* Defined after the ctnetlink helpers below; built in handle_show_sessions. */
static int ct_iface_map_build(struct ct_iface_ent **out);

/* Look up a flow's ingress/egress ifindex by key; 0/0 if absent (e.g. local
 * INPUT flows never traverse FORWARD, so they carry no recorded interface). */
static void ct_iface_lookup(const struct ct_iface_ent *map, int n,
			    const char *key, unsigned *iif, unsigned *oif)
{
	*iif = 0;
	*oif = 0;
	if (!map)
		return;
	for (int i = 0; i < n; i++) {
		if (strcmp(map[i].key, key) == 0) {
			*iif = map[i].iif;
			*oif = map[i].oif;
			return;
		}
	}
}

/* ifindex → name into buf (size >= IF_NAMESIZE); "-" if 0 or unresolvable. */
static const char *ct_ifname(unsigned ifindex, char *buf, size_t sz)
{
	if (ifindex == 0 || sz < IF_NAMESIZE)
		return "-";
	if (!if_indextoname(ifindex, buf))
		return "-";
	return buf;
}

/*
 * The firewall's own IPv4 addresses and their subnets. A flow whose original
 * tuple is to/from one of these addresses is local (INPUT/OUTPUT) rather than
 * forwarded, so it carries no firewall policy and never traversed FORWARD;
 * ct_emit_line labels it "local" and resolves the peer's interface from these
 * subnets. Built once per listing with getifaddrs().
 */
struct ct_localif {
	struct in_addr addr;
	struct in_addr mask;
	char name[IF_NAMESIZE];
};

static int ct_localif_build(struct ct_localif **out)
{
	struct ifaddrs *ifa, *p;
	struct ct_localif *arr = NULL;
	int n = 0, cap = 0;

	*out = NULL;
	if (getifaddrs(&ifa) != 0)
		return -1;
	for (p = ifa; p; p = p->ifa_next) {
		if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET)
			continue;
		if (n == cap) {
			int ncap = cap ? cap * 2 : 8;
			struct ct_localif *t = realloc(arr, (size_t)ncap * sizeof(*t));

			if (!t) {
				free(arr);
				freeifaddrs(ifa);
				return -1;
			}
			arr = t;
			cap = ncap;
		}
		arr[n].addr = ((struct sockaddr_in *)p->ifa_addr)->sin_addr;
		if (p->ifa_netmask)
			arr[n].mask =
				((struct sockaddr_in *)p->ifa_netmask)->sin_addr;
		else
			arr[n].mask.s_addr = 0xffffffffu;
		snprintf(arr[n].name, sizeof(arr[n].name), "%s",
			 p->ifa_name ? p->ifa_name : "-");
		n++;
	}
	freeifaddrs(ifa);
	*out = arr;
	return n;
}

/* 1 if `ip` (dotted quad) is exactly one of the firewall's own addresses. */
static int ct_addr_is_local(const struct ct_localif *lm, int nlm,
			    const char *ip)
{
	struct in_addr a;
	int i;

	if (inet_pton(AF_INET, ip, &a) != 1)
		return 0;
	for (i = 0; i < nlm; i++)
		if (lm[i].addr.s_addr == a.s_addr)
			return 1;
	return 0;
}

/* Name of the firewall interface whose subnet contains `ip`, or NULL. */
static const char *ct_subnet_ifname(const struct ct_localif *lm, int nlm,
				    const char *ip)
{
	struct in_addr a;
	int i;

	if (inet_pton(AF_INET, ip, &a) != 1)
		return NULL;
	for (i = 0; i < nlm; i++) {
		uint32_t m = lm[i].mask.s_addr;

		if (m == 0)
			continue;	/* 0.0.0.0 netmask matches everything */
		if ((a.s_addr & m) == (lm[i].addr.s_addr & m))
			return lm[i].name;
	}
	return NULL;
}

/*
 * ct_classify - resolve a flow's *displayed* policy / iif / oif names from its
 * raw fields. The session listing (ct_emit_line) and the filtered clear path
 * (conntrack_delete_by_filter) both call this, so a flow is filtered on exactly
 * the same names an operator sees in `execute diagnose session status`.
 *
 * iif_idx/oif_idx are the ML extension's recorded ingress/egress ifindexes
 * (0 = none, e.g. local/INPUT flows that never traversed FORWARD). ibuf/obuf
 * (size IF_NAMESIZE) back the if_indextoname() results; the returned pointers
 * are either into those buffers or string literals ("-"/"local"/subnet name).
 */
static void ct_classify(const char *src, const char *dst,
			unsigned long mark, unsigned iif_idx, unsigned oif_idx,
			const struct ct_pol *pmap, int npmap,
			const struct ct_localif *lm, int nlm,
			char ibuf[IF_NAMESIZE], char obuf[IF_NAMESIZE],
			const char **policy_out, const char **iifn_out,
			const char **oifn_out)
{
	unsigned cmkid = (unsigned)(mark >> SG_CMK_PID_SHIFT);
	const char *policy = ct_policy_name(pmap, npmap, cmkid);
	const char *iifn = ct_ifname(iif_idx, ibuf, IF_NAMESIZE);
	const char *oifn = ct_ifname(oif_idx, obuf, IF_NAMESIZE);

	/* A local flow never traversed FORWARD (iif==oif==0). When it is to/from
	 * a firewall address, label it "local" and resolve the peer's interface
	 * from the address that owns its subnet — identical to the listing. */
	if (iif_idx == 0 && oif_idx == 0) {
		if (ct_addr_is_local(lm, nlm, dst)) {
			const char *in = ct_subnet_ifname(lm, nlm, src);

			policy = "local";
			iifn = ct_addr_is_local(lm, nlm, src) ? "local" :
			       (in ? in : "-");
			oifn = "local";
		} else if (ct_addr_is_local(lm, nlm, src)) {
			const char *eg = ct_subnet_ifname(lm, nlm, dst);

			policy = "local";
			iifn = "local";
			oifn = eg ? eg : "-";
		}
	}
	*policy_out = policy;
	*iifn_out = iifn;
	*oifn_out = oifn;
}

/* ── Stateful session filter (shared by listing and filtered clear) ──────────
 *
 * A constraint set for `execute diagnose session [list|clear]`. A flow matches
 * only if it satisfies EVERY supplied field (logical AND), compared against the
 * same normalized fields the listing shows. Fields left unset (have_* == 0) are
 * wildcards. An empty payload means "no filter" and never builds one of these.
 */
struct ct_filter {
	int      have_proto, have_src, have_dst, have_policy, have_iif, have_oif;
	char     proto[12];
	char     src_ip[INET_ADDRSTRLEN];
	char     dst_ip[INET_ADDRSTRLEN];
	int      src_has_port, dst_has_port;
	unsigned src_port, dst_port;
	char     policy[64];
	char     iif[IF_NAMESIZE];
	char     oif[IF_NAMESIZE];
};

struct ct_clear_result {
	long matched;	/* flows that matched the filter             */
	long deleted;	/* delete requests the kernel ACKed (err==0) */
	long failed;	/* build/send errors + non-zero/absent ACKs  */
	int  dump_ok;	/* dump reached a clean NLMSG_DONE           */
};

/* Split "ip" or "ip:port" into ip + optional port. Returns 0 on success and
 * sets has_port and port; -1 if the IP is not valid dotted-quad IPv4 or the port
 * is out of range. */
static int ct_split_ipport(const char *val, char *ip, size_t ipsz,
			   int *has_port, unsigned *port)
{
	const char *colon = strchr(val, ':');
	size_t iplen = colon ? (size_t)(colon - val) : strlen(val);
	struct in_addr a;

	*has_port = 0;
	*port = 0;
	if (iplen == 0 || iplen >= ipsz)
		return -1;
	memcpy(ip, val, iplen);
	ip[iplen] = '\0';
	if (inet_pton(AF_INET, ip, &a) != 1)
		return -1;
	if (colon) {
		char *end = NULL;
		unsigned long p = strtoul(colon + 1, &end, 10);

		if (end == colon + 1 || *end != '\0' || p > 65535)
			return -1;
		*has_port = 1;
		*port = (unsigned)p;
	}
	return 0;
}

/* Copy a validated string field, rejecting (never truncating) an over-long
 * value. Length-guarded memcpy keeps the compiler's format-truncation check
 * happy and honors "no silent caps". Returns 0 / -1 (message in err). */
static int ct_filter_setstr(char *dst, size_t dstsz, const char *v,
			    const char *name, char *err, size_t errsz)
{
	size_t l = strlen(v);

	if (l >= dstsz) {
		snprintf(err, errsz, "%s value too long", name);
		return -1;
	}
	memcpy(dst, v, l + 1);
	return 0;
}

/*
 * ct_filter_parse - build a ct_filter from a key=value payload. Recognized
 * keys: proto, src, dst, policy, iif, oif. Returns the number of constraints
 * set (>= 0), or -1 on a malformed value (message in err). A return of 0 means
 * the payload carried no recognized constraint — the clear caller MUST refuse
 * it rather than fall through to flushing every flow (fail-safe).
 */
static int ct_filter_parse(const char *payload, struct ct_filter *f,
			   char *err, size_t errsz)
{
	char v[128];
	int n = 0;

	memset(f, 0, sizeof(*f));

	extract_val(payload, "proto", v, sizeof(v));
	if (v[0]) {
		if (!ct_l4_name(v)) {
			snprintf(err, errsz, "unknown proto '%.40s'", v);
			return -1;
		}
		if (ct_filter_setstr(f->proto, sizeof(f->proto), v,
				     "proto", err, errsz) != 0)
			return -1;
		f->have_proto = 1; n++;
	}

	extract_val(payload, "src", v, sizeof(v));
	if (v[0]) {
		if (ct_split_ipport(v, f->src_ip, sizeof(f->src_ip),
				    &f->src_has_port, &f->src_port) != 0) {
			snprintf(err, errsz, "invalid src '%.40s'", v);
			return -1;
		}
		f->have_src = 1; n++;
	}

	extract_val(payload, "dst", v, sizeof(v));
	if (v[0]) {
		if (ct_split_ipport(v, f->dst_ip, sizeof(f->dst_ip),
				    &f->dst_has_port, &f->dst_port) != 0) {
			snprintf(err, errsz, "invalid dst '%.40s'", v);
			return -1;
		}
		f->have_dst = 1; n++;
	}

	extract_val(payload, "policy", v, sizeof(v));
	if (v[0]) {
		if (ct_filter_setstr(f->policy, sizeof(f->policy), v,
				     "policy", err, errsz) != 0)
			return -1;
		f->have_policy = 1; n++;
	}

	extract_val(payload, "iif", v, sizeof(v));
	if (v[0]) {
		if (ct_filter_setstr(f->iif, sizeof(f->iif), v,
				     "iif", err, errsz) != 0)
			return -1;
		f->have_iif = 1; n++;
	}

	extract_val(payload, "oif", v, sizeof(v));
	if (v[0]) {
		if (ct_filter_setstr(f->oif, sizeof(f->oif), v,
				     "oif", err, errsz) != 0)
			return -1;
		f->have_oif = 1; n++;
	}

	return n;
}

/*
 * ct_filter_parse_tuple - parse one space-joined batch record into a filter,
 * e.g. "proto=tcp src=10.0.1.1:59436 dst=10.0.1.2:80". Only proto/src/dst are
 * accepted (all a selected session row carries). Unlike ct_filter_parse (which
 * reads newline-separated key=value and stops a value at end-of-line), this
 * tokenizes on whitespace so many tuples pack into one bounded IPC payload.
 * Reuses the same validators. Returns constraint count (>0) or -1 (err set);
 * mutates `line` (strtok_r). An unknown field is rejected — fail-closed.
 */
static int ct_filter_parse_tuple(char *line, struct ct_filter *f,
				 char *err, size_t errsz)
{
	char *sp = NULL;
	int n = 0;

	memset(f, 0, sizeof(*f));

	for (char *t = strtok_r(line, " \t", &sp); t;
	     t = strtok_r(NULL, " \t", &sp)) {
		if (!strncmp(t, "proto=", 6)) {
			const char *v = t + 6;
			if (!ct_l4_name(v)) {
				snprintf(err, errsz, "unknown proto '%.40s'", v);
				return -1;
			}
			if (ct_filter_setstr(f->proto, sizeof(f->proto), v,
					     "proto", err, errsz) != 0)
				return -1;
			f->have_proto = 1; n++;
		} else if (!strncmp(t, "src=", 4)) {
			if (ct_split_ipport(t + 4, f->src_ip, sizeof(f->src_ip),
					    &f->src_has_port, &f->src_port) != 0) {
				snprintf(err, errsz, "invalid src '%.40s'", t + 4);
				return -1;
			}
			f->have_src = 1; n++;
		} else if (!strncmp(t, "dst=", 4)) {
			if (ct_split_ipport(t + 4, f->dst_ip, sizeof(f->dst_ip),
					    &f->dst_has_port, &f->dst_port) != 0) {
				snprintf(err, errsz, "invalid dst '%.40s'", t + 4);
				return -1;
			}
			f->have_dst = 1; n++;
		} else {
			snprintf(err, errsz, "unknown tuple field '%.40s'", t);
			return -1;
		}
	}
	return n;
}

/* 1 if the classified flow matches every supplied constraint (AND). */
static int ct_filter_match(const struct ct_filter *f,
			   const char *proto, const char *src, unsigned sport,
			   const char *dst, unsigned dport,
			   const char *policy, const char *iifn,
			   const char *oifn)
{
	if (f->have_proto && strcmp(f->proto, proto) != 0)
		return 0;
	if (f->have_src) {
		if (strcmp(f->src_ip, src) != 0)
			return 0;
		if (f->src_has_port && f->src_port != sport)
			return 0;
	}
	if (f->have_dst) {
		if (strcmp(f->dst_ip, dst) != 0)
			return 0;
		if (f->dst_has_port && f->dst_port != dport)
			return 0;
	}
	if (f->have_policy && strcmp(f->policy, policy) != 0)
		return 0;
	if (f->have_iif && strcmp(f->iif, iifn) != 0)
		return 0;
	if (f->have_oif && strcmp(f->oif, oifn) != 0)
		return 0;
	return 1;
}

static int conntrack_delete_by_filter(const struct ct_filter *f,
				      struct ct_clear_result *res);
static int conntrack_delete_by_filters(const struct ct_filter *filters, int nf,
				       struct ct_clear_result *res);

/*
 * ct_emit_line - parse one /proc/net/nf_conntrack line, append a normalized
 * session line to `out`:
 *   proto=<p> state=<S> src=<ip>:<port> dst=<ip>:<port> pkts=<n> bytes=<n> policy=<name> iif=<if> oif=<if>
 * pkts/bytes sum both directions (nf_conntrack_acct); policy is resolved from
 * the flow's connmark via `map`; iif/oif from the ML iface overlay via `imap`.
 * A flow to/from a firewall address that never traversed FORWARD is labelled
 * "local" using `lm`. When `filter` is non-NULL, a flow that does not match it
 * is dropped (returns -1) so the listing shows only matching flows. Returns 0
 * on success, -1 if unparseable or filtered out; modifies `line`.
 */
static int ct_emit_line(char *line, struct dynbuf *out,
			const struct ct_pol *map, int nmap,
			const struct ct_iface_ent *imap, int nimap,
			const struct ct_localif *lm, int nlm,
			const struct ct_filter *filter)
{
	char proto[12] = "", state[24] = "";
	char src[INET_ADDRSTRLEN] = "", dst[INET_ADDRSTRLEN] = "";
	unsigned sport = 0, dport = 0;
	unsigned long long pkts = 0, bytes = 0;
	unsigned long mark = 0;
	int have_proto = 0, have_tuple = 0;
	char *sp = NULL;

	for (char *t = strtok_r(line, " \t\n", &sp); t;
	     t = strtok_r(NULL, " \t\n", &sp)) {
		if (!have_proto) {
			const char *p = ct_l4_name(t);
			if (p) {
				snprintf(proto, sizeof(proto), "%s", p);
				have_proto = 1;
				continue;
			}
		}
		/* TCP state: an UPPERCASE word before the first src=, not a [FLAG] */
		if (have_proto && !have_tuple && !state[0] &&
		    t[0] >= 'A' && t[0] <= 'Z' && t[0] != '[' && !strchr(t, '=')) {
			snprintf(state, sizeof(state), "%s", t);
			continue;
		}
		if (!strncmp(t, "src=", 4)) {
			if (!src[0]) snprintf(src, sizeof(src), "%s", t + 4);
			have_tuple = 1;
		} else if (!strncmp(t, "dst=", 4)) {
			if (!dst[0]) snprintf(dst, sizeof(dst), "%s", t + 4);
		} else if (!strncmp(t, "sport=", 6)) {
			if (!sport) sport = (unsigned)atoi(t + 6);
		} else if (!strncmp(t, "dport=", 6)) {
			if (!dport) dport = (unsigned)atoi(t + 6);
		} else if (!strncmp(t, "packets=", 8)) {
			pkts += strtoull(t + 8, NULL, 10);
		} else if (!strncmp(t, "bytes=", 6)) {
			bytes += strtoull(t + 6, NULL, 10);
		} else if (!strncmp(t, "mark=", 5)) {
			if (!mark) mark = strtoul(t + 5, NULL, 0);
		}
	}
	if (!have_proto || !src[0])
		return -1;

	/* Overlay the in/out interfaces recorded in the ML extension, matched
	 * by the original 5-tuple. Local/INPUT flows carry none → "-". */
	char key[80];
	ct_flow_key(key, sizeof(key), proto, src, sport, dst, dport);
	unsigned iif = 0, oif = 0;
	ct_iface_lookup(imap, nimap, key, &iif, &oif);

	char ibuf[IF_NAMESIZE], obuf[IF_NAMESIZE];
	const char *policy, *iifn, *oifn;
	ct_classify(src, dst, mark, iif, oif, map, nmap, lm, nlm,
		    ibuf, obuf, &policy, &iifn, &oifn);

	/* Listing filter: drop flows that don't match every supplied field. */
	if (filter && !ct_filter_match(filter, proto, src, sport, dst, dport,
				       policy, iifn, oifn))
		return -1;

	char l[320];
	int n = snprintf(l, sizeof(l),
			 "proto=%s state=%s src=%s:%u dst=%s:%u pkts=%llu bytes=%llu policy=%s iif=%s oif=%s\n",
			 proto, state[0] ? state : "-",
			 src, sport, dst, dport, pkts, bytes, policy, iifn, oifn);
	/* snprintf returns the untruncated length; clamp to the source
	 * buffer before using it as the append length. */
	if (n > 0)
		dbuf_append(out, l, (size_t)n < sizeof(l) ? (size_t)n : sizeof(l) - 1);
	return 0;
}

/* Count active conntrack flows (one per line). -1 if conntrack unavailable. */
static long conntrack_count(void)
{
	FILE *fp = fopen("/proc/net/nf_conntrack", "r");
	if (!fp)
		return -1;
	long n = 0;
	char line[1024];
	while (fgets(line, sizeof(line), fp))
		n++;
	fclose(fp);
	return n;
}

/* nfnetlink constants defined locally to avoid build-sysroot header deps. */
#define SG_NETLINK_NETFILTER      12
#define SG_NFNL_SUBSYS_CTNETLINK  1
#define SG_IPCTNL_MSG_CT_DELETE   2

struct sg_nfgenmsg {
	unsigned char  nfgen_family;
	unsigned char  version;
	unsigned short res_id;
};

/*
 * conntrack_flush_all - flush the whole conntrack table via NFNETLINK
 * (the in-process equivalent of "conntrack -F"; no system command).
 * Returns 0 on success, negative on failure. Declared in mgmtd_apply.h so
 * the firewall apply path can force live-flow re-evaluation on policy change.
 */
int conntrack_flush_all(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, SG_NETLINK_NETFILTER);
	if (fd < 0)
		return -1;

	/* Don't let a missing ACK hang single-threaded mgmtd. */
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	struct {
		struct nlmsghdr    nlh;
		struct sg_nfgenmsg nfg;
	} req;
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len    = NLMSG_LENGTH(sizeof(req.nfg));
	req.nlh.nlmsg_type   = (SG_NFNL_SUBSYS_CTNETLINK << 8) | SG_IPCTNL_MSG_CT_DELETE;
	req.nlh.nlmsg_flags  = NLM_F_REQUEST | NLM_F_ACK;
	req.nlh.nlmsg_seq    = 1;
	req.nfg.nfgen_family = AF_UNSPEC;   /* flush all families */

	struct sockaddr_nl sa;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	int ret = -1;
	if (sendto(fd, &req, req.nlh.nlmsg_len, 0,
		   (struct sockaddr *)&sa, sizeof(sa)) >= 0) {
		char rbuf[256];
		ssize_t r = recv(fd, rbuf, sizeof(rbuf), 0);
		ret = 0;  /* request accepted */
		if (r >= (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
			struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
			if (rh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(rh);
				ret = e->error;  /* 0 = success ACK */
			}
		}
	}
	close(fd);
	return ret;
}

/* ── SG_CMD_SHOW_SESSIONS (650) — active flows from nf_conntrack ────────── */

int handle_show_sessions(int client_fd, const char *user,
			 const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	/* Optional filter: list only matching flows. A malformed value is a hard
	 * error; a payload with no recognized field lists everything (benign for
	 * a read-only listing). */
	struct ct_filter filt;
	const struct ct_filter *fp = NULL;
	if (payload && payload[0]) {
		char err[96];
		int nset = ct_filter_parse(payload, &filt, err, sizeof(err));

		if (nset < 0) {
			send_error(client_fd, SG_ERR_INVALID_ARG, err);
			return 0;
		}
		if (nset > 0)
			fp = &filt;
	}

	FILE *fp_ct = fopen("/proc/net/nf_conntrack", "r");
	if (!fp_ct) {
		send_ok(client_fd, "not_available",
			"Connection tracking not available\n");
		return 0;
	}

	struct dynbuf out;
	if (dbuf_init(&out, 8192) < 0) {
		fclose(fp_ct);
		send_error(client_fd, SG_ERR_SYSTEM_FAIL, "out of memory");
		return 0;
	}

	struct ct_pol *pmap = NULL;
	int npmap = ct_policy_map_build(&pmap);
	if (npmap < 0)
		npmap = 0;   /* alloc failure → flows just show policy=- */

	struct ct_iface_ent *imap = NULL;
	int nimap = ct_iface_map_build(&imap);
	if (nimap < 0)
		nimap = 0;   /* dump failure → flows just show iif/oif=- */

	struct ct_localif *lmap = NULL;
	int nlmap = ct_localif_build(&lmap);
	if (nlmap < 0)
		nlmap = 0;   /* getifaddrs failure → local flows just show "-" */

	long count = 0;
	char line[1024];
	while (fgets(line, sizeof(line), fp_ct)) {
		if (ct_emit_line(line, &out, pmap, npmap, imap, nimap,
				 lmap, nlmap, fp) == 0)
			count++;
	}
	fclose(fp_ct);
	free(pmap);
	free(imap);
	free(lmap);

	struct dynbuf resp;
	if (dbuf_init(&resp, out.used + 64) < 0) {
		send_ok(client_fd, NULL, out.data);
		free(out.data);
		return 0;
	}
	dbuf_printf(&resp, "active=%ld\n", count);
	dbuf_append(&resp, out.data, out.used);
	send_ok(client_fd, NULL, resp.data);
	free(out.data);
	free(resp.data);
	return 0;
}

/* ── SG_CMD_SESSION_STATS (656) — conntrack flow count + pkt_forward stats ── */

int handle_session_stats(int client_fd, const char *user,
			 const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	long active = conntrack_count();
	int conntrack_ok = (active >= 0);
	if (active < 0)
		active = 0;

	int pkt_fwd_loaded = (access("/sys/module/pkt_forward", F_OK) == 0);
	long long forwarded = 0, dropped = 0, anomaly_dropped = 0;
	if (pkt_fwd_loaded) {
		char pf_buf[1024];
		ssize_t pf_n = read_small_file("/proc/stargazer/pkt_forward_stats",
					       pf_buf, sizeof(pf_buf));
		if (pf_n > 0) {
			const char *kv;
			kv = strstr(pf_buf, "pkts_forwarded=");
			if (kv) forwarded       = strtoll(kv + 15, NULL, 10);
			kv = strstr(pf_buf, "pkts_dropped=");
			if (kv) dropped         = strtoll(kv + 13, NULL, 10);
			kv = strstr(pf_buf, "pkts_anomaly_dropped=");
			if (kv) anomaly_dropped = strtoll(kv + 21, NULL, 10);
		}
	}

	char resp[512];
	snprintf(resp, sizeof(resp),
		 "conntrack_available=%d\n"
		 "pkt_forward_loaded=%d\n"
		 "active=%ld\n"
		 "forwarded=%lld\n"
		 "dropped=%lld\n"
		 "anomaly_dropped=%lld\n",
		 conntrack_ok, pkt_fwd_loaded, active,
		 forwarded, dropped, anomaly_dropped);
	send_ok(client_fd, NULL, resp);
	return 0;
}

/* ── SG_CMD_SESSION_CLEAR (655) — flush conntrack via netlink ───────────── */

int handle_session_clear(int client_fd, const char *user,
			 const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "admin permission required");
		return 0;
	}

	long before = conntrack_count();
	if (before < 0) {
		send_error(client_fd, SG_ERR_NOT_FOUND,
			   "connection tracking not available");
		return 0;
	}

	/* No filter → legacy flush-all fast path (one netlink DELETE, no dump). */
	if (!payload || !payload[0]) {
		if (conntrack_flush_all() < 0) {
			send_error(client_fd, SG_ERR_SYSTEM_FAIL,
				   "conntrack flush failed");
			return 0;
		}
		char resp[64];
		snprintf(resp, sizeof(resp), "mode=all\nflushed=%ld\n", before);
		send_ok(client_fd, NULL, resp);
		return 0;
	}

	/* Batch clear: payload begins "tuples=N", then N lines each a complete
	 * tuple ("proto=.. src=.. dst=.."). The whole batch is deleted in ONE
	 * conntrack dump, matching ANY listed tuple. Fail-closed — a malformed
	 * or empty record rejects the entire batch rather than under-deleting
	 * (a silent miss) or widening into a full flush. */
	if (!strncmp(payload, "tuples=", 7)) {
		char nbuf[16];
		extract_val(payload, "tuples", nbuf, sizeof(nbuf));
		long want = strtol(nbuf, NULL, 10);
		if (want < 1 || want > 64) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "tuples out of range (1..64)");
			return 0;
		}

		struct ct_filter *filters = calloc((size_t)want, sizeof(*filters));
		if (!filters) {
			send_error(client_fd, SG_ERR_SYSTEM_FAIL, "out of memory");
			return 0;
		}

		int cnt = 0;
		const char *p = strchr(payload, '\n');	/* skip the header line */
		char err[96];
		while (p && *p && cnt < want) {
			p++;				/* past the '\n' */
			const char *nl = strchr(p, '\n');
			size_t ll = nl ? (size_t)(nl - p) : strlen(p);
			if (ll == 0) { p = nl; continue; }
			if (ll >= 256) {
				free(filters);
				send_error(client_fd, SG_ERR_INVALID_ARG,
					   "tuple record too long");
				return 0;
			}
			char line[256];
			memcpy(line, p, ll);
			line[ll] = '\0';
			int nset = ct_filter_parse_tuple(line, &filters[cnt],
							 err, sizeof(err));
			if (nset < 0) {
				free(filters);
				send_error(client_fd, SG_ERR_INVALID_ARG, err);
				return 0;
			}
			if (nset == 0) {
				free(filters);
				send_error(client_fd, SG_ERR_INVALID_ARG,
					   "empty tuple record");
				return 0;
			}
			cnt++;
			p = nl;
		}

		if (cnt == 0) {
			free(filters);
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "no tuple records");
			return 0;
		}

		struct ct_clear_result rb = {0};
		if (conntrack_delete_by_filters(filters, cnt, &rb) < 0) {
			free(filters);
			send_error(client_fd, SG_ERR_SYSTEM_FAIL,
				   "conntrack batch clear failed");
			return 0;
		}
		free(filters);

		char resp[160];
		snprintf(resp, sizeof(resp),
			 "mode=batch\nrequested=%d\nmatched=%ld\ndeleted=%ld\n"
			 "failed=%ld\ndump_complete=%d\n",
			 cnt, rb.matched, rb.deleted, rb.failed, rb.dump_ok);
		send_ok(client_fd, NULL, resp);
		return 0;
	}

	/* Filtered clear. A payload with no recognized constraint is refused —
	 * never silently widen a typo'd filter into a full flush. */
	struct ct_filter f;
	char err[96];
	int nset = ct_filter_parse(payload, &f, err, sizeof(err));
	if (nset < 0) {
		send_error(client_fd, SG_ERR_INVALID_ARG, err);
		return 0;
	}
	if (nset == 0) {
		send_error(client_fd, SG_ERR_INVALID_ARG,
			   "no valid filter fields (proto|src|dst|policy|iif|oif)");
		return 0;
	}

	struct ct_clear_result r = {0};
	if (conntrack_delete_by_filter(&f, &r) < 0) {
		send_error(client_fd, SG_ERR_SYSTEM_FAIL,
			   "conntrack filtered clear failed");
		return 0;
	}

	/* Honest accounting: report matched/deleted/failed and whether the dump
	 * completed, so a partial sweep is never reported as a clean clear. */
	char resp[128];
	snprintf(resp, sizeof(resp),
		 "mode=filter\nmatched=%ld\ndeleted=%ld\nfailed=%ld\ndump_complete=%d\n",
		 r.matched, r.deleted, r.failed, r.dump_ok);
	send_ok(client_fd, NULL, resp);
	return 0;
}

/* ── SG_CMD_SESSION_ML (659) — per-flow ML features via ctnetlink dump ──────
 *
 * Read-only collector/viewer: dump conntrack (IPCTNL_MSG_CT_GET + NLM_F_DUMP)
 * and print the per-flow CTA_ML feature blob the kernel exports. No scoring,
 * no blocking — for verification and training-data collection until a model
 * exists. In-process netlink (no shelling out).
 */

/* CTA_* numbers (stable ABI; defined locally — CTA_ML is a Stargazer addition
 * absent from the host uapi header, and this avoids depending on it). */
#define SG_IPCTNL_MSG_CT_GET    1
#define SG_NLA_TYPE_MASK        0x3fff
#define SG_CTA_TUPLE_ORIG       1
#define SG_CTA_TUPLE_IP         1   /* nested in CTA_TUPLE_* */
#define SG_CTA_IP_V4_SRC        1
#define SG_CTA_IP_V4_DST        2
#define SG_CTA_TUPLE_PROTO      2   /* nested in CTA_TUPLE_* */
#define SG_CTA_PROTO_NUM        1
#define SG_CTA_PROTO_SRC_PORT   2
#define SG_CTA_PROTO_DST_PORT   3
#define SG_CTA_ML               27
#define SG_CTA_MARK             8    /* conntrack connmark (be32) */
#define SG_CTA_MARK_MASK        21   /* masked connmark update (kernel CTA_MARK_MASK) */
#define SG_IPCTNL_MSG_CT_NEW    0    /* also used as "update" (no NLM_F_CREATE) */
#define SG_NLA_F_NESTED         0x8000

/* SG_CMK_DIRTY / SG_CMK_PID_SHIFT are defined up in the nf_conntrack readers
 * section (above ct_emit_line), which also uses them. */

/* Must match the kernel struct nf_conn_ml (same host/arch, host byte order). */
struct sg_nf_conn_ml {
	uint64_t first_ns, last_ns, iat_sum_us;
	uint32_t iat_count;
	uint16_t tcp_flags[2];
	uint16_t len_min[2];
	uint16_t len_max[2];
	int32_t  ml_score;
	uint16_t iif;   /* ingress ifindex, original direction (0 = unset) */
	uint16_t oif;   /* egress  ifindex, original direction (0 = unset) */
	uint64_t flow_iat_sq_sum;
	int64_t  last_seen_fwd;   /* kernel ktime_t (s64) */
	uint64_t fwd_iat_sum;
	uint64_t fwd_iat_sq_sum;
	uint64_t pktlen_sum;
	uint64_t pktlen_sq_sum;
	uint64_t bytes_fwd;
	uint64_t bytes_bwd;
	uint32_t flow_iat_min;
	uint32_t fwd_iat_count;
	uint32_t syn_count;
	uint32_t ack_count;
	uint32_t psh_count;
	uint32_t urg_count;
	uint32_t pktlen_count;
};

/* Find attribute `want` in an nlattr stream [data, data+len); return payload. */
static const void *sg_nla_find(const void *data, int len, int want, int *plen)
{
	const struct nlattr *nla = data;

	while (len >= (int)NLA_HDRLEN) {
		int alen = nla->nla_len;

		if (alen < (int)NLA_HDRLEN || alen > len)
			break;
		if ((nla->nla_type & SG_NLA_TYPE_MASK) == want) {
			*plen = alen - NLA_HDRLEN;
			return (const char *)nla + NLA_HDRLEN;
		}
		len -= NLA_ALIGN(alen);
		nla = (const struct nlattr *)((const char *)nla + NLA_ALIGN(alen));
	}
	return NULL;
}

/* Parse one conntrack dump message; if it carries CTA_ML, append a line. */
static void ct_ml_emit(const struct nlmsghdr *nh, struct dynbuf *out, long *count)
{
	const void *attrs = (const char *)NLMSG_DATA(nh) +
			    NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));
	int alen = (int)nh->nlmsg_len - NLMSG_HDRLEN -
		   (int)NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));
	const void *mlp, *tup;
	int ml_len = 0, tlen = 0;
	struct sg_nf_conn_ml ml;
	char src[INET_ADDRSTRLEN] = "?", dst[INET_ADDRSTRLEN] = "?";
	unsigned proto = 0, sport = 0, dport = 0;
	unsigned long long dur_ms, iat_us, iat_min;
	char line[768];
	int ll;

	if (alen <= 0)
		return;

	mlp = sg_nla_find(attrs, alen, SG_CTA_ML, &ml_len);
	if (!mlp)
		return;			/* flow has no ML features — skip */
	memset(&ml, 0, sizeof(ml));
	memcpy(&ml, mlp, ml_len < (int)sizeof(ml) ? (size_t)ml_len : sizeof(ml));

	tup = sg_nla_find(attrs, alen, SG_CTA_TUPLE_ORIG, &tlen);
	if (tup) {
		int l = 0;
		const void *ip = sg_nla_find(tup, tlen, SG_CTA_TUPLE_IP, &l);
		const void *pr;

		if (ip) {
			int il = 0;
			const void *s = sg_nla_find(ip, l, SG_CTA_IP_V4_SRC, &il);
			const void *d = sg_nla_find(ip, l, SG_CTA_IP_V4_DST, &il);

			if (s) inet_ntop(AF_INET, s, src, sizeof(src));
			if (d) inet_ntop(AF_INET, d, dst, sizeof(dst));
		}
		l = 0;
		pr = sg_nla_find(tup, tlen, SG_CTA_TUPLE_PROTO, &l);
		if (pr) {
			int pnl = 0, spl = 0, dpl = 0;
			const void *pn = sg_nla_find(pr, l, SG_CTA_PROTO_NUM, &pnl);
			const void *sp = sg_nla_find(pr, l, SG_CTA_PROTO_SRC_PORT, &spl);
			const void *dp = sg_nla_find(pr, l, SG_CTA_PROTO_DST_PORT, &dpl);

			/* Gate each read on the attribute's own payload length —
			 * sg_nla_find only proves the attr fits the parent, not
			 * that its payload is wide enough to deref. */
			if (pn && pnl >= 1) proto = *(const uint8_t *)pn;
			if (sp && spl >= 2) sport = ntohs(*(const uint16_t *)sp);
			if (dp && dpl >= 2) dport = ntohs(*(const uint16_t *)dp);
		}
	}

	dur_ms = (ml.last_ns > ml.first_ns) ?
		 (ml.last_ns - ml.first_ns) / 1000000ULL : 0;
	/* iat_sum_us is in microseconds; the mean is sum/count. */
	iat_us = ml.iat_count ? ml.iat_sum_us / ml.iat_count : 0;
	iat_min = (ml.flow_iat_min == UINT32_MAX) ? 0 : ml.flow_iat_min;

	ll = snprintf(line, sizeof(line),
		"proto=%u src=%s:%u dst=%s:%u iat_avg_us=%llu flow_iat_min=%llu "
		"flow_iat_sq_sum=%llu dur_ms=%llu fwd_iat_count=%u fwd_iat_sum=%llu "
		"fwd_iat_sq_sum=%llu len_o=%u-%u len_r=%u-%u pktlen_sum=%llu "
		"pktlen_sq_sum=%llu pktlen_count=%u bytes_fwd=%llu bytes_bwd=%llu "
		"flags_o=0x%02x flags_r=0x%02x "
		"syn=%u ack=%u psh=%u urg=%u score=%d\n",
		proto, src, sport, dst, dport, iat_us, iat_min,
		(unsigned long long)ml.flow_iat_sq_sum, dur_ms,
		ml.fwd_iat_count, (unsigned long long)ml.fwd_iat_sum,
		(unsigned long long)ml.fwd_iat_sq_sum,
		ml.len_min[0] == UINT16_MAX ? 0 : ml.len_min[0], ml.len_max[0],
		ml.len_min[1] == UINT16_MAX ? 0 : ml.len_min[1], ml.len_max[1],
		(unsigned long long)ml.pktlen_sum,
		(unsigned long long)ml.pktlen_sq_sum,
		ml.pktlen_count,
		(unsigned long long)ml.bytes_fwd,
		(unsigned long long)ml.bytes_bwd,
		ml.tcp_flags[0], ml.tcp_flags[1],
		ml.syn_count, ml.ack_count, ml.psh_count, ml.urg_count,
		ml.ml_score);
	/* snprintf returns the would-be length; clamp to what actually landed in
	 * the buffer so dbuf_append never reads past it on truncation. */
	if (ll > 0) {
		if (ll >= (int)sizeof(line))
			ll = (int)sizeof(line) - 1;
		dbuf_append(out, line, (size_t)ll);
	}
	(*count)++;
}

int handle_session_ml(int client_fd, const char *user,
		      const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	int fd = socket(AF_NETLINK, SOCK_RAW, SG_NETLINK_NETFILTER);
	if (fd < 0) {
		send_error(client_fd, SG_ERR_SYSTEM_FAIL, "netlink socket failed");
		return 0;
	}
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	struct {
		struct nlmsghdr    nlh;
		struct sg_nfgenmsg nfg;
	} req;
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len    = NLMSG_LENGTH(sizeof(req.nfg));
	req.nlh.nlmsg_type   = (SG_NFNL_SUBSYS_CTNETLINK << 8) | SG_IPCTNL_MSG_CT_GET;
	req.nlh.nlmsg_flags  = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq    = 1;
	req.nfg.nfgen_family = AF_INET;

	struct sockaddr_nl sa;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	if (sendto(fd, &req, req.nlh.nlmsg_len, 0,
		   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		send_error(client_fd, SG_ERR_SYSTEM_FAIL, "conntrack dump request failed");
		return 0;
	}

	struct dynbuf out;
	if (dbuf_init(&out, 8192) < 0) {
		close(fd);
		send_error(client_fd, SG_ERR_SYSTEM_FAIL, "out of memory");
		return 0;
	}

	long count = 0;
	char rbuf[32768];
	int done = 0;

	while (!done) {
		ssize_t rn = recv(fd, rbuf, sizeof(rbuf), 0);
		struct nlmsghdr *nh;
		int rem;

		if (rn <= 0)
			break;
		rem = (int)rn;
		for (nh = (struct nlmsghdr *)rbuf; NLMSG_OK(nh, rem);
		     nh = NLMSG_NEXT(nh, rem)) {
			if (nh->nlmsg_type == NLMSG_DONE ||
			    nh->nlmsg_type == NLMSG_ERROR) {
				done = 1;
				break;
			}
			ct_ml_emit(nh, &out, &count);
		}
	}
	close(fd);

	struct dynbuf resp;
	if (dbuf_init(&resp, out.used + 64) < 0) {
		send_ok(client_fd, NULL, out.data);
		free(out.data);
		return 0;
	}
	dbuf_printf(&resp, "flows=%ld\n", count);
	dbuf_append(&resp, out.data, out.used);
	send_ok(client_fd, NULL, resp.data);
	free(out.data);
	free(resp.data);
	return 0;
}

/* L4 protocol number → /proc name, so a ctnetlink-built key matches the key
 * ct_emit_line builds from /proc (which uses the name). NULL = unrecognised
 * (those flows simply won't get an iface overlay). Mirrors ct_l4_name(). */
static const char *ct_proto_name(unsigned num)
{
	switch (num) {
	case 6:   return "tcp";
	case 17:  return "udp";
	case 1:   return "icmp";
	case 58:  return "icmpv6";
	case 136: return "udplite";
	case 132: return "sctp";
	case 33:  return "dccp";
	case 47:  return "gre";
	default:  return NULL;
	}
}

/*
 * ct_iface_map_build - dump conntrack via ctnetlink and capture each FORWARD
 * flow's original-direction ingress/egress ifindex from the ML extension,
 * keyed by the same 5-tuple string ct_emit_line() builds from /proc. Flows
 * with no recorded interface (local/INPUT never hit the FORWARD hook) are
 * skipped. Returns the entry count (>=0); *out is malloc'd (caller frees,
 * even when 0). Returns -1 on socket/send/OOM failure → caller shows iif/oif
 * as "-". A mid-dump timeout returns the partial map (display-only overlay,
 * so a missing entry is a cosmetic "-", never a correctness issue).
 */
static int ct_iface_map_build(struct ct_iface_ent **out)
{
	*out = NULL;

	int fd = socket(AF_NETLINK, SOCK_RAW, SG_NETLINK_NETFILTER);
	if (fd < 0)
		return -1;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	struct {
		struct nlmsghdr    nlh;
		struct sg_nfgenmsg nfg;
	} req;
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len    = NLMSG_LENGTH(sizeof(req.nfg));
	req.nlh.nlmsg_type   = (SG_NFNL_SUBSYS_CTNETLINK << 8) | SG_IPCTNL_MSG_CT_GET;
	req.nlh.nlmsg_flags  = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq    = 1;
	req.nfg.nfgen_family = AF_INET;

	struct sockaddr_nl sa;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	if (sendto(fd, &req, req.nlh.nlmsg_len, 0,
		   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	struct ct_iface_ent *arr = NULL;
	size_t n = 0, cap = 0;
	char rbuf[32768];
	int done = 0;

	while (!done) {
		ssize_t rn = recv(fd, rbuf, sizeof(rbuf), 0);
		struct nlmsghdr *nh;
		int rem;

		if (rn <= 0)
			break;		/* timeout → return partial map */
		rem = (int)rn;
		for (nh = (struct nlmsghdr *)rbuf; NLMSG_OK(nh, rem);
		     nh = NLMSG_NEXT(nh, rem)) {
			const void *attrs, *mlp, *tup;
			int alen, ml_len = 0, tlen = 0;
			struct sg_nf_conn_ml ml;
			char src[INET_ADDRSTRLEN] = "", dst[INET_ADDRSTRLEN] = "";
			unsigned sport = 0, dport = 0;
			const char *pname = NULL;

			if (nh->nlmsg_type == NLMSG_DONE ||
			    nh->nlmsg_type == NLMSG_ERROR) {
				done = 1;
				break;
			}
			attrs = (const char *)NLMSG_DATA(nh) +
				NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));
			alen = (int)nh->nlmsg_len - NLMSG_HDRLEN -
			       (int)NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));
			if (alen <= 0)
				continue;

			mlp = sg_nla_find(attrs, alen, SG_CTA_ML, &ml_len);
			if (!mlp)
				continue;
			memset(&ml, 0, sizeof(ml));
			memcpy(&ml, mlp,
			       ml_len < (int)sizeof(ml) ? (size_t)ml_len : sizeof(ml));
			if (ml.iif == 0 && ml.oif == 0)
				continue;	/* no interface recorded */

			tup = sg_nla_find(attrs, alen, SG_CTA_TUPLE_ORIG, &tlen);
			if (!tup)
				continue;
			{
				int l = 0;
				const void *ip = sg_nla_find(tup, tlen,
							     SG_CTA_TUPLE_IP, &l);
				const void *pr;

				if (ip) {
					int il = 0;
					const void *s = sg_nla_find(ip, l,
							SG_CTA_IP_V4_SRC, &il);
					const void *d = sg_nla_find(ip, l,
							SG_CTA_IP_V4_DST, &il);
					if (s) inet_ntop(AF_INET, s, src, sizeof(src));
					if (d) inet_ntop(AF_INET, d, dst, sizeof(dst));
				}
				l = 0;
				pr = sg_nla_find(tup, tlen, SG_CTA_TUPLE_PROTO, &l);
				if (pr) {
					int pnl = 0, spl = 0, dpl = 0;
					const void *pn = sg_nla_find(pr, l,
							SG_CTA_PROTO_NUM, &pnl);
					const void *sp = sg_nla_find(pr, l,
							SG_CTA_PROTO_SRC_PORT, &spl);
					const void *dp = sg_nla_find(pr, l,
							SG_CTA_PROTO_DST_PORT, &dpl);
					/* Gate each deref on its own payload width. */
					if (pn && pnl >= 1) pname = ct_proto_name(*(const uint8_t *)pn);
					if (sp && spl >= 2) sport = ntohs(*(const uint16_t *)sp);
					if (dp && dpl >= 2) dport = ntohs(*(const uint16_t *)dp);
				}
			}
			if (!pname || !src[0])
				continue;	/* can't form a matching key */

			if (n == cap) {
				size_t ncap = cap ? cap * 2 : 256;
				struct ct_iface_ent *t =
					realloc(arr, ncap * sizeof(*arr));
				if (!t) {
					free(arr);
					close(fd);
					return -1;
				}
				arr = t;
				cap = ncap;
			}
			ct_flow_key(arr[n].key, sizeof(arr[n].key),
				    pname, src, sport, dst, dport);
			arr[n].iif = ml.iif;
			arr[n].oif = ml.oif;
			n++;
		}
	}
	close(fd);
	*out = arr;
	return (int)n;
}

/* Append one netlink attribute to a flat message buffer. Returns 0 / -1. */
static int sg_nla_put(char *buf, int *off, int cap, int type,
		      const void *data, int dlen)
{
	int total = NLA_HDRLEN + dlen;
	int aligned = NLA_ALIGN(total);
	struct nlattr *nla;
	int i;

	if (dlen < 0 || *off + aligned > cap)
		return -1;
	nla = (struct nlattr *)(buf + *off);
	nla->nla_len  = (uint16_t)total;
	nla->nla_type = (uint16_t)type;
	if (dlen)
		memcpy(buf + *off + NLA_HDRLEN, data, (size_t)dlen);
	for (i = total; i < aligned; i++)
		buf[*off + i] = 0;
	*off += aligned;
	return 0;
}

/*
 * sg_drain_ct_acks - consume pending masked-update ACKs from the write socket.
 *
 * Each CT_NEW update is sent with NLM_F_ACK, so the kernel queues one
 * NLMSG_ERROR reply per update (error == 0 is the success ACK). Every reply
 * consumed decrements *outstanding; a non-zero error counts in *fails. Reads
 * stop once *outstanding reaches `target` or a recv times out. `buf` must be a
 * different buffer from the dump batch so a drain mid-dump cannot clobber the
 * messages still being parsed.
 */
static void sg_drain_ct_acks(int wfd, char *buf, size_t buflen,
			     size_t *outstanding, size_t *fails, size_t target)
{
	while (*outstanding > target) {
		ssize_t rn = recv(wfd, buf, buflen, 0);
		struct nlmsghdr *nh;
		int rem;

		if (rn <= 0)
			break;		/* timeout/error: leave the rest to the caller */
		rem = (int)rn;
		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, rem);
		     nh = NLMSG_NEXT(nh, rem)) {
			if (nh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = NLMSG_DATA(nh);

				if (e->error != 0)
					(*fails)++;
			}
			if (*outstanding > 0)
				(*outstanding)--;
		}
	}
}

/*
 * conntrack_mark_dirty_by_policy - set the connmark DIRTY bit on live flows so
 * they re-traverse the freshly-rebuilt FORWARD chain on their next packet.
 *
 * pid == 0 → every flow. pid == cmkid → only flows that policy stamped. Two
 * NFNETLINK sockets stream concurrently: the read socket runs CT_GET|NLM_F_DUMP
 * (narrowed to the policy's not-yet-dirty flows with a CTA_MARK/CTA_MARK_MASK
 * filter when pid != 0), and as each matching flow arrives a masked CT_NEW
 * update setting DIRTY is sent on the write socket. Updates are not waited on
 * per flow; their ACKs are drained in a window so the reply queue cannot back
 * up, and the in-flight count is reconciled once the dump completes. No flow is
 * buffered, so memory stays constant regardless of table size.
 *
 * Returns 0 on success, negative on a hard failure (caller then flushes the
 * whole table). A dump that never reaches NLMSG_DONE, or a run where every
 * update went unconfirmed, is a hard failure (fail-closed). A per-flow ENOENT
 * (flow torn down mid-stream) is benign. The per-flow check below also selects
 * correctly when the kernel ignores the dump filter (older kernels).
 */
int conntrack_mark_dirty_by_policy(unsigned int pid)
{
	const size_t WINDOW = 64;	/* updates in flight before draining ACKs */
	int rfd, wfd, rc = -1;
	struct sockaddr_nl sa;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
	size_t n = 0, fails = 0, outstanding = 0;
	int done = 0, dump_ok = 0;
	char rbuf[32768];	/* dump batch                                  */
	char abuf[8192];	/* ACK drain — must be distinct from rbuf      */

	rfd = socket(AF_NETLINK, SOCK_RAW, SG_NETLINK_NETFILTER);
	if (rfd < 0)
		return -1;
	wfd = socket(AF_NETLINK, SOCK_RAW, SG_NETLINK_NETFILTER);
	if (wfd < 0) {
		close(rfd);
		return -1;	/* no second socket → caller flushes (fail-closed) */
	}
	setsockopt(rfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(wfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	/* ── Dump request, narrowed to the policy's not-yet-dirty flows ── */
	{
		char req[256];
		struct nlmsghdr *nlh = (struct nlmsghdr *)req;
		struct sg_nfgenmsg *nfg =
			(struct sg_nfgenmsg *)(req + NLMSG_HDRLEN);
		int off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));

		memset(req, 0, sizeof(req));
		nlh->nlmsg_type   = (SG_NFNL_SUBSYS_CTNETLINK << 8) |
				    SG_IPCTNL_MSG_CT_GET;
		nlh->nlmsg_flags  = NLM_F_REQUEST | NLM_F_DUMP;
		nlh->nlmsg_seq    = 100;
		nfg->nfgen_family = AF_INET;

		/* Kernel-side filter: keep only flows whose cmkid == pid with the
		 * DIRTY bit clear. The per-flow check below re-selects regardless,
		 * so a kernel that filters differently only changes efficiency. */
		if (pid != 0) {
			uint32_t fmark = htonl(pid << SG_CMK_PID_SHIFT);
			uint32_t fmask = htonl(SG_CMK_PID_MASK | SG_CMK_DIRTY);

			if (sg_nla_put(req, &off, sizeof(req),
				       SG_CTA_MARK, &fmark, 4) < 0 ||
			    sg_nla_put(req, &off, sizeof(req),
				       SG_CTA_MARK_MASK, &fmask, 4) < 0) {
				close(rfd);
				close(wfd);
				return -1;
			}
		}
		nlh->nlmsg_len = (uint32_t)off;
		if (sendto(rfd, req, off, 0,
			   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			close(rfd);
			close(wfd);
			return -1;
		}
	}

	/* ── Stream: read each matching flow, send its masked DIRTY update ── */
	while (!done) {
		ssize_t rn = recv(rfd, rbuf, sizeof(rbuf), 0);
		struct nlmsghdr *nh;
		int rem;

		if (rn <= 0)
			break;		/* timeout/error: dump_ok stays 0 */
		rem = (int)rn;
		for (nh = (struct nlmsghdr *)rbuf; NLMSG_OK(nh, rem);
		     nh = NLMSG_NEXT(nh, rem)) {
			const void *attrs, *mp, *tup;
			int alen, mlen = 0, tlen = 0;
			uint32_t mark, bmark, bmask;
			char msg[512];
			struct nlmsghdr *unlh = (struct nlmsghdr *)msg;
			struct sg_nfgenmsg *unfg =
				(struct sg_nfgenmsg *)(msg + NLMSG_HDRLEN);
			int uoff = NLMSG_HDRLEN +
				   NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));

			/* A clean NLMSG_DONE is the only success terminator;
			 * NLMSG_ERROR leaves dump_ok = 0 so the caller flushes
			 * instead of mistaking a failed dump for an empty table. */
			if (nh->nlmsg_type == NLMSG_DONE) {
				done = 1;
				dump_ok = 1;
				break;
			}
			if (nh->nlmsg_type == NLMSG_ERROR) {
				done = 1;
				break;
			}
			attrs = (const char *)NLMSG_DATA(nh) +
				NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));
			alen = (int)nh->nlmsg_len - NLMSG_HDRLEN -
			       (int)NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));
			if (alen <= 0)
				continue;

			mp = sg_nla_find(attrs, alen, SG_CTA_MARK, &mlen);
			mark = (mp && mlen >= 4) ?
			       ntohl(*(const uint32_t *)mp) : 0;

			/* Per-flow filter (and the fallback when the kernel
			 * ignored the dump filter): the policy's own flows that
			 * are not already dirty. */
			if (pid != 0 && (mark >> SG_CMK_PID_SHIFT) != pid)
				continue;
			if (mark & SG_CMK_DIRTY)
				continue;

			tup = sg_nla_find(attrs, alen, SG_CTA_TUPLE_ORIG, &tlen);
			if (!tup || tlen <= 0 || tlen > 128)
				continue;	/* can't address it — skip */

			/* Build the masked update straight from the dump tuple.
			 * The kernel applies (ct->mark & ~CTA_MARK_MASK) ^ CTA_MARK,
			 * so CTA_MARK must carry only the in-mask bit: set DIRTY and
			 * leave the cmkid (bits 8-31) untouched. */
			memset(msg, 0, sizeof(msg));
			bmark = htonl(SG_CMK_DIRTY);
			bmask = htonl(SG_CMK_DIRTY);
			if (sg_nla_put(msg, &uoff, sizeof(msg),
				       SG_CTA_TUPLE_ORIG | SG_NLA_F_NESTED,
				       tup, tlen) < 0 ||
			    sg_nla_put(msg, &uoff, sizeof(msg),
				       SG_CTA_MARK, &bmark, 4) < 0 ||
			    sg_nla_put(msg, &uoff, sizeof(msg),
				       SG_CTA_MARK_MASK, &bmask, 4) < 0) {
				n++;
				fails++;
				continue;
			}
			unlh->nlmsg_len   = (uint32_t)uoff;
			unlh->nlmsg_type  = (SG_NFNL_SUBSYS_CTNETLINK << 8) |
					    SG_IPCTNL_MSG_CT_NEW;
			unlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
			unlh->nlmsg_seq   = (unsigned int)(1000 + n);
			unfg->nfgen_family = AF_INET;

			n++;
			if (sendto(wfd, msg, uoff, 0,
				   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
				fails++;
			} else {
				outstanding++;
				if (outstanding >= WINDOW)
					sg_drain_ct_acks(wfd, abuf,
							 sizeof(abuf),
							 &outstanding,
							 &fails, 0);
			}
		}
	}

	/* Dump must reach a clean NLMSG_DONE; otherwise some flows were never
	 * seen — flush rather than leave now-denied flows on the fast path. */
	if (!dump_ok) {
		close(rfd);
		close(wfd);
		return -1;
	}

	/* Reconcile the remaining in-flight updates; an ACK that never arrived
	 * counts as a failure (fail-closed), like the per-flow discipline. */
	sg_drain_ct_acks(wfd, abuf, sizeof(abuf), &outstanding, &fails, 0);
	fails += outstanding;

	rc = (n == 0) ? 0 : (fails >= n ? -1 : 0);
	close(rfd);
	close(wfd);
	return rc;
}

/*
 * conntrack_delete_by_filters - dump conntrack and delete every flow matching
 * ANY of `nf` filters (logical OR across the array; AND within each filter),
 * addressing each by echoing its dumped CTA_TUPLE_ORIG in an
 * IPCTNL_MSG_CT_DELETE (the in-process equivalent of "conntrack -D ...").
 * A single-tuple delete is just nf==1; the GUI multi-select batch passes the
 * selected rows as nf filters so the whole batch costs exactly one dump.
 *
 * Each flow is classified (policy / iif / oif) with ct_classify() — the exact
 * names the session listing shows — so an operator clears precisely what they
 * saw. Two NFNETLINK sockets stream concurrently like the dirty-by-policy path:
 * the read socket dumps, and as each matching flow arrives its DELETE is sent
 * on the write socket with NLM_F_ACK; ACKs are drained in a window so the reply
 * queue cannot back up. No flow is buffered (constant memory).
 *
 * Fills *res (matched/deleted/failed/dump_ok). Returns 0 once the sockets are
 * set up and the dump ran, -1 on a hard setup failure (socket/send/OOM). A
 * delete that returns a non-zero ACK (e.g. ENOENT — the flow ended between dump
 * and delete) counts as failed, reported honestly rather than hidden.
 */
static int conntrack_delete_by_filters(const struct ct_filter *filters, int nf,
				       struct ct_clear_result *res)
{
	const size_t WINDOW = 64;
	int rfd, wfd;
	struct sockaddr_nl sa;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
	size_t sent = 0, fails = 0, outstanding = 0;
	long matched = 0;
	int done = 0, dump_ok = 0;
	char rbuf[32768];	/* dump batch                              */
	char abuf[8192];	/* ACK drain — must be distinct from rbuf  */

	struct ct_pol *pmap = NULL;
	int npmap = ct_policy_map_build(&pmap);
	if (npmap < 0)
		npmap = 0;	/* no policy names → policy= matches only "-" */
	struct ct_localif *lmap = NULL;
	int nlmap = ct_localif_build(&lmap);
	if (nlmap < 0)
		nlmap = 0;

	rfd = socket(AF_NETLINK, SOCK_RAW, SG_NETLINK_NETFILTER);
	if (rfd < 0) {
		free(pmap);
		free(lmap);
		return -1;
	}
	wfd = socket(AF_NETLINK, SOCK_RAW, SG_NETLINK_NETFILTER);
	if (wfd < 0) {
		close(rfd);
		free(pmap);
		free(lmap);
		return -1;
	}
	setsockopt(rfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(wfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	/* Dump request (whole IPv4 table; the per-flow filter is applied below). */
	{
		struct {
			struct nlmsghdr    nlh;
			struct sg_nfgenmsg nfg;
		} req;
		memset(&req, 0, sizeof(req));
		req.nlh.nlmsg_len    = NLMSG_LENGTH(sizeof(req.nfg));
		req.nlh.nlmsg_type   = (SG_NFNL_SUBSYS_CTNETLINK << 8) |
				       SG_IPCTNL_MSG_CT_GET;
		req.nlh.nlmsg_flags  = NLM_F_REQUEST | NLM_F_DUMP;
		req.nlh.nlmsg_seq    = 1;
		req.nfg.nfgen_family = AF_INET;
		if (sendto(rfd, &req, req.nlh.nlmsg_len, 0,
			   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			close(rfd);
			close(wfd);
			free(pmap);
			free(lmap);
			return -1;
		}
	}

	while (!done) {
		ssize_t rn = recv(rfd, rbuf, sizeof(rbuf), 0);
		struct nlmsghdr *nh;
		int rem;

		if (rn <= 0)
			break;		/* timeout/error: dump_ok stays 0 */
		rem = (int)rn;
		for (nh = (struct nlmsghdr *)rbuf; NLMSG_OK(nh, rem);
		     nh = NLMSG_NEXT(nh, rem)) {
			const void *attrs, *mlp, *tup, *mp;
			int alen, ml_len = 0, tlen = 0, mlen2 = 0;
			struct sg_nf_conn_ml ml;
			char src[INET_ADDRSTRLEN] = "", dst[INET_ADDRSTRLEN] = "";
			unsigned sport = 0, dport = 0;
			const char *pname = NULL;
			unsigned long mark = 0;
			char ibuf[IF_NAMESIZE], obuf[IF_NAMESIZE];
			const char *policy, *iifn, *oifn;
			char msg[512];
			struct nlmsghdr *dnlh = (struct nlmsghdr *)msg;
			struct sg_nfgenmsg *dnfg =
				(struct sg_nfgenmsg *)(msg + NLMSG_HDRLEN);
			int doff = NLMSG_HDRLEN +
				   NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));

			if (nh->nlmsg_type == NLMSG_DONE) {
				done = 1;
				dump_ok = 1;
				break;
			}
			if (nh->nlmsg_type == NLMSG_ERROR) {
				done = 1;
				break;
			}
			attrs = (const char *)NLMSG_DATA(nh) +
				NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));
			alen = (int)nh->nlmsg_len - NLMSG_HDRLEN -
			       (int)NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));
			if (alen <= 0)
				continue;

			/* Original tuple — needed both to match and to address
			 * the delete (echoed back verbatim). */
			tup = sg_nla_find(attrs, alen, SG_CTA_TUPLE_ORIG, &tlen);
			if (!tup || tlen <= 0 || tlen > 128)
				continue;
			{
				int l = 0;
				const void *ip = sg_nla_find(tup, tlen,
							     SG_CTA_TUPLE_IP, &l);
				const void *pr;

				if (ip) {
					int il = 0;
					const void *s = sg_nla_find(ip, l,
							SG_CTA_IP_V4_SRC, &il);
					const void *d = sg_nla_find(ip, l,
							SG_CTA_IP_V4_DST, &il);
					if (s) inet_ntop(AF_INET, s, src, sizeof(src));
					if (d) inet_ntop(AF_INET, d, dst, sizeof(dst));
				}
				l = 0;
				pr = sg_nla_find(tup, tlen, SG_CTA_TUPLE_PROTO, &l);
				if (pr) {
					int pnl = 0, spl = 0, dpl = 0;
					const void *pn = sg_nla_find(pr, l,
							SG_CTA_PROTO_NUM, &pnl);
					const void *sp = sg_nla_find(pr, l,
							SG_CTA_PROTO_SRC_PORT, &spl);
					const void *dp = sg_nla_find(pr, l,
							SG_CTA_PROTO_DST_PORT, &dpl);
					if (pn && pnl >= 1)
						pname = ct_proto_name(*(const uint8_t *)pn);
					if (sp && spl >= 2)
						sport = ntohs(*(const uint16_t *)sp);
					if (dp && dpl >= 2)
						dport = ntohs(*(const uint16_t *)dp);
				}
			}
			if (!pname || !src[0] || !dst[0])
				continue;	/* can't classify or address it */

			/* connmark → policy; ML iface indexes → iif/oif. */
			mp = sg_nla_find(attrs, alen, SG_CTA_MARK, &mlen2);
			if (mp && mlen2 >= 4)
				mark = ntohl(*(const uint32_t *)mp);
			memset(&ml, 0, sizeof(ml));
			mlp = sg_nla_find(attrs, alen, SG_CTA_ML, &ml_len);
			if (mlp)
				memcpy(&ml, mlp, ml_len < (int)sizeof(ml) ?
				       (size_t)ml_len : sizeof(ml));

			ct_classify(src, dst, mark, ml.iif, ml.oif,
				    pmap, npmap, lmap, nlmap,
				    ibuf, obuf, &policy, &iifn, &oifn);

			{
				int mi, hit = 0;
				for (mi = 0; mi < nf && !hit; mi++)
					if (ct_filter_match(&filters[mi], pname,
							    src, sport, dst, dport,
							    policy, iifn, oifn))
						hit = 1;
				if (!hit)
					continue;
			}

			matched++;

			/* Build CT_DELETE addressing this exact flow. */
			memset(msg, 0, sizeof(msg));
			if (sg_nla_put(msg, &doff, sizeof(msg),
				       SG_CTA_TUPLE_ORIG | SG_NLA_F_NESTED,
				       tup, tlen) < 0) {
				fails++;
				continue;
			}
			dnlh->nlmsg_len    = (uint32_t)doff;
			dnlh->nlmsg_type   = (SG_NFNL_SUBSYS_CTNETLINK << 8) |
					     SG_IPCTNL_MSG_CT_DELETE;
			dnlh->nlmsg_flags  = NLM_F_REQUEST | NLM_F_ACK;
			dnlh->nlmsg_seq    = (unsigned int)(1000 + sent);
			dnfg->nfgen_family = AF_INET;

			if (sendto(wfd, msg, doff, 0,
				   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
				fails++;
			} else {
				sent++;
				outstanding++;
				if (outstanding >= WINDOW)
					sg_drain_ct_acks(wfd, abuf, sizeof(abuf),
							 &outstanding, &fails, 0);
			}
		}
	}

	/* Reconcile in-flight ACKs; an unconfirmed delete counts as failed. */
	sg_drain_ct_acks(wfd, abuf, sizeof(abuf), &outstanding, &fails, 0);
	fails += outstanding;

	close(rfd);
	close(wfd);
	free(pmap);
	free(lmap);

	res->matched = matched;
	res->failed  = (long)fails;
	res->deleted = matched - (long)fails;
	if (res->deleted < 0)
		res->deleted = 0;
	res->dump_ok = dump_ok;
	return 0;
}

/* Single-filter convenience wrapper — preserves the original entry point. */
static int conntrack_delete_by_filter(const struct ct_filter *f,
				      struct ct_clear_result *res)
{
	return conntrack_delete_by_filters(f, 1, res);
}

/* ── SG_CMD_SHOW_BOOT_CONFIG (651) ─────────────────────────────────────── */

int handle_show_boot_config(int client_fd, const char *user,
			    const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	char resp[SG_RESPONSE_MAX];
	size_t pos = 0;

	buf_appendf(resp, sizeof(resp), &pos, "[modules]\n");
	{
		char buf[4096];
		if (read_small_file("/etc/modules-load.d/stargazer.conf",
				    buf, sizeof(buf)) > 0)
			buf_appendf(resp, sizeof(resp), &pos, "%s", buf);
	}

	buf_appendf(resp, sizeof(resp), &pos, "[sysctl]\n");
	{
		char buf[4096];
		if (read_small_file("/etc/sysctl.d/10-stargazer.conf",
				    buf, sizeof(buf)) > 0) {
			/* Filter comments and blank lines */
			const char *p = buf;
			while (*p) {
				const char *eol = strchr(p, '\n');
				size_t llen = eol ? (size_t)(eol - p) : strlen(p);
				if (llen > 0 && p[0] != '#')
					buf_appendf(resp, sizeof(resp), &pos,
						    "%.*s\n", (int)llen, p);
				if (!eol) break;
				p = eol + 1;
			}
		}
	}

	send_ok(client_fd, NULL, resp);
	return 0;
}

/* ── SG_CMD_DEBUG_STATE_GET (660) ──────────────────────────────────────── */

#define DEBUG_STATE_PATH "/tmp/stargazer-debug.conf"

int handle_debug_state_get(int client_fd, const char *user,
			   const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "admin permission required");
		return 0;
	}

	char buf[4096];
	ssize_t n = read_small_file(DEBUG_STATE_PATH, buf, sizeof(buf));
	if (n < 0) {
		/* No debug state file is normal — return empty payload */
		send_ok(client_fd, NULL, NULL);
		return 0;
	}

	send_ok(client_fd, NULL, buf);
	return 0;
}

/* ── SG_CMD_DEBUG_STATE_SET (661) ──────────────────────────────────────── */

int handle_debug_state_set(int client_fd, const char *user,
			   const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "admin permission required");
		return 0;
	}

	if (!payload || !payload[0]) {
		send_error(client_fd, SG_ERR_MISSING_ARG,
			   "payload required");
		return 0;
	}

	/* Atomic write: tmp + rename */
	char tmppath[128];
	snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d",
		 DEBUG_STATE_PATH, (int)getpid());

	int fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		send_error(client_fd, SG_ERR_IO_FAIL,
			   "cannot write debug state");
		return 0;
	}

	size_t plen = strlen(payload);
	ssize_t written = 0;
	while ((size_t)written < plen) {
		ssize_t n = write(fd, payload + written, plen - (size_t)written);
		if (n <= 0) {
			close(fd);
			unlink(tmppath);
			send_error(client_fd, SG_ERR_IO_FAIL,
				   "write failed");
			return 0;
		}
		written += n;
	}
	close(fd);

	if (rename(tmppath, DEBUG_STATE_PATH) != 0) {
		unlink(tmppath);
		send_error(client_fd, SG_ERR_IO_FAIL,
			   "rename failed");
		return 0;
	}

	send_ok(client_fd, NULL, NULL);
	return 0;
}

/* ── SG_CMD_DEBUG_STATE_RESET (662) ────────────────────────────────────── */

int handle_debug_state_reset(int client_fd, const char *user,
			     const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "admin permission required");
		return 0;
	}

	unlink(DEBUG_STATE_PATH);
	send_ok(client_fd, NULL, NULL);
	return 0;
}

/* ── SG_CMD_HISTORY_SAVE (663) ─────────────────────────────────────────── */

int handle_history_save(int client_fd, const char *user,
			const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;

	/*
	 * Payload format: "user=<username>\n<history lines>"
	 * We write to /tmp/stargazer_cli_history_<uid> atomically.
	 * The username from the request header is used for the filename
	 * to prevent path traversal via the payload.
	 */
	(void)payload;  /* payload contains history lines */

	if (!user || !user[0]) {
		send_error(client_fd, SG_ERR_MISSING_ARG,
			   "user required");
		return 0;
	}

	/* Validate no path traversal in username (defense in depth) —
	 * checked before building the path so an invalid username
	 * never touches snprintf. */
	if (strchr(user, '/') || strchr(user, '.')) {
		send_error(client_fd, SG_ERR_INVALID_ARG,
			   "invalid username for history path");
		return 0;
	}

	/* Build safe filename using the authenticated username */
	char hist_path[256];
	snprintf(hist_path, sizeof(hist_path),
		 "/tmp/stargazer_cli_history_%s", user);

	/* Find history content after "user=<username>\n" */
	const char *hist_data = payload;
	if (payload && strncmp(payload, "user=", 5) == 0) {
		const char *nl = strchr(payload, '\n');
		hist_data = nl ? nl + 1 : "";
	}

	if (!hist_data || !hist_data[0]) {
		/* Empty history — nothing to save */
		send_ok(client_fd, NULL, NULL);
		return 0;
	}

	/* Atomic write: tmp + rename */
	char tmppath[280];
	snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d",
		 hist_path, (int)getpid());

	int fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		send_error(client_fd, SG_ERR_IO_FAIL,
			   "cannot write history");
		return 0;
	}

	size_t hlen = strlen(hist_data);
	ssize_t written = 0;
	while ((size_t)written < hlen) {
		ssize_t n = write(fd, hist_data + written,
				  hlen - (size_t)written);
		if (n <= 0) {
			close(fd);
			unlink(tmppath);
			send_error(client_fd, SG_ERR_IO_FAIL,
				   "write failed");
			return 0;
		}
		written += n;
	}
	close(fd);

	if (rename(tmppath, hist_path) != 0) {
		unlink(tmppath);
		send_error(client_fd, SG_ERR_IO_FAIL, "rename failed");
		return 0;
	}

	send_ok(client_fd, NULL, NULL);
	return 0;
}

/* ── SG_CMD_HISTORY_LOAD (664) ─────────────────────────────────────────── */

int handle_history_load(int client_fd, const char *user,
			const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	if (!user || !user[0]) {
		send_error(client_fd, SG_ERR_MISSING_ARG,
			   "user required");
		return 0;
	}

	/* Validate no path traversal in username (defense in depth) —
	 * checked before building the path. */
	if (strchr(user, '/') || strchr(user, '.')) {
		send_error(client_fd, SG_ERR_INVALID_ARG,
			   "invalid username for history path");
		return 0;
	}

	char hist_path[256];
	snprintf(hist_path, sizeof(hist_path),
		 "/tmp/stargazer_cli_history_%s", user);

	char buf[SG_RESPONSE_MAX];
	ssize_t n = read_small_file(hist_path, buf, sizeof(buf));
	if (n < 0) {
		/* No history file is normal — return empty */
		send_ok(client_fd, NULL, NULL);
		return 0;
	}

	send_ok(client_fd, NULL, buf);
	return 0;
}

/* ── SG_CMD_DIAG_BUSYBOX_LIST (653) ───────────────────────────────────── */

/*
 * Enumerate every symlink under /bin, /sbin, /usr/bin, /usr/sbin that
 * resolves to /bin/busybox, and return one path per line. Used by the
 * BUSYBOX-WHITELIST selftest to detect drift between the committed
 * configs/busybox.config.fragment and what actually shipped in the rootfs.
 *
 * The CLI is sandboxed (no readlinkat/getdents64), so this enumeration
 * must run in mgmtd.
 */
int handle_diag_busybox_list(int client_fd, const char *user,
			     const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	static const char *dirs[] = {
		"/bin", "/sbin", "/usr/bin", "/usr/sbin", NULL
	};

	char resp[SG_RESPONSE_MAX];
	size_t pos = 0;
	resp[0] = '\0';

	for (int i = 0; dirs[i]; i++) {
		DIR *d = opendir(dirs[i]);
		if (!d)
			continue;

		struct dirent *de;
		while ((de = readdir(d)) != NULL) {
			if (de->d_name[0] == '.')
				continue;

			char path[512];
			int n = snprintf(path, sizeof(path), "%s/%s",
					 dirs[i], de->d_name);
			if (n <= 0 || (size_t)n >= sizeof(path))
				continue;

			char target[256];
			ssize_t tlen = readlink(path, target,
						sizeof(target) - 1);
			if (tlen <= 0)
				continue;
			target[tlen] = '\0';

			/* Only include symlinks resolving to /bin/busybox */
			if (strcmp(target, "/bin/busybox") != 0)
				continue;

			buf_appendf(resp, sizeof(resp), &pos, "%s\n", path);
		}
		closedir(d);
	}

	send_ok(client_fd, NULL, resp);
	return 0;
}

/* ── SG_CMD_SYS_LIST (617) ────────────────────────────────────────────── */

#define SYS_LIST_MAX      512   /* max binaries collected per group */
#define SYS_LIST_NAMELEN  48    /* max basename length kept            */

static int sys_list_namecmp(const void *a, const void *b)
{
	return strcmp((const char *)a, (const char *)b);
}

/*
 * Enumerate every executable under /bin, /sbin, /usr/bin, /usr/sbin and
 * return them grouped (busybox applets vs standalone binaries), sorted and
 * word-wrapped, ready for the CLI to print verbatim. Backs the
 * `execute system ?` listing.
 *
 * Admin-only, matching the `execute system` command itself. The CLI is
 * sandboxed (no getdents64/readlinkat), so this enumeration runs in mgmtd.
 */
int handle_sys_list(int client_fd, const char *user,
		    const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "admin permission required");
		return 0;
	}

	static const char *dirs[] = {
		"/bin", "/sbin", "/usr/bin", "/usr/sbin", NULL
	};

	/* static (not stack): two 24 KiB arrays — handler runs serially. */
	static char applets[SYS_LIST_MAX][SYS_LIST_NAMELEN];
	static char standalone[SYS_LIST_MAX][SYS_LIST_NAMELEN];
	int n_applet = 0, n_stand = 0;

	for (int i = 0; dirs[i]; i++) {
		DIR *d = opendir(dirs[i]);
		if (!d)
			continue;
		struct dirent *de;
		while ((de = readdir(d)) != NULL) {
			if (de->d_name[0] == '.')
				continue;

			char path[512];
			int n = snprintf(path, sizeof(path), "%s/%s",
					 dirs[i], de->d_name);
			if (n <= 0 || (size_t)n >= sizeof(path))
				continue;

			/* Only runnable files (resolves symlinks). */
			if (access(path, X_OK) != 0)
				continue;

			/* Skip implausibly long basenames (keeps the copy
			 * below bounded and the compiler's truncation check
			 * satisfied). */
			size_t nlen = strlen(de->d_name);
			if (nlen >= SYS_LIST_NAMELEN)
				continue;

			char target[256];
			ssize_t tlen = readlink(path, target, sizeof(target) - 1);
			int is_applet = (tlen > 0 &&
					 (target[tlen] = '\0',
					  strcmp(target, "/bin/busybox") == 0));

			char (*arr)[SYS_LIST_NAMELEN] =
				is_applet ? applets : standalone;
			int *cnt = is_applet ? &n_applet : &n_stand;

			/* Dedup by basename across directories. */
			int dup = 0;
			for (int k = 0; k < *cnt; k++) {
				if (strcmp(arr[k], de->d_name) == 0) {
					dup = 1;
					break;
				}
			}
			if (dup || *cnt >= SYS_LIST_MAX)
				continue;
			memcpy(arr[(*cnt)++], de->d_name, nlen + 1);
		}
		closedir(d);
	}

	qsort(applets, n_applet, SYS_LIST_NAMELEN, sys_list_namecmp);
	qsort(standalone, n_stand, SYS_LIST_NAMELEN, sys_list_namecmp);

	char resp[SG_RESPONSE_MAX];
	size_t pos = 0;
	resp[0] = '\0';

	/* Two groups, each word-wrapped at ~72 cols with a 4-space indent. */
	for (int g = 0; g < 2; g++) {
		char (*arr)[SYS_LIST_NAMELEN] = g ? standalone : applets;
		int cnt = g ? n_stand : n_applet;
		buf_appendf(resp, sizeof(resp), &pos, "  %s (%d):\n",
			    g ? "Standalone binaries" : "BusyBox applets", cnt);
		int col = 0;
		for (int k = 0; k < cnt; k++) {
			int wlen = (int)strlen(arr[k]);
			if (col == 0) {
				buf_appendf(resp, sizeof(resp), &pos, "    ");
				col = 4;
			} else if (col + 2 + wlen > 72) {
				buf_appendf(resp, sizeof(resp), &pos, "\n    ");
				col = 4;
			} else {
				buf_appendf(resp, sizeof(resp), &pos, "  ");
				col += 2;
			}
			buf_appendf(resp, sizeof(resp), &pos, "%s", arr[k]);
			col += wlen;
		}
		buf_appendf(resp, sizeof(resp), &pos, "\n");
	}

	send_ok(client_fd, NULL, resp);
	return 0;
}

/* ── SG_CMD_DIAG_NTP (652) ────────────────────────────────────────────── */

int handle_diag_ntp(int client_fd, const char *user,
		    const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	char resp[SG_RESPONSE_MAX];
	size_t pos = 0;

	/* NTP server from config */
	char *data = sg_db_get("system_ntp", "0");
	char server[128] = {0};
	if (data) {
		extract_val(data, "server", server, sizeof(server));
		free(data);
	}

	buf_appendf(resp, sizeof(resp), &pos,
		    "server=%s\n", server[0] ? server : "(none)");

	/* ntpd process status via supervisor */
	pid_t pid = supervisor_get_pid("ntpd");
	buf_appendf(resp, sizeof(resp), &pos,
		    "status=%s\n", pid > 0 ? "running" : "stopped");
	buf_appendf(resp, sizeof(resp), &pos,
		    "pid=%d\n", (int)pid);

	/* Current system time */
	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);
	char ts[64];
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tm);
	buf_appendf(resp, sizeof(resp), &pos, "time=%s\n", ts);

	send_ok(client_fd, NULL, pos > 0 ? resp : NULL);
	return 0;
}

/*
 * json_escape_field — escape a string for a JSON double-quoted value.
 *
 * Escapes the metacharacters " and \ and any control byte (< 0x20), so
 * untrusted input (e.g. the DHCP option-12 hostname, controlled by any LAN
 * client) cannot break out of the JSON string. Writes at most outsz-1 chars
 * + NUL; stops early (never truncates mid-escape) if the escaped form would
 * not fit.
 */
static void json_escape_field(const char *in, char *out, size_t outsz)
{
	size_t o = 0;

	if (outsz == 0)
		return;
	for (size_t i = 0; in && in[i] && o + 7 < outsz; i++) {
		unsigned char c = (unsigned char)in[i];

		if (c == '"' || c == '\\') {
			out[o++] = '\\';
			out[o++] = (char)c;
		} else if (c == '\n') {
			out[o++] = '\\'; out[o++] = 'n';
		} else if (c == '\r') {
			out[o++] = '\\'; out[o++] = 'r';
		} else if (c == '\t') {
			out[o++] = '\\'; out[o++] = 't';
		} else if (c < 0x20) {
			o += (size_t)snprintf(out + o, outsz - o, "\\u%04x", c);
		} else {
			out[o++] = (char)c;
		}
	}
	out[o] = '\0';
}

/* ─────────────────────────────────────────────────────────────────────────
 * handle_diag_dhcp_leases — active leases from all udhcpd pools.
 *
 * Reads each pool's binary lease file at /var/run/udhcpd-<id>.leases.
 * File layout (from busybox udhcpd):
 *   [int64_t written_at, big-endian]
 *   [struct dyn_lease × N, PACKED, 34 bytes each]:
 *     uint32_t expires  — seconds remaining from written_at, htonl
 *     uint32_t lease_nip — IP in network byte order
 *     uint8_t  lease_mac[6]
 *     char     hostname[20]
 *
 * Returns JSON: {"leases":[{"pool":"..","ip":"..","mac":"..","hostname":"..","expires":<unix>}]}
 * ─────────────────────────────────────────────────────────────────────────
 */
int handle_diag_dhcp_leases(int client_fd, const char *user,
			     const char *payload,
			     const sg_request_hdr_t *hdr)
{
	(void)payload;
	(void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'monitor' permission");
		return 0;
	}

	/* udhcpd dyn_lease struct (PACKED, 36 bytes — matches busybox dhcpd.h) */
	struct __attribute__((packed)) dyn_lease {
		uint32_t expires;
		uint32_t lease_nip;
		uint8_t  lease_mac[6];
		char     hostname[20];
		uint8_t  pad[2];
	};

	size_t cap = 4096;
	char *json = malloc(cap);
	if (!json) {
		send_error(client_fd, SG_ERR_SYSTEM_FAIL, "Out of memory");
		return 0;
	}
	size_t pos = 0;
	int first = 1;

#define LEASE_JA(s, n) do { \
	while (pos + (n) + 1 >= cap) { \
		cap *= 2; \
		char *_t = realloc(json, cap); \
		if (!_t) { free(json); \
			send_error(client_fd, SG_ERR_SYSTEM_FAIL, "Out of memory"); \
			return 0; } \
		json = _t; \
	} \
	memcpy(json + pos, (s), (n)); \
	pos += (n); \
} while (0)

	LEASE_JA("{\"leases\":[", 11);

	/* Enumerate all DHCP server pools */
	char *pool_list = sg_db_list("network_dhcp-server");
	if (pool_list) {
		char *p = pool_list;
		while (*p) {
			char *nl = strchr(p, '\n');
			size_t plen = nl ? (size_t)(nl - p) : strlen(p);
			if (plen == 0) {
				if (!nl) break;
				p = nl + 1;
				continue;
			}
			char pool_id[64];
			if (plen >= sizeof(pool_id))
				plen = sizeof(pool_id) - 1;
			memcpy(pool_id, p, plen);
			pool_id[plen] = '\0';

			char lease_path[128];
			snprintf(lease_path, sizeof(lease_path),
				 "/var/run/udhcpd-%s.leases", pool_id);

			FILE *lf = fopen(lease_path, "rb");
			if (!lf) {
				if (!nl) break;
				p = nl + 1;
				continue;
			}

			int64_t written_at_be;
			if (fread(&written_at_be, sizeof(written_at_be), 1, lf) != 1) {
				fclose(lf);
				if (!nl) break;
				p = nl + 1;
				continue;
			}
			/* Big-endian to host */
			uint8_t *wb = (uint8_t *)&written_at_be;
			int64_t written_at = ((int64_t)wb[0] << 56) |
					     ((int64_t)wb[1] << 48) |
					     ((int64_t)wb[2] << 40) |
					     ((int64_t)wb[3] << 32) |
					     ((int64_t)wb[4] << 24) |
					     ((int64_t)wb[5] << 16) |
					     ((int64_t)wb[6] <<  8) |
					     ((int64_t)wb[7]);

			/* Reject files written more than 12 hours ago (sanity check) */
			time_t now = time(NULL);
			int64_t age = (int64_t)now - written_at;
			if (age < 0 || age > 12 * 3600) {
				fclose(lf);
				if (!nl) break;
				p = nl + 1;
				continue;
			}

			struct dyn_lease rec;
			while (fread(&rec, sizeof(rec), 1, lf) == 1) {
				if (rec.lease_nip == 0)
					continue;

				/* seconds-remaining stored as htonl relative to written_at */
				uint32_t rel = ntohl(rec.expires);
				int64_t abs_exp = written_at + (int64_t)rel;
				if (abs_exp < (int64_t)now)
					continue;

				struct in_addr ia;
				ia.s_addr = rec.lease_nip;
				char ip_str[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &ia, ip_str, sizeof(ip_str));

				char mac_str[24];
				snprintf(mac_str, sizeof(mac_str),
					 "%02x:%02x:%02x:%02x:%02x:%02x",
					 rec.lease_mac[0], rec.lease_mac[1],
					 rec.lease_mac[2], rec.lease_mac[3],
					 rec.lease_mac[4], rec.lease_mac[5]);

				char hostname[21];
				memcpy(hostname, rec.hostname, 20);
				hostname[20] = '\0';

				/* hostname is DHCP option-12 (attacker-
				 * controlled); pool_id is config-derived.
				 * Escape both before interpolating into JSON
				 * so a " or \ cannot break the structure. A
				 * 20-byte hostname can expand ~6x when fully
				 * escaped, so size the buffer for it. */
				char host_esc[128], pool_esc[256];
				json_escape_field(hostname, host_esc,
						  sizeof(host_esc));
				json_escape_field(pool_id, pool_esc,
						  sizeof(pool_esc));

				if (!first)
					LEASE_JA(",", 1);
				first = 0;

				char entry[512];
				int elen = snprintf(entry, sizeof(entry),
					"{\"pool\":\"%s\","
					"\"ip\":\"%s\","
					"\"mac\":\"%s\","
					"\"hostname\":\"%s\","
					"\"expires\":%lld}",
					pool_esc, ip_str, mac_str, host_esc,
					(long long)abs_exp);
				if (elen > 0 && (size_t)elen < sizeof(entry))
					LEASE_JA(entry, (size_t)elen);
			}
			fclose(lf);

			if (!nl) break;
			p = nl + 1;
		}
		free(pool_list);
	}

	LEASE_JA("]}", 2);
	json[pos] = '\0';

	send_ok(client_fd, NULL, json);
	free(json);
	return 0;
}
