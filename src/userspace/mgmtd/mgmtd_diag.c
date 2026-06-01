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

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
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
 * ct_emit_line - parse one /proc/net/nf_conntrack line, append a normalized
 * session line to `out`:
 *   proto=<p> state=<S> src=<ip>:<port> dst=<ip>:<port> pkts=<n> bytes=<n> policy=<name> iif=<if> oif=<if>
 * pkts/bytes sum both directions (nf_conntrack_acct); policy is resolved from
 * the flow's connmark via `map`; iif/oif from the ML iface overlay via `imap`.
 * Returns 0 on success, -1 if unparseable. `line` is modified by strtok_r.
 */
static int ct_emit_line(char *line, struct dynbuf *out,
			const struct ct_pol *map, int nmap,
			const struct ct_iface_ent *imap, int nimap)
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

	unsigned cmkid = (unsigned)(mark >> SG_CMK_PID_SHIFT);
	const char *policy = ct_policy_name(map, nmap, cmkid);

	/* Overlay the in/out interfaces recorded in the ML extension, matched
	 * by the original 5-tuple. Local/INPUT flows carry none → "-". */
	char key[80];
	ct_flow_key(key, sizeof(key), proto, src, sport, dst, dport);
	unsigned iif = 0, oif = 0;
	ct_iface_lookup(imap, nimap, key, &iif, &oif);
	char ibuf[IF_NAMESIZE], obuf[IF_NAMESIZE];
	const char *iifn = ct_ifname(iif, ibuf, sizeof(ibuf));
	const char *oifn = ct_ifname(oif, obuf, sizeof(obuf));

	char l[320];
	int n = snprintf(l, sizeof(l),
			 "proto=%s state=%s src=%s:%u dst=%s:%u pkts=%llu bytes=%llu policy=%s iif=%s oif=%s\n",
			 proto, state[0] ? state : "-",
			 src, sport, dst, dport, pkts, bytes, policy, iifn, oifn);
	if (n > 0)
		dbuf_append(out, l, (size_t)n);
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
	(void)payload; (void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "monitor permission required");
		return 0;
	}

	FILE *fp = fopen("/proc/net/nf_conntrack", "r");
	if (!fp) {
		send_ok(client_fd, "not_available",
			"Connection tracking not available\n");
		return 0;
	}

	struct dynbuf out;
	if (dbuf_init(&out, 8192) < 0) {
		fclose(fp);
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

	long count = 0;
	char line[1024];
	while (fgets(line, sizeof(line), fp)) {
		if (ct_emit_line(line, &out, pmap, npmap, imap, nimap) == 0)
			count++;
	}
	fclose(fp);
	free(pmap);
	free(imap);

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
	(void)payload; (void)hdr;

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

	if (conntrack_flush_all() < 0) {
		send_error(client_fd, SG_ERR_SYSTEM_FAIL,
			   "conntrack flush failed");
		return 0;
	}

	char resp[64];
	snprintf(resp, sizeof(resp), "flushed=%ld\n", before);
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
#define SG_CTA_MARK_MASK        11   /* masked connmark update */
#define SG_IPCTNL_MSG_CT_NEW    0    /* also used as "update" (no NLM_F_CREATE) */
#define SG_NLA_F_NESTED         0x8000

/* SG_CMK_DIRTY / SG_CMK_PID_SHIFT are defined up in the nf_conntrack readers
 * section (above ct_emit_line), which also uses them. */

/* Must match the kernel struct nf_conn_ml (same host/arch, host byte order). */
struct sg_nf_conn_ml {
	uint64_t first_ns, last_ns, iat_sum_ns;
	uint32_t iat_count;
	uint16_t tcp_flags[2];
	uint16_t len_min[2];
	uint16_t len_max[2];
	int32_t  ml_score;
	uint16_t iif;   /* ingress ifindex, original direction (0 = unset) */
	uint16_t oif;   /* egress  ifindex, original direction (0 = unset) */
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
	unsigned long long dur_ms, iat_us;
	char line[320];
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
			int pl = 0;
			const void *pn = sg_nla_find(pr, l, SG_CTA_PROTO_NUM, &pl);
			const void *sp = sg_nla_find(pr, l, SG_CTA_PROTO_SRC_PORT, &pl);
			const void *dp = sg_nla_find(pr, l, SG_CTA_PROTO_DST_PORT, &pl);

			if (pn) proto = *(const uint8_t *)pn;
			if (sp) sport = ntohs(*(const uint16_t *)sp);
			if (dp) dport = ntohs(*(const uint16_t *)dp);
		}
	}

	dur_ms = (ml.last_ns > ml.first_ns) ?
		 (ml.last_ns - ml.first_ns) / 1000000ULL : 0;
	iat_us = ml.iat_count ? (ml.iat_sum_ns / ml.iat_count) / 1000ULL : 0;

	ll = snprintf(line, sizeof(line),
		"proto=%u src=%s:%u dst=%s:%u iat_avg_us=%llu dur_ms=%llu "
		"len_o=%u-%u len_r=%u-%u flags_o=0x%02x flags_r=0x%02x score=%d\n",
		proto, src, sport, dst, dport, iat_us, dur_ms,
		ml.len_min[0] == UINT16_MAX ? 0 : ml.len_min[0], ml.len_max[0],
		ml.len_min[1] == UINT16_MAX ? 0 : ml.len_min[1], ml.len_max[1],
		ml.tcp_flags[0], ml.tcp_flags[1], ml.ml_score);
	if (ll > 0)
		dbuf_append(out, line, (size_t)ll);
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
					int pl = 0;
					const void *pn = sg_nla_find(pr, l,
							SG_CTA_PROTO_NUM, &pl);
					const void *sp = sg_nla_find(pr, l,
							SG_CTA_PROTO_SRC_PORT, &pl);
					const void *dp = sg_nla_find(pr, l,
							SG_CTA_PROTO_DST_PORT, &pl);
					if (pn) pname = ct_proto_name(*(const uint8_t *)pn);
					if (sp) sport = ntohs(*(const uint16_t *)sp);
					if (dp) dport = ntohs(*(const uint16_t *)dp);
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

/* One buffered live flow: its CTA_TUPLE_ORIG payload (verbatim, to echo back in
 * the update) plus the current connmark. */
struct sg_dirty_ent {
	uint32_t mark;
	uint16_t tlen;
	uint8_t  tuple[128];
};

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
 * conntrack_mark_dirty_by_policy - set the connmark DIRTY bit on live flows so
 * they re-traverse the freshly-rebuilt FORWARD chain on their next packet.
 *
 * pid == 0  → every flow. pid == cmkid → only flows that policy stamped
 * (mark>>SG_CMK_PID_SHIFT == pid). Two passes on one in-process NFNETLINK
 * socket: (1) CT_GET|NLM_F_DUMP, buffer matching flows; (2) CT_NEW masked
 * update per flow, setting DIRTY without disturbing the policy_id bits.
 *
 * Returns 0 on success, negative on a hard failure (caller then flushes the
 * whole table). Benign per-flow update errors (e.g. a flow torn down between
 * the two passes) are tolerated; only an all-updates-failed run is treated as
 * a hard failure.
 */
int conntrack_mark_dirty_by_policy(unsigned int pid)
{
	int fd, rc = -1;
	struct sockaddr_nl sa;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
	struct sg_dirty_ent *ents = NULL;
	size_t n = 0, cap = 0;
	unsigned int seq = 100;
	char rbuf[32768];

	fd = socket(AF_NETLINK, SOCK_RAW, SG_NETLINK_NETFILTER);
	if (fd < 0)
		return -1;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	/* ── Pass 1: dump every flow, buffer the ones we need to dirty ── */
	{
		struct {
			struct nlmsghdr    nlh;
			struct sg_nfgenmsg nfg;
		} req;
		int done = 0, dump_ok = 0;

		memset(&req, 0, sizeof(req));
		req.nlh.nlmsg_len    = NLMSG_LENGTH(sizeof(req.nfg));
		req.nlh.nlmsg_type   = (SG_NFNL_SUBSYS_CTNETLINK << 8) |
				       SG_IPCTNL_MSG_CT_GET;
		req.nlh.nlmsg_flags  = NLM_F_REQUEST | NLM_F_DUMP;
		req.nlh.nlmsg_seq    = ++seq;
		req.nfg.nfgen_family = AF_INET;

		if (sendto(fd, &req, req.nlh.nlmsg_len, 0,
			   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			close(fd);
			return -1;
		}

		while (!done) {
			ssize_t rn = recv(fd, rbuf, sizeof(rbuf), 0);
			struct nlmsghdr *nh;
			int rem;

			if (rn <= 0)
				break;		/* timeout/error: dump incomplete */
			rem = (int)rn;
			for (nh = (struct nlmsghdr *)rbuf; NLMSG_OK(nh, rem);
			     nh = NLMSG_NEXT(nh, rem)) {
				const void *attrs, *mp, *tup;
				int alen, mlen = 0, tlen = 0;
				uint32_t mark;

				/* A clean NLMSG_DONE is the only success terminator.
				 * NLMSG_ERROR means the dump request was rejected —
				 * leave dump_ok = 0 so we fall back to a full flush
				 * rather than mistaking a failed dump for an empty
				 * table and skipping re-evaluation. */
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

				/* Narrow filter: only the policy's own flows. */
				if (pid != 0 &&
				    (mark >> SG_CMK_PID_SHIFT) != pid)
					continue;
				/* Already dirty → nothing to do. */
				if (mark & SG_CMK_DIRTY)
					continue;

				tup = sg_nla_find(attrs, alen,
						  SG_CTA_TUPLE_ORIG, &tlen);
				if (!tup || tlen <= 0 ||
				    tlen > (int)sizeof(ents[0].tuple))
					continue;	/* can't address it — skip */

				if (n == cap) {
					size_t ncap = cap ? cap * 2 : 256;
					struct sg_dirty_ent *t =
						realloc(ents,
							ncap * sizeof(*ents));
					if (!t) {
						free(ents);
						close(fd);
						return -1;  /* OOM → flush */
					}
					ents = t;
					cap = ncap;
				}
				ents[n].mark = mark;
				ents[n].tlen = (uint16_t)tlen;
				memcpy(ents[n].tuple, tup, (size_t)tlen);
				n++;
			}
		}

		/* Dump ended without a clean NLMSG_DONE (rejected request or a
		 * recv timeout mid-stream) → we may not have seen every flow.
		 * Fail safe: tell the caller to flush rather than leave some
		 * now-denied flows carrying a stale clean fast-path mark. */
		if (!dump_ok) {
			free(ents);
			close(fd);
			return -1;
		}
	}

	if (n == 0) {		/* nothing matched — success, nothing to do */
		free(ents);
		close(fd);
		return 0;
	}

	/* ── Pass 2: masked CT_NEW update setting DIRTY on each buffered flow ── */
	{
		size_t i, fails = 0;

		for (i = 0; i < n; i++) {
			char msg[512];
			struct nlmsghdr *nlh = (struct nlmsghdr *)msg;
			struct sg_nfgenmsg *nfg =
				(struct sg_nfgenmsg *)(msg + NLMSG_HDRLEN);
			int off = NLMSG_HDRLEN +
				  NLMSG_ALIGN(sizeof(struct sg_nfgenmsg));
			uint32_t bmark = htonl(ents[i].mark | SG_CMK_DIRTY);
			uint32_t bmask = htonl(SG_CMK_DIRTY);

			memset(msg, 0, sizeof(msg));
			if (sg_nla_put(msg, &off, sizeof(msg),
				       SG_CTA_TUPLE_ORIG | SG_NLA_F_NESTED,
				       ents[i].tuple, ents[i].tlen) < 0 ||
			    sg_nla_put(msg, &off, sizeof(msg),
				       SG_CTA_MARK, &bmark, 4) < 0 ||
			    sg_nla_put(msg, &off, sizeof(msg),
				       SG_CTA_MARK_MASK, &bmask, 4) < 0) {
				fails++;
				continue;
			}

			nlh->nlmsg_len   = (uint32_t)off;
			nlh->nlmsg_type  = (SG_NFNL_SUBSYS_CTNETLINK << 8) |
					   SG_IPCTNL_MSG_CT_NEW;
			nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
			nlh->nlmsg_seq   = ++seq;
			nfg->nfgen_family = AF_INET;

			if (sendto(fd, msg, off, 0, (struct sockaddr *)&sa,
				   sizeof(sa)) < 0) {
				fails++;
				continue;
			}
			/* Drain the ACK so the socket buffer can't back up. A
			 * per-flow ENOENT (flow vanished between passes) arrives
			 * as a real NLMSG_ERROR and is benign. A missing ACK
			 * (recv timeout / short read) means the update was NOT
			 * confirmed — count it as a failure too, mirroring the
			 * pass-1 dump_ok discipline, so an all-timed-out run
			 * yields fails >= n → flush rather than silently leaving
			 * stale clean marks (fail-closed). */
			{
				ssize_t rn = recv(fd, rbuf, sizeof(rbuf), 0);
				if (rn < (ssize_t)NLMSG_HDRLEN) {
					fails++;	/* timeout / short read */
				} else {
					struct nlmsghdr *rh =
						(struct nlmsghdr *)rbuf;
					if (rh->nlmsg_type == NLMSG_ERROR) {
						struct nlmsgerr *e =
							NLMSG_DATA(rh);
						if (e->error != 0)
							fails++;
					}
				}
			}
		}
		/* Every single update failed → masked update unsupported or the
		 * table is unreachable; tell the caller to flush instead. */
		rc = (fails >= n) ? -1 : 0;
	}

	free(ents);
	close(fd);
	return rc;
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
				/* Scrub non-printable bytes from hostname */
				for (int i = 0; i < 20; i++)
					if ((unsigned char)hostname[i] < 0x20)
						hostname[i] = '\0';

				if (!first)
					LEASE_JA(",", 1);
				first = 0;

				char entry[256];
				int elen = snprintf(entry, sizeof(entry),
					"{\"pool\":\"%s\","
					"\"ip\":\"%s\","
					"\"mac\":\"%s\","
					"\"hostname\":\"%s\","
					"\"expires\":%lld}",
					pool_id, ip_str, mac_str, hostname,
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
