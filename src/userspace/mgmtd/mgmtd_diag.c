/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_diag.c — System diagnostics, debug state, and history handlers
 *
 * Reads /proc, /sys, and config files on behalf of the sandboxed CLI.
 * The CLI cannot open files after sandbox activation — all file reads
 * are proxied through these IPC handlers.
 *
 * Permission requirements:
 *   - Diagnostics (640-645, 650-651): "monitor" permission
 *   - Debug state (660-662): "admin" permission
 *   - History save (663): any authenticated user
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "mgmtd_internal.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
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

	/* Read thermal zones */
	char path[128], tbuf[32];
	for (int z = 0; z < 16; z++) {
		snprintf(path, sizeof(path),
			 "/sys/class/thermal/thermal_zone%d/temp", z);
		if (read_small_file(path, tbuf, sizeof(tbuf)) > 0) {
			/* Trim newline */
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
		send_error(client_fd, SG_ERR_IO_FAIL,
			   "cannot read /proc/meminfo");
		return 0;
	}

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

	char resp[256];
	snprintf(resp, sizeof(resp), "MemTotal=%ld\nMemAvailable=%ld\n",
		 mt, ma);
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

	struct statvfs sv;
	if (statvfs("/", &sv) != 0) {
		send_error(client_fd, SG_ERR_IO_FAIL, "statvfs failed");
		return 0;
	}

	char resp[256];
	snprintf(resp, sizeof(resp),
		 "blocks=%lu\nbfree=%lu\nbavail=%lu\nfrsize=%lu\n",
		 (unsigned long)sv.f_blocks,
		 (unsigned long)sv.f_bfree,
		 (unsigned long)sv.f_bavail,
		 (unsigned long)sv.f_frsize);
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
						/* Parse rx_bytes (field 1) and tx_bytes (field 9) */
						const char *fp = colon + 1;
						while (*fp == ' ') fp++;
						unsigned long long rx = strtoull(fp, NULL, 10);

						for (int f = 0; f < 8; f++) {
							while (*fp && *fp != ' ' && *fp != '\n') fp++;
							while (*fp == ' ') fp++;
						}
						unsigned long long tx = strtoull(fp, NULL, 10);

						buf_appendf(resp, sizeof(resp), &pos,
							    "iface=%s rx_bytes=%llu tx_bytes=%llu",
							    iname, rx, tx);

						/* Link speed */
						char spath[128], spd[32];
						snprintf(spath, sizeof(spath),
							 "/sys/class/net/%s/speed",
							 iname);
						if (read_small_file(spath, spd, sizeof(spd)) > 0) {
							size_t slen = strlen(spd);
							while (slen > 0 && (spd[slen-1] == '\n' || spd[slen-1] == '\r'))
								spd[--slen] = '\0';
							buf_appendf(resp, sizeof(resp), &pos,
								    " speed=%s", spd);
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
			while (*pp && *pp != ' ') pp++;
			while (*pp == ' ') pp++;
			long rss = strtol(pp, NULL, 10);

			buf_appendf(resp, sizeof(resp), &pos,
				    "proc=%d %s %c %lu %lu %lu %ld\n",
				    pid, comm, state,
				    utime, stime, vsize, rss);

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

/* ── SG_CMD_SHOW_SESSIONS (650) ────────────────────────────────────────── */

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

	char buf[SG_RESPONSE_MAX];
	ssize_t n = read_small_file("/proc/stargazer/sessions",
				    buf, sizeof(buf));
	if (n < 0) {
		send_ok(client_fd, "not_available",
			"Session tracking not available "
			"(module not loaded)\n");
		return 0;
	}

	send_ok(client_fd, NULL, buf);
	return 0;
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
