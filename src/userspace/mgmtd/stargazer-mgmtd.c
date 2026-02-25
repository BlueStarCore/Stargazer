/* SPDX-License-Identifier: MIT */
/*
 * stargazer-mgmtd — Stargazer NGFW Management Daemon
 *
 * Runs as root. Listens on a Unix domain socket for requests from CLI
 * processes (which run as unprivileged users). Performs all privileged
 * operations: config file I/O, shadow password updates, iptables, ip route,
 * hostname changes, etc.
 *
 * Architecture:
 *   - Single-threaded, sequential request processing (sufficient for CLI)
 *   - Unix domain socket at /run/stargazer-mgmtd.sock
 *   - Each CLI connection: read request → process → write response → close
 *   - All system errors mapped to sg_status_t, never leaked to CLI
 *   - Syslog for internal diagnostics
 *
 * Build: cross-compile with musl-gcc, static linking
 *   aarch64-linux-musl-gcc -static -o stargazer-mgmtd stargazer-mgmtd.c -lcrypt
 */

#define _GNU_SOURCE
#include <crypt.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/file.h>
#include <sys/wait.h>

#include "stargazer_ipc.h"
#include "password_policy.h"
#include "sg_db.h"
#include "sg_validate.h"
#include "mgmtd_apply.h"

/* ── Constants ──────────────────────────────────────────────────────────── */

#define CMD_BUF_SIZE     512
#ifndef CONF_DIR
#define CONF_DIR         "/etc/stargazer"
#endif
#define AUDIT_LOG        "/var/log/stargazer-audit.log"
#define AUDIT_LOG_FB     "/tmp/stargazer-audit.log"
#define SESSION_REV_FILE "/run/stargazer-session.rev"
#define MAX_LINE         1024
#define MAX_SALT_LEN     32
#define MAX_CLIENTS_QUEUE 8
#define BUF_SIZE         (sizeof(sg_request_hdr_t) + SG_PAYLOAD_MAX)
#define DEBUG_STATE_FILE  "/tmp/stargazer-debug.conf"
#define MGMT_DEFAULT_IP   "192.168.99.99/24" /* first NIC on first boot */
#define SHADOW_LOCK_MODE  0600  /* /etc/shadow.lock — owner-only          */
#define SHADOW_FILE_MODE  0640  /* /etc/shadow — owner rw, group read     */

/* /etc/shadow field values (date fields are in days since epoch) */
#define SHADOW_LAST_CHANGED  "19700"  /* password last changed (days)   */
#define SHADOW_MAX_DAYS      "99999"  /* max days before must change    */
#define SHADOW_WARN_DAYS     "7"      /* days of warning before expiry  */

#define DEBUG_BUF_SIZE 4096
static char debug_buf[DEBUG_BUF_SIZE];
static int  debug_buf_used;

/* Per-request debug flags (set from request header) */
static uint8_t g_debug_flags;

static void debug_buf_push(const char *fmt, ...)
{
	int avail = DEBUG_BUF_SIZE - debug_buf_used - 1;
	if (avail <= 0)
		return;
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(debug_buf + debug_buf_used, avail, fmt, ap);
	va_end(ap);
	if (n > 0 && n < avail)
		debug_buf_used += n;
}

static volatile sig_atomic_t g_running = 1;
static int g_listen_fd = -1;  /* listen socket fd, for child to close after fork */

/* ── Input validation ───────────────────────────────────────────────────── */
/* Validators now live in common/sg_validate.c — included via sg_validate.h */

/* ── Interface existence check ─────────────────────────────────────────── */

int iface_exists(const char *name)
{
	char path[256];
	snprintf(path, sizeof(path), "/sys/class/net/%s", name);
	return access(path, F_OK) == 0;
}

/* ── Safe command execution (replaces popen) ──────────────────────────── */

/*
 * safe_exec: fork + execvp with argument array. No shell interpretation.
 * Returns dynamically allocated stdout output (caller frees), or NULL.
 */
char *safe_exec(const char *const argv[])
{
	int pipefd[2];
	if (pipe(pipefd) < 0) return NULL;

	pid_t pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return NULL;
	}

	if (pid == 0) {
		/* Child */
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);
		execvp(argv[0], (char *const *)argv);
		_exit(127);
	}

	/* Parent */
	close(pipefd[1]);

	size_t bufsize = 4096, used = 0;
	char *buf = malloc(bufsize);
	if (!buf) { close(pipefd[0]); waitpid(pid, NULL, 0); return NULL; }

	ssize_t n;
	char tmp[1024];
	while ((n = read(pipefd[0], tmp, sizeof(tmp))) > 0) {
		while (used + (size_t)n + 1 > bufsize) {
			bufsize *= 2;
			char *nb = realloc(buf, bufsize);
			if (!nb) { free(buf); close(pipefd[0]); waitpid(pid, NULL, 0); return NULL; }
			buf = nb;
		}
		memcpy(buf + used, tmp, (size_t)n);
		used += (size_t)n;
	}
	buf[used] = '\0';
	close(pipefd[0]);
	waitpid(pid, NULL, 0);
	return buf;
}

/* ── Debug state ───────────────────────────────────────────────────────── */

static int debug_state_get_bool(const char *key, int defval)
{
	FILE *fp = fopen(DEBUG_STATE_FILE, "r");
	if (!fp)
		return defval;

	char line[128];
	char prefix[64];
	int val = defval;

	snprintf(prefix, sizeof(prefix), "%s=", key);

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, prefix, strlen(prefix)) == 0) {
			const char *v = line + strlen(prefix);
			val = (v[0] == '1') ? 1 : 0;
			break;
		}
	}

	fclose(fp);
	return val;
}

static int mgmtd_debug_enabled(void)
{
	int enabled = debug_state_get_bool("enabled", 0);
	int mgmtd = debug_state_get_bool("mgmtd_debug", 0);
	return enabled && mgmtd;
}

/* ── Logging ────────────────────────────────────────────────────────────── */

void mgmt_log(const char *level, const char *fmt, ...)
{
	if ((strcmp(level, "INFO") == 0 || strcmp(level, "WARN") == 0) &&
	    !mgmtd_debug_enabled())
		return;

	char ts[64];
	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm);

	fprintf(stderr, "%s [mgmtd] %s: ", ts, level);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

static int audit_log(const char *user, const char *event, const char *msg)
{
	const char *path = AUDIT_LOG;
	if (access("/var/log", W_OK) != 0)
		path = AUDIT_LOG_FB;

	char ts[64];
	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tm);

	FILE *fp = fopen(path, "a");
	if (fp) {
		fprintf(fp, "%s user=%s event=%s msg=%s\n", ts, user, event, msg);
		fclose(fp);
		return 0;
	}
	mgmt_log("ERROR", "audit_log: cannot write to %s: %s (event=%s user=%s msg=%s)",
		 path, strerror(errno), event, user, msg);
	return -1;
}

#define AUDIT_WARN " [WARNING: audit log write failed]"

/* ── Signal handling ────────────────────────────────────────────────────── */

static void sig_handler(int sig)
{
	(void)sig;
	g_running = 0;
}

/* ── Safe I/O helpers ───────────────────────────────────────────────────── */

static ssize_t safe_read(int fd, void *buf, size_t len)
{
	size_t done = 0;
	while (done < len) {
		ssize_t n = read(fd, (char *)buf + done, len - done);
		if (n <= 0) {
			if (n < 0 && errno == EINTR) continue;
			return n == 0 ? (ssize_t)done : -1;
		}
		done += (size_t)n;
	}
	return (ssize_t)done;
}

static ssize_t safe_write(int fd, const void *buf, size_t len)
{
	size_t done = 0;
	while (done < len) {
		ssize_t n = write(fd, (const char *)buf + done, len - done);
		if (n <= 0) {
			if (n < 0 && errno == EINTR) continue;
			return -1;
		}
		done += (size_t)n;
	}
	return (ssize_t)done;
}

/* ── Response builder ───────────────────────────────────────────────────── */

static void send_response(int fd, sg_status_t status, const char *extra,
			   const char *payload, uint32_t payload_len)
{
	sg_response_hdr_t resp;
	memset(&resp, 0, sizeof(resp));
	resp.magic = SG_MSG_MAGIC;
	resp.version = SG_MSG_VERSION;
	resp.status = (uint32_t)status;
	if (extra)
		snprintf(resp.extra, sizeof(resp.extra), "%s", extra);
	resp.payload_len = payload_len;

	if (g_debug_flags & SG_DBG_FLAG_MGMTD)
		debug_buf_push("[MGMTD-DBG] -> status=%u\n",
			       (unsigned)status);

	safe_write(fd, &resp, sizeof(resp));
	if (payload_len > 0 && payload)
		safe_write(fd, payload, payload_len);
}

static void send_ok(int fd, const char *extra, const char *payload)
{
	uint32_t plen = payload ? (uint32_t)strlen(payload) : 0;
	send_response(fd, SG_OK, extra, payload, plen);
}

static void send_error(int fd, sg_status_t status, const char *extra)
{
	send_response(fd, status, extra, NULL, 0);
}

/* send_ok with inline audit — appends warning to extra if audit fails */
static void send_ok_audited(int fd, const char *extra, const char *payload,
			    const char *user, const char *event, const char *amsg)
{
	if (audit_log(user, event, amsg) != 0) {
		char warn[SG_EXTRA_MAX];
		snprintf(warn, sizeof(warn), "%s%s",
			 extra ? extra : "", AUDIT_WARN);
		send_ok(fd, warn, payload);
	} else {
		send_ok(fd, extra, payload);
	}
}

/* Forward declaration (defined below, after password/user helpers) */
static sg_status_t apply_config(const char *type, const char *id,
				const char *data, char *result, size_t rsize);

/* ── First-boot database seeding ────────────────────────────────────────── */

/*
 * Seed database with default configuration on first boot.
 * Only runs if no admin profiles exist (empty database).
 * Idempotent: safe to call on every startup.
 */
static void mgmtd_seed_defaults(void)
{
	/* If profiles already exist, database was previously seeded */
	if (sg_db_count("system_admin-profile") > 0)
		return;

	mgmt_log("INFO", "first boot detected — seeding default configuration");

	/* ── Admin profiles ─────────────────────────────────────────── */
	sg_db_set("system_admin-profile", "read-write",
		  "permissions=monitor,configure,admin\n"
		  "description=Full administrative access\n"
		  "builtin=yes\n");

	sg_db_set("system_admin-profile", "read-only",
		  "permissions=monitor\n"
		  "description=Read-only monitoring access\n"
		  "builtin=yes\n");

	/* ── Default admin account ──────────────────────────────────── */
	sg_db_set("system_admin", "admin",
		  "profile=read-write\n"
		  "enforce-change-password=enable\n"
		  "enforce-password-policy=enable\n"
		  "builtin=yes\n");

	/* ── Password policy ────────────────────────────────────────── */
	sg_db_set("system_password-policy", "0",
		  "min-length=8\n"
		  "min-uppercase=1\n"
		  "min-lowercase=1\n"
		  "min-digit=1\n"
		  "min-special=0\n"
		  "builtin=yes\n");

	/* ── System settings ────────────────────────────────────────── */
	sg_db_set("system_settings", "0",
		  "hostname=stargazer\n"
		  "ip-forward=enable\n");

	/* ── Default firewall policy (deny all) ─────────────────────── */
	sg_db_set("firewall_policy", "1",
		  "name=default-deny\n"
		  "srcintf=any\n"
		  "dstintf=any\n"
		  "srcaddr=all\n"
		  "dstaddr=all\n"
		  "action=deny\n"
		  "status=enable\n"
		  "comment=Default deny all traffic\n");

	/* Interfaces and routes are handled by mgmtd_sync_interfaces() */

	mgmt_log("INFO", "default configuration seeded successfully");
}

/* ── Interface discovery and protection ─────────────────────────────────── */

/*
 * Read /sys/class/net/<name>/type and return the value (1 = Ethernet).
 * Returns -1 on error.
 */
static int read_net_type(const char *name)
{
	/* IFNAMSIZ is 16; interface names are always short */
	char nmbuf[16];
	size_t nlen = strlen(name);
	if (nlen >= sizeof(nmbuf))
		return -1;
	memcpy(nmbuf, name, nlen + 1);

	char path[48]; /* "/sys/class/net/" (15) + name (15) + "/type" (5) + NUL */
	snprintf(path, sizeof(path), "/sys/class/net/%.15s/type", nmbuf);
	FILE *fp = fopen(path, "r");
	if (!fp)
		return -1;
	int val = -1;
	if (fscanf(fp, "%d", &val) != 1)
		val = -1;
	fclose(fp);
	return val;
}

/*
 * Read /sys/class/net/<name>/mtu and return the current MTU value.
 * Returns -1 on error.
 */
static int read_iface_mtu(const char *name)
{
	char path[48];
	snprintf(path, sizeof(path), "/sys/class/net/%.15s/mtu", name);
	FILE *fp = fopen(path, "r");
	if (!fp)
		return -1;
	int val = -1;
	if (fscanf(fp, "%d", &val) != 1)
		val = -1;
	fclose(fp);
	return val;
}

/*
 * Query the driver-reported min/max MTU for an interface via netlink
 * (ip -d link show <name>).  Falls back to 68/65535 if unavailable.
 */
void read_iface_mtu_limits(const char *name,
			   int *out_min, int *out_max)
{
	*out_min = 68;
	*out_max = 65535;

	const char *argv[] = {"ip", "-d", "link", "show", name, NULL};
	char *out = safe_exec(argv);
	if (!out)
		return;

	char *p = strstr(out, "minmtu ");
	if (p) {
		int v = atoi(p + 7);
		if (v > 0)
			*out_min = v;
	}
	p = strstr(out, "maxmtu ");
	if (p) {
		int v = atoi(p + 7);
		if (v > 0)
			*out_max = v;
	}
	free(out);
}

/*
 * Sync interface config entries with actual hardware on every boot.
 *
 * - Scans /sys/class/net for Ethernet NICs (type == 1), skips lo and dotfiles
 * - Creates DB entries for new NICs with builtin=yes
 * - Assigns management IP (192.168.99.99/24) to first NIC on first boot
 * - Marks existing NICs as builtin=yes (protects from deletion)
 * - Clears builtin flag from DB entries whose hardware was removed
 */
static void mgmtd_sync_interfaces(void)
{
#define MAX_NICS 16
	char *nics[MAX_NICS];
	int nic_count = 0;

	/* 1. Scan /sys/class/net for Ethernet NICs */
	DIR *d = opendir("/sys/class/net");
	if (!d) {
		mgmt_log("WARN", "sync_interfaces: cannot open /sys/class/net");
		return;
	}

	struct dirent *ent;
	while ((ent = readdir(d)) != NULL && nic_count < MAX_NICS) {
		if (ent->d_name[0] == '.')
			continue;
		if (strcmp(ent->d_name, "lo") == 0)
			continue;
		if (read_net_type(ent->d_name) != 1)
			continue;

		nics[nic_count] = strdup(ent->d_name);
		if (!nics[nic_count])
			continue;
		nic_count++;
	}
	closedir(d);

	/* 2. Sort alphabetically (insertion sort) */
	for (int i = 1; i < nic_count; i++) {
		char *key = nics[i];
		int j = i - 1;
		while (j >= 0 && strcmp(nics[j], key) > 0) {
			nics[j + 1] = nics[j];
			j--;
		}
		nics[j + 1] = key;
	}

	/* 3. Detect first boot: no interface entries in DB yet */
	int first_boot = (sg_db_count("system_interface") == 0);

	/* 4. Create/protect entries for each discovered NIC */
	for (int i = 0; i < nic_count; i++) {
		char *existing = sg_db_get("system_interface", nics[i]);

		if (!existing) {
			/* New NIC — create entry with current MTU from driver */
			int cur_mtu = read_iface_mtu(nics[i]);
			if (cur_mtu <= 0)
				cur_mtu = 1500;

			char seed[256];
			if (first_boot && i == 0) {
				snprintf(seed, sizeof(seed),
					 "ip=" MGMT_DEFAULT_IP "\n"
					 "allowaccess=ping\n"
					 "status=up\n"
					 "mtu=%d\n"
					 "builtin=yes\n", cur_mtu);
				sg_db_set("system_interface", nics[i], seed);
				mgmt_log("INFO",
					 "interface %s: created (management IP " MGMT_DEFAULT_IP ", mtu %d)",
					 nics[i], cur_mtu);
			} else {
				snprintf(seed, sizeof(seed),
					 "allowaccess=ping\n"
					 "status=up\n"
					 "mtu=%d\n"
					 "builtin=yes\n", cur_mtu);
				sg_db_set("system_interface", nics[i], seed);
				mgmt_log("INFO", "interface %s: created (mtu %d)",
					 nics[i], cur_mtu);
			}
		} else {
			/* Existing NIC — ensure builtin=yes */
			sg_db_set_val("system_interface", nics[i],
				      "builtin", "yes");
			free(existing);
			mgmt_log("INFO", "interface %s: protected (builtin)",
				 nics[i]);
		}
	}

	/* 5. Stale interface cleanup: clear builtin from removed hardware */
	char *list = sg_db_list("system_interface");
	if (list) {
		const char *p = list;
		while (*p) {
			const char *eol = strchr(p, '\n');
			size_t len = eol ? (size_t)(eol - p) : strlen(p);
			if (len == 0) { p++; continue; }

			char name[256];
			if (len >= sizeof(name)) len = sizeof(name) - 1;
			memcpy(name, p, len);
			name[len] = '\0';

			/* Check if this DB entry has builtin=yes */
			char *bi = sg_db_get_val("system_interface", name,
						 "builtin");
			if (bi && strcmp(bi, "yes") == 0) {
				/* Check if still in discovered NIC list */
				int found = 0;
				for (int i = 0; i < nic_count; i++) {
					if (strcmp(nics[i], name) == 0) {
						found = 1;
						break;
					}
				}
				if (!found) {
					sg_db_set_val("system_interface", name,
						      "builtin", "no");
					mgmt_log("INFO",
						 "interface %s: hardware removed, builtin cleared",
						 name);
				}
			}
			free(bi);

			p += len;
			if (eol) p++;
		}
		free(list);
	}

	/* Cleanup */
	for (int i = 0; i < nic_count; i++)
		free(nics[i]);

	mgmt_log("INFO", "interface sync complete: %d NIC(s) discovered",
		 nic_count);
#undef MAX_NICS
}

/*
 * Build a formatted table of network interfaces with status, IP, and
 * description from the config database. Returns heap-allocated string.
 */
static char *mgmtd_show_interfaces(void)
{
#define MAX_SHOW_NICS 16
	char *nics[MAX_SHOW_NICS];
	int nic_count = 0;

	DIR *d = opendir("/sys/class/net");
	if (!d)
		return strdup("(cannot read interfaces)\n");

	struct dirent *ent;
	while ((ent = readdir(d)) != NULL && nic_count < MAX_SHOW_NICS) {
		if (ent->d_name[0] == '.')
			continue;
		if (strcmp(ent->d_name, "lo") == 0)
			continue;
		if (read_net_type(ent->d_name) != 1)
			continue;
		nics[nic_count] = strdup(ent->d_name);
		if (!nics[nic_count])
			continue;
		nic_count++;
	}
	closedir(d);

	/* Sort alphabetically (insertion sort) */
	for (int i = 1; i < nic_count; i++) {
		char *key = nics[i];
		int j = i - 1;
		while (j >= 0 && strcmp(nics[j], key) > 0) {
			nics[j + 1] = nics[j];
			j--;
		}
		nics[j + 1] = key;
	}

	size_t bufsz = 4096, used = 0;
	char *buf = malloc(bufsz);
	if (!buf) {
		for (int i = 0; i < nic_count; i++)
			free(nics[i]);
		return NULL;
	}

	/* Header */
	used += (size_t)snprintf(buf, bufsz,
		"%-16s %-8s %-21s %s\n", "Name", "Status", "IP", "Description");

	for (int i = 0; i < nic_count; i++) {
		/* Read operstate from sysfs */
		char state[16] = "unknown";
		char spath[64];
		snprintf(spath, sizeof(spath), "/sys/class/net/%.15s/operstate",
			 nics[i]);
		FILE *fp = fopen(spath, "r");
		if (fp) {
			if (fgets(state, sizeof(state), fp)) {
				char *nl = strchr(state, '\n');
				if (nl) *nl = '\0';
			}
			fclose(fp);
		}

		/* Get IP address via ip command */
		char ip[32] = "-";
		const char *argv[] = {
			"ip", "-4", "-o", "addr", "show", nics[i], NULL
		};
		char *ipout = safe_exec(argv);
		if (ipout && ipout[0]) {
			char *inet = strstr(ipout, "inet ");
			if (inet) {
				inet += 5;
				char *end = strchr(inet, ' ');
				if (end) *end = '\0';
				snprintf(ip, sizeof(ip), "%s", inet);
			}
		}
		free(ipout);

		/* Get description from config DB */
		char *desc = sg_db_get_val("system_interface", nics[i],
					   "description");

		/* Format row */
		char line[256];
		int n = snprintf(line, sizeof(line), "%-16s %-8s %-21s %s\n",
				 nics[i], state, ip, desc ? desc : "");

		/* Grow buffer if needed */
		while (used + (size_t)n + 1 > bufsz) {
			bufsz *= 2;
			char *nb = realloc(buf, bufsz);
			if (!nb) {
				free(buf);
				free(desc);
				for (int k = i; k < nic_count; k++)
					free(nics[k]);
				return NULL;
			}
			buf = nb;
		}
		memcpy(buf + used, line, (size_t)n);
		used += (size_t)n;

		free(desc);
		free(nics[i]);
	}

	buf[used] = '\0';
	return buf;
#undef MAX_SHOW_NICS
}

/*
 * Replay saved configuration at boot.
 * Iterates through config types that have runtime apply handlers
 * and calls apply_config() for each entry.
 */
static void mgmtd_replay_config(void)
{
	char result[512];

	/* Single config types (id="0") */
	static const char *single_types[] = {
		"system_settings",
		"network_dns",
		NULL
	};
	for (int i = 0; single_types[i]; i++) {
		char *data = sg_db_get(single_types[i], "0");
		if (data) {
			sg_status_t rc = apply_config(single_types[i], "0",
						      data, result,
						      sizeof(result));
			mgmt_log(rc == SG_OK ? "INFO" : "WARN",
				 "replay %s: %s", single_types[i], result);
			free(data);
		}
	}

	/* Table config types (multiple entries) */
	static const char *table_types[] = {
		"system_interface",
		"network_route_static",
		"network_nat",
		"network_dhcp-server",
		NULL
	};
	for (int i = 0; table_types[i]; i++) {
		/* Flush NAT chains before replaying to prevent rule accumulation */
		if (strcmp(table_types[i], "network_nat") == 0) {
			const char *f1[] = {"iptables", "-t", "nat",
					    "-F", "PREROUTING", NULL};
			free(safe_exec(f1));
			const char *f2[] = {"iptables", "-t", "nat",
					    "-F", "POSTROUTING", NULL};
			free(safe_exec(f2));
			mgmt_log("INFO", "flushed NAT chains before replay");
		}

		char *list = sg_db_list(table_types[i]);
		if (!list)
			continue;

		const char *p = list;
		while (*p) {
			const char *eol = strchr(p, '\n');
			size_t len = eol ? (size_t)(eol - p) : strlen(p);
			if (len == 0) { p++; continue; }

			char id[256];
			if (len >= sizeof(id)) len = sizeof(id) - 1;
			memcpy(id, p, len);
			id[len] = '\0';

			char *data = sg_db_get(table_types[i], id);
			if (data) {
				sg_status_t rc = apply_config(
					table_types[i], id, data,
					result, sizeof(result));
				mgmt_log(rc == SG_OK ? "INFO" : "WARN",
					 "replay %s:%s: %s",
					 table_types[i], id, result);
				free(data);
			}

			p += len;
			if (eol) p++;
		}
		free(list);
	}
}

/* ── Password / Shadow helpers ──────────────────────────────────────────── */

static int generate_salt(char *salt, size_t saltlen)
{
	static const char charset[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"0123456789./";

	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) return -1;

	unsigned char raw[16];
	ssize_t n = read(fd, raw, sizeof(raw));
	close(fd);
	if (n != (ssize_t)sizeof(raw)) return -1;

	size_t off = 0;
	salt[off++] = '$';
	salt[off++] = '6';
	salt[off++] = '$';
	for (size_t i = 0; i < sizeof(raw) && off < saltlen - 2; i++)
		salt[off++] = charset[raw[i] % (sizeof(charset) - 1)];
	salt[off++] = '$';
	salt[off] = '\0';
	return 0;
}

static int set_password(const char *username, const char *password)
{
#ifdef STARGAZER_TEST_MODE
	(void)username; (void)password;
	return 0;
#endif
	char salt[MAX_SALT_LEN];
	if (generate_salt(salt, sizeof(salt)) != 0)
		return -1;

	char *hash = crypt(password, salt);
	if (!hash) return -1;

	/* Acquire advisory lock for shadow file manipulation */
	int lockfd = open("/etc/shadow.lock", O_CREAT | O_RDWR, SHADOW_LOCK_MODE);
	if (lockfd < 0) return -1;
	if (flock(lockfd, LOCK_EX) != 0) {
		close(lockfd);
		return -1;
	}

	/* Update shadow atomically */
	FILE *fp = fopen("/etc/shadow", "r");
	if (!fp) { flock(lockfd, LOCK_UN); close(lockfd); return -1; }

	char tmppath[64];
	snprintf(tmppath, sizeof(tmppath), "/etc/shadow.XXXXXX");
	int tfd = mkstemp(tmppath);
	if (tfd < 0) { fclose(fp); flock(lockfd, LOCK_UN); close(lockfd); return -1; }
	fchmod(tfd, SHADOW_FILE_MODE);
	FILE *out = fdopen(tfd, "w");
	if (!out) { close(tfd); unlink(tmppath); fclose(fp); flock(lockfd, LOCK_UN); close(lockfd); return -1; }

	char line[MAX_LINE];
	size_t ulen = strlen(username);
	int found = 0;

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, username, ulen) == 0 && line[ulen] == ':') {
			char *rest = strchr(line + ulen + 1, ':');
			if (rest)
				fprintf(out, "%s:%s%s", username, hash, rest);
			else
				fprintf(out, "%s:%s:" SHADOW_LAST_CHANGED ":0:" SHADOW_MAX_DAYS ":" SHADOW_WARN_DAYS ":::\n", username, hash);
			found = 1;
		} else {
			fputs(line, out);
		}
	}
	fclose(fp);
	fclose(out);

	if (!found) {
		unlink(tmppath);
		flock(lockfd, LOCK_UN);
		close(lockfd);
		return -1;
	}

	if (rename(tmppath, "/etc/shadow") != 0) {
		unlink(tmppath);
		flock(lockfd, LOCK_UN);
		close(lockfd);
		return -1;
	}
	flock(lockfd, LOCK_UN);
	close(lockfd);
	return 0;
}

/*
 * Lock a user's password by replacing the hash with '!' in /etc/shadow.
 * This prevents login with any password.
 */
static int lock_password(const char *username)
{
#ifdef STARGAZER_TEST_MODE
	(void)username;
	return 0;
#endif
	/* Acquire advisory lock for shadow file manipulation */
	int lockfd = open("/etc/shadow.lock", O_CREAT | O_RDWR, SHADOW_LOCK_MODE);
	if (lockfd < 0) return -1;
	if (flock(lockfd, LOCK_EX) != 0) {
		close(lockfd);
		return -1;
	}

	FILE *fp = fopen("/etc/shadow", "r");
	if (!fp) { flock(lockfd, LOCK_UN); close(lockfd); return -1; }

	char tmppath[64];
	snprintf(tmppath, sizeof(tmppath), "/etc/shadow.XXXXXX");
	int tfd = mkstemp(tmppath);
	if (tfd < 0) { fclose(fp); flock(lockfd, LOCK_UN); close(lockfd); return -1; }
	fchmod(tfd, SHADOW_FILE_MODE);
	FILE *out = fdopen(tfd, "w");
	if (!out) { close(tfd); unlink(tmppath); fclose(fp); flock(lockfd, LOCK_UN); close(lockfd); return -1; }

	char line[MAX_LINE];
	size_t ulen = strlen(username);
	int found = 0;

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, username, ulen) == 0 && line[ulen] == ':') {
			char *rest = strchr(line + ulen + 1, ':');
			if (rest)
				fprintf(out, "%s:!%s", username, rest);
			else
				fprintf(out, "%s:!:" SHADOW_LAST_CHANGED ":0:" SHADOW_MAX_DAYS ":" SHADOW_WARN_DAYS ":::\n", username);
			found = 1;
		} else {
			fputs(line, out);
		}
	}
	fclose(fp);
	fclose(out);

	if (!found) {
		unlink(tmppath);
		flock(lockfd, LOCK_UN);
		close(lockfd);
		return -1;
	}

	if (rename(tmppath, "/etc/shadow") != 0) {
		unlink(tmppath);
		flock(lockfd, LOCK_UN);
		close(lockfd);
		return -1;
	}
	flock(lockfd, LOCK_UN);
	close(lockfd);
	return 0;
}

/*
 * Check whether a user has a valid password hash in /etc/shadow.
 * Returns 1 if user has a usable password, 0 if locked/empty/missing.
 */
static int user_has_password(const char *username)
{
#ifdef STARGAZER_TEST_MODE
	(void)username;
	return 1;
#endif
	FILE *fp = fopen("/etc/shadow", "r");
	if (!fp) return 0;

	char line[MAX_LINE];
	size_t ulen = strlen(username);

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, username, ulen) == 0 && line[ulen] == ':') {
			fclose(fp);
			char c = line[ulen + 1];
			/* Locked (!), disabled (*), or empty field = no password */
			if (c == '!' || c == '*' || c == ':' || c == '\n' || c == '\0')
				return 0;
			return 1;
		}
	}
	fclose(fp);
	return 0; /* user not found in shadow */
}

/* ── User management ────────────────────────────────────────────────────── */

/*
 * Add a user to an existing group in /etc/group.
 * Group line format: groupname:x:GID:user1,user2,...
 */
static void add_user_to_group(const char *username, const char *groupname)
{
#ifdef STARGAZER_TEST_MODE
	(void)username; (void)groupname;
	return;
#endif
	FILE *fp = fopen("/etc/group", "r");
	if (!fp) return;

	char tmppath[64];
	snprintf(tmppath, sizeof(tmppath), "/etc/group.XXXXXX");
	int tfd = mkstemp(tmppath);
	if (tfd < 0) { fclose(fp); return; }
	fchmod(tfd, 0644);
	FILE *out = fdopen(tfd, "w");
	if (!out) { close(tfd); unlink(tmppath); fclose(fp); return; }

	char line[MAX_LINE];
	size_t glen = strlen(groupname);

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, groupname, glen) == 0 && line[glen] == ':') {
			/* Found the group line — check if user already in it */
			size_t len = strlen(line);
			if (len > 0 && line[len - 1] == '\n')
				line[--len] = '\0';

			/* Check if username already present */
			char *members = line;
			int field = 0;
			for (char *p = line; *p; p++) {
				if (*p == ':') {
					field++;
					if (field == 3) { members = p + 1; break; }
				}
			}
			/* Simple check: is username in the members list? */
			int found = 0;
			if (*members) {
				char *tok = members;
				while (tok) {
					char *comma = strchr(tok, ',');
					size_t tlen = comma ?
						(size_t)(comma - tok) : strlen(tok);
					if (tlen == strlen(username) &&
					    strncmp(tok, username, tlen) == 0) {
						found = 1;
						break;
					}
					tok = comma ? comma + 1 : NULL;
				}
			}
			if (found) {
				fprintf(out, "%s\n", line);
			} else if (*members) {
				fprintf(out, "%s,%s\n", line, username);
			} else {
				fprintf(out, "%s%s\n", line, username);
			}
		} else {
			fputs(line, out);
		}
	}

	fclose(fp);
	fclose(out);
	rename(tmppath, "/etc/group");
}

static int create_system_user(const char *username, const char *shell)
{
#ifdef STARGAZER_TEST_MODE
	(void)username; (void)shell;
	return 0;
#endif
	/* Check if already exists */
	char check[MAX_LINE];
	snprintf(check, sizeof(check), "%s:", username);
	FILE *fp = fopen("/etc/passwd", "r");
	if (fp) {
		char line[MAX_LINE];
		while (fgets(line, sizeof(line), fp)) {
			if (strncmp(line, check, strlen(check)) == 0) {
				fclose(fp);
				return 0; /* already exists */
			}
		}
		fclose(fp);
	}

	/* Find next available UID >= 1000 (track max to handle unsorted passwd) */
	int uid = 1000;
	fp = fopen("/etc/passwd", "r");
	if (fp) {
		char line[MAX_LINE];
		while (fgets(line, sizeof(line), fp)) {
			/* Parse UID field (3rd field) */
			int field = 0;
			const char *p = line;
			int cur_uid = -1;
			while (*p) {
				if (*p == ':') {
					field++;
					if (field == 2) {
						cur_uid = atoi(p + 1);
						break;
					}
				}
				p++;
			}
			if (cur_uid >= uid)
				uid = cur_uid + 1;
		}
		fclose(fp);
	}

	/* Append to /etc/passwd */
	fp = fopen("/etc/passwd", "a");
	if (!fp) return -1;
	fprintf(fp, "%s:x:%d:%d:Stargazer Admin:/home/%s:%s\n",
		username, uid, uid, username, shell);
	fclose(fp);

	/* Append to /etc/shadow */
	fp = fopen("/etc/shadow", "a");
	if (fp) {
		fprintf(fp, "%s::" SHADOW_LAST_CHANGED ":0:" SHADOW_MAX_DAYS ":" SHADOW_WARN_DAYS ":::\n", username);
		fclose(fp);
	}

	/* Append to /etc/group (user's own group) */
	fp = fopen("/etc/group", "a");
	if (fp) {
		fprintf(fp, "%s:x:%d:\n", username, uid);
		fclose(fp);
	}

	/* Add user to 'stargazer' group for socket + config access */
	add_user_to_group(username, "stargazer");

	/* Create home dir */
	char homedir[128];
	snprintf(homedir, sizeof(homedir), "/home/%s", username);
	mkdir(homedir, 0750);
	if (chown(homedir, uid, uid) != 0)
		mgmt_log("WARN", "chown %s: %s", homedir, strerror(errno));

	return 0;
}

static int delete_system_user(const char *username)
{
#ifdef STARGAZER_TEST_MODE
	(void)username;
	return 0;
#endif
	const char *files[] = { "/etc/passwd", "/etc/shadow", "/etc/group" };
	char prefix[128];
	snprintf(prefix, sizeof(prefix), "%s:", username);
	size_t plen = strlen(prefix);

	for (int i = 0; i < 3; i++) {
		FILE *in = fopen(files[i], "r");
		if (!in) continue;

		char tmppath[128];
		snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d", files[i], (int)getpid());
		FILE *out = fopen(tmppath, "w");
		if (!out) { fclose(in); continue; }

		if (i == 1) /* shadow */
			fchmod(fileno(out), SHADOW_FILE_MODE);

		char line[MAX_LINE];
		while (fgets(line, sizeof(line), in)) {
			if (strncmp(line, prefix, plen) != 0)
				fputs(line, out);
		}

		fclose(in);
		fclose(out);
		if (rename(tmppath, files[i]) != 0) {
			mgmt_log("WARN", "delete_system_user: rename %s: %s",
				 files[i], strerror(errno));
			unlink(tmppath);
		}
	}

	return 0;
}

/* ── Session revision tracking ──────────────────────────────────────────── */

static int session_rev_get(const char *user)
{
	FILE *fp = fopen(SESSION_REV_FILE, "r");
	if (!fp) return 0;

	char line[MAX_LINE];
	int rev = 0;
	size_t ulen = strlen(user);

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, user, ulen) == 0 && line[ulen] == ':') {
			rev = atoi(line + ulen + 1);
			break;
		}
	}
	fclose(fp);
	return rev;
}

static void session_rev_set(const char *user, int rev)
{
	char tmppath[128];
	snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d", SESSION_REV_FILE, (int)getpid());

	FILE *out = fopen(tmppath, "w");
	if (!out) return;

	size_t ulen = strlen(user);

	FILE *in = fopen(SESSION_REV_FILE, "r");
	if (in) {
		char line[MAX_LINE];
		while (fgets(line, sizeof(line), in)) {
			if (strncmp(line, user, ulen) != 0 || line[ulen] != ':')
				fputs(line, out);
		}
		fclose(in);
	}
	fprintf(out, "%s:%d\n", user, rev);
	fchmod(fileno(out), 0644);
	fclose(out);

	if (rename(tmppath, SESSION_REV_FILE) != 0)
		unlink(tmppath);
}

static int session_rev_bump(const char *user)
{
	int rev = session_rev_get(user);
	session_rev_set(user, rev + 1);
	return rev + 1;
}

/* ── System command helpers ─────────────────────────────────────────────── */

/*
 * run_cmd: DEPRECATED — kept only for hardcoded status commands.
 * New code MUST use safe_exec() with argument arrays.
 */
static char *run_cmd(const char *cmd)
{
	FILE *fp = popen(cmd, "r");
	if (!fp) return NULL;

	size_t bufsize = 4096, used = 0;
	char *buf = malloc(bufsize);
	if (!buf) { pclose(fp); return NULL; }

	char line[1024];
	while (fgets(line, sizeof(line), fp)) {
		size_t llen = strlen(line);
		while (used + llen + 1 > bufsize) {
			bufsize *= 2;
			char *nb = realloc(buf, bufsize);
			if (!nb) { free(buf); pclose(fp); return NULL; }
			buf = nb;
		}
		memcpy(buf + used, line, llen);
		used += llen;
	}
	buf[used] = '\0';
	pclose(fp);
	return buf;
}

/* ── Apply config to running system ─────────────────────────────────────── */

/*
 * Helper: extract value for a key from key=value data block.
 * Copies result into caller-provided buffer 'out' of size 'outsz'.
 * Sets out[0]='\0' if key not found.  Always NUL-terminates.
 */
void extract_val(const char *data, const char *key,
		 char *out, size_t outsz)
{
	out[0] = '\0';
	if (!data || !key || outsz == 0) return;

	size_t klen = strlen(key);
	const char *p = data;
	while (*p) {
		if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
			const char *v = p + klen + 1;
			const char *eol = strchr(v, '\n');
			size_t vlen = eol ? (size_t)(eol - v) : strlen(v);
			if (vlen >= outsz) {
				mgmt_log("WARN", "extract_val: value for '%s' truncated (%zu -> %zu)",
					 key, vlen, outsz - 1);
				vlen = outsz - 1;
			}
			memcpy(out, v, vlen);
			out[vlen] = '\0';
			return;
		}
		const char *nl = strchr(p, '\n');
		if (!nl) break;
		p = nl + 1;
	}
}

/* ── Password policy helpers ─────────────────────────────────────────────── */

/*
 * Read global password policy from database (system_password-policy).
 */
static void mgmtd_read_password_policy(struct password_policy *pol)
{
	pol->min_length = 0;
	pol->min_uppercase = 0;
	pol->min_lowercase = 0;
	pol->min_digit = 0;
	pol->min_special = 0;

	char *v;
	v = sg_db_get_val("system_password-policy", "0", "min-length");
	if (v) { int n = atoi(v); pol->min_length = (n > 0 && n <= 256) ? n : 0; free(v); }
	v = sg_db_get_val("system_password-policy", "0", "min-uppercase");
	if (v) { int n = atoi(v); pol->min_uppercase = (n > 0 && n <= 128) ? n : 0; free(v); }
	v = sg_db_get_val("system_password-policy", "0", "min-lowercase");
	if (v) { int n = atoi(v); pol->min_lowercase = (n > 0 && n <= 128) ? n : 0; free(v); }
	v = sg_db_get_val("system_password-policy", "0", "min-digit");
	if (v) { int n = atoi(v); pol->min_digit = (n > 0 && n <= 128) ? n : 0; free(v); }
	v = sg_db_get_val("system_password-policy", "0", "min-special");
	if (v) { int n = atoi(v); pol->min_special = (n > 0 && n <= 128) ? n : 0; free(v); }
}

/*
 * Check if user has enforce-password-policy=enable in their admin config.
 * Returns 1 if enforced, 0 if not.
 */
static int mgmtd_is_policy_enforced(const char *username)
{
	char *val = sg_db_get_val("system_admin", username,
				  "enforce-password-policy");
	if (!val) return 0;
	int enforced = (strcmp(val, "enable") == 0) ? 1 : 0;
	free(val);
	return enforced;
}

/*
 * Validate password against policy.
 * Returns 0 if ok (policy not enforced or satisfied), >0 on violation.
 * Sets *reason to human-readable string on failure.
 *
 * enforce_override: if non-empty, overrides the per-user enforce flag
 *   (used by CFG_APPLY where the value may not be saved yet).
 */
static int mgmtd_validate_password(const char *username, const char *password,
				    const char *enforce_override,
				    const char **reason)
{
	int enforced;

	if (enforce_override && enforce_override[0])
		enforced = (strcmp(enforce_override, "enable") == 0);
	else
		enforced = mgmtd_is_policy_enforced(username);

	if (!enforced) return 0;

	struct password_policy pol;
	mgmtd_read_password_policy(&pol);

	/* Apply MIN_PASS_LEN floor (same as logind) */
	if (pol.min_length <= 0) pol.min_length = PW_MIN_PASS_LEN;

	int rc = pw_check_policy(password, username, &pol);
	if (rc == 1) return 0; /* satisfied */
	if (reason) *reason = pw_policy_reason(rc);
	return rc;
}

/* ── Apply config to running system ─────────────────────────────────────── */

static sg_status_t apply_config(const char *type, const char *id,
				const char *data, char *result, size_t rsize)
{
	result[0] = '\0';

	/* ── Dispatched handlers (each in its own .c file) ───────────── */
	if (strcmp(type, "network_route_static") == 0)
		return apply_route_static(id, data, result, rsize);

	if (strcmp(type, "system_settings") == 0)
		return apply_settings(id, data, result, rsize);

	if (strcmp(type, "system_interface") == 0)
		return apply_interface(id, data, result, rsize);

	if (strcmp(type, "network_nat") == 0)
		return apply_nat(id, data, result, rsize);

	if (strcmp(type, "network_dns") == 0)
		return apply_dns(id, data, result, rsize);

	if (strcmp(type, "network_dhcp-server") == 0)
		return apply_dhcp(id, data, result, rsize);

	/* ── Inline handlers (tightly coupled to monolith statics) ───── */
	if (strcmp(type, "system_admin-profile") == 0) {
		char perms[VALBUFSZ];
		extract_val(data, "permissions", perms, sizeof(perms));
		if (perms[0] == '\0') {
			snprintf(result, rsize, "'permissions' not set.");
			return SG_ERR_MISSING_ARG;
		}
		if (audit_log("mgmtd", "admin_profile_apply", perms) != 0)
			snprintf(result, rsize, "Profile '%s' loaded (perms: %s)." AUDIT_WARN, id, perms);
		else
			snprintf(result, rsize, "Profile '%s' loaded (perms: %s).", id, perms);
		session_rev_bump(id);
		return SG_OK;
	}

	if (strcmp(type, "system_admin") == 0) {
		char profile[VALBUFSZ], password[VALBUFSZ], enforce[VALBUFSZ];
		char enforce_policy[VALBUFSZ];
		extract_val(data, "profile", profile, sizeof(profile));
		extract_val(data, "password", password, sizeof(password));
		extract_val(data, "enforce-change-password", enforce, sizeof(enforce));
		extract_val(data, "enforce-password-policy", enforce_policy,
			    sizeof(enforce_policy));

		if (profile[0] == '\0') {
			snprintf(result, rsize, "'profile' not set.");
			return SG_ERR_MISSING_ARG;
		}

		/* Check profile exists */
		char *prof_check = sg_db_get("system_admin-profile", profile);
		if (!prof_check) {
			snprintf(result, rsize, "Profile '%s' does not exist.", profile);
			return SG_ERR_PROFILE_NOT_FOUND;
		}
		free(prof_check);

		/* Create Linux user if needed */
		if (create_system_user(id, "/sbin/stargazer-cli") != 0) {
			snprintf(result, rsize, "Failed to create user '%s'.", id);
			return SG_ERR_SYSTEM_FAIL;
		}

		/* Handle password */
		if (password[0]) {
			/* Validate against password policy */
			const char *pw_reason = NULL;
			int pw_rc = mgmtd_validate_password(id, password,
							    enforce_policy,
							    &pw_reason);
			if (pw_rc > 0) {
				explicit_bzero(password, sizeof(password));
				snprintf(result, rsize, "Password policy: %s",
					 pw_reason ? pw_reason : "violation");
				return SG_ERR_POLICY_FAIL;
			}
			if (set_password(id, password) != 0) {
				explicit_bzero(password, sizeof(password));
				snprintf(result, rsize, "Failed to set password for '%s'.", id);
				return SG_ERR_SYSTEM_FAIL;
			}
			explicit_bzero(password, sizeof(password));
			(void)audit_log(id, "admin_password_set", "source=mgmtd");
		}

		/* Ensure admin has a usable password (new or existing) */
		if (!user_has_password(id)) {
			snprintf(result, rsize,
				 "Admin '%s' has no password. Use 'set password'.", id);
			return SG_ERR_MISSING_ARG;
		}

		/* Handle enforce-change-password default for new users */
		if (enforce[0] == '\0') {
			/* Check if user already has a config entry */
			char *existing = sg_db_get("system_admin", id);
			if (!existing)
				snprintf(enforce, sizeof(enforce), "enable");
			else {
				free(existing);
				snprintf(enforce, sizeof(enforce), "disable");
			}
		}

		if (audit_log(id, "admin_apply", profile) != 0)
			snprintf(result, rsize, "Admin '%s' applied (profile: %s)." AUDIT_WARN, id, profile);
		else
			snprintf(result, rsize, "Admin '%s' applied (profile: %s).", id, profile);
		session_rev_bump(id);
		return SG_OK;
	}

	/* Default: no apply handler */
	snprintf(result, rsize, "Config saved (no runtime handler for %s).", type);
	return SG_OK;
}

/* ── Permission checking ────────────────────────────────────────────────── */

/*
 * Get user's permissions string from system.conf.
 * Returns statically allocated string.
 */
static const char *get_user_permissions(const char *username)
{
	static char perms[256];
	perms[0] = '\0';

	/* Get user's profile */
	char *user_data = sg_db_get("system_admin", username);
	if (!user_data) return "monitor";

	char prof_name[VALBUFSZ];
	extract_val(user_data, "profile", prof_name, sizeof(prof_name));
	if (prof_name[0] == '\0') {
		free(user_data);
		return "monitor";
	}
	free(user_data);

	/* Get profile's permissions */
	char *prof_data = sg_db_get("system_admin-profile", prof_name);
	if (!prof_data) return "monitor";

	extract_val(prof_data, "permissions", perms, sizeof(perms));
	free(prof_data);

	return perms[0] ? perms : "monitor";
}

static int has_permission(const char *perms_csv, const char *perm)
{
	if (!perms_csv || !perm) return 0;

	size_t plen = strlen(perm);
	const char *p = perms_csv;

	while (*p) {
		/* Skip commas */
		while (*p == ',') p++;
		if (!*p) break;

		const char *end = strchr(p, ',');
		size_t slen = end ? (size_t)(end - p) : strlen(p);

		if (slen == plen && strncmp(p, perm, plen) == 0)
			return 1;

		p = end ? end + 1 : p + slen;
	}
	return 0;
}

/*
 * Check if user has the per-type permission for a config type.
 * Returns 1 if allowed, 0 if denied.
 * "admin" perm types require "admin".
 * "configure" perm types require "configure" OR "admin".
 */
static int check_type_permission(const char *user, const char *type_name)
{
	const char *required = sg_reg_type_perm(type_name);
	if (!required)
		return 0; /* unknown type → deny */
	const char *perms = get_user_permissions(user);
	if (strcmp(required, "admin") == 0)
		return has_permission(perms, "admin");
	/* "configure" types: configure OR admin */
	return has_permission(perms, "configure") || has_permission(perms, "admin");
}

/* ── Referential integrity check ────────────────────────────────────────── */

/*
 * Check if any config entries reference this object by its ID.
 * Returns 0 if safe to delete, -1 if referenced (errbuf filled).
 */
static int check_references(const char *type, const char *id,
			    char *errbuf, size_t errsz)
{
	sg_ref_entry_t refs[16];
	int nrefs = sg_reg_find_referencing(type, refs, 16);

	for (int i = 0; i < nrefs; i++) {
		char *found = sg_db_find_referencing(refs[i].type,
						     refs[i].key, id);
		if (found) {
			/* Extract first referencing entry for the message */
			const char *nl = strchr(found, '\n');
			size_t flen = nl ? (size_t)(nl - found) : strlen(found);
			char first[128];
			if (flen >= sizeof(first)) flen = sizeof(first) - 1;
			memcpy(first, found, flen);
			first[flen] = '\0';

			snprintf(errbuf, errsz,
				 "Referenced by %s (%s)", first, refs[i].key);
			free(found);
			return -1;
		}
	}
	return 0;
}

/* ── Firmware upgrade state file ─────────────────────────────────────────── */

#define FW_STATE_FILE     "/tmp/sg-fw-upgrade.state"
#define FW_STATE_FILE_TMP "/tmp/sg-fw-upgrade.state.tmp"

/*
 * Write firmware upgrade progress to state file atomically.
 * The child process calls this at each step so the parent (serving
 * FW_PROGRESS polls) always reads a complete, consistent file.
 */
static void fw_write_state(int step, int total, const char *status,
			   const char *message, const char *version)
{
	FILE *fp = fopen(FW_STATE_FILE_TMP, "w");
	if (!fp)
		return;
	fprintf(fp, "step=%d\ntotal=%d\nstatus=%s\nmessage=%s\nversion=%s\n",
		step, total, status, message, version ? version : "");
	fclose(fp);
	rename(FW_STATE_FILE_TMP, FW_STATE_FILE);
}

/* ── Server-side key=value validation for CFG_SET ──────────────────────── */

/*
 * Validate key=value data against the config type registry before writing
 * to the database.  Checks:
 *   1. Every key is known for the type (reject unknown keys)
 *   2. Every value passes sg_reg_validate_value()
 *   3. All required keys are present
 *
 * Returns SG_OK on success, or an error status with a human-readable
 * message written to errbuf.
 */
static sg_status_t validate_cfg_data(const char *type, const char *data,
				     char *errbuf, size_t errsz)
{
	errbuf[0] = '\0';

	/* --- check each key=value line -------------------------------- */
	const char *p = data;
	while (*p) {
		if (*p == '\n') { p++; continue; }

		const char *eol = strchr(p, '\n');
		size_t llen = eol ? (size_t)(eol - p) : strlen(p);

		const char *eq = memchr(p, '=', llen);
		if (eq) {
			size_t klen = (size_t)(eq - p);
			if (klen >= 64) {
				snprintf(errbuf, errsz,
					 "Key name too long");
				return SG_ERR_INVALID_ARG;
			}
			char key[64];
			memcpy(key, p, klen);
			key[klen] = '\0';

			const char *vstart = eq + 1;
			size_t vlen = llen - klen - 1;
			if (vlen > 511) {
				snprintf(errbuf, errsz,
					 "Value for '%s' too long", key);
				return SG_ERR_INVALID_VAL;
			}
			char val[512];
			memcpy(val, vstart, vlen);
			val[vlen] = '\0';

			/* Skip 'builtin' — internal marker managed by
			 * mgmtd, not a user-settable field.  Handled
			 * separately in the CFG_SET handler. */
			if (strcmp(key, "builtin") == 0) {
				p += llen;
				if (eol) p++;
				continue;
			}

			/* 1. reject unknown keys */
			if (!sg_reg_is_valid_key(type, key)) {
				snprintf(errbuf, errsz,
					 "Unknown key '%s'", key);
				return SG_ERR_INVALID_ARG;
			}

			/* 2. validate value format */
			if (!sg_reg_validate_value(type, key, val)) {
				const char *rule =
					sg_reg_value_rule(type, key);
				char t_rule[128];
				snprintf(t_rule, sizeof(t_rule), "%s",
					 rule ? rule : "bad value");
				snprintf(errbuf, errsz,
					 "Invalid value for '%s': %s",
					 key, t_rule);
				return SG_ERR_INVALID_VAL;
			}
		}

		p += llen;
		if (eol) p++;
	}

	/* --- check required keys are present -------------------------- */
	const char *req = sg_reg_required_keys(type);
	if (req && *req) {
		char reqbuf[512];
		snprintf(reqbuf, sizeof(reqbuf), "%s", req);
		char *tok = reqbuf;

		while (*tok) {
			while (*tok == ' ') tok++;
			if (!*tok) break;

			char *end = tok;
			while (*end && *end != ' ') end++;
			char saved = *end;
			*end = '\0';

			/* search data for "key=" */
			int found = 0;
			const char *s = data;
			size_t tlen = strlen(tok);
			while (*s) {
				if (*s == '\n') { s++; continue; }
				const char *el = strchr(s, '\n');
				size_t ll = el ? (size_t)(el - s) : strlen(s);
				if (ll > tlen &&
				    memcmp(s, tok, tlen) == 0 &&
				    s[tlen] == '=') {
					found = 1;
					break;
				}
				s += ll;
				if (el) s++;
			}

			if (!found) {
				snprintf(errbuf, errsz,
					 "Missing required field '%.60s'",
					 tok);
				*end = saved;
				return SG_ERR_MISSING_ARG;
			}

			*end = saved;
			tok = end;
		}
	}

	return SG_OK;
}

/* ── Request handler ────────────────────────────────────────────────────── */

static void handle_request(int client_fd, sg_request_hdr_t *hdr,
			   const char *payload)
{
	sg_cmd_t cmd = (sg_cmd_t)hdr->cmd;
	const char *user = hdr->username;

	/* Latch per-request debug flags from CLI header */
	g_debug_flags = hdr->debug_flags;

	mgmt_log("INFO", "cmd=%u user=%s payload_len=%u",
		 hdr->cmd, user, hdr->payload_len);

	if (g_debug_flags & SG_DBG_FLAG_MGMTD)
		debug_buf_push("[MGMTD-DBG] user=%s cmd=%u payload_len=%u\n",
			       user, hdr->cmd, hdr->payload_len);

	switch (cmd) {

	/* ── Config read ────────────────────────────────────────────────── */
	case SG_CMD_CFG_GET: {
		/* Payload format: "section\n" (section = "type:id" or "type") */
		if (!payload || hdr->payload_len == 0) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing section name");
			return;
		}
		char section[512] = {0};
		const char *nl = strchr(payload, '\n');
		if (nl) {
			size_t slen = (size_t)(nl - payload);
			if (slen >= sizeof(section)) slen = sizeof(section) - 1;
			memcpy(section, payload, slen);
		} else {
			snprintf(section, sizeof(section), "%s", payload);
		}

		/* Parse "type:id" → type + id (no colon → id="0") */
		char db_type[256], db_id[256];
		sg_db_parse_section(section, db_type, sizeof(db_type),
				    db_id, sizeof(db_id));

		if (!sg_is_safe_id(db_type)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid type name");
			return;
		}
		if (!check_type_permission(user, db_type)) {
			send_error(client_fd, SG_ERR_ENTRY_NOT_FOUND, section);
			return;
		}

		char *data = sg_db_get(db_type, db_id);
		if (data) {
			send_ok(client_fd, NULL, data);
			free(data);
		} else {
			send_error(client_fd, SG_ERR_ENTRY_NOT_FOUND, section);
		}
		return;
	}

	case SG_CMD_CFG_LIST: {
		/* Payload: "type\n" — list entry IDs for a config type */
		if (!payload || hdr->payload_len == 0) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing type prefix");
			return;
		}
		char prefix[256] = {0};
		snprintf(prefix, sizeof(prefix), "%s", payload);
		size_t plen = strlen(prefix);
		if (plen > 0 && prefix[plen-1] == '\n') prefix[--plen] = '\0';

		if (!sg_is_safe_id(prefix)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid type prefix");
			return;
		}
		if (!check_type_permission(user, prefix)) {
			send_ok(client_fd, "No entries", "");
			return;
		}

		char *list = sg_db_list(prefix);
		if (list) {
			send_ok(client_fd, NULL, list);
			free(list);
		} else {
			send_ok(client_fd, "No entries", "");
		}
		return;
	}

	/* ── Config write ───────────────────────────────────────────────── */
	case SG_CMD_CFG_SET: {
		/* Payload format: "section\nkey=value\nkey=value\n..." */
		if (!payload || hdr->payload_len == 0) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing section + data");
			return;
		}
		char section[256] = {0};
		const char *nl = strchr(payload, '\n');
		if (!nl) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Missing data after section");
			return;
		}
		size_t slen = (size_t)(nl - payload);
		if (slen >= sizeof(section)) slen = sizeof(section) - 1;
		memcpy(section, payload, slen);
		section[slen] = '\0';
		const char *data = nl + 1;
		if (*data == '\0') {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Missing data after section");
			return;
		}

		/* Parse "type:id" → type + id */
		char db_type[256], db_id[256];
		sg_db_parse_section(section, db_type, sizeof(db_type),
				    db_id, sizeof(db_id));

		if (sg_reg_type_mode(db_type) < 0) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Unknown config type");
			return;
		}
		if (!check_type_permission(user, db_type)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Unknown config type");
			return;
		}
		if (!sg_reg_validate_entry_id(db_type, db_id)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid entry ID");
			return;
		}

		/* Validate key names, values, and required fields */
		char val_err[SG_EXTRA_MAX];
		sg_status_t val_st = validate_cfg_data(db_type, data,
						       val_err, sizeof(val_err));
		if (val_st != SG_OK) {
			if (g_debug_flags & SG_DBG_FLAG_MGMTD)
				debug_buf_push("[MGMTD-DBG] cfg_set rejected: %s\n",
					       val_err);
			send_error(client_fd, val_st, val_err);
			return;
		}

		/* Preserve builtin status: clients cannot grant or
		 * revoke the builtin flag — it is set only by mgmtd
		 * seed logic.  Read the existing entry's builtin value
		 * and re-apply it after the write.  Any builtin= line
		 * in the incoming data is stripped by building a clean
		 * payload that omits it, then appending the original. */
		char *existing = sg_db_get(db_type, db_id);
		int was_builtin = 0;
		if (existing) {
			char bi[VALBUFSZ];
			extract_val(existing, "builtin", bi, sizeof(bi));
			if (strcmp(bi, "yes") == 0)
				was_builtin = 1;
			free(existing);
		}

		/* Build clean data: strip any client-sent builtin= */
		char clean[SG_PAYLOAD_MAX];
		size_t cpos = 0;
		const char *dp = data;
		while (*dp) {
			if (*dp == '\n') { dp++; continue; }
			const char *el = strchr(dp, '\n');
			size_t ll = el ? (size_t)(el - dp) : strlen(dp);
			if (ll >= 8 && memcmp(dp, "builtin=", 8) == 0) {
				dp += ll;
				if (el) dp++;
				continue;
			}
			if (cpos + ll + 1 < sizeof(clean)) {
				memcpy(clean + cpos, dp, ll);
				cpos += ll;
				clean[cpos++] = '\n';
			}
			dp += ll;
			if (el) dp++;
		}
		/* Re-append original builtin status */
		if (was_builtin) {
			const char *tag = "builtin=yes\n";
			size_t tlen = strlen(tag);
			if (cpos + tlen < sizeof(clean)) {
				memcpy(clean + cpos, tag, tlen);
				cpos += tlen;
			}
		}
		clean[cpos] = '\0';

		if (sg_db_set(db_type, db_id, clean) != 0) {
			mgmt_log("ERROR", "sg_db_set failed for %s", section);
			send_error(client_fd, SG_ERR_IO_FAIL, "Failed to write config");
			return;
		}

		/* Bump session for admin/profile/policy config changes */
		if (strcmp(db_type, "system_admin") == 0) {
			session_rev_bump(db_id);
		} else if (strcmp(db_type, "system_password-policy") == 0) {
			/* Policy change affects all admins — bump everyone */
			char *admins = sg_db_list("system_admin");
			if (admins) {
				const char *p = admins;
				while (*p) {
					const char *eol = strchr(p, '\n');
					size_t len = eol ? (size_t)(eol - p)
							 : strlen(p);
					if (len == 0) { p++; continue; }
					char aname[128];
					if (len >= sizeof(aname))
						len = sizeof(aname) - 1;
					memcpy(aname, p, len);
					aname[len] = '\0';
					session_rev_bump(aname);
					p += len;
					if (eol) p++;
				}
				free(admins);
			}
		} else if (strcmp(db_type, "system_admin-profile") == 0) {
			/* Bump all users that have this profile */
			char *admins = sg_db_list("system_admin");
			if (admins) {
				const char *p = admins;
				while (*p) {
					const char *eol = strchr(p, '\n');
					size_t len = eol ? (size_t)(eol - p)
							 : strlen(p);
					if (len == 0) { p++; continue; }
					char aname[128];
					if (len >= sizeof(aname))
						len = sizeof(aname) - 1;
					memcpy(aname, p, len);
					aname[len] = '\0';

					char *prof = sg_db_get_val(
						"system_admin", aname,
						"profile");
					if (prof) {
						if (strcmp(prof, db_id) == 0)
							session_rev_bump(aname);
						free(prof);
					}
					p += len;
					if (eol) p++;
				}
				free(admins);
			}
		}

		send_ok_audited(client_fd, "Config saved", NULL,
				user, "cfg_set", section);
		return;
	}

	case SG_CMD_CFG_DEL: {
		if (!payload || hdr->payload_len == 0) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing section");
			return;
		}
		char section[256] = {0};
		snprintf(section, sizeof(section), "%s", payload);
		size_t slen = strlen(section);
		if (slen > 0 && section[slen-1] == '\n') section[--slen] = '\0';

		if (!strchr(section, ':')) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Missing ':' separator (expected type:id)");
			return;
		}

		/* Parse "type:id" → type + id */
		char db_type[256], db_id[256];
		sg_db_parse_section(section, db_type, sizeof(db_type),
				    db_id, sizeof(db_id));

		if (sg_reg_type_mode(db_type) < 0) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Unknown config type");
			return;
		}
		if (!check_type_permission(user, db_type)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Unknown config type");
			return;
		}
		if (db_id[0] == '\0') {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Missing entry ID");
			return;
		}

		/* Check builtin flag */
		char *existing = sg_db_get(db_type, db_id);
		if (existing) {
			char bi[VALBUFSZ];
			extract_val(existing, "builtin", bi, sizeof(bi));
			if (strcmp(bi, "yes") == 0) {
				free(existing);
				send_error(client_fd, SG_ERR_BUILTIN, section);
				return;
			}
			free(existing);
		}

		/* Check referential integrity */
		char ref_err[SG_EXTRA_MAX];
		if (check_references(db_type, db_id, ref_err, sizeof(ref_err)) != 0) {
			send_error(client_fd, SG_ERR_IN_USE, ref_err);
			return;
		}

		/* If deleting admin, bump session and delete system user */
		if (strcmp(db_type, "system_admin") == 0) {
			session_rev_bump(db_id);
			delete_system_user(db_id);
		}

		if (sg_db_del(db_type, db_id) != 0) {
			send_error(client_fd, SG_ERR_IO_FAIL, "Failed to delete section");
			return;
		}
		send_ok_audited(client_fd, "Deleted", NULL,
				user, "cfg_del", section);
		return;
	}

	case SG_CMD_CFG_APPLY: {
		/* Payload: "type\nid\nkey=value\n..." */
		if (!payload || hdr->payload_len == 0) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing type+id+data");
			return;
		}
		char type_str[256] = {0}, id_str[256] = {0};
		const char *p = payload;
		const char *nl1 = strchr(p, '\n');
		if (!nl1) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Bad format");
			return;
		}
		size_t tlen = (size_t)(nl1 - p);
		if (tlen >= sizeof(type_str)) tlen = sizeof(type_str) - 1;
		memcpy(type_str, p, tlen);
		type_str[tlen] = '\0';

		p = nl1 + 1;
		const char *nl2 = strchr(p, '\n');
		if (!nl2) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Bad format");
			return;
		}
		size_t ilen = (size_t)(nl2 - p);
		if (ilen >= sizeof(id_str)) ilen = sizeof(id_str) - 1;
		memcpy(id_str, p, ilen);
		id_str[ilen] = '\0';

		if (!check_type_permission(user, type_str)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Unknown config type");
			return;
		}

		const char *data = nl2 + 1;
		char result[512];
		sg_status_t st = apply_config(type_str, id_str, data, result, sizeof(result));

		if (st == SG_OK) {
			char audit_msg[512];
			snprintf(audit_msg, sizeof(audit_msg), "%s:%s", type_str, id_str);
			send_ok_audited(client_fd, result, NULL,
					user, "cfg_apply", audit_msg);
		} else {
			send_error(client_fd, st, result);
		}
		return;
	}

	/* ── Admin management ───────────────────────────────────────────── */
	case SG_CMD_ADMIN_CREATE: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "admin")) {
			send_error(client_fd, SG_ERR_PERM_DENIED, "Requires 'admin' permission");
			return;
		}
		/* Payload: "username\nprofile\n" */
		if (!payload) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing username+profile");
			return;
		}
		char newuser[128] = {0}, newprof[128] = {0};
		const char *nl1 = strchr(payload, '\n');
		if (!nl1) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Bad format");
			return;
		}
		size_t ulen = (size_t)(nl1 - payload);
		if (ulen >= sizeof(newuser)) ulen = sizeof(newuser) - 1;
		memcpy(newuser, payload, ulen);

		const char *p2 = nl1 + 1;
		const char *nl2 = strchr(p2, '\n');
		size_t plen2 = nl2 ? (size_t)(nl2 - p2) : strlen(p2);
		if (plen2 >= sizeof(newprof)) plen2 = sizeof(newprof) - 1;
		memcpy(newprof, p2, plen2);

		if (!sg_is_safe_id(newuser)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid username");
			return;
		}
		if (!sg_is_safe_id(newprof)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid profile name");
			return;
		}

		/* Check profile exists */
		char *pdata = sg_db_get("system_admin-profile", newprof);
		if (!pdata) {
			send_error(client_fd, SG_ERR_PROFILE_NOT_FOUND, newprof);
			return;
		}
		free(pdata);

		/* Check user doesn't exist */
		char *udata = sg_db_get("system_admin", newuser);
		if (udata) {
			free(udata);
			send_error(client_fd, SG_ERR_ALREADY_EXISTS, newuser);
			return;
		}

		/* Create Linux user */
		if (create_system_user(newuser, "/sbin/stargazer-cli") != 0) {
			send_error(client_fd, SG_ERR_SYSTEM_FAIL, "create user failed");
			return;
		}

		/* Add to database */
		char cfgdata[256];
		snprintf(cfgdata, sizeof(cfgdata),
			 "profile=%s\nenforce-change-password=enable\n", newprof);
		if (sg_db_set("system_admin", newuser, cfgdata) != 0) {
			send_error(client_fd, SG_ERR_IO_FAIL, "config write failed");
			return;
		}

		if (g_debug_flags & SG_DBG_FLAG_AUTH)
			debug_buf_push("[AUTH-DBG] create user=%s result=ok\n",
				       newuser);
		char msg[CMD_BUF_SIZE];
		snprintf(msg, sizeof(msg), "User '%s' created with profile '%s'", newuser, newprof);
		send_ok_audited(client_fd, msg, NULL,
				user, "admin_create", newuser);
		return;
	}

	case SG_CMD_ADMIN_DELETE: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "admin")) {
			send_error(client_fd, SG_ERR_PERM_DENIED, "Requires 'admin' permission");
			return;
		}
		if (!payload) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing username");
			return;
		}
		char target[128] = {0};
		snprintf(target, sizeof(target), "%s", payload);
		size_t tlen = strlen(target);
		if (tlen > 0 && target[tlen-1] == '\n') target[--tlen] = '\0';

		if (!sg_is_safe_id(target)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid username");
			return;
		}

		/* Check builtin */
		char *existing = sg_db_get("system_admin", target);
		if (!existing) {
			send_error(client_fd, SG_ERR_USER_NOT_FOUND, target);
			return;
		}
		char bi[VALBUFSZ];
		extract_val(existing, "builtin", bi, sizeof(bi));
		if (strcmp(bi, "yes") == 0) {
			free(existing);
			send_error(client_fd, SG_ERR_BUILTIN, "Cannot delete built-in admin");
			return;
		}
		free(existing);

		/* Block self-deletion */
		if (strcmp(target, user) == 0) {
			send_error(client_fd, SG_ERR_IN_USE,
				   "Cannot delete your own account");
			return;
		}

		/* Check referential integrity */
		{
			char ref_err[SG_EXTRA_MAX];
			if (check_references("system_admin", target,
					     ref_err, sizeof(ref_err)) != 0) {
				send_error(client_fd, SG_ERR_IN_USE, ref_err);
				return;
			}
		}

		sg_db_del("system_admin", target);
		delete_system_user(target);
		session_rev_bump(target);

		if (g_debug_flags & SG_DBG_FLAG_AUTH)
			debug_buf_push("[AUTH-DBG] delete user=%s result=ok\n",
				       target);
		char msg[CMD_BUF_SIZE];
		snprintf(msg, sizeof(msg), "User '%s' deleted", target);
		send_ok_audited(client_fd, msg, NULL,
				user, "admin_delete", target);
		return;
	}

	case SG_CMD_ADMIN_SET_PW: {
		/* Payload: "username\npassword\n" */
		if (!payload) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing username+password");
			return;
		}
		char target[128] = {0}, pw[256] = {0};
		const char *nl1 = strchr(payload, '\n');
		if (!nl1) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Bad format");
			return;
		}
		size_t ulen = (size_t)(nl1 - payload);
		if (ulen >= sizeof(target)) ulen = sizeof(target) - 1;
		memcpy(target, payload, ulen);

		const char *p2 = nl1 + 1;
		size_t plen2 = strlen(p2);
		if (plen2 > 0 && p2[plen2-1] == '\n') plen2--;
		if (plen2 >= sizeof(pw)) plen2 = sizeof(pw) - 1;
		memcpy(pw, p2, plen2);

		if (!sg_is_safe_id(target)) {
			explicit_bzero(pw, sizeof(pw));
			send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid username");
			return;
		}

		/* Permission: admin can set anyone's password,
		 * regular user can only set their own */
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "admin") && strcmp(user, target) != 0) {
			send_error(client_fd, SG_ERR_PERM_DENIED,
				   "Can only change your own password");
			explicit_bzero(pw, sizeof(pw));
			return;
		}

		/* Validate against password policy */
		const char *pw_reason = NULL;
		int pw_rc = mgmtd_validate_password(target, pw, NULL, &pw_reason);
		if (pw_rc > 0) {
			explicit_bzero(pw, sizeof(pw));
			send_error(client_fd, SG_ERR_POLICY_FAIL,
				   pw_reason ? pw_reason : "Policy violation");
			return;
		}

		if (set_password(target, pw) != 0) {
			explicit_bzero(pw, sizeof(pw));
			mgmt_log("ERROR", "set_password failed for %s: %s",
				 target, strerror(errno));
			send_error(client_fd, SG_ERR_SYSTEM_FAIL, "Password update failed");
			return;
		}
		explicit_bzero(pw, sizeof(pw));
		if (g_debug_flags & SG_DBG_FLAG_AUTH)
			debug_buf_push("[AUTH-DBG] set_password user=%s result=ok\n",
				       target);
		send_ok_audited(client_fd, "Password updated", NULL,
				user, "admin_password_set", target);
		return;
	}

	case SG_CMD_ADMIN_SET_ENF: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "admin")) {
			send_error(client_fd, SG_ERR_PERM_DENIED, "Requires 'admin' permission");
			return;
		}
		/* Payload: "username\nenable|disable\n" */
		if (!payload) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing args");
			return;
		}
		char target[128] = {0}, val[32] = {0};
		const char *nl1 = strchr(payload, '\n');
		if (!nl1) { send_error(client_fd, SG_ERR_INVALID_ARG, "Bad format"); return; }
		size_t ulen = (size_t)(nl1 - payload);
		if (ulen >= sizeof(target)) ulen = sizeof(target) - 1;
		memcpy(target, payload, ulen);
		snprintf(val, sizeof(val), "%s", nl1 + 1);
		size_t vlen = strlen(val);
		if (vlen > 0 && val[vlen-1] == '\n') val[--vlen] = '\0';

		if (!sg_is_safe_id(target)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid username");
			return;
		}
		if (strcmp(val, "enable") != 0 && strcmp(val, "disable") != 0) {
			send_error(client_fd, SG_ERR_INVALID_VAL,
				   "Value must be 'enable' or 'disable'");
			return;
		}

		char *existing = sg_db_get("system_admin", target);
		if (!existing) {
			send_error(client_fd, SG_ERR_USER_NOT_FOUND, target);
			return;
		}

		/* Rebuild data with updated enforce flag */
		size_t elen = strlen(existing);
		char *newdata = malloc(elen + 64);
		if (!newdata) { free(existing); send_error(client_fd, SG_ERR_INTERNAL, NULL); return; }

		/* Copy lines except enforce-change-password */
		const char *p = existing;
		size_t ndoff = 0;
		while (*p) {
			const char *nl = strchr(p, '\n');
			size_t llen = nl ? (size_t)(nl - p + 1) : strlen(p);
			if (strncmp(p, "enforce-change-password=", 24) != 0) {
				memcpy(newdata + ndoff, p, llen);
				ndoff += llen;
			}
			p += llen;
		}
		ndoff += (size_t)snprintf(newdata + ndoff, 64,
					  "enforce-change-password=%s\n", val);
		newdata[ndoff] = '\0';

		sg_db_set("system_admin", target, newdata);
		free(existing);
		free(newdata);
		send_ok_audited(client_fd, "Enforce policy updated", NULL,
				user, "admin_set_enforce", target);
		return;
	}

	case SG_CMD_ADMIN_CHECK_PW: {
		/* Validate password against policy without setting it.
		 * Payload: "username\npassword[\nenforce_override]" */
		if (!payload) {
			send_error(client_fd, SG_ERR_MISSING_ARG,
				   "Missing username+password");
			return;
		}
		char chk_user[128] = {0}, chk_pw[256] = {0};
		char chk_enforce[32] = {0};
		const char *nl1 = strchr(payload, '\n');
		if (!nl1) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Bad format");
			return;
		}
		size_t ulen = (size_t)(nl1 - payload);
		if (ulen >= sizeof(chk_user)) ulen = sizeof(chk_user) - 1;
		memcpy(chk_user, payload, ulen);

		const char *p2 = nl1 + 1;
		const char *nl2 = strchr(p2, '\n');
		if (nl2) {
			size_t plen2 = (size_t)(nl2 - p2);
			if (plen2 >= sizeof(chk_pw)) plen2 = sizeof(chk_pw) - 1;
			memcpy(chk_pw, p2, plen2);
			/* Third line: enforce override */
			const char *p3 = nl2 + 1;
			size_t elen = strlen(p3);
			if (elen > 0 && p3[elen-1] == '\n') elen--;
			if (elen >= sizeof(chk_enforce)) elen = sizeof(chk_enforce) - 1;
			memcpy(chk_enforce, p3, elen);
		} else {
			size_t plen2 = strlen(p2);
			if (plen2 > 0 && p2[plen2-1] == '\n') plen2--;
			if (plen2 >= sizeof(chk_pw)) plen2 = sizeof(chk_pw) - 1;
			memcpy(chk_pw, p2, plen2);
		}

		if (!sg_is_safe_id(chk_user)) {
			explicit_bzero(chk_pw, sizeof(chk_pw));
			send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid username");
			return;
		}

		const char *reason = NULL;
		int rc = mgmtd_validate_password(chk_user, chk_pw,
						  chk_enforce[0] ? chk_enforce : NULL,
						  &reason);
		explicit_bzero(chk_pw, sizeof(chk_pw));

		if (rc > 0) {
			if (g_debug_flags & SG_DBG_FLAG_AUTH)
				debug_buf_push("[AUTH-DBG] check_password user=%s result=fail\n",
					       chk_user);
			send_error(client_fd, SG_ERR_POLICY_FAIL,
				   reason ? reason : "Policy violation");
		} else {
			if (g_debug_flags & SG_DBG_FLAG_AUTH)
				debug_buf_push("[AUTH-DBG] check_password user=%s result=ok\n",
					       chk_user);
			send_ok(client_fd, "Password meets policy", NULL);
		}
		return;
	}

	case SG_CMD_ADMIN_LOCK_PW: {
		/* Lock (invalidate) an admin's password.  Payload: "username\n" */
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "admin")) {
			send_error(client_fd, SG_ERR_PERM_DENIED, NULL);
			return;
		}
		if (!payload) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing username");
			return;
		}
		char lock_target[128] = {0};
		snprintf(lock_target, sizeof(lock_target), "%s", payload);
		size_t llen = strlen(lock_target);
		if (llen > 0 && lock_target[llen - 1] == '\n')
			lock_target[--llen] = '\0';

		if (!sg_is_safe_id(lock_target)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid username");
			return;
		}

		if (lock_password(lock_target) != 0) {
			send_error(client_fd, SG_ERR_SYSTEM_FAIL,
				   "Failed to lock password");
			return;
		}
		if (g_debug_flags & SG_DBG_FLAG_AUTH)
			debug_buf_push("[AUTH-DBG] lock_password user=%s result=ok\n",
				       lock_target);
		send_ok_audited(client_fd, "Password locked", NULL,
				user, "admin_password_locked", lock_target);
		return;
	}

	/* ── Session ────────────────────────────────────────────────────── */
	case SG_CMD_SESSION_REV: {
		if (!payload) { send_error(client_fd, SG_ERR_MISSING_ARG, NULL); return; }
		char target[128] = {0};
		snprintf(target, sizeof(target), "%s", payload);
		size_t tlen = strlen(target);
		if (tlen > 0 && target[tlen-1] == '\n') target[--tlen] = '\0';

		if (!sg_is_safe_id(target)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid username");
			return;
		}

		int rev = session_rev_get(target);
		char revstr[32];
		snprintf(revstr, sizeof(revstr), "%d", rev);
		send_ok(client_fd, NULL, revstr);
		return;
	}

	case SG_CMD_SESSION_BUMP: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "admin")) {
			send_error(client_fd, SG_ERR_PERM_DENIED, NULL);
			return;
		}
		if (!payload) { send_error(client_fd, SG_ERR_MISSING_ARG, NULL); return; }
		char target[128] = {0};
		snprintf(target, sizeof(target), "%s", payload);
		size_t tlen = strlen(target);
		if (tlen > 0 && target[tlen-1] == '\n') target[--tlen] = '\0';

		if (!sg_is_safe_id(target)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid username");
			return;
		}

		int rev = session_rev_bump(target);
		char revstr[32];
		snprintf(revstr, sizeof(revstr), "%d", rev);
		send_ok(client_fd, NULL, revstr);
		return;
	}

	/* ── System commands ────────────────────────────────────────────── */
	case SG_CMD_SYS_POWEROFF: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "admin")) {
			send_error(client_fd, SG_ERR_PERM_DENIED, "Requires 'admin' permission");
			return;
		}
		send_ok(client_fd, "Shutting down...", NULL);
		(void)audit_log(user, "system_poweroff", "");
		/* Close DB so /etc/stargazer can be cleanly unmounted */
		sg_db_close();
		/* Give time for response to be sent */
		usleep(100000);
		(void)run_cmd("/sbin/poweroff");
		return;
	}

	case SG_CMD_SYS_REBOOT: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "admin")) {
			send_error(client_fd, SG_ERR_PERM_DENIED, "Requires 'admin' permission");
			return;
		}
		send_ok(client_fd, "Rebooting...", NULL);
		(void)audit_log(user, "system_reboot", "");
		/* Close DB so /etc/stargazer can be cleanly unmounted */
		sg_db_close();
		usleep(100000);
		(void)run_cmd("/sbin/reboot");
		return;
	}

	case SG_CMD_FW_STATUS: {
		char result[2048];
		int off = 0;

		off += snprintf(result + off, sizeof(result) - off,
				"  === Firmware Status ===\n");

		/* Running version from build-time define or runtime file */
#ifdef VERSION
		off += snprintf(result + off, sizeof(result) - off,
				"  Running version: %s\n", VERSION);
#else
		{
			char verbuf[64] = {0};
			FILE *vf = fopen("/tmp/stargazer-fw-version", "r");
			if (vf) {
				if (fgets(verbuf, sizeof(verbuf), vf)) {
					char *nl = strchr(verbuf, '\n');
					if (nl) *nl = '\0';
				}
				fclose(vf);
			}
			off += snprintf(result + off, sizeof(result) - off,
					"  Running version: %s\n",
					verbuf[0] ? verbuf : "unknown");
		}
#endif

		/* Check for staged firmware */
		FILE *mf = fopen("/tmp/sg-fw-staged/manifest.txt", "r");
		if (mf) {
			char line[256];
			char staged_ver[256] = {0};
			while (fgets(line, sizeof(line), mf)) {
				if (strncmp(line, "version=", 8) == 0) {
					char *nl = strchr(line + 8, '\n');
					if (nl) *nl = '\0';
					snprintf(staged_ver, sizeof(staged_ver),
						 "%s", line + 8);
				}
			}
			fclose(mf);
			if (staged_ver[0])
				off += snprintf(result + off,
						sizeof(result) - off,
						"  Staged version: %s\n",
						staged_ver);
		}

		/* Boot partition device */
		const char *bdev_argv[] = {"findfs", "LABEL=boot", NULL};
		char *bdev = safe_exec(bdev_argv);
		if (!bdev || !bdev[0]) {
			free(bdev);
			const char *blkid_argv[] = {"blkid", "-L", "boot", NULL};
			bdev = safe_exec(blkid_argv);
		}
		if (bdev && bdev[0]) {
			char *nl = strchr(bdev, '\n');
			if (nl) *nl = '\0';
			off += snprintf(result + off, sizeof(result) - off,
					"  Boot partition: %s\n", bdev);
		} else {
			off += snprintf(result + off, sizeof(result) - off,
					"  Boot partition: not found\n");
		}
		free(bdev);

		(void)off;
		send_ok(client_fd, NULL, result);
		return;
	}

	case SG_CMD_FW_UPGRADE: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "admin")) {
			send_error(client_fd, SG_ERR_PERM_DENIED,
				   "Requires 'admin' permission");
			return;
		}
		if (!payload || hdr->payload_len == 0) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing URL");
			return;
		}

		/* Extract URL from payload */
		char url[1024];
		extract_val(payload, "url", url, sizeof(url));
		if (!url[0]) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing URL");
			return;
		}

		/* Validate URL scheme */
		if (strncmp(url, "http://", 7) != 0 &&
		    strncmp(url, "https://", 8) != 0 &&
		    strncmp(url, "tftp://", 7) != 0) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "URL must start with http://, https://, or tftp://");
			return;
		}

		/* Check if upgrade already running */
		{
			char state_check[256] = {0};
			FILE *sf = fopen(FW_STATE_FILE, "r");
			if (sf) {
				size_t rd = fread(state_check, 1, sizeof(state_check) - 1, sf);
				state_check[rd] = '\0';
				fclose(sf);
				if (strstr(state_check, "status=running")) {
					send_error(client_fd, SG_ERR_IN_USE,
						   "Firmware upgrade already in progress");
					return;
				}
			}
		}

		/* Write initial state and respond immediately */
		fw_write_state(0, 6, "running", "Starting firmware upgrade...", "");
		send_ok(client_fd, NULL, "Firmware upgrade started\n");

		/* Save username for child audit log */
		char fw_user[SG_USERNAME_MAX];
		snprintf(fw_user, sizeof(fw_user), "%s", user);

		/* Fork: parent returns to accept loop, child performs upgrade */
		pid_t pid = fork();
		if (pid < 0) {
			mgmt_log("ERROR", "firmware upgrade fork failed: %s",
				 strerror(errno));
			fw_write_state(0, 6, "error", "Internal error: fork failed", "");
			return;
		}

		if (pid > 0) {
			/* Parent — return to main accept loop */
			return;
		}

		/* ── Child process ─────────────────────────────────────── */

		/* Close fds we don't need */
		close(client_fd);
		if (g_listen_fd >= 0)
			close(g_listen_fd);

		/* Re-open database (parent keeps its connection) */
		sg_db_close();
		if (sg_db_open(SG_DB_PATH) != 0)
			mgmt_log("WARN", "firmware child: failed to reopen db");

		/* Prepare working directories */
		(void)run_cmd("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged /tmp/sg-fw-boot");
		(void)run_cmd("mkdir -p /tmp/sg-fw-download /tmp/sg-fw-staged /tmp/sg-fw-boot");

		/* Step 1: Download firmware package */
		fw_write_state(1, 6, "running", "Downloading firmware...", "");
		mgmt_log("INFO", "firmware upgrade: downloading from %s", url);
		char dlcmd[2048];
		if (strncmp(url, "tftp://", 7) == 0) {
			/* Parse tftp://host/path */
			const char *hp = url + 7;
			const char *slash = strchr(hp, '/');
			if (!slash || !slash[1]) {
				(void)run_cmd("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
				fw_write_state(1, 6, "error",
					       "TFTP URL must be tftp://host/path", "");
				sg_db_close();
				_exit(1);
			}
			char thost[256];
			size_t hlen = (size_t)(slash - hp);
			if (hlen >= sizeof(thost)) hlen = sizeof(thost) - 1;
			memcpy(thost, hp, hlen);
			thost[hlen] = '\0';
			const char *tremote = slash + 1;
			snprintf(dlcmd, sizeof(dlcmd),
				 "tftp -g -l /tmp/sg-fw-download/firmware.tar.gz "
				 "-r '%s' '%s' 2>&1", tremote, thost);
		} else {
			snprintf(dlcmd, sizeof(dlcmd),
				 "wget -q -O /tmp/sg-fw-download/firmware.tar.gz "
				 "'%s' 2>&1", url);
		}

		char *dlout = run_cmd(dlcmd);
		if (access("/tmp/sg-fw-download/firmware.tar.gz", F_OK) != 0) {
			mgmt_log("ERROR", "firmware download failed: %s",
				 dlout ? dlout : "(no output)");
			free(dlout);
			(void)run_cmd("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
			fw_write_state(1, 6, "error", "Download failed", "");
			sg_db_close();
			_exit(1);
		}
		free(dlout);

		/* Step 2: Extract firmware package */
		fw_write_state(2, 6, "running", "Extracting firmware package...", "");
		char *exout = run_cmd("tar -xzf /tmp/sg-fw-download/firmware.tar.gz "
				      "-C /tmp/sg-fw-staged/ 2>&1");
		if (access("/tmp/sg-fw-staged/manifest.txt", F_OK) != 0) {
			mgmt_log("ERROR", "firmware extract failed or missing manifest: %s",
				 exout ? exout : "(no output)");
			free(exout);
			(void)run_cmd("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
			fw_write_state(2, 6, "error",
				       "Invalid firmware package (missing manifest.txt)", "");
			sg_db_close();
			_exit(1);
		}
		free(exout);

		/* Read manifest */
		char manifest[2048] = {0};
		FILE *mf = fopen("/tmp/sg-fw-staged/manifest.txt", "r");
		if (mf) {
			size_t rd = fread(manifest, 1, sizeof(manifest) - 1, mf);
			manifest[rd] = '\0';
			fclose(mf);
		}

		char fw_version[64], kernel_sha[128], initramfs_sha[128];
		extract_val(manifest, "version", fw_version, sizeof(fw_version));
		extract_val(manifest, "kernel_sha256", kernel_sha, sizeof(kernel_sha));
		extract_val(manifest, "initramfs_sha256", initramfs_sha,
			    sizeof(initramfs_sha));

		if (!fw_version[0] || !kernel_sha[0] || !initramfs_sha[0]) {
			(void)run_cmd("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
			fw_write_state(2, 6, "error",
				       "Incomplete manifest (missing version or checksums)", "");
			sg_db_close();
			_exit(1);
		}

		/* Step 3: Verify checksums */
		fw_write_state(3, 6, "running", "Verifying checksums...", "");
		char *ksum = run_cmd("sha256sum /tmp/sg-fw-staged/kernel 2>/dev/null "
				     "| cut -d' ' -f1");
		char *isum = run_cmd("sha256sum /tmp/sg-fw-staged/initramfs.gz 2>/dev/null "
				     "| cut -d' ' -f1");

		/* Trim trailing newlines */
		if (ksum) { char *nl = strchr(ksum, '\n'); if (nl) *nl = '\0'; }
		if (isum) { char *nl = strchr(isum, '\n'); if (nl) *nl = '\0'; }

		if (!ksum || !isum ||
		    strcmp(ksum, kernel_sha) != 0 ||
		    strcmp(isum, initramfs_sha) != 0) {
			mgmt_log("ERROR", "firmware checksum mismatch: "
				 "kernel=%s (expect %s) initramfs=%s (expect %s)",
				 ksum ? ksum : "null", kernel_sha,
				 isum ? isum : "null", initramfs_sha);
			free(ksum);
			free(isum);
			(void)run_cmd("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
			fw_write_state(3, 6, "error",
				       "Firmware checksum verification failed", "");
			sg_db_close();
			_exit(1);
		}
		free(ksum);
		free(isum);

		mgmt_log("INFO", "firmware v%s verified, installing...", fw_version);

		/* Step 4: Find and mount boot partition */
		fw_write_state(4, 6, "running", "Mounting boot partition...", "");
		const char *bdev_argv[] = {"findfs", "LABEL=boot", NULL};
		char *bdev = safe_exec(bdev_argv);
		if (!bdev || !bdev[0]) {
			free(bdev);
			const char *blkid_argv[] = {"blkid", "-L", "boot", NULL};
			bdev = safe_exec(blkid_argv);
		}
		if (!bdev || !bdev[0]) {
			free(bdev);
			/* Scan common device paths */
			const char *candidates[] = {
				"/dev/mmcblk0p1", "/dev/mmcblk1p1",
				"/dev/vda1", "/dev/sda1", NULL
			};
			for (int i = 0; candidates[i]; i++) {
				if (access(candidates[i], F_OK) != 0)
					continue;
				char bcmd[256];
				snprintf(bcmd, sizeof(bcmd),
					 "blkid -s LABEL -o value '%s' 2>/dev/null",
					 candidates[i]);
				char *lbl = run_cmd(bcmd);
				if (lbl) {
					char *nl = strchr(lbl, '\n');
					if (nl) *nl = '\0';
					if (strcmp(lbl, "boot") == 0) {
						bdev = malloc(strlen(candidates[i]) + 1);
						if (bdev)
							strcpy(bdev, candidates[i]);
						free(lbl);
						break;
					}
					free(lbl);
				}
			}
		}

		if (!bdev || !bdev[0]) {
			free(bdev);
			(void)run_cmd("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
			fw_write_state(4, 6, "error",
				       "Boot partition (LABEL=boot) not found", "");
			sg_db_close();
			_exit(1);
		}

		/* Trim trailing newline from device path */
		{
			char *nl = strchr(bdev, '\n');
			if (nl) *nl = '\0';
		}

		/* Mount boot partition */
		char mntcmd[512];
		snprintf(mntcmd, sizeof(mntcmd),
			 "mount '%s' /tmp/sg-fw-boot 2>&1", bdev);
		char *mntout = run_cmd(mntcmd);
		if (access("/tmp/sg-fw-boot/kernel", F_OK) != 0 &&
		    access("/tmp/sg-fw-boot/initramfs.gz", F_OK) != 0) {
			/* Boot partition mounted but seems empty — still ok
			 * for first firmware install */
			mgmt_log("WARN", "boot partition %s appears empty", bdev);
		}
		free(mntout);

		/* Verify mount succeeded by checking mountpoint */
		char *mpcheck = run_cmd("mountpoint -q /tmp/sg-fw-boot && echo ok 2>/dev/null");
		if (!mpcheck || strncmp(mpcheck, "ok", 2) != 0) {
			mgmt_log("ERROR", "failed to mount boot partition %s", bdev);
			free(mpcheck);
			free(bdev);
			(void)run_cmd("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
			fw_write_state(4, 6, "error",
				       "Failed to mount boot partition", "");
			sg_db_close();
			_exit(1);
		}
		free(mpcheck);

		/* Log boot partition space before install */
		char *df_before = run_cmd("df -h /tmp/sg-fw-boot 2>/dev/null | tail -1");
		mgmt_log("INFO", "boot partition before install: %s",
			 df_before ? df_before : "(unknown)");
		free(df_before);

		/* Remove existing files to free space (64MB partition can't
		 * hold old + new simultaneously with a ~44MB kernel) */
		(void)run_cmd("rm -f /tmp/sg-fw-boot/kernel "
			      "/tmp/sg-fw-boot/initramfs.gz "
			      "/tmp/sg-fw-boot/kernel.bak "
			      "/tmp/sg-fw-boot/initramfs.gz.bak 2>/dev/null");

		/* Step 5: Install firmware files */
		fw_write_state(5, 6, "running",
			       "Installing kernel and initramfs...", "");

		int install_ok = 1;

		char *cpk = run_cmd("cp /tmp/sg-fw-staged/kernel /tmp/sg-fw-boot/kernel 2>&1");
		if (cpk && cpk[0])
			mgmt_log("WARN", "kernel copy: %s", cpk);
		free(cpk);

		char *vk = run_cmd("cmp -s /tmp/sg-fw-staged/kernel /tmp/sg-fw-boot/kernel "
				   "&& echo ok");
		if (!vk || strncmp(vk, "ok", 2) != 0) {
			mgmt_log("ERROR", "kernel verify failed");
			install_ok = 0;
		}
		free(vk);

		char *cpi = run_cmd("cp /tmp/sg-fw-staged/initramfs.gz /tmp/sg-fw-boot/initramfs.gz 2>&1");
		if (cpi && cpi[0])
			mgmt_log("WARN", "initramfs copy: %s", cpi);
		free(cpi);

		char *vi = run_cmd("cmp -s /tmp/sg-fw-staged/initramfs.gz /tmp/sg-fw-boot/initramfs.gz "
				   "&& echo ok");
		if (!vi || strncmp(vi, "ok", 2) != 0) {
			mgmt_log("ERROR", "initramfs verify failed");
			install_ok = 0;
		}
		free(vi);

		if (!install_ok) {
			char *df_fail = run_cmd("df -h /tmp/sg-fw-boot 2>/dev/null | tail -1");
			mgmt_log("ERROR", "firmware install failed, boot partition: %s",
				 df_fail ? df_fail : "(unknown)");
			free(df_fail);
			(void)run_cmd("sync");
			(void)run_cmd("umount /tmp/sg-fw-boot 2>/dev/null");
			free(bdev);
			(void)run_cmd("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
			fw_write_state(5, 6, "error", "Firmware install failed", "");
			sg_db_close();
			_exit(1);
		}

		/* Copy manifest to boot partition for version tracking */
		(void)run_cmd("cp /tmp/sg-fw-staged/manifest.txt /tmp/sg-fw-boot/manifest.txt 2>/dev/null");

		/* Step 6: Sync, unmount, and finalize */
		fw_write_state(6, 6, "running",
			       "Syncing and unmounting boot partition...", "");
		(void)run_cmd("sync");
		(void)run_cmd("umount /tmp/sg-fw-boot 2>/dev/null");
		free(bdev);

		/* Cleanup download artifacts */
		(void)run_cmd("rm -rf /tmp/sg-fw-download");

		/* Audit log */
		char audit_msg[1200];
		snprintf(audit_msg, sizeof(audit_msg),
			 "version=%s url=%s", fw_version, url);
		(void)audit_log(fw_user, "firmware_upgrade", audit_msg);

		mgmt_log("INFO", "firmware v%s installed successfully", fw_version);

		char done_msg[256];
		snprintf(done_msg, sizeof(done_msg),
			 "Firmware v%s installed successfully. Rebooting...",
			 fw_version);
		fw_write_state(6, 6, "done", done_msg, fw_version);

		/* Close DB and reboot */
		sg_db_close();
		usleep(100000);
		(void)run_cmd("/sbin/reboot");
		_exit(0);
	}

	case SG_CMD_FW_PROGRESS: {
		/* Poll firmware upgrade progress from state file */
		char state[512] = {0};
		FILE *sf = fopen(FW_STATE_FILE, "r");
		if (!sf) {
			send_ok(client_fd, NULL,
				"step=0\ntotal=0\nstatus=idle\n"
				"message=No upgrade in progress\nversion=\n");
			return;
		}
		size_t rd = fread(state, 1, sizeof(state) - 1, sf);
		state[rd] = '\0';
		fclose(sf);

		/* If terminal state (done/error), clean up the file */
		if (strstr(state, "status=done") || strstr(state, "status=error"))
			unlink(FW_STATE_FILE);

		send_ok(client_fd, NULL, state);
		return;
	}

	case SG_CMD_SHOW_STATUS: {
		char *out = run_cmd(
			"echo '=== Stargazer Status ===';"
			"if lsmod 2>/dev/null | grep -q pkt_forward; then"
			"  echo 'Module pkt_forward: loaded';"
			"else"
			"  echo 'Module pkt_forward: not loaded';"
			"fi;"
			"echo \"Uptime: $(cut -d' ' -f1 /proc/uptime 2>/dev/null)s\"");
		send_ok(client_fd, NULL, out ? out : "");
		free(out);
		return;
	}

	case SG_CMD_SHOW_IFACES: {
		char *out = mgmtd_show_interfaces();
		send_ok(client_fd, NULL, out ? out : "");
		free(out);
		return;
	}

	case SG_CMD_SHOW_ROUTES: {
		char *out = run_cmd("ip route 2>/dev/null || route -n 2>/dev/null");
		send_ok(client_fd, NULL, out ? out : "");
		free(out);
		return;
	}

	case SG_CMD_SHOW_STATS: {
		char *out = run_cmd(
			"dmesg 2>/dev/null | grep -i 'pkt_forward\\|forwarded\\|dropped' | tail -20");
		send_ok(client_fd, NULL, out ? out : "");
		free(out);
		return;
	}

	case SG_CMD_WHOAMI: {
		/* Return caller's profile and permissions from database */
		char *udata = sg_db_get("system_admin", user);
		if (!udata) {
			send_ok(client_fd, NULL, "profile=read-only\npermissions=monitor\n");
			return;
		}
		char prof[128] = {0}, perm[256] = {0};
		extract_val(udata, "profile", prof, sizeof(prof));
		free(udata);

		if (prof[0]) {
			char *pdata = sg_db_get("system_admin-profile", prof);
			if (pdata) {
				extract_val(pdata, "permissions", perm, sizeof(perm));
				free(pdata);
			}
		}
		if (!prof[0]) snprintf(prof, sizeof(prof), "read-only");
		if (!perm[0]) snprintf(perm, sizeof(perm), "monitor");

		char result[512];
		snprintf(result, sizeof(result),
			 "profile=%s\npermissions=%s\n", prof, perm);
		send_ok(client_fd, NULL, result);
		return;
	}

	case SG_CMD_NET_PING: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "monitor")) {
			send_error(client_fd, SG_ERR_PERM_DENIED,
				   "Requires 'monitor' permission");
			return;
		}
		char target[256];
		extract_val(payload, "target", target, sizeof(target));
		if (!target[0]) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing target");
			return;
		}
		if (!sg_is_safe_id(target)) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Invalid target (use IPv4 address or hostname)");
			return;
		}
		const char *argv[] = {"ping", "-c", "4", "-W", "2", target, NULL};
		char *out = safe_exec(argv);
		if (out) {
			send_ok(client_fd, NULL, out);
			free(out);
		} else {
			send_error(client_fd, SG_ERR_SYSTEM_FAIL,
				   "Failed to execute ping");
		}
		return;
	}

	case SG_CMD_NET_TRACEROUTE: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "monitor")) {
			send_error(client_fd, SG_ERR_PERM_DENIED,
				   "Requires 'monitor' permission");
			return;
		}
		char target[256];
		extract_val(payload, "target", target, sizeof(target));
		if (!target[0]) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing target");
			return;
		}
		if (!sg_is_safe_id(target)) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Invalid target (use IPv4 address or hostname)");
			return;
		}
		const char *argv[] = {"traceroute", "-m", "20", "-w", "2", target, NULL};
		char *out = safe_exec(argv);
		if (out) {
			send_ok(client_fd, NULL, out);
			free(out);
		} else {
			send_error(client_fd, SG_ERR_SYSTEM_FAIL,
				   "Failed to execute traceroute");
		}
		return;
	}

	case SG_CMD_NET_NSLOOKUP: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "monitor")) {
			send_error(client_fd, SG_ERR_PERM_DENIED,
				   "Requires 'monitor' permission");
			return;
		}
		char target[256];
		extract_val(payload, "target", target, sizeof(target));
		if (!target[0]) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing target");
			return;
		}
		if (!sg_is_safe_id(target)) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Invalid target (use hostname or IP address)");
			return;
		}
		const char *argv[] = {"nslookup", target, NULL};
		char *out = safe_exec(argv);
		if (out) {
			send_ok(client_fd, NULL, out);
			free(out);
		} else {
			send_error(client_fd, SG_ERR_SYSTEM_FAIL,
				   "Failed to execute nslookup");
		}
		return;
	}

	case SG_CMD_NET_ARPING: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "monitor")) {
			send_error(client_fd, SG_ERR_PERM_DENIED,
				   "Requires 'monitor' permission");
			return;
		}
		char target[256], iface[64];
		extract_val(payload, "target", target, sizeof(target));
		extract_val(payload, "iface", iface, sizeof(iface));
		if (!target[0]) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing target");
			return;
		}
		if (!sg_is_safe_id(target)) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Invalid target (use IPv4 address or hostname)");
			return;
		}
		char *out;
		if (iface[0]) {
			if (!sg_is_safe_id(iface)) {
				send_error(client_fd, SG_ERR_INVALID_ARG,
					   "Invalid interface name");
				return;
			}
			const char *argv[] = {"arping", "-c", "4", "-w", "2",
					      "-I", iface, target, NULL};
			out = safe_exec(argv);
		} else {
			const char *argv[] = {"arping", "-c", "4", "-w", "2",
					      target, NULL};
			out = safe_exec(argv);
		}
		if (out) {
			send_ok(client_fd, NULL, out);
			free(out);
		} else {
			send_error(client_fd, SG_ERR_SYSTEM_FAIL,
				   "Failed to execute arping");
		}
		return;
	}

	case SG_CMD_PING:
		send_ok(client_fd, "pong", NULL);
		return;

	case SG_CMD_DEBUG_FETCH: {
		if (debug_buf_used > 0) {
			send_ok(client_fd, NULL, debug_buf);
			debug_buf_used = 0;
			debug_buf[0] = '\0';
		} else {
			send_ok(client_fd, NULL, NULL);
		}
		return;
	}

	default:
		send_error(client_fd, SG_ERR_INVALID_CMD, "Unknown command");
		return;
	}
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(void)
{
	/* Must run as root (skip in test mode) */
#ifndef STARGAZER_TEST_MODE
	if (getuid() != 0) {
		fprintf(stderr, "stargazer-mgmtd: must run as root\n");
		return 1;
	}
#endif

	/* Signal handlers */
	signal(SIGINT,  sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);  /* auto-reap forked children (fw upgrade) */

	/* Remove stale socket */
	unlink(SG_MGMTD_SOCK);

	/* Create socket */
	int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd < 0) {
		perror("socket");
		return 1;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SG_MGMTD_SOCK);

	if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(sfd);
		return 1;
	}

	/* VULN-01: Restrict socket to root:stargazer 0660 */
	chmod(SG_MGMTD_SOCK, 0660);
	{
		struct group *sg_grp = getgrnam("stargazer");
		if (sg_grp) {
			if (chown(SG_MGMTD_SOCK, 0, sg_grp->gr_gid) != 0)
				mgmt_log("WARN", "chown socket: %s", strerror(errno));
		}
	}

	if (listen(sfd, MAX_CLIENTS_QUEUE) < 0) {
		perror("listen");
		close(sfd);
		return 1;
	}

	mgmt_log("INFO", "stargazer-mgmtd started, listening on %s", SG_MGMTD_SOCK);

	/* Ensure config directory exists */
	mkdir(CONF_DIR, 0755);

	/* Open SQLite database */
	if (sg_db_open(SG_DB_PATH) != 0) {
		fprintf(stderr, "stargazer-mgmtd: failed to open database\n");
		close(sfd);
		return 1;
	}

	/* Seed defaults on first boot (no-op if already seeded) */
	mgmtd_seed_defaults();

	/* Discover NICs, create/protect interface entries */
	mgmtd_sync_interfaces();

	/* Apply saved configuration to running system */
	mgmtd_replay_config();

	/* Store listen fd for forked children to close */
	g_listen_fd = sfd;

	/* Main accept loop */
	while (g_running) {
		int cfd = accept(sfd, NULL, NULL);
		if (cfd < 0) {
			if (errno == EINTR) continue;
			mgmt_log("ERROR", "accept: %s", strerror(errno));
			continue;
		}

		/* Read request header */
		sg_request_hdr_t hdr;
		ssize_t n = safe_read(cfd, &hdr, sizeof(hdr));
		if (n < (ssize_t)sizeof(hdr)) {
			mgmt_log("WARN", "short read on header (%zd bytes)", n);
			close(cfd);
			continue;
		}

		/* Ensure username is NUL-terminated (untrusted network input) */
		hdr.username[SG_USERNAME_MAX - 1] = '\0';

		/* Validate header */
		if (hdr.magic != SG_MSG_MAGIC || hdr.version != SG_MSG_VERSION) {
			mgmt_log("WARN", "bad magic/version: %04x/%u",
				 hdr.magic, hdr.version);
			send_error(cfd, SG_ERR_INVALID_CMD, "Protocol error");
			close(cfd);
			continue;
		}

		if (hdr.payload_len > SG_PAYLOAD_MAX) {
			mgmt_log("WARN", "payload too large: %u", hdr.payload_len);
			send_error(cfd, SG_ERR_INVALID_ARG, "Payload too large");
			close(cfd);
			continue;
		}

		/* Read payload */
		char *payload = NULL;
		if (hdr.payload_len > 0) {
			payload = malloc(hdr.payload_len + 1);
			if (!payload) {
				send_error(cfd, SG_ERR_INTERNAL, "Out of memory");
				close(cfd);
				continue;
			}
			n = safe_read(cfd, payload, hdr.payload_len);
			if (n < (ssize_t)hdr.payload_len) {
				mgmt_log("WARN", "short payload read");
				free(payload);
				close(cfd);
				continue;
			}
			payload[hdr.payload_len] = '\0';
		}

		/*
		 * VULN-02: Verify real client identity via SO_PEERCRED.
		 * The client sends a username in hdr.username. We verify that
		 * the claimed username's UID matches the kernel-verified UID.
		 * If the claim is valid, trust it; otherwise fall back to
		 * getpwuid() for the canonical name.
		 */
#ifndef STARGAZER_TEST_MODE
		{
			struct ucred cred;
			socklen_t cred_len = sizeof(cred);
			if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED,
				       &cred, &cred_len) == 0) {
				/*
				 * Verify the client-claimed username matches
				 * the kernel-verified UID. If the claimed user
				 * exists and has the same UID, trust it.
				 * Otherwise fall back to getpwuid().
				 */
				int verified = 0;
				if (hdr.username[0] != '\0') {
					struct passwd *claimed =
						getpwnam(hdr.username);
					if (claimed &&
					    claimed->pw_uid == cred.uid) {
						verified = 1;
						/* username already correct */
					}
				}
				if (!verified) {
					struct passwd *pw = getpwuid(cred.uid);
					if (pw) {
						snprintf(hdr.username,
							 sizeof(hdr.username),
							 "%s", pw->pw_name);
					} else {
						snprintf(hdr.username,
							 sizeof(hdr.username),
							 "uid:%u", cred.uid);
					}
				}
			} else {
				mgmt_log("WARN", "SO_PEERCRED failed: %s",
					 strerror(errno));
				/* Reject if we can't verify identity */
				send_error(cfd, SG_ERR_AUTH_FAIL,
					   "Cannot verify client identity");
				free(payload);
				close(cfd);
				continue;
			}
		}
#endif

		/* Handle request (with verified username) */
		handle_request(cfd, &hdr, payload);

		free(payload);
		close(cfd);
	}

	close(sfd);
	unlink(SG_MGMTD_SOCK);
	sg_db_close();
	mgmt_log("INFO", "stargazer-mgmtd stopped");
	return 0;
}
