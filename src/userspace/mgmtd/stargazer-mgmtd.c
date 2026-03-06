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
#include <limits.h>
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
#include <poll.h>

#include "stargazer_ipc.h"
#include "password_policy.h"
#include "sg_db.h"
#include "sg_validate.h"
#include "mgmtd_apply.h"
#include "mgmtd_internal.h"

/* ── Constants ──────────────────────────────────────────────────────────── */

/* Constants shared with sub-modules are in mgmtd_internal.h.
 * Below are constants used only in this file. */
#ifndef CONF_DIR
#define CONF_DIR         "/etc/stargazer"
#endif
#define AUDIT_LOG        "/var/log/stargazer-audit.log"
#define AUDIT_LOG_FB     "/tmp/stargazer-audit.log"
#define MAX_SESSION_TAGS  16
#define MAX_CLIENTS_QUEUE 8
#define BUF_SIZE         (sizeof(sg_request_hdr_t) + SG_PAYLOAD_MAX)
#define DEBUG_STATE_FILE  "/tmp/stargazer-debug.conf"
#define MGMT_DEFAULT_IP   "192.168.99.99/24" /* first NIC on first boot */

/* Boot integrity states — returned by mgmtd_check_boot_integrity() */
typedef enum {
	BOOT_FIRST,       /* No flag, all tables empty → seed defaults */
	BOOT_NORMAL,      /* Flag present, all tables populated → skip seed */
	BOOT_CORRUPTED,   /* Flag present but critical tables missing rows */
	BOOT_COMPROMISED  /* No flag but critical tables have data (tampering) */
} boot_state_t;

#define DEBUG_BUF_SIZE 4096
static char debug_buf[DEBUG_BUF_SIZE];
static int  debug_buf_used;

/* Per-request debug flags (set from request header) */
uint8_t g_debug_flags;

void debug_buf_push(const char *fmt, ...)
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
int g_listen_fd = -1;  /* listen socket fd, for child to close after fork */

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

/*
 * ipt_exec — Run an iptables command and check for errors.
 *
 * For iptables write operations (-P, -A, -D, -F, -N), success produces
 * empty output.  Errors produce messages on stderr (captured by safe_exec).
 * Binary-not-found also produces empty output (child exits 127), which is
 * indistinguishable from success without an exit code — callers must use
 * ipt_available() first to guard against that case.
 *
 * Returns 0 on success (empty output), -1 on error (non-empty output).
 * On error, logs the command and iptables error message.
 */
int ipt_exec(const char *const argv[])
{
	char *out = safe_exec(argv);
	if (!out) {
		mgmt_log("ERROR", "ipt_exec: fork/malloc failed for '%s'",
			 argv[0]);
		return -1;
	}
	if (out[0] != '\0') {
		/* Build command string for logging */
		char cmd[256];
		int pos = 0;
		for (int i = 0; argv[i] && pos < (int)sizeof(cmd) - 1; i++) {
			if (i > 0 && pos < (int)sizeof(cmd) - 1)
				cmd[pos++] = ' ';
			int n = snprintf(cmd + pos, sizeof(cmd) - (size_t)pos,
					 "%s", argv[i]);
			pos += n;
		}
		cmd[pos] = '\0';

		/* Trim trailing newline from error output */
		size_t len = strlen(out);
		while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r'))
			out[--len] = '\0';

		mgmt_log("ERROR", "iptables failed: %s (cmd: %s)", out, cmd);
		free(out);
		return -1;
	}
	free(out);
	return 0;
}

/*
 * ipt_available — Check if the iptables binary is usable.
 * Returns 1 if iptables responds to --version, 0 otherwise.
 */
static int ipt_available(void)
{
	const char *argv[] = {"iptables", "--version", NULL};
	char *out = safe_exec(argv);
	if (!out || out[0] == '\0') {
		free(out);
		return 0;
	}
	free(out);
	return 1;
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

int audit_log(const char *user, const char *event, const char *msg)
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

void send_ok(int fd, const char *extra, const char *payload)
{
	uint32_t plen = payload ? (uint32_t)strlen(payload) : 0;
	send_response(fd, SG_OK, extra, payload, plen);
}

void send_error(int fd, sg_status_t status, const char *extra)
{
	send_response(fd, status, extra, NULL, 0);
}

/* send_stream_chunk: send one streaming chunk (extra starts with '+').
 * Returns 0 on success, -1 if the client disconnected. */
int send_stream_chunk(int fd, const char *data, size_t len)
{
	sg_response_hdr_t resp;
	memset(&resp, 0, sizeof(resp));
	resp.magic = SG_MSG_MAGIC;
	resp.version = SG_MSG_VERSION;
	resp.status = (uint32_t)SG_OK;
	snprintf(resp.extra, sizeof(resp.extra), "+");
	resp.payload_len = (uint32_t)len;

	if (safe_write(fd, &resp, sizeof(resp)) < 0)
		return -1;
	if (len > 0 && data && safe_write(fd, data, len) < 0)
		return -1;
	return 0;
}

/*
 * stream_exec — fork+exec argv, stream child stdout/stderr to client_fd.
 *
 * Uses poll() to monitor both the child pipe and the client socket.
 * If the client disconnects (Ctrl+C), the child is killed immediately
 * instead of waiting for the next line of output.
 *
 * Returns 1 (took ownership of client_fd — caller must not close it).
 */
int stream_exec(int client_fd, const char *const argv[])
{
	int pipefd[2];
	if (pipe(pipefd) < 0) {
		send_error(client_fd, SG_ERR_SYSTEM_FAIL,
			   "Failed to create pipe");
		return 0;
	}
	pid_t pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		send_error(client_fd, SG_ERR_SYSTEM_FAIL,
			   "Failed to fork");
		return 0;
	}
	if (pid == 0) {
		/* Child: redirect stdout+stderr to pipe, exec */
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);
		execvp(argv[0], (char *const *)argv);
		_exit(127);
	}
	close(pipefd[1]);

	/* Parent: poll pipe (child output) + client socket (disconnect) */
	struct pollfd pfds[2];
	pfds[0].fd = pipefd[0];
	pfds[0].events = POLLIN;
	pfds[1].fd = client_fd;
	pfds[1].events = POLLIN;

	int killed = 0;
	for (;;) {
		int ret = poll(pfds, 2, 30000);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			break; /* poll error */
		}
		if (ret == 0)
			break; /* 30s timeout — child stalled */

		/* Check client socket first: disconnect → kill child */
		if (pfds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
			kill(pid, SIGTERM);
			killed = 1;
			break;
		}

		/* Child has output ready */
		if (pfds[0].revents & POLLIN) {
			char buf[1024];
			ssize_t n = read(pipefd[0], buf, sizeof(buf));
			if (n <= 0)
				break; /* EOF or error */
			if (send_stream_chunk(client_fd, buf, (size_t)n) < 0) {
				kill(pid, SIGTERM);
				killed = 1;
				break;
			}
		}

		/* Child pipe closed (EOF) */
		if (pfds[0].revents & (POLLHUP | POLLERR)) {
			/* Drain any remaining data */
			for (;;) {
				char buf[1024];
				ssize_t n = read(pipefd[0], buf, sizeof(buf));
				if (n <= 0)
					break;
				if (send_stream_chunk(client_fd, buf, (size_t)n) < 0) {
					kill(pid, SIGTERM);
					killed = 1;
					break;
				}
			}
			break;
		}
	}

	close(pipefd[0]);
	if (killed)
		waitpid(pid, NULL, WNOHANG);
	else
		waitpid(pid, NULL, 0);
	if (!killed)
		send_ok(client_fd, NULL, NULL);
	close(client_fd);
	return 1;
}

/* send_ok with inline audit — appends warning to extra if audit fails */
void send_ok_audited(int fd, const char *extra, const char *payload,
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
				const char *data,
				char *result, size_t rsize);

/* ── FIFO signaling to init ─────────────────────────────────────────────── */

/*
 * Signal init via the readiness FIFO. Used for both "ready" and "error".
 */
static void mgmtd_signal_fifo(const char *msg)
{
	int rfd = open("/run/mgmtd-ready", O_WRONLY);
	if (rfd >= 0) {
		write(rfd, msg, strlen(msg));
		close(rfd);
	}
}

/* ── Boot integrity check ──────────────────────────────────────────────── */

/*
 * Critical tables that MUST all be populated after first-boot seeding.
 * If the seeded flag is set but any of these are empty, the database
 * is corrupted.  If the flag is absent but any have data, the flag
 * was removed (potential tampering).
 */
static const char *critical_tables[] = {
	"system_admin-profile",
	"system_admin",
	"system_password-policy",
};
#define N_CRITICAL (sizeof(critical_tables) / sizeof(critical_tables[0]))

static boot_state_t mgmtd_check_boot_integrity(void)
{
	/* Read the seeded flag from system_meta */
	int flag_set = 0;
	char *val = sg_db_get_val("system_meta", "0", "seeded");
	if (val) {
		flag_set = (strcmp(val, "1") == 0);
		free(val);
	}

	/* Count rows in each critical table */
	int counts[N_CRITICAL];
	int all_empty = 1;
	int all_populated = 1;

	for (size_t i = 0; i < N_CRITICAL; i++) {
		counts[i] = sg_db_count(critical_tables[i]);
		if (counts[i] > 0)
			all_empty = 0;
		else
			all_populated = 0;
	}

	if (!flag_set && all_empty) {
		mgmt_log("INFO", "first boot detected — no seeded flag, all tables empty");
		return BOOT_FIRST;
	}

	if (flag_set && all_populated) {
		return BOOT_NORMAL;
	}

	if (flag_set && !all_populated) {
		/* CORRUPTED: flag says seeded but some tables are empty */
		mgmt_log("ERROR", "boot integrity: CORRUPTED — "
			 "seeded flag present but critical tables missing data");
		for (size_t i = 0; i < N_CRITICAL; i++) {
			mgmt_log("ERROR", "  %-30s %s",
				 critical_tables[i],
				 counts[i] > 0 ? "OK" : "MISSING");
		}
		return BOOT_CORRUPTED;
	}

	/* !flag_set && !all_empty → COMPROMISED */
	mgmt_log("ERROR", "boot integrity: COMPROMISED — "
		 "seeded flag absent but critical tables contain data");
	for (size_t i = 0; i < N_CRITICAL; i++) {
		mgmt_log("ERROR", "  %-30s %s",
			 critical_tables[i],
			 counts[i] > 0 ? "PRESENT" : "empty");
	}
	return BOOT_COMPROMISED;
}

/* ── First-boot database seeding ────────────────────────────────────────── */

/*
 * Seed database with default configuration on first boot.
 * Called only when mgmtd_check_boot_integrity() returns BOOT_FIRST.
 * Sets the seeded flag LAST — if seeding partially fails, next boot
 * re-tries as FIRST BOOT.
 */
static int mgmtd_seed_defaults(void)
{
	mgmt_log("INFO", "first boot — seeding default configuration");

	/* ── Admin profiles ─────────────────────────────────────────── */
	if (sg_db_set("system_admin-profile", "read-write",
		      "permissions=monitor,configure,admin\n"
		      "description=Full administrative access\n"
		      "builtin=yes\n") != 0) goto fail;

	if (sg_db_set("system_admin-profile", "read-only",
		      "permissions=monitor\n"
		      "description=Read-only monitoring access\n"
		      "builtin=yes\n") != 0) goto fail;

	/* ── Default admin account ──────────────────────────────────── */
	if (sg_db_set("system_admin", "admin",
		      "profile=read-write\n"
		      "enforce-change-password=enable\n"
		      "enforce-password-policy=enable\n"
		      "builtin=yes\n") != 0) goto fail;

	/* ── Password policy ────────────────────────────────────────── */
	if (sg_db_set("system_password-policy", "0",
		      "min-length=8\n"
		      "min-uppercase=1\n"
		      "min-lowercase=1\n"
		      "min-digit=1\n"
		      "min-special=0\n"
		      "builtin=yes\n") != 0) goto fail;

	/* ── System settings ────────────────────────────────────────── */
	if (sg_db_set("system_settings", "0",
		      "hostname=stargazer\n"
		      "ip-forward=enable\n") != 0) goto fail;

	/* ── Default firewall policy (deny all) ─────────────────────── */
	if (sg_db_set("firewall_policy", "1",
		      "name=default-deny\n"
		      "srcintf=any\n"
		      "dstintf=any\n"
		      "srcaddr=all\n"
		      "dstaddr=all\n"
		      "action=deny\n"
		      "status=enable\n"
		      "comment=Default deny all traffic\n") != 0) goto fail;

	/* Interfaces and routes are handled by mgmtd_sync_interfaces() */

	/* Verify critical tables populated before stamping flag */
	for (size_t i = 0; i < N_CRITICAL; i++) {
		if (sg_db_count(critical_tables[i]) == 0) {
			mgmt_log("ERROR", "seed verify: %s has 0 entries",
				 critical_tables[i]);
			return -1;
		}
	}

	/* Stamp the seeded flag LAST — if seeding partially fails,
	 * next boot retries as BOOT_FIRST (no flag, all tables empty). */
	sg_db_set_val("system_meta", "0", "seeded", "1");

	mgmt_log("INFO", "default configuration seeded successfully");
	return 0;

fail:
	mgmt_log("ERROR", "seed failed — database write error");
	return -1;
}

/* ── Config reconciliation ──────────────────────────────────────────────── */

/*
 * Reconcile database state with the current firmware's config registry.
 * Runs on every boot (both FIRST and NORMAL). Direction-agnostic:
 * handles upgrade, downgrade, and same-version equally.
 *
 * Phase 1: Seed missing CFG_SINGLE types (new types added by firmware)
 * Phase 2: Backfill missing keys on existing entries (new fields added)
 * Phase 3: Purge stale types (types removed from registry)
 */
static void mgmtd_reconcile_config(void)
{
	const sg_type_info_t *types = sg_reg_types();
	int changes = 0;

	/* ── Phase 1: seed missing CFG_SINGLE types ───────────────── */

	for (const sg_type_info_t *t = types; t->name; t++) {
		if (t->mode != CFG_SINGLE)
			continue;
		if (sg_db_count(t->name) > 0)
			continue;

		const char *defs = sg_reg_default_values(t->name);
		if (!defs || !defs[0])
			continue;

		/* Copy static buffer — sg_db_set may clobber it */
		char defcopy[1024];
		snprintf(defcopy, sizeof(defcopy), "%s", defs);

		if (sg_db_set(t->name, "0", defcopy) == 0) {
			mgmt_log("INFO", "reconcile: seeded missing %s",
				 t->name);
			changes++;
		} else {
			mgmt_log("ERROR", "reconcile: failed to seed %s",
				 t->name);
		}
	}

	/* ── Phase 2: backfill missing keys on existing entries ───── */

	for (const sg_type_info_t *t = types; t->name; t++) {
		const char *defs = sg_reg_default_values(t->name);
		if (!defs || !defs[0])
			continue;

		/* Copy static buffer before iterating */
		char defcopy[1024];
		snprintf(defcopy, sizeof(defcopy), "%s", defs);

		/* Parse "key=val\n" pairs from defaults */
		char *p = defcopy;
		while (*p) {
			if (*p == '\n') { p++; continue; }

			char *eol = strchr(p, '\n');
			if (eol) *eol = '\0';

			char *eq = strchr(p, '=');
			if (!eq) {
				p = eol ? eol + 1 : p + strlen(p);
				continue;
			}
			*eq = '\0';
			const char *key = p;
			const char *val = eq + 1;

			if (t->mode == CFG_SINGLE) {
				if (sg_db_count(t->name) > 0) {
					char *cur = sg_db_get_val(t->name, "0", key);
					if (!cur) {
						sg_db_set_val(t->name, "0", key, val);
						mgmt_log("INFO", "reconcile: backfilled %s.%s = %s",
							 t->name, key, val);
						changes++;
					} else {
						free(cur);
					}
				}
			} else {
				/* CFG_TABLE: iterate all existing entries */
				char *ids = sg_db_list(t->name);
				if (ids) {
					char *id = ids;
					while (*id) {
						char *nl = strchr(id, '\n');
						if (nl) *nl = '\0';
						if (*id) {
							char *cur = sg_db_get_val(t->name, id, key);
							if (!cur) {
								sg_db_set_val(t->name, id, key, val);
								mgmt_log("INFO", "reconcile: backfilled %s:%s.%s = %s",
									 t->name, id, key, val);
								changes++;
							} else {
								free(cur);
							}
						}
						if (!nl) break;
						id = nl + 1;
					}
					free(ids);
				}
			}

			p = eol ? eol + 1 : p + strlen(p) + strlen(val) + 1;
		}
	}

	/* ── Phase 3: purge stale types ───────────────────────────── */

	char *db_types = sg_db_list_types();
	if (db_types) {
		/* Copy because we modify during iteration */
		char *copy = strdup(db_types);
		free(db_types);
		if (copy) {
			char *tp = copy;
			while (*tp) {
				char *nl = strchr(tp, '\n');
				if (nl) *nl = '\0';
				if (*tp) {
					/* Skip internal meta type */
					if (strcmp(tp, "system_meta") != 0 &&
					    sg_reg_type_mode(tp) == -1) {
						mgmt_log("INFO", "reconcile: purging stale type '%s'", tp);
						sg_db_purge_type(tp);
						changes++;
					}
				}
				if (!nl) break;
				tp = nl + 1;
			}
			free(copy);
		}
	}

	if (changes > 0)
		mgmt_log("INFO", "reconcile: %d change(s) applied", changes);
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
 * Initialise base INPUT chain policy at boot.
 * Must run BEFORE mgmtd_replay_config() so that per-interface SG_IN_*
 * jump rules are appended after these foundational rules.
 *
 * Result:
 *   INPUT policy DROP
 *   1. -i lo -j ACCEPT                 (loopback / self-ping)
 *   2. -m conntrack --ctstate EST,REL   (return traffic)
 *   ... per-interface jumps added later by apply_allowaccess()
 */
static void mgmtd_init_firewall(void)
{
	/* Verify iptables is installed before touching any rules */
	if (!ipt_available()) {
		mgmt_log("ERROR",
			 "iptables binary not found — firewall NOT configured! "
			 "INPUT chain remains at default ACCEPT policy.");
		return;
	}

	/* Policy DROP first — never leave INPUT in ACCEPT, even briefly */
	const char *policy[] = {"iptables", "-P", "INPUT", "DROP", NULL};
	if (ipt_exec(policy) != 0) {
		mgmt_log("ERROR",
			 "CRITICAL: failed to set INPUT policy DROP — "
			 "firewall is NOT active!");
		return;
	}

	/* Flush INPUT — clean slate (safe on restart) */
	const char *flush[] = {"iptables", "-F", "INPUT", NULL};
	ipt_exec(flush);

	/* Ensure loopback is UP — nothing else in the boot sequence does this.
	 * mgmtd_sync_interfaces() skips lo, so apply_interface() never runs
	 * for it.  Without lo UP, self-ping and local daemon IPC break. */
	if (iface_exists("lo")) {
		const char *lo_up[] = {"ip", "link", "set", "lo", "up", NULL};
		free(safe_exec(lo_up));
		const char *lo_ip[] = {"ip", "addr", "add", "127.0.0.1/8",
				       "dev", "lo", NULL};
		free(safe_exec(lo_ip));  /* no-op if already assigned */

		const char *lo[] = {"iptables", "-A", "INPUT",
				    "-i", "lo", "-j", "ACCEPT", NULL};
		if (ipt_exec(lo) != 0)
			mgmt_log("ERROR", "failed to add loopback ACCEPT rule");
	}

	/* Allow return traffic for connections initiated by the firewall
	 * (e.g. ping reply, DNS response, HTTP response). */
	const char *est[] = {"iptables", "-A", "INPUT",
			     "-m", "conntrack",
			     "--ctstate", "ESTABLISHED,RELATED",
			     "-j", "ACCEPT", NULL};
	if (ipt_exec(est) != 0)
		mgmt_log("ERROR",
			 "failed to add ESTABLISHED/RELATED rule");
	else
		mgmt_log("INFO", "INPUT chain: policy DROP, lo ACCEPT, "
			 "ESTABLISHED/RELATED ACCEPT");

	/* Load conntrack TFTP helper module and assign it explicitly
	 * via xt_CT in the raw table.  This teaches conntrack about
	 * TFTP's port-switching so return traffic is marked RELATED
	 * and accepted by the ESTABLISHED,RELATED rules.
	 *
	 * Without this, TFTP firmware downloads will fail because the
	 * server responds from a random port (not 69) and conntrack
	 * can't mark those packets as RELATED without the helper. */
	const char *mod1[] = {"insmod",
		"/lib/modules/stargazer/nf_conntrack_tftp.ko", NULL};
	const char *mod2[] = {"insmod",
		"/lib/modules/stargazer/nf_nat_tftp.ko", NULL};
	char *m1out = safe_exec(mod1);
	char *m2out = safe_exec(mod2);

	if (m1out && m1out[0] != '\0')
		mgmt_log("ERROR", "insmod nf_conntrack_tftp: %s", m1out);
	else
		mgmt_log("INFO", "loaded nf_conntrack_tftp");
	if (m2out && m2out[0] != '\0')
		mgmt_log("ERROR", "insmod nf_nat_tftp: %s", m2out);
	else
		mgmt_log("INFO", "loaded nf_nat_tftp");
	free(m1out);
	free(m2out);

	/* Assign TFTP helper for outbound TFTP requests (firmware dl) */
	const char *ct_out[] = {"iptables", "-t", "raw",
				"-I", "OUTPUT",
				"-p", "udp", "-m", "udp",
				"--dport", "69",
				"-j", "CT", "--helper", "tftp", NULL};
	if (ipt_exec(ct_out) == 0)
		mgmt_log("INFO", "CT helper: tftp on OUTPUT udp/69");
	else
		mgmt_log("ERROR", "TFTP CT helper failed — "
			 "firmware download via TFTP will not work");
}

/*
 * scrub_config_entry — Validate every key=value line in a config entry.
 *
 * Strips unknown keys and cleans invalid values using sg_reg_scrub_value().
 * Builds the scrubbed output in 'out'. Returns 1 if anything changed, 0 if clean.
 */
static int scrub_config_entry(const char *type, const char *id,
                              const char *data, char *out, size_t outsz)
{
	int changed = 0;
	size_t pos = 0;
	const char *p = data;

	while (*p) {
		const char *eol = strchr(p, '\n');
		size_t llen = eol ? (size_t)(eol - p) : strlen(p);

		/* Skip empty lines */
		if (llen == 0) {
			p++;
			continue;
		}

		/* Extract key=value */
		char line[MAX_LINE];
		if (llen >= sizeof(line)) llen = sizeof(line) - 1;
		memcpy(line, p, llen);
		line[llen] = '\0';

		char *eq = strchr(line, '=');
		if (!eq) {
			/* Malformed line — skip */
			p += llen;
			if (eol) p++;
			changed = 1;
			continue;
		}

		*eq = '\0';
		const char *key = line;
		const char *val = eq + 1;

		/* Internal metadata keys — preserve as-is, never scrub */
		if (strcmp(key, "builtin") == 0) {
			int n = snprintf(out + pos, outsz - pos,
					 "%s=%s\n", key, val);
			if (n > 0 && pos + (size_t)n < outsz)
				pos += (size_t)n;
			p += llen;
			if (eol) p++;
			continue;
		}

		/* Unknown key → strip */
		if (!sg_reg_is_valid_key(type, key)) {
			mgmt_log("INFO", "scrub %s:%s: stripped unknown key '%s'",
				 type, id, key);
			changed = 1;
			p += llen;
			if (eol) p++;
			continue;
		}

		/* Validate and scrub value */
		char clean_val[MAX_LINE];
		int scrubbed = sg_reg_scrub_value(type, key, val,
		                                  clean_val, sizeof(clean_val));
		if (scrubbed) {
			mgmt_log("INFO", "scrub %s:%s: '%s' cleaned '%s' -> '%s'",
				 type, id, key, val, clean_val);
			changed = 1;
		}

		const char *use_val = scrubbed ? clean_val : val;

		/* Append key=value\n to output */
		int n = snprintf(out + pos, outsz - pos, "%s=%s\n", key, use_val);
		if (n > 0 && pos + (size_t)n < outsz)
			pos += (size_t)n;

		p += llen;
		if (eol) p++;
	}

	out[pos] = '\0';
	return changed;
}

/*
 * Replay saved configuration at boot.
 * Iterates through config types that have runtime apply handlers
 * and calls apply_config() for each entry.
 * Scrubs invalid values before applying — survives version upgrades/downgrades.
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
			char clean[SG_PAYLOAD_MAX];
			int scrubbed = scrub_config_entry(single_types[i], "0",
			                                  data, clean,
			                                  sizeof(clean));
			const char *use = scrubbed ? clean : data;

			if (scrubbed)
				sg_db_set(single_types[i], "0", clean);

			sg_status_t rc = apply_config(single_types[i], "0",
						      use,
						      result, sizeof(result));
			mgmt_log(rc == SG_OK ? "INFO" : "WARN",
				 "replay %s: %s", single_types[i], result);
			free(data);
		}
	}

	/* Table config types (multiple entries) */
	static const char *table_types[] = {
		"system_admin",
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
				char clean[SG_PAYLOAD_MAX];
				int scrubbed = scrub_config_entry(
					table_types[i], id, data,
					clean, sizeof(clean));
				const char *use = scrubbed ? clean : data;

				if (scrubbed)
					sg_db_set(table_types[i], id, clean);

				sg_status_t rc = apply_config(
					table_types[i], id, use,
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

/* ── Session tag table ──────────────────────────────────────────────────── */

/*
 * In-memory table of active session tags.  At login, CLI acquires a random
 * 64-bit tag via SG_CMD_SESSION_TAG_NEW.  Every subsequent IPC request
 * carries the tag in the header.  mgmtd validates the tag on every request.
 * When admin accounts are mutated, all tags for affected users are purged.
 */

typedef struct {
	uint64_t tag;
	char     user[SG_USERNAME_MAX];
} session_tag_entry_t;

static session_tag_entry_t g_session_tags[MAX_SESSION_TAGS];

static uint64_t session_tag_generate(void)
{
	uint64_t tag = 0;
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) return 0;
	ssize_t n = read(fd, &tag, sizeof(tag));
	close(fd);
	if (n != (ssize_t)sizeof(tag)) return 0;
	/* Ensure non-zero (0 means untagged) */
	if (tag == 0) tag = 1;
	return tag;
}

static uint64_t session_tag_new(const char *user)
{
	uint64_t tag = session_tag_generate();
	if (tag == 0) return 0;

	for (int i = 0; i < MAX_SESSION_TAGS; i++) {
		if (g_session_tags[i].tag == 0) {
			g_session_tags[i].tag = tag;
			snprintf(g_session_tags[i].user,
				 sizeof(g_session_tags[i].user),
				 "%s", user);
			return tag;
		}
	}
	return 0; /* table full */
}

static int session_tag_validate(const char *user, uint64_t tag)
{
	if (tag == 0) return 0;
	for (int i = 0; i < MAX_SESSION_TAGS; i++) {
		if (g_session_tags[i].tag == tag &&
		    strcmp(g_session_tags[i].user, user) == 0)
			return 1;
	}
	return 0;
}

static void session_tag_delete(const char *user, uint64_t tag)
{
	for (int i = 0; i < MAX_SESSION_TAGS; i++) {
		if (g_session_tags[i].tag == tag &&
		    strcmp(g_session_tags[i].user, user) == 0) {
			g_session_tags[i].tag = 0;
			g_session_tags[i].user[0] = '\0';
			return;
		}
	}
}

void session_tag_purge_user(const char *user)
{
	for (int i = 0; i < MAX_SESSION_TAGS; i++) {
		if (g_session_tags[i].tag != 0 &&
		    strcmp(g_session_tags[i].user, user) == 0) {
			g_session_tags[i].tag = 0;
			g_session_tags[i].user[0] = '\0';
		}
	}
}

/*
 * Must be called after ANY successful admin account mutation.
 * Invalidates the target user's active CLI sessions so they
 * must re-authenticate with updated credentials / permissions.
 */
void admin_notify_change(const char *user)
{
	session_tag_purge_user(user);
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

/* ── Apply config to running system ─────────────────────────────────────── */

static sg_status_t apply_config(const char *type, const char *id,
				const char *data,
				char *result, size_t rsize)
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

		/* Session purge deferred to CFG_SET cascade — apply_config()
		 * is called before save, so purging here would kill the tag
		 * before the save can complete. */
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
		/* Session purge deferred to CFG_SET cascade — apply_config()
		 * is called before save, so purging here would kill the tag
		 * before the save can complete. */
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
const char *get_user_permissions(const char *username)
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

int has_permission(const char *perms_csv, const char *perm)
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
 * Return the permission required to access a config type.
 * Returns "admin", "configure", etc., or NULL if the type is unknown.
 * Callers decide what user permissions satisfy the requirement
 * based on the operation (read vs write).
 */
const char *get_type_permission(const char *type_name)
{
	return sg_reg_type_perm(type_name);
}

/* ── Referential integrity check ────────────────────────────────────────── */

/*
 * Check if any config entries reference this object by its ID.
 * Returns 0 if safe to delete, -1 if referenced (errbuf filled).
 */
int check_references(const char *type, const char *id,
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
sg_status_t validate_cfg_data(const char *type, const char *data,
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
			if (vlen >= SG_PAYLOAD_MAX) {
				snprintf(errbuf, errsz,
					 "Value for '%s' too long", key);
				return SG_ERR_INVALID_VAL;
			}
			char val[SG_PAYLOAD_MAX];
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

static int handle_request(int client_fd, sg_request_hdr_t *hdr,
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

	/* Session tag validation gate.
	 * Commands exempt from tag validation (no tag required):
	 *   - SESSION_TAG_NEW: acquiring a tag (no tag yet)
	 *   - SESSION_TAG_DEL: releasing a tag (best-effort cleanup)
	 *   - WHOAMI: identity query (used before tag acquisition)
	 *   - DEBUG_FETCH: debug trace retrieval
	 *   - HISTORY_LOAD/SAVE: called during login before tag acquisition
	 * All other commands (including PING) require a valid tag.
	 * PING is intentionally NOT exempt so the idle callback can
	 * detect expired sessions by sending a tag-validated PING. */
	if (cmd != SG_CMD_SESSION_TAG_NEW &&
	    cmd != SG_CMD_SESSION_TAG_DEL &&
	    cmd != SG_CMD_WHOAMI &&
	    cmd != SG_CMD_DEBUG_FETCH &&
	    cmd != SG_CMD_HISTORY_LOAD &&
	    cmd != SG_CMD_HISTORY_SAVE) {
		if (!session_tag_validate(user, hdr->session_tag)) {
			send_error(client_fd, SG_ERR_SESSION_EXPIRED,
				   "Session tag invalid or expired");
			return 0;
		}
	}

	switch (cmd) {

	/* ── Config read ────────────────────────────────────────────────── */
	case SG_CMD_CFG_GET: {
		/* Payload format: "section\n" (section = "type:id" or "type") */
		if (!payload || hdr->payload_len == 0) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing section name");
			return 0;
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
			return 0;
		}
		if (!get_type_permission(db_type)) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Unknown config type");
			return 0;
		}
		/* Read operations: any authenticated user can view config */

		if (db_id[0] && !sg_reg_validate_entry_id(db_type, db_id)) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Invalid entry ID");
			return 0;
		}

		char *data = sg_db_get(db_type, db_id);
		if (data) {
			send_ok(client_fd, NULL, data);
			free(data);
		} else {
			send_error(client_fd, SG_ERR_ENTRY_NOT_FOUND, section);
		}
		return 0;
	}

	case SG_CMD_CFG_LIST: {
		/* Payload: "type\n" — list entry IDs for a config type */
		if (!payload || hdr->payload_len == 0) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing type prefix");
			return 0;
		}
		char prefix[256] = {0};
		snprintf(prefix, sizeof(prefix), "%s", payload);
		size_t plen = strlen(prefix);
		if (plen > 0 && prefix[plen-1] == '\n') prefix[--plen] = '\0';

		if (!sg_is_safe_id(prefix)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid type prefix");
			return 0;
		}
		if (!get_type_permission(prefix)) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Unknown config type");
			return 0;
		}
		/* Read operations: any authenticated user can list */

		char *list = sg_db_list(prefix);
		if (list) {
			send_ok(client_fd, NULL, list);
			free(list);
		} else {
			send_ok(client_fd, "No entries", "");
		}
		return 0;
	}

	case SG_CMD_CFG_LIST_TYPES: {
		/* List all distinct config types stored in the database.
		 * Requires admin permission (exposes full schema). */
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "admin")) {
			send_error(client_fd, SG_ERR_PERM_DENIED,
				   "Requires 'admin' permission");
			return 0;
		}
		char *types = sg_db_list_types();
		if (types) {
			send_ok(client_fd, NULL, types);
			free(types);
		} else {
			send_ok(client_fd, "No types", "");
		}
		return 0;
	}

	/* ── Config write ───────────────────────────────────────────────── */
	case SG_CMD_CFG_SET: {
		/* Payload format: "section\nkey=value\nkey=value\n..." */
		if (!payload || hdr->payload_len == 0) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing section + data");
			return 0;
		}
		char section[256] = {0};
		const char *nl = strchr(payload, '\n');
		if (!nl) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Missing data after section");
			return 0;
		}
		size_t slen = (size_t)(nl - payload);
		if (slen >= sizeof(section)) slen = sizeof(section) - 1;
		memcpy(section, payload, slen);
		section[slen] = '\0';
		const char *data = nl + 1;
		if (*data == '\0') {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Missing data after section");
			return 0;
		}

		/* Parse "type:id" → type + id */
		char db_type[256], db_id[256];
		sg_db_parse_section(section, db_type, sizeof(db_type),
				    db_id, sizeof(db_id));

		if (sg_reg_type_mode(db_type) < 0) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Unknown config type");
			return 0;
		}
		{
			const char *req = get_type_permission(db_type);
			if (!req) {
				send_error(client_fd, SG_ERR_INVALID_ARG,
					   "Unknown config type");
				return 0;
			}
			const char *perms = get_user_permissions(user);
			if (strcmp(req, "admin") == 0) {
				if (!has_permission(perms, "admin")) {
					send_error(client_fd, SG_ERR_PERM_DENIED,
						   "Requires 'admin' permission");
					return 0;
				}
			} else {
				if (!has_permission(perms, "configure") &&
				    !has_permission(perms, "admin")) {
					send_error(client_fd, SG_ERR_PERM_DENIED,
						   "Requires 'configure' permission");
					return 0;
				}
			}
		}
		if (!sg_reg_validate_entry_id(db_type, db_id)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid entry ID");
			return 0;
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
			return 0;
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
			if (cpos + ll + 1 >= sizeof(clean)) {
				send_error(client_fd, SG_ERR_INVALID_ARG,
					   "Config payload too large");
				return 0;
			}
			memcpy(clean + cpos, dp, ll);
			cpos += ll;
			clean[cpos++] = '\n';
			dp += ll;
			if (el) dp++;
		}
		/* Re-append original builtin status */
		if (was_builtin) {
			const char *tag = "builtin=yes\n";
			size_t tlen = strlen(tag);
			if (cpos + tlen >= sizeof(clean)) {
				send_error(client_fd, SG_ERR_INVALID_ARG,
					   "Config payload too large");
				return 0;
			}
			memcpy(clean + cpos, tag, tlen);
			cpos += tlen;
		}
		clean[cpos] = '\0';

		if (sg_db_set(db_type, db_id, clean) != 0) {
			mgmt_log("ERROR", "sg_db_set failed for %s", section);
			send_error(client_fd, SG_ERR_IO_FAIL, "Failed to write config");
			return 0;
		}

		/* Invalidate sessions for admin/profile/policy config changes.
		 * All affected admins are purged so they re-authenticate,
		 * including the acting user. */
		if (strcmp(db_type, "system_admin") == 0) {
			admin_notify_change(db_id);
		} else if (strcmp(db_type, "system_password-policy") == 0) {
			/* Policy change affects all admins — purge everyone */
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
					session_tag_purge_user(aname);
					p += len;
					if (eol) p++;
				}
				free(admins);
			}
		} else if (strcmp(db_type, "system_admin-profile") == 0) {
			/* Purge all admins that use this profile */
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
							session_tag_purge_user(aname);
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
		return 0;
	}

	case SG_CMD_CFG_DEL: {
		if (!payload || hdr->payload_len == 0) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing section");
			return 0;
		}
		char section[256] = {0};
		snprintf(section, sizeof(section), "%s", payload);
		size_t slen = strlen(section);
		if (slen > 0 && section[slen-1] == '\n') section[--slen] = '\0';

		if (!strchr(section, ':')) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Missing ':' separator (expected type:id)");
			return 0;
		}

		/* Parse "type:id" → type + id */
		char db_type[256], db_id[256];
		sg_db_parse_section(section, db_type, sizeof(db_type),
				    db_id, sizeof(db_id));

		if (sg_reg_type_mode(db_type) < 0) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Unknown config type");
			return 0;
		}
		{
			const char *req = get_type_permission(db_type);
			if (!req) {
				send_error(client_fd, SG_ERR_INVALID_ARG, "Unknown config type");
				return 0;
			}
			const char *perms = get_user_permissions(user);
			if (strcmp(req, "admin") == 0) {
				if (!has_permission(perms, "admin")) {
					send_error(client_fd, SG_ERR_PERM_DENIED,
						   "Requires 'admin' permission");
					return 0;
				}
			} else {
				if (!has_permission(perms, "configure") &&
				    !has_permission(perms, "admin")) {
					send_error(client_fd, SG_ERR_PERM_DENIED,
						   "Requires 'configure' permission");
					return 0;
				}
			}
		}
		if (db_id[0] == '\0') {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Missing entry ID");
			return 0;
		}
		if (!sg_reg_validate_entry_id(db_type, db_id)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid entry ID");
			return 0;
		}

		/* Check builtin flag */
		char *existing = sg_db_get(db_type, db_id);
		if (existing) {
			char bi[VALBUFSZ];
			extract_val(existing, "builtin", bi, sizeof(bi));
			if (strcmp(bi, "yes") == 0) {
				free(existing);
				send_error(client_fd, SG_ERR_BUILTIN, section);
				return 0;
			}
			free(existing);
		}

		/* Check referential integrity */
		char ref_err[SG_EXTRA_MAX];
		if (check_references(db_type, db_id, ref_err, sizeof(ref_err)) != 0) {
			send_error(client_fd, SG_ERR_IN_USE, ref_err);
			return 0;
		}

		/* If deleting admin, purge tags and delete system user */
		if (strcmp(db_type, "system_admin") == 0) {
			admin_notify_change(db_id);
			delete_system_user(db_id);
		}

		if (sg_db_del(db_type, db_id) != 0) {
			send_error(client_fd, SG_ERR_IO_FAIL, "Failed to delete section");
			return 0;
		}
		send_ok_audited(client_fd, "Deleted", NULL,
				user, "cfg_del", section);
		return 0;
	}

	case SG_CMD_CFG_APPLY: {
		/* Payload: "type\nid\nkey=value\n..." */
		if (!payload || hdr->payload_len == 0) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing type+id+data");
			return 0;
		}
		char type_str[256] = {0}, id_str[256] = {0};
		const char *p = payload;
		const char *nl1 = strchr(p, '\n');
		if (!nl1) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Bad format");
			return 0;
		}
		size_t tlen = (size_t)(nl1 - p);
		if (tlen >= sizeof(type_str)) tlen = sizeof(type_str) - 1;
		memcpy(type_str, p, tlen);
		type_str[tlen] = '\0';

		p = nl1 + 1;
		const char *nl2 = strchr(p, '\n');
		if (!nl2) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Bad format");
			return 0;
		}
		size_t ilen = (size_t)(nl2 - p);
		if (ilen >= sizeof(id_str)) ilen = sizeof(id_str) - 1;
		memcpy(id_str, p, ilen);
		id_str[ilen] = '\0';

		{
			const char *req = get_type_permission(type_str);
			if (!req) {
				send_error(client_fd, SG_ERR_INVALID_ARG, "Unknown config type");
				return 0;
			}
			const char *perms = get_user_permissions(user);
			if (strcmp(req, "admin") == 0) {
				if (!has_permission(perms, "admin")) {
					send_error(client_fd, SG_ERR_PERM_DENIED,
						   "Requires 'admin' permission");
					return 0;
				}
			} else {
				if (!has_permission(perms, "configure") &&
				    !has_permission(perms, "admin")) {
					send_error(client_fd, SG_ERR_PERM_DENIED,
						   "Requires 'configure' permission");
					return 0;
				}
			}
		}

		if (!sg_reg_validate_entry_id(type_str, id_str)) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Invalid entry ID");
			return 0;
		}

		const char *data = nl2 + 1;
		char result[512];
		sg_status_t st = apply_config(type_str, id_str, data,
					      result, sizeof(result));

		if (st == SG_OK) {
			char audit_msg[512];
			snprintf(audit_msg, sizeof(audit_msg), "%s:%s", type_str, id_str);
			send_ok_audited(client_fd, result, NULL,
					user, "cfg_apply", audit_msg);
		} else {
			send_error(client_fd, st, result);
		}
		return 0;
	}

	/* ── Admin management (handlers in mgmtd_user.c) ──────────────── */
	case SG_CMD_ADMIN_CREATE:
		return handle_admin_create(client_fd, user, payload, hdr);
	case SG_CMD_ADMIN_DELETE:
		return handle_admin_delete(client_fd, user, payload, hdr);
	case SG_CMD_ADMIN_SET_PW:
		return handle_admin_set_pw(client_fd, user, payload, hdr);
	case SG_CMD_ADMIN_SET_ENF:
		return handle_admin_set_enf(client_fd, user, payload, hdr);
	case SG_CMD_ADMIN_CHECK_PW:
		return handle_admin_check_pw(client_fd, user, payload, hdr);
	case SG_CMD_ADMIN_LOCK_PW:
		return handle_admin_lock_pw(client_fd, user, payload, hdr);

	/* ── Session tag ───────────────────────────────────────────────── */
	case SG_CMD_SESSION_TAG_NEW: {
		if (!sg_is_safe_id(user)) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Invalid username");
			return 0;
		}
		uint64_t tag = session_tag_new(user);
		if (tag == 0) {
			send_error(client_fd, SG_ERR_SYSTEM_FAIL,
				   "Session table full");
			return 0;
		}
		char tagstr[32];
		snprintf(tagstr, sizeof(tagstr), "%llu",
			 (unsigned long long)tag);
		send_ok(client_fd, NULL, tagstr);
		return 0;
	}

	case SG_CMD_SESSION_TAG_DEL: {
		session_tag_delete(user, hdr->session_tag);
		send_ok(client_fd, "Session released", NULL);
		return 0;
	}

	/* ── System commands ────────────────────────────────────────────── */
	case SG_CMD_SYS_POWEROFF: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "admin")) {
			send_error(client_fd, SG_ERR_PERM_DENIED, "Requires 'admin' permission");
			return 0;
		}
		send_ok(client_fd, "Shutting down...", NULL);
		(void)audit_log(user, "system_poweroff", "");
		/* Close DB so /etc/stargazer can be cleanly unmounted */
		sg_db_close();
		/* Give time for response to be sent */
		usleep(100000);
		{
			const char *argv[] = {"/sbin/poweroff", NULL};
			free(safe_exec(argv));
		}
		return 0;
	}

	case SG_CMD_SYS_REBOOT: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "admin")) {
			send_error(client_fd, SG_ERR_PERM_DENIED, "Requires 'admin' permission");
			return 0;
		}
		send_ok(client_fd, "Rebooting...", NULL);
		(void)audit_log(user, "system_reboot", "");
		/* Close DB so /etc/stargazer can be cleanly unmounted */
		sg_db_close();
		usleep(100000);
		{
			const char *argv[] = {"/sbin/reboot", NULL};
			free(safe_exec(argv));
		}
		return 0;
	}

	/* ── Firmware upgrade (handlers in mgmtd_firmware.c) ──────────── */
	case SG_CMD_UPGRADE_STATUS:
		return handle_upgrade_status(client_fd, user, payload, hdr);
	case SG_CMD_UPGRADE_START:
		return handle_upgrade_start(client_fd, user, payload, hdr);
	case SG_CMD_UPGRADE_PROGRESS:
		return handle_upgrade_progress(client_fd, user, payload, hdr);
	case SG_CMD_UPGRADE_CANCEL:
		return handle_upgrade_cancel(client_fd, user, payload, hdr);

	case SG_CMD_SHOW_STATUS: {
		char status_buf[512];
		size_t spos = 0;
		int n;

		n = snprintf(status_buf, sizeof(status_buf),
			     "=== Stargazer Status ===\n");
		if (n > 0) spos += (size_t)n;

		/* Check if pkt_forward module is loaded */
		const char *lsmod_argv[] = {"lsmod", NULL};
		char *lsmod_out = safe_exec(lsmod_argv);
		const char *mod_status = "not loaded";
		if (lsmod_out && strstr(lsmod_out, "pkt_forward"))
			mod_status = "loaded";
		n = snprintf(status_buf + spos, sizeof(status_buf) - spos,
			     "Module pkt_forward: %s\n", mod_status);
		if (n > 0 && (size_t)n < sizeof(status_buf) - spos)
			spos += (size_t)n;
		free(lsmod_out);

		/* Read uptime from /proc */
		FILE *fp = fopen("/proc/uptime", "r");
		if (fp) {
			char uptbuf[64] = {0};
			if (fgets(uptbuf, sizeof(uptbuf), fp)) {
				/* First field is seconds */
				char *sp = strchr(uptbuf, ' ');
				if (sp) *sp = '\0';
				n = snprintf(status_buf + spos,
					     sizeof(status_buf) - spos,
					     "Uptime: %ss\n", uptbuf);
				if (n > 0 && (size_t)n < sizeof(status_buf) - spos)
					spos += (size_t)n;
			}
			fclose(fp);
		}

		send_ok(client_fd, NULL, status_buf);
		return 0;
	}

	case SG_CMD_SHOW_IFACES: {
		char *out = mgmtd_show_interfaces();
		send_ok(client_fd, NULL, out ? out : "");
		free(out);
		return 0;
	}

	case SG_CMD_SHOW_ROUTES: {
		const char *argv[] = {"ip", "route", NULL};
		char *out = safe_exec(argv);
		send_ok(client_fd, NULL, out ? out : "");
		free(out);
		return 0;
	}

	case SG_CMD_SHOW_STATS: {
		const char *argv[] = {"dmesg", NULL};
		char *raw = safe_exec(argv);
		if (!raw || !raw[0]) {
			send_ok(client_fd, NULL, raw ? raw : "");
			free(raw);
			return 0;
		}

		/* Filter lines matching pkt_forward/forwarded/dropped,
		 * keep last 20 matching lines (replaces grep|tail pipeline).
		 * Circular buffer of (start, len) pairs. */
		struct { const char *s; size_t len; } ring[20];
		int nmatches = 0;
		const char *p = raw;
		while (*p) {
			const char *eol = strchr(p, '\n');
			size_t llen = eol ? (size_t)(eol - p) : strlen(p);
			/* Case-insensitive match within the line */
			if (memmem(p, llen, "pkt_forward", 11) ||
			    memmem(p, llen, "forwarded", 9) ||
			    memmem(p, llen, "dropped", 7) ||
			    memmem(p, llen, "Forwarded", 9) ||
			    memmem(p, llen, "Dropped", 7)) {
				ring[nmatches % 20].s = p;
				ring[nmatches % 20].len = llen;
				nmatches++;
			}
			if (!eol) break;
			p = eol + 1;
		}

		/* Build output from ring buffer */
		char buf[4096];
		size_t used = 0;
		int count = nmatches < 20 ? nmatches : 20;
		int start = nmatches <= 20 ? 0 : nmatches % 20;
		for (int i = 0; i < count && used < sizeof(buf) - 2; i++) {
			int idx = (start + i) % 20;
			size_t llen = ring[idx].len;
			if (used + llen + 2 > sizeof(buf))
				llen = sizeof(buf) - used - 2;
			memcpy(buf + used, ring[idx].s, llen);
			used += llen;
			buf[used++] = '\n';
		}
		buf[used] = '\0';
		send_ok(client_fd, NULL, buf);
		free(raw);
		return 0;
	}

	case SG_CMD_WHOAMI: {
		/* Return caller's profile and permissions from database */
		char *udata = sg_db_get("system_admin", user);
		if (!udata) {
			send_ok(client_fd, NULL, "profile=read-only\npermissions=monitor\n");
			return 0;
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
		return 0;
	}

	/* ── Firewall/routing diagnostics ─────────────────────────────── */

	case SG_CMD_DIAG_FW_IPTABLES: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "monitor")) {
			mgmt_log("WARN", "user '%s' denied FW_IPTABLES (no monitor perm)", user);
			send_error(client_fd, SG_ERR_PERM_DENIED,
				   "Requires 'monitor' permission");
			return 0;
		}
		/* Extract table from payload (default "filter") */
		char table[16] = "filter";
		if (payload && payload[0])
			extract_val(payload, "table", table, sizeof(table));

		/* Whitelist: only "filter", "nat", or "raw" */
		if (strcmp(table, "filter") != 0 && strcmp(table, "nat") != 0 &&
		    strcmp(table, "raw") != 0) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Table must be 'filter', 'nat', or 'raw'");
			return 0;
		}

		const char *argv[] = {
			"iptables", "-t", table, "-L", "-n", "-v", NULL
		};
		char *out = safe_exec(argv);
		if (out && out[0])
			send_ok(client_fd, NULL, out);
		else
			send_ok(client_fd, "empty",
				"  No iptables rules found.\n"
				"  (is iptables available?)\n");
		free(out);
		return 0;
	}

	case SG_CMD_DIAG_FW_POLICY: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "monitor")) {
			mgmt_log("WARN", "user '%s' denied FW_POLICY (no monitor perm)", user);
			send_error(client_fd, SG_ERR_PERM_DENIED,
				   "Requires 'monitor' permission");
			return 0;
		}
		const char *argv[] = {
			"iptables", "-L", "INPUT", "-n", "-v", NULL
		};
		char *out = safe_exec(argv);
		if (out && out[0])
			send_ok(client_fd, NULL, out);
		else
			send_ok(client_fd, "empty",
				"  No INPUT chain rules found.\n"
				"  (is iptables available?)\n");
		free(out);
		return 0;
	}

	case SG_CMD_DIAG_FW_CONNTRACK: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "monitor")) {
			mgmt_log("WARN", "user '%s' denied FW_CONNTRACK (no monitor perm)", user);
			send_error(client_fd, SG_ERR_PERM_DENIED,
				   "Requires 'monitor' permission");
			return 0;
		}
		/* Read /proc/net/nf_conntrack directly (zero fork) */
		FILE *fp = fopen("/proc/net/nf_conntrack", "r");
		if (!fp) {
			send_ok(client_fd, NULL, "");
			return 0;
		}

		size_t bufsz = 4096, used = 0;
		char *buf = malloc(bufsz);
		if (!buf) {
			fclose(fp);
			send_ok(client_fd, NULL, "");
			return 0;
		}

		char line[512];
		while (fgets(line, sizeof(line), fp)) {
			size_t llen = strlen(line);
			while (used + llen + 1 > bufsz) {
				bufsz *= 2;
				char *nb = realloc(buf, bufsz);
				if (!nb) {
					buf[used] = '\0';
					fclose(fp);
					send_ok(client_fd, NULL, buf);
					free(buf);
					return 0;
				}
				buf = nb;
			}
			memcpy(buf + used, line, llen);
			used += llen;
		}
		buf[used] = '\0';
		fclose(fp);
		send_ok(client_fd, NULL, buf);
		free(buf);
		return 0;
	}

	case SG_CMD_DIAG_ROUTES: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "monitor")) {
			mgmt_log("WARN", "user '%s' denied DIAG_ROUTES (no monitor perm)", user);
			send_error(client_fd, SG_ERR_PERM_DENIED,
				   "Requires 'monitor' permission");
			return 0;
		}
		const char *argv4[] = {"ip", "-4", "route", NULL};
		const char *argv6[] = {"ip", "-6", "route", NULL};
		char *out4 = safe_exec(argv4);
		char *out6 = safe_exec(argv6);

		/* Detect when ip -6 silently returns IPv4 routes
		 * (happens if IPv6 kernel module is not loaded).
		 * Real IPv6 output always contains ':' in addresses. */
		const char *v6_display;
		if (out6 && out6[0] && !strchr(out6, ':'))
			v6_display = "(IPv6 not available)\n";
		else
			v6_display = out6 ? out6 : "";

		/* Concatenate with headers */
		size_t len4 = out4 ? strlen(out4) : 0;
		size_t len6 = strlen(v6_display);
		size_t total = len4 + len6 + 64; /* room for headers */
		char *buf = malloc(total);
		if (buf) {
			int n = snprintf(buf, total,
					 "=== IPv4 Routes ===\n%s"
					 "\n=== IPv6 Routes ===\n%s",
					 out4 ? out4 : "",
					 v6_display);
			(void)n;
			send_ok(client_fd, NULL, buf);
			free(buf);
		} else {
			send_ok(client_fd, NULL, out4 ? out4 : "");
		}
		free(out4);
		free(out6);
		return 0;
	}

	/* ── Network diagnostics (handlers in mgmtd_network.c) ────────── */
	case SG_CMD_NET_PING:
		return handle_net_ping(client_fd, user, payload, hdr);
	case SG_CMD_NET_TRACEROUTE:
		return handle_net_traceroute(client_fd, user, payload, hdr);
	case SG_CMD_NET_NSLOOKUP:
		return handle_net_nslookup(client_fd, user, payload, hdr);
	case SG_CMD_NET_ARPING:
		return handle_net_arping(client_fd, user, payload, hdr);

	/* ── System diagnostics (handlers in mgmtd_diag.c) ───────────── */
	case SG_CMD_DIAG_CPU:
		return handle_diag_cpu(client_fd, user, payload, hdr);
	case SG_CMD_DIAG_RAM:
		return handle_diag_ram(client_fd, user, payload, hdr);
	case SG_CMD_DIAG_DISK:
		return handle_diag_disk(client_fd, user, payload, hdr);
	case SG_CMD_DIAG_IFACE_STATS:
		return handle_diag_iface_stats(client_fd, user, payload, hdr);
	case SG_CMD_DIAG_PROCTOP:
		return handle_diag_proctop(client_fd, user, payload, hdr);
	case SG_CMD_DIAG_THERMAL:
		return handle_diag_thermal(client_fd, user, payload, hdr);

	case SG_CMD_SHOW_SESSIONS:
		return handle_show_sessions(client_fd, user, payload, hdr);
	case SG_CMD_SHOW_BOOT_CONFIG:
		return handle_show_boot_config(client_fd, user, payload, hdr);

	case SG_CMD_DEBUG_STATE_GET:
		return handle_debug_state_get(client_fd, user, payload, hdr);
	case SG_CMD_DEBUG_STATE_SET:
		return handle_debug_state_set(client_fd, user, payload, hdr);
	case SG_CMD_DEBUG_STATE_RESET:
		return handle_debug_state_reset(client_fd, user, payload, hdr);
	case SG_CMD_HISTORY_SAVE:
		return handle_history_save(client_fd, user, payload, hdr);
	case SG_CMD_HISTORY_LOAD:
		return handle_history_load(client_fd, user, payload, hdr);

	case SG_CMD_PING:
		send_ok(client_fd, "pong", NULL);
		return 0;

	case SG_CMD_UPGRADE_TEST_SETUP:
		return handle_upgrade_test_setup(client_fd, user, payload, hdr);

	case SG_CMD_DEBUG_FETCH: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "admin")) {
			send_error(client_fd, SG_ERR_PERM_DENIED,
				   "Requires 'admin' permission");
			return 0;
		}
		if (debug_buf_used > 0) {
			send_ok(client_fd, NULL, debug_buf);
			debug_buf_used = 0;
			debug_buf[0] = '\0';
		} else {
			send_ok(client_fd, NULL, NULL);
		}
		return 0;
	}

	default:
		send_error(client_fd, SG_ERR_INVALID_CMD, "Unknown command");
		return 0;
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

	/* Ensure config directory exists with restricted permissions.
	 * mgmtd is now the sole accessor — CLI reads via IPC only. */
	mkdir(CONF_DIR, 0700);
	chmod(CONF_DIR, 0700);

	/* Open SQLite database */
	if (sg_db_open(SG_DB_PATH) != 0) {
		fprintf(stderr, "stargazer-mgmtd: failed to open database\n");
		mgmtd_signal_fifo("error");
		return 1;
	}

	/* Harden file permissions — mgmtd is the sole file accessor */
	chmod(SG_DB_PATH, 0600);
	chmod(AUDIT_LOG, 0600);

	/* Boot integrity check — single source of truth for first-boot detection */
	boot_state_t boot = mgmtd_check_boot_integrity();
	if (boot == BOOT_CORRUPTED || boot == BOOT_COMPROMISED) {
		mgmt_log("ERROR", "refusing to start — database integrity check failed");
		mgmtd_signal_fifo("error");
		sg_db_close();
		return 1;
	}
	if (boot == BOOT_FIRST) {
		if (mgmtd_seed_defaults() != 0) {
			mgmt_log("ERROR", "refusing to start — seed failed");
			mgmtd_signal_fifo("error");
			sg_db_close();
			return 1;
		}
	}

	/* Reconcile config: seed missing types, backfill keys, purge stale */
	mgmtd_reconcile_config();

	/* Discover NICs, create/protect interface entries */
	mgmtd_sync_interfaces();

	/* Set INPUT policy DROP, allow loopback + return traffic */
	mgmtd_init_firewall();

	/* Apply saved configuration to running system */
	mgmtd_replay_config();

	/* Create socket AFTER init is complete — socket file appearance means
	 * mgmtd is truly ready to accept connections (no backlog delay). */
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

	/* Signal readiness to init via FIFO */
	mgmtd_signal_fifo("ready");

	mgmt_log("INFO", "stargazer-mgmtd started, listening on %s", SG_MGMTD_SOCK);

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

		/* Handle request (with verified username)
		 * Return 0 = main loop closes fd (default)
		 * Return 1 = handler already closed fd (streaming) */
		int owned = handle_request(cfd, &hdr, payload);

		free(payload);
		if (!owned)
			close(cfd);
	}

	close(sfd);
	unlink(SG_MGMTD_SOCK);
	sg_db_close();
	mgmt_log("INFO", "stargazer-mgmtd stopped");
	return 0;
}
