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
#include <sys/mount.h>
#include <sys/wait.h>
#include <poll.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "stargazer_ipc.h"
#include "password_policy.h"
#include "sg_db.h"
#include "sg_validate.h"
#include "mgmtd_apply.h"
#include "mgmtd_sequence.h"
#include "mgmtd_internal.h"

/* ── Constants ──────────────────────────────────────────────────────────── */

/* Constants shared with sub-modules are in mgmtd_internal.h.
 * Below are constants used only in this file. */
#ifndef CONF_DIR
#define CONF_DIR         "/etc/stargazer"
#endif
#define AUDIT_LOG        "/etc/stargazer/logs/audit.log"
#define AUDIT_LOG_FB     "/var/log/stargazer-audit.log"
#define MAX_SESSION_TAGS  16
#define MAX_CLIENTS_QUEUE 8
#define BUF_SIZE         (sizeof(sg_request_hdr_t) + SG_PAYLOAD_MAX)
#define DEBUG_STATE_FILE  "/tmp/stargazer-debug.conf"
#define MGMT_DEFAULT_IP   "192.168.99.99/24" /* first NIC on first boot */
#define WEBD_SERVICE_UID  900                 /* __webd service account  */

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
static volatile sig_atomic_t g_child_died = 0;
int g_listen_fd = -1;  /* listen socket fd, for child to close after fork */

/* ── Process supervisor ────────────────────────────────────────────────── */

/*
 * Supervised child table. mgmtd is the direct parent of all managed
 * daemons (udhcpc, udhcpd, webd). SIGCHLD + waitpid gives instant
 * crash detection — no polling, no pidfiles, no watchdogd.
 */

#define SUP_MAX_CHILDREN 32
#define SUP_ARGV_STORE   512
#define SUP_ARGV_MAX     16
#define SUP_RESTART_MAX  5      /* default restart limit */

typedef struct {
	char            name[64];
	pid_t           pid;
	int             active;          /* slot in use */
	child_source_t  source;
	char            argv_store[SUP_ARGV_STORE]; /* packed NUL-separated */
	const char     *argv[SUP_ARGV_MAX];         /* pointers into store  */
	int             restart_count;
	int             restart_max;     /* 0 = do not restart */
	struct timespec started_at;      /* CLOCK_MONOTONIC */
	/* SRC_CONFIG: DB condition for restart eligibility */
	char            cfg_type[64];
	char            cfg_id[64];
	char            cfg_key[32];
	char            cfg_val[32];
} child_entry_t;

static child_entry_t g_children[SUP_MAX_CHILDREN];
static int           g_nchildren;

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
 * pipe_exec_stdin — fork+exec with data piped to child's stdin.
 *
 * Writes 'input' to the child's stdin, closes it, reads stdout+stderr.
 * Returns heap-allocated output (caller frees) or NULL on fork/pipe
 * failure.  Sets *exit_code if non-NULL.
 */
char *pipe_exec_stdin(const char *const argv[],
		      const char *input, size_t input_len,
		      int *exit_code)
{
	int in_fd[2], out_fd[2];
	if (pipe(in_fd) < 0) return NULL;
	if (pipe(out_fd) < 0) { close(in_fd[0]); close(in_fd[1]); return NULL; }

	pid_t pid = fork();
	if (pid < 0) {
		close(in_fd[0]); close(in_fd[1]);
		close(out_fd[0]); close(out_fd[1]);
		return NULL;
	}

	if (pid == 0) {
		/* Child: stdin from in_fd, stdout+stderr to out_fd */
		close(in_fd[1]);
		close(out_fd[0]);
		dup2(in_fd[0], STDIN_FILENO);
		dup2(out_fd[1], STDOUT_FILENO);
		dup2(out_fd[1], STDERR_FILENO);
		close(in_fd[0]);
		close(out_fd[1]);
		execvp(argv[0], (char *const *)argv);
		_exit(127);
	}

	/* Parent: write input to child's stdin, then read output */
	close(in_fd[0]);
	close(out_fd[1]);

	/* Write all input (small payloads — single write is fine) */
	if (input && input_len > 0) {
		const char *p = input;
		size_t remain = input_len;
		while (remain > 0) {
			ssize_t w = write(in_fd[1], p, remain);
			if (w < 0) {
				if (errno == EINTR) continue;
				break;
			}
			p += w;
			remain -= (size_t)w;
		}
	}
	close(in_fd[1]);

	/* Read all output */
	size_t bufsz = 4096, used = 0;
	char *buf = malloc(bufsz);
	if (!buf) { close(out_fd[0]); waitpid(pid, NULL, 0); return NULL; }

	ssize_t n;
	char tmp[1024];
	while ((n = read(out_fd[0], tmp, sizeof(tmp))) > 0) {
		while (used + (size_t)n + 1 > bufsz) {
			bufsz *= 2;
			char *nb = realloc(buf, bufsz);
			if (!nb) { free(buf); close(out_fd[0]); waitpid(pid, NULL, 0); return NULL; }
			buf = nb;
		}
		memcpy(buf + used, tmp, (size_t)n);
		used += (size_t)n;
	}
	buf[used] = '\0';
	close(out_fd[0]);

	int wstatus;
	waitpid(pid, &wstatus, 0);
	if (exit_code)
		*exit_code = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;

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

/* ── Pre-replay flush functions ─────────────────────────────────────────
 *
 * Each function removes runtime state for one config type so that
 * replay starts from a clean baseline.  Called once per type before
 * iterating entries.
 *
 * IMPORTANT: BusyBox "ip route flush proto X" ignores the proto
 * filter (protocol matching is commented out in iproute.c).  We
 * must list routes and delete matching lines individually.
 * ────────────────────────────────────────────────────────────────────── */

void flush_static_routes(void)
{
	/* List all routes, delete only "proto static" lines.
	 * Preserves proto kernel connected routes.
	 *
	 * BusyBox "ip route flush proto static" ignores the proto
	 * filter (iproute.c has protocol matching commented out),
	 * so we parse output and delete individually.
	 *
	 * "ip route del" needs just the destination (first word),
	 * not the full display line. */
	const char *ls[] = {"ip", "route", "show", NULL};
	char *routes = safe_exec(ls);
	if (routes && routes[0]) {
		char *copy = strdup(routes);
		if (copy) {
			char *saveptr = NULL;
			for (char *line = strtok_r(copy, "\n", &saveptr);
			     line;
			     line = strtok_r(NULL, "\n", &saveptr)) {
				if (!strstr(line, "proto static"))
					continue;
				/* Extract destination (first token) */
				char dst[128];
				if (sscanf(line, "%127s", dst) != 1)
					continue;
				const char *del[] = {"ip", "route", "del",
						     dst, "proto", "static",
						     NULL};
				free(safe_exec(del));
			}
			free(copy);
		}
	}
	free(routes);
	fprintf(stderr, "[mgmtd] flush: static routes\n");
}

void flush_nat_rules(void)
{
	const char *f1[] = {"iptables", "-t", "nat",
			    "-F", "PREROUTING", NULL};
	free(safe_exec(f1));
	const char *f2[] = {"iptables", "-t", "nat",
			    "-F", "POSTROUTING", NULL};
	free(safe_exec(f2));
	fprintf(stderr, "[mgmtd] flush: NAT chains\n");
}

void flush_forward_chain(void)
{
	const char *ff[] = {"iptables", "-F", "FORWARD", NULL};
	const char *fe[] = {"iptables", "-A", "FORWARD",
			    "-m", "conntrack",
			    "--ctstate", "ESTABLISHED,RELATED",
			    "-j", "ACCEPT", NULL};
	ipt_exec(ff);
	ipt_exec(fe);
	fprintf(stderr, "[mgmtd] flush: FORWARD chain\n");
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

#define MGMTD_LOG    "/etc/stargazer/logs/mgmtd.log"
#define MGMTD_LOG_FB "/var/log/stargazer-mgmtd.log"

void mgmt_log(const char *level, const char *fmt, ...)
{
	/* INFO/WARN only printed to stderr when debug enabled */
	int is_debug = (strcmp(level, "INFO") == 0 ||
			strcmp(level, "WARN") == 0);

	char ts[64];
	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tm);

	char msg[1024];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	/* Always write to log file */
	const char *path = MGMTD_LOG;
	if (access("/etc/stargazer/logs", W_OK) != 0)
		path = MGMTD_LOG_FB;
	FILE *fp = fopen(path, "a");
	if (fp) {
		fprintf(fp, "%s %s: %s\n", ts, level, msg);
		fclose(fp);
	}

	/* Also print to stderr (debug-gated for INFO/WARN) */
	if (!is_debug || mgmtd_debug_enabled())
		fprintf(stderr, "%s [mgmtd] %s: %s\n", ts, level, msg);
}

int audit_log(const char *user, const char *event, const char *msg)
{
	const char *path = AUDIT_LOG;
	if (access("/etc/stargazer/logs", W_OK) != 0)
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

/* ── Log handlers ───────────────────────────────────────────────────────── */

/*
 * handle_log_audit — Read last N lines from audit log.
 * Payload: optional line count as decimal string (default 50, max 200).
 */
int handle_log_audit(int client_fd, const char *user,
		     const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'monitor' permission");
		return 0;
	}

	int count = 50;
	if (payload && payload[0]) {
		int n = atoi(payload);
		if (n > 0 && n <= 200)
			count = n;
		else if (n > 200)
			count = 200;
	}

	/* Try primary path first, fall back to secondary */
	FILE *fp = fopen(AUDIT_LOG, "r");
	if (!fp)
		fp = fopen(AUDIT_LOG_FB, "r");
	if (!fp) {
		send_ok(client_fd, NULL, "  No audit log entries.\n");
		return 0;
	}

	/* Read all lines, keep last 'count' in a circular buffer */
	char **lines = calloc((size_t)count, sizeof(char *));
	if (!lines) {
		fclose(fp);
		send_error(client_fd, SG_ERR_SYSTEM_FAIL, "Out of memory");
		return 0;
	}

	char linebuf[1024];
	unsigned int total = 0;
	while (fgets(linebuf, (int)sizeof(linebuf), fp)) {
		unsigned int idx = total % (unsigned int)count;
		free(lines[idx]);
		lines[idx] = strdup(linebuf);
		total++;
	}
	fclose(fp);

	if (total == 0) {
		free(lines);
		send_ok(client_fd, NULL, "  No audit log entries.\n");
		return 0;
	}

	/* Build response from circular buffer */
	size_t bufsz = SG_RESPONSE_MAX;
	char *buf = malloc(bufsz);
	if (!buf) {
		for (int i = 0; i < count; i++)
			free(lines[i]);
		free(lines);
		send_error(client_fd, SG_ERR_SYSTEM_FAIL, "Out of memory");
		return 0;
	}

	size_t used = 0;
	unsigned int ucount = (unsigned int)count;
	int nlines = total < ucount ? (int)total : count;
	int start = total < ucount ? 0 : (int)(total % ucount);
	for (int i = 0; i < nlines && used < bufsz - 1; i++) {
		int idx = (start + i) % count;
		if (lines[idx]) {
			size_t llen = strlen(lines[idx]);
			if (used + llen >= bufsz - 1)
				break;
			memcpy(buf + used, lines[idx], llen);
			used += llen;
		}
	}
	buf[used] = '\0';

	for (int i = 0; i < count; i++)
		free(lines[i]);
	free(lines);

	send_ok(client_fd, NULL, buf);
	free(buf);
	return 0;
}

/*
 * handle_log_mgmtd — Read last N lines from mgmtd daemon log.
 * Same pattern as handle_log_audit but reads from mgmtd.log.
 */
int handle_log_mgmtd(int client_fd, const char *user,
		     const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'monitor' permission");
		return 0;
	}

	int count = 50;
	if (payload && payload[0]) {
		int n = atoi(payload);
		if (n > 0 && n <= 200)
			count = n;
		else if (n > 200)
			count = 200;
	}

	FILE *fp = fopen(MGMTD_LOG, "r");
	if (!fp)
		fp = fopen(MGMTD_LOG_FB, "r");
	if (!fp) {
		send_ok(client_fd, NULL, "  No mgmtd log entries.\n");
		return 0;
	}

	char **lines = calloc((size_t)count, sizeof(char *));
	if (!lines) {
		fclose(fp);
		send_error(client_fd, SG_ERR_SYSTEM_FAIL, "Out of memory");
		return 0;
	}

	char linebuf[1024];
	unsigned int total = 0;
	while (fgets(linebuf, (int)sizeof(linebuf), fp)) {
		unsigned int idx = total % (unsigned int)count;
		free(lines[idx]);
		lines[idx] = strdup(linebuf);
		total++;
	}
	fclose(fp);

	if (total == 0) {
		free(lines);
		send_ok(client_fd, NULL, "  No mgmtd log entries.\n");
		return 0;
	}

	size_t bufsz = SG_RESPONSE_MAX;
	char *buf = malloc(bufsz);
	if (!buf) {
		for (int i = 0; i < count; i++)
			free(lines[i]);
		free(lines);
		send_error(client_fd, SG_ERR_SYSTEM_FAIL, "Out of memory");
		return 0;
	}

	size_t used = 0;
	unsigned int ucount = (unsigned int)count;
	int nlines = total < ucount ? (int)total : count;
	int start = total < ucount ? 0 : (int)(total % ucount);
	for (int i = 0; i < nlines && used < bufsz - 1; i++) {
		int idx = (start + i) % count;
		if (lines[idx]) {
			size_t llen = strlen(lines[idx]);
			if (used + llen >= bufsz - 1)
				break;
			memcpy(buf + used, lines[idx], llen);
			used += llen;
		}
	}
	buf[used] = '\0';

	for (int i = 0; i < count; i++)
		free(lines[i]);
	free(lines);

	send_ok(client_fd, NULL, buf);
	free(buf);
	return 0;
}

/*
 * handle_log_system — Read dmesg output (last N lines).
 * Payload: optional line count as decimal string (default 50, max 500).
 * Truncates to fit within SG_RESPONSE_MAX if needed.
 */
int handle_log_system(int client_fd, const char *user,
		      const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'monitor' permission");
		return 0;
	}

	int count = 50;
	if (payload && payload[0]) {
		int n = atoi(payload);
		if (n > 0 && n <= 500)
			count = n;
		else if (n > 500)
			count = 500;
	}

	const char *argv[] = {"dmesg", NULL};
	char *out = safe_exec(argv);
	if (!out || !out[0]) {
		free(out);
		send_ok(client_fd, NULL, "  No kernel log output.\n");
		return 0;
	}

	/* Keep only the last 'count' lines */
	size_t len = strlen(out);
	if (count > 0) {
		/* Walk backwards counting newlines */
		int nl_seen = 0;
		const char *p = out + len;
		while (p > out) {
			p--;
			if (*p == '\n') {
				nl_seen++;
				if (nl_seen == count + 1) {
					/* Advance past this newline */
					p++;
					size_t keep = (size_t)((out + len) - p);
					memmove(out, p, keep);
					out[keep] = '\0';
					len = keep;
					break;
				}
			}
		}
	}

	/* Truncate if still exceeds response limit */
	size_t max_len = SG_RESPONSE_MAX - 256; /* safely below protocol limit */
	if (len > max_len) {
		const char *start = out + len - max_len;
		const char *nl = strchr(start, '\n');
		if (nl)
			start = nl + 1;
		size_t keep = (size_t)((out + len) - start);
		memmove(out, start, keep);
		out[keep] = '\0';
	}

	send_ok(client_fd, NULL, out);
	free(out);
	return 0;
}

/*
 * handle_log_clear_audit — Truncate audit log file to 0 bytes.
 * Requires admin permission.
 */
int handle_log_clear_audit(int client_fd, const char *user,
			   const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload;
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'admin' permission");
		return 0;
	}

	/* Try primary path first, fall back to secondary */
	const char *path = AUDIT_LOG;
	if (truncate(path, 0) != 0) {
		if (errno == ENOENT) {
			path = AUDIT_LOG_FB;
			if (truncate(path, 0) != 0 && errno != ENOENT) {
				mgmt_log("ERROR", "log_clear_audit: truncate %s: %s",
					 path, strerror(errno));
				send_error(client_fd, SG_ERR_IO_FAIL,
					   "Failed to clear audit log");
				return 0;
			}
		} else {
			mgmt_log("ERROR", "log_clear_audit: truncate %s: %s",
				 path, strerror(errno));
			send_error(client_fd, SG_ERR_IO_FAIL,
				   "Failed to clear audit log");
			return 0;
		}
	}

	audit_log(user, "log_clear", "audit log cleared");
	send_ok(client_fd, NULL, "  Audit log cleared.\n");
	return 0;
}

/*
 * handle_diag_stargazer_log — Filter dmesg for stargazer init messages.
 * Shows [stargazer], sgdata, _sg_prepare, mmcblk0p related messages.
 */
int handle_diag_stargazer_log(int client_fd, const char *user,
			      const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload;
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'monitor' permission");
		return 0;
	}

	const char *argv[] = {
		"sh", "-c",
		"/bin/dmesg | /bin/grep -E '\\[stargazer\\]|sgdata|_sg_prepare|mmcblk0p'",
		NULL
	};
	char *out = safe_exec(argv);
	if (!out || !out[0]) {
		free(out);
		send_ok(client_fd, NULL, "  No stargazer messages found in kernel log.\n");
		return 0;
	}

	send_ok(client_fd, NULL, out);
	free(out);
	return 0;
}

/*
 * handle_diag_storage — Show storage device and mount status.
 * Reports partition devices, mount points, blkid info, and database status.
 */
int handle_diag_storage(int client_fd, const char *user,
		       const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload;
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'monitor' permission");
		return 0;
	}

	char *buf = malloc(SG_RESPONSE_MAX);
	if (!buf) {
		send_error(client_fd, SG_ERR_SYSTEM_FAIL, "Out of memory");
		return 0;
	}
	size_t pos = 0;

	/* Storage devices */
	pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
			"Storage devices:\n");
	const char *argv1[] = {"sh", "-c",
			       "/bin/ls -la /dev/mmcblk0p* 2>/dev/null || echo '  No eMMC partitions found'",
			       NULL};
	char *out1 = safe_exec(argv1);
	if (out1) {
		pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos, "%s", out1);
		free(out1);
	}

	/* Mount points */
	pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
			"\nStorage mount points:\n");
	const char *argv2[] = {"sh", "-c",
			       "/bin/mount | /bin/grep -E 'stargazer|mmcblk'",
			       NULL};
	char *out2 = safe_exec(argv2);
	if (out2 && out2[0]) {
		pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos, "%s", out2);
		free(out2);
	} else {
		pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
				"  No stargazer/mmcblk mounts found\n");
		free(out2);
	}

	/* Partition info */
	pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
			"\nPartition info:\n");
	const char *argv3[] = {"blkid", "/dev/mmcblk0p5", NULL};
	char *out3 = safe_exec(argv3);
	if (out3 && out3[0]) {
		pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
				"/dev/mmcblk0p5: %s", out3);
		free(out3);
	} else {
		pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
				"/dev/mmcblk0p5: not found or unformatted\n");
		free(out3);
	}

	const char *argv4[] = {"blkid", "/dev/mmcblk0p6", NULL};
	char *out4 = safe_exec(argv4);
	if (out4 && out4[0]) {
		pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
				"/dev/mmcblk0p6: %s", out4);
		free(out4);
	} else {
		pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
				"/dev/mmcblk0p6: not found or unformatted\n");
		free(out4);
	}

	/* Database status */
	pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
			"\nConfig database:\n");
	const char *argv5[] = {"sh", "-c",
			       "/bin/ls -lh /etc/stargazer/stargazer.db 2>/dev/null || echo '  Database not found'",
			       NULL};
	char *out5 = safe_exec(argv5);
	if (out5) {
		pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos, "%s", out5);
		free(out5);
	}

	send_ok(client_fd, NULL, buf);
	free(buf);
	return 0;
}

/*
 * handle_diag_dhcp_client — DHCP client status for all or one interface.
 *
 * Payload: empty (all DHCP interfaces) or "<iface>" (one interface).
 *
 * For each DHCP-mode interface reports:
 *   - Supervisor status (udhcpc.<iface>): PID, restart count
 *   - Lease state from /var/run/dhcp-status.<iface>
 *   - Current kernel-assigned IP from ip addr
 */
int handle_diag_dhcp_client(int client_fd, const char *user,
			     const char *payload,
			     const sg_request_hdr_t *hdr)
{
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'monitor' permission");
		return 0;
	}

	char *buf = malloc(SG_RESPONSE_MAX);
	if (!buf) {
		send_error(client_fd, SG_ERR_SYSTEM_FAIL, "Out of memory");
		return 0;
	}
	size_t pos = 0;

	/* Build list of DHCP-mode interfaces to inspect */
	char *iface_list[16];
	int   iface_count = 0;

	/* If caller specified one interface, use it directly */
	char req_iface[32] = {0};
	if (payload && payload[0] && sg_is_iface_name(payload)) {
		size_t plen = strlen(payload);
		if (plen >= sizeof(req_iface))
			plen = sizeof(req_iface) - 1;
		memcpy(req_iface, payload, plen);
	}

	if (req_iface[0]) {
		/* Single interface requested */
		char *mode = sg_db_get_val("system_interface", req_iface, "mode");
		if (mode && strcmp(mode, "dhcp") == 0)
			iface_list[iface_count++] = strdup(req_iface);
		else if (!mode)
			iface_list[iface_count++] = strdup(req_iface);
		free(mode);
	} else {
		/* All interfaces in DHCP mode */
		char *list = sg_db_list("system_interface");
		if (list) {
			char *p = list;
			while (*p && iface_count < 16) {
				char *nl = strchr(p, '\n');
				size_t len = nl ? (size_t)(nl - p) : strlen(p);
				if (len > 0 && len < 32) {
					char iname[32];
					memcpy(iname, p, len);
					iname[len] = '\0';
					char *mode = sg_db_get_val(
						"system_interface", iname,
						"mode");
					if (mode &&
					    strcmp(mode, "dhcp") == 0)
						iface_list[iface_count++] =
							strdup(iname);
					free(mode);
				}
				if (!nl)
					break;
				p = nl + 1;
			}
			free(list);
		}
	}

	if (iface_count == 0) {
		pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
				"No DHCP client interfaces configured.\n");
		send_ok(client_fd, NULL, buf);
		free(buf);
		return 0;
	}

	for (int i = 0; i < iface_count; i++) {
		const char *iface = iface_list[i];
		pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
				"Interface: %s\n", iface);

		/* ── Supervisor status ─────────────────────────────── */
		char sup_name[80];
		snprintf(sup_name, sizeof(sup_name), "udhcpc.%s", iface);
		pid_t upid = supervisor_get_pid(sup_name);
		int   ucnt = supervisor_get_restart_count(sup_name);

		if (upid > 0) {
			pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
					"  udhcpc:     running (pid %d,"
					" restarts %d)\n",
					(int)upid, ucnt);
		} else if (ucnt == -1) {
			pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
					"  udhcpc:     NOT running"
					" (not tracked — restart limit hit"
					" or never started)\n");
		} else {
			pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
					"  udhcpc:     NOT running"
					" (restarts %d)\n", ucnt);
		}

		/* ── Orphan check via /proc ─────────────────────────
		 * Catches processes not tracked by the supervisor
		 * (e.g., from a previous mgmtd instance). */
		{
			DIR *pd = opendir("/proc");
			if (pd) {
				struct dirent *pe;
				while ((pe = readdir(pd)) != NULL) {
					if (pe->d_name[0] < '1' ||
					    pe->d_name[0] > '9')
						continue;
					char cp[280];
					snprintf(cp, sizeof(cp),
						 "/proc/%s/cmdline",
						 pe->d_name);
					int cfd = open(cp, O_RDONLY);
					if (cfd < 0) continue;
					char cb[512];
					ssize_t cn = read(cfd, cb,
							  sizeof(cb) - 1);
					close(cfd);
					if (cn <= 0) continue;
					cb[cn] = '\0';
					if (!strstr(cb, "udhcpc")) continue;
					int fi = 0;
					for (ssize_t ci = 0; ci < cn; ) {
						const char *arg = cb + ci;
						size_t al = strlen(arg);
						if (strcmp(arg, "-i") == 0) {
							fi = 1;
						} else if (fi &&
							   strcmp(arg, iface)
							   == 0) {
							pid_t op =
							  (pid_t)atoi(
							    pe->d_name);
							pos += snprintf(
							  buf + pos,
							  SG_RESPONSE_MAX - pos,
							  "  orphan:     "
							  "pid %d (not"
							  " supervisor-"
							  "tracked)\n",
							  (int)op);
							break;
						} else {
							fi = 0;
						}
						ci += (ssize_t)al + 1;
						if (ci >= cn) break;
					}
				}
				closedir(pd);
			}
		}

		/* ── Lease state from status file ─────────────────── */
		char sf[64];
		snprintf(sf, sizeof(sf), "/var/run/dhcp-status.%s", iface);
		FILE *fp = fopen(sf, "r");
		if (fp) {
			char line[128];
			while (fgets(line, sizeof(line), fp)) {
				size_t llen = strlen(line);
				while (llen > 0 &&
				       (line[llen-1] == '\n' ||
					line[llen-1] == '\r'))
					line[--llen] = '\0';
				if (!line[0]) continue;
				pos += snprintf(buf + pos,
						SG_RESPONSE_MAX - pos,
						"  %s\n", line);
			}
			fclose(fp);
		} else {
			pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
					"  lease:      (no status file)\n");
		}

		/* ── Kernel-assigned IP ──────────────────────────── */
		const char *ip_argv[] = {
			"ip", "-4", "-o", "addr", "show", iface, NULL
		};
		char *ipout = safe_exec(ip_argv);
		if (ipout && ipout[0]) {
			char *inet_p = strstr(ipout, "inet ");
			if (inet_p) {
				inet_p += 5;
				char *sp = strchr(inet_p, ' ');
				if (sp) *sp = '\0';
				pos += snprintf(buf + pos,
						SG_RESPONSE_MAX - pos,
						"  ip:         %s\n",
						inet_p);
			} else {
				pos += snprintf(buf + pos,
						SG_RESPONSE_MAX - pos,
						"  ip:         (none)\n");
			}
		} else {
			pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
					"  ip:         (none)\n");
		}
		free(ipout);

		if (i + 1 < iface_count)
			pos += snprintf(buf + pos, SG_RESPONSE_MAX - pos,
					"\n");
		free(iface_list[i]);
	}

	send_ok(client_fd, NULL, buf);
	free(buf);
	return 0;
}

/* ── Signal handling ────────────────────────────────────────────────────── */

static void sig_handler(int sig)
{
	(void)sig;
	g_running = 0;
}

static void sigchld_handler(int sig)
{
	(void)sig;
	g_child_died = 1;
}

/* ── Supervisor: spawn / start / stop / reap ───────────────────────────── */

static child_entry_t *sup_find(const char *name)
{
	for (int i = 0; i < g_nchildren; i++)
		if (g_children[i].active && strcmp(g_children[i].name, name) == 0)
			return &g_children[i];
	return NULL;
}

static child_entry_t *sup_alloc(const char *name)
{
	/* Reuse existing slot */
	child_entry_t *e = sup_find(name);
	if (e) return e;
	/* Find free slot */
	for (int i = 0; i < SUP_MAX_CHILDREN; i++) {
		if (!g_children[i].active) {
			memset(&g_children[i], 0, sizeof(g_children[i]));
			g_children[i].active = 1;
			snprintf(g_children[i].name, sizeof(g_children[i].name),
				 "%s", name);
			if (i >= g_nchildren)
				g_nchildren = i + 1;
			return &g_children[i];
		}
	}
	return NULL;
}

static void sup_unregister(child_entry_t *e)
{
	e->active = 0;
	e->pid = 0;
	/* Shrink g_nchildren if this was the last slot */
	while (g_nchildren > 0 && !g_children[g_nchildren - 1].active)
		g_nchildren--;
}

/*
 * Deep-copy argv into entry's argv_store (packed NUL-separated strings).
 * Sets entry->argv[] pointers into the store.
 */
static int sup_copy_argv(child_entry_t *e, const char *const argv[])
{
	size_t off = 0;
	int argc = 0;
	for (int i = 0; argv[i] && i < SUP_ARGV_MAX - 1; i++) {
		size_t len = strlen(argv[i]) + 1;
		if (off + len > SUP_ARGV_STORE)
			return -1;
		memcpy(e->argv_store + off, argv[i], len);
		e->argv[argc++] = e->argv_store + off;
		off += len;
	}
	e->argv[argc] = NULL;
	return 0;
}

/*
 * Fork+exec a supervised child. Child: close all fds >= 3, reset signals
 * to SIG_DFL, setsid, redirect stdio to /dev/null.
 */
static int spawn_child(child_entry_t *e)
{
	pid_t pid = fork();
	if (pid < 0) {
		mgmt_log("ERROR", "supervisor: fork failed for %s: %s",
			 e->name, strerror(errno));
		return -1;
	}
	if (pid == 0) {
		/* Child process */
		/* Close all inherited fds (db, sockets, etc.) */
		long maxfd = sysconf(_SC_OPEN_MAX);
		if (maxfd < 0) maxfd = 1024;
		for (int fd = 3; fd < (int)maxfd; fd++)
			close(fd);

		/* Reset signals to default */
		signal(SIGCHLD, SIG_DFL);
		signal(SIGINT,  SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGPIPE, SIG_DFL);

		/* New session (detach from mgmtd's terminal) */
		setsid();

		/* Redirect stdio to /dev/null */
		int devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			dup2(devnull, STDIN_FILENO);
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			if (devnull > STDERR_FILENO)
				close(devnull);
		}

		execvp(e->argv[0], (char *const *)e->argv);
		_exit(127);
	}

	e->pid = pid;
	clock_gettime(CLOCK_MONOTONIC, &e->started_at);
	mgmt_log("INFO", "supervisor: started %s (pid %d)", e->name, (int)pid);
	return 0;
}

int supervisor_start(const char *name, const char *const argv[],
		     child_source_t source,
		     const char *cfg_type, const char *cfg_id,
		     const char *cfg_key, const char *cfg_val)
{
	/* If already running, stop it first */
	child_entry_t *e = sup_find(name);
	if (e && e->pid > 0) {
		supervisor_stop(name);
		e = NULL;
	}

	e = sup_alloc(name);
	if (!e) {
		mgmt_log("ERROR", "supervisor: no free slot for %s", name);
		return -1;
	}

	if (sup_copy_argv(e, argv) != 0) {
		mgmt_log("ERROR", "supervisor: argv too large for %s", name);
		sup_unregister(e);
		return -1;
	}

	e->source = source;
	e->restart_count = 0;
	e->restart_max = SUP_RESTART_MAX;

	if (cfg_type) snprintf(e->cfg_type, sizeof(e->cfg_type), "%s", cfg_type);
	if (cfg_id)   snprintf(e->cfg_id,   sizeof(e->cfg_id),   "%s", cfg_id);
	if (cfg_key)  snprintf(e->cfg_key,   sizeof(e->cfg_key),  "%s", cfg_key);
	if (cfg_val)  snprintf(e->cfg_val,   sizeof(e->cfg_val),  "%s", cfg_val);

	return spawn_child(e);
}

void supervisor_stop(const char *name)
{
	child_entry_t *e = sup_find(name);
	if (!e) return;

	/* Prevent auto-restart */
	e->restart_max = 0;

	if (e->pid > 0 && kill(e->pid, 0) == 0) {
		kill(e->pid, SIGTERM);
		/* Wait up to 3s (100ms polls) for exit */
		for (int i = 0; i < 30; i++) {
			usleep(100000);
			int wstatus;
			pid_t w = waitpid(e->pid, &wstatus, WNOHANG);
			if (w > 0 || (w < 0 && errno == ECHILD))
				goto reaped;
		}
		/* Still alive — SIGKILL */
		mgmt_log("WARN", "supervisor: %s (pid %d) did not exit, "
			 "sending SIGKILL", e->name, (int)e->pid);
		kill(e->pid, SIGKILL);
		waitpid(e->pid, NULL, 0);
	}

reaped:
	mgmt_log("INFO", "supervisor: stopped %s", e->name);
	sup_unregister(e);
}

pid_t supervisor_get_pid(const char *name)
{
	child_entry_t *e = sup_find(name);
	if (e && e->pid > 0)
		return e->pid;
	return 0;
}

int supervisor_get_restart_count(const char *name)
{
	child_entry_t *e = sup_find(name);
	return e ? e->restart_count : -1;
}

/*
 * Check if a dead child should be restarted.
 * For SRC_CONFIG: query DB to see if the config condition still holds.
 */
static int should_restart(child_entry_t *e)
{
	if (e->restart_max == 0)
		return 0;
	if (e->restart_count >= e->restart_max)
		return 0;

	if (e->source == SRC_CONFIG && e->cfg_type[0]) {
		char *val = sg_db_get_val(e->cfg_type, e->cfg_id, e->cfg_key);
		int match = (val && strcmp(val, e->cfg_val) == 0);
		free(val);
		if (!match) {
			mgmt_log("INFO", "supervisor: %s config changed "
				 "(%s.%s.%s != %s), not restarting",
				 e->name, e->cfg_type, e->cfg_id,
				 e->cfg_key, e->cfg_val);
			return 0;
		}
	}
	return 1;
}

/*
 * Reap dead supervised children by iterating the table and calling
 * waitpid() on each known PID. This avoids stealing safe_exec()'s
 * children which are reaped by their own waitpid(specific_pid) calls.
 *
 * For each dead child: log exit info, check restart eligibility,
 * apply backoff, and respawn.
 */
static void reap_children(void)
{
	for (int i = 0; i < g_nchildren; i++) {
		child_entry_t *e = &g_children[i];
		if (!e->active || e->pid <= 0)
			continue;

		int wstatus;
		pid_t w = waitpid(e->pid, &wstatus, WNOHANG);
		if (w <= 0)
			continue;  /* still alive or error */

		/* Log exit reason */
		if (WIFEXITED(wstatus)) {
			mgmt_log("WARN", "supervisor: %s (pid %d) exited "
				 "with code %d",
				 e->name, (int)e->pid, WEXITSTATUS(wstatus));
		} else if (WIFSIGNALED(wstatus)) {
			mgmt_log("WARN", "supervisor: %s (pid %d) killed "
				 "by signal %d",
				 e->name, (int)e->pid, WTERMSIG(wstatus));
		}

		e->pid = 0;

		/* If uptime >= 30s, reset restart counter (stable run) */
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		long uptime = now.tv_sec - e->started_at.tv_sec;
		if (uptime >= 30)
			e->restart_count = 0;

		if (!should_restart(e)) {
			mgmt_log("INFO", "supervisor: %s will not be "
				 "restarted (count=%d, max=%d)",
				 e->name, e->restart_count, e->restart_max);
			sup_unregister(e);
			continue;
		}

		e->restart_count++;
		/* Backoff: sleep min(restart_count, 5) seconds */
		int delay = e->restart_count;
		if (delay > 5) delay = 5;
		mgmt_log("INFO", "supervisor: restarting %s in %ds "
			 "(attempt %d/%d)",
			 e->name, delay, e->restart_count, e->restart_max);
		sleep(delay);
		spawn_child(e);
	}
}

/*
 * Graceful shutdown of all supervised children.
 * 1. SIGUSR2 to udhcpc children (triggers DHCP RELEASE)
 * 2. Sleep 0.5s for RELEASE to be sent
 * 3. SIGTERM all children with restart_max=0 (prevent restart)
 * 4. Wait up to 5s for all to exit
 * 5. SIGKILL any stragglers
 */
static void shutdown_children(void)
{
	/* Phase 1: SIGUSR2 to udhcpc children for DHCP RELEASE */
	for (int i = 0; i < g_nchildren; i++) {
		if (!g_children[i].active || g_children[i].pid <= 0)
			continue;
		if (strncmp(g_children[i].name, "udhcpc.", 7) == 0) {
			kill(g_children[i].pid, SIGUSR2);
			mgmt_log("INFO", "supervisor: sent SIGUSR2 (DHCP "
				 "RELEASE) to %s", g_children[i].name);
		}
	}
	usleep(500000);  /* 0.5s for RELEASE */

	/* Phase 2: SIGTERM all, prevent restarts */
	for (int i = 0; i < g_nchildren; i++) {
		if (!g_children[i].active || g_children[i].pid <= 0)
			continue;
		g_children[i].restart_max = 0;
		kill(g_children[i].pid, SIGTERM);
	}

	/* Phase 3: Wait up to 5s, reaping as they die */
	for (int round = 0; round < 50; round++) {
		int alive = 0;
		for (int i = 0; i < g_nchildren; i++) {
			if (!g_children[i].active || g_children[i].pid <= 0)
				continue;
			int wstatus;
			pid_t w = waitpid(g_children[i].pid, &wstatus, WNOHANG);
			if (w > 0 || (w < 0 && errno == ECHILD)) {
				g_children[i].pid = 0;
				sup_unregister(&g_children[i]);
			} else {
				alive++;
			}
		}
		if (alive == 0) break;
		usleep(100000);
	}

	/* Phase 4: SIGKILL stragglers */
	for (int i = 0; i < g_nchildren; i++) {
		if (!g_children[i].active || g_children[i].pid <= 0)
			continue;
		mgmt_log("WARN", "supervisor: SIGKILL %s (pid %d)",
			 g_children[i].name, (int)g_children[i].pid);
		kill(g_children[i].pid, SIGKILL);
		waitpid(g_children[i].pid, NULL, 0);
		sup_unregister(&g_children[i]);
	}
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

static sg_status_t g_last_response_status;

static void send_response(int fd, sg_status_t status, const char *extra,
			   const char *payload, uint32_t payload_len)
{
	g_last_response_status = status;
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
		mgmt_log("ERROR", "stream_exec: pipe() failed: %s",
			 strerror(errno));
		send_error(client_fd, SG_ERR_SYSTEM_FAIL,
			   "Internal error");
		return 0;
	}
	pid_t pid = fork();
	if (pid < 0) {
		mgmt_log("ERROR", "stream_exec: fork() failed: %s",
			 strerror(errno));
		close(pipefd[0]);
		close(pipefd[1]);
		send_error(client_fd, SG_ERR_SYSTEM_FAIL,
			   "Internal error");
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
		if (write(rfd, msg, strlen(msg)) < 0)
			(void)0; /* best-effort FIFO signal, ignore error */
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
static int mgmtd_first_boot_seed(void)
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

	/* ── DNS (always on) ─────────────────────────────────────── */
	if (sg_db_set("network_dns", "0",
		      "primary=1.1.1.1\n"
		      "secondary=8.8.8.8\n") != 0) goto fail;

	/* ── NTP (always on, default to pool.ntp.org) ────────────── */
	if (sg_db_set("system_ntp", "0",
		      "server=pool.ntp.org\n") != 0) goto fail;

	/* Built-in immutable objects (firewall_address:all,
	 * firewall_service:all, firewall_policy:1) are seeded by
	 * mgmtd_reconcile_config() Phase 2 — runs every boot,
	 * idempotent, also handles upgrade migration. */

	/* ── Default interfaces ──────────────────────────────────────── */
	/* lan3: LAN management interface — only seed if the hardware
	 * actually exists.  On non-BPI-R4 platforms (e.g. QEMU) lan3
	 * does not exist and mgmtd_sync_interfaces() will create entries
	 * for whatever NICs the platform actually has. */
	if (iface_exists("lan3")) {
		if (sg_db_set("system_interface", "lan3",
			      "mode=static\n"
			      "ip=" MGMT_DEFAULT_IP "\n"
			      "status=up\n"
			      "mtu=1500\n"
			      "allowaccess=ping http https\n") != 0) goto fail;
	} else {
		mgmt_log("INFO",
			 "first-boot: skipping lan3 seed (hardware not present)");
	}

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

/* ── Immutable check ───────────────────────────────────────────────────── */

/*
 * is_immutable — Check if a config entry is marked immutable.
 *
 * Reads the "immutable" key from the entry's existing DB data.
 * Immutable entries cannot be modified or deleted.
 *
 * 'existing' is the already-fetched DB data (avoids redundant read).
 * Returns 1 if immutable, 0 if not.
 */
static int is_immutable(const char *existing)
{
	if (!existing)
		return 0;
	char imm[VALBUFSZ];
	extract_val(existing, "immutable", imm, sizeof(imm));
	return strcmp(imm, "yes") == 0;
}

/* Forward declaration — defined further down with the IPC handlers. */
sg_status_t validate_cfg_data(const char *type, const char *data,
			      char *errbuf, size_t errsz);

/* ── Config reconciliation ──────────────────────────────────────────────── */

/*
 * Reconcile database state with the current firmware's config registry.
 * Runs on every boot.  Idempotent and direction-agnostic — handles
 * upgrade, downgrade, and same-version equally.
 *
 * Phase 1: Seed missing CFG_SINGLE types       (new types added)
 * Phase 2: Seed/repair built-in immutable      (force-overwrite on conflict)
 * Phase 3: Backfill missing keys               (new fields added)
 * Phase 4: Backfill sequence numbers           (firewall_policy, network_nat)
 * Phase 5: Purge stale types                   (types removed from registry)
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

	/* ── Phase 2: seed/repair built-in immutable objects ───────
	 *
	 * Idempotent.  For each built-in: if missing → create, if has
	 * immutable=yes → skip, otherwise force-overwrite (user data lost).
	 * This is the migration entry point for upgrades from firmware
	 * that pre-dates the reference object system. */
	{
		static const struct {
			const char *type;
			const char *id;
			const char *data;
		} builtins[] = {
			{ "firewall_address", "all",
			  "name=all\n"
			  "subnet=0.0.0.0/0\n"
			  "type=ipmask\n"
			  "builtin=yes\n"
			  "immutable=yes\n"
			  "comment=Match all addresses\n" },
			{ "firewall_service", "all",
			  "name=all\n"
			  "protocol=all\n"
			  "builtin=yes\n"
			  "immutable=yes\n"
			  "comment=Match all services\n" },
			{ "firewall_policy", "1",
			  "name=default-deny\n"
			  "srcintf=any\n"
			  "dstintf=any\n"
			  "srcaddr=all\n"
			  "dstaddr=all\n"
			  "action=deny\n"
			  "service=all\n"
			  "status=enable\n"
			  "sequence=1\n"
			  "builtin=yes\n"
			  "immutable=yes\n"
			  "comment=Default deny all traffic\n" },
			{ NULL, NULL, NULL }
		};

		for (int i = 0; builtins[i].type; i++) {
			const char *btype = builtins[i].type;
			const char *bid   = builtins[i].id;
			const char *bdata = builtins[i].data;

			/* Sanity check hardcoded data against the registry —
			 * graceful degradation: log error but still write.
			 * Catches developer bugs (typo'd field name, invalid
			 * enum value) without aborting boot. */
			{
				char verr[SG_EXTRA_MAX];
				if (validate_cfg_data(btype, bdata,
						      verr, sizeof(verr))
				    != SG_OK) {
					mgmt_log("ERROR",
						 "BUG: hardcoded built-in "
						 "%s:%s fails validation: %s",
						 btype, bid, verr);
				}
			}

			char *existing = sg_db_get(btype, bid);

			if (!existing) {
				/* Missing → create */
				if (sg_db_set(btype, bid, bdata) == 0) {
					mgmt_log("INFO",
						 "reconcile: created built-in "
						 "%s:%s", btype, bid);
					changes++;
				} else {
					mgmt_log("ERROR",
						 "reconcile: failed to create "
						 "built-in %s:%s", btype, bid);
				}
				continue;
			}

			/* Already immutable → skip */
			if (is_immutable(existing)) {
				free(existing);
				continue;
			}

			/* Conflict → force-overwrite */
			mgmt_log("WARN",
				 "reconcile: CONFLICT %s:%s exists without "
				 "immutable=yes — overwriting with built-in "
				 "defaults (user data lost)",
				 btype, bid);
			free(existing);

			if (sg_db_set(btype, bid, bdata) == 0) {
				mgmt_log("INFO",
					 "reconcile: overwrote %s:%s with "
					 "built-in defaults", btype, bid);
				char amsg[256];
				snprintf(amsg, sizeof(amsg),
					 "force-overwrite conflict %.64s:%.64s",
					 btype, bid);
				audit_log("__migration", "200", amsg);
				changes++;
			} else {
				mgmt_log("ERROR",
					 "reconcile: failed to overwrite %s:%s",
					 btype, bid);
			}
		}
	}

	/* ── Phase 3: backfill missing keys on existing entries ───── */

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

	/* ── Phase 4: backfill sequence numbers ────────────────────
	 *
	 * Folded from former mgmtd_backfill_sequences().  Assigns
	 * monotonically increasing sequence numbers to firewall_policy
	 * and network_nat entries that lack one. */
	{
		const char **seq_types = SEQ_ORDERABLE_TYPES;
		for (int t = 0; seq_types[t]; t++) {
			char *list = sg_db_list(seq_types[t]);
			if (!list)
				continue;
			int next_seq = 1;
			char *saveptr = NULL;
			for (char *tok = strtok_r(list, "\n", &saveptr);
			     tok;
			     tok = strtok_r(NULL, "\n", &saveptr)) {
				char *existing = sg_db_get_val(
					seq_types[t], tok, "sequence");
				if (!existing) {
					char val[16];
					snprintf(val, sizeof(val), "%d",
						 next_seq);
					sg_db_set_val(seq_types[t], tok,
						      "sequence", val);
					mgmt_log("INFO",
						 "reconcile: backfilled "
						 "%s:%s sequence=%d",
						 seq_types[t], tok, next_seq);
					next_seq++;
					changes++;
				} else {
					int cur = atoi(existing);
					if (cur >= next_seq)
						next_seq = cur + 1;
					free(existing);
				}
			}
			free(list);
		}
	}

	/* ── Phase 5: purge stale types ───────────────────────────── */

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
						fprintf(stderr, "[mgmtd] reconcile: PURGING stale type '%s'\n", tp);
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
 * Return 1 if the interface has any netdev upper layers (DSA master,
 * bridge master, bonding master, etc.).  These are system-managed
 * interfaces that users should not configure directly.
 *
 * Linux exposes upper devices as "upper_<name>" symlinks under
 * /sys/class/net/<iface>/.  A single match is sufficient.
 */
static int read_iface_has_upper(const char *name)
{
	char path[48];
	snprintf(path, sizeof(path), "/sys/class/net/%.15s", name);
	DIR *d = opendir(path);
	if (!d)
		return 0;
	struct dirent *ent;
	int found = 0;
	while ((ent = readdir(d)) != NULL) {
		if (strncmp(ent->d_name, "upper_", 6) == 0) {
			found = 1;
			break;
		}
	}
	closedir(d);
	return found;
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
static void mgmtd_sync_interfaces(int is_first_boot)
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

	/* On first boot, pick management and WAN NICs:
	 * - "lan3" gets static management IP (fallback: first NIC)
	 * - "wan" gets DHCP mode for upstream connectivity */
	int mgmt_idx = 0;
	int wan_idx = -1;
	if (is_first_boot) {
		for (int i = 0; i < nic_count; i++) {
			if (strcmp(nics[i], "lan3") == 0)
				mgmt_idx = i;
			else if (strcmp(nics[i], "wan") == 0)
				wan_idx = i;
		}
	}

	/* 4. Create/protect entries for each discovered NIC */
	for (int i = 0; i < nic_count; i++) {
		int is_dsa_master = read_iface_has_upper(nics[i]);
		char *existing = sg_db_get("system_interface", nics[i]);

		if (!existing) {
			/* New NIC — create entry with current MTU from driver */
			int cur_mtu = read_iface_mtu(nics[i]);
			if (cur_mtu <= 0)
				cur_mtu = 1500;

			char seed[256];
			if (is_dsa_master) {
				/* DSA/bridge master — kept up by mgmtd but hidden
				 * from the user CLI.  No IP, no DHCP client. */
				snprintf(seed, sizeof(seed),
					 "mode=static\n"
					 "ip=0.0.0.0/0\n"
					 "status=up\n"
					 "mtu=%d\n"
					 "builtin=yes\n"
					 "system=yes\n", cur_mtu);
				sg_db_set("system_interface", nics[i], seed);
				mgmt_log("INFO",
					 "interface %s: created (DSA master, mtu %d, system)",
					 nics[i], cur_mtu);
			} else if (is_first_boot && i == mgmt_idx) {
				snprintf(seed, sizeof(seed),
					 "mode=static\n"
					 "ip=" MGMT_DEFAULT_IP "\n"
					 "allowaccess=ping\n"
					 "status=up\n"
					 "mtu=%d\n"
					 "builtin=yes\n", cur_mtu);
				sg_db_set("system_interface", nics[i], seed);
				mgmt_log("INFO",
					 "interface %s: created (management IP " MGMT_DEFAULT_IP ", mtu %d)",
					 nics[i], cur_mtu);
			} else if (is_first_boot && i == wan_idx) {
				snprintf(seed, sizeof(seed),
					 "mode=dhcp\n"
					 "allowaccess=ping\n"
					 "status=up\n"
					 "mtu=%d\n"
					 "builtin=yes\n", cur_mtu);
				sg_db_set("system_interface", nics[i], seed);
				mgmt_log("INFO",
					 "interface %s: created (dhcp, mtu %d)",
					 nics[i], cur_mtu);
			} else {
				/* Normal boot new NIC, or first-boot non-wan/non-mgmt NIC.
				 * Seed with static + sentinel 0.0.0.0/0 so the entry has
				 * a valid mode and ip immediately without waiting for
				 * reconcile to backfill defaults on the next boot. */
				snprintf(seed, sizeof(seed),
					 "mode=static\n"
					 "ip=0.0.0.0/0\n"
					 "allowaccess=ping\n"
					 "status=up\n"
					 "mtu=%d\n"
					 "builtin=yes\n", cur_mtu);
				sg_db_set("system_interface", nics[i], seed);
				mgmt_log("INFO", "interface %s: created (static, mtu %d)",
					 nics[i], cur_mtu);
			}
		} else {
			/* Existing NIC — ensure builtin=yes and keep system=yes
			 * consistent with current hardware topology. */
			sg_db_set_val("system_interface", nics[i],
				      "builtin", "yes");
			if (is_dsa_master)
				sg_db_set_val("system_interface", nics[i],
					      "system", "yes");
			free(existing);
			mgmt_log("INFO", "interface %s: protected (builtin%s)",
				 nics[i], is_dsa_master ? ", system" : "");
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
		/* Skip system-managed interfaces (DSA master, etc.) */
		char *sys_flag = sg_db_get_val("system_interface", nics[i],
					       "system");
		int is_sys = sys_flag && strcmp(sys_flag, "yes") == 0;
		free(sys_flag);
		if (is_sys) {
			free(nics[i]);
			continue;
		}

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
		if (strcmp(state, "lowerlayerdown") == 0)
			snprintf(state, sizeof(state), "down");

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
 * Initialise base INPUT chain rules at boot.
 * Must run BEFORE mgmtd_replay_config() so that per-interface SG_IN_*
 * jump rules are appended after these foundational rules.
 *
 * INPUT policy DROP is set at kernel level (iptable_filter.c input_drop=1)
 * so there is no window of ACCEPT policy between kernel boot and mgmtd start.
 *
 * Result:
 *   INPUT policy DROP   (kernel)
 *   1. -i lo -j ACCEPT                 (loopback / self-ping)
 *   2. -m conntrack --ctstate EST,REL   (return traffic)
 *   ... per-interface jumps added later by apply_allowaccess()
 */
static void mgmtd_init_firewall(void)
{
	/* Verify iptables is installed before touching any rules */
	if (!ipt_available()) {
		mgmt_log("ERROR",
			 "iptables binary not found — firewall NOT configured!");
		return;
	}

	/* INPUT policy DROP is set by kernel (iptable_filter input_drop=1).
	 * No need to set it here — the chain is DROP from the instant the
	 * filter table is created, before any userspace process runs. */

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
		mgmt_log("INFO", "INPUT chain: policy DROP (kernel), "
			 "lo ACCEPT, ESTABLISHED/RELATED ACCEPT");

	/* FORWARD chain: policy DROP, flush, allow return traffic.
	 * Firewall policies are replayed on top of this foundation. */
	{
		const char *fwd_p[]   = {"iptables", "-P", "FORWARD", "DROP", NULL};
		const char *fwd_f[]   = {"iptables", "-F", "FORWARD", NULL};
		const char *fwd_est[] = {"iptables", "-A", "FORWARD",
					 "-m", "conntrack",
					 "--ctstate", "ESTABLISHED,RELATED",
					 "-j", "ACCEPT", NULL};
		if (ipt_exec(fwd_p) != 0)
			mgmt_log("ERROR",
				 "CRITICAL: FORWARD policy DROP failed");
		ipt_exec(fwd_f);
		if (ipt_exec(fwd_est) != 0)
			mgmt_log("ERROR",
				 "FORWARD ESTABLISHED/RELATED rule failed");
		else
			mgmt_log("INFO", "FORWARD chain: policy DROP, "
				 "ESTABLISHED/RELATED ACCEPT");
	}

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
		if (strcmp(key, "builtin") == 0 ||
		    strcmp(key, "immutable") == 0 ||
		    strcmp(key, "password-hash") == 0) {
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
 *
 * Sequence number backfill is done by mgmtd_reconcile_config()
 * Phase 4 which runs before this function in main().
 */
static int g_replaying = 1;

static void mgmtd_replay_config(void)
{
	char result[512];

	/* Single config types (id="0").
	 * Order: settings first, then services that depend on them. */
	static const char *single_types[] = {
		"system_settings",        /* hostname, ip-forward — always first */
		"system_password-policy", /* load before admin auth checks */
		"network_dns",            /* write /etc/resolv.conf */
		"system_ntp",             /* write /etc/ntp.conf */
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
			if (rc == SG_OK)
				fprintf(stderr, "[mgmtd] replay %s: %s\n",
					single_types[i], result);
			else
				fprintf(stderr, "[mgmtd] replay FAIL %s: %s\n",
					single_types[i], result);
			free(data);
		}
	}

	/* Table config types (multiple entries).
	 * Order: profiles → admins → interfaces → routing/nat → dhcp → firewall */
	static const char *table_types[] = {
		"system_admin-profile",  /* must be before system_admin */
		"system_admin",          /* depends on profiles */
		"system_interface",      /* IP + allowaccess INPUT rules */
		"network_route_static",  /* flush proto static first */
		"firewall_address",      /* data-only: before firewall/NAT rebuild */
		"firewall_service",      /* data-only: before firewall/NAT rebuild */
		"network_nat",
		"network_dhcp-server",
		"firewall_policy",       /* FORWARD rules — flush chain first */
		NULL
	};
	for (int i = 0; table_types[i]; i++) {
		/* Firewall/NAT: atomic rebuild reads all entries from DB
		 * and generates the complete chain in one shot.  No need
		 * for per-entry loop, flush, or ordered list. */
		if (strcmp(table_types[i], "firewall_policy") == 0) {
			char rb_result[512];
			sg_status_t rc = rebuild_forward_chain(
				rb_result, sizeof(rb_result));
			fprintf(stderr, "[mgmtd] replay firewall_policy: %s%s\n",
				rc == SG_OK ? "" : "FAIL ",
				rb_result);
			continue;
		}
		if (strcmp(table_types[i], "network_nat") == 0) {
			char rb_result[512];
			sg_status_t rc = rebuild_nat_chains(
				rb_result, sizeof(rb_result));
			fprintf(stderr, "[mgmtd] replay network_nat: %s%s\n",
				rc == SG_OK ? "" : "FAIL ",
				rb_result);
			continue;
		}

		/* Pre-flush: clean runtime state before replaying each type.
		 * Centralized flush functions in mgmtd_apply.h — each one
		 * only removes state owned by its config type. */
		if (strcmp(table_types[i], "network_route_static") == 0)
			flush_static_routes();

		char *list = sg_db_list(table_types[i]);
		if (!list) {
			fprintf(stderr, "[mgmtd] replay %s: no entries in DB\n",
				table_types[i]);
			continue;
		}
		/* Log entry count for diagnostics */
		{
			int cnt = 0;
			const char *cp = list;
			while (*cp) {
				if (*cp == '\n') cnt++;
				cp++;
			}
			fprintf(stderr, "[mgmtd] replay %s: found %d entries\n",
				table_types[i], cnt);
		}

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
				/* Always log replay results — boot failures
				 * must be visible without debug mode.
				 * "ERROR" bypasses the debug-only filter. */
				if (rc == SG_OK)
					fprintf(stderr, "[mgmtd] replay %s:%s: %s\n",
						table_types[i], id, result);
				else
					fprintf(stderr, "[mgmtd] replay FAIL %s:%s: %s\n",
						table_types[i], id, result);
				free(data);
			}

			p += len;
			if (eol) p++;
		}
		free(list);
	}

	/* Enable ref existence checks now that all config is loaded */
	g_replaying = 0;
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

	/* network_nat and firewall_policy use rebuild_*_chain()
	 * directly from the CFG_SET fast-path — not apply_config(). */

	if (strcmp(type, "network_dns") == 0)
		return apply_dns(id, data, result, rsize);

	if (strcmp(type, "network_dhcp-server") == 0)
		return apply_dhcp(id, data, result, rsize);

	if (strcmp(type, "system_ntp") == 0)
		return apply_ntp(id, data, result, rsize);

	/* ── Inline handlers (tightly coupled to monolith statics) ───── */
	if (strcmp(type, "system_admin-profile") == 0) {
		char perms[VALBUFSZ];
		extract_val(data, "permissions", perms, sizeof(perms));
		if (perms[0] == '\0') {
			snprintf(result, rsize, "'permissions' not set.");
			return SG_ERR_MISSING_ARG;
		}
		snprintf(result, rsize, "Profile '%s' loaded (perms: %s).", id, perms);

		/* Session purge deferred to CFG_SET cascade — apply_config()
		 * is called before save, so purging here would kill the tag
		 * before the save can complete. */
		return SG_OK;
	}

	if (strcmp(type, "system_admin") == 0) {
		char profile[VALBUFSZ], password[VALBUFSZ], enforce[VALBUFSZ];
		char enforce_policy[VALBUFSZ], builtin_flag[VALBUFSZ];
		char pw_hash[SG_PAYLOAD_MAX];
		extract_val(data, "profile", profile, sizeof(profile));
		extract_val(data, "password", password, sizeof(password));
		extract_val(data, "enforce-change-password", enforce, sizeof(enforce));
		extract_val(data, "enforce-password-policy", enforce_policy,
			    sizeof(enforce_policy));
		extract_val(data, "builtin", builtin_flag, sizeof(builtin_flag));
		extract_val(data, "password-hash", pw_hash, sizeof(pw_hash));

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

		/* Create Linux user if needed.
		 * Builtin accounts (first-boot admin) get an empty password
		 * so the first-login flow can require a change.
		 * Non-builtin accounts are locked until a password is set. */
		int is_builtin = (strcmp(builtin_flag, "yes") == 0);
		if (create_system_user(id, "/sbin/stargazer-cli", is_builtin) != 0) {
			snprintf(result, rsize, "Failed to create user '%s'.", id);
			return SG_ERR_SYSTEM_FAIL;
		}

		/* Replay: restore shadow from DB hash if present.
		 * This runs on every reboot so the shadow file is always
		 * consistent with the database. */
		if (pw_hash[0]) {
			if (set_shadow_hash(id, pw_hash) != 0)
				mgmt_log("WARN",
					 "apply system_admin %s: "
					 "set_shadow_hash failed", id);
		}

		/* Handle plaintext password from web UI or CFG_APPLY payload.
		 * set_password() also persists the hash to DB. */
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
		}

		/* Non-builtin users without a password are left locked.
		 * create_system_user() locks the shadow entry, so the
		 * account is safe until a password is explicitly set via
		 * ADMIN_SET_PW.  logind enforces password verification
		 * at login time.  Blocking CFG_SET here would prevent
		 * the normal ADMIN_CREATE → CFG_SET update workflow. */

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

	/* Service accounts: __webd gets monitor permission (read config only) */
	if (strcmp(username, "__webd") == 0)
		return "monitor";

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
 * Check if user has the per-type permission for a config type.
 * Returns 1 if allowed, 0 if denied.
 * "admin" perm types require "admin".
 * "configure" perm types require "configure" OR "admin".
 */
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

/* ── Usage cascade — re-apply entries that reference a changed object ── */

/*
 * usage_cascade — When object type:id changes, find all config entries
 * that reference it and re-apply them.
 *
 * Uses the same infrastructure as check_references():
 *   sg_reg_find_referencing() → which fields reference this type
 *   sg_db_find_referencing()  → which entries have this value
 *
 * No separate index needed — DB is the source of truth.
 *
 * Types that use atomic chain rebuild (firewall_policy, network_nat)
 * are not re-applied individually — instead, the rebuild is triggered
 * once at the end if any dependent of that type was found.
 *
 * Writes warning message to warn_out if any re-apply fails.
 * Logs each re-apply to audit log with user="__cascade".
 */
static void usage_cascade(const char *type, const char *id,
			  char *warn_out, size_t warn_sz)
{
	if (warn_out && warn_sz > 0)
		warn_out[0] = '\0';

	sg_ref_entry_t refs[16];
	int nrefs = sg_reg_find_referencing(type, refs, 16);
	int need_fw_rebuild = 0;
	int need_nat_rebuild = 0;

	for (int i = 0; i < nrefs; i++) {
		char *found = sg_db_find_referencing(refs[i].type,
						     refs[i].key, id);
		if (!found)
			continue;

		/* found = "type:id1\ntype:id2\n..." */
		char *saveptr = NULL;
		for (char *entry = strtok_r(found, "\n", &saveptr);
		     entry;
		     entry = strtok_r(NULL, "\n", &saveptr)) {

			/* Parse "type:id" */
			char etype[256], eid[256];
			sg_db_parse_section(entry, etype, sizeof(etype),
					    eid, sizeof(eid));

			/* Atomic-rebuild types: mark for rebuild at end */
			if (strcmp(etype, "firewall_policy") == 0) {
				need_fw_rebuild = 1;
				continue;
			}
			if (strcmp(etype, "network_nat") == 0) {
				need_nat_rebuild = 1;
				continue;
			}

			/* Per-entry re-apply */
			char *data = sg_db_get(etype, eid);
			if (!data)
				continue;

			char result[512];
			sg_status_t rc = apply_config(etype, eid, data,
						      result, sizeof(result));
			free(data);

			/* Audit log each cascade re-apply */
			char amsg[512];
			snprintf(amsg, sizeof(amsg),
				 "%s %.64s:%.64s (cascade from %.64s:%.64s): %.128s",
				 rc == SG_OK ? "OK" : "FAILED",
				 etype, eid, type, id, result);
			audit_log("__cascade", "200", amsg);

			/* Accumulate warnings for failed re-applies */
			if (rc != SG_OK && warn_out && warn_sz > 0) {
				size_t cur = strlen(warn_out);
				if (cur > 0 && cur + 2 < warn_sz) {
					warn_out[cur++] = ';';
					warn_out[cur++] = ' ';
					warn_out[cur] = '\0';
				}
				snprintf(warn_out + cur, warn_sz - cur,
					 "%.64s:%.64s re-apply failed: %.128s",
					 etype, eid, result);
			}
		}
		free(found);
	}

	/* Atomic rebuilds — once at the end if any dependent was found */
	if (need_fw_rebuild) {
		char rb[512];
		rebuild_forward_chain(rb, sizeof(rb));
		char amsg[512];
		snprintf(amsg, sizeof(amsg),
			 "cascade from %.64s:%.64s: %.256s", type, id, rb);
		audit_log("__cascade", "200", amsg);
	}
	if (need_nat_rebuild) {
		char rb[512];
		rebuild_nat_chains(rb, sizeof(rb));
		char amsg[512];
		snprintf(amsg, sizeof(amsg),
			 "cascade from %.64s:%.64s: %.256s", type, id, rb);
		audit_log("__cascade", "200", amsg);
	}
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
/*
 * validate_cfg_fields — Validate each key=value line in the payload.
 *
 * Checks key names are registered, value formats match the schema.
 * Does NOT check that all required keys are present — use
 * validate_cfg_data() for that (full payload only).
 *
 * Safe for partial payloads (e.g. CFG_APPLY with only changed fields).
 */
static sg_status_t validate_cfg_fields(const char *type, const char *data,
				       char *errbuf, size_t errsz)
{
	errbuf[0] = '\0';

	const char *p = data;
	while (*p) {
		if (*p == '\n') { p++; continue; }

		const char *eol = strchr(p, '\n');
		size_t llen = eol ? (size_t)(eol - p) : strlen(p);

		const char *eq = memchr(p, '=', llen);
		if (eq) {
			size_t klen = (size_t)(eq - p);
			if (klen >= 64) {
				snprintf(errbuf, errsz, "Key name too long");
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

			/* Skip internal/storage-only keys that are never
			 * user-settable and have no entry in field_table.
			 * Note: "name" is NOT skipped here — for types like
			 * firewall_address it IS a registered safe-id field
			 * and must be validated like any other. */
			if (strcmp(key, "builtin") == 0 ||
			    strcmp(key, "immutable") == 0 ||
			    strcmp(key, "password-hash") == 0 ||
			    strcmp(key, "id") == 0) {
				p += llen;
				if (eol) p++;
				continue;
			}

			if (!sg_reg_is_valid_key(type, key)) {
				snprintf(errbuf, errsz,
					 "Unknown key '%s'", key);
				return SG_ERR_INVALID_ARG;
			}

			/* Skip validation for optional fields with empty
			 * values — empty means "not set" / "clear field".
			 * e.g. interface ip= is valid when mode=dhcp. */
			if (val[0] == '\0' && sg_reg_is_optional(type, key))
				goto next_line;

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

	next_line:
		p += llen;
		if (eol) p++;
	}

	return SG_OK;
}

/*
 * validate_cfg_data — Full validation: field formats + required keys.
 *
 * Only use for full payloads (CFG_SET) where all required keys must
 * be present.  For partial payloads (CFG_APPLY), use validate_cfg_fields().
 */
sg_status_t validate_cfg_data(const char *type, const char *data,
			      char *errbuf, size_t errsz)
{
	/* Part 1: validate each field */
	sg_status_t st = validate_cfg_fields(type, data, errbuf, errsz);
	if (st != SG_OK) return st;

	/* Part 2: check required keys are present */
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

			/* Entry identity keys validated via entry ID — skip */
			if (strcmp(tok, "name") == 0 ||
			    strcmp(tok, "id") == 0) {
				*end = saved;
				tok = end;
				continue;
			}

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

/* ── Server-side reference existence check ─────────────────────────────── */

/*
 * validate_ref_existence — Verify that ref field values point to
 * existing objects in the database.
 *
 * For each key=value in data, if the field kind is a reference type
 * (ref:, ref-or:, ref-iface:, ref-iface-or:, ref-or-cidr:), verify
 * the referenced entry exists via sg_db_get().  Hardcoded options
 * (e.g. interface "any") are accepted without lookup.
 *
 * This runs inside mgmtd — direct DB access, no IPC needed.
 *
 * Returns SG_OK on success, or SG_ERR_NOT_FOUND with message.
 */
static sg_status_t validate_ref_existence(const char *type,
					  const char *data,
					  char *errbuf, size_t errsz)
{
	if (g_replaying)
		return SG_OK;

	const char *p = data;
	while (*p) {
		if (*p == '\n') { p++; continue; }

		const char *eol = strchr(p, '\n');
		size_t llen = eol ? (size_t)(eol - p) : strlen(p);
		const char *eq = memchr(p, '=', llen);
		if (!eq)
			goto next_ref;

		size_t klen = (size_t)(eq - p);
		if (klen == 0 || klen >= 64)
			goto next_ref;

		char key[64];
		memcpy(key, p, klen);
		key[klen] = '\0';

		const char *vstart = eq + 1;
		size_t vlen = llen - klen - 1;
		if (vlen == 0 || vlen >= VALBUFSZ)
			goto next_ref;

		char val[VALBUFSZ];
		memcpy(val, vstart, vlen);
		val[vlen] = '\0';

		/* Skip internal-only keys */
		if (strcmp(key, "builtin") == 0 ||
		    strcmp(key, "immutable") == 0 ||
		    strcmp(key, "password-hash") == 0 ||
		    strcmp(key, "id") == 0)
			goto next_ref;

		/* Get field kind from registry */
		const char *kind = sg_reg_value_kind(type, key);
		if (!kind)
			goto next_ref;

		/* Parse ref kind — skip if not a reference field */
		char ref_type[64], opts[64];
		if (!sg_parse_ref_kind(kind, ref_type, sizeof(ref_type),
				       opts, sizeof(opts)))
			goto next_ref;

		/* Hardcoded options (e.g. interface "any") are always valid */
		if (opts[0] && sg_match_csv_option(opts, val))
			goto next_ref;

		/* For ref-or-cidr: raw CIDR values are valid without lookup */
		if (strncmp(kind, "ref-or-cidr:", 12) == 0 && sg_is_cidr(val))
			goto next_ref;

		/* Verify referenced entry exists in DB */
		char *entry = sg_db_get(ref_type, val);
		if (!entry) {
			snprintf(errbuf, errsz,
				 "'%.32s': %.32s '%.32s' does not exist",
				 key, ref_type, val);
			return SG_ERR_NOT_FOUND;
		}
		free(entry);

	next_ref:
		p += llen;
		if (eol) p++;
	}

	return SG_OK;
}

/* ── Audit detail extraction ─────────────────────────────────────────── */

static void audit_detail(const char *payload, uint32_t len,
			 char *out, size_t outsz)
{
	if (!payload || !len) { out[0] = '\0'; return; }
	const char *nl = memchr(payload, '\n', len);
	size_t n = nl ? (size_t)(nl - payload) : len;
	if (n >= outsz) n = outsz - 1;
	memcpy(out, payload, n);
	out[n] = '\0';
}

/* ── Supervisor test handler ────────────────────────────────────────────── */

/*
 * IPC handler for SG_CMD_SUPERVISOR_TEST — used by selftest suite.
 * Payload format: "op\narg1\narg2\n..."
 * Ops: start, stop, query, start_config, set_config_val
 */
static int handle_supervisor_test(int client_fd, const char *user,
				  const char *payload,
				  const sg_request_hdr_t *hdr)
{
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'admin' permission");
		return 0;
	}

	if (!payload || !payload[0]) {
		send_error(client_fd, SG_ERR_MISSING_ARG, "No operation");
		return 0;
	}

	/* Parse op and args from newline-separated payload */
	char buf[1024];
	snprintf(buf, sizeof(buf), "%s", payload);
	char *lines[16];
	int nlines = 0;
	char *sp = NULL;
	for (char *tok = strtok_r(buf, "\n", &sp);
	     tok && nlines < 16;
	     tok = strtok_r(NULL, "\n", &sp))
		lines[nlines++] = tok;

	const char *op = lines[0];

	if (strcmp(op, "start") == 0 && nlines >= 2) {
		/* start\nname\narg0\narg1\n... */
		const char *name = lines[1];
		const char *argv[SUP_ARGV_MAX];
		int argc = 0;
		for (int i = 2; i < nlines && argc < SUP_ARGV_MAX - 1; i++)
			argv[argc++] = lines[i];
		argv[argc] = NULL;
		if (argc == 0) {
			send_error(client_fd, SG_ERR_MISSING_ARG,
				   "No argv for start");
			return 0;
		}
		int rc = supervisor_start(name, argv, SRC_ALWAYS,
					  NULL, NULL, NULL, NULL);
		if (rc == 0)
			send_ok(client_fd, NULL, NULL);
		else
			send_error(client_fd, SG_ERR_SYSTEM_FAIL,
				   "supervisor_start failed");
		return 0;
	}

	if (strcmp(op, "start_config") == 0 && nlines >= 3) {
		/* start_config\nname\narg0[\narg1...]\n---\ncfg_type\ncfg_id\ncfg_key\ncfg_val
		 * The "---" separator divides argv from config params. */
		const char *name = lines[1];
		const char *argv[SUP_ARGV_MAX];
		int argc = 0;
		int sep = -1;
		for (int i = 2; i < nlines; i++) {
			if (strcmp(lines[i], "---") == 0) {
				sep = i;
				break;
			}
			if (argc < SUP_ARGV_MAX - 1)
				argv[argc++] = lines[i];
		}
		argv[argc] = NULL;
		if (argc == 0 || sep < 0 || sep + 4 >= nlines) {
			send_error(client_fd, SG_ERR_MISSING_ARG,
				   "Bad start_config format");
			return 0;
		}
		int rc = supervisor_start(name, argv, SRC_CONFIG,
					  lines[sep + 1], lines[sep + 2],
					  lines[sep + 3], lines[sep + 4]);
		if (rc == 0)
			send_ok(client_fd, NULL, NULL);
		else
			send_error(client_fd, SG_ERR_SYSTEM_FAIL,
				   "supervisor_start failed");
		return 0;
	}

	if (strcmp(op, "stop") == 0 && nlines >= 2) {
		supervisor_stop(lines[1]);
		send_ok(client_fd, NULL, NULL);
		return 0;
	}

	if (strcmp(op, "kill") == 0 && nlines >= 2) {
		/* Send SIGKILL to a supervised child (for testing) */
		child_entry_t *e = sup_find(lines[1]);
		if (!e || e->pid <= 0) {
			send_error(client_fd, SG_ERR_NOT_FOUND,
				   "Not in supervisor table");
			return 0;
		}
		kill(e->pid, SIGKILL);
		send_ok(client_fd, NULL, NULL);
		return 0;
	}

	if (strcmp(op, "query") == 0 && nlines >= 2) {
		/* Return "pid=N\nrestart_count=N\n" or SG_ERR_NOT_FOUND */
		child_entry_t *e = sup_find(lines[1]);
		if (!e) {
			send_error(client_fd, SG_ERR_NOT_FOUND,
				   "Not in supervisor table");
			return 0;
		}
		char resp[128];
		snprintf(resp, sizeof(resp), "pid=%d\nrestart_count=%d\n",
			 (int)e->pid, e->restart_count);
		send_ok(client_fd, NULL, resp);
		return 0;
	}

	send_error(client_fd, SG_ERR_INVALID_ARG, "Unknown test op");
	return 0;
}

/* ── Factory reset handler ───────────────────────────────────────────────── */

/*
 * find_mount_device — resolve a mount point to its block device.
 *
 * Reads /proc/mounts to find which device is mounted at the given path.
 * Returns 0 and fills dev_out on success, -1 if not found.
 */
static int find_mount_device(const char *mount_point,
			     char *dev_out, size_t dev_sz)
{
	FILE *fp = fopen("/proc/mounts", "r");
	if (!fp) return -1;

	char line[512];
	int found = 0;
	while (fgets(line, sizeof(line), fp)) {
		char dev[128], mnt[256];
		if (sscanf(line, "%127s %255s", dev, mnt) == 2 &&
		    strcmp(mnt, mount_point) == 0) {
			snprintf(dev_out, dev_sz, "%s", dev);
			found = 1;
			break;
		}
	}
	fclose(fp);
	return found ? 0 : -1;
}

/*
 * wipe_partition — zero the superblock of a block device.
 *
 * Writes 4096 bytes of zeros to the start of the device, destroying
 * the ext2 superblock.  On next boot, init's _sg_prepare() detects
 * the blank partition and reformats it as a fresh ext2 filesystem.
 *
 * This is the nuclear option: ALL data on the partition is lost.
 * No individual file cleanup needed — the entire filesystem is gone.
 */
static int wipe_partition(const char *dev)
{
	int fd = open(dev, O_WRONLY);
	if (fd < 0)
		return -1;
	char zeros[4096];
	memset(zeros, 0, sizeof(zeros));
	ssize_t n = write(fd, zeros, sizeof(zeros));
	close(fd);
	return (n == sizeof(zeros)) ? 0 : -1;
}

/*
 * handle_factory_reset — Wipe data and logs partitions, then reboot.
 *
 * Strategy: instead of individually cleaning up DB entries, files,
 * shadow hashes, TLS certs, DHCP leases, etc., we destroy the ext2
 * superblock on both the sgdata and sglogs partitions.  On reboot,
 * init detects blank partitions, reformats them, and mgmtd runs the
 * first-boot seed flow.  Everything starts fresh — no state survives.
 *
 * This matches how real network appliances (FortiGate, etc.) handle
 * factory reset: wipe the config partition, reboot, first-boot flow.
 *
 * Steps:
 *   1. Permission check (admin only)
 *   2. Parse action (reboot or shutdown)
 *   3. Audit log BEFORE wiping
 *   4. Send OK response (before we close DB / unmount)
 *   5. Close DB (releases file locks on data partition)
 *   6. Stop all supervised children (releases files on data/logs)
 *   7. Wipe sgdata partition superblock
 *   8. Wipe sglogs partition superblock
 *   9. Reboot or shutdown
 *
 * Error handling:
 *   - Steps 1-3: safe to abort (no side effects)
 *   - Steps 4+: point of no return — always reboot/shutdown
 *   - If wipe fails, reboot anyway — init will fsck and reformat
 */
static int handle_factory_reset(int client_fd, const char *user,
				const char *payload,
				const sg_request_hdr_t *hdr)
{
	(void)hdr;

	/* 1. Permission check */
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'admin' permission");
		return 0;
	}

	/* 2. Parse action */
	int do_reboot = 1; /* default to reboot */
	if (payload) {
		char action[32] = {0};
		sg_kv_get(payload, "action", action, sizeof(action));
		if (strcmp(action, "shutdown") == 0)
			do_reboot = 0;
	}

	/* 3. Audit log BEFORE wiping (will be lost with the partition) */
	(void)audit_log(user, "factory_reset",
			do_reboot ? "action=reboot" : "action=shutdown");

	mgmt_log("WARN", "FACTORY RESET initiated by user=%s action=%s",
		 user, do_reboot ? "reboot" : "shutdown");

	/* 4. Send OK response now — after DB close we can't use IPC.
	 * The client receives confirmation before the wipe begins. */
	send_ok(client_fd,
		do_reboot ? "Factory reset complete. Rebooting..."
			  : "Factory reset complete. Shutting down...",
		NULL);

	/* ── Point of no return ───────────────────────────────────── */

	/* 5. Close DB (release file handles on data partition) */
	sg_db_close();

	/* 6. Stop all supervised children (release file handles) */
	shutdown_children();

	/* 7. Find and wipe sgdata partition.
	 * /etc/stargazer is the mount point for the data partition.
	 * Zeroing the superblock makes init reformat on next boot. */
	{
		char data_dev[128] = {0};
		if (find_mount_device(CONF_DIR, data_dev,
				      sizeof(data_dev)) == 0) {
			/* Unmount so the device is not busy */
			umount(CONF_DIR "/logs");
			umount(CONF_DIR);
			if (wipe_partition(data_dev) == 0)
				mgmt_log("INFO", "factory reset: wiped %s",
					 data_dev);
			else
				mgmt_log("WARN", "factory reset: wipe %s "
					 "failed (will fsck on boot)",
					 data_dev);
		} else {
			mgmt_log("WARN", "factory reset: data partition "
				 "not found at %s", CONF_DIR);
		}
	}

	/* 8. Find and wipe sglogs partition.
	 * Logs partition is at CONF_DIR/logs (already unmounted above).
	 * We derive the device from the data device. */
	{
		char logs_dev[128] = {0};
		if (find_mount_device(CONF_DIR "/logs", logs_dev,
				      sizeof(logs_dev)) == 0) {
			umount(CONF_DIR "/logs");
			if (wipe_partition(logs_dev) == 0)
				mgmt_log("INFO", "factory reset: wiped %s",
					 logs_dev);
			else
				mgmt_log("WARN", "factory reset: wipe %s "
					 "failed", logs_dev);
		}
		/* Logs partition is optional — don't warn if not found */
	}

	mgmt_log("WARN", "FACTORY RESET complete — %s",
		 do_reboot ? "rebooting" : "shutting down");

	/* 9. Reboot or shutdown */
	usleep(100000);
	{
		const char *argv[] = {
			do_reboot ? "/sbin/reboot" : "/sbin/poweroff",
			NULL
		};
		free(safe_exec(argv));
	}
	return 0;
}

/* ── Request handler ────────────────────────────────────────────────────── */

static int handle_request_dispatch(int client_fd, sg_request_hdr_t *hdr,
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
	    cmd != SG_CMD_HISTORY_SAVE &&
	    cmd != SG_CMD_AUTH_LOGIN &&
	    cmd != SG_CMD_AUTH_CHANGE_PW &&
	    cmd != SG_CMD_AUTH_LOGIN_OK &&
	    strcmp(user, "__webd") != 0) {
		if (!session_tag_validate(user, hdr->session_tag)) {
			send_error(client_fd, SG_ERR_SESSION_EXPIRED,
				   "Session invalid or expired");
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
			/* Strip password-hash from system_admin responses —
			 * hashes must never leave mgmtd over the IPC socket. */
			if (strcmp(db_type, "system_admin") == 0) {
				char filtered[SG_PAYLOAD_MAX];
				size_t fpos = 0;
				const char *p = data;
				while (*p) {
					if (*p == '\n') { p++; continue; }
					const char *eol = strchr(p, '\n');
					size_t llen = eol ? (size_t)(eol - p)
							  : strlen(p);
					if (!(llen >= 14 &&
					      memcmp(p, "password-hash=", 14) == 0)) {
						if (fpos + llen + 1 < sizeof(filtered)) {
							memcpy(filtered + fpos, p, llen);
							fpos += llen;
							filtered[fpos++] = '\n';
						}
					}
					p += llen;
					if (eol) p++;
				}
				filtered[fpos] = '\0';
				send_ok(client_fd, NULL, filtered);
			} else {
				send_ok(client_fd, NULL, data);
			}
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

		/* Verify referenced objects exist in DB (server-side).
		 * Closes the web API gap where CLI checks refs via IPC
		 * but mgmtd itself did not verify. */
		{
			sg_status_t ref_st = validate_ref_existence(
				db_type, data, val_err, sizeof(val_err));
			if (ref_st != SG_OK) {
				if (g_debug_flags & SG_DBG_FLAG_MGMTD)
					debug_buf_push("[MGMTD-DBG] cfg_set "
						       "ref check: %s\n",
						       val_err);
				send_error(client_fd, ref_st, val_err);
				return 0;
			}
		}

		/* Preserve internal-only fields that clients cannot set:
		 *  - builtin: mgmtd seed flag, never client-controllable
		 *  - immutable: mgmtd seed flag, never client-controllable
		 *  - password-hash: managed by set_password(), never plaintext
		 * Also strip password= — plaintext passwords are only accepted
		 * by CFG_APPLY (which calls set_password and stores the hash);
		 * they must never be written as plaintext to the DB.
		 *
		 * Keep 'existing' alive — firewall/NAT rollback needs
		 * the old DB data to restore on rebuild failure. */
		char *existing = sg_db_get(db_type, db_id);
		int was_builtin = 0;
		int was_immutable = 0;
		int is_new_entry = (existing == NULL);
		char saved_pw_hash[SG_PAYLOAD_MAX];
		saved_pw_hash[0] = '\0';
		if (existing) {
			char bi[VALBUFSZ];
			extract_val(existing, "builtin", bi, sizeof(bi));
			if (strcmp(bi, "yes") == 0)
				was_builtin = 1;
			extract_val(existing, "password-hash",
				    saved_pw_hash, sizeof(saved_pw_hash));
			was_immutable = is_immutable(existing);
		}

		/* Immutable entries cannot be modified at all.
		 * Covers default-deny policy, built-in address/service
		 * objects, and any future immutable seeds.
		 * This prevents an attacker who gains configure access
		 * from silently opening the firewall. */
		if (was_immutable) {
			free(existing);
			send_error(client_fd, SG_ERR_BUILTIN,
				   "Immutable object cannot be modified");
			return 0;
		}

		/* Build clean data: strip builtin=, password=, password-hash= */
		char clean[SG_PAYLOAD_MAX];
		size_t cpos = 0;
		const char *dp = data;
		while (*dp) {
			if (*dp == '\n') { dp++; continue; }
			const char *el = strchr(dp, '\n');
			size_t ll = el ? (size_t)(el - dp) : strlen(dp);
			if ((ll >=  8 && memcmp(dp, "builtin=",       8) == 0) ||
			    (ll >= 10 && memcmp(dp, "immutable=",    10) == 0) ||
			    (ll >=  9 && memcmp(dp, "password=",      9) == 0) ||
			    (ll >= 14 && memcmp(dp, "password-hash=", 14) == 0)) {
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
		/* Re-append preserved internal fields */
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
		if (was_immutable) {
			const char *tag = "immutable=yes\n";
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

		/* Backfill missing keys that have registry defaults.
		 * Ensures entries always have keys like status, mode, mtu
		 * even if the caller didn't send them.  Optional keys
		 * without defaults (ip, description, allowaccess) are
		 * NOT backfilled — they're genuinely absent until set. */
		{
			const char *defs = sg_reg_default_values(db_type);
			if (defs && *defs) {
				char defcopy[1024];
				snprintf(defcopy, sizeof(defcopy), "%s", defs);
				char *dk = defcopy;
				while (*dk) {
					char *dnl = strchr(dk, '\n');
					if (dnl) *dnl = '\0';
					char *deq = strchr(dk, '=');
					if (deq) {
						*deq = '\0';
						if (!sg_kv_has_key(clean, dk)) {
							*deq = '=';
							size_t dlen = strlen(dk);
							if (cpos + dlen + 1 <
							    sizeof(clean)) {
								memcpy(clean + cpos,
								       dk, dlen);
								cpos += dlen;
								clean[cpos++] = '\n';
								clean[cpos] = '\0';
							}
						}
					}
					if (!dnl) break;
					dk = dnl + 1;
				}
			}
		}

		/* Auto-assign sequence for firewall/NAT on new entries.
		 * Sequence = max(existing) + 1.  Must happen before
		 * apply_config so the apply handler knows the position. */
		if (is_new_entry && seq_type_is_orderable(db_type)) {
			seq_auto_assign(db_type, clean, sizeof(clean));
		}

		/* Firewall/NAT types: persist first, then atomic rebuild.
		 * The rebuild reads ALL entries from DB, so the new data
		 * must be in the DB before we can generate the chain.
		 * If rebuild fails, we rollback the DB change. */
		if (strcmp(db_type, "firewall_policy") == 0 ||
		    strcmp(db_type, "network_nat") == 0) {
			/* Validate fields without touching the kernel */
			char val_result[512];
			sg_status_t val_rc;
			if (strcmp(db_type, "firewall_policy") == 0)
				val_rc = validate_firewall_policy(
					db_id, clean,
					val_result, sizeof(val_result));
			else
				val_rc = validate_nat(
					db_id, clean,
					val_result, sizeof(val_result));
			if (val_rc != SG_OK) {
				free(existing);
				send_error(client_fd, val_rc, val_result);
				return 0;
			}

			/* Write to DB */
			if (sg_db_set(db_type, db_id, clean) != 0) {
				free(existing);
				mgmt_log("ERROR", "sg_db_set failed for %s",
					 section);
				send_error(client_fd, SG_ERR_IO_FAIL,
					   "Failed to write config");
				return 0;
			}

			/* Atomic rebuild from DB */
			char rb_result[512];
			sg_status_t rb_rc;
			if (strcmp(db_type, "firewall_policy") == 0)
				rb_rc = rebuild_forward_chain(
					rb_result, sizeof(rb_result));
			else
				rb_rc = rebuild_nat_chains(
					rb_result, sizeof(rb_result));
			if (rb_rc != SG_OK) {
				/* Rollback: restore old DB state */
				if (is_new_entry)
					sg_db_del(db_type, db_id);
				else if (existing)
					sg_db_set(db_type, db_id, existing);
				free(existing);
				send_error(client_fd, rb_rc, rb_result);
				return 0;
			}
			free(existing);
			existing = NULL;

			send_ok(client_fd, "Config saved", NULL);
			return 0;
		}

		/* All other types: apply before persist.
		 * If apply fails, the config never reaches the DB. */
		{
			char apply_result[512];
			sg_status_t apply_st = apply_config(
				db_type, db_id, clean,
				apply_result, sizeof(apply_result));
			if (apply_st != SG_OK) {
				free(existing);
				send_error(client_fd, apply_st, apply_result);
				return 0;
			}
		}

		free(existing);
		existing = NULL;

		if (sg_db_set(db_type, db_id, clean) != 0) {
			mgmt_log("ERROR", "sg_db_set failed for %s", section);
			send_error(client_fd, SG_ERR_IO_FAIL, "Failed to write config");
			return 0;
		}

		/* Restore password-hash after the overwrite — sg_db_set()
		 * replaces all values so it would clear the hash. */
		if (saved_pw_hash[0])
			sg_db_set_val(db_type, db_id, "password-hash",
				      saved_pw_hash);

		/* Cascade: re-apply entries that reference this object.
		 * Runs after apply + DB persist so cascade reads fresh data. */
		char cascade_warn[512];
		usage_cascade(db_type, db_id,
			      cascade_warn, sizeof(cascade_warn));

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

		if (cascade_warn[0]) {
			char msg[768];
			snprintf(msg, sizeof(msg),
				 "Config saved. Warning: %s", cascade_warn);
			send_ok(client_fd, msg, NULL);
		} else {
			send_ok(client_fd, "Config saved", NULL);
		}
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

		/* Check entry exists */
		char *existing = sg_db_get(db_type, db_id);
		if (!existing) {
			send_error(client_fd, SG_ERR_ENTRY_NOT_FOUND, db_id);
			return 0;
		}
		/* Check builtin flag */
		{
			char bi[VALBUFSZ];
			extract_val(existing, "builtin", bi, sizeof(bi));
			if (strcmp(bi, "yes") == 0) {
				free(existing);
				send_error(client_fd, SG_ERR_BUILTIN, section);
				return 0;
			}
		}
		/* Check immutable flag (defense-in-depth — immutable
		 * entries also have builtin=yes, so the above check
		 * should already catch them) */
		if (is_immutable(existing)) {
			free(existing);
			send_error(client_fd, SG_ERR_BUILTIN,
				   "Immutable object cannot be deleted");
			return 0;
		}
		free(existing);

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

		/* Unapply runtime state before removing from DB.
		 * Config SET takes effect immediately via apply_config();
		 * deletion must also take effect immediately. */
		if (strcmp(db_type, "network_route_static") == 0) {
			char *data = sg_db_get(db_type, db_id);
			if (data) {
				char dst[VALBUFSZ], gw[VALBUFSZ];
				char dev[VALBUFSZ], dist[VALBUFSZ];
				extract_val(data, "dst", dst, sizeof(dst));
				extract_val(data, "gateway", gw, sizeof(gw));
				extract_val(data, "device", dev, sizeof(dev));
				extract_val(data, "distance", dist, sizeof(dist));
				if (dst[0] && sg_is_cidr(dst)) {
					const char *argv[14];
					int ac = 0;
					argv[ac++] = "ip";
					argv[ac++] = "route";
					argv[ac++] = "del";
					argv[ac++] = dst;
					if (gw[0])   { argv[ac++] = "via";
						       argv[ac++] = gw; }
					if (dev[0])  { argv[ac++] = "dev";
						       argv[ac++] = dev; }
					if (dist[0]) { argv[ac++] = "metric";
						       argv[ac++] = dist; }
					argv[ac] = NULL;
					free(safe_exec(argv));
				}
				free(data);
			}
		} else if (strcmp(db_type, "network_dhcp-server") == 0) {
			/* Stop udhcpd daemon, remove firewall rule and
			 * runtime files for this DHCP pool. */
			unapply_dhcp(db_id);
		}
		/* Firewall/NAT: no per-rule unapply needed — atomic
		 * rebuild after DB delete handles everything. */

		if (sg_db_del(db_type, db_id) != 0) {
			send_error(client_fd, SG_ERR_IO_FAIL, "Failed to delete section");
			return 0;
		}

		/* Rebuild chains after deletion */
		if (strcmp(db_type, "firewall_policy") == 0) {
			char rb[512];
			rebuild_forward_chain(rb, sizeof(rb));
		} else if (strcmp(db_type, "network_nat") == 0) {
			char rb[512];
			rebuild_nat_chains(rb, sizeof(rb));
		}

		send_ok(client_fd, "Deleted", NULL);
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

		/* Validate field formats AND required-key completeness.
		 * CFG_APPLY always receives full payloads — CLI loads
		 * all keys via CFG_GET before editing, webd merges
		 * before applying.  Partial payloads are a test artifact. */
		char val_err[256];
		sg_status_t val_st = validate_cfg_data(type_str, data,
						       val_err,
						       sizeof(val_err));
		if (val_st != SG_OK) {
			send_error(client_fd, val_st, val_err);
			return 0;
		}

		/* Verify referenced objects exist in DB (server-side) */
		{
			char ref_err[SG_EXTRA_MAX];
			sg_status_t ref_st = validate_ref_existence(
				type_str, data, ref_err, sizeof(ref_err));
			if (ref_st != SG_OK) {
				send_error(client_fd, ref_st, ref_err);
				return 0;
			}
		}

		/* Cross-field check: system_interface in static mode must have
		 * an explicit IP.  0.0.0.0/0 is accepted as sentinel (means
		 * "no address yet"), but a completely absent ip is rejected
		 * so the user must make an explicit choice. */
		if (strcmp(type_str, "system_interface") == 0) {
			char chk_mode[VALBUFSZ], chk_ip[VALBUFSZ];
			extract_val(data, "mode", chk_mode, sizeof(chk_mode));
			extract_val(data, "ip",   chk_ip,   sizeof(chk_ip));
			if (strcmp(chk_mode, "static") == 0 &&
			    chk_ip[0] == '\0') {
				send_error(client_fd, SG_ERR_MISSING_ARG,
					   "Static mode requires 'ip' "
					   "(e.g. 192.168.1.1/24 or 0.0.0.0/0).");
				return 0;
			}
		}

		/* Firewall/NAT: validation only — no kernel changes.
		 * The actual iptables update happens in CFG_SET via
		 * atomic rebuild.  This prevents the duplicate-rule
		 * problem (CFG_APPLY + CFG_SET both inserting). */
		char result[512];
		sg_status_t st;
		if (strcmp(type_str, "firewall_policy") == 0)
			st = validate_firewall_policy(id_str, data,
						      result, sizeof(result));
		else if (strcmp(type_str, "network_nat") == 0)
			st = validate_nat(id_str, data,
					  result, sizeof(result));
		else
			st = apply_config(type_str, id_str, data,
					  result, sizeof(result));

		if (st == SG_OK) {
			send_ok(client_fd, result, NULL);
		} else {
			send_error(client_fd, st, result);
		}
		return 0;
	}

	case SG_CMD_CFG_INSERT: {
		/* Move entry to a new sequence position.
		 * Payload: "type:id\nnew_sequence\n"
		 * Flow: delete old kernel rule → insert at new position
		 * → update DB only if kernel succeeded. */
		if (!payload || hdr->payload_len == 0) {
			send_error(client_fd, SG_ERR_MISSING_ARG,
				   "Missing type:id + sequence");
			return 0;
		}
		char section[256] = {0};
		const char *nl = strchr(payload, '\n');
		if (!nl) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Bad format (expected type:id\\nsequence)");
			return 0;
		}
		size_t slen = (size_t)(nl - payload);
		if (slen >= sizeof(section)) slen = sizeof(section) - 1;
		memcpy(section, payload, slen);
		section[slen] = '\0';

		const char *seq_data = nl + 1;
		int new_seq = atoi(seq_data);
		if (new_seq < 1 || new_seq > 9999) {
			send_error(client_fd, SG_ERR_INVALID_VAL,
				   "Sequence out of range (1-9999)");
			return 0;
		}

		char db_type[256], db_id[256];
		sg_db_parse_section(section, db_type, sizeof(db_type),
				    db_id, sizeof(db_id));

		/* Only orderable types support sequence reordering */
		if (!seq_type_is_orderable(db_type)) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Type does not support sequence ordering");
			return 0;
		}

		/* Permission check (same as CFG_SET) */
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

		/* Entry must exist */
		char *entry_data = sg_db_get(db_type, db_id);
		if (!entry_data) {
			send_error(client_fd, SG_ERR_ENTRY_NOT_FOUND, db_id);
			return 0;
		}

		/* Builtin policies cannot be reordered */
		{
			char bi[VALBUFSZ];
			extract_val(entry_data, "builtin", bi, sizeof(bi));
			if (strcmp(bi, "yes") == 0) {
				free(entry_data);
				send_error(client_fd, SG_ERR_BUILTIN,
					   "Builtin policy cannot be moved");
				return 0;
			}
		}

		/* Read old sequence */
		char old_seq_str[VALBUFSZ];
		extract_val(entry_data, "sequence", old_seq_str,
			    sizeof(old_seq_str));
		int old_seq = old_seq_str[0] ? atoi(old_seq_str) : 0;

		/* No-op if sequence unchanged */
		if (old_seq == new_seq) {
			free(entry_data);
			send_ok(client_fd, "Sequence unchanged", NULL);
			return 0;
		}

		free(entry_data);

		/* Step 1: Rotate sequences in affected range */
		seq_rotate(db_type, old_seq, new_seq, db_id);

		/* Step 2: Update sequence in DB */
		{
			char seq_clean[16];
			snprintf(seq_clean, sizeof(seq_clean), "%d", new_seq);
			sg_db_set_val(db_type, db_id, "sequence", seq_clean);
		}

		/* Step 3: Atomic rebuild from DB */
		char result[512];
		if (strcmp(db_type, "firewall_policy") == 0)
			rebuild_forward_chain(result, sizeof(result));
		else
			rebuild_nat_chains(result, sizeof(result));

		send_ok(client_fd, result, NULL);
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

	/* ── Auth login flow (logind privilege separation) ─────────────── */
	case SG_CMD_AUTH_LOGIN:
		return handle_auth_login(client_fd, user, payload, hdr);
	case SG_CMD_AUTH_CHANGE_PW:
		return handle_auth_change_pw(client_fd, user, payload, hdr);
	case SG_CMD_AUTH_LOGIN_OK:
		return handle_auth_login_ok(client_fd, user, payload, hdr);

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
		sg_db_close();
		sync();
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
		sg_db_close();
		sync();
		{
			const char *argv[] = {"/sbin/reboot", NULL};
			free(safe_exec(argv));
		}
		return 0;
	}

	case SG_CMD_SYS_FACTORY_RESET:
		return handle_factory_reset(client_fd, user, payload, hdr);

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
			     "Firewall engine: %s\n", mod_status);
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
		send_ok(client_fd, NULL,
			(out && out[0]) ? out : "  (no routes)\n");
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

		/* Build output from ring buffer, stripping kernel module
		 * prefix ("pkt_forward: ") from lines to avoid exposing
		 * internal module names to the CLI user. */
		char buf[4096];
		size_t used = 0;
		int count = nmatches < 20 ? nmatches : 20;
		int start = nmatches <= 20 ? 0 : nmatches % 20;
		for (int i = 0; i < count && used < sizeof(buf) - 2; i++) {
			int idx = (start + i) % 20;
			const char *ls = ring[idx].s;
			size_t llen = ring[idx].len;
			/* Strip "pkt_forward: " from the line content */
			const char *mod = memmem(ls, llen, "pkt_forward: ", 13);
			if (mod) {
				/* Keep everything before the module prefix,
				 * skip "pkt_forward: ", keep the rest */
				size_t pre = (size_t)(mod - ls);
				size_t post = llen - pre - 13;
				if (used + pre + post + 2 > sizeof(buf))
					break;
				memcpy(buf + used, ls, pre);
				used += pre;
				memcpy(buf + used, mod + 13, post);
				used += post;
			} else {
				if (used + llen + 2 > sizeof(buf))
					llen = sizeof(buf) - used - 2;
				memcpy(buf + used, ls, llen);
				used += llen;
			}
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
			 "username=%s\nprofile=%s\npermissions=%s\n",
			 user, prof, perm);
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
	case SG_CMD_DIAG_DISK_HEALTH:
		return handle_diag_disk_health(client_fd, user, payload, hdr);
	case SG_CMD_DISK_LIST:
		return handle_disk_list(client_fd, user, payload, hdr);
	case SG_CMD_DISK_INFO:
		return handle_disk_info(client_fd, user, payload, hdr);
	case SG_CMD_DISK_SMART:
		return handle_disk_smart(client_fd, user, payload, hdr);

	case SG_CMD_DIAG_NTP:
		return handle_diag_ntp(client_fd, user, payload, hdr);
	case SG_CMD_DIAG_BUSYBOX_LIST:
		return handle_diag_busybox_list(client_fd, user, payload, hdr);
	case SG_CMD_DIAG_SESSION:
		return handle_diag_session(client_fd, user, payload, hdr);
	case SG_CMD_SESSION_CLEAR:
		return handle_session_clear(client_fd, user, payload, hdr);
	case SG_CMD_SESSION_STATS:
		return handle_session_stats(client_fd, user, payload, hdr);
	case SG_CMD_NETFLOW_STATUS:
		return handle_netflow_status(client_fd, user, payload, hdr);
	case SG_CMD_NETFLOW_SET:
		return handle_netflow_set(client_fd, user, payload, hdr);
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

	/* ── Log viewing/management ──────────────────────────────────── */

	case SG_CMD_LOG_AUDIT:
		return handle_log_audit(client_fd, user, payload, hdr);
	case SG_CMD_LOG_SYSTEM:
		return handle_log_system(client_fd, user, payload, hdr);
	case SG_CMD_LOG_MGMTD:
		return handle_log_mgmtd(client_fd, user, payload, hdr);
	case SG_CMD_LOG_CLEAR_AUDIT:
		return handle_log_clear_audit(client_fd, user, payload, hdr);
	case SG_CMD_DIAG_STARGAZER_LOG:
		return handle_diag_stargazer_log(client_fd, user, payload, hdr);
	case SG_CMD_DIAG_STORAGE:
		return handle_diag_storage(client_fd, user, payload, hdr);
	case SG_CMD_DIAG_DHCP_CLIENT:
		return handle_diag_dhcp_client(client_fd, user, payload, hdr);

	case SG_CMD_PING:
		send_ok(client_fd, "pong", NULL);
		return 0;

	case SG_CMD_UPGRADE_TEST_SETUP:
		return handle_upgrade_test_setup(client_fd, user, payload, hdr);

	case SG_CMD_SUPERVISOR_TEST:
		return handle_supervisor_test(client_fd, user, payload, hdr);

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

/* ── Central audit hook wrapper ─────────────────────────────────────────── */

static int handle_request(int client_fd, sg_request_hdr_t *hdr,
			  const char *payload)
{
	sg_cmd_t cmd = (sg_cmd_t)hdr->cmd;
	const char *user = hdr->username;

	g_last_response_status = SG_OK;
	int rc = handle_request_dispatch(client_fd, hdr, payload);

	if (!sg_cmd_audit_skip(cmd)) {
		char event[16], detail[256];
		snprintf(event, sizeof(event), "%u", (unsigned)cmd);
		audit_detail(payload, hdr->payload_len, detail, sizeof(detail));

		char amsg[512];
		if (g_last_response_status == SG_OK) {
			snprintf(amsg, sizeof(amsg), "OK %s", detail);
		} else {
			snprintf(amsg, sizeof(amsg), "FAILED %s: %s",
				 sg_status_str(g_last_response_status), detail);
		}
		if (audit_log(user, event, amsg) != 0)
			mgmt_log("WARN", "audit write failed: cmd=%u by %s",
				 (unsigned)cmd, user);
	}

	return rc;
}

/* ── Carrier monitoring ─────────────────────────────────────────────────── */

static int open_netlink_link_socket(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0) {
		mgmt_log("WARN", "netlink socket: %s — carrier monitoring disabled",
			 strerror(errno));
		return -1;
	}
	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_LINK,
	};
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		mgmt_log("WARN", "netlink bind: %s — carrier monitoring disabled",
			 strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
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

	/* SIGCHLD: set flag for main loop reaping (SA_NOCLDSTOP skips
	 * stopped-child signals which we don't care about) */
	{
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = sigchld_handler;
		sa.sa_flags = SA_NOCLDSTOP;
		sigaction(SIGCHLD, &sa, NULL);
	}

	/* Remove stale socket */
	unlink(SG_MGMTD_SOCK);

	/* Ensure config directory exists with restricted permissions.
	 * mgmtd is now the sole accessor — CLI reads via IPC only. */
	mkdir(CONF_DIR, 0700);
	chmod(CONF_DIR, 0700);

	/* Ensure logs directory exists (sglogs partition) */
	mkdir(CONF_DIR "/logs", 0700);
	chmod(CONF_DIR "/logs", 0700);

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
		if (mgmtd_first_boot_seed() != 0) {
			mgmt_log("ERROR", "refusing to start — seed failed");
			mgmtd_signal_fifo("error");
			sg_db_close();
			return 1;
		}
	}

	/* Reconcile config: seed/repair built-in immutable objects,
	 * backfill missing keys and sequences, purge stale types.
	 * Idempotent — runs every boot, handles upgrade migration. */
	mgmtd_reconcile_config();

	/* Wait for ethernet NICs to appear — the MTK GMAC + DSA subsystem
	 * probes asynchronously and may not be visible in /sys/class/net by
	 * the time mgmtd starts.  Poll up to 5 seconds then proceed. */
	{
		int ms = 0;
		while (ms < 5000) {
			DIR *nd = opendir("/sys/class/net");
			if (nd) {
				int found = 0;
				struct dirent *ne;
				while ((ne = readdir(nd)) != NULL) {
					if (ne->d_name[0] == '.' ||
					    strcmp(ne->d_name, "lo") == 0)
						continue;
					if (read_net_type(ne->d_name) == 1) {
						found = 1;
						break;
					}
				}
				closedir(nd);
				if (found) break;
			}
			usleep(100000);
			ms += 100;
		}
		if (ms > 0)
			mgmt_log("INFO",
				 "waited %dms for ethernet interfaces", ms);
	}

	/* Discover NICs, create/protect interface entries */
	mgmtd_sync_interfaces(boot == BOOT_FIRST);

	/* INPUT policy DROP set by kernel; add loopback + return traffic rules */
	mgmtd_init_firewall();

	/* Apply saved configuration to running system BEFORE accepting
	 * any connections.  Clients must see a fully-applied state —
	 * iptables rules, routes, interfaces all consistent with the DB.
	 * This may take several seconds on large configs. */
	mgmtd_replay_config();

	mgmt_log("INFO", "config replay complete");

	/* Create socket AFTER replay — socket appearance means mgmtd is
	 * truly ready to accept connections with consistent state. */
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

	int nl_fd = open_netlink_link_socket();

	/* Start webd under supervision — unconditional (SRC_ALWAYS).
	 * Must start AFTER socket listen() so webd's bind_listeners()
	 * can connect to mgmtd and query interface allowaccess config. */
	{
		const char *webd_argv[] = {"/sbin/stargazer-webd", NULL};
		supervisor_start("webd", webd_argv, SRC_ALWAYS,
				 NULL, NULL, NULL, NULL);
	}

	/* Signal readiness to init — config is fully applied, socket is
	 * listening, webd is started.  Init can now start the login loop. */
	mgmtd_signal_fifo("ready");

	mgmt_log("INFO", "stargazer-mgmtd ready, listening on %s", SG_MGMTD_SOCK);

	/* Store listen fd for forked children to close */
	g_listen_fd = sfd;

	/* Main accept loop — poll() so SIGCHLD wakes us for reaping */
	while (g_running) {
		/* Reap any dead supervised children */
		if (g_child_died) {
			g_child_died = 0;
			reap_children();
		}

		struct pollfd pfds[2];
		int nfds = 0;
		pfds[nfds].fd = sfd;
		pfds[nfds].events = POLLIN;
		nfds++;
		if (nl_fd >= 0) {
			pfds[nfds].fd = nl_fd;
			pfds[nfds].events = POLLIN;
			nfds++;
		}

		int pr = poll(pfds, (nfds_t)nfds, 5000);
		if (pr < 0) {
			if (errno == EINTR) continue;
			mgmt_log("ERROR", "poll: %s", strerror(errno));
			continue;
		}
		if (pr == 0) continue;  /* timeout, loop back for reap */

		/* Carrier events from kernel — process before accepting IPC */
		if (nl_fd >= 0 && pfds[1].revents & POLLIN)
			handle_netlink_link_event(nl_fd);

		if (!(pfds[0].revents & POLLIN))
			continue;

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
				/* Trusted proxy: webd (UID 900) forwards
				 * web user identities via IPC. Trust the
				 * claimed username — webd authenticates
				 * users itself before proxying requests.
				 * Scoped: only UID 900, and webd is
				 * seccomp-sandboxed (no fork/exec). */
				if (cred.uid == WEBD_SERVICE_UID) {
					verified = 1;
				} else if (hdr.username[0] != '\0') {
					struct passwd *claimed =
						getpwnam(hdr.username);
					if (claimed &&
					    claimed->pw_uid == cred.uid) {
						verified = 1;
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

	/* Gracefully stop all supervised children */
	shutdown_children();

	close(sfd);
	unlink(SG_MGMTD_SOCK);
	sg_db_close();
	mgmt_log("INFO", "stargazer-mgmtd stopped");
	return 0;
}
