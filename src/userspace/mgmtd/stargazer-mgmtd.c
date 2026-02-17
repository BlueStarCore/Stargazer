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
#include <sys/wait.h>

#include "stargazer_ipc.h"
#include "password_policy.h"

/* ── Constants ──────────────────────────────────────────────────────────── */

#define CMD_BUF_SIZE     512
#define CONF_DIR         "/etc/stargazer"
#define SYSTEM_CONF      CONF_DIR "/system.conf"
#define NETWORK_CONF     CONF_DIR "/network.conf"
#define FIREWALL_CONF    CONF_DIR "/firewall.conf"
#define AUDIT_LOG        "/var/log/stargazer-audit.log"
#define AUDIT_LOG_FB     "/tmp/stargazer-audit.log"
#define SESSION_REV_FILE "/tmp/stargazer-session.rev"
#define MAX_LINE         1024
#define MAX_SALT_LEN     32
#define MAX_CLIENTS_QUEUE 8
#define BUF_SIZE         (sizeof(sg_request_hdr_t) + SG_PAYLOAD_MAX)
#define DEBUG_STATE_FILE  "/tmp/stargazer-debug.conf"

static volatile sig_atomic_t g_running = 1;

/* ── Input validation (VULN-09, BUG-CFG-01, IMPROVE-CFG-01) ───────────── */

/* Safe identifier: [A-Za-z0-9_.-] only */
static int is_safe_id(const char *s)
{
	if (!s || !s[0]) return 0;
	for (const char *p = s; *p; p++) {
		if (!isalnum((unsigned char)*p) && *p != '_' && *p != '.' && *p != '-')
			return 0;
	}
	return 1;
}

/* Validate IPv4 address: exactly 4 octets 0-255 */
static int is_valid_ipv4(const char *s)
{
	if (!s || !s[0]) return 0;
	int octets = 0;
	const char *p = s;
	while (*p) {
		if (!isdigit((unsigned char)*p)) return 0;
		int val = 0;
		while (isdigit((unsigned char)*p)) {
			val = val * 10 + (*p - '0');
			if (val > 255) return 0;
			p++;
		}
		octets++;
		if (*p == '.') { p++; continue; }
		if (*p == '\0') break;
		return 0;
	}
	return octets == 4;
}

/* Validate CIDR: A.B.C.D/0-32 */
static int is_valid_cidr(const char *s)
{
	if (!s || !s[0]) return 0;
	char buf[64];
	snprintf(buf, sizeof(buf), "%s", s);
	char *slash = strchr(buf, '/');
	if (!slash) return 0;
	*slash = '\0';
	if (!is_valid_ipv4(buf)) return 0;
	const char *mask = slash + 1;
	if (!mask[0]) return 0;
	for (const char *p = mask; *p; p++)
		if (!isdigit((unsigned char)*p)) return 0;
	int m = atoi(mask);
	return m >= 0 && m <= 32;
}

/* Validate interface name: [A-Za-z0-9_.:- ] */
static int is_valid_iface(const char *s)
{
	if (!s || !s[0]) return 0;
	for (const char *p = s; *p; p++) {
		if (!isalnum((unsigned char)*p) && *p != '_' && *p != '.'
		    && *p != ':' && *p != '-')
			return 0;
	}
	return 1;
}

/* Validate unsigned integer in range */
static int is_valid_uint_range(const char *s, int lo, int hi)
{
	if (!s || !s[0]) return 0;
	for (const char *p = s; *p; p++)
		if (!isdigit((unsigned char)*p)) return 0;
	int v = atoi(s);
	return v >= lo && v <= hi;
}

/* ── Safe command execution (replaces popen) ──────────────────────────── */

/*
 * safe_exec: fork + execvp with argument array. No shell interpretation.
 * Returns dynamically allocated stdout output (caller frees), or NULL.
 */
static char *safe_exec(const char *const argv[])
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

static void mgmt_log(const char *level, const char *fmt, ...)
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

static void audit_log(const char *user, const char *event, const char *msg)
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
	}
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

/* ── INI Config I/O (mirrors config_lib.sh) ─────────────────────────────── */

static const char *domain_for(const char *type)
{
	if (strncmp(type, "system_interface", 16) == 0)
		return NETWORK_CONF;
	if (strncmp(type, "network_", 8) == 0)
		return NETWORK_CONF;
	if (strncmp(type, "firewall_", 9) == 0)
		return FIREWALL_CONF;
	return SYSTEM_CONF;
}

/*
 * cfg_get_section: read all key=value lines under [section] from file.
 * Returns dynamically allocated string (caller must free), or NULL.
 */
static char *cfg_get_section(const char *file, const char *section)
{
	FILE *fp = fopen(file, "r");
	if (!fp) return NULL;

	char line[MAX_LINE];
	char header[MAX_LINE + 4];
	snprintf(header, sizeof(header), "[%s]", section);

	int in_section = 0;
	size_t bufsize = 4096, used = 0;
	char *buf = malloc(bufsize);
	if (!buf) { fclose(fp); return NULL; }
	buf[0] = '\0';

	while (fgets(line, sizeof(line), fp)) {
		size_t len = strlen(line);
		if (len > 0 && line[len-1] == '\n') line[--len] = '\0';

		if (strcmp(line, header) == 0) {
			in_section = 1;
			continue;
		}
		if (line[0] == '[') {
			if (in_section) break;
			continue;
		}
		if (!in_section) continue;
		if (line[0] == '#' || line[0] == '\0') continue;

		/* Append line to buffer */
		size_t llen = strlen(line);
		while (used + llen + 2 > bufsize) {
			bufsize *= 2;
			char *nb = realloc(buf, bufsize);
			if (!nb) { free(buf); fclose(fp); return NULL; }
			buf = nb;
		}
		memcpy(buf + used, line, llen);
		used += llen;
		buf[used++] = '\n';
		buf[used] = '\0';
	}

	fclose(fp);
	if (!in_section || used == 0) {
		free(buf);
		return NULL;
	}
	return buf;
}

/*
 * cfg_set_section: write key=value data under [section] in file.
 * Creates file if needed. Replaces existing section or appends.
 * Uses atomic write (tmpfile + rename).
 */
static int cfg_set_section(const char *file, const char *section,
			   const char *data)
{
	char tmppath[256];
	snprintf(tmppath, sizeof(tmppath), "%s.tmp.XXXXXX", file);

	/* If file doesn't exist, create it */
	if (access(file, F_OK) != 0) {
		int tfd = mkstemp(tmppath);
		if (tfd < 0) return -1;
		fchmod(tfd, 0640);
		FILE *fp = fdopen(tfd, "w");
		if (!fp) { close(tfd); unlink(tmppath); return -1; }
		fprintf(fp, "[%s]\n%s\n", section, data);
		fclose(fp);
		if (rename(tmppath, file) != 0) {
			unlink(tmppath);
			return -1;
		}
		return 0;
	}

	FILE *in = fopen(file, "r");
	if (!in) return -1;
	int tfd = mkstemp(tmppath);
	if (tfd < 0) { fclose(in); return -1; }
	fchmod(tfd, 0640);
	FILE *out = fdopen(tfd, "w");
	if (!out) { close(tfd); fclose(in); unlink(tmppath); return -1; }

	char header[MAX_LINE + 4];
	snprintf(header, sizeof(header), "[%s]", section);

	char line[MAX_LINE];
	int found = 0, skip = 0, wrote = 0;

	while (fgets(line, sizeof(line), in)) {
		size_t len = strlen(line);
		char trimmed[MAX_LINE];
		memcpy(trimmed, line, len + 1);
		if (len > 0 && trimmed[len-1] == '\n') trimmed[len-1] = '\0';

		if (strcmp(trimmed, header) == 0) {
			found = 1;
			skip = 1;
			fprintf(out, "[%s]\n%s\n", section, data);
			wrote = 1;
			continue;
		}
		if (trimmed[0] == '[') {
			skip = 0;
		}
		if (skip) continue;
		fputs(line, out);
	}

	if (!found) {
		fprintf(out, "[%s]\n%s\n", section, data);
	}

	fclose(in);
	fclose(out);
	(void)wrote;

	if (rename(tmppath, file) != 0) {
		unlink(tmppath);
		return -1;
	}
	return 0;
}

/*
 * cfg_del_section: remove [section] and its contents from file.
 */
static int cfg_del_section(const char *file, const char *section)
{
	if (access(file, F_OK) != 0) return -1;

	char tmppath[256];
	snprintf(tmppath, sizeof(tmppath), "%s.tmp.XXXXXX", file);

	FILE *in = fopen(file, "r");
	if (!in) return -1;
	int tfd = mkstemp(tmppath);
	if (tfd < 0) { fclose(in); return -1; }
	fchmod(tfd, 0640);
	FILE *out = fdopen(tfd, "w");
	if (!out) { close(tfd); fclose(in); unlink(tmppath); return -1; }

	char header[MAX_LINE + 4];
	snprintf(header, sizeof(header), "[%s]", section);

	char line[MAX_LINE];
	int skip = 0;

	while (fgets(line, sizeof(line), in)) {
		size_t len = strlen(line);
		char trimmed[MAX_LINE];
		memcpy(trimmed, line, len + 1);
		if (len > 0 && trimmed[len-1] == '\n') trimmed[len-1] = '\0';

		if (strcmp(trimmed, header) == 0) {
			skip = 1;
			continue;
		}
		if (trimmed[0] == '[')
			skip = 0;
		if (skip) continue;
		fputs(line, out);
	}

	fclose(in);
	fclose(out);

	if (rename(tmppath, file) != 0) {
		unlink(tmppath);
		return -1;
	}
	return 0;
}

/*
 * cfg_list_entries: list all entry IDs under a type prefix.
 * Returns newline-separated list of IDs (caller must free).
 * E.g. for prefix "system_admin", finds [system_admin:admin], [system_admin:admin1]
 * and returns "admin\nadmin1\n".
 */
static char *cfg_list_entries(const char *file, const char *prefix)
{
	FILE *fp = fopen(file, "r");
	if (!fp) return NULL;

	size_t plen = strlen(prefix);
	size_t bufsize = 1024, used = 0;
	char *buf = malloc(bufsize);
	if (!buf) { fclose(fp); return NULL; }
	buf[0] = '\0';

	char line[MAX_LINE];
	while (fgets(line, sizeof(line), fp)) {
		size_t len = strlen(line);
		if (len > 0 && line[len-1] == '\n') line[--len] = '\0';

		/* Match [prefix:id] */
		if (line[0] != '[') continue;
		if (strncmp(line + 1, prefix, plen) != 0) continue;
		if (line[1 + plen] != ':') continue;

		/* Extract id */
		const char *id_start = line + 1 + plen + 1;
		const char *id_end = strchr(id_start, ']');
		if (!id_end) continue;

		size_t id_len = (size_t)(id_end - id_start);
		while (used + id_len + 2 > bufsize) {
			bufsize *= 2;
			char *nb = realloc(buf, bufsize);
			if (!nb) { free(buf); fclose(fp); return NULL; }
			buf = nb;
		}
		memcpy(buf + used, id_start, id_len);
		used += id_len;
		buf[used++] = '\n';
		buf[used] = '\0';
	}

	fclose(fp);
	if (used == 0) { free(buf); return NULL; }
	return buf;
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
	char salt[MAX_SALT_LEN];
	if (generate_salt(salt, sizeof(salt)) != 0)
		return -1;

	char *hash = crypt(password, salt);
	if (!hash) return -1;

	/* Update shadow atomically */
	FILE *fp = fopen("/etc/shadow", "r");
	if (!fp) return -1;

	char tmppath[64];
	snprintf(tmppath, sizeof(tmppath), "/etc/shadow.tmp.%d", (int)getpid());
	FILE *out = fopen(tmppath, "w");
	if (!out) { fclose(fp); return -1; }
	fchmod(fileno(out), 0640);

	char line[MAX_LINE];
	size_t ulen = strlen(username);
	int found = 0;

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, username, ulen) == 0 && line[ulen] == ':') {
			char *rest = strchr(line + ulen + 1, ':');
			if (rest)
				fprintf(out, "%s:%s%s", username, hash, rest);
			else
				fprintf(out, "%s:%s:19700:0:99999:7:::\n", username, hash);
			found = 1;
		} else {
			fputs(line, out);
		}
	}
	fclose(fp);
	fclose(out);

	if (!found) {
		unlink(tmppath);
		return -1;
	}

	if (rename(tmppath, "/etc/shadow") != 0) {
		unlink(tmppath);
		return -1;
	}
	return 0;
}

/*
 * Check whether a user has a valid password hash in /etc/shadow.
 * Returns 1 if user has a usable password, 0 if locked/empty/missing.
 */
static int user_has_password(const char *username)
{
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

	/* Find next available UID >= 1000 */
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
			if (cur_uid == uid)
				uid++;
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
		fprintf(fp, "%s::19700:0:99999:7:::\n", username);
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
	chown(homedir, uid, uid);

	return 0;
}

static int delete_system_user(const char *username)
{
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
			fchmod(fileno(out), 0640);

		char line[MAX_LINE];
		while (fgets(line, sizeof(line), in)) {
			if (strncmp(line, prefix, plen) != 0)
				fputs(line, out);
		}

		fclose(in);
		fclose(out);
		rename(tmppath, files[i]);
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
	fclose(out);

	rename(tmppath, SESSION_REV_FILE);
	chmod(SESSION_REV_FILE, 0644);
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
#define VALBUFSZ 128
static void extract_val(const char *data, const char *key,
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
			if (vlen >= outsz) vlen = outsz - 1;
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
 * Read global password policy from system.conf [system_password-policy].
 * Uses cfg_get_section + extract_val (mgmtd-specific).
 */
static void mgmtd_read_password_policy(struct password_policy *pol)
{
	pol->min_length = 0;
	pol->min_uppercase = 0;
	pol->min_lowercase = 0;
	pol->min_digit = 0;
	pol->min_special = 0;

	char *data = cfg_get_section(SYSTEM_CONF, "system_password-policy");
	if (!data) return;

	char val[VALBUFSZ];
	extract_val(data, "min-length", val, sizeof(val));
	if (val[0]) { int v = atoi(val); pol->min_length = (v > 0) ? v : 0; }
	extract_val(data, "min-uppercase", val, sizeof(val));
	if (val[0]) { int v = atoi(val); pol->min_uppercase = (v > 0) ? v : 0; }
	extract_val(data, "min-lowercase", val, sizeof(val));
	if (val[0]) { int v = atoi(val); pol->min_lowercase = (v > 0) ? v : 0; }
	extract_val(data, "min-digit", val, sizeof(val));
	if (val[0]) { int v = atoi(val); pol->min_digit = (v > 0) ? v : 0; }
	extract_val(data, "min-special", val, sizeof(val));
	if (val[0]) { int v = atoi(val); pol->min_special = (v > 0) ? v : 0; }

	free(data);
}

/*
 * Check if user has enforce-password-policy=enable in their admin config.
 * Returns 1 if enforced, 0 if not.
 */
static int mgmtd_is_policy_enforced(const char *username)
{
	char section[256];
	snprintf(section, sizeof(section), "system_admin:%s", username);

	char *data = cfg_get_section(SYSTEM_CONF, section);
	if (!data) return 0;

	char val[VALBUFSZ];
	extract_val(data, "enforce-password-policy", val, sizeof(val));
	free(data);

	return (strcmp(val, "enable") == 0) ? 1 : 0;
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

	if (strcmp(type, "network_route_static") == 0) {
		char dst[VALBUFSZ], gw[VALBUFSZ], dev[VALBUFSZ], status[VALBUFSZ];
		extract_val(data, "dst", dst, sizeof(dst));
		extract_val(data, "gateway", gw, sizeof(gw));
		extract_val(data, "device", dev, sizeof(dev));
		extract_val(data, "status", status, sizeof(status));

		/* Validate all inputs before any system call */
		if (dst[0] && !is_valid_cidr(dst)) {
			snprintf(result, rsize, "Invalid dst '%s'.", dst);
			return SG_ERR_INVALID_VAL;
		}
		if (gw[0] && !is_valid_ipv4(gw)) {
			snprintf(result, rsize, "Invalid gateway '%s'.", gw);
			return SG_ERR_INVALID_VAL;
		}
		if (dev[0] && !is_valid_iface(dev)) {
			snprintf(result, rsize, "Invalid device '%s'.", dev);
			return SG_ERR_INVALID_VAL;
		}

		if (strcmp(status, "disable") == 0) {
			if (dst[0]) {
				const char *argv[] = {"ip", "route", "del", dst, NULL};
				free(safe_exec(argv));
			}
			snprintf(result, rsize, "Route %s disabled.", id);
			return SG_OK;
		}
		if (dst[0] == '\0') {
			snprintf(result, rsize, "'dst' not set, route not applied.");
			return SG_ERR_MISSING_ARG;
		}

		/* Build argv for ip route replace — no shell interpretation */
		if (gw[0] && dev[0]) {
			const char *argv[] = {"ip", "route", "replace", dst, "via", gw, "dev", dev, NULL};
			free(safe_exec(argv));
		} else if (gw[0]) {
			const char *argv[] = {"ip", "route", "replace", dst, "via", gw, NULL};
			free(safe_exec(argv));
		} else if (dev[0]) {
			const char *argv[] = {"ip", "route", "replace", dst, "dev", dev, NULL};
			free(safe_exec(argv));
		} else {
			const char *argv[] = {"ip", "route", "replace", dst, NULL};
			free(safe_exec(argv));
		}

		snprintf(result, rsize, "Route %s applied: %s", id, dst);
		return SG_OK;
	}

	if (strcmp(type, "system_settings") == 0) {
		char hostname[VALBUFSZ], ipfwd[VALBUFSZ];
		extract_val(data, "hostname", hostname, sizeof(hostname));
		extract_val(data, "ip-forward", ipfwd, sizeof(ipfwd));

		if (hostname[0]) {
			if (!is_safe_id(hostname)) {
				snprintf(result, rsize, "Invalid hostname '%s'.", hostname);
				return SG_ERR_INVALID_VAL;
			}
			/* Use sethostname() syscall — no shell (VULN-09) */
			sethostname(hostname, strlen(hostname));
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

	if (strcmp(type, "system_hostname") == 0) {
		char name[VALBUFSZ];
		extract_val(data, "hostname", name, sizeof(name));
		if (name[0]) {
			if (!is_safe_id(name)) {
				snprintf(result, rsize, "Invalid hostname '%s'.", name);
				return SG_ERR_INVALID_VAL;
			}
			/* Use sethostname() syscall — no shell (VULN-09) */
			sethostname(name, strlen(name));
			FILE *fp = fopen("/etc/hostname", "w");
			if (fp) { fprintf(fp, "%s\n", name); fclose(fp); }
			snprintf(result, rsize, "Hostname set to '%s'.", name);
		}
		return SG_OK;
	}

	if (strcmp(type, "system_interface") == 0) {
		char ip[VALBUFSZ], status[VALBUFSZ], mtu[VALBUFSZ];
		extract_val(data, "ip", ip, sizeof(ip));
		extract_val(data, "status", status, sizeof(status));
		extract_val(data, "mtu", mtu, sizeof(mtu));

		/* Validate inputs */
		if (!is_valid_iface(id)) {
			snprintf(result, rsize, "Invalid interface '%s'.", id);
			return SG_ERR_INVALID_VAL;
		}
		if (ip[0] && !is_valid_cidr(ip)) {
			snprintf(result, rsize, "Invalid IP '%s'.", ip);
			return SG_ERR_INVALID_VAL;
		}
		if (mtu[0] && !is_valid_uint_range(mtu, 576, 9200)) {
			snprintf(result, rsize, "Invalid MTU '%s'.", mtu);
			return SG_ERR_INVALID_VAL;
		}

		if (ip[0]) {
			const char *a1[] = {"ip", "addr", "flush", "dev", id, NULL};
			free(safe_exec(a1));
			const char *a2[] = {"ip", "addr", "add", ip, "dev", id, NULL};
			free(safe_exec(a2));
		}
		if (strcmp(status, "up") == 0) {
			const char *a[] = {"ip", "link", "set", id, "up", NULL};
			free(safe_exec(a));
		} else if (strcmp(status, "down") == 0) {
			const char *a[] = {"ip", "link", "set", id, "down", NULL};
			free(safe_exec(a));
		}
		if (mtu[0]) {
			const char *a[] = {"ip", "link", "set", id, "mtu", mtu, NULL};
			free(safe_exec(a));
		}
		snprintf(result, rsize, "Interface %s configured.", id);
		return SG_OK;
	}

	if (strcmp(type, "network_nat") == 0) {
		char nattype[VALBUFSZ], srcintf[VALBUFSZ], dstport[VALBUFSZ];
		char mapped_ip[VALBUFSZ], mapped_port[VALBUFSZ], status[VALBUFSZ];
		extract_val(data, "type", nattype, sizeof(nattype));
		extract_val(data, "srcintf", srcintf, sizeof(srcintf));
		extract_val(data, "dstport", dstport, sizeof(dstport));
		extract_val(data, "mapped-ip", mapped_ip, sizeof(mapped_ip));
		extract_val(data, "mapped-port", mapped_port, sizeof(mapped_port));
		extract_val(data, "status", status, sizeof(status));

		/* Validate inputs */
		if (srcintf[0] && !is_valid_iface(srcintf)) {
			snprintf(result, rsize, "Invalid srcintf '%s'.", srcintf);
			return SG_ERR_INVALID_VAL;
		}
		if (mapped_ip[0] && !is_valid_ipv4(mapped_ip)) {
			snprintf(result, rsize, "Invalid mapped-ip '%s'.", mapped_ip);
			return SG_ERR_INVALID_VAL;
		}
		if (dstport[0] && !is_valid_uint_range(dstport, 1, 65535)) {
			snprintf(result, rsize, "Invalid dstport '%s'.", dstport);
			return SG_ERR_INVALID_VAL;
		}
		if (mapped_port[0] && !is_valid_uint_range(mapped_port, 1, 65535)) {
			snprintf(result, rsize, "Invalid mapped-port '%s'.", mapped_port);
			return SG_ERR_INVALID_VAL;
		}

		if (strcmp(status, "disable") == 0) {
			snprintf(result, rsize, "NAT rule %s disabled.", id);
			return SG_OK;
		}
		if (strcmp(nattype, "snat") == 0 && srcintf[0]) {
			const char *a[] = {"iptables", "-t", "nat", "-A", "POSTROUTING",
					   "-o", srcintf, "-j", "MASQUERADE", NULL};
			free(safe_exec(a));
			snprintf(result, rsize, "SNAT rule %s applied.", id);
		} else if (strcmp(nattype, "dnat") == 0 && dstport[0] && mapped_ip[0]) {
			char target[256];
			if (mapped_port[0])
				snprintf(target, sizeof(target), "%s:%s", mapped_ip, mapped_port);
			else
				snprintf(target, sizeof(target), "%s", mapped_ip);

			const char *a[] = {"iptables", "-t", "nat", "-A", "PREROUTING",
					   "-p", "tcp", "--dport", dstport,
					   "-j", "DNAT", "--to-destination", target, NULL};
			free(safe_exec(a));
			snprintf(result, rsize, "DNAT rule %s applied.", id);
		}
		return SG_OK;
	}

	if (strcmp(type, "system_admin-profile") == 0) {
		char perms[VALBUFSZ];
		extract_val(data, "permissions", perms, sizeof(perms));
		if (perms[0] == '\0') {
			snprintf(result, rsize, "'permissions' not set.");
			return SG_ERR_MISSING_ARG;
		}
		audit_log("mgmtd", "admin_profile_apply",
			  perms);
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
		char *prof_data = cfg_get_section(SYSTEM_CONF,
						  "system_admin-profile");
		/* Simple existence check via formatted section name */
		char prof_sec[256];
		snprintf(prof_sec, sizeof(prof_sec), "system_admin-profile:%s", profile);
		char *prof_check = cfg_get_section(SYSTEM_CONF, prof_sec);
		if (!prof_check) {
			snprintf(result, rsize, "Profile '%s' does not exist.", profile);
			free(prof_data);
			return SG_ERR_PROFILE_NOT_FOUND;
		}
		free(prof_check);
		free(prof_data);

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
			audit_log(id, "admin_password_set", "source=mgmtd");
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
			char admin_sec[CMD_BUF_SIZE];
			snprintf(admin_sec, sizeof(admin_sec), "system_admin:%s", id);
			char *existing = cfg_get_section(SYSTEM_CONF, admin_sec);
			if (!existing)
				strcpy(enforce, "enable"); /* new user default */
			else {
				free(existing);
				strcpy(enforce, "disable");
			}
		}

		audit_log(id, "admin_apply", profile);
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
	char section[256];
	snprintf(section, sizeof(section), "system_admin:%s", username);
	char *user_data = cfg_get_section(SYSTEM_CONF, section);
	if (!user_data) return "monitor";

	char prof_name[VALBUFSZ];
	extract_val(user_data, "profile", prof_name, sizeof(prof_name));
	if (prof_name[0] == '\0') {
		free(user_data);
		return "monitor";
	}
	free(user_data);

	/* Get profile's permissions */
	snprintf(section, sizeof(section), "system_admin-profile:%s", prof_name);
	char *prof_data = cfg_get_section(SYSTEM_CONF, section);
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

/* ── Request handler ────────────────────────────────────────────────────── */

static void handle_request(int client_fd, sg_request_hdr_t *hdr,
			   const char *payload)
{
	sg_cmd_t cmd = (sg_cmd_t)hdr->cmd;
	const char *user = hdr->username;

	mgmt_log("INFO", "cmd=%u user=%s payload_len=%u",
		 hdr->cmd, user, hdr->payload_len);

	switch (cmd) {

	/* ── Config read ────────────────────────────────────────────────── */
	case SG_CMD_CFG_GET: {
		/* Payload format: "section\n" */
		if (!payload || hdr->payload_len == 0) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing section name");
			return;
		}
		/* Parse: first line = section, optional second line = domain file */
		char section[512] = {0};
		char domain_override[256] = {0};
		const char *nl = strchr(payload, '\n');
		if (nl) {
			size_t slen = (size_t)(nl - payload);
			if (slen >= sizeof(section)) slen = sizeof(section) - 1;
			memcpy(section, payload, slen);
			section[slen] = '\0';
		} else {
			snprintf(section, sizeof(section), "%s", payload);
		}

		/* Determine domain file from section type */
		const char *type = section;
		char type_buf[256];
		const char *colon = strchr(section, ':');
		if (colon) {
			size_t tlen = (size_t)(colon - section);
			if (tlen >= sizeof(type_buf)) tlen = sizeof(type_buf) - 1;
			memcpy(type_buf, section, tlen);
			type_buf[tlen] = '\0';
			type = type_buf;
		}
		const char *file = domain_override[0] ? domain_override : domain_for(type);

		char *data = cfg_get_section(file, section);
		if (data) {
			send_ok(client_fd, NULL, data);
			free(data);
		} else {
			send_error(client_fd, SG_ERR_ENTRY_NOT_FOUND, section);
		}
		return;
	}

	case SG_CMD_CFG_LIST: {
		/* Payload: "prefix\n" */
		if (!payload || hdr->payload_len == 0) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing type prefix");
			return;
		}
		char prefix[256] = {0};
		snprintf(prefix, sizeof(prefix), "%s", payload);
		/* Strip trailing newline */
		size_t plen = strlen(prefix);
		if (plen > 0 && prefix[plen-1] == '\n') prefix[--plen] = '\0';

		const char *file = domain_for(prefix);
		char *list = cfg_list_entries(file, prefix);
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
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "configure") && !has_permission(perms, "admin")) {
			send_error(client_fd, SG_ERR_PERM_DENIED,
				   "Requires 'configure' or 'admin' permission");
			audit_log(user, "cfg_set_deny", "permission denied");
			return;
		}
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

		/* Determine domain file */
		char type_buf[256];
		const char *colon = strchr(section, ':');
		const char *type = section;
		if (colon) {
			size_t tlen = (size_t)(colon - section);
			if (tlen >= sizeof(type_buf)) tlen = sizeof(type_buf) - 1;
			memcpy(type_buf, section, tlen);
			type_buf[tlen] = '\0';
			type = type_buf;
		}
		const char *file = domain_for(type);

		if (cfg_set_section(file, section, data) != 0) {
			mgmt_log("ERROR", "cfg_set failed: %s", strerror(errno));
			send_error(client_fd, SG_ERR_IO_FAIL, "Failed to write config");
			return;
		}

		audit_log(user, "cfg_set", section);
		send_ok(client_fd, "Config saved", NULL);
		return;
	}

	case SG_CMD_CFG_DEL: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "configure") && !has_permission(perms, "admin")) {
			send_error(client_fd, SG_ERR_PERM_DENIED,
				   "Requires 'configure' or 'admin' permission");
			return;
		}
		if (!payload || hdr->payload_len == 0) {
			send_error(client_fd, SG_ERR_MISSING_ARG, "Missing section");
			return;
		}
		char section[256] = {0};
		snprintf(section, sizeof(section), "%s", payload);
		size_t slen = strlen(section);
		if (slen > 0 && section[slen-1] == '\n') section[--slen] = '\0';

		/* Check if builtin */
		char type_buf[256];
		const char *colon = strchr(section, ':');
		const char *type_s = section;
		if (colon) {
			size_t tlen = (size_t)(colon - section);
			if (tlen >= sizeof(type_buf)) tlen = sizeof(type_buf) - 1;
			memcpy(type_buf, section, tlen);
			type_buf[tlen] = '\0';
			type_s = type_buf;
		}
		const char *file = domain_for(type_s);

		char *existing = cfg_get_section(file, section);
		if (existing) {
			/* Check builtin flag */
			char bi[VALBUFSZ];
			extract_val(existing, "builtin", bi, sizeof(bi));
			if (strcmp(bi, "yes") == 0) {
				free(existing);
				send_error(client_fd, SG_ERR_BUILTIN, section);
				return;
			}
			free(existing);
		}

		/* If deleting admin, also delete system user */
		if (strncmp(section, "system_admin:", 13) == 0) {
			const char *adm_name = section + 13;
			delete_system_user(adm_name);
		}

		if (cfg_del_section(file, section) != 0) {
			send_error(client_fd, SG_ERR_IO_FAIL, "Failed to delete section");
			return;
		}
		audit_log(user, "cfg_del", section);
		send_ok(client_fd, "Deleted", NULL);
		return;
	}

	case SG_CMD_CFG_APPLY: {
		const char *perms = get_user_permissions(user);
		if (!has_permission(perms, "configure") && !has_permission(perms, "admin")) {
			send_error(client_fd, SG_ERR_PERM_DENIED,
				   "Requires 'configure' or 'admin' permission");
			return;
		}
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

		const char *data = nl2 + 1;
		char result[512];
		sg_status_t st = apply_config(type_str, id_str, data, result, sizeof(result));

		if (st == SG_OK)
			send_ok(client_fd, result, NULL);
		else
			send_error(client_fd, st, result);
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

		/* Check profile exists */
		char psec[256];
		snprintf(psec, sizeof(psec), "system_admin-profile:%s", newprof);
		char *pdata = cfg_get_section(SYSTEM_CONF, psec);
		if (!pdata) {
			send_error(client_fd, SG_ERR_PROFILE_NOT_FOUND, newprof);
			return;
		}
		free(pdata);

		/* Check user doesn't exist */
		char usec[256];
		snprintf(usec, sizeof(usec), "system_admin:%s", newuser);
		char *udata = cfg_get_section(SYSTEM_CONF, usec);
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

		/* Add to system.conf */
		char cfgdata[256];
		snprintf(cfgdata, sizeof(cfgdata),
			 "profile=%s\nenforce-change-password=enable\n", newprof);
		if (cfg_set_section(SYSTEM_CONF, usec, cfgdata) != 0) {
			send_error(client_fd, SG_ERR_IO_FAIL, "config write failed");
			return;
		}

		audit_log(user, "admin_create", newuser);
		char msg[CMD_BUF_SIZE];
		snprintf(msg, sizeof(msg), "User '%s' created with profile '%s'", newuser, newprof);
		send_ok(client_fd, msg, NULL);
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

		char sec[256];
		snprintf(sec, sizeof(sec), "system_admin:%s", target);

		/* Check builtin */
		char *existing = cfg_get_section(SYSTEM_CONF, sec);
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

		cfg_del_section(SYSTEM_CONF, sec);
		delete_system_user(target);
		session_rev_bump(target);

		audit_log(user, "admin_delete", target);
		char msg[CMD_BUF_SIZE];
		snprintf(msg, sizeof(msg), "User '%s' deleted", target);
		send_ok(client_fd, msg, NULL);
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
		audit_log(user, "admin_password_set", target);
		send_ok(client_fd, "Password updated", NULL);
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

		char sec[256];
		snprintf(sec, sizeof(sec), "system_admin:%s", target);
		char *existing = cfg_get_section(SYSTEM_CONF, sec);
		if (!existing) {
			send_error(client_fd, SG_ERR_USER_NOT_FOUND, target);
			return;
		}

		/* Rebuild data with updated enforce flag */
		/* Simple approach: remove old enforce line, append new one */
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

		cfg_set_section(SYSTEM_CONF, sec, newdata);
		free(existing);
		free(newdata);
		audit_log(user, "admin_set_enforce", target);
		send_ok(client_fd, "Enforce policy updated", NULL);
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

		const char *reason = NULL;
		int rc = mgmtd_validate_password(chk_user, chk_pw,
						  chk_enforce[0] ? chk_enforce : NULL,
						  &reason);
		explicit_bzero(chk_pw, sizeof(chk_pw));

		if (rc > 0) {
			send_error(client_fd, SG_ERR_POLICY_FAIL,
				   reason ? reason : "Policy violation");
		} else {
			send_ok(client_fd, "Password meets policy", NULL);
		}
		return;
	}

	/* ── Session ────────────────────────────────────────────────────── */
	case SG_CMD_SESSION_REV: {
		if (!payload) { send_error(client_fd, SG_ERR_MISSING_ARG, NULL); return; }
		char target[128] = {0};
		snprintf(target, sizeof(target), "%s", payload);
		size_t tlen = strlen(target);
		if (tlen > 0 && target[tlen-1] == '\n') target[--tlen] = '\0';

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
		audit_log(user, "system_poweroff", "");
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
		audit_log(user, "system_reboot", "");
		usleep(100000);
		(void)run_cmd("/sbin/reboot");
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
		char *out = run_cmd("ip -brief link 2>/dev/null || ifconfig -a 2>/dev/null");
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

	case SG_CMD_WHOAMI: {
		/* Return caller's profile and permissions from system.conf */
		char section[256];
		snprintf(section, sizeof(section), "system_admin:%s", user);
		char *udata = cfg_get_section(SYSTEM_CONF, section);
		if (!udata) {
			send_ok(client_fd, NULL, "profile=read-only\npermissions=monitor\n");
			return;
		}
		char prof[128] = {0}, perm[256] = {0};
		extract_val(udata, "profile", prof, sizeof(prof));
		free(udata);

		if (prof[0]) {
			snprintf(section, sizeof(section),
				 "system_admin-profile:%s", prof);
			char *pdata = cfg_get_section(SYSTEM_CONF, section);
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

	case SG_CMD_PING:
		send_ok(client_fd, "pong", NULL);
		return;

	default:
		send_error(client_fd, SG_ERR_INVALID_CMD, "Unknown command");
		return;
	}
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(void)
{
	/* Must run as root */
	if (getuid() != 0) {
		fprintf(stderr, "stargazer-mgmtd: must run as root\n");
		return 1;
	}

	/* Signal handlers */
	signal(SIGINT,  sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGPIPE, SIG_IGN);

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
		if (sg_grp)
			chown(SG_MGMTD_SOCK, 0, sg_grp->gr_gid);
	}

	if (listen(sfd, MAX_CLIENTS_QUEUE) < 0) {
		perror("listen");
		close(sfd);
		return 1;
	}

	mgmt_log("INFO", "stargazer-mgmtd started, listening on %s", SG_MGMTD_SOCK);

	/* Ensure config directory exists */
	mkdir(CONF_DIR, 0755);

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

		/* Handle request (with verified username) */
		handle_request(cfd, &hdr, payload);

		free(payload);
		close(cfd);
	}

	close(sfd);
	unlink(SG_MGMTD_SOCK);
	mgmt_log("INFO", "stargazer-mgmtd stopped");
	return 0;
}
