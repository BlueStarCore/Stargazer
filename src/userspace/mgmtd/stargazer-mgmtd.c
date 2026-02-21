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

/* ── Constants ──────────────────────────────────────────────────────────── */

#define CMD_BUF_SIZE     512
#ifndef CONF_DIR
#define CONF_DIR         "/etc/stargazer"
#endif
#define AUDIT_LOG        "/var/log/stargazer-audit.log"
#define AUDIT_LOG_FB     "/tmp/stargazer-audit.log"
#define SESSION_REV_FILE "/tmp/stargazer-session.rev"
#define MAX_LINE         1024
#define MAX_SALT_LEN     32
#define MAX_CLIENTS_QUEUE 8
#define BUF_SIZE         (sizeof(sg_request_hdr_t) + SG_PAYLOAD_MAX)
#define DEBUG_STATE_FILE  "/tmp/stargazer-debug.conf"

static volatile sig_atomic_t g_running = 1;

/* ── Input validation ───────────────────────────────────────────────────── */
/* Validators now live in common/sg_validate.c — included via sg_validate.h */

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

	/* ── Auto-detect network interfaces ────────────────────────── */
	{
		DIR *d = opendir("/sys/class/net");
		if (d) {
			struct dirent *ent;
			while ((ent = readdir(d)) != NULL) {
				if (ent->d_name[0] == '.')
					continue;
				if (strcmp(ent->d_name, "lo") == 0)
					continue;
				sg_db_set("system_interface", ent->d_name,
					  "status=up\n");
				mgmt_log("INFO", "detected interface: %s",
					 ent->d_name);
			}
			closedir(d);
		}
	}

	mgmt_log("INFO", "default configuration seeded successfully");
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
		NULL
	};
	for (int i = 0; single_types[i]; i++) {
		char *data = sg_db_get(single_types[i], "0");
		if (data) {
			apply_config(single_types[i], "0", data,
				     result, sizeof(result));
			mgmt_log("INFO", "replay %s: %s",
				 single_types[i], result);
			free(data);
		}
	}

	/* Table config types (multiple entries) */
	static const char *table_types[] = {
		"system_interface",
		"network_route_static",
		"network_nat",
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
				apply_config(table_types[i], id, data,
					     result, sizeof(result));
				mgmt_log("INFO", "replay %s:%s: %s",
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
	int lockfd = open("/etc/shadow.lock", O_CREAT | O_RDWR, 0600);
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
	fchmod(tfd, 0640);
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
	int lockfd = open("/etc/shadow.lock", O_CREAT | O_RDWR, 0600);
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
	fchmod(tfd, 0640);
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
				fprintf(out, "%s:!:19700:0:99999:7:::\n", username);
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
	if (v) { int n = atoi(v); pol->min_length = (n > 0) ? n : 0; free(v); }
	v = sg_db_get_val("system_password-policy", "0", "min-uppercase");
	if (v) { int n = atoi(v); pol->min_uppercase = (n > 0) ? n : 0; free(v); }
	v = sg_db_get_val("system_password-policy", "0", "min-lowercase");
	if (v) { int n = atoi(v); pol->min_lowercase = (n > 0) ? n : 0; free(v); }
	v = sg_db_get_val("system_password-policy", "0", "min-digit");
	if (v) { int n = atoi(v); pol->min_digit = (n > 0) ? n : 0; free(v); }
	v = sg_db_get_val("system_password-policy", "0", "min-special");
	if (v) { int n = atoi(v); pol->min_special = (n > 0) ? n : 0; free(v); }
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

	if (strcmp(type, "network_route_static") == 0) {
		char dst[VALBUFSZ], gw[VALBUFSZ], dev[VALBUFSZ], status[VALBUFSZ];
		extract_val(data, "dst", dst, sizeof(dst));
		extract_val(data, "gateway", gw, sizeof(gw));
		extract_val(data, "device", dev, sizeof(dev));
		extract_val(data, "status", status, sizeof(status));

		/* Validate all inputs before any system call */
		if (dst[0] && !sg_is_cidr(dst)) {
			snprintf(result, rsize, "Invalid dst '%s'.", dst);
			return SG_ERR_INVALID_VAL;
		}
		if (gw[0] && !sg_is_ipv4(gw)) {
			snprintf(result, rsize, "Invalid gateway '%s'.", gw);
			return SG_ERR_INVALID_VAL;
		}
		if (dev[0] && !sg_is_iface_name(dev)) {
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
			if (!sg_is_safe_id(hostname)) {
				snprintf(result, rsize, "Invalid hostname '%s'.", hostname);
				return SG_ERR_INVALID_VAL;
			}
			/* Use sethostname() syscall — no shell (VULN-09) */
			if (sethostname(hostname, strlen(hostname)) != 0)
				mgmt_log("WARN", "sethostname: %s", strerror(errno));
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
			if (!sg_is_safe_id(name)) {
				snprintf(result, rsize, "Invalid hostname '%s'.", name);
				return SG_ERR_INVALID_VAL;
			}
			/* Use sethostname() syscall — no shell (VULN-09) */
			if (sethostname(name, strlen(name)) != 0)
				mgmt_log("WARN", "sethostname: %s", strerror(errno));
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
		if (!sg_is_iface_name(id)) {
			snprintf(result, rsize, "Invalid interface '%s'.", id);
			return SG_ERR_INVALID_VAL;
		}
		if (ip[0] && !sg_is_cidr(ip)) {
			snprintf(result, rsize, "Invalid IP '%s'.", ip);
			return SG_ERR_INVALID_VAL;
		}
		if (mtu[0] && !sg_is_uint_range(mtu, 576, 9200)) {
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
		if (srcintf[0] && !sg_is_iface_name(srcintf)) {
			snprintf(result, rsize, "Invalid srcintf '%s'.", srcintf);
			return SG_ERR_INVALID_VAL;
		}
		if (mapped_ip[0] && !sg_is_ipv4(mapped_ip)) {
			snprintf(result, rsize, "Invalid mapped-ip '%s'.", mapped_ip);
			return SG_ERR_INVALID_VAL;
		}
		if (dstport[0] && !sg_is_uint_range(dstport, 1, 65535)) {
			snprintf(result, rsize, "Invalid dstport '%s'.", dstport);
			return SG_ERR_INVALID_VAL;
		}
		if (mapped_port[0] && !sg_is_uint_range(mapped_port, 1, 65535)) {
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
			char target[VALBUFSZ * 2 + 4];
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
			char *existing = sg_db_get("system_admin", id);
			if (!existing)
				snprintf(enforce, sizeof(enforce), "enable");
			else {
				free(existing);
				snprintf(enforce, sizeof(enforce), "disable");
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
		if (!sg_reg_validate_entry_id(db_type, db_id)) {
			send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid entry ID");
			return;
		}

		if (sg_db_set(db_type, db_id, data) != 0) {
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

		/* If deleting admin, bump session and delete system user */
		if (strcmp(db_type, "system_admin") == 0) {
			session_rev_bump(db_id);
			delete_system_user(db_id);
		}

		if (sg_db_del(db_type, db_id) != 0) {
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

		sg_db_del("system_admin", target);
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
			send_error(client_fd, SG_ERR_POLICY_FAIL,
				   reason ? reason : "Policy violation");
		} else {
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
		audit_log(user, "admin_password_locked", lock_target);
		send_ok(client_fd, "Password locked", NULL);
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

	/* Apply saved configuration to running system */
	mgmtd_replay_config();

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
