/* SPDX-License-Identifier: MIT */
/*
 * stargazer-logind — Stargazer NGFW login daemon
 *
 * Replaces BusyBox login + LOGIN_PRE_SUID_SCRIPT with a single C binary.
 * Flow:
 *   1. Receive username as argv[1]
 *   2. Prompt for password (stty -echo equivalent via termios)
 *   3. Authenticate via shadow + crypt(3)
 *   4. Check enforce-change-password policy from SQLite database
 *   5. If enforced: prompt new password, update shadow, clear flag
 *   6. Audit log all events
 *   7. Drop privileges (setgid/setuid)
 *   8. exec user shell
 */

#define _GNU_SOURCE
#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "password_policy.h"
#include "sg_db.h"

#define AUDIT_LOG         "/var/log/stargazer-audit.log"
#define AUDIT_LOG_FALLBACK "/tmp/stargazer-audit.log"
#define MAX_PASS_LEN      256
#define MAX_LINE_LEN      1024
#define MAX_SALT_LEN      32
#define EXIT_SIGINT       130  /* Convention: 128 + SIGINT(2) */

/* ── SIGINT handling (Ctrl+C returns to login prompt) ───────────────────── */

static volatile sig_atomic_t g_interrupted = 0;
static struct termios g_saved_termios;
static int g_termios_saved = 0;

static void sigint_handler(int sig)
{
	(void)sig;
	g_interrupted = 1;
	/* Restore terminal echo immediately (async-signal-safe via tcsetattr) */
	if (g_termios_saved)
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_termios);
}

/*
 * Install SIGINT handler using sigaction WITHOUT SA_RESTART.
 * This ensures read() inside fgets() returns EINTR immediately
 * when Ctrl+C is pressed, rather than being silently restarted.
 */
static void install_sigint_handler(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigint_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;  /* explicitly NO SA_RESTART */
	sigaction(SIGINT, &sa, NULL);
}

/* ── Audit logging ──────────────────────────────────────────────────────── */

static void audit_log(const char *user, const char *event, const char *msg)
{
	const char *path = AUDIT_LOG;
	time_t now = time(NULL);
	struct tm tm;
	char ts[64];
	FILE *fp;

	if (access("/var/log", W_OK) != 0)
		path = AUDIT_LOG_FALLBACK;

	localtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tm);

	fp = fopen(path, "a");
	if (fp) {
		char *tty = ttyname(STDIN_FILENO);
		fprintf(fp, "%s user=%s event=%s msg=%s pid=%d tty=%s\n",
			ts, user, event, msg, (int)getpid(),
			tty ? tty : "unknown");
		fclose(fp);
	} else {
		fprintf(stderr, "[logind] audit_log: cannot write to %s: %s (event=%s user=%s)\n",
			path, strerror(errno), event, user);
	}
}

/* ── Password prompt (echo disabled) ────────────────────────────────────── */

static int read_password(const char *prompt, char *buf, size_t buflen)
{
	struct termios new;

	if (g_interrupted)
		return -2;

	fprintf(stderr, "%s", prompt);
	fflush(stderr);

	g_termios_saved = 0;
	if (tcgetattr(STDIN_FILENO, &g_saved_termios) == 0) {
		new = g_saved_termios;
		new.c_lflag &= ~ECHO;
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &new);
		g_termios_saved = 1;
	}

	if (!fgets(buf, (int)buflen, stdin)) {
		if (g_termios_saved)
			tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_termios);
		g_termios_saved = 0;
		fprintf(stderr, "\n");
		return g_interrupted ? -2 : -1;
	}

	if (g_termios_saved)
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_termios);
	g_termios_saved = 0;
	fprintf(stderr, "\n");

	if (g_interrupted)
		return -2;

	/* Strip trailing newline */
	size_t len = strlen(buf);
	if (len > 0 && buf[len - 1] == '\n')
		buf[len - 1] = '\0';

	return 0;
}

/* ── Shadow authentication ──────────────────────────────────────────────── */

static int authenticate(const char *username, const char *password)
{
	/*
	 * Constant-time defense: always call crypt() even if the user
	 * doesn't exist, so the response latency doesn't leak whether
	 * a username is valid. (BUG-AUTH-01)
	 */
	static const char dummy_hash[] =
		"$6$dummy.salt.value$"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

	struct spwd *sp = getspnam(username);
	const char *hash = sp ? sp->sp_pwdp : dummy_hash;

	/* Always call crypt to keep timing constant */
	char *result = crypt(password, hash);

	/* User not found — fail after crypt */
	if (!sp)
		return -1;

	/* Empty password hash: allow login with empty password (first-login) */
	if (sp->sp_pwdp[0] == '\0' && password[0] == '\0')
		return 0;

	/* Locked account */
	if (sp->sp_pwdp[0] == '!' || sp->sp_pwdp[0] == '*')
		return -1;

	if (!result)
		return -1;

	return strcmp(result, sp->sp_pwdp) == 0 ? 0 : -1;
}

/* ── Shadow update (atomic tmpfile + rename) ────────────────────────────── */

static int update_shadow(const char *username, const char *hash)
{
	/* Acquire advisory lock for shadow file manipulation */
	int lockfd = open("/etc/shadow.lock", O_CREAT | O_RDWR, 0600);
	if (lockfd < 0)
		return -1;
	if (flock(lockfd, LOCK_EX) != 0) {
		close(lockfd);
		return -1;
	}

	FILE *fp = fopen("/etc/shadow", "r");
	if (!fp) {
		flock(lockfd, LOCK_UN);
		close(lockfd);
		return -1;
	}

	char tmppath[64];
	snprintf(tmppath, sizeof(tmppath), "/etc/shadow.XXXXXX");
	int tfd = mkstemp(tmppath);
	if (tfd < 0) {
		fclose(fp);
		flock(lockfd, LOCK_UN);
		close(lockfd);
		return -1;
	}
	fchmod(tfd, 0640);
	FILE *out = fdopen(tfd, "w");
	if (!out) {
		close(tfd);
		unlink(tmppath);
		fclose(fp);
		flock(lockfd, LOCK_UN);
		close(lockfd);
		return -1;
	}

	char line[MAX_LINE_LEN];
	int found = 0;
	size_t ulen = strlen(username);

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, username, ulen) == 0 && line[ulen] == ':') {
			/* Replace the password field (field 2) */
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

/* ── Salt generation for crypt(3) ───────────────────────────────────────── */

static int generate_salt(char *salt, size_t saltlen)
{
	static const char charset[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"0123456789./";

	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return -1;

	unsigned char raw[16];
	ssize_t n = read(fd, raw, sizeof(raw));
	close(fd);
	if (n != (ssize_t)sizeof(raw))
		return -1;

	/* SHA-512 prefix */
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

/* ── Password policy ────────────────────────────────────────────────────── */

/*
 * Read global password policy from SQLite (system_password-policy).
 * Missing keys default to 0 (no requirement).
 */
static void read_password_policy(struct password_policy *pol)
{
	char *v;

	pol->min_length = 0;
	pol->min_uppercase = 0;
	pol->min_lowercase = 0;
	pol->min_digit = 0;
	pol->min_special = 0;

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
static int is_password_policy_enforced(const char *username)
{
	char *val = sg_db_get_val("system_admin", username,
				  "enforce-password-policy");
	if (!val)
		return 0; /* key missing → not enforced */

	int enforced = (strcmp(val, "enable") == 0) ? 1 : 0;
	free(val);
	return enforced;
}

/* ── Password change core ──────────────────────────────────────────────── */

/*
 * Print password requirements line.
 * Used by both enforce_password_change and enforce_policy_compliance.
 */
static void print_requirements(int eff_min_len, int has_policy,
			       const struct password_policy *pol)
{
	fprintf(stderr, " Requirements: minimum %d characters", eff_min_len);
	if (has_policy) {
		if (pol->min_uppercase > 0)
			fprintf(stderr, ", %d uppercase", pol->min_uppercase);
		if (pol->min_lowercase > 0)
			fprintf(stderr, ", %d lowercase", pol->min_lowercase);
		if (pol->min_digit > 0)
			fprintf(stderr, ", %d digit(s)", pol->min_digit);
		if (pol->min_special > 0)
			fprintf(stderr, ", %d special", pol->min_special);
	}
	fprintf(stderr, ".\n\n");
}

/*
 * Core password change loop — prompts, validates, hashes, updates shadow.
 * Returns: 0 on success, -1 on error, -2 on Ctrl+C.
 * Does NOT read or write any config flags — caller handles that.
 */
static int force_password_change(const char *username, int eff_min_len,
				 int has_policy,
				 const struct password_policy *pol)
{
	char pw1[MAX_PASS_LEN], pw2[MAX_PASS_LEN];
	int rc;

	while (1) {
		rc = read_password("New password: ", pw1, sizeof(pw1));
		if (rc == -2) return -2; /* interrupted */
		if (rc != 0)  return -1;

		if ((int)strlen(pw1) < eff_min_len) {
			fprintf(stderr, "Too short: password must be at least %d characters.\n\n",
				eff_min_len);
			continue;
		}

		if (has_policy) {
			int prc = pw_check_policy(pw1, username, pol);
			if (prc != 1) {
				fprintf(stderr, "  %s\n\n", pw_policy_reason(prc));
				continue;
			}
		}

		rc = read_password("Retype password: ", pw2, sizeof(pw2));
		if (rc == -2) { explicit_bzero(pw1, sizeof(pw1)); return -2; }
		if (rc != 0)  { explicit_bzero(pw1, sizeof(pw1)); return -1; }

		if (strcmp(pw1, pw2) != 0) {
			fprintf(stderr, "Passwords don't match. Try again.\n\n");
			continue;
		}

		/* Hash and update shadow */
		char salt[MAX_SALT_LEN];
		if (generate_salt(salt, sizeof(salt)) != 0) {
			fprintf(stderr, "Failed to generate salt.\n\n");
			continue;
		}

		char *hash = crypt(pw1, salt);
		if (!hash) {
			fprintf(stderr, "Failed to hash password.\n\n");
			continue;
		}

		if (update_shadow(username, hash) != 0) {
			fprintf(stderr, "Failed to update shadow file. Try again.\n\n");
			continue;
		}

		break;
	}

	explicit_bzero(pw1, sizeof(pw1));
	explicit_bzero(pw2, sizeof(pw2));

	fprintf(stderr, "\n  Password set successfully.\n\n");
	return 0;
}

/* ── Enforce password change (admin-controlled flag) ───────────────────── */

static int enforce_password_change(const char *username)
{
	char *val = sg_db_get_val("system_admin", username,
				  "enforce-change-password");
	if (!val)
		return 0; /* no key → skip */

	int need_change = (strcmp(val, "enable") == 0);
	free(val);
	if (!need_change)
		return 0;

	/* Read password policy for requirements */
	struct password_policy pol;
	int has_policy = is_password_policy_enforced(username);
	if (has_policy)
		read_password_policy(&pol);
	else
		memset(&pol, 0, sizeof(pol));

	int eff_min_len = has_policy
		? ((pol.min_length > 0) ? pol.min_length : PW_MIN_PASS_LEN)
		: PW_MIN_PASS_LEN_ABS;

	fprintf(stderr, "\n");
	fprintf(stderr, " PASSWORD CHANGE REQUIRED\n");
	fprintf(stderr, " Account '%s' must change password now.\n", username);
	print_requirements(eff_min_len, has_policy, &pol);

	int rc = force_password_change(username, eff_min_len, has_policy, &pol);
	if (rc != 0)
		return rc;

	/* Clear admin-controlled enforce flag */
	sg_db_set_val("system_admin", username,
		      "enforce-change-password", "disable");

	audit_log(username, "password_force_change", "source=admin-flag");
	return 0;
}

/* ── Enforce policy compliance (triggered by global policy change) ─────── */

static int enforce_policy_compliance(const char *username,
				     const struct password_policy *pol)
{
	fprintf(stderr, "\n");
	fprintf(stderr, " NOTICE: Password Policy Changed\n");
	fprintf(stderr, " Your current password does not meet the updated\n");
	fprintf(stderr, " global password policy. You must set a new password.\n");
	print_requirements(
		(pol->min_length > 0) ? pol->min_length : PW_MIN_PASS_LEN,
		1, pol);

	int rc = force_password_change(username,
		(pol->min_length > 0) ? pol->min_length : PW_MIN_PASS_LEN,
		1, pol);
	if (rc != 0)
		return rc;

	/* NOTE: enforce-change-password is NOT touched here.
	 * This is a system-triggered change due to policy update,
	 * not an admin-controlled flag. */

	audit_log(username, "password_policy_change", "source=policy-mismatch");
	return 0;
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: stargazer-logind <username>\n");
		return 1;
	}

	const char *username = argv[1];

	/* Install Ctrl+C handler WITHOUT SA_RESTART so fgets() returns on EINTR */
	install_sigint_handler();
	signal(SIGQUIT, SIG_IGN);

	/* Open config database (read password policy, enforce flags) */
	if (sg_db_open(SG_DB_PATH) != 0) {
		fprintf(stderr, "stargazer-logind: failed to open config database\n");
		return 1;
	}

	/* Authenticate */
	char password[MAX_PASS_LEN];
	int pw_rc = read_password("Password: ", password, sizeof(password));
	if (pw_rc == -2) {
		/* Ctrl+C during password — return to login prompt */
		explicit_bzero(password, sizeof(password));
		return EXIT_SIGINT;
	}
	if (pw_rc != 0) {
		audit_log(username, "login_fail", "reason=read-error");
		return 1;
	}

	if (authenticate(username, password) != 0) {
		explicit_bzero(password, sizeof(password));
		audit_log(username, "login_fail", "reason=bad-password");
		fprintf(stderr, "Invalid credentials\n");
		return 1;
	}

	/*
	 * Check if current password meets policy — store result but don't
	 * act yet. We need the plaintext password for the check, but the
	 * admin-controlled enforce-change-password flag takes priority.
	 */
	struct password_policy login_pol;
	int policy_mismatch = 0;
	if (is_password_policy_enforced(username)) {
		read_password_policy(&login_pol);
		int prc = pw_check_policy(password, username, &login_pol);
		if (prc != 1) {
			policy_mismatch = 1;
			audit_log(username, "password_policy_mismatch",
				  pw_policy_reason(prc));
		}
	}

	explicit_bzero(password, sizeof(password));

	/*
	 * Read admin flag BEFORE calling enforce_password_change so we
	 * know whether it will actually trigger a change or just skip.
	 */
	int admin_flag_set = 0;
	{
		char *epc_val = sg_db_get_val("system_admin", username,
					      "enforce-change-password");
		if (epc_val) {
			if (strcmp(epc_val, "enable") == 0)
				admin_flag_set = 1;
			free(epc_val);
		}
	}

	/*
	 * Path 1: Admin-controlled enforce-change-password flag.
	 * If triggered, the new password is validated against policy too,
	 * so a successful change here satisfies both the admin flag AND
	 * any policy mismatch — we can skip the policy path entirely.
	 */
	int epc_rc = enforce_password_change(username);
	if (epc_rc == -2) {
		audit_log(username, "login_fail", "reason=password-change-interrupted");
		return EXIT_SIGINT;
	}
	if (epc_rc != 0) {
		audit_log(username, "login_fail", "reason=enforce-change-failed");
		return 1;
	}

	/*
	 * Path 2: Policy mismatch — system-triggered, does NOT touch
	 * enforce-change-password config. Only runs if the admin flag
	 * did NOT trigger (if it did, the new password already meets policy).
	 */
	if (policy_mismatch && !admin_flag_set) {
		int pm_rc = enforce_policy_compliance(username, &login_pol);
		if (pm_rc == -2) {
			audit_log(username, "login_fail",
				  "reason=policy-change-interrupted");
			return EXIT_SIGINT;
		}
		if (pm_rc != 0) {
			audit_log(username, "login_fail",
				  "reason=policy-change-failed");
			return 1;
		}
	}

	/* Close config database before dropping privileges */
	sg_db_close();

	/* Restore signals */
	signal(SIGINT, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);

	/* Look up user for privilege drop */
	struct passwd *pw = getpwnam(username);
	if (!pw) {
		audit_log(username, "login_fail", "reason=no-passwd-entry");
		fprintf(stderr, "Invalid credentials\n");
		return 1;
	}

	audit_log(username, "login_success", "source=logind");

	/*
	 * Establish controlling terminal BEFORE dropping privileges.
	 * /dev/console is mode 0600 root:root — must open while still UID 0.
	 * After this block, stdin/stdout/stderr point to /dev/console and
	 * /dev/tty resolves correctly for any UID.
	 */
	(void)setsid();
	int tfd = open("/dev/console", O_RDWR);
	if (tfd >= 0) {
		(void)ioctl(tfd, TIOCSCTTY, 0);
		dup2(tfd, STDIN_FILENO);
		dup2(tfd, STDOUT_FILENO);
		dup2(tfd, STDERR_FILENO);
		if (tfd > STDERR_FILENO)
			close(tfd);
	}

	/*
	 * Drop to actual user credentials.
	 * All privileged operations are delegated to stargazer-mgmtd via
	 * Unix domain socket IPC. CLI scripts run as the logged-in user
	 * and never touch system files directly.
	 */
	if (initgroups(username, pw->pw_gid) != 0)
		perror("initgroups");

	if (setgid(pw->pw_gid) != 0) {
		perror("setgid");
		return 1;
	}
	if (setuid(pw->pw_uid) != 0) {
		perror("setuid");
		return 1;
	}

	/* Set environment */
	setenv("HOME", pw->pw_dir, 1);
	setenv("SHELL", pw->pw_shell, 1);
	setenv("USER", username, 1);
	setenv("LOGNAME", username, 1);
	setenv("STARGAZER_USER", username, 1);
	setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 0); /* preserve if set */
	setenv("TMOUT", "900", 1); /* 15-min idle session timeout (IMPROVE-AUTH-02) */

	/* exec user shell */
	const char *shell = pw->pw_shell;
	if (!shell || shell[0] == '\0')
		shell = "/bin/sh";

	execl(shell, shell, (char *)NULL);
	perror("exec");
	return 1;
}
