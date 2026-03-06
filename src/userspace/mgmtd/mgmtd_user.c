/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_user.c — User & password management for stargazer-mgmtd
 *
 * Extracted from stargazer-mgmtd.c to keep the monolith manageable.
 * Contains:
 *   - Shadow file helpers (generate_salt, set_password, lock_password, ...)
 *   - Linux user management (create_system_user, delete_system_user, ...)
 *   - Password policy helpers
 *   - Admin command handlers (ADMIN_CREATE, ADMIN_DELETE, ...)
 */

#define _GNU_SOURCE
#include <crypt.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "mgmtd_internal.h"
#include "mgmtd_apply.h"

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

int set_password(const char *username, const char *password)
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
int user_has_password(const char *username)
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

int create_system_user(const char *username, const char *shell)
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
				/* User exists — still ensure group membership
				 * so they can connect to the mgmtd socket. */
				add_user_to_group(username, "stargazer");
				return 0;
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

int delete_system_user(const char *username)
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
int mgmtd_validate_password(const char *username, const char *password,
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

/* ── Admin command handlers ──────────────────────────────────────────────── */

int handle_admin_create(int client_fd, const char *user,
			const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED, "Requires 'admin' permission");
		return 0;
	}
	/* Payload: "username\nprofile\n" */
	if (!payload) {
		send_error(client_fd, SG_ERR_MISSING_ARG, "Missing username+profile");
		return 0;
	}
	char newuser[128] = {0}, newprof[128] = {0};
	const char *nl1 = strchr(payload, '\n');
	if (!nl1) {
		send_error(client_fd, SG_ERR_INVALID_ARG, "Bad format");
		return 0;
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
		return 0;
	}
	if (!sg_is_safe_id(newprof)) {
		send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid profile name");
		return 0;
	}

	/* Check profile exists */
	char *pdata = sg_db_get("system_admin-profile", newprof);
	if (!pdata) {
		send_error(client_fd, SG_ERR_PROFILE_NOT_FOUND, newprof);
		return 0;
	}
	free(pdata);

	/* Check user doesn't exist */
	char *udata = sg_db_get("system_admin", newuser);
	if (udata) {
		free(udata);
		send_error(client_fd, SG_ERR_ALREADY_EXISTS, newuser);
		return 0;
	}

	/* Create Linux user */
	if (create_system_user(newuser, "/sbin/stargazer-cli") != 0) {
		send_error(client_fd, SG_ERR_SYSTEM_FAIL, "create user failed");
		return 0;
	}

	/* Add to database */
	char cfgdata[256];
	snprintf(cfgdata, sizeof(cfgdata),
		 "profile=%s\nenforce-change-password=enable\n"
		 "enforce-password-policy=enable\n", newprof);
	if (sg_db_set("system_admin", newuser, cfgdata) != 0) {
		send_error(client_fd, SG_ERR_IO_FAIL, "config write failed");
		return 0;
	}

	if (g_debug_flags & SG_DBG_FLAG_AUTH)
		debug_buf_push("[AUTH-DBG] create user=%s result=ok\n",
			       newuser);
	char msg[CMD_BUF_SIZE];
	snprintf(msg, sizeof(msg), "User '%s' created with profile '%s'", newuser, newprof);
	send_ok_audited(client_fd, msg, NULL,
			user, "admin_create", newuser);
	return 0;
}

int handle_admin_delete(int client_fd, const char *user,
			const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED, "Requires 'admin' permission");
		return 0;
	}
	if (!payload) {
		send_error(client_fd, SG_ERR_MISSING_ARG, "Missing username");
		return 0;
	}
	char target[128] = {0};
	snprintf(target, sizeof(target), "%s", payload);
	size_t tlen = strlen(target);
	if (tlen > 0 && target[tlen-1] == '\n') target[--tlen] = '\0';

	if (!sg_is_safe_id(target)) {
		send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid username");
		return 0;
	}

	/* Check builtin */
	char *existing = sg_db_get("system_admin", target);
	if (!existing) {
		send_error(client_fd, SG_ERR_USER_NOT_FOUND, target);
		return 0;
	}
	char bi[VALBUFSZ];
	extract_val(existing, "builtin", bi, sizeof(bi));
	if (strcmp(bi, "yes") == 0) {
		free(existing);
		send_error(client_fd, SG_ERR_BUILTIN, "Cannot delete built-in admin");
		return 0;
	}
	free(existing);

	/* Block self-deletion */
	if (strcmp(target, user) == 0) {
		send_error(client_fd, SG_ERR_IN_USE,
			   "Cannot delete your own account");
		return 0;
	}

	/* Check referential integrity */
	{
		char ref_err[SG_EXTRA_MAX];
		if (check_references("system_admin", target,
				     ref_err, sizeof(ref_err)) != 0) {
			send_error(client_fd, SG_ERR_IN_USE, ref_err);
			return 0;
		}
	}

	sg_db_del("system_admin", target);
	delete_system_user(target);
	admin_notify_change(target);

	if (g_debug_flags & SG_DBG_FLAG_AUTH)
		debug_buf_push("[AUTH-DBG] delete user=%s result=ok\n",
			       target);
	char msg[CMD_BUF_SIZE];
	snprintf(msg, sizeof(msg), "User '%s' deleted", target);
	send_ok_audited(client_fd, msg, NULL,
			user, "admin_delete", target);
	return 0;
}

int handle_admin_set_pw(int client_fd, const char *user,
			const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;
	/* Payload: "username\npassword\n" */
	if (!payload) {
		send_error(client_fd, SG_ERR_MISSING_ARG, "Missing username+password");
		return 0;
	}
	char target[128] = {0}, pw[256] = {0};
	const char *nl1 = strchr(payload, '\n');
	if (!nl1) {
		send_error(client_fd, SG_ERR_INVALID_ARG, "Bad format");
		return 0;
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
		return 0;
	}

	/* Permission: admin can set anyone's password,
	 * regular user can only set their own */
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin") && strcmp(user, target) != 0) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Can only change your own password");
		explicit_bzero(pw, sizeof(pw));
		return 0;
	}

	/* Validate against password policy */
	const char *pw_reason = NULL;
	int pw_rc = mgmtd_validate_password(target, pw, NULL, &pw_reason);
	if (pw_rc > 0) {
		explicit_bzero(pw, sizeof(pw));
		send_error(client_fd, SG_ERR_POLICY_FAIL,
			   pw_reason ? pw_reason : "Policy violation");
		return 0;
	}

	if (set_password(target, pw) != 0) {
		explicit_bzero(pw, sizeof(pw));
		mgmt_log("ERROR", "set_password failed for %s: %s",
			 target, strerror(errno));
		send_error(client_fd, SG_ERR_SYSTEM_FAIL, "Password update failed");
		return 0;
	}
	explicit_bzero(pw, sizeof(pw));
	admin_notify_change(target);
	if (g_debug_flags & SG_DBG_FLAG_AUTH)
		debug_buf_push("[AUTH-DBG] set_password user=%s result=ok\n",
			       target);
	send_ok_audited(client_fd, "Password updated", NULL,
			user, "admin_password_set", target);
	return 0;
}

int handle_admin_set_enf(int client_fd, const char *user,
			 const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED, "Requires 'admin' permission");
		return 0;
	}
	/* Payload: "username\nenable|disable\n" */
	if (!payload) {
		send_error(client_fd, SG_ERR_MISSING_ARG, "Missing args");
		return 0;
	}
	char target[128] = {0}, val[32] = {0};
	const char *nl1 = strchr(payload, '\n');
	if (!nl1) { send_error(client_fd, SG_ERR_INVALID_ARG, "Bad format"); return 0; }
	size_t ulen = (size_t)(nl1 - payload);
	if (ulen >= sizeof(target)) ulen = sizeof(target) - 1;
	memcpy(target, payload, ulen);
	snprintf(val, sizeof(val), "%s", nl1 + 1);
	size_t vlen = strlen(val);
	if (vlen > 0 && val[vlen-1] == '\n') val[--vlen] = '\0';

	if (!sg_is_safe_id(target)) {
		send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid username");
		return 0;
	}
	if (strcmp(val, "enable") != 0 && strcmp(val, "disable") != 0) {
		send_error(client_fd, SG_ERR_INVALID_VAL,
			   "Value must be 'enable' or 'disable'");
		return 0;
	}

	char *existing = sg_db_get("system_admin", target);
	if (!existing) {
		send_error(client_fd, SG_ERR_USER_NOT_FOUND, target);
		return 0;
	}

	/* Rebuild data with updated enforce flag */
	size_t elen = strlen(existing);
	char *newdata = malloc(elen + 64);
	if (!newdata) { free(existing); send_error(client_fd, SG_ERR_INTERNAL, NULL); return 0; }

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
	admin_notify_change(target);
	send_ok_audited(client_fd, "Enforce policy updated", NULL,
			user, "admin_set_enforce", target);
	return 0;
}

int handle_admin_check_pw(int client_fd, const char *user,
			  const char *payload, const sg_request_hdr_t *hdr)
{
	(void)user;
	(void)hdr;
	/* Validate password against policy without setting it.
	 * Payload: "username\npassword[\nenforce_override]" */
	if (!payload) {
		send_error(client_fd, SG_ERR_MISSING_ARG,
			   "Missing username+password");
		return 0;
	}
	char chk_user[128] = {0}, chk_pw[256] = {0};
	char chk_enforce[32] = {0};
	const char *nl1 = strchr(payload, '\n');
	if (!nl1) {
		send_error(client_fd, SG_ERR_INVALID_ARG, "Bad format");
		return 0;
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
		return 0;
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
	return 0;
}

int handle_admin_lock_pw(int client_fd, const char *user,
			 const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;
	/* Lock (invalidate) an admin's password.  Payload: "username\n" */
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED, NULL);
		return 0;
	}
	if (!payload) {
		send_error(client_fd, SG_ERR_MISSING_ARG, "Missing username");
		return 0;
	}
	char lock_target[128] = {0};
	snprintf(lock_target, sizeof(lock_target), "%s", payload);
	size_t llen = strlen(lock_target);
	if (llen > 0 && lock_target[llen - 1] == '\n')
		lock_target[--llen] = '\0';

	if (!sg_is_safe_id(lock_target)) {
		send_error(client_fd, SG_ERR_INVALID_ARG, "Invalid username");
		return 0;
	}

	if (lock_password(lock_target) != 0) {
		send_error(client_fd, SG_ERR_SYSTEM_FAIL,
			   "Failed to lock password");
		return 0;
	}
	admin_notify_change(lock_target);
	if (g_debug_flags & SG_DBG_FLAG_AUTH)
		debug_buf_push("[AUTH-DBG] lock_password user=%s result=ok\n",
			       lock_target);
	send_ok_audited(client_fd, "Password locked", NULL,
			user, "admin_password_locked", lock_target);
	return 0;
}
