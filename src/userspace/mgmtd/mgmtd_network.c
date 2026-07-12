/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_network.c — Network diagnostic handlers for stargazer-mgmtd
 *
 * Extracted from stargazer-mgmtd.c to keep the monolith manageable.
 * Contains:
 *   - NET_PING, NET_TRACEROUTE, NET_NSLOOKUP, NET_ARPING handlers
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mgmtd_internal.h"
#include "mgmtd_apply.h"

/* ── Network diagnostic handlers ─────────────────────────────────────────── */

int handle_net_ping(int client_fd, const char *user,
		    const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'monitor' permission");
		return 0;
	}
	char target[256];
	extract_val(payload, "target", target, sizeof(target));
	if (!target[0]) {
		send_error(client_fd, SG_ERR_MISSING_ARG, "Missing target");
		return 0;
	}
	if (!sg_is_net_target(target)) {
		send_error(client_fd, SG_ERR_INVALID_ARG,
			   "Invalid target (use IPv4/IPv6 address or hostname)");
		return 0;
	}

	return stream_exec(client_fd,
		(const char *[]){"ping", "-c", "4", "-W", "2",
				 target, NULL});
}

int handle_net_traceroute(int client_fd, const char *user,
			  const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'monitor' permission");
		return 0;
	}
	char target[256];
	extract_val(payload, "target", target, sizeof(target));
	if (!target[0]) {
		send_error(client_fd, SG_ERR_MISSING_ARG, "Missing target");
		return 0;
	}
	if (!sg_is_net_target(target)) {
		send_error(client_fd, SG_ERR_INVALID_ARG,
			   "Invalid target (use IPv4/IPv6 address or hostname)");
		return 0;
	}

	/* -m 14: 14 hops × 2 s/hop = 28 s max, 2 s below the 30 s webd IPC timeout */
	return stream_exec(client_fd,
		(const char *[]){"traceroute", "-m", "14", "-w", "2",
				 target, NULL});
}

int handle_net_nslookup(int client_fd, const char *user,
			const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'monitor' permission");
		return 0;
	}
	char target[256];
	extract_val(payload, "target", target, sizeof(target));
	if (!target[0]) {
		send_error(client_fd, SG_ERR_MISSING_ARG, "Missing target");
		return 0;
	}
	if (!sg_is_net_target(target)) {
		send_error(client_fd, SG_ERR_INVALID_ARG,
			   "Invalid target (use hostname or IP address)");
		return 0;
	}
	/* Wrap with timeout(1) so a non-resolving host returns in ≤ 5 s */
	const char *argv[] = {"timeout", "5", "nslookup", target, NULL};
	char *out = safe_exec(argv);
	if (out) {
		send_ok(client_fd, NULL, out);
		free(out);
	} else {
		send_error(client_fd, SG_ERR_SYSTEM_FAIL,
			   "Failed to execute nslookup");
	}
	return 0;
}

int handle_net_arping(int client_fd, const char *user,
		      const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "monitor")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'monitor' permission");
		return 0;
	}
	char target[256], iface[64];
	extract_val(payload, "target", target, sizeof(target));
	extract_val(payload, "iface", iface, sizeof(iface));
	if (!target[0]) {
		send_error(client_fd, SG_ERR_MISSING_ARG, "Missing target");
		return 0;
	}
	if (!sg_is_net_target(target)) {
		send_error(client_fd, SG_ERR_INVALID_ARG,
			   "Invalid target (use IPv4/IPv6 address or hostname)");
		return 0;
	}
	if (iface[0] && !sg_is_iface_name(iface)) {
		send_error(client_fd, SG_ERR_INVALID_ARG,
			   "Invalid interface name");
		return 0;
	}

	if (iface[0])
		return stream_exec(client_fd,
			(const char *[]){"arping", "-c", "4",
					 "-w", "2", "-I", iface,
					 target, NULL});
	else
		return stream_exec(client_fd,
			(const char *[]){"arping", "-c", "4",
					 "-w", "2", target, NULL});
}

/* Upper bound on tokens in an `execute system` command line (argv slots,
 * including the NULL terminator). 4096-byte payloads cannot hold more
 * meaningful tokens than this in practice. */
#define SYS_EXEC_MAX_ARGS 64

/*
 * sys_exec_resolvable — true if `cmd` names an executable mgmtd can run.
 *
 * stream_exec()'s grandchild calls execvp() and, on failure, _exit(127)
 * silently — the stream still ends with send_ok, so a missing binary looks
 * like a command that produced no output. We pre-resolve the same way
 * execvp() does (literal path if it contains '/', else search PATH) so a
 * missing command yields an honest error instead of silence.
 */
static int sys_exec_resolvable(const char *cmd)
{
	if (strchr(cmd, '/'))
		return access(cmd, X_OK) == 0;

	const char *path = getenv("PATH");
	if (!path || !*path)
		path = "/bin:/sbin:/usr/bin:/usr/sbin";

	for (const char *p = path; *p; ) {
		const char *colon = strchr(p, ':');
		size_t dlen = colon ? (size_t)(colon - p) : strlen(p);
		char buf[512];
		if (dlen > 0 && dlen + 1 + strlen(cmd) + 1 <= sizeof(buf)) {
			memcpy(buf, p, dlen);
			buf[dlen] = '/';
			memcpy(buf + dlen + 1, cmd, strlen(cmd) + 1);
			if (access(buf, X_OK) == 0)
				return 1;
		}
		if (!colon)
			break;
		p = colon + 1;
	}
	return 0;
}

/*
 * handle_sys_exec — run an arbitrary system binary as root, FortiOS
 * `fnsysctl`-style. Admin-only.
 *
 * Security model (the firewall runs this as root, so this is deliberate):
 *   - Requires the 'admin' permission, re-checked here server-side; the
 *     CLI's own permission gate is advisory and a raw IPC client bypasses
 *     it, so mgmtd must not trust it.
 *   - The command line is split on whitespace into an argv[] array and
 *     handed to execvp() inside stream_exec(). There is NO shell, so ';',
 *     '|', '&&', '$()', backticks and redirects are passed verbatim as
 *     literal arguments — they cannot chain or inject further commands.
 *   - Quoting/escaping is NOT honored: each whitespace-separated word is
 *     exactly one argv element (an argument containing a space is not
 *     expressible — acceptable for a diagnostic shell-out).
 *   - Every invocation is audit-logged with the full command line BEFORE
 *     it runs, because stream_exec() double-forks and detaches the child.
 */
int handle_sys_exec(int client_fd, const char *user,
		    const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;

	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'admin' permission");
		return 0;
	}

	char cmdline[SG_PAYLOAD_MAX];
	extract_val(payload, "cmd", cmdline, sizeof(cmdline));
	if (!cmdline[0]) {
		send_error(client_fd, SG_ERR_MISSING_ARG,
			   "Missing command (usage: execute system <binary> [args...])");
		return 0;
	}

	/* Tokenize in place on spaces/tabs into a NULL-terminated argv[]. */
	char *argv[SYS_EXEC_MAX_ARGS];
	int argc = 0;
	char *p = cmdline;
	while (*p && argc < SYS_EXEC_MAX_ARGS - 1) {
		while (*p == ' ' || *p == '\t')
			p++;
		if (!*p)
			break;
		argv[argc++] = p;
		while (*p && *p != ' ' && *p != '\t')
			p++;
		if (*p)
			*p++ = '\0';
	}
	argv[argc] = NULL;

	if (argc == 0) {
		send_error(client_fd, SG_ERR_MISSING_ARG, "Empty command");
		return 0;
	}

	/*
	 * No silent truncation: if the loop stopped at the argv cap with tokens
	 * still unparsed, refuse rather than run a command with dropped args.
	 */
	while (*p == ' ' || *p == '\t')
		p++;
	if (*p) {
		send_error(client_fd, SG_ERR_INVALID_ARG,
			   "Too many arguments (max 63)");
		return 0;
	}

	/* Audit the exact argv before detaching to run it. */
	char joined[256];
	size_t off = 0;
	for (int i = 0; i < argc && off < sizeof(joined) - 1; i++) {
		int n = snprintf(joined + off, sizeof(joined) - off,
				 "%s%s", i ? " " : "", argv[i]);
		if (n < 0)
			break;
		off += (size_t)n;
	}
	audit_log(user, "system_exec", joined);

	/* Honest failure: report a missing binary instead of streaming nothing. */
	if (!sys_exec_resolvable(argv[0])) {
		char msg[128];
		snprintf(msg, sizeof(msg), "%s: command not found", argv[0]);
		send_error(client_fd, SG_ERR_NOT_FOUND, msg);
		return 0;
	}

	return stream_exec(client_fd, (const char *const *)argv);
}
