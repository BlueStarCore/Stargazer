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

	return stream_exec(client_fd,
		(const char *[]){"traceroute", "-m", "20", "-w", "2",
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
	const char *argv[] = {"nslookup", target, NULL};
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
