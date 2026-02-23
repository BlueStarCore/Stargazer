/* SPDX-License-Identifier: MIT */
/*
 * cli_ipc.c — IPC client library for Stargazer CLI
 *
 * Provides a C API for CLI programs to communicate with stargazer-mgmtd
 * over a Unix domain socket. Each ipc_send() opens a fresh connection
 * because mgmtd closes the socket after every response.
 *
 * Refactored from stargazer-ipc-cli.c (the shell-facing binary) into a
 * reusable library for the native C CLI.
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_ipc.h"
#include "cli_debug.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

/* ── Static state ──────────────────────────────────────────────────────── */

static char ipc_username[SG_USERNAME_MAX];

/* ── Debug helpers ─────────────────────────────────────────────────────── */

static int ipc_dbg(void)
{
	return dbg_enabled() &&
	       strcmp(dbg_get("cli_debug", "0"), "1") == 0;
}

static const char *cmd_name(uint32_t cmd)
{
	switch (cmd) {
	case SG_CMD_CFG_GET:        return "CFG_GET";
	case SG_CMD_CFG_LIST:       return "CFG_LIST";
	case SG_CMD_CFG_LIST_TYPES: return "CFG_LIST_TYPES";
	case SG_CMD_CFG_SET:        return "CFG_SET";
	case SG_CMD_CFG_DEL:        return "CFG_DEL";
	case SG_CMD_CFG_APPLY:      return "CFG_APPLY";
	case SG_CMD_ADMIN_CREATE:   return "ADMIN_CREATE";
	case SG_CMD_ADMIN_DELETE:   return "ADMIN_DELETE";
	case SG_CMD_ADMIN_SET_PW:   return "ADMIN_SET_PW";
	case SG_CMD_ADMIN_SET_ENF:  return "ADMIN_SET_ENF";
	case SG_CMD_ADMIN_CHECK_PW: return "ADMIN_CHECK_PW";
	case SG_CMD_ADMIN_LOCK_PW:  return "ADMIN_LOCK_PW";
	case SG_CMD_SESSION_REV:    return "SESSION_REV";
	case SG_CMD_SESSION_BUMP:   return "SESSION_BUMP";
	case SG_CMD_COMMIT:         return "COMMIT";
	case SG_CMD_REVISIONS:      return "REVISIONS";
	case SG_CMD_ROLLBACK:       return "ROLLBACK";
	case SG_CMD_SYS_POWEROFF:   return "SYS_POWEROFF";
	case SG_CMD_SYS_REBOOT:     return "SYS_REBOOT";
	case SG_CMD_SHOW_STATUS:    return "SHOW_STATUS";
	case SG_CMD_SHOW_IFACES:    return "SHOW_IFACES";
	case SG_CMD_SHOW_ROUTES:    return "SHOW_ROUTES";
	case SG_CMD_SHOW_CONFIG:    return "SHOW_CONFIG";
	case SG_CMD_SHOW_STATS:     return "SHOW_STATS";
	case SG_CMD_WHOAMI:         return "WHOAMI";
	case SG_CMD_PING:           return "PING";
	case SG_CMD_DEBUG_FETCH:    return "DEBUG_FETCH";
	default:                    return "?";
	}
}

static const char *status_name(uint32_t s)
{
	switch (s) {
	case SG_OK:                    return "OK";
	case SG_ERR_INVALID_CMD:       return "INVALID_CMD";
	case SG_ERR_INVALID_ARG:       return "INVALID_ARG";
	case SG_ERR_INVALID_VAL:       return "INVALID_VAL";
	case SG_ERR_MISSING_ARG:       return "MISSING_ARG";
	case SG_ERR_POLICY_FAIL:       return "POLICY_FAIL";
	case SG_ERR_PERM_DENIED:       return "PERM_DENIED";
	case SG_ERR_AUTH_FAIL:         return "AUTH_FAIL";
	case SG_ERR_LOCKED:            return "LOCKED";
	case SG_ERR_PROFILE_DENY:      return "PROFILE_DENY";
	case SG_ERR_NOT_FOUND:         return "NOT_FOUND";
	case SG_ERR_USER_NOT_FOUND:    return "USER_NOT_FOUND";
	case SG_ERR_PROFILE_NOT_FOUND: return "PROFILE_NOT_FOUND";
	case SG_ERR_ENTRY_NOT_FOUND:   return "ENTRY_NOT_FOUND";
	case SG_ERR_ALREADY_EXISTS:    return "ALREADY_EXISTS";
	case SG_ERR_IN_USE:            return "IN_USE";
	case SG_ERR_BUILTIN:           return "BUILTIN";
	case SG_ERR_SYSTEM_FAIL:       return "SYSTEM_FAIL";
	case SG_ERR_IO_FAIL:           return "IO_FAIL";
	case SG_ERR_DISK_FULL:         return "DISK_FULL";
	case SG_ERR_INTERNAL:          return "INTERNAL";
	default:                       return "?";
	}
}

/* ── I/O helpers ───────────────────────────────────────────────────────── */

static ssize_t safe_read(int fd, void *buf, size_t len)
{
	size_t done = 0;
	while (done < len) {
		ssize_t n = read(fd, (char *)buf + done, len - done);
		if (n <= 0) {
			if (n < 0 && errno == EINTR)
				continue;
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
			if (n < 0 && errno == EINTR)
				continue;
			return -1;
		}
		done += (size_t)n;
	}
	return (ssize_t)done;
}

/* ── Public API ────────────────────────────────────────────────────────── */

int ipc_init(const char *username)
{
	if (!username || !username[0])
		return -1;

	snprintf(ipc_username, sizeof(ipc_username), "%s", username);
	return 0;
}

int ipc_send(uint32_t cmd, const char *payload, size_t payload_len,
	     struct ipc_response *resp)
{
	int ret = -1;

	if (!resp)
		return -1;

	memset(resp, 0, sizeof(*resp));

	if (payload_len > SG_PAYLOAD_MAX)
		return -1;

	/* Open a new connection for each request */
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SG_MGMTD_SOCK);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto out;

	/* Build and send request header */
	sg_request_hdr_t hdr;
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic       = SG_MSG_MAGIC;
	hdr.version     = SG_MSG_VERSION;
	hdr.cmd         = cmd;
	snprintf(hdr.username, sizeof(hdr.username), "%s", ipc_username);
	hdr.payload_len = (uint32_t)payload_len;

	/* Pass debug flags to mgmtd so it knows to buffer traces */
	if (dbg_enabled()) {
		if (strcmp(dbg_get("mgmtd_debug", "0"), "1") == 0)
			hdr.debug_flags |= 0x01;
		if (strcmp(dbg_get("auth_admin", "0"), "1") == 0)
			hdr.debug_flags |= 0x02;
	}

	if (safe_write(fd, &hdr, sizeof(hdr)) < 0)
		goto out;

	if (payload_len > 0 && payload) {
		if (safe_write(fd, payload, payload_len) < 0)
			goto out;
	}

	/* IPC debug trace: request sent (suppress for DEBUG_FETCH) */
	if (ipc_dbg() && cmd != SG_CMD_DEBUG_FETCH)
		fprintf(stderr, "[IPC-DBG] -> cmd=%u(%s) len=%u\n",
			cmd, cmd_name(cmd), (unsigned)payload_len);

	/* Read response header */
	sg_response_hdr_t rhdr;
	ssize_t n = safe_read(fd, &rhdr, sizeof(rhdr));
	if (n < (ssize_t)sizeof(rhdr))
		goto out;

	if (rhdr.magic != SG_MSG_MAGIC)
		goto out;

	/* Populate response struct */
	resp->status = rhdr.status;
	memcpy(resp->extra, rhdr.extra, sizeof(resp->extra));
	resp->extra[sizeof(resp->extra) - 1] = '\0';

	/* Read response payload */
	if (rhdr.payload_len > 0 && rhdr.payload_len <= SG_PAYLOAD_MAX) {
		resp->payload = malloc(rhdr.payload_len + 1);
		if (!resp->payload)
			goto out;

		n = safe_read(fd, resp->payload, rhdr.payload_len);
		if (n < 0) {
			free(resp->payload);
			resp->payload = NULL;
			goto out;
		}
		resp->payload[n]  = '\0';
		resp->payload_len = (size_t)n;
	}

	/* IPC debug trace: response received (suppress for DEBUG_FETCH) */
	if (ipc_dbg() && cmd != SG_CMD_DEBUG_FETCH)
		fprintf(stderr, "[IPC-DBG] <- status=%u(%s) len=%u\n",
			resp->status, status_name(resp->status),
			(unsigned)resp->payload_len);

	ret = 0;

out:
	close(fd);
	return ret;
}

int ipc_send_str(uint32_t cmd, const char *payload_str,
		 struct ipc_response *resp)
{
	size_t len = payload_str ? strlen(payload_str) : 0;
	return ipc_send(cmd, payload_str, len, resp);
}

int ipc_available(void)
{
	return access(SG_MGMTD_SOCK, F_OK) == 0;
}

void ipc_resp_free(struct ipc_response *resp)
{
	if (resp && resp->payload) {
		free(resp->payload);
		resp->payload     = NULL;
		resp->payload_len = 0;
	}
}

void ipc_fetch_debug(void)
{
	if (!dbg_enabled())
		return;
	if (strcmp(dbg_get("mgmtd_debug", "0"), "1") != 0 &&
	    strcmp(dbg_get("auth_admin", "0"), "1") != 0 &&
	    strcmp(dbg_get("auth_user", "0"), "1") != 0)
		return;

	struct ipc_response resp;
	if (ipc_send(SG_CMD_DEBUG_FETCH, NULL, 0, &resp) == 0) {
		if (resp.payload && resp.payload_len > 0)
			fprintf(stderr, "%s", resp.payload);
		ipc_resp_free(&resp);
	}
}
