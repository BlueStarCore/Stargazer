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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

/* ── Static state ──────────────────────────────────────────────────────── */

static char ipc_username[SG_USERNAME_MAX];

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

	if (safe_write(fd, &hdr, sizeof(hdr)) < 0)
		goto out;

	if (payload_len > 0 && payload) {
		if (safe_write(fd, payload, payload_len) < 0)
			goto out;
	}

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
