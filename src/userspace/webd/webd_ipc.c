/* SPDX-License-Identifier: MIT */
/*
 * webd_ipc.c — IPC client for stargazer-mgmtd
 *
 * Adapted from logind_ipc() in stargazer-logind.c.
 * Each call opens a fresh AF_UNIX socket, sends request, reads response.
 * Thread-safe: no shared state, each call is self-contained.
 */

#define _GNU_SOURCE
#include "webd_ipc.h"
#include "stargazer_ipc.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define STREAM_TIMEOUT_DEFAULT 30

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

/*
 * Open a connection to mgmtd and send a request header + payload.
 * Returns the connected fd on success, -1 on failure.
 */
static int ipc_connect_and_send(uint32_t cmd, const char *username,
				uint64_t session_tag, const char *payload,
				size_t plen)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) return -1;

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SG_MGMTD_SOCK);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	sg_request_hdr_t req;
	memset(&req, 0, sizeof(req));
	req.magic       = SG_MSG_MAGIC;
	req.version     = SG_MSG_VERSION;
	req.cmd         = cmd;
	req.payload_len = (uint32_t)plen;
	req.session_tag = session_tag;
	if (username)
		snprintf(req.username, sizeof(req.username), "%s", username);

	if (safe_write(fd, &req, sizeof(req)) < 0) {
		close(fd);
		return -1;
	}
	if (plen > 0 && safe_write(fd, payload, plen) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * Read a single response from an already-connected fd.
 * Fills resp fields. Returns 0 on success, -1 on transport failure.
 */
static int ipc_read_response(int fd, webd_ipc_response_t *resp)
{
	sg_response_hdr_t rhdr;
	if (safe_read(fd, &rhdr, sizeof(rhdr)) < (ssize_t)sizeof(rhdr))
		return -1;
	if (rhdr.magic != SG_MSG_MAGIC)
		return -1;

	resp->status = rhdr.status;
	memcpy(resp->extra, rhdr.extra, sizeof(resp->extra));
	resp->extra[sizeof(resp->extra) - 1] = '\0';

	resp->payload = NULL;
	resp->payload_len = 0;

	if (rhdr.payload_len > 0 && rhdr.payload_len <= SG_RESPONSE_MAX) {
		resp->payload = malloc(rhdr.payload_len + 1);
		if (!resp->payload) return -1;
		if (safe_read(fd, resp->payload, rhdr.payload_len) <
		    (ssize_t)rhdr.payload_len) {
			free(resp->payload);
			resp->payload = NULL;
			return -1;
		}
		resp->payload[rhdr.payload_len] = '\0';
		resp->payload_len = rhdr.payload_len;
	}

	return 0;
}

int webd_ipc_send(uint32_t cmd, const char *username,
		  uint64_t session_tag, const char *payload,
		  webd_ipc_response_t *resp)
{
	resp->status = SG_ERR_SYSTEM_FAIL;
	resp->extra[0] = '\0';
	resp->payload = NULL;
	resp->payload_len = 0;

	size_t plen = payload ? strlen(payload) : 0;
	if (plen > SG_PAYLOAD_MAX) return -1;

	int fd = ipc_connect_and_send(cmd, username, session_tag, payload, plen);
	if (fd < 0) return -1;

	int ret = ipc_read_response(fd, resp);
	close(fd);
	return ret;
}

int webd_ipc_send_stream(uint32_t cmd, const char *username,
			 uint64_t session_tag, const char *payload,
			 int timeout_sec, webd_ipc_response_t *resp)
{
	resp->status = SG_ERR_SYSTEM_FAIL;
	resp->extra[0] = '\0';
	resp->payload = NULL;
	resp->payload_len = 0;

	if (timeout_sec <= 0) timeout_sec = STREAM_TIMEOUT_DEFAULT;

	size_t plen = payload ? strlen(payload) : 0;
	if (plen > SG_PAYLOAD_MAX) return -1;

	int fd = ipc_connect_and_send(cmd, username, session_tag, payload, plen);
	if (fd < 0) return -1;

	/* Accumulate streaming chunks into a single buffer */
	char *buf = NULL;
	size_t buf_len = 0;
	size_t buf_cap = 0;
	time_t deadline = time(NULL) + timeout_sec;

	for (;;) {
		/* Poll with remaining timeout */
		int remaining = (int)(deadline - time(NULL));
		if (remaining <= 0) {
			resp->status = SG_OK;
			snprintf(resp->extra, sizeof(resp->extra), "timeout");
			break;
		}

		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int pr = poll(&pfd, 1, remaining * 1000);
		if (pr <= 0) {
			resp->status = SG_OK;
			snprintf(resp->extra, sizeof(resp->extra), "timeout");
			break;
		}

		webd_ipc_response_t chunk;
		memset(&chunk, 0, sizeof(chunk));
		if (ipc_read_response(fd, &chunk) != 0) {
			free(buf);
			close(fd);
			return -1;
		}

		/* Append chunk payload to buffer */
		if (chunk.payload && chunk.payload_len > 0) {
			size_t needed = buf_len + chunk.payload_len;
			if (needed >= buf_cap) {
				size_t new_cap = buf_cap ? buf_cap * 2 : 4096;
				while (new_cap <= needed) new_cap *= 2;
				char *tmp = realloc(buf, new_cap);
				if (!tmp) {
					free(chunk.payload);
					free(buf);
					close(fd);
					return -1;
				}
				buf = tmp;
				buf_cap = new_cap;
			}
			memcpy(buf + buf_len, chunk.payload, chunk.payload_len);
			buf_len += chunk.payload_len;
		}

		int more = (chunk.extra[0] == '+');
		resp->status = chunk.status;
		memcpy(resp->extra, chunk.extra, sizeof(resp->extra));
		free(chunk.payload);

		if (!more) break;
	}

	close(fd);

	/* NUL-terminate the accumulated buffer */
	if (buf) {
		char *tmp = realloc(buf, buf_len + 1);
		if (tmp) {
			buf = tmp;
			buf[buf_len] = '\0';
		}
	}
	resp->payload = buf;
	resp->payload_len = buf_len;

	return 0;
}

void webd_ipc_resp_free(webd_ipc_response_t *resp)
{
	if (resp) {
		free(resp->payload);
		resp->payload = NULL;
		resp->payload_len = 0;
	}
}
