/* SPDX-License-Identifier: MIT */
/*
 * webd_ipc.h — IPC client for stargazer-mgmtd
 *
 * Adapted from logind_ipc() pattern. Each call opens a fresh AF_UNIX
 * socket to mgmtd, sends a request, reads the response, and closes.
 */

#ifndef WEBD_IPC_H
#define WEBD_IPC_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
	uint32_t status;
	char     extra[256];
	char    *payload;        /* heap-allocated, caller frees via webd_ipc_resp_free() */
	size_t   payload_len;
} webd_ipc_response_t;

/*
 * Send IPC request to mgmtd and receive response.
 * Returns 0 on successful IPC exchange, -1 on transport failure.
 */
int  webd_ipc_send(uint32_t cmd, const char *username,
		   uint64_t session_tag, const char *payload,
		   webd_ipc_response_t *resp);

/*
 * Send IPC request and accumulate streaming response.
 * Streaming protocol: response extra[0]=='+' means more data coming.
 * Accumulates all chunks into resp->payload.
 * timeout_sec: max seconds to wait for all chunks (0 = 30s default).
 * Returns 0 on success, -1 on transport failure.
 */
int  webd_ipc_send_stream(uint32_t cmd, const char *username,
			  uint64_t session_tag, const char *payload,
			  int timeout_sec, webd_ipc_response_t *resp);

void webd_ipc_resp_free(webd_ipc_response_t *resp);

#endif /* WEBD_IPC_H */
