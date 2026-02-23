/* SPDX-License-Identifier: MIT */
/*
 * cli_ipc.h — IPC client for Stargazer CLI
 *
 * Provides communication with stargazer-mgmtd over Unix domain socket.
 * Connection is re-established per request (mgmtd is request-response).
 */

#ifndef CLI_IPC_H
#define CLI_IPC_H

#include "../mgmtd/stargazer_ipc.h"
#include <stddef.h>

struct ipc_response {
	uint32_t status;
	char     extra[SG_EXTRA_MAX];
	char    *payload;        /* heap-allocated, caller must free */
	size_t   payload_len;
};

/* Initialize IPC client with the authenticated username. */
int ipc_init(const char *username);

/* Send request and receive response. Returns 0 on SG_OK, -1 on conn error.
 * On success/error, resp is populated. Caller must free resp->payload. */
int ipc_send(uint32_t cmd, const char *payload, size_t payload_len,
	     struct ipc_response *resp);

/* Convenience: send with null-terminated string payload. */
int ipc_send_str(uint32_t cmd, const char *payload_str,
		 struct ipc_response *resp);

/* Check if mgmtd socket exists. */
int ipc_available(void);

/* Free response payload if allocated. */
void ipc_resp_free(struct ipc_response *resp);

/* Fetch and print buffered mgmtd/auth debug traces (if active). */
void ipc_fetch_debug(void);

#endif /* CLI_IPC_H */
