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

/* Session tag management.
 * Tag is sent in every IPC request header for server-side validation. */
void     ipc_set_session_tag(uint64_t tag);
uint64_t ipc_get_session_tag(void);
int      ipc_session_expired(void);
void     ipc_clear_session_expired(void);

/* Re-acquire a session tag after expiration. Returns 0 on success, -1 on error.
 * Clears the session-expired flag and replaces the stored tag. */
int      ipc_reacquire_tag(void);

/* Send request and receive response. Returns 0 on SG_OK, -1 on conn error.
 * On success/error, resp is populated. Caller must free resp->payload. */
int ipc_send(uint32_t cmd, const char *payload, size_t payload_len,
	     struct ipc_response *resp);

/* Convenience: send with null-terminated string payload. */
int ipc_send_str(uint32_t cmd, const char *payload_str,
		 struct ipc_response *resp);

/* Send request and receive streaming response.
 * on_chunk is called for each chunk; final status is returned.
 * Returns SG_OK on success, or SG_ERR_* / -1 on error. */
int ipc_send_stream(uint32_t cmd, const char *payload_str,
		    void (*on_chunk)(const char *data, size_t len));

/* Set the terminal fd used for Ctrl+C detection during streaming/polling.
 * Call once at startup with the readline tty fd. */
void ipc_set_interrupt_fd(int fd);

/* Enter/leave interruptible mode for polling loops (e.g. firmware upgrade).
 * ipc_send_stream() handles this internally; these are for manual loops. */
void ipc_install_interrupt_handler(void);
void ipc_restore_interrupt_handler(void);
int  ipc_stream_interrupted(void);
void ipc_clear_interrupt(void);

/* Check for 'q'/'Q' or Ctrl+C on the tty (for interactive monitors).
 * Unlike ipc_stream_interrupted() which only handles Ctrl+C, this also
 * treats 'q' as a quit signal. Sets the interrupted flag on match. */
int  ipc_check_quit_or_ctrl_c(void);

/* Check if mgmtd socket exists. */
int ipc_available(void);

/* Free response payload if allocated. */
void ipc_resp_free(struct ipc_response *resp);

/* Fetch and print buffered mgmtd/auth debug traces (if active). */
void ipc_fetch_debug(void);

#endif /* CLI_IPC_H */
