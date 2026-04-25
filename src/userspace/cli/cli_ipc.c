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
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

/* ── Static state ──────────────────────────────────────────────────────── */

static char     ipc_username[SG_USERNAME_MAX];
static uint64_t ipc_session_tag;
static int      g_session_expired;

/* ── Poll-based Ctrl+C interrupt detection ────────────────────────────── */

static int            g_interrupt_fd = -1;   /* tty fd for Ctrl+C reads  */
static int            g_stream_interrupted;
static struct termios g_saved_tty;
static int            g_tty_saved;

void ipc_set_interrupt_fd(int fd)
{
	g_interrupt_fd = fd;
}

/* Put the tty in raw mode so Ctrl+C (0x03) is readable immediately. */
static void interrupt_raw_on(void)
{
	g_tty_saved = 0;
	if (g_interrupt_fd < 0)
		return;
	struct termios t;
	if (tcgetattr(g_interrupt_fd, &g_saved_tty) != 0)
		return;
	g_tty_saved = 1;
	t = g_saved_tty;
	t.c_lflag &= ~(unsigned)(ICANON | ECHO | ISIG);
	t.c_cc[VMIN] = 0;
	t.c_cc[VTIME] = 0;
	tcsetattr(g_interrupt_fd, TCSANOW, &t);
}

static void interrupt_raw_off(void)
{
	if (g_tty_saved && g_interrupt_fd >= 0)
		tcsetattr(g_interrupt_fd, TCSANOW, &g_saved_tty);
	g_tty_saved = 0;
}

/* Non-blocking drain: read any pending bytes and check for 0x03. */
static int check_ctrl_c(void)
{
	if (g_interrupt_fd < 0)
		return 0;
	struct pollfd pfd;
	pfd.fd = g_interrupt_fd;
	pfd.events = POLLIN;
	while (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN)) {
		char c;
		if (read(g_interrupt_fd, &c, 1) != 1)
			break;
		if (c == 3) { /* Ctrl+C */
			g_stream_interrupted = 1;
			return 1;
		}
	}
	return 0;
}

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
	case SG_CMD_SESSION_TAG_NEW: return "SESSION_TAG_NEW";
	case SG_CMD_SESSION_TAG_DEL: return "SESSION_TAG_DEL";
	case SG_CMD_COMMIT:         return "COMMIT";
	case SG_CMD_REVISIONS:      return "REVISIONS";
	case SG_CMD_ROLLBACK:       return "ROLLBACK";
	case SG_CMD_SYS_POWEROFF:   return "SYS_POWEROFF";
	case SG_CMD_SYS_REBOOT:     return "SYS_REBOOT";
	case SG_CMD_UPGRADE_START:      return "UPGRADE_START";
	case SG_CMD_UPGRADE_STATUS:    return "UPGRADE_STATUS";
	case SG_CMD_UPGRADE_PROGRESS:  return "UPGRADE_PROGRESS";
	case SG_CMD_UPGRADE_CANCEL:    return "UPGRADE_CANCEL";
	case SG_CMD_NET_PING:       return "NET_PING";
	case SG_CMD_NET_TRACEROUTE: return "NET_TRACEROUTE";
	case SG_CMD_NET_NSLOOKUP:  return "NET_NSLOOKUP";
	case SG_CMD_NET_ARPING:    return "NET_ARPING";
	case SG_CMD_SHOW_STATUS:    return "SHOW_STATUS";
	case SG_CMD_SHOW_IFACES:    return "SHOW_IFACES";
	case SG_CMD_SHOW_ROUTES:    return "SHOW_ROUTES";
	case SG_CMD_SHOW_CONFIG:    return "SHOW_CONFIG";
	case SG_CMD_SHOW_STATS:     return "SHOW_STATS";
	case SG_CMD_WHOAMI:         return "WHOAMI";
	case SG_CMD_DIAG_FW_IPTABLES:  return "DIAG_FW_IPTABLES";
	case SG_CMD_DIAG_FW_POLICY:    return "DIAG_FW_POLICY";
	case SG_CMD_DIAG_FW_CONNTRACK: return "DIAG_FW_CONNTRACK";
	case SG_CMD_DIAG_ROUTES:       return "DIAG_ROUTES";
	case SG_CMD_DIAG_CPU:          return "DIAG_CPU";
	case SG_CMD_DIAG_RAM:          return "DIAG_RAM";
	case SG_CMD_DIAG_DISK:         return "DIAG_DISK";
	case SG_CMD_DIAG_IFACE_STATS:  return "DIAG_IFACE_STATS";
	case SG_CMD_DIAG_PROCTOP:      return "DIAG_PROCTOP";
	case SG_CMD_DIAG_THERMAL:      return "DIAG_THERMAL";
	case SG_CMD_DIAG_DISK_HEALTH:  return "DIAG_DISK_HEALTH";
	case SG_CMD_DISK_LIST:         return "DISK_LIST";
	case SG_CMD_DISK_INFO:         return "DISK_INFO";
	case SG_CMD_DISK_SMART:        return "DISK_SMART";
	case SG_CMD_DIAG_BUSYBOX_LIST: return "DIAG_BUSYBOX_LIST";
	case SG_CMD_SHOW_SESSIONS:     return "SHOW_SESSIONS";
	case SG_CMD_SHOW_BOOT_CONFIG:  return "SHOW_BOOT_CONFIG";
	case SG_CMD_DEBUG_STATE_GET:   return "DEBUG_STATE_GET";
	case SG_CMD_DEBUG_STATE_SET:   return "DEBUG_STATE_SET";
	case SG_CMD_DEBUG_STATE_RESET: return "DEBUG_STATE_RESET";
	case SG_CMD_HISTORY_SAVE:      return "HISTORY_SAVE";
	case SG_CMD_HISTORY_LOAD:      return "HISTORY_LOAD";
	case SG_CMD_LOG_AUDIT:         return "LOG_AUDIT";
	case SG_CMD_LOG_SYSTEM:        return "LOG_SYSTEM";
	case SG_CMD_LOG_MGMTD:         return "LOG_MGMTD";
	case SG_CMD_LOG_CLEAR_AUDIT:   return "LOG_CLEAR_AUDIT";
	case SG_CMD_PING:           return "PING";
	case SG_CMD_DEBUG_FETCH:    return "DEBUG_FETCH";
	case SG_CMD_UPGRADE_TEST_SETUP: return "UPGRADE_TEST_SETUP";
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
	case SG_ERR_SESSION_EXPIRED:   return "SESSION_EXPIRED";
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
			if (n < 0 && errno == EINTR) {
				if (g_stream_interrupted)
					return (ssize_t)done;
				continue;
			}
			return n == 0 ? (ssize_t)done : -1;
		}
		done += (size_t)n;
	}
	return (ssize_t)done;
}

/*
 * stream_read — like safe_read but polls for Ctrl+C between partial reads.
 * During streaming, the outer poll() guarantees at least 1 byte is ready,
 * but safe_read() then loops calling blocking read() until it has the full
 * header/payload.  If mgmtd stalls mid-write, that read() blocks with no
 * way to detect Ctrl+C (ISIG is off → no SIGINT → no EINTR).
 *
 * stream_read() re-polls before every read(), monitoring the tty alongside
 * the socket so Ctrl+C is always responsive.
 */
static ssize_t stream_read(int fd, void *buf, size_t len)
{
	size_t done = 0;
	while (done < len) {
		if (g_stream_interrupted)
			return (ssize_t)done;

		struct pollfd pfds[2];
		int nfds = 1;
		pfds[0].fd = fd;
		pfds[0].events = POLLIN;
		if (g_interrupt_fd >= 0) {
			pfds[1].fd = g_interrupt_fd;
			pfds[1].events = POLLIN;
			nfds = 2;
		}

		int prc = poll(pfds, (nfds_t)nfds, 30000);
		if (prc <= 0)
			return (ssize_t)done; /* timeout or error */

		if (nfds > 1 && (pfds[1].revents & POLLIN))
			check_ctrl_c();
		if (g_stream_interrupted)
			return (ssize_t)done;

		if (!(pfds[0].revents & POLLIN))
			continue;

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

void ipc_set_session_tag(uint64_t tag)
{
	ipc_session_tag = tag;
}

uint64_t ipc_get_session_tag(void)
{
	return ipc_session_tag;
}

int ipc_has_tag(void)
{
	return ipc_session_tag != 0;
}

int ipc_session_expired(void)
{
	return g_session_expired;
}

void ipc_clear_session_expired(void)
{
	g_session_expired = 0;
}

int ipc_reacquire_tag(void)
{
	struct ipc_response resp;
	uint64_t old_tag = ipc_session_tag;

	/* Clear expired flag so the SESSION_TAG_NEW request goes through */
	g_session_expired = 0;
	ipc_session_tag = 0;

	if (ipc_send_str(SG_CMD_SESSION_TAG_NEW, "", &resp) != 0 ||
	    resp.status != SG_OK || !resp.payload) {
		ipc_resp_free(&resp);
		ipc_session_tag = old_tag;
		return -1;
	}
	uint64_t new_tag = strtoull(resp.payload, NULL, 10);
	ipc_resp_free(&resp);
	if (new_tag == 0) {
		ipc_session_tag = old_tag;
		return -1;
	}
	ipc_session_tag = new_tag;
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

	/*
	 * Compute debug flags BEFORE opening the connection.
	 *
	 * dbg_enabled() → mem_load_once() may trigger an IPC call on
	 * first access (to load debug state).  If we called it after
	 * connect(), mgmtd would already be blocked reading our socket
	 * while the inner IPC opens a second connection → deadlock
	 * (mgmtd is single-threaded).  By doing it here, any inner
	 * IPC completes before we touch the network.
	 */
	uint32_t debug_flags = 0;
	if (dbg_enabled()) {
		if (strcmp(dbg_get("mgmtd_debug", "0"), "1") == 0)
			debug_flags |= SG_DBG_FLAG_MGMTD;
		if (strcmp(dbg_get("auth_admin", "0"), "1") == 0)
			debug_flags |= SG_DBG_FLAG_AUTH;
	}

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
	hdr.debug_flags = debug_flags;
	hdr.session_tag = ipc_session_tag;

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

	/* Detect session expiration */
	if (resp->status == SG_ERR_SESSION_EXPIRED)
		g_session_expired = 1;

	/* Read response payload */
	if (rhdr.payload_len > 0 && rhdr.payload_len <= SG_RESPONSE_MAX) {
		resp->payload = malloc(rhdr.payload_len + 1);
		if (!resp->payload)
			goto out;

		n = safe_read(fd, resp->payload, rhdr.payload_len);
		if (n < (ssize_t)rhdr.payload_len) {
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

int ipc_send_stream(uint32_t cmd, const char *payload_str,
		    void (*on_chunk)(const char *data, size_t len))
{
	int ret = -1;
	size_t payload_len = payload_str ? strlen(payload_str) : 0;

	if (payload_len > SG_PAYLOAD_MAX)
		return -1;

	/* Compute debug flags before connecting (same reason as ipc_send) */
	uint32_t debug_flags = 0;
	if (dbg_enabled()) {
		if (strcmp(dbg_get("mgmtd_debug", "0"), "1") == 0)
			debug_flags |= SG_DBG_FLAG_MGMTD;
		if (strcmp(dbg_get("auth_admin", "0"), "1") == 0)
			debug_flags |= SG_DBG_FLAG_AUTH;
	}

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SG_MGMTD_SOCK);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto out;

	/* Send request header */
	sg_request_hdr_t hdr;
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic       = SG_MSG_MAGIC;
	hdr.version     = SG_MSG_VERSION;
	hdr.cmd         = cmd;
	snprintf(hdr.username, sizeof(hdr.username), "%s", ipc_username);
	hdr.payload_len = (uint32_t)payload_len;
	hdr.debug_flags = debug_flags;
	hdr.session_tag = ipc_session_tag;

	if (safe_write(fd, &hdr, sizeof(hdr)) < 0)
		goto out;

	if (payload_len > 0 && payload_str) {
		if (safe_write(fd, payload_str, payload_len) < 0)
			goto out;
	}

	if (ipc_dbg())
		fprintf(stderr, "[IPC-DBG] -> cmd=%u(%s) len=%u [stream]\n",
			cmd, cmd_name(cmd), (unsigned)payload_len);

	/* Enter interruptible mode: tty in raw mode for Ctrl+C polling */
	g_stream_interrupted = 0;
	interrupt_raw_on();

	/* Read streaming responses until final (extra[0] != '+') */
	for (;;) {
		if (g_stream_interrupted) {
			ret = SG_OK;
			goto out;
		}

		/* Wait for socket data while monitoring tty for Ctrl+C */
		struct pollfd pfds[2];
		int nfds = 1;
		pfds[0].fd = fd;
		pfds[0].events = POLLIN;
		if (g_interrupt_fd >= 0) {
			pfds[1].fd = g_interrupt_fd;
			pfds[1].events = POLLIN;
			nfds = 2;
		}

		int prc = poll(pfds, (nfds_t)nfds, 30000);
		if (prc <= 0)
			goto out; /* timeout or error */

		/* Check tty for Ctrl+C */
		if (nfds > 1 && (pfds[1].revents & POLLIN)) {
			if (check_ctrl_c()) {
				ret = SG_OK;
				goto out;
			}
		}

		/* No socket data ready (only tty triggered) */
		if (!(pfds[0].revents & POLLIN))
			continue;

		sg_response_hdr_t rhdr;
		ssize_t n = stream_read(fd, &rhdr, sizeof(rhdr));
		if (n < (ssize_t)sizeof(rhdr)) {
			if (g_stream_interrupted)
				ret = SG_OK;
			goto out;
		}
		if (rhdr.magic != SG_MSG_MAGIC)
			goto out;

		/* Read payload if present */
		char *chunk = NULL;
		if (rhdr.payload_len > 0 && rhdr.payload_len <= SG_PAYLOAD_MAX) {
			chunk = malloc(rhdr.payload_len + 1);
			if (!chunk)
				goto out;
			n = stream_read(fd, chunk, rhdr.payload_len);
			if (n < (ssize_t)rhdr.payload_len) {
				free(chunk);
				if (g_stream_interrupted)
					ret = SG_OK;
				goto out;
			}
			chunk[n] = '\0';
		}

		int is_stream = (rhdr.extra[0] == '+');

		if (is_stream && chunk && on_chunk)
			on_chunk(chunk, (size_t)rhdr.payload_len);

		free(chunk);

		if (!is_stream) {
			/* Final response */
			ret = (int)rhdr.status;
			if (rhdr.status == SG_ERR_SESSION_EXPIRED)
				g_session_expired = 1;
			break;
		}
	}

	if (ipc_dbg())
		fprintf(stderr, "[IPC-DBG] <- stream done status=%d\n", ret);

out:
	interrupt_raw_off();
	if (g_stream_interrupted)
		printf("\n");
	close(fd);
	return ret;
}

void ipc_install_interrupt_handler(void)
{
	g_stream_interrupted = 0;
	interrupt_raw_on();
}

void ipc_restore_interrupt_handler(void)
{
	interrupt_raw_off();
}

int ipc_stream_interrupted(void)
{
	if (!g_stream_interrupted)
		check_ctrl_c();
	return g_stream_interrupted != 0;
}

void ipc_clear_interrupt(void)
{
	g_stream_interrupted = 0;
}

/* Like check_ctrl_c but also treats 'q'/'Q' as quit.
 * Used by interactive monitors (e.g. diagnose top) where 'q' means exit.
 * NOT suitable for IPC streaming where 'q' is valid payload data. */
int ipc_check_quit_or_ctrl_c(void)
{
	if (g_stream_interrupted)
		return 1;
	if (g_interrupt_fd < 0)
		return 0;
	struct pollfd pfd;
	pfd.fd = g_interrupt_fd;
	pfd.events = POLLIN;
	while (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN)) {
		char c;
		if (read(g_interrupt_fd, &c, 1) != 1)
			break;
		if (c == 3 || c == 'q' || c == 'Q') {
			g_stream_interrupted = 1;
			return 1;
		}
	}
	return 0;
}

int ipc_available(void)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return 0;
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SG_MGMTD_SOCK);
	int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	close(fd);
	return rc == 0;
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
	if (ipc_send(SG_CMD_DEBUG_FETCH, NULL, 0, &resp) == 0 &&
	    resp.status == SG_OK) {
		if (resp.payload && resp.payload_len > 0)
			fprintf(stderr, "%s", resp.payload);
	}
	ipc_resp_free(&resp);
}
