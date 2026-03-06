/* SPDX-License-Identifier: MIT */
/*
 * stargazer-ipc-cli — IPC client for shell scripts
 *
 * Small binary that sends a request to stargazer-mgmtd via Unix domain
 * socket and prints the response. Used by shell-based CLI scripts to
 * delegate privileged operations to the root daemon.
 *
 * Usage:
 *   stargazer-ipc-cli <cmd_id> [payload_string]
 *   stargazer-ipc-cli <cmd_id> -f <payload_file>
 *
 * The username is automatically taken from STARGAZER_USER env var.
 *
 * Exit codes:
 *   0       = SG_OK
 *   1       = connection/protocol error
 *   100-599 = sg_status_t error code (divided by 1 for shell)
 *
 * Output:
 *   stdout line 1: status code (numeric)
 *   stdout line 2: extra info (hint string)
 *   stdout line 3+: payload data
 *
 * Build: aarch64-linux-musl-gcc -static -o stargazer-ipc-cli stargazer-ipc-cli.c
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "stargazer_ipc.h"

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

static char *read_file_contents(const char *path, size_t *outlen)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) return NULL;

	size_t bufsize = 4096, used = 0;
	char *buf = malloc(bufsize);
	if (!buf) { close(fd); return NULL; }

	ssize_t n;
	while ((n = read(fd, buf + used, bufsize - used)) > 0) {
		used += (size_t)n;
		if (used >= bufsize) {
			bufsize *= 2;
			char *nb = realloc(buf, bufsize);
			if (!nb) { free(buf); close(fd); return NULL; }
			buf = nb;
		}
	}
	close(fd);
	buf[used] = '\0';
	*outlen = used;
	return buf;
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <cmd_id> [payload]\n", prog);
	fprintf(stderr, "       %s <cmd_id> -f <payload_file>\n", prog);
	fprintf(stderr, "\nCommands:\n");
	fprintf(stderr, "  100  CFG_GET      <section>\n");
	fprintf(stderr, "  101  CFG_LIST     <prefix>\n");
	fprintf(stderr, "  200  CFG_SET      <section>\\n<data>\n");
	fprintf(stderr, "  201  CFG_DEL      <section>\n");
	fprintf(stderr, "  202  CFG_APPLY    <type>\\n<id>\\n<data>\n");
	fprintf(stderr, "  300  ADMIN_CREATE <user>\\n<profile>\n");
	fprintf(stderr, "  301  ADMIN_DELETE <username>\n");
	fprintf(stderr, "  302  ADMIN_SET_PW <user>\\n<password>\n");
	fprintf(stderr, "  303  ADMIN_SET_ENF <user>\\n<enable|disable>\n");
	fprintf(stderr, "  400  SESSION_TAG_NEW\n");
	fprintf(stderr, "  401  SESSION_TAG_DEL\n");
	fprintf(stderr, "  600  SYS_POWEROFF\n");
	fprintf(stderr, "  601  SYS_REBOOT\n");
	fprintf(stderr, "  610  SHOW_STATUS\n");
	fprintf(stderr, "  611  SHOW_IFACES\n");
	fprintf(stderr, "  612  SHOW_ROUTES\n");
	fprintf(stderr, "  900  PING\n");
}

/* ── IPC round-trip helper ─────────────────────────────────────────────── */

/*
 * Send a single IPC request and read the response.
 * Caller must free *out_payload.
 * Returns 0 on success, -1 on communication error.
 */
static int ipc_roundtrip(uint32_t cmd, const char *user, uint64_t tag,
			 const void *payload, size_t payload_len,
			 sg_response_hdr_t *out_resp, char **out_payload)
{
	*out_payload = NULL;

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

	sg_request_hdr_t hdr;
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic       = SG_MSG_MAGIC;
	hdr.version     = SG_MSG_VERSION;
	hdr.cmd         = cmd;
	snprintf(hdr.username, sizeof(hdr.username), "%s", user);
	hdr.payload_len = (uint32_t)payload_len;
	hdr.session_tag = tag;

	if (safe_write(fd, &hdr, sizeof(hdr)) < 0) {
		close(fd);
		return -1;
	}
	if (payload_len > 0 && payload &&
	    safe_write(fd, payload, payload_len) < 0) {
		close(fd);
		return -1;
	}

	ssize_t n = safe_read(fd, out_resp, sizeof(*out_resp));
	if (n < (ssize_t)sizeof(*out_resp) ||
	    out_resp->magic != SG_MSG_MAGIC) {
		close(fd);
		return -1;
	}

	if (out_resp->payload_len > 0 &&
	    out_resp->payload_len <= SG_PAYLOAD_MAX) {
		*out_payload = malloc(out_resp->payload_len + 1);
		if (*out_payload) {
			n = safe_read(fd, *out_payload, out_resp->payload_len);
			if (n >= 0)
				(*out_payload)[n] = '\0';
			else {
				free(*out_payload);
				*out_payload = NULL;
			}
		}
	}

	close(fd);
	return 0;
}

/* Commands exempt from session tag (must match mgmtd validation gate) */
static int cmd_needs_tag(int cmd)
{
	return cmd != (int)SG_CMD_SESSION_TAG_NEW &&
	       cmd != (int)SG_CMD_SESSION_TAG_DEL &&
	       cmd != (int)SG_CMD_WHOAMI &&
	       cmd != (int)SG_CMD_DEBUG_FETCH;
}

/* Release a session tag (best-effort, ignores errors) */
static void release_tag(const char *user, uint64_t tag)
{
	sg_response_hdr_t del_resp;
	char *del_payload = NULL;
	ipc_roundtrip(SG_CMD_SESSION_TAG_DEL, user, tag,
		      NULL, 0, &del_resp, &del_payload);
	free(del_payload);
}

/* ── Main ──────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	int cmd_id = atoi(argv[1]);
	if (cmd_id == 0 && strcmp(argv[1], "0") != 0) {
		fprintf(stderr, "Error: invalid command ID '%s'\n", argv[1]);
		return 1;
	}

	/* Get payload */
	char *payload = NULL;
	size_t payload_len = 0;

	if (argc >= 4 && strcmp(argv[2], "-f") == 0) {
		/* Read from file */
		payload = read_file_contents(argv[3], &payload_len);
		if (!payload) {
			fprintf(stderr, "Error: cannot read '%s': %s\n",
				argv[3], strerror(errno));
			return 1;
		}
	} else if (argc >= 3) {
		/* Inline payload — join remaining args with space */
		size_t total = 0;
		for (int i = 2; i < argc; i++)
			total += strlen(argv[i]) + 1;

		payload = malloc(total + 1);
		if (!payload) { perror("malloc"); return 1; }

		size_t off = 0;
		for (int i = 2; i < argc; i++) {
			size_t l = strlen(argv[i]);
			memcpy(payload + off, argv[i], l);
			off += l;
			if (i < argc - 1) payload[off++] = ' ';
		}
		payload[off] = '\0';
		payload_len = off;
	}

	if (payload_len > SG_PAYLOAD_MAX) {
		fprintf(stderr, "Error: payload too large (%zu > %d)\n",
			payload_len, SG_PAYLOAD_MAX);
		free(payload);
		return 1;
	}

	/* Get username from environment */
	const char *user = getenv("STARGAZER_USER");
	if (!user) user = getenv("LOGNAME");
	if (!user) user = getenv("USER");
	if (!user) user = "unknown";

	/* Auto-acquire session tag for commands that need it */
	uint64_t session_tag = 0;
	if (cmd_needs_tag(cmd_id)) {
		sg_response_hdr_t tag_resp;
		char *tag_payload = NULL;
		if (ipc_roundtrip(SG_CMD_SESSION_TAG_NEW, user, 0,
				  NULL, 0, &tag_resp, &tag_payload) < 0 ||
		    tag_resp.status != SG_OK || !tag_payload) {
			fprintf(stderr, "Error: cannot connect to mgmtd");
			if (tag_payload)
				fprintf(stderr, " (%s)", tag_resp.extra);
			fprintf(stderr, "\nIs stargazer-mgmtd running?\n");
			free(tag_payload);
			free(payload);
			return 1;
		}
		session_tag = strtoull(tag_payload, NULL, 10);
		free(tag_payload);
		if (session_tag == 0) {
			fprintf(stderr, "Error: failed to acquire session tag\n");
			free(payload);
			return 1;
		}
	}

	/* Send the actual command */
	sg_response_hdr_t resp;
	char *resp_payload = NULL;
	if (ipc_roundtrip((uint32_t)cmd_id, user, session_tag,
			  payload, payload_len, &resp, &resp_payload) < 0) {
		fprintf(stderr, "Error: communication with mgmtd failed\n");
		if (session_tag != 0)
			release_tag(user, session_tag);
		free(payload);
		return 1;
	}
	free(payload);

	/* Release session tag (best effort) */
	if (session_tag != 0)
		release_tag(user, session_tag);

	/* Output:
	 * Line 1: status code
	 * Line 2: extra info
	 * Line 3+: payload
	 */
	printf("%u\n", resp.status);
	printf("%s\n", resp.extra);
	if (resp_payload) {
		printf("%s", resp_payload);
		free(resp_payload);
	}

	/* Exit code: 0 for success, 1 for any error */
	return resp.status == SG_OK ? 0 : 1;
}
