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
	fprintf(stderr, "  400  SESSION_REV  <username>\n");
	fprintf(stderr, "  401  SESSION_BUMP <username>\n");
	fprintf(stderr, "  600  SYS_POWEROFF\n");
	fprintf(stderr, "  601  SYS_REBOOT\n");
	fprintf(stderr, "  610  SHOW_STATUS\n");
	fprintf(stderr, "  611  SHOW_IFACES\n");
	fprintf(stderr, "  612  SHOW_ROUTES\n");
	fprintf(stderr, "  900  PING\n");
}

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

	/* Connect to mgmtd */
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Error: socket: %s\n", strerror(errno));
		free(payload);
		return 1;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SG_MGMTD_SOCK);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Error: cannot connect to mgmtd: %s\n", strerror(errno));
		fprintf(stderr, "Is stargazer-mgmtd running?\n");
		close(fd);
		free(payload);
		return 1;
	}

	/* Build request */
	sg_request_hdr_t hdr;
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = SG_MSG_MAGIC;
	hdr.version = SG_MSG_VERSION;
	hdr.cmd = (uint32_t)cmd_id;
	snprintf(hdr.username, sizeof(hdr.username), "%s", user);
	hdr.payload_len = (uint32_t)payload_len;

	/* Send header + payload */
	if (safe_write(fd, &hdr, sizeof(hdr)) < 0) {
		fprintf(stderr, "Error: write header: %s\n", strerror(errno));
		close(fd);
		free(payload);
		return 1;
	}
	if (payload_len > 0 && safe_write(fd, payload, payload_len) < 0) {
		fprintf(stderr, "Error: write payload: %s\n", strerror(errno));
		close(fd);
		free(payload);
		return 1;
	}
	free(payload);

	/* Read response header */
	sg_response_hdr_t resp;
	ssize_t n = safe_read(fd, &resp, sizeof(resp));
	if (n < (ssize_t)sizeof(resp)) {
		fprintf(stderr, "Error: short response (%zd bytes)\n", n);
		close(fd);
		return 1;
	}

	if (resp.magic != SG_MSG_MAGIC) {
		fprintf(stderr, "Error: bad response magic\n");
		close(fd);
		return 1;
	}

	/* Read response payload */
	char *resp_payload = NULL;
	if (resp.payload_len > 0 && resp.payload_len <= SG_PAYLOAD_MAX) {
		resp_payload = malloc(resp.payload_len + 1);
		if (resp_payload) {
			n = safe_read(fd, resp_payload, resp.payload_len);
			if (n >= 0)
				resp_payload[n] = '\0';
			else {
				free(resp_payload);
				resp_payload = NULL;
			}
		}
	}
	close(fd);

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
