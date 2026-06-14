/* SPDX-License-Identifier: MIT */
/*
 * relay.c - Bidirectional byte pump (see relay.h).
 */
#include "relay.h"

#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>

int relay_write_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	size_t off = 0;
	while (off < len) {
		ssize_t n = write(fd, p + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		off += (size_t)n;
	}
	return 0;
}

/* Read from `from`, write it all to `to`. Returns 1 if still open, 0 on EOF, -1
 * on error. */
static int pump_one(int from, int to)
{
	char buf[RELAY_BUF_SIZE];
	ssize_t n = read(from, buf, sizeof(buf));
	if (n > 0) {
		if (relay_write_all(to, buf, (size_t)n) < 0)
			return -1;
		return 1;
	}
	if (n == 0)
		return 0;                       /* EOF */
	if (errno == EINTR)
		return 1;                       /* retry next round */
	return -1;                              /* read error */
}

int relay_pump(int a, int b)
{
	int a_open = 1, b_open = 1;              /* is the READ direction still open? */
	struct pollfd pfd[2];

	while (a_open || b_open) {
		pfd[0].fd      = a_open ? a : -1;
		pfd[0].events  = POLLIN;
		pfd[0].revents = 0;
		pfd[1].fd      = b_open ? b : -1;
		pfd[1].events  = POLLIN;
		pfd[1].revents = 0;

		int r = poll(pfd, 2, -1);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		/* a -> b */
		if (a_open && (pfd[0].revents & (POLLIN | POLLHUP | POLLERR))) {
			int s = pump_one(a, b);
			if (s <= 0) {
				a_open = 0;
				if (s == 0)
					shutdown(b, SHUT_WR);  /* propagate FIN */
				else
					b_open = 0;            /* error -> drop both */
			}
		}

		/* b -> a */
		if (b_open && (pfd[1].revents & (POLLIN | POLLHUP | POLLERR))) {
			int s = pump_one(b, a);
			if (s <= 0) {
				b_open = 0;
				if (s == 0)
					shutdown(a, SHUT_WR);
				else
					a_open = 0;
			}
		}
	}
	return 0;
}
