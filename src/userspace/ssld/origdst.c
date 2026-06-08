/* SPDX-License-Identifier: MIT */
/*
 * origdst.c - SO_ORIGINAL_DST (xem origdst.h).
 */
#include "origdst.h"

#include <string.h>
#include <sys/socket.h>
#include <linux/netfilter_ipv4.h>   /* SO_ORIGINAL_DST */

int origdst_get(int client_fd, struct sockaddr_in *out)
{
	if (!out)
		return -1;
	memset(out, 0, sizeof(*out));
	socklen_t len = sizeof(*out);
	if (getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST, out, &len) < 0)
		return -1;
	if (out->sin_family != AF_INET)
		return -1;
	return 0;
}
