/* SPDX-License-Identifier: MIT */
/*
 * origdst.h - Get the ORIGINAL destination address of a connection redirected
 * into ssld.
 *
 * When iptables REDIRECT/DNAT pushes a TLS flow into ssld's listen port, the
 * kernel-side socket still remembers the real destination via SO_ORIGINAL_DST
 * (netfilter). ssld needs this destination to open a connection to the real
 * server (both splice and bump).
 *
 * (TPROXY is an alternative - an IP_TRANSPARENT socket keeps the original
 *  destination directly, read with getsockname; to be added when mgmtd chooses
 *  TPROXY. MVP uses SO_ORIGINAL_DST.)
 */
#ifndef SG_SSLD_ORIGDST_H
#define SG_SSLD_ORIGDST_H

#include <netinet/in.h>

/*
 * Fill *out with the original (IPv4) destination of client_fd. Returns 0 on
 * success, -1 otherwise (not REDIRECTed, or IPv6 - not supported yet).
 */
int origdst_get(int client_fd, struct sockaddr_in *out);

#endif /* SG_SSLD_ORIGDST_H */
