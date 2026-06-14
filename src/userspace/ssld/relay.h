/* SPDX-License-Identifier: MIT */
/*
 * relay.h - Bidirectional byte pump between two sockets (ssld's SPLICE path).
 *
 * SPLICE = raw TCP relay WITHOUT decryption: client <-relay_pump-> real server.
 * Used for bypassed TLS flows (banking/pinned apps) and is the basis of the
 * later BUMP path too (after decryption, the two plaintext halves are also
 * pumped into each other).
 *
 * MVP: poll on both read ends + blocking-write (write_all) to the other side.
 * Known limitation: blocking-write can deadlock if BOTH send buffers fill at the
 * same time (rare with normal traffic); a production version needs non-blocking
 * + a buffer per direction - noted as "future work". Handles half-close
 * correctly (FIN one way, the other still has data).
 */
#ifndef SG_SSLD_RELAY_H
#define SG_SSLD_RELAY_H

#include <stddef.h>

#define RELAY_BUF_SIZE 16384

/*
 * Pump data both ways between fd `a` and fd `b` until both directions close
 * (EOF/error). When one direction hits EOF, shutdown(SHUT_WR) the other end to
 * propagate FIN, and keep going on the remaining direction (half-close). Does
 * NOT close a/b - the caller closes them. Returns 0 on normal completion, -1 on
 * an unrecoverable poll error.
 */
int relay_pump(int a, int b);

/*
 * Write all `len` bytes to fd (loops over partial writes, ignores EINTR).
 * Returns 0 if fully written, -1 on error/peer close. Exported so conn.c can
 * forward the buffered ClientHello before entering the relay.
 */
int relay_write_all(int fd, const void *buf, size_t len);

#endif /* SG_SSLD_RELAY_H */
