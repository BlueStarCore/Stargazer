/* SPDX-License-Identifier: MIT */
/*
 * conn.h - Handle ONE client connection redirected into ssld.
 *
 * Lifecycle:
 *   1. origdst_get         : find the original destination (SO_ORIGINAL_DST)
 *   2. PEEK ClientHello    : MSG_PEEK (does NOT consume - left intact for later)
 *   3. tls_policy_decide   : BUMP or SPLICE based on SNI + bypass list
 *   4a. SPLICE : connect to the original destination -> raw relay_pump (the
 *                ClientHello still in the socket is relayed naturally)
 *   4b. BUMP   : bump_run terminate+decrypt+inspect (SSL_accept reads the
 *                ClientHello)
 */
#ifndef SG_SSLD_CONN_H
#define SG_SSLD_CONN_H

#include "tls_policy.h"
#include "ca.h"
#include "certcache.h"

struct sig_ruleset;   /* ../ipsd/sig_rule.h — fwd decl */

/* Limit on accumulated (peeked) ClientHello bytes before giving up the parse. */
#define CONN_HELLO_MAX 16384

/* Shared context for every connection (read-only within conn). */
struct ssld_ctx {
	const struct tls_policy *pol;
	struct ca_ctx           *ca;       /* NULL -> SPLICE only (no bump) */
	struct certcache        *cc;
	struct sig_ruleset      *rules;    /* NULL -> bump does not inspect payload */
	int                      verify_upstream;
	int                      no_ipc;         /* P4: 1 = inspect per-chunk, no IPC */
	int                      ipc_failclosed; /* P4: 1 = IPC error -> block flow */
};

struct ssld_stats {
	unsigned long n_total;
	unsigned long n_splice;
	unsigned long n_bump;
	unsigned long n_error;
};

/*
 * Handle one connection end to end; CLOSES client_fd before returning.
 * Safe to run in a dedicated thread per connection.
 */
void ssld_handle_conn(int client_fd, const struct ssld_ctx *ctx,
		      struct ssld_stats *st);

#endif /* SG_SSLD_CONN_H */
