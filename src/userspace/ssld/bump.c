/* SPDX-License-Identifier: MIT */
/*
 * bump.c - MITM a single TLS flow (see bump.h).
 *
 * Uses BLOCKING sockets + poll on the two raw fds to pump plaintext both ways.
 * SSL_set_fd uses BIO_NOCLOSE -> bump closes the fds itself. MVP limitation:
 * half-close is imperfect (EOF in one direction -> close both); mid-stream
 * renegotiation relies on SSL_read/SSL_write handling it on a blocking socket.
 */
#include "bump.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUMP_BUF 16384

/* Open TCP to the original destination. Returns fd, -1 on error. */
static int connect_tcp(const struct sockaddr_in *dst)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	if (connect(fd, (const struct sockaddr *)dst, sizeof(*dst)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Write all len plaintext bytes over SSL (blocking -> one shot suffices, or
 * error). */
static int ssl_write_all(SSL *ssl, const unsigned char *buf, int len)
{
	int off = 0;
	while (off < len) {
		int n = SSL_write(ssl, buf + off, len - off);
		if (n > 0) {
			off += n;
			continue;
		}
		int e = SSL_get_error(ssl, n);
		if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
			continue;
		return -1;
	}
	return 0;
}

/*
 * Pump one direction: read plaintext from `from`, inspect it, write to `to`.
 * Returns 1 if still open, 0 on EOF/clean close, -1 on error or inspect BLOCK.
 * Drain SSL_pending so data already in the SSL buffer doesn't get stuck.
 * `out_written` (if != NULL): accumulates bytes written to `to` — used to know
 * whether the response has started reaching the client (decides whether to
 * inject the block page).
 */
static int pump_ssl(SSL *from, SSL *to, int to_server,
		    const struct bump_cfg *cfg, size_t *out_written)
{
	unsigned char buf[BUMP_BUF];
	do {
		int n = SSL_read(from, buf, sizeof(buf));
		if (n > 0) {
			if (cfg->inspect &&
			    cfg->inspect(buf, n, to_server, cfg->inspect_ud)) {
				return -2;          /* BLOCK (inspect DROP) - distinct from error */
			}
			if (ssl_write_all(to, buf, n) < 0)
				return -1;
			if (out_written)
				*out_written += (size_t)n;
			continue;
		}
		int e = SSL_get_error(from, n);
		if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
			return 1;                   /* record incomplete - wait for poll */
		if (e == SSL_ERROR_ZERO_RETURN)
			return 0;                   /* close_notify */
		return -1;                          /* error/broken */
	} while (SSL_pending(from) > 0);
	return 1;
}

/* The TLS handshake can return WANT_* on a blocking socket (rare) - loop. */
static int do_handshake(SSL *ssl, int accept)
{
	for (;;) {
		int r = accept ? SSL_accept(ssl) : SSL_connect(ssl);
		if (r == 1)
			return 0;
		int e = SSL_get_error(ssl, r);
		if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
			continue;
		return -1;
	}
}

int bump_run(int client_fd, const char *sni, const struct sockaddr_in *dst,
	     const struct bump_cfg *cfg)
{
	int up_fd = -1;
	SSL_CTX *uctx = NULL, *cctx = NULL;
	SSL *ussl = NULL, *cssl = NULL;
	X509 *upcert = NULL;
	int rc = -1;

	char dip[INET_ADDRSTRLEN] = "?";
	inet_ntop(AF_INET, &dst->sin_addr, dip, sizeof(dip));
	const char *host = (sni && *sni) ? sni : dip;

	/* -- [1] connect + TLS handshake TO THE REAL SERVER (reverse: backend) -- */
	const struct sockaddr_in *up = cfg->upstream ? cfg->upstream : dst;
	up_fd = connect_tcp(up);
	if (up_fd < 0) {
		fprintf(stderr, "bump: connect %s failed: %m\n", dip);
		goto out;
	}

	uctx = SSL_CTX_new(TLS_client_method());
	if (!uctx)
		goto out;
	SSL_CTX_set_min_proto_version(uctx, TLS1_2_VERSION);
	if (cfg->verify_upstream) {
		/* Trust store to tell whether the REAL server's cert is valid: the root
		 * CA bundle shipped in the rootfs (/etc/ssl/certs/ca-certificates.crt).
		 * WITHOUT it -> OpenSSL has no roots -> EVERY server is treated as
		 * untrusted -> everything blocked. Fall back to the default paths
		 * (OPENSSLDIR) if the bundle is missing. */
		if (SSL_CTX_load_verify_locations(uctx,
				"/etc/ssl/certs/ca-certificates.crt", NULL) != 1)
			SSL_CTX_set_default_verify_paths(uctx);
		SSL_CTX_set_verify(uctx, SSL_VERIFY_PEER, NULL);
	}

	ussl = SSL_new(uctx);
	if (!ussl)
		goto out;
	SSL_set_fd(ussl, up_fd);                  /* BIO_NOCLOSE */
	if (sni && *sni) {
		SSL_set_tlsext_host_name(ussl, sni);   /* SNI to the server */
		if (cfg->verify_upstream)
			SSL_set1_host(ussl, sni);      /* check name matches cert */
	}
	if (do_handshake(ussl, 0) < 0) {
		/* FAIL-CLOSED: real server has a cert/handshake error -> do NOT bump */
		fprintf(stderr, "bump: upstream TLS %s failed "
			"(verify=%d) - fail-closed\n", host, cfg->verify_upstream);
		goto out;
	}
	upcert = SSL_get1_peer_certificate(ussl);   /* to mirror validity */

	/* -- [2] server identity + TLS handshake WITH THE CLIENT (act as server) -- */
	cctx = SSL_CTX_new(TLS_server_method());
	if (!cctx)
		goto out;
	SSL_CTX_set_min_proto_version(cctx, TLS1_2_VERSION);

	if (cfg->reverse) {
		/* REVERSE ("Protect SSL Server"): present the REAL server cert+key, so the
		 * external client validates against the public CA chain as usual — no
		 * Stargazer-CA install required on the client. */
		if (SSL_CTX_use_certificate(cctx, cfg->srv_cert) != 1 ||
		    SSL_CTX_use_PrivateKey(cctx, cfg->srv_key) != 1) {
			fprintf(stderr, "bump: reverse cert/key %s failed\n", host);
			goto out;
		}
		/* Send the intermediate chain so the client can build a path to a trusted
		 * root. up_ref each (add_extra_chain_cert takes ownership; cctx is freed
		 * per-connection while the chain lives in the shared revmap). */
		for (int i = 0; cfg->srv_chain &&
				i < sk_X509_num(cfg->srv_chain); i++) {
			X509 *ic = sk_X509_value(cfg->srv_chain, i);
			if (X509_up_ref(ic))
				SSL_CTX_add_extra_chain_cert(cctx, ic);
		}
	} else {
		/* FORWARD: forge a leaf signed by our CA (client must trust the CA). */
		X509 *leaf = NULL; EVP_PKEY *key = NULL;
		if (certcache_get(cfg->cc, host, upcert, &leaf, &key) < 0) {
			fprintf(stderr, "bump: forge cert %s failed\n", host);
			goto out;
		}
		if (SSL_CTX_use_certificate(cctx, leaf) != 1 ||
		    SSL_CTX_use_PrivateKey(cctx, key) != 1) {
			goto out;
		}
		/* include the CA in the chain (client already trusts it, but for
		 * completeness) */
		if (X509_up_ref(cfg->ca->cert))
			SSL_CTX_add_extra_chain_cert(cctx, cfg->ca->cert);
	}

	cssl = SSL_new(cctx);
	if (!cssl)
		goto out;
	SSL_set_fd(cssl, client_fd);              /* BIO_NOCLOSE */
	if (do_handshake(cssl, 1) < 0) {
		fprintf(stderr, "bump: client TLS %s failed\n", host);
		goto out;
	}

	fprintf(stderr, "bump: %s%s%s ✓ decrypted\n", host,
		cfg->reverse ? " (reverse)" : "",
		cfg->verify_upstream ? " (verified)" : "");

	/* -- [3] relay plaintext both ways + inspect ------------------------ */
	{
		int c_open = 1, u_open = 1, blocked = 0;
		size_t cli_written = 0;   /* byte response đã gửi tới client */
		struct pollfd pfd[2];
		while (c_open || u_open) {
			pfd[0].fd = c_open ? client_fd : -1;
			pfd[0].events = POLLIN; pfd[0].revents = 0;
			pfd[1].fd = u_open ? up_fd : -1;
			pfd[1].events = POLLIN; pfd[1].revents = 0;

			if (poll(pfd, 2, -1) < 0) {
				if (errno == EINTR)
					continue;
				break;
			}
			if (c_open &&
			    (pfd[0].revents & (POLLIN | POLLHUP | POLLERR))) {
				int s = pump_ssl(cssl, ussl, 1, cfg, NULL);
				if (s == -2) blocked = 1;
				if (s <= 0) { c_open = 0; if (s < 0) u_open = 0; }
			}
			if (!blocked && u_open &&
			    (pfd[1].revents & (POLLIN | POLLHUP | POLLERR))) {
				int s = pump_ssl(ussl, cssl, 0, cfg, &cli_written);
				if (s == -2) blocked = 1;
				if (s <= 0) { u_open = 0; if (s < 0) c_open = 0; }
			}
			if (blocked) break;
		}
		/* DROP → write the block page (FortiGate-style) to the client before
		 * closing. Only inject when NO response byte has reached the client yet:
		 * if the response already started (DROP on the server→client direction,
		 * e.g. a signature in the response body), appending an HTTP 403 would be
		 * parsed by the browser as the BODY of the previous response → it shows
		 * the raw text "HTTP/1.1 403 Forbidden Content-Type: t...". In that case
		 * just close the connection (client sees a load error, not a fake page). */
		if (blocked && cfg->on_block && cli_written == 0)
			cfg->on_block(cssl, cfg->inspect_ud);
	}
	rc = 0;

out:
	if (cssl) { SSL_shutdown(cssl); SSL_free(cssl); }
	if (ussl) { SSL_shutdown(ussl); SSL_free(ussl); }
	if (upcert) X509_free(upcert);
	if (cctx) SSL_CTX_free(cctx);
	if (uctx) SSL_CTX_free(uctx);
	if (up_fd >= 0) close(up_fd);
	close(client_fd);          /* bump consumes client_fd */
	return rc;
}
