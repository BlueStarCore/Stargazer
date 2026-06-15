/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE   /* memmem */
/*
 * bump_test.c - end-to-end MITM test with real TLS over loopback.
 *
 * Layout:
 *   [TLS client trusting CA]  ──►  [proxy: bump_run]  ──►  [origin TLS server]
 *
 * Proves:
 *  1. A client configured just like a browser that installed the CA -> handshake
 *     with the FORGED cert succeeds (verifies to the CA, name matches SNI). This
 *     proves forge+CA is correct.
 *  2. Data flows both ways through decryption (client sends request, gets response).
 *  3. inspect() SEES the plaintext (decrypted request).
 *  4. inspect() returns BLOCK -> connection is cut.
 *  5. verify_upstream=1 + self-signed origin -> fail-closed (client handshake fails).
 */
#include "ca.h"
#include "certcache.h"
#include "bump.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

static int g_fail;
#define CHECK(c, m) do { if (!(c)) { printf("  FAIL: %s\n", m); g_fail++; } \
			 else printf("  ok:   %s\n", m); } while (0)

#define REQ  "GET /secret-path HTTP/1.1\r\nHost: test.local\r\n\r\n"
#define RESP "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"

/* -- origin TLS server (self-signed) --------------------------------------- */
struct origin {
	int             fd;       /* listener */
	uint16_t        port;
	struct ca_ctx  *id;       /* used as the self-signed server cert */
};

static void *origin_thread(void *arg)
{
	struct origin *o = arg;
	int c = accept(o->fd, NULL, NULL);
	if (c < 0)
		return NULL;

	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	SSL_CTX_use_certificate(ctx, o->id->cert);
	SSL_CTX_use_PrivateKey(ctx, o->id->key);
	SSL *s = SSL_new(ctx);
	SSL_set_fd(s, c);
	if (SSL_accept(s) == 1) {
		char buf[512];
		int n = SSL_read(s, buf, sizeof(buf));
		(void)n;
		SSL_write(s, RESP, (int)strlen(RESP));
	}
	SSL_shutdown(s);
	SSL_free(s);
	SSL_CTX_free(ctx);
	close(c);
	return NULL;
}

/* -- proxy: accept 1 connection, call bump_run ----------------------------- */
struct proxy {
	int                    fd;     /* listener */
	uint16_t               port;
	struct sockaddr_in     origin_addr;
	struct bump_cfg       *cfg;
	int                    bump_rc;
};

static void *proxy_thread(void *arg)
{
	struct proxy *p = arg;
	int c = accept(p->fd, NULL, NULL);
	if (c < 0)
		return NULL;
	p->bump_rc = bump_run(c, "test.local", &p->origin_addr, p->cfg);
	return NULL;
}

/* -- inspect callback: record the to_server plaintext seen ----------------- */
static char g_seen[1024];
static int  g_seen_len;
static int  g_block;     /* if 1, block when the request is seen */

static int test_inspect(const unsigned char *data, int len, int to_server,
			void *ud)
{
	(void)ud;
	if (to_server && g_seen_len + len < (int)sizeof(g_seen)) {
		memcpy(g_seen + g_seen_len, data, len);
		g_seen_len += len;
	}
	if (g_block && to_server &&
	    memmem(data, len, "secret-path", 11))
		return 1;     /* BLOCK */
	return 0;
}

/* -- helper: listener 127.0.0.1:0, returns fd + port ----------------------- */
static int make_loopback(uint16_t *port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in sa = { .sin_family = AF_INET };
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;
	bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	listen(fd, 8);
	socklen_t sl = sizeof(sa);
	getsockname(fd, (struct sockaddr *)&sa, &sl);
	*port = ntohs(sa.sin_port);
	return fd;
}

/* -- TLS client trusting the CA; returns the response read (NULL if handshake
 * fails) ------------------------------------------------------------------- */
static int tls_client(uint16_t proxy_port, struct ca_ctx *ca,
		      char *resp, int rcap)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa = { .sin_family = AF_INET };
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = htons(proxy_port);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), ca->cert);  /* "CA installed" */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	SSL *s = SSL_new(ctx);
	SSL_set_fd(s, fd);
	SSL_set_tlsext_host_name(s, "test.local");
	SSL_set1_host(s, "test.local");      /* check name matches cert */

	int rc = -1;
	if (SSL_connect(s) == 1) {
		SSL_write(s, REQ, (int)strlen(REQ));
		int n = SSL_read(s, resp, rcap - 1);
		if (n > 0) { resp[n] = '\0'; rc = n; }
		else rc = 0;          /* handshake OK but no data (blocked) */
	}
	SSL_shutdown(s);
	SSL_free(s);
	SSL_CTX_free(ctx);
	close(fd);
	return rc;
}

/* Run a scenario: returns the response the client received + bump_rc. */
static int run_scenario(struct ca_ctx *ca, struct certcache *cc,
			int verify_upstream, int block,
			char *resp, int rcap, int *bump_rc)
{
	g_seen_len = 0; g_seen[0] = '\0'; g_block = block;

	/* origin */
	struct ca_ctx origin_id;
	ca_load_or_create(&origin_id, "/tmp/sg_origin_c.pem", "/tmp/sg_origin_k.pem");
	struct origin o = { .id = &origin_id };
	o.fd = make_loopback(&o.port);
	pthread_t ot; pthread_create(&ot, NULL, origin_thread, &o);

	/* proxy */
	struct bump_cfg cfg = {
		.ca = ca, .cc = cc, .verify_upstream = verify_upstream,
		.inspect = test_inspect, .inspect_ud = NULL,
	};
	struct proxy p = { .cfg = &cfg, .bump_rc = -99 };
	p.fd = make_loopback(&p.port);
	p.origin_addr.sin_family = AF_INET;
	p.origin_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	p.origin_addr.sin_port = htons(o.port);
	pthread_t pt; pthread_create(&pt, NULL, proxy_thread, &p);

	/* client */
	int n = tls_client(p.port, ca, resp, rcap);

	pthread_join(pt, NULL);
	/* the origin thread may be stuck in accept on fail-closed (the client never
	 * reaches the origin); close the listener so it exits. */
	close(o.fd);
	pthread_join(ot, NULL);
	close(p.fd);
	ca_free(&origin_id);
	unlink("/tmp/sg_origin_c.pem"); unlink("/tmp/sg_origin_k.pem");

	*bump_rc = p.bump_rc;
	return n;
}

int main(void)
{
	SSL_library_init();
	unlink("/tmp/sg_bca_c.pem"); unlink("/tmp/sg_bca_k.pem");

	struct ca_ctx ca;
	if (ca_load_or_create(&ca, "/tmp/sg_bca_c.pem", "/tmp/sg_bca_k.pem") != 0) {
		printf("FAIL: create CA\n");
		return 1;
	}
	struct certcache *cc = certcache_new(&ca, 16);

	char resp[1024];
	int bump_rc;

	printf("== test 1: bump happy-path (verify_upstream=0) ==\n");
	{
		int n = run_scenario(&ca, cc, 0, 0, resp, sizeof(resp), &bump_rc);
		CHECK(n > 0, "client handshake with FORGED cert succeeds (trusts CA)");
		CHECK(n > 0 && strstr(resp, "HELLO"),
		      "client receives the correct response through decryption");
		CHECK(memmem(g_seen, g_seen_len, "secret-path", 11) != NULL,
		      "inspect() sees the decrypted plaintext request");
	}

	printf("== test 2: inspect BLOCK -> cut connection ==\n");
	{
		int n = run_scenario(&ca, cc, 0, 1, resp, sizeof(resp), &bump_rc);
		/* handshake still completes (n>=0), but there is no HELLO response */
		CHECK(!(n > 0 && strstr(resp, "HELLO")),
		      "request blocked -> client does NOT receive a response");
	}

	printf("== test 3: fail-closed (verify_upstream=1, origin self-signed) ==\n");
	{
		int n = run_scenario(&ca, cc, 1, 0, resp, sizeof(resp), &bump_rc);
		CHECK(bump_rc != 0, "bump_run returns an error (fail-closed)");
		CHECK(!(n > 0 && strstr(resp, "HELLO")),
		      "client does NOT receive data when the upstream cert is untrusted");
	}

	certcache_free(cc);
	ca_free(&ca);
	unlink("/tmp/sg_bca_c.pem"); unlink("/tmp/sg_bca_k.pem");

	if (g_fail) { printf("\n== %d TEST FAIL ==\n", g_fail); return 1; }
	printf("\n== ALL bump TESTS PASS ==\n");
	return 0;
}
