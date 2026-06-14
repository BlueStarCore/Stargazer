/* SPDX-License-Identifier: MIT */
/*
 * bump.c - MITM một flow TLS (xem bump.h).
 *
 * Dùng socket BLOCKING + poll trên hai raw fd để bơm plaintext hai chiều.
 * SSL_set_fd dùng BIO_NOCLOSE → bump tự close fd. Giới hạn MVP: half-close
 * không hoàn hảo (EOF một chiều → đóng cả hai); renegotiation giữa chừng dựa
 * vào SSL_read/SSL_write tự xử lý trên blocking socket.
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

/* Mở TCP tới đích gốc. Trả fd, -1 nếu lỗi. */
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

/* Ghi đủ len byte plaintext qua SSL (blocking → một lần là đủ hoặc lỗi). */
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
 * Bơm một chiều: đọc plaintext từ `from`, soi, ghi sang `to`.
 * Trả 1 nếu còn mở, 0 nếu EOF/đóng sạch, -1 nếu lỗi hoặc inspect CHẶN.
 * Drain SSL_pending để không kẹt dữ liệu đã nằm trong buffer SSL.
 * `out_written` (nếu != NULL): cộng dồn số byte đã ghi sang `to` — dùng để
 * biết response đã bắt đầu gửi cho client chưa (quyết định có chèn block page).
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
				return -2;          /* CHẶN (inspect DROP) — phân biệt lỗi */
			}
			if (ssl_write_all(to, buf, n) < 0)
				return -1;
			if (out_written)
				*out_written += (size_t)n;
			continue;
		}
		int e = SSL_get_error(from, n);
		if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
			return 1;                   /* chưa đủ record — chờ poll */
		if (e == SSL_ERROR_ZERO_RETURN)
			return 0;                   /* close_notify */
		return -1;                          /* lỗi/đứt */
	} while (SSL_pending(from) > 0);
	return 1;
}

/* Bắt tay TLS có thể trả WANT_* trên blocking socket (hiếm) — lặp lại. */
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

	/* ── [1] kết nối + bắt tay TLS RA SERVER THẬT ───────────────────── */
	up_fd = connect_tcp(dst);
	if (up_fd < 0) {
		fprintf(stderr, "bump: connect %s thất bại: %m\n", dip);
		goto out;
	}

	uctx = SSL_CTX_new(TLS_client_method());
	if (!uctx)
		goto out;
	SSL_CTX_set_min_proto_version(uctx, TLS1_2_VERSION);
	if (cfg->verify_upstream) {
		/* Trust store để biết cert server THẬT có hợp lệ không: bundle root CA
		 * ship trong rootfs (/etc/ssl/certs/ca-certificates.crt). KHÔNG có nó
		 * → OpenSSL không có root nào → MỌI server bị coi untrusted → chặn hết.
		 * Fallback default paths (OPENSSLDIR) nếu bundle thiếu. */
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
		SSL_set_tlsext_host_name(ussl, sni);   /* SNI ra server */
		if (cfg->verify_upstream)
			SSL_set1_host(ussl, sni);      /* kiểm tên trùng cert */
	}
	if (do_handshake(ussl, 0) < 0) {
		/* FAIL-CLOSED: server thật lỗi cert/handshake → KHÔNG bump */
		fprintf(stderr, "bump: upstream TLS %s thất bại "
			"(verify=%d) — fail-closed\n", host, cfg->verify_upstream);
		goto out;
	}
	upcert = SSL_get1_peer_certificate(ussl);   /* để mirror thời hạn */

	/* ── [2] forge cert + bắt tay TLS VỚI CLIENT (đóng vai server) ──── */
	cctx = SSL_CTX_new(TLS_server_method());
	if (!cctx)
		goto out;
	SSL_CTX_set_min_proto_version(cctx, TLS1_2_VERSION);

	{
		X509 *leaf = NULL; EVP_PKEY *key = NULL;
		if (certcache_get(cfg->cc, host, upcert, &leaf, &key) < 0) {
			fprintf(stderr, "bump: forge cert %s thất bại\n", host);
			goto out;
		}
		if (SSL_CTX_use_certificate(cctx, leaf) != 1 ||
		    SSL_CTX_use_PrivateKey(cctx, key) != 1) {
			goto out;
		}
		/* gửi kèm CA trong chain (client đã cài CA, nhưng cho đầy đủ) */
		if (X509_up_ref(cfg->ca->cert))
			SSL_CTX_add_extra_chain_cert(cctx, cfg->ca->cert);
	}

	cssl = SSL_new(cctx);
	if (!cssl)
		goto out;
	SSL_set_fd(cssl, client_fd);              /* BIO_NOCLOSE */
	if (do_handshake(cssl, 1) < 0) {
		fprintf(stderr, "bump: client TLS %s thất bại\n", host);
		goto out;
	}

	fprintf(stderr, "bump: %s%s ✓ giải mã\n",
		host, cfg->verify_upstream ? " (verified)" : "");

	/* ── [3] relay plaintext hai chiều + soi ────────────────────────── */
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
		/* DROP → ghi block page (FortiGate-style) ra client trước khi đóng.
		 * CHỈ chèn khi CHƯA byte response nào tới client: nếu response đã bắt
		 * đầu (DROP ở chiều server→client, vd signature trong response body),
		 * thì nối thêm HTTP 403 sẽ bị browser hiểu là BODY của response cũ →
		 * hiện nguyên text "HTTP/1.1 403 Forbidden Content-Type: t...". Trường
		 * hợp đó chỉ đóng kết nối (client thấy load lỗi, không phải trang giả). */
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
	close(client_fd);          /* bump consume client_fd */
	return rc;
}
