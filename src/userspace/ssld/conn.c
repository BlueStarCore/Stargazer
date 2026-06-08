/* SPDX-License-Identifier: MIT */
/*
 * conn.c - Xử lý một kết nối (xem conn.h).
 */
#define _POSIX_C_SOURCE 200809L
#include "conn.h"
#include "relay.h"
#include "origdst.h"
#include "bump.h"
#include "tls_clienthello.h"
#include "sig_rule.h"        /* ../ipsd: sig_match, struct flow_ctx, SIG_* */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Mở TCP tới đích gốc (đường splice). */
static int connect_upstream(const struct sockaddr_in *dst)
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

/*
 * PEEK ClientHello bằng MSG_PEEK (KHÔNG tiêu thụ): lặp poll→peek tới khi parse
 * khác NEED_MORE hoặc đầy hạn mức. Byte vẫn nằm trong socket cho bước sau
 * (relay forward khi splice, hoặc SSL_accept đọc khi bump).
 * Trả kết quả parse; điền *out.
 */
static enum tls_ch_result peek_clienthello(int fd, struct tls_clienthello *out)
{
	uint8_t buf[CONN_HELLO_MAX];
	enum tls_ch_result res = TLS_CH_NEED_MORE;

	for (int iter = 0; iter < 64; iter++) {
		struct pollfd p = { .fd = fd, .events = POLLIN };
		if (poll(&p, 1, 5000) <= 0)
			break;                       /* timeout/lỗi */
		ssize_t n = recv(fd, buf, sizeof(buf), MSG_PEEK);
		if (n <= 0) {
			if (n < 0 && errno == EINTR)
				continue;
			break;                       /* client đóng */
		}
		res = tls_parse_clienthello(buf, (size_t)n, out);
		if (res != TLS_CH_NEED_MORE)
			return res;
		if ((size_t)n >= sizeof(buf))
			return res;                  /* hết hạn mức */
	}
	return res;
}

/* ── inspect callback: chạy signature engine trên plaintext đã giải mã ──── */
struct insp_ctx {
	struct sig_ruleset *rs;
	uint16_t            dport;
	const char         *host;
};

static int conn_inspect(const unsigned char *data, int len, int to_server,
			void *ud)
{
	struct insp_ctx *ic = ud;
	if (!ic->rs || len <= 0)
		return 0;

	struct flow_ctx fc = {
		.proto     = SIG_PROTO_TCP,
		.dport     = ic->dport,
		.tcp_flags = 0,
	};
	int idx = sig_match(ic->rs, data, (size_t)len, &fc);
	if (idx < 0)
		return 0;

	int action = ic->rs->rules[idx].action;
	fprintf(stderr, "ssld: SIG %s host=%s dir=%s sid=%u msg=%s\n",
		action == SIG_DROP ? "DROP" : "ALERT",
		ic->host, to_server ? "->srv" : "<-srv",
		ic->rs->rules[idx].sid, ic->rs->rules[idx].msg);

	return action == SIG_DROP ? 1 : 0;   /* DROP → chặn flow */
}

void ssld_handle_conn(int client_fd, const struct ssld_ctx *ctx,
		      struct ssld_stats *st)
{
	if (st) st->n_total++;

	/* [1] đích gốc */
	struct sockaddr_in dst;
	if (origdst_get(client_fd, &dst) < 0) {
		if (st) st->n_error++;
		close(client_fd);
		return;
	}
	char dip[INET_ADDRSTRLEN] = "?";
	inet_ntop(AF_INET, &dst.sin_addr, dip, sizeof(dip));
	int dport = ntohs(dst.sin_port);

	/* [2] peek ClientHello (không tiêu thụ) */
	struct tls_clienthello ch;
	enum tls_ch_result res = peek_clienthello(client_fd, &ch);
	int has_sni = (res == TLS_CH_OK && ch.has_sni);
	const char *sni = has_sni ? ch.sni : NULL;

	/* [3] quyết định */
	enum tls_action act = tls_policy_decide(ctx->pol, sni, has_sni);

	/* [4b] BUMP — nếu có hạ tầng CA */
	if (act == TLS_BUMP && ctx->ca && ctx->cc) {
		if (st) st->n_bump++;
		struct insp_ctx ic = {
			.rs = ctx->rules, .dport = (uint16_t)dport,
			.host = has_sni ? ch.sni : dip,
		};
		struct bump_cfg bc = {
			.ca = ctx->ca, .cc = ctx->cc,
			.verify_upstream = ctx->verify_upstream,
			.inspect = conn_inspect, .inspect_ud = &ic,
		};
		bump_run(client_fd, sni, &dst, &bc);   /* consume client_fd */
		return;
	}

	/* [4a] SPLICE (hoặc bump không khả dụng → fallback) */
	if (st) st->n_splice++;
	fprintf(stderr, "ssld: SPLICE %s:%d sni=%s\n",
		dip, dport, has_sni ? ch.sni : "(none)");

	int up = connect_upstream(&dst);
	if (up < 0) {
		if (st) st->n_error++;
		fprintf(stderr, "ssld: connect %s:%d thất bại: %m\n", dip, dport);
		close(client_fd);
		return;
	}
	relay_pump(client_fd, up);   /* ClientHello còn trong socket → relay tự nhiên */
	close(up);
	close(client_fd);
}
