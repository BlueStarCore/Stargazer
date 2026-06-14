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
#include "insp_ipc.h"        /* Phase 4: IPC client → engine stateful của ipsd */
#include <openssl/ssl.h>     /* SSL_write — block page ra client */
#include <sys/un.h>          /* AF_UNIX socket tới ipsd insp server */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>           /* timestamp cho alert log */
#include <fcntl.h>          /* open O_APPEND alert log */
#include <sys/stat.h>       /* mkdir — đảm bảo /etc/stargazer/logs */

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
	/* cho alert log: 5-tuple của flow đã giải mã (điền ở ssld_handle_conn). */
	char                src_ip[INET_ADDRSTRLEN];
	uint16_t            src_port;
	char                dst_ip[INET_ADDRSTRLEN];
	/* dedup: sid đã alert trên flow này → 1 alert/signature/flow (response bị
	 * chia nhiều record hoặc client retry trên cùng connection sẽ KHÔNG spam). */
	uint32_t            seen_sids[32];
	int                 n_seen;
	/* thông tin chặn (điền khi conn_inspect quyết DROP) — cho block page. */
	uint32_t            block_sid;
	char                block_msg[128];
	/* Phase 4 IPC: socket tới ipsd insp server (-1 = fallback per-chunk). */
	int                 ipc_fd;
	uint32_t            chunk_id;
	int                 fail_closed;   /* IPC lỗi → chặn flow thay vì fallback */
};

/* Log alert dùng CHUNG file với ipsd để `execute diagnose ips alerts` thấy được
 * cả phát hiện trên HTTPS đã giải mã (ipsd qua NFQUEUE chỉ thấy HTTP rõ; luồng
 * bump nằm hoàn toàn trong ssld). Cùng format dòng với ipsd/main.c log_alert.
 * O_APPEND lên file thường là atomic ⇒ nhiều writer (ipsd + nhiều ssld) không
 * xé dòng. Thư mục log có thể chưa tồn tại trên storage persistent → mkdir. */
#define SSLD_ALERT_LOG "/etc/stargazer/logs/ips-alert.log"

static void ssld_log_alert(const struct insp_ctx *ic, int drop,
			   uint32_t sid, const char *msg)
{
	time_t now = time(NULL);
	struct tm tm; localtime_r(&now, &tm);
	char ts[24]; strftime(ts, sizeof(ts), "%F %T", &tm);

	char line[512];
	int ln = snprintf(line, sizeof(line),
		"%s %s proto=6 src=%s:%u dst=%s:%u "
		"reason=signature score=n/a sid=%u msg=%s\n",
		ts, drop ? "DROP" : "ALERT",
		ic->src_ip[0] ? ic->src_ip : "?", ic->src_port,
		ic->dst_ip[0] ? ic->dst_ip : "?", ic->dport,
		sid, msg ? msg : "");
	if (ln < 0)
		return;
	if (ln > (int)sizeof(line))
		ln = sizeof(line);

	int fd = open(SSLD_ALERT_LOG,
		      O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
	if (fd < 0) {
		mkdir("/etc/stargazer/logs", 0755);   /* dir có thể chưa có */
		fd = open(SSLD_ALERT_LOG,
			  O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
		if (fd < 0)
			return;
	}
	if (write(fd, line, (size_t)ln) < 0)
		fprintf(stderr, "ssld: alert log write failed: %m\n");
	close(fd);
}

/* Dedup theo flow + ghi alert (1 dòng/sid/flow) + ghi block info nếu DROP. */
static void conn_alert(struct insp_ctx *ic, int drop, uint32_t sid,
		       const char *msg, int to_server)
{
	if (drop) {
		ic->block_sid = sid;
		snprintf(ic->block_msg, sizeof(ic->block_msg), "%s",
			 msg ? msg : "");
	}
	for (int i = 0; i < ic->n_seen; i++)
		if (ic->seen_sids[i] == sid)
			return;             /* đã alert sid này trên flow */
	if (ic->n_seen < (int)(sizeof(ic->seen_sids) / sizeof(ic->seen_sids[0])))
		ic->seen_sids[ic->n_seen++] = sid;
	ssld_log_alert(ic, drop, sid, msg);
	fprintf(stderr, "ssld: SIG %s host=%s dir=%s sid=%u msg=%s\n",
		drop ? "DROP" : "ALERT", ic->host,
		to_server ? "->srv" : "<-srv", sid, msg ? msg : "");
}

/* Fallback per-chunk (khi IPC không khả dụng) — soi rời từng buffer SSL_read. */
static int conn_inspect_local(struct insp_ctx *ic, const unsigned char *data,
			      int len, int to_server)
{
	if (!ic->rs || len <= 0)
		return 0;
	struct flow_ctx fc = {
		.proto = SIG_PROTO_TCP, .dport = ic->dport, .tcp_flags = 0,
	};
	int idx = sig_match(ic->rs, data, (size_t)len, &fc);
	if (idx < 0)
		return 0;
	int drop = (ic->rs->rules[idx].action == SIG_DROP);
	conn_alert(ic, drop, ic->rs->rules[idx].sid,
		   ic->rs->rules[idx].msg, to_server);
	return drop ? 1 : 0;
}

/* Phase 4: đẩy chunk plaintext qua IPC tới engine stateful của ipsd (reass +
 * AC + verify), CHỜ verdict (prevent inline). Lỗi IPC → đóng + fallback. */
static int conn_inspect_ipc(struct insp_ctx *ic, const unsigned char *data,
			    int len, int to_server)
{
	if (len > INSP_MAX_PLAIN)
		len = INSP_MAX_PLAIN;

	static __thread uint8_t sbuf[sizeof(struct insp_hdr) +
				     sizeof(struct insp_data_body) + INSP_MAX_PLAIN];
	struct insp_hdr *h = (struct insp_hdr *)sbuf;
	struct insp_data_body *d = (struct insp_data_body *)
		(sbuf + sizeof(struct insp_hdr));
	uint8_t *p = sbuf + sizeof(struct insp_hdr) + sizeof(struct insp_data_body);
	memset(h, 0, sizeof(*h));
	memset(d, 0, sizeof(*d));
	h->type     = INSP_DATA;
	d->dir      = to_server ? 0 : 1;
	d->chunk_id = ic->chunk_id++;
	d->len      = (uint32_t)len;
	memcpy(p, data, (size_t)len);
	size_t mlen = sizeof(struct insp_hdr) + sizeof(struct insp_data_body) +
		      (size_t)len;

	struct { struct insp_hdr h; struct insp_verdict_body v; } reply;
	if (send(ic->ipc_fd, sbuf, mlen, MSG_NOSIGNAL) < 0 ||
	    recv(ic->ipc_fd, &reply, sizeof(reply), 0) != (ssize_t)sizeof(reply) ||
	    reply.h.type != INSP_VERDICT) {
		close(ic->ipc_fd);
		ic->ipc_fd = -1;
		if (ic->fail_closed) {
			/* fail-closed: IPC lỗi → chặn flow (an toàn hơn). */
			conn_alert(ic, 1, 0, "IPC inspection unavailable", to_server);
			return 1;
		}
		return conn_inspect_local(ic, data, len, to_server);
	}
	if (reply.v.action == INSP_DROP) {
		conn_alert(ic, 1, reply.v.sid, reply.v.msg, to_server);
		return 1;
	}
	if (reply.v.action == INSP_ALERT)
		conn_alert(ic, 0, reply.v.sid, reply.v.msg, to_server);
	return 0;
}

static int conn_inspect(const unsigned char *data, int len, int to_server,
			void *ud)
{
	struct insp_ctx *ic = ud;
	if (len <= 0)
		return 0;
	if (ic->ipc_fd >= 0)
		return conn_inspect_ipc(ic, data, len, to_server);
	return conn_inspect_local(ic, data, len, to_server);
}

/* Mở socket IPC tới ipsd insp server + gửi OPEN (kèm leg_tuple cho ML).
 * client_fd để getpeername (client) + getsockname (fw). Trả fd, hoặc -1. */
static int ssld_ipc_open(int client_fd, uint16_t dport, const char *sni,
			 const struct sockaddr_in *dst)
{
	int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd < 0)
		return -1;
	struct sockaddr_un sa;
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", INSP_SOCK_PATH);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}
	struct { struct insp_hdr h; struct insp_open_body o; } m;
	memset(&m, 0, sizeof(m));
	m.h.type       = INSP_OPEN;
	m.o.srv_ip     = dst ? dst->sin_addr.s_addr : 0;
	m.o.srv_port   = dport;
	m.o.profile_id = 0;             /* áp mọi rule (ssld chưa scope profile) */
	snprintf(m.o.sni, sizeof(m.o.sni), "%s", sni ? sni : "");

	/* Phase 2 — leg client→ssld cho ipsd đọc CTA_ML. */
	struct sockaddr_in pa, la;
	socklen_t pl = sizeof(pa), ll = sizeof(la);
	if (getpeername(client_fd, (struct sockaddr *)&pa, &pl) == 0) {
		m.o.leg_cli_ip   = pa.sin_addr.s_addr;
		m.o.leg_cli_port = ntohs(pa.sin_port);
	}
	if (getsockname(client_fd, (struct sockaddr *)&la, &ll) == 0) {
		m.o.leg_fw_ip   = la.sin_addr.s_addr;
		m.o.leg_fw_port = ntohs(la.sin_port);
	}

	if (send(fd, &m, sizeof(m), MSG_NOSIGNAL) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void ssld_ipc_close(int fd)
{
	if (fd < 0)
		return;
	struct insp_hdr h;
	memset(&h, 0, sizeof(h));
	h.type = INSP_CLOSE;
	send(fd, &h, sizeof(h), MSG_NOSIGNAL);
	close(fd);
}

/* ── Block page (FortiGate-style) — khớp webui/www/block.html ────────────── */
/* Lưu ý: là format string của snprintf nên mọi '%' literal trong CSS phải là
 * '%%'; ở đây CSS tránh dùng '%' để khỏi rối. Placeholder: %s=URL, %s=signature,
 * %s=description. */
static const char SSLD_BLOCK_HTML[] =
"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
"<title>Access Blocked - Stargazer NGFW</title><style>"
"*{box-sizing:border-box}html,body{margin:0;min-height:100vh;background:"
"radial-gradient(circle at 50%% 0%%,#16203a,#0a0e1a 70%%);color:#e8eaf0;"
"font-family:Consolas,Menlo,monospace}"
".wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:32px}"
".card{width:100%%;max-width:640px;background:#141c30;border:1px solid #2a3452;"
"border-top:4px solid #d4524e;border-radius:10px;box-shadow:0 18px 50px rgba(0,0,0,.55);overflow:hidden}"
".head{display:flex;align-items:center;gap:14px;padding:22px 28px;border-bottom:1px solid #2a3452;"
"background:linear-gradient(180deg,rgba(212,82,78,.10),transparent)}"
".sh{width:46px;height:46px;border-radius:10px;display:flex;align-items:center;justify-content:center;"
"background:#8f2a27;border:1px solid #d4524e;font-size:24px}"
".brand{font-size:12px;letter-spacing:1px;color:#a0a8b8;text-transform:uppercase}"
".brand b{color:#e8956a}.title{font-size:19px;font-weight:700;margin-top:4px;color:#fff}"
".body{padding:24px 28px 28px}.lead{font-size:13.5px;line-height:1.6;color:#a0a8b8;margin:0 0 20px}"
".lead b{color:#e8eaf0}table{width:100%%;border-collapse:collapse;font-size:13px}"
"th,td{text-align:left;padding:11px 12px;vertical-align:top;border-bottom:1px solid #2a3452}"
"th{width:130px;color:#a0a8b8;font-weight:600;white-space:nowrap}td{word-break:break-all}"
"tr:last-child th,tr:last-child td{border-bottom:0}"
".pill{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;"
"background:#8f2a27;color:#ffd9d7;border:1px solid #d4524e}"
".foot{padding:16px 28px;border-top:1px solid #2a3452;font-size:11.5px;color:#a0a8b8;"
"display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}</style></head><body>"
"<div class=\"wrap\"><div class=\"card\" role=\"alert\">"
"<div class=\"head\"><div class=\"sh\">&#9888;</div><div>"
"<div class=\"brand\"><b>Stargazer NGFW</b> &middot; Intrusion Prevention</div>"
"<div class=\"title\">Access Blocked</div></div></div>"
"<div class=\"body\"><p class=\"lead\">Your request was blocked by "
"<b>Stargazer NGFW Intrusion Prevention</b> because it matched an attack "
"signature. If you believe this is an error, please contact your network "
"administrator.</p>"
"<table><tr><th>Status</th><td><span class=\"pill\">BLOCKED</span></td></tr>"
"<tr><th>URL</th><td>%s</td></tr>"
"<tr><th>Description</th><td>%s</td></tr></table></div>"
"<div class=\"foot\"><span>Stargazer NGFW &middot; Intrusion Prevention System</span>"
"<span>Blocked by IPS engine</span></div></div></div></body></html>";

/* Escape tối thiểu để chèn host vào HTML an toàn (chống nhúng thẻ). */
static void html_escape(const char *in, char *out, size_t cap)
{
	size_t o = 0;
	for (const char *p = in; p && *p && o + 7 < cap; p++) {
		const char *e = NULL;
		switch (*p) {
		case '<': e = "&lt;"; break;
		case '>': e = "&gt;"; break;
		case '&': e = "&amp;"; break;
		case '"': e = "&quot;"; break;
		case '\'': e = "&#39;"; break;
		default: out[o++] = *p; continue;
		}
		for (const char *q = e; *q; q++) out[o++] = *q;
	}
	out[o] = '\0';
}

/* SSL_write ghi HẾT (partial write → trang block bị cắt "...Content-Type: t").
 * Lặp tới khi đủ; WANT_READ/WRITE → thử lại. Trả 0 OK, -1 lỗi. */
static int ssl_write_full(SSL *s, const void *buf, int len)
{
	const char *p = buf;
	int off = 0;
	while (off < len) {
		int n = SSL_write(s, p + off, len - off);
		if (n > 0) { off += n; continue; }
		int e = SSL_get_error(s, n);
		if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ)
			continue;
		return -1;
	}
	return 0;
}

static void ssld_send_block_page(SSL *client, const struct insp_ctx *ic)
{
	if (!client || !ic)
		return;
	char hostraw[300], host[600], url[640];
	snprintf(hostraw, sizeof(hostraw), "%s",
		 (ic->host && ic->host[0]) ? ic->host : ic->dst_ip);
	html_escape(hostraw, host, sizeof(host));
	snprintf(url, sizeof(url), "https://%s/", host);

	/* KHÔNG đưa signature/SID ra trang (tránh lộ chi tiết phát hiện). */
	char body[6144];
	int blen = snprintf(body, sizeof(body), SSLD_BLOCK_HTML, url, "");
	if (blen < 0)
		return;
	if (blen >= (int)sizeof(body))      /* snprintf cắt → dùng độ dài thực */
		blen = (int)sizeof(body) - 1;
	char hdr[256];
	int hlen = snprintf(hdr, sizeof(hdr),
		"HTTP/1.1 403 Forbidden\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Cache-Control: no-store\r\n"
		"Connection: close\r\n"
		"Content-Length: %d\r\n\r\n", blen);
	if (hlen <= 0)
		return;
	/* Ghi HẾT header rồi body — không để partial-write cắt response. */
	if (ssl_write_full(client, hdr, hlen) == 0)
		ssl_write_full(client, body, blen);
}

/* Callback cho bump_run: inspect DROP → ghi block page ra client. */
static void conn_on_block(void *client_ssl, void *ud)
{
	ssld_send_block_page((SSL *)client_ssl, (const struct insp_ctx *)ud);
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

	/* Chống loop: kết nối TỚI THẲNG cổng ssld (không đi qua REDIRECT) có
	 * origdst == địa chỉ local của chính socket — còn flow hợp lệ thì origdst
	 * là server:443 ≠ local:<listen_port>. Nếu để chạy tiếp, ssld sẽ mở
	 * upstream về chính cổng của mình → đệ quy vô hạn (DoS). Từ chối ngay. */
	struct sockaddr_in local;
	socklen_t llen = sizeof(local);
	if (getsockname(client_fd, (struct sockaddr *)&local, &llen) == 0 &&
	    local.sin_addr.s_addr == dst.sin_addr.s_addr &&
	    local.sin_port == dst.sin_port) {
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
		/* 5-tuple cho alert log: dst = đích GỐC, src = client thật. */
		snprintf(ic.dst_ip, sizeof(ic.dst_ip), "%s", dip);
		struct sockaddr_in peer;
		socklen_t plen = sizeof(peer);
		if (getpeername(client_fd, (struct sockaddr *)&peer, &plen) == 0) {
			inet_ntop(AF_INET, &peer.sin_addr, ic.src_ip,
				  sizeof(ic.src_ip));
			ic.src_port = ntohs(peer.sin_port);
		}
		/* Phase 4: thử nối IPC tới engine stateful của ipsd. no_ipc → bỏ qua
		 * (soi per-chunk). Thất bại → ipc_fd=-1 → fallback theo failmode. */
		ic.fail_closed = ctx->ipc_failclosed;
		ic.ipc_fd = ctx->no_ipc ? -1
				: ssld_ipc_open(client_fd, ic.dport, sni, &dst);

		struct bump_cfg bc = {
			.ca = ctx->ca, .cc = ctx->cc,
			.verify_upstream = ctx->verify_upstream,
			.inspect = conn_inspect, .inspect_ud = &ic,
			.on_block = conn_on_block,
		};
		bump_run(client_fd, sni, &dst, &bc);   /* consume client_fd */
		ssld_ipc_close(ic.ipc_fd);
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
