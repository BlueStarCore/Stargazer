/* SPDX-License-Identifier: MIT */
/*
 * conn.c - Handle a single connection (see conn.h).
 */
#define _POSIX_C_SOURCE 200809L
#include "conn.h"
#include "relay.h"
#include "origdst.h"
#include "bump.h"
#include "tls_clienthello.h"
#include "sig_rule.h"        /* ../ipsd: sig_match, struct flow_ctx, SIG_* */
#include "insp_ipc.h"        /* Phase 4: IPC client -> ipsd stateful engine */
#include <openssl/ssl.h>     /* SSL_write - block page to client */
#include <sys/un.h>          /* AF_UNIX socket to ipsd insp server */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>           /* timestamp for alert log */
#include <fcntl.h>          /* open O_APPEND alert log */
#include <sys/stat.h>       /* mkdir - ensure /etc/stargazer/logs */

/* Open TCP to the original destination (splice path). */
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
 * PEEK the ClientHello with MSG_PEEK (does NOT consume): loop poll->peek until
 * the parse returns something other than NEED_MORE or the limit is reached. The
 * bytes stay in the socket for the next step (relay forward on splice, or
 * SSL_accept reads them on bump).
 * Returns the parse result; fills *out.
 */
static enum tls_ch_result peek_clienthello(int fd, struct tls_clienthello *out)
{
	uint8_t buf[CONN_HELLO_MAX];
	enum tls_ch_result res = TLS_CH_NEED_MORE;

	for (int iter = 0; iter < 64; iter++) {
		struct pollfd p = { .fd = fd, .events = POLLIN };
		if (poll(&p, 1, 5000) <= 0)
			break;                       /* timeout/error */
		ssize_t n = recv(fd, buf, sizeof(buf), MSG_PEEK);
		if (n <= 0) {
			if (n < 0 && errno == EINTR)
				continue;
			break;                       /* client closed */
		}
		res = tls_parse_clienthello(buf, (size_t)n, out);
		if (res != TLS_CH_NEED_MORE)
			return res;
		if ((size_t)n >= sizeof(buf))
			return res;                  /* limit reached */
	}
	return res;
}

/* -- inspect callback: run the signature engine on decrypted plaintext ----- */
struct insp_ctx {
	struct sig_ruleset *rs;
	uint16_t            dport;
	const char         *host;
	/* for alert log: 5-tuple of the decrypted flow (filled in ssld_handle_conn). */
	char                src_ip[INET_ADDRSTRLEN];
	uint16_t            src_port;
	char                dst_ip[INET_ADDRSTRLEN];
	/* dedup: sids already alerted on this flow -> 1 alert/signature/flow (a
	 * response split across records, or a client retry on the same connection,
	 * will NOT spam). */
	uint32_t            seen_sids[32];
	int                 n_seen;
	/* block info (filled when conn_inspect decides DROP) - for the block page. */
	uint32_t            block_sid;
	char                block_msg[128];
	/* Phase 4 IPC: socket to the ipsd insp server (-1 = per-chunk fallback). */
	int                 ipc_fd;
	uint32_t            chunk_id;
	int                 fail_closed;   /* IPC error -> block flow instead of fallback */
};

/* Log alerts to the SAME file as ipsd so `execute diagnose ips alerts` also sees
 * detections on decrypted HTTPS (ipsd via NFQUEUE only sees cleartext HTTP; the
 * bump flow lives entirely inside ssld). Same line format as ipsd/main.c
 * log_alert. O_APPEND to a regular file is atomic => multiple writers (ipsd +
 * several ssld) do not tear lines. The log dir may not exist on persistent
 * storage -> mkdir. */
#define SSLD_ALERT_LOG "/etc/stargazer/logs/ips-alert.log"

/* is_ml: verdict came from the ML model (insp_verdict_body.src==1), not a
 * signature. Render the SAME reason/score vocabulary as the NFQUEUE path
 * (ipsd main.c log_alert): ML → reason=ml-block/ml-alert + numeric score;
 * signature → reason=signature score=n/a. Mislabelling ML as "signature" (the
 * old hardcoded behaviour) hid that these hits had no sid and came from the
 * model — confusing on the firewall, where the reason is what gets triaged. */
static void ssld_log_alert(const struct insp_ctx *ic, int drop,
			   uint32_t sid, const char *msg, int is_ml, float score)
{
	time_t now = time(NULL);
	struct tm tm; localtime_r(&now, &tm);
	char ts[24]; strftime(ts, sizeof(ts), "%F %T", &tm);

	const char *reason = is_ml ? (drop ? "ml-block" : "ml-alert") : "signature";
	char scorebuf[16];
	if (is_ml)
		snprintf(scorebuf, sizeof(scorebuf), "%.3f", (double)score);
	else
		snprintf(scorebuf, sizeof(scorebuf), "n/a");

	char line[512];
	int ln = snprintf(line, sizeof(line),
		"%s %s proto=6 src=%s:%u dst=%s:%u "
		"reason=%s score=%s sid=%u msg=%s\n",
		ts, drop ? "DROP" : "ALERT",
		ic->src_ip[0] ? ic->src_ip : "?", ic->src_port,
		ic->dst_ip[0] ? ic->dst_ip : "?", ic->dport,
		reason, scorebuf, sid, msg ? msg : "");
	if (ln < 0)
		return;
	if (ln > (int)sizeof(line))
		ln = sizeof(line);

	int fd = open(SSLD_ALERT_LOG,
		      O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
	if (fd < 0) {
		mkdir("/etc/stargazer/logs", 0755);   /* dir may not exist yet */
		fd = open(SSLD_ALERT_LOG,
			  O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
		if (fd < 0)
			return;
	}
	if (write(fd, line, (size_t)ln) < 0)
		fprintf(stderr, "ssld: alert log write failed: %m\n");
	close(fd);
}

/* Dedup per flow + log alert (1 line/sid/flow) + record block info if DROP.
 * is_ml/score: pass the verdict's source so the log reason matches reality
 * (ML vs signature); signature callers pass is_ml=0, score=0. */
static void conn_alert(struct insp_ctx *ic, int drop, uint32_t sid,
		       const char *msg, int to_server, int is_ml, float score)
{
	if (drop) {
		ic->block_sid = sid;
		snprintf(ic->block_msg, sizeof(ic->block_msg), "%s",
			 msg ? msg : "");
	}
	for (int i = 0; i < ic->n_seen; i++)
		if (ic->seen_sids[i] == sid)
			return;             /* already alerted this sid on the flow */
	if (ic->n_seen < (int)(sizeof(ic->seen_sids) / sizeof(ic->seen_sids[0])))
		ic->seen_sids[ic->n_seen++] = sid;
	ssld_log_alert(ic, drop, sid, msg, is_ml, score);
	fprintf(stderr, "ssld: SIG %s host=%s dir=%s sid=%u msg=%s\n",
		drop ? "DROP" : "ALERT", ic->host,
		to_server ? "->srv" : "<-srv", sid, msg ? msg : "");
}

/* Per-chunk fallback (when IPC is unavailable) - inspect each SSL_read buffer
 * separately. */
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
		   ic->rs->rules[idx].msg, to_server, 0 /*signature*/, 0.0f);
	return drop ? 1 : 0;
}

/* Phase 4: push a plaintext chunk over IPC to the ipsd stateful engine (reass +
 * AC + verify), WAIT for the verdict (inline prevent). IPC error -> close +
 * fallback. */
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
			/* fail-closed: IPC error -> block flow (safer). */
			conn_alert(ic, 1, 0, "IPC inspection unavailable",
				   to_server, 0 /*not ML*/, 0.0f);
			return 1;
		}
		return conn_inspect_local(ic, data, len, to_server);
	}
	if (reply.v.action == INSP_DROP) {
		conn_alert(ic, 1, reply.v.sid, reply.v.msg, to_server,
			   reply.v.src == 1 /*ML*/, reply.v.score);
		return 1;
	}
	if (reply.v.action == INSP_ALERT)
		conn_alert(ic, 0, reply.v.sid, reply.v.msg, to_server,
			   reply.v.src == 1 /*ML*/, reply.v.score);
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

/* Open an IPC socket to the ipsd insp server + send OPEN (with leg_tuple for ML).
 * client_fd is used for getpeername (client) + getsockname (fw). Returns fd, or
 * -1. */
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
	m.o.profile_id = 0;             /* apply all rules (ssld does not scope by profile yet) */
	snprintf(m.o.sni, sizeof(m.o.sni), "%s", sni ? sni : "");

	/* Phase 2 - client->ssld leg so ipsd can read CTA_ML. */
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

/* -- Block page (FortiGate-style) - matches webui/www/block.html ----------- */
/* Note: this is an snprintf format string, so every literal '%' in the CSS must
 * be '%%'; the CSS here avoids '%' to keep it clean. Placeholders: %s=URL,
 * %s=signature, %s=description. */
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

/* Minimal escaping to insert the host into HTML safely (prevents tag injection). */
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

/* SSL_write everything (a partial write truncates the block page to
 * "...Content-Type: t"). Loop until complete; WANT_READ/WRITE -> retry. Returns
 * 0 OK, -1 error. */
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

	/* Do NOT put the signature/SID on the page (avoid leaking detection detail). */
	char body[6144];
	int blen = snprintf(body, sizeof(body), SSLD_BLOCK_HTML, url, "");
	if (blen < 0)
		return;
	if (blen >= (int)sizeof(body))      /* snprintf truncated -> use actual length */
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
	/* Write the header in full, then the body - don't let a partial write cut
	 * the response. */
	if (ssl_write_full(client, hdr, hlen) == 0)
		ssl_write_full(client, body, blen);
}

/* Callback for bump_run: inspect DROP -> write the block page to the client. */
static void conn_on_block(void *client_ssl, void *ud)
{
	ssld_send_block_page((SSL *)client_ssl, (const struct insp_ctx *)ud);
}

void ssld_handle_conn(int client_fd, const struct ssld_ctx *ctx,
		      struct ssld_stats *st)
{
	if (st) st->n_total++;

	/* [1] original destination */
	struct sockaddr_in dst;
	if (origdst_get(client_fd, &dst) < 0) {
		if (st) st->n_error++;
		close(client_fd);
		return;
	}

	/* Loop guard: a connection made DIRECTLY to the ssld port (not via REDIRECT)
	 * has origdst == the socket's own local address - whereas a legitimate flow
	 * has origdst = server:443 != local:<listen_port>. If allowed to proceed,
	 * ssld would open an upstream back to its own port -> infinite recursion
	 * (DoS). Reject immediately. */
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

	/* [2] peek ClientHello (does not consume) */
	struct tls_clienthello ch;
	enum tls_ch_result res = peek_clienthello(client_fd, &ch);
	int has_sni = (res == TLS_CH_OK && ch.has_sni);
	const char *sni = has_sni ? ch.sni : NULL;

	/* [3] decision */
	enum tls_action act = tls_policy_decide(ctx->pol, sni, has_sni);

	/* [4b] BUMP - if CA infrastructure is available */
	if (act == TLS_BUMP && ctx->ca && ctx->cc) {
		if (st) st->n_bump++;
		struct insp_ctx ic = {
			.rs = ctx->rules, .dport = (uint16_t)dport,
			.host = has_sni ? ch.sni : dip,
		};
		/* 5-tuple for alert log: dst = ORIGINAL destination, src = real client. */
		snprintf(ic.dst_ip, sizeof(ic.dst_ip), "%s", dip);
		struct sockaddr_in peer;
		socklen_t plen = sizeof(peer);
		if (getpeername(client_fd, (struct sockaddr *)&peer, &plen) == 0) {
			inet_ntop(AF_INET, &peer.sin_addr, ic.src_ip,
				  sizeof(ic.src_ip));
			ic.src_port = ntohs(peer.sin_port);
		}
		/* Phase 4: try to connect IPC to the ipsd stateful engine. no_ipc -> skip
		 * (per-chunk inspection). Failure -> ipc_fd=-1 -> fallback per failmode. */
		ic.fail_closed = ctx->ipc_failclosed;
		ic.ipc_fd = ctx->no_ipc ? -1
				: ssld_ipc_open(client_fd, ic.dport, sni, &dst);

		struct bump_cfg bc = {
			.ca = ctx->ca, .cc = ctx->cc,
			.verify_upstream = ctx->verify_upstream,
			.inspect = conn_inspect, .inspect_ud = &ic,
			.on_block = conn_on_block,
		};
		bump_run(client_fd, sni, &dst, &bc);   /* consumes client_fd */
		ssld_ipc_close(ic.ipc_fd);
		return;
	}

	/* [4a] SPLICE (or bump unavailable -> fallback) */
	if (st) st->n_splice++;
	fprintf(stderr, "ssld: SPLICE %s:%d sni=%s\n",
		dip, dport, has_sni ? ch.sni : "(none)");

	int up = connect_upstream(&dst);
	if (up < 0) {
		if (st) st->n_error++;
		fprintf(stderr, "ssld: connect %s:%d failed: %m\n", dip, dport);
		close(client_fd);
		return;
	}
	relay_pump(client_fd, up);   /* ClientHello still in socket -> relayed naturally */
	close(up);
	close(client_fd);
}
