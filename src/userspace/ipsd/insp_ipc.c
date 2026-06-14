/* SPDX-License-Identifier: MIT */
/*
 * insp_ipc.c — Phase 4 server: nhận plaintext HTTPS từ ssld, soi bằng CHÍNH
 * engine stateful của ipsd (reass + AC streaming + verify + flowbits), trả
 * verdict. Mỗi kết nối ssld = 1 handler thread sở hữu virtual-flow riêng;
 * rdlock(ruleset) khi soi (dùng chung an toàn với NFQUEUE — verify read-only).
 *
 * ADDITIVE: KHÔNG sửa process_packet / main loop NFQUEUE / CTA_ML.
 */
#define _GNU_SOURCE
#include "insp_ipc.h"
#include "sig_reload.h"
#include "sig_rule.h"
#include "reass.h"
#include "proto_buf.h"
#include "ctdump.h"      /* Phase 2: query CTA_ML của leg */
#include "ips_model.h"   /* ips_score */
#include "fusion.h"      /* ips_fuse, struct ips_decision */
#include "engine.h"      /* struct ips_config */
#include "feature.h"     /* FEAT_COUNT, struct flow_stats */
#include <arpa/inet.h>   /* ntohl */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>

/* Telemetry (Phase 4) — không đụng số liệu cũ. */
#define INSP_STAT_PATH "/run/stargazer-ipsd-insp.stat"
static _Atomic unsigned long g_conns_total, g_conns_open, g_chunks,
			     g_sig_hits, g_blocked, g_ml_hits;

/* Phase 2 — config ML (mode/threshold) từ main; con trỏ tới g_cfg (ổn định). */
static const struct ips_config *g_ips_cfg;

/* Ngưỡng checkpoint ML (khớp main.c). */
#define INSP_ML_PKTS   24u
#define INSP_ML_BYTES  14000ULL

/* Virtual flow của một kết nối HTTPS (sở hữu bởi handler thread). */
struct insp_conn {
	struct reass_flow    rf;
	struct flowbit_state fb;
	struct flow_ctx      fc;        /* proto/dport/prof_id cố định theo OPEN  */
	uint32_t             next_off[2];
	int                  rf_inited;
	char                 sni[256];
	/* Phase 2 — leg client→ssld (host order) cho ML; ml_done: chấm 1 lần/conn. */
	uint32_t             leg_cli_ip, leg_fw_ip;   /* host order */
	uint16_t             leg_cli_port, leg_fw_port;
	uint8_t              ml_done;
};

/* Bối cảnh truyền vào reass callback — y hệt l2_on_match của main.c. */
struct insp_match {
	const struct sig_ruleset *rs;
	struct reass_flow        *rf;
	struct flow_ctx           fc;
	struct flowbit_state     *fb;
	int                       best_idx;
	int                       best_action;
	struct match_buffers      bufs;
};

/* AC fast-pattern khớp trên dòng đã ráp → verify đầy đủ + flowbits (read-only
 * ruleset). Sao y main.c:l2_on_match. */
static int insp_on_match(int rule_id, uint64_t end_off, int dir, void *ctx)
{
	(void)end_off;
	struct insp_match *m = ctx;
	uint32_t clen = 0;
	const uint8_t *buf = reass_dir_buf(m->rf, dir, &clen);
	if (!buf)
		return 0;
	bufs_init_raw(&m->bufs, buf, (int)clen);
	bufs_extract(&m->bufs, buf, (int)clen);
	m->fc.bufs = &m->bufs;
	if (!sig_verify(m->rs, rule_id, buf, (int)clen, &m->fc))
		return 0;               /* AC prefilter hit nhưng verify trượt */
	const struct sig_rule *r = &m->rs->rules[rule_id];
	sig_flowbits_apply(r, m->fb);
	if (r->fb_noalert)
		return 0;               /* chỉ set cờ, không verdict */
	int action = r->action;
	if (r->fidelity == SIG_FID_ALERT)
		action = SIG_ALERT;     /* fidelity cap */
	if (action > m->best_action) {
		m->best_action = action;
		m->best_idx = rule_id;
	}
	return (m->best_action == SIG_DROP);   /* DROP → dừng sớm */
}

/* Soi 1 chunk DATA, trả verdict qua *vb (đã điền). */
static void insp_handle_data(struct insp_conn *c, struct sig_reload *sr,
			     int dir01, uint32_t chunk_id,
			     const uint8_t *plain, uint32_t len,
			     struct insp_verdict_body *vb)
{
	memset(vb, 0, sizeof(*vb));
	vb->chunk_id = chunk_id;
	vb->action   = INSP_PASS;
	vb->score    = -1.0f;

	int dir = (dir01 == 1) ? REASS_TO_CLIENT : REASS_TO_SERVER;

	pthread_rwlock_rdlock(&sr->rwlock);
	const struct sig_ruleset *rs = sr->active;

	struct insp_match mm;
	memset(&mm, 0, sizeof(mm));
	mm.rs = rs; mm.rf = &c->rf; mm.fb = &c->fb;
	mm.best_idx = -1; mm.best_action = -1;
	mm.fc = c->fc;
	mm.fc.to_server = (dir == REASS_TO_SERVER) ? 1 : 0;
	mm.fc.fb = &c->fb;

	if (!c->rf_inited) {
		if (reass_flow_init(&c->rf, &rs->ac, 0) == 0)
			c->rf_inited = 1;
		memset(&c->fb, 0, sizeof(c->fb));
	} else if (c->rf.ac != &rs->ac) {
		/* ruleset reload giữa chừng → rebind + re-scan dòng đã ráp */
		memset(&c->fb, 0, sizeof(c->fb));
		reass_flow_rebind(&c->rf, &rs->ac, insp_on_match, &mm);
	}

	if (c->rf_inited && plain && len) {
		reass_segment(&c->rf, dir, c->next_off[dir], plain, len,
			      insp_on_match, &mm);
		c->next_off[dir] += len;
	}

	if (mm.best_idx >= 0) {
		const struct sig_rule *r = &rs->rules[mm.best_idx];
		vb->action = (mm.best_action == SIG_DROP) ? INSP_DROP : INSP_ALERT;
		vb->sid    = r->sid;
		vb->src    = 0;
		snprintf(vb->msg, sizeof(vb->msg), "%s", r->msg);
	}
	pthread_rwlock_unlock(&sr->rwlock);

	atomic_fetch_add(&g_chunks, 1);
	if (vb->action != INSP_PASS) atomic_fetch_add(&g_sig_hits, 1);
	if (vb->action == INSP_DROP) atomic_fetch_add(&g_blocked, 1);

	/* Phase 2 — ML cho HTTPS: KHÔNG match signature + chưa chấm + có leg →
	 * đọc CTA_ML của leg client→ssld (do kernel LOCAL_IN hook tích lũy khi
	 * ml-https bật) → ips_score → ips_fuse. Gọi NGOÀI rdlock (netlink I/O).
	 * Tuple không khớp / CTA_ML rỗng → ml_valid=0 → bỏ qua (degrade sạch). */
	if (vb->action == INSP_PASS && g_ips_cfg && !c->ml_done &&
	    c->leg_cli_ip && c->leg_fw_ip) {
		struct ctdump_result ctr;
		if (ctdump_query(c->leg_cli_ip, c->leg_fw_ip,
				 c->leg_cli_port, c->leg_fw_port,
				 6 /* IPPROTO_TCP */, &ctr) == 0 && ctr.ml_valid) {
			struct flow_stats fs;
			ctdump_to_flow_stats(&ctr, &fs);
			uint32_t N = fs.pkts_fwd + fs.pkts_bwd;
			uint64_t B = ctr.ml.bytes_fwd + ctr.ml.bytes_bwd;
			if (N >= INSP_ML_PKTS || B >= INSP_ML_BYTES) {
				double feat[FEAT_COUNT];
				ctdump_to_features(&ctr, fs.pkts_fwd, fs.pkts_bwd,
						   -1, feat);
				double sc = ips_score(feat);
				struct ips_decision d =
					ips_fuse(g_ips_cfg, -1, 0, sc);
				c->ml_done = 1;
				vb->src   = 1;          /* ML */
				vb->score = (float)sc;
				if (d.verdict == IPS_DROP)
					vb->action = INSP_DROP;
				else if (d.verdict == IPS_ALERT)
					vb->action = INSP_ALERT;
				if (vb->action != INSP_PASS) {
					snprintf(vb->msg, sizeof(vb->msg),
						 "ML anomaly (score %.2f)", sc);
					atomic_fetch_add(&g_ml_hits, 1);
				}
			}
		}
	}
}

struct conn_arg { int fd; struct sig_reload *sr; };

/* Một handler thread cho một kết nối ssld. */
static void *insp_conn_thread(void *arg)
{
	struct conn_arg *a = arg;
	int fd = a->fd;
	struct sig_reload *sr = a->sr;
	free(a);
	atomic_fetch_add(&g_conns_total, 1);
	atomic_fetch_add(&g_conns_open, 1);

	struct insp_conn c;
	memset(&c, 0, sizeof(c));

	const size_t cap = sizeof(struct insp_hdr) +
			   sizeof(struct insp_data_body) + INSP_MAX_PLAIN;
	uint8_t *buf = malloc(cap);
	if (!buf) { close(fd); return NULL; }

	for (;;) {
		ssize_t n = recv(fd, buf, cap, 0);
		if (n <= 0) {
			if (n < 0 && errno == EINTR) continue;
			break;
		}
		if ((size_t)n < sizeof(struct insp_hdr))
			continue;
		struct insp_hdr *h = (struct insp_hdr *)buf;

		if (h->type == INSP_OPEN) {
			if ((size_t)n < sizeof(struct insp_hdr) +
					sizeof(struct insp_open_body))
				continue;
			struct insp_open_body *o = (struct insp_open_body *)
				(buf + sizeof(struct insp_hdr));
			c.fc.proto       = SIG_PROTO_TCP;
			/* Plaintext sau giải mã TLS LÀ HTTP ở L7. Hầu hết ET HTTP
			 * signature scoped $HTTP_PORTS={80,8080,8000,8008} — KHÔNG
			 * có 443. Nếu đưa cổng TLS thật (443) vào fc.dport thì
			 * port_match() trượt → MỌI rule HTTP bị bỏ qua âm thầm trên
			 * HTTPS giải mã (đã chứng minh: dport=443 không khớp, dport=80
			 * khớp). Chuẩn hoá về 80 để soi như HTTP, độc lập cổng TLS.
			 * (srv_port gốc vẫn ở o->srv_port nếu cần cho log/leg.) */
			c.fc.dport       = 80;
			c.fc.prof_id     = o->profile_id;
			c.fc.established = 1;   /* leg proxy đã established */
			o->sni[sizeof(o->sni) - 1] = '\0';
			snprintf(c.sni, sizeof(c.sni), "%s", o->sni);
			/* leg → host order cho ctdump_query (ip getpeername = net order). */
			c.leg_cli_ip   = ntohl(o->leg_cli_ip);
			c.leg_fw_ip    = ntohl(o->leg_fw_ip);
			c.leg_cli_port = o->leg_cli_port;
			c.leg_fw_port  = o->leg_fw_port;

		} else if (h->type == INSP_DATA) {
			if ((size_t)n < sizeof(struct insp_hdr) +
					sizeof(struct insp_data_body))
				continue;
			struct insp_data_body *d = (struct insp_data_body *)
				(buf + sizeof(struct insp_hdr));
			size_t off = sizeof(struct insp_hdr) +
				     sizeof(struct insp_data_body);
			uint32_t len = d->len;
			if (len > INSP_MAX_PLAIN || off + len > (size_t)n)
				len = (off <= (size_t)n) ? (uint32_t)(n - off) : 0;

			struct {
				struct insp_hdr          h;
				struct insp_verdict_body v;
			} reply;
			memset(&reply, 0, sizeof(reply));
			reply.h.type    = INSP_VERDICT;
			reply.h.conn_id = h->conn_id;
			insp_handle_data(&c, sr, d->dir, d->chunk_id,
					 buf + off, len, &reply.v);

			if (send(fd, &reply, sizeof(reply), MSG_NOSIGNAL) < 0)
				break;

		} else if (h->type == INSP_CLOSE) {
			break;
		}
	}

	free(buf);
	if (c.rf_inited)
		reass_flow_free(&c.rf);
	close(fd);
	atomic_fetch_sub(&g_conns_open, 1);
	return NULL;
}

/* Ghi telemetry định kỳ ra INSP_STAT_PATH (không đụng số liệu cũ). */
static void *insp_stat_thread(void *arg)
{
	(void)arg;
	for (;;) {
		struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
		nanosleep(&ts, NULL);
		FILE *f = fopen(INSP_STAT_PATH, "w");
		if (!f)
			continue;
		fprintf(f,
			"conns_total=%lu\nconns_open=%lu\nchunks=%lu\n"
			"sig_hits_https=%lu\nml_hits_https=%lu\nblocked_https=%lu\n",
			atomic_load(&g_conns_total), atomic_load(&g_conns_open),
			atomic_load(&g_chunks), atomic_load(&g_sig_hits),
			atomic_load(&g_ml_hits), atomic_load(&g_blocked));
		fclose(f);
	}
	return NULL;
}

/* Acceptor thread: listen SEQPACKET, mỗi kết nối → 1 handler thread. */
static void *insp_accept_thread(void *arg)
{
	struct sig_reload *sr = arg;

	int lfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (lfd < 0) {
		fprintf(stderr, "insp_ipc: socket: %m\n");
		return NULL;
	}
	struct sockaddr_un sa;
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", INSP_SOCK_PATH);
	unlink(INSP_SOCK_PATH);
	if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		fprintf(stderr, "insp_ipc: bind %s: %m\n", INSP_SOCK_PATH);
		close(lfd);
		return NULL;
	}
	if (listen(lfd, 64) < 0) {
		fprintf(stderr, "insp_ipc: listen: %m\n");
		close(lfd);
		unlink(INSP_SOCK_PATH);
		return NULL;
	}
	fprintf(stderr, "insp_ipc: server lắng nghe %s\n", INSP_SOCK_PATH);

	for (;;) {
		int cfd = accept(lfd, NULL, NULL);
		if (cfd < 0) {
			if (errno == EINTR) continue;
			break;
		}
		struct conn_arg *a = malloc(sizeof(*a));
		if (!a) { close(cfd); continue; }
		a->fd = cfd; a->sr = sr;
		pthread_t th;
		if (pthread_create(&th, NULL, insp_conn_thread, a) != 0) {
			fprintf(stderr, "insp_ipc: pthread_create: %m\n");
			close(cfd);
			free(a);
			continue;
		}
		pthread_detach(th);
	}
	close(lfd);
	unlink(INSP_SOCK_PATH);
	return NULL;
}

int insp_ipc_start(struct sig_reload *sr, const struct ips_config *cfg)
{
	if (!sr)
		return -1;
	g_ips_cfg = cfg;        /* Phase 2: dùng cho ML fuse (NULL → không chấm ML) */
	pthread_t th;
	if (pthread_create(&th, NULL, insp_accept_thread, sr) != 0) {
		fprintf(stderr, "insp_ipc: không tạo được acceptor thread: %m\n");
		return -1;
	}
	pthread_detach(th);

	pthread_t st;
	if (pthread_create(&st, NULL, insp_stat_thread, NULL) == 0)
		pthread_detach(st);   /* telemetry — không bắt buộc */
	return 0;
}
