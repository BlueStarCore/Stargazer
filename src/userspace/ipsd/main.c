/* SPDX-License-Identifier: MIT */
/*
 * main.c - stargazer-ipsd: IPS daemon cho Stargazer NGFW.
 *
 * Luồng mỗi gói từ NFQUEUE:
 *   nfq_recv → ctdump_query (CTA_ML + ACCT) → ctdump_to_flow_stats/features
 *   → ips_evaluate (L1-builtin → L1-user → L2-payload → ML)
 *   → nfq_verdict (ACCEPT/DROP + set connmark)
 *   → rule_gen_feed (nếu ML block, không sig)
 *   → log_alert (nếu ALERT/DROP)
 *
 * Config đọc từ mgmtd (SG_CMD_CFG_GET "security_ips") lúc khởi động; nếu
 * mgmtd chưa có type đó thì dùng giá trị mặc định. Reload ruleset qua SIGUSR1.
 * Graceful shutdown qua SIGTERM/SIGINT.
 *
 * Iptables rules cần mgmtd thêm khi IPS bật (rebuild_forward_chain):
 *   -I FORWARD 1 -m connmark --mark 0x2/0x2 -j DROP
 *   -I FORWARD 2 -m conntrack --ctstate NEW \
 *               -m connmark ! --mark 0x4/0x4 -j NFQUEUE --queue-num 0
 */
#define _GNU_SOURCE
#include "nfq.h"
#include "ctdump.h"
#include "engine.h"
#include "flow_rule.h"
#include "sig_reload.h"
#include "rule_gen.h"
#include "fusion.h"
#include "feature.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/select.h>
#include <arpa/inet.h>

/* IPC mgmtd — chỉ dùng để đọc config, không bắt buộc */
#include <sys/socket.h>
#include <sys/un.h>

#define MGMTD_SOCK      "/run/stargazer-mgmtd.sock"
#define DEFAULT_RULES   "/etc/stargazer/ips/rules/active.rules"
#define ALERT_LOG       "/etc/stargazer/logs/ips-alert.log"
#define AUTORULE_SAVE   "/etc/stargazer/ips/auto.rules"

/* ---- config -------------------------------------------------------------- */

struct ipsd_config {
	int      enabled;
	int      mode;            /* IPS_MODE_DETECT / IPS_MODE_PREVENT */
	double   thr_block;       /* ML threshold → DROP  (default 0.95) */
	double   thr_alert;       /* ML threshold → ALERT (default 0.50) */
	uint32_t snapshot_n;      /* N gói đầu mỗi flow đưa vào NFQUEUE  */
	uint16_t queue_num;
	char     rules_path[256];
	uint32_t rule_gen_min;    /* min_support cho rule_gen              */
};

static struct ipsd_config g_cfg = {
	.enabled     = 1,
	.mode        = IPS_MODE_PREVENT,
	.thr_block   = 0.95,
	.thr_alert   = 0.50,
	.snapshot_n  = 8,
	.queue_num   = 0,
	.rules_path  = DEFAULT_RULES,
	.rule_gen_min = 3,
};

/* ---- global state -------------------------------------------------------- */

static volatile int g_stop = 0;   /* SIGTERM/SIGINT */

static void handle_stop(int sig) { (void)sig; g_stop = 1; }

/* ---- alert log ----------------------------------------------------------- */

static FILE *g_logfp;

static void log_init(void)
{
	g_logfp = fopen(ALERT_LOG, "a");
	if (!g_logfp)
		fprintf(stderr, "ipsd: cannot open alert log %s: %m\n", ALERT_LOG);
}

static void log_alert(const struct ips_decision *d, const struct nfq_pkt *pkt,
		      const struct flow_ctx *fc, double score)
{
	FILE *f = g_logfp ? g_logfp : stderr;
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	struct in_addr sa, da;
	sa.s_addr = htonl(pkt->src_ip); inet_ntop(AF_INET, &sa, src, sizeof(src));
	da.s_addr = htonl(pkt->dst_ip); inet_ntop(AF_INET, &da, dst, sizeof(dst));

	time_t now = time(NULL);
	struct tm tm; localtime_r(&now, &tm);
	char ts[24]; strftime(ts, sizeof(ts), "%F %T", &tm);

	fprintf(f, "%s %s proto=%u src=%s:%u dst=%s:%u "
		"reason=%s score=%.3f sid=%u msg=%s\n",
		ts, ips_verdict_str(d->verdict),
		fc->proto, src, pkt->sport, dst, pkt->dport,
		ips_reason_str(d->reason), score,
		(d->sig_rule >= 0) ? 0u : 0u,   /* sid future */
		"");
	fflush(f);
}

/* ---- đọc config từ mgmtd (best-effort) ----------------------------------- */

/*
 * Gửi SG_CMD_CFG_GET "security_ips" tới mgmtd và parse kết quả key=value.
 * Nếu mgmtd không có (ENOENT / type chưa cài) → giữ default.
 */
static void load_config_from_mgmtd(void)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) return;

	struct sockaddr_un sa;
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", MGMTD_SOCK);

	struct timeval tv = { .tv_sec = 2 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		goto done;

	/* Request: cmd=SG_CMD_CFG_GET (100), payload="type=security_ips\nid=default\n" */
	char req[256];
	const char *pl = "type=security_ips\nid=default\n";
	uint32_t plen  = (uint32_t)strlen(pl);

	/* minimal header (magic=0xSG55, version=1, cmd=100, payload_len) */
	uint8_t hdr[18]; memset(hdr, 0, sizeof(hdr));
	hdr[0] = 0x53; hdr[1] = 0x47;  /* "SG" magic */
	hdr[2] = 1;                      /* version    */
	uint32_t cmd = 100;
	memcpy(hdr + 6, &cmd,  4);
	memcpy(hdr + 14, &plen, 4);

	int n = snprintf(req, sizeof(req), "%.*s%s", 18, (char *)hdr, pl);
	if (n <= 0 || write(fd, req, (size_t)n) < 0) goto done;

	/* Response: parse payload for key=value */
	char rbuf[1024]; ssize_t rn = read(fd, rbuf, sizeof(rbuf) - 1);
	if (rn <= 0) goto done;
	rbuf[rn] = '\0';

	/* Find payload (after 22-byte response header) */
	char *p = rbuf + 22;
	char *end = rbuf + rn;
	while (p < end) {
		char *nl = memchr(p, '\n', (size_t)(end - p));
		int ll   = nl ? (int)(nl - p) : (int)(end - p);
		if (ll <= 0) break;
		char line[128]; int cp = ll < 127 ? ll : 127;
		memcpy(line, p, (size_t)cp); line[cp] = '\0';

		char *eq = strchr(line, '=');
		if (eq) {
			*eq = '\0';
			const char *k = line, *v = eq + 1;
			if (!strcmp(k, "enabled"))    g_cfg.enabled    = atoi(v);
			if (!strcmp(k, "mode"))       g_cfg.mode       = !strcmp(v,"detect") ? IPS_MODE_DETECT : IPS_MODE_PREVENT;
			if (!strcmp(k, "thr_block"))  g_cfg.thr_block  = atof(v);
			if (!strcmp(k, "thr_alert"))  g_cfg.thr_alert  = atof(v);
			if (!strcmp(k, "snapshot_n")) g_cfg.snapshot_n = (uint32_t)atoi(v);
			if (!strcmp(k, "queue_num"))  g_cfg.queue_num  = (uint16_t)atoi(v);
			if (!strcmp(k, "rules_path")) snprintf(g_cfg.rules_path, sizeof(g_cfg.rules_path), "%s", v);
		}
		p = nl ? nl + 1 : end;
	}
done:
	close(fd);
}

/* ---- xử lý một gói từ NFQUEUE ------------------------------------------- */

static void process_packet(struct nfq_ctx *nfq, struct nfq_pkt *pkt,
			    struct sig_reload *sr, struct rule_gen_ctx *rgen,
			    const struct ips_config *ips_cfg)
{
	/* [1] Lấy flow stats từ conntrack */
	struct ctdump_result ctr;
	int ct_ok = (ctdump_query(pkt->src_ip, pkt->dst_ip,
				  pkt->sport, pkt->dport,
				  pkt->proto, &ctr) == 0);

	struct flow_stats fs;
	double feat[FEAT_COUNT];
	memset(&fs, 0, sizeof(fs));
	memset(feat, 0, sizeof(feat));

	uint32_t pkts_fwd = 0, pkts_bwd = 0;

	if (ct_ok) {
		ctdump_to_flow_stats(&ctr, &fs);
		pkts_fwd = fs.pkts_fwd;
		pkts_bwd = fs.pkts_bwd;
		ctdump_to_features(&ctr, pkts_fwd, pkts_bwd,
				   pkt->init_win, feat);
	}

	/* [2] Evaluate: L1-builtin → L1-user → L2-payload → ML */
	struct flow_ctx fc;
	nfq_pkt_to_flow_ctx(pkt, &fc);

	struct ips_decision d = ips_evaluate(ips_cfg, sr->active,
					     pkt->payload, pkt->plen,
					     &fc, feat,
					     ct_ok ? &fs : NULL);

	/* [3] Verdict + connmark.
	 *
	 * Với connbytes-based NFQUEUE rule, gating đã do kernel lo (connbytes
	 * 0:N-1 tự hết hiệu lực sau N gói). ipsd chỉ cần:
	 *   - DROP  : NF_DROP + set IPS_BLOCK connmark → rule global DROP ở đầu
	 *             chain chặn mọi gói tiếp theo của flow.
	 *   - ACCEPT: NF_ACCEPT đơn giản, không cần INSPECTED connmark. Gói
	 *             tiếp tục forwarding và đến CONNMARK+ACCEPT policy rule.
	 *             Sau N gói (connbytes vượt N-1), gói không vào NFQUEUE nữa.
	 */
	uint32_t connmark = 0, cmask = 0;
	int accept = 1;

	if (d.verdict == IPS_DROP) {
		accept   = 0;
		connmark = SG_CMK_IPS_BLOCK;
		cmask    = SG_CMK_IPS_MASK;
	}

	if (nfq_verdict(nfq, pkt->id, accept, connmark, cmask) < 0)
		fprintf(stderr, "ipsd: nfq_verdict failed: %m\n");

	/* [4] Rule generation: ML bắt được mà signature bỏ sót */
	if (d.ml_evaluated && d.score >= ips_cfg->thr_block && rgen) {
		struct rule_gen_input rgi = {
			.proto      = pkt->proto,
			.dport      = pkt->dport,
			.tcp_flags  = pkt->tcp_flags,
			.dsize      = pkt->plen,
			.syn_count  = fs.syn_count,
			.ack_count  = fs.ack_count,
			.psh_count  = fs.psh_count,
			.bytes_fwd  = ctr.ml.bytes_fwd,
			.bytes_bwd  = ctr.ml.bytes_bwd,
			.pkts_fwd   = pkts_fwd,
			.pkts_bwd   = pkts_bwd,
			.ml_score   = d.score,
		};
		if (rule_gen_feed(rgen, &rgi, sr->active) == 1)
			rule_gen_save(rgen, AUTORULE_SAVE);
	}

	/* [5] Log alert */
	if (d.verdict != IPS_PASS)
		log_alert(&d, pkt, &fc, d.score);
}

/* ---- main ----------------------------------------------------------------- */

static void usage(const char *prog)
{
	fprintf(stderr,
		"dùng: %s [-q queue_num] [-r rules_path] [-d (detect)] [-n]\n"
		"  -q <n>    NFQUEUE number (mặc định %u)\n"
		"  -r <path> rules file (mặc định %s)\n"
		"  -d        detect mode (chỉ log, không block)\n"
		"  -n        không đọc config từ mgmtd\n",
		prog, g_cfg.queue_num, DEFAULT_RULES);
}

int main(int argc, char **argv)
{
	int no_mgmtd = 0;
	int opt;

	while ((opt = getopt(argc, argv, "q:r:dn")) != -1) {
		switch (opt) {
		case 'q': g_cfg.queue_num = (uint16_t)atoi(optarg); break;
		case 'r': snprintf(g_cfg.rules_path, sizeof(g_cfg.rules_path),
				   "%s", optarg); break;
		case 'd': g_cfg.mode = IPS_MODE_DETECT; break;
		case 'n': no_mgmtd = 1; break;
		default: usage(argv[0]); return 1;
		}
	}

	/* [1] Load config từ mgmtd (best-effort) */
	if (!no_mgmtd)
		load_config_from_mgmtd();

	if (!g_cfg.enabled) {
		fprintf(stderr, "ipsd: IPS disabled in config — exiting\n");
		return 0;
	}

	fprintf(stderr, "ipsd: starting — mode=%s thr_block=%.2f thr_alert=%.2f "
		"queue=%u rules=%s\n",
		g_cfg.mode == IPS_MODE_PREVENT ? "prevent" : "detect",
		g_cfg.thr_block, g_cfg.thr_alert,
		g_cfg.queue_num, g_cfg.rules_path);

	/* [2] Init components */
	log_init();

	struct sig_reload sr;
	if (sig_reload_init(&sr, g_cfg.rules_path) < 0) {
		fprintf(stderr, "ipsd: cannot load rules from %s\n",
			g_cfg.rules_path);
		return 1;
	}

	/* Nạp auto-rules đã lưu từ lần trước */
	struct rule_gen_ctx rgen;
	rule_gen_init(&rgen, g_cfg.rule_gen_min, g_cfg.thr_block, 0);
	rule_gen_load(&rgen, sr.active, AUTORULE_SAVE);

	struct nfq_ctx nfq;
	if (nfq_open(&nfq, g_cfg.queue_num) < 0) {
		fprintf(stderr, "ipsd: cannot open NFQUEUE %u: %m\n",
			g_cfg.queue_num);
		sig_reload_free(&sr);
		rule_gen_free(&rgen);
		return 1;
	}

	/* ips_config từ g_cfg */
	struct ips_config ips_cfg;
	ips_config_default(&ips_cfg);
	ips_cfg.mode      = g_cfg.mode;
	ips_cfg.thr_block = g_cfg.thr_block;
	ips_cfg.thr_alert = g_cfg.thr_alert;

	/* [3] Signal handlers */
	struct sigaction sa_stop = { .sa_handler = handle_stop,
				     .sa_flags   = SA_RESTART };
	sigemptyset(&sa_stop.sa_mask);
	sigaction(SIGTERM, &sa_stop, NULL);
	sigaction(SIGINT,  &sa_stop, NULL);
	/* SIGUSR1 đã được sig_reload_init đăng ký (→ self-pipe) */

	fprintf(stderr, "ipsd: ready (%d rules, queue %u)\n",
		sr.active->n_rules + sr.active->n_l1, g_cfg.queue_num);

	/* [4] Main event loop */
	struct nfq_pkt pkt;

	while (!g_stop) {
		fd_set rfds;
		int maxfd = nfq.fd > sr.pipe_rd ? nfq.fd : sr.pipe_rd;

		FD_ZERO(&rfds);
		FD_SET(nfq.fd,    &rfds);
		FD_SET(sr.pipe_rd, &rfds);

		struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
		int n = select(maxfd + 1, &rfds, NULL, NULL, &tv);

		if (n < 0) {
			if (errno == EINTR) continue;
			fprintf(stderr, "ipsd: select: %m\n");
			break;
		}

		/* SIGUSR1 → reload ruleset */
		if (FD_ISSET(sr.pipe_rd, &rfds))
			sig_reload_handle_signal(&sr);

		/* gói từ NFQUEUE */
		if (FD_ISSET(nfq.fd, &rfds)) {
			if (nfq_recv(&nfq, &pkt) == 0)
				process_packet(&nfq, &pkt, &sr, &rgen, &ips_cfg);
		}
	}

	/* [5] Graceful shutdown */
	fprintf(stderr, "ipsd: shutting down\n");
	nfq_close(&nfq);
	sig_reload_wait(&sr);
	sig_reload_free(&sr);
	rule_gen_save(&rgen, AUTORULE_SAVE);
	rule_gen_free(&rgen);
	if (g_logfp) fclose(g_logfp);

	return 0;
}
