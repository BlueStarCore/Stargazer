/* SPDX-License-Identifier: MIT */
/*
 * main.c - stargazer-ipsd: IPS daemon cho Stargazer NGFW.
 *
 * Luồng mỗi gói từ NFQUEUE:
 *   nfq_recv → ctdump_query (CTA_ML + ACCT) → ctdump_to_flow_stats/features
 *   → [TCP] reass_segment (ráp dòng) + streaming AC làm lớp L2;
 *     [UDP/ICMP] khớp payload gói đơn
 *   → ips_evaluate_full (L1-builtin → L1-user → L2 → ML)
 *   → nfq_verdict (ACCEPT/DROP + set connmark)
 *   → log_alert (nếu ALERT/DROP)
 *
 * Config đọc từ mgmtd (SG_CMD_CFG_GET "security_ips") lúc khởi động; nếu
 * mgmtd chưa có type đó thì dùng giá trị mặc định. Reload ruleset qua SIGUSR1
 * (reass pool rebind sang automaton mới + re-scan dòng đã có).
 * Graceful shutdown qua SIGTERM/SIGINT.
 */
#define _GNU_SOURCE
#include "nfq.h"
#include "ctdump.h"
#include "engine.h"
#include "ips_model.h"   /* ips_score — gọi tại checkpoint */
#include "flow_rule.h"
#include "sig_reload.h"
#include "fusion.h"
#include "feature.h"
#include "reass.h"
#include "proto_buf.h"
#include "ml_scan.h"
#include "insp_ipc.h"   /* Phase 4: IPC inspection server (HTTPS-deep) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/stat.h>     /* mkdir — đảm bảo /etc/stargazer/logs tồn tại */
#include <fcntl.h>        /* open O_APPEND — alert log fd giữ mở */
#include <arpa/inet.h>

/* IPC mgmtd — chỉ dùng để đọc config, không bắt buộc */
#include <sys/socket.h>
#include <sys/un.h>

#define MGMTD_SOCK      "/run/stargazer-mgmtd.sock"
#define DEFAULT_RULES   "/etc/stargazer/ips/rules/active.rules"
#define ALERT_LOG       "/etc/stargazer/logs/ips-alert.log"
#define PID_FILE        "/run/stargazer-ipsd.pid"   /* logrotate gửi SIGHUP tới pid này */

/* ---- config -------------------------------------------------------------- */

struct ipsd_config {
	int      enabled;
	int      mode;            /* IPS_MODE_DETECT / IPS_MODE_PREVENT */
	double   thr_block;       /* ML threshold → DROP  (default 0.95) */
	double   thr_alert;       /* ML threshold → ALERT (default 0.50) */
	uint32_t snapshot_n;      /* N gói đầu mỗi flow đưa vào NFQUEUE  */
	uint16_t queue_num;
	char     rules_path[256];
};

static struct ipsd_config g_cfg = {
	.enabled     = 1,
	.mode        = IPS_MODE_PREVENT,
	.thr_block   = 0.95,
	.thr_alert   = 0.50,
	.snapshot_n  = 8,
	.queue_num   = 0,
	.rules_path  = DEFAULT_RULES,
};

/* ---- global state -------------------------------------------------------- */

static volatile int g_stop = 0;   /* SIGTERM/SIGINT */

static void handle_stop(int sig) { (void)sig; g_stop = 1; }

/* ---- alert log ----------------------------------------------------------- */

/* Đếm số alert đã ghi — telemetry để chẩn đoán "alert log trống". */
unsigned long g_alert_logged;

/* fd alert log giữ mở suốt vòng đời daemon → 1 write()/alert thay vì
 * open+write+close (3 syscall). Lúc burst (đang bị quét/tấn công) alert
 * dồn dập, chi phí mỗi alert nằm thẳng trên đường đi của gói nên phải rẻ.
 * O_APPEND: kernel luôn ghi cuối file ⇒ `alerts-clear` (mgmtd open O_TRUNC)
 * cắt file về 0 không tạo sparse hole, và không cần fflush thủ công vì
 * write() đi thẳng kernel (không qua buffer libc → alert hiện ngay cho
 * mgmtd read_last_lines). -1 = chưa mở / mở lỗi. */
static int g_alert_fd = -1;

/* SIGHUP = logrotate báo "đã xoay file". Handler chỉ bật cờ (open() KHÔNG
 * async-signal-safe → không gọi trong handler); main loop đóng+mở lại fd. */
static volatile sig_atomic_t g_log_reopen;

static void handle_hup(int sig) { (void)sig; g_log_reopen = 1; }

static void log_open(void)
{
	/* O_CLOEXEC: ip/dmesg fork ra không kế thừa fd. 0640: /etc/stargazer/logs
	 * là 0700 root, chỉ root đọc trực tiếp — mgmtd phục vụ cho webd/cli. */
	g_alert_fd = open(ALERT_LOG,
			  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
}

static void log_init(void)
{
	/* /etc/stargazer/logs là partition lưu trữ — đảm bảo dir tồn tại. */
	mkdir("/etc/stargazer", 0755);
	mkdir("/etc/stargazer/logs", 0755);
	log_open();
	if (g_alert_fd < 0)
		fprintf(stderr, "ipsd: open %s failed: %m\n", ALERT_LOG);
}

/* SIGHUP → đóng fd cũ, mở lại theo path (giống Suricata). Nếu logrotate đã
 * rename file cũ + tạo file mới cùng tên, lần mở này bám file mới rỗng; nếu
 * file CHƯA bị xoay, chỉ là append tiếp đúng file đó → vô hại (idempotent),
 * nên SIGHUP an toàn gửi bất cứ lúc nào. */
static void log_reopen(void)
{
	if (g_alert_fd >= 0) close(g_alert_fd);
	log_open();
	if (g_alert_fd < 0)
		fprintf(stderr, "ipsd: log reopen %s failed: %m\n", ALERT_LOG);
}

static void log_alert(const struct ips_decision *d, const struct nfq_pkt *pkt,
		      const struct flow_ctx *fc, double score)
{
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	struct in_addr sa, da;
	sa.s_addr = htonl(pkt->src_ip); inet_ntop(AF_INET, &sa, src, sizeof(src));
	da.s_addr = htonl(pkt->dst_ip); inet_ntop(AF_INET, &da, dst, sizeof(dst));

	/* Date/Time = thời điểm gói tấn công được GHI NHẬN, lấy từ kernel
	 * (NFQA_TIMESTAMP lúc gói vào queue). Vắng (cap_sec=0, kernel không set
	 * skb->tstamp) → fallback giờ hiện tại lúc ghi log. Dưới burst userspace
	 * trễ sau queue nên cap_sec phản ánh đúng thời điểm tấn công hơn. */
	time_t now = (pkt->cap_sec > 0) ? (time_t)pkt->cap_sec : time(NULL);
	struct tm tm; localtime_r(&now, &tm);
	char ts[24]; strftime(ts, sizeof(ts), "%F %T", &tm);

	const char *msg = d->matched_msg[0] ? d->matched_msg :
		((d->reason == IPS_R_ML_BLOCK || d->reason == IPS_R_ML_ALERT)
			? "ML-ANOMALY" : "");
	(void)fc;   /* fc->proto là enum SIG_PROTO_*, KHÔNG phải IP proto — dùng pkt */
	/* score < 0 = ML chưa chấm (khớp signature thuần) → in "n/a" cho rõ. */
	char scorebuf[16];
	if (score >= 0) snprintf(scorebuf, sizeof(scorebuf), "%.3f", score);
	else            snprintf(scorebuf, sizeof(scorebuf), "n/a");
	char line[512];
	int ln = snprintf(line, sizeof(line),
		"%s %s proto=%u src=%s:%u dst=%s:%u "
		"reason=%s score=%s sid=%u msg=%s\n",
		ts, ips_verdict_str(d->verdict),
		pkt->proto, src, pkt->sport, dst, pkt->dport,
		ips_reason_str(d->reason), scorebuf,
		d->matched_sid, msg);
	if (ln < 0) ln = 0;

	/* fd chưa mở (init lỗi / log-partition mới mount) → thử mở lại 1 lần.
	 * Vẫn lỗi thì rơi xuống stderr — đừng nuốt alert lặng lẽ (honesty first).
	 * write() O_APPEND lên file thường là atomic ⇒ không xé dòng giữa các
	 * alert dù sau này có nhiều writer. */
	if (g_alert_fd < 0)
		log_open();
	int fd = (g_alert_fd >= 0) ? g_alert_fd : STDERR_FILENO;
	if (write(fd, line, (size_t)ln) < 0 && fd != STDERR_FILENO) {
		/* fd hỏng giữa chừng (ENOSPC/EIO/EBADF do file bị thay) → mở lại
		 * rồi thử lần nữa; cùng đường thì stderr. */
		log_reopen();
		int rfd = (g_alert_fd >= 0) ? g_alert_fd : STDERR_FILENO;
		if (write(rfd, line, (size_t)ln) < 0)
			fprintf(stderr, "ipsd: alert log write failed: %m\n");
	}
	g_alert_logged++;
}

/* ---- pid file ------------------------------------------------------------ */

/* logrotate (postrotate) đọc PID_FILE để biết gửi SIGHUP cho ai. mgmtd
 * supervise ipsd qua fork+exec nên tự biết pid; file này dành cho công cụ
 * xoay log bên ngoài. */
static void write_pidfile(void)
{
	int fd = open(PID_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		fprintf(stderr, "ipsd: write %s failed: %m\n", PID_FILE);
		return;
	}
	char buf[16];
	int n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
	if (n > 0 && write(fd, buf, (size_t)n) < 0)
		fprintf(stderr, "ipsd: write %s failed: %m\n", PID_FILE);
	close(fd);
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

/* ---- pool reassembly per-flow (P1) -------------------------------------- *
 * Direct-mapped (1 entry/bucket): hash 5-tuple → bucket; va chạm → evict (đơn
 * giản, BỊ CHẶN bộ nhớ cứng: ≤ FLOW_BUCKETS flow). Mỗi flow ~2*(K + K/8) byte;
 * 512 * ~36KB ≈ 18MB < trần 32MB. Chỉ truy cập từ main thread → không cần lock.
 * (LRU theo thời gian là cải tiến sau; va-chạm-evict đã chặn bộ nhớ an toàn.)   */
#define FLOW_BUCKETS 512

/* CHECKPOINT inference — ngưỡng rút từ phân tích thống kê CIC-IDS-2017
 * (2.83 triệu flow): chấm ML đúng 1 lần khi flow chạm trigger ĐẦU TIÊN trong
 * {FIN/RST, N gói, K byte, T tuổi}, miễn signature CHƯA khớp gói nào. Cơ sở:
 *   FIN/RST → flow KẾT THÚC: chấm trên flow hoàn chỉnh, BẮT flow NGẮN (PortScan
 *             ~2 gói/~0s) vốn không bao giờ chạm cap gói/byte/thời gian.
 *   N=24  → phủ ~hoàn-chỉnh DoS/DDoS (≤16 gói: 95-100%) + Patator (≤32: 100%).
 *   K=14KB→ ngay dưới byte-window kernel 16KB (bắt flow nặng trước khi offload).
 *   T=12s → khe giữa flow thường (<2s) và slow-DoS (60-97s) → bắt slow sớm. */
#define ML_CKP_PKTS    24u
#define ML_CKP_BYTES   14000u
#define ML_CKP_AGE_NS  12000000000ULL   /* 12 giây (ns) */

/* now theo CLOCK_MONOTONIC ns — cùng đồng hồ với kernel first_ns (ktime_get_ns). */
static uint64_t mono_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

struct flow_key {
	uint32_t ip_a, ip_b;
	uint16_t port_a, port_b;
	uint8_t  proto;
	uint8_t  used;
};

struct flow_slot {
	struct flow_key   key;
	uint32_t          init_ip;    /* initiator: to_server = gói từ (init_ip,init_port) */
	uint16_t          init_port;
	struct reass_flow rf;
	struct flowbit_state fb;      /* P5 — cờ flowbits per-flow */
	uint8_t             ml_done;  /* đã chấm ML tại checkpoint (1 lần/flow) */
};

static struct flow_slot g_flows[FLOW_BUCKETS];

/* Khoá canonical: 2 chiều của cùng flow map về cùng key. */
static void flow_build_key(struct flow_key *k, uint32_t sip, uint16_t sp,
			   uint32_t dip, uint16_t dp, uint8_t proto)
{
	int a_first = (sip != dip) ? (sip < dip) : (sp <= dp);
	if (a_first) { k->ip_a = sip; k->port_a = sp; k->ip_b = dip; k->port_b = dp; }
	else         { k->ip_a = dip; k->port_a = dp; k->ip_b = sip; k->port_b = sp; }
	k->proto = proto;
	k->used  = 1;
}
static uint32_t flow_hash(const struct flow_key *k)
{
	uint32_t h = 2166136261u;
	h = (h ^ k->ip_a) * 16777619u;
	h = (h ^ k->ip_b) * 16777619u;
	h = (h ^ (((uint32_t)k->port_a << 16) | k->port_b)) * 16777619u;
	h = (h ^ k->proto) * 16777619u;
	return h;
}
static int flow_key_eq(const struct flow_key *a, const struct flow_key *b)
{
	return a->used && b->used && a->ip_a == b->ip_a && a->ip_b == b->ip_b &&
	       a->port_a == b->port_a && a->port_b == b->port_b &&
	       a->proto == b->proto;
}

/* Lấy/ tạo slot cho gói TCP. *dir_out = REASS_TO_SERVER/CLIENT. NULL nếu OOM. */
static struct flow_slot *flow_get(const struct nfq_pkt *pkt,
				  const struct ac_automaton *ac, int *dir_out)
{
	struct flow_key k;
	flow_build_key(&k, pkt->src_ip, pkt->sport, pkt->dst_ip, pkt->dport,
		       pkt->proto);
	struct flow_slot *s = &g_flows[flow_hash(&k) % FLOW_BUCKETS];

	if (!flow_key_eq(&s->key, &k)) {
		if (s->key.used)
			reass_flow_free(&s->rf);        /* evict flow cũ ở bucket này */
		if (reass_flow_init(&s->rf, ac, 0) != 0) {
			s->key.used = 0;
			return NULL;
		}
		s->key       = k;
		s->init_ip   = pkt->src_ip;             /* gói đầu thấy = initiator */
		s->init_port = pkt->sport;
		memset(&s->fb, 0, sizeof(s->fb));       /* P5 — flow mới: cờ sạch */
		s->ml_done = 0;                         /* flow mới: chưa chấm ML */
	}
	int to_server = (pkt->src_ip == s->init_ip && pkt->sport == s->init_port);
	*dir_out = to_server ? REASS_TO_SERVER : REASS_TO_CLIENT;
	return s;
}

/* Ctx gom kết quả L2 khi streaming AC trúng trên dòng đã ghép. */
struct l2_match {
	const struct sig_ruleset *rs;
	struct reass_flow        *rf;
	struct flow_ctx           fc;
	struct flowbit_state     *fb;   /* P5 — bitset cờ của flow (để set/unset) */
	int best_idx;
	int best_action;
	struct match_buffers      bufs; /* P6 — vùng giao thức (trích 1 lần/feed) */
	int bufs_ready;
	int bufs_dir;
	uint32_t bufs_contig;
};
/* Khoanh vùng vì sao L2 không match: ac_raw = số lần AC prefilter trúng (trước
 * sig_verify); flow_oom = số gói rơi vào đường per-packet (flow_get NULL). */
static unsigned long g_ac_raw, g_flow_oom, g_tcp_payload;
extern unsigned long g_reass_fed;   /* byte thực sự feed vào AC (reass.c) */

static int l2_on_match(int rule_id, uint64_t end_off, int dir, void *ctx)
{
	(void)end_off;
	g_ac_raw++;                 /* AC prefilter trúng (trước sig_verify) */
	struct l2_match *m = ctx;
	uint32_t clen;
	const uint8_t *buf = reass_dir_buf(m->rf, dir, &clen);
	if (!buf)
		return 0;

	/* P6 — trích sticky buffer từ dòng chiều này (HTTP request / TLS SNI).
	 * Cache theo (dir, contig): consume (P1 re-arm) làm cửa sổ TRƯỢT → contig
	 * đổi → trích lại (tránh buffer stale). */
	if (!m->bufs_ready || m->bufs_dir != dir || m->bufs_contig != clen) {
		bufs_init_raw(&m->bufs, buf, (int)clen);
		bufs_extract(&m->bufs, buf, (int)clen);
		m->fc.bufs    = &m->bufs;
		m->bufs_ready = 1;
		m->bufs_dir   = dir;
		m->bufs_contig = clen;
	}

	if (!sig_verify(m->rs, rule_id, buf, (int)clen, &m->fc))
		return 0;                               /* prefilter trúng, verify trượt */

	const struct sig_rule *r = &m->rs->rules[rule_id];
	sig_flowbits_apply(r, m->fb);                   /* P5 — set/unset/toggle */
	if (r->fb_noalert)
		return 0;                               /* chỉ tag cờ, không verdict */

	int action = r->action;
	if (r->fidelity == SIG_FID_ALERT)
		action = SIG_ALERT;                     /* P0 fidelity-cap */
	if (action > m->best_action) {
		m->best_action = action;
		m->best_idx    = rule_id;
	}
	return (m->best_action == SIG_DROP);            /* dừng sớm khi đã có DROP */
}

/* Quyết định fail-closed khi ráp dòng bất thường (lỗ trống/quá tải). */
static struct ips_decision make_failclosed(const struct ips_config *cfg)
{
	struct ips_decision d;
	memset(&d, 0, sizeof(d));
	d.sig_rule     = -1;
	d.score        = -1.0;
	d.ml_evaluated = 0;
	d.reason       = IPS_R_SIGNATURE;
	d.verdict      = (cfg->mode == IPS_MODE_DETECT) ? IPS_ALERT : IPS_DROP;
	snprintf(d.matched_msg, sizeof(d.matched_msg),
		 "reass anomaly (gap/overflow) fail-closed");
	return d;
}

/* ---- telemetry runtime — soi đường NFQUEUE trên thiết bị (không có shell).
 * Ghi /run/stargazer-ipsd.rt; handle_ips_status đính vào `execute diagnose ips
 * status`. pkt_seen=0 → kernel KHÔNG giao gói (queue bind fail). pkt_seen>0 +
 * pkt_accept>0 mà traffic vẫn treo → verdict không release. recv_err cao →
 * nfq_recv parse fail. ------------------------------------------------------ */
static unsigned long g_pkt_seen, g_pkt_accept, g_pkt_drop, g_recv_err;
/* Phân loại nguồn phát hiện:
 *   flow_anomaly = L1-builtin (SYN-flood/port-scan, KHÔNG phải signature)
 *   l2_sig       = signature dựa-content (rule người dùng — 9000001/9000002…)
 *   ml           = ML scoring
 * l2_sig=0 mà gửi traffic có pattern → content-signature KHÔNG match (bug L2). */
static unsigned long g_anomaly_hits, g_l2_hits, g_ml_hits;

static void write_rt_stats(void)
{
	FILE *f = fopen("/run/stargazer-ipsd.rt.tmp", "w");
	if (!f) return;
	fprintf(f, "pkt_seen=%lu\npkt_accept=%lu\npkt_drop=%lu\npkt_recv_err=%lu\n"
		   "hits_flow_anomaly=%lu\nhits_l2_sig=%lu\nhits_ml=%lu\n"
		   "ac_raw=%lu\nflow_oom=%lu\ntcp_payload=%lu\nreass_fed=%lu\n"
		   "alerts_logged=%lu\n",
		g_pkt_seen, g_pkt_accept, g_pkt_drop, g_recv_err,
		g_anomaly_hits, g_l2_hits, g_ml_hits, g_ac_raw, g_flow_oom,
		g_tcp_payload, g_reass_fed, g_alert_logged);
	fclose(f);
	rename("/run/stargazer-ipsd.rt.tmp", "/run/stargazer-ipsd.rt");
}

/* ---- xử lý một gói từ NFQUEUE ------------------------------------------- */

static void process_packet(struct nfq_ctx *nfq, struct nfq_pkt *pkt,
			    struct sig_reload *sr,
			    const struct ips_config *ips_cfg)
{
	/* [0] Gói SYN forward (SYN set, ACK clear) mang Init_Win_bytes_forward —
	 * lưu cache cho vòng ML scoring (conntrack dump KHÔNG có window này). */
	if (pkt->proto == 6 && pkt->init_win >= 0 &&
	    (pkt->tcp_flags & SIG_TCP_SYN) && !(pkt->tcp_flags & SIG_TCP_ACK))
		ml_iwin_put(pkt->proto, pkt->src_ip, pkt->dst_ip,
			    pkt->sport, pkt->dport, pkt->init_win);

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
	/* P6 — flow: established = đã thấy traffic chiều ngược (proxy). to_server
	 * mặc định 1 (đặt lại theo dir thực cho TCP bên dưới). */
	fc.established = (pkts_bwd > 0) ? 1 : 0;
	fc.to_server   = 1;

	/*
	 * Đọc ruleset dưới read-lock: reload chạy ở thread nền (sig_reload.c)
	 * swap con trỏ active rồi FREE bản cũ. Không giữ rdlock ở đây sẽ
	 * use-after-free khi sig_match đang duyệt AC của bản cũ lúc nó bị free.
	 * `d` là struct trả về theo GIÁ TRỊ (copy hết) — sig_rule chỉ là index,
	 * không deref ruleset sau khi unlock → an toàn giải phóng lock sớm.
	 */
	pthread_rwlock_rdlock(&sr->rwlock);
	const struct sig_ruleset *rs = sr->active;
	struct ips_decision d;
	int sig_inspected = 0;   /* ML-benign → connmark INSPECTED (offload) */

	if (pkt->proto == 6 /* TCP */) {
		/* L2 chạy trên DÒNG ĐÃ GHÉP (P1): chống né cắt-segment/đảo-chiều. */
		int dir;
		struct flow_slot *slot = flow_get(pkt, &rs->ac, &dir);
		if (slot) {
			fc.to_server = (dir == REASS_TO_SERVER) ? 1 : 0;   /* P6 */
			fc.fb = &slot->fb;                                 /* P5 */
			struct l2_match mm = { .rs = rs, .rf = &slot->rf,
					       .fc = fc, .fb = &slot->fb,
					       .best_idx = -1, .best_action = -1 };

			/* Hot-reload: ruleset đổi → node-state cũ vô nghĩa + con trỏ ac
			 * cũ đã free. So sánh con trỏ (KHÔNG deref) rồi rebind: reset
			 * + re-scan dòng đã có bằng automaton mới TRƯỚC khi feed.
			 * Flag-id flowbits cũng đổi theo ruleset → xoá bitset luôn. */
			if (slot->rf.ac != &rs->ac) {
				memset(&slot->fb, 0, sizeof(slot->fb));
				reass_flow_rebind(&slot->rf, &rs->ac,
						  l2_on_match, &mm);
			}

			int rrc = REASS_OK;
			if (pkt->payload && pkt->plen) {
				g_tcp_payload++;        /* gói TCP có payload tới reass */
				rrc = reass_segment(&slot->rf, dir, pkt->tcp_seq,
						    pkt->payload, pkt->plen,
						    l2_on_match, &mm);
			}

			if (rrc == REASS_FAILCLOSED)
				d = make_failclosed(ips_cfg);
			else
				d = ips_evaluate_full(ips_cfg, rs, NULL, 0, &fc,
						      feat, ct_ok ? &fs : NULL,
						      1, mm.best_idx,
						      mm.best_action);

			/* CHECKPOINT: signature CHƯA khớp gói nào + flow chạm trigger
			 * ĐẦU TIÊN {FIN/RST, N gói, K byte, T tuổi} → ML phán quyết
			 * ĐÚNG 1 LẦN trên feature TÍCH LŨY. init_win lấy từ cache (gói
			 * hiện tại không phải SYN → pkt->init_win=-1). Chấm xong: lành/
			 * alert → offload (INSPECTED); độc (prevent) → block. */
			if (d.verdict == IPS_PASS && d.sig_rule == -1 &&
			    !slot->ml_done && ct_ok && ctr.ml_valid) {
				uint32_t N = fs.pkts_fwd + fs.pkts_bwd;
				uint64_t B = ctr.ml.bytes_fwd + ctr.ml.bytes_bwd;
				uint64_t now = mono_ns();
				uint64_t age = (ctr.ml.first_ns && now > ctr.ml.first_ns)
					       ? now - ctr.ml.first_ns : 0;
				/* T1 — flow kết thúc: chấm trên flow hoàn chỉnh, bắt flow
				 * NGẮN (PortScan ~2 gói) không bao giờ chạm cap dưới đây. */
				int fin_rst = (pkt->tcp_flags &
					       (SIG_TCP_FIN | SIG_TCP_RST)) != 0;
				if (fin_rst || N >= ML_CKP_PKTS || B >= ML_CKP_BYTES ||
				    age >= ML_CKP_AGE_NS) {
					int32_t iwin = ml_iwin_get(pkt->proto,
						pkt->src_ip, pkt->dst_ip,
						pkt->sport, pkt->dport);
					if (iwin < 0) iwin = pkt->init_win;
					ctdump_to_features(&ctr, fs.pkts_fwd,
						fs.pkts_bwd, iwin, feat);
					double sc = ips_score(feat);
					d = ips_fuse(ips_cfg, -1, 0, sc);
					d.ml_evaluated = 1;
					d.score        = sc;
					slot->ml_done  = 1;
					/* Đã chấm xong flow này → offload trừ khi DROP (DROP đã
					 * offload qua IPS_BLOCK). Gồm cả ALERT (detect mode). */
					if (d.verdict != IPS_DROP)
						sig_inspected = 1;
					ml_record_score(pkt->proto, pkt->src_ip,
						pkt->dst_ip, pkt->sport,
						pkt->dport, N, ctr.ml.syn_count,
						ctr.ml.ack_count, iwin, sc);
				}
			}
		} else {
			/* pool OOM → fallback khớp per-packet (không reass) */
			g_flow_oom++;
			d = ips_evaluate(ips_cfg, rs, pkt->payload, pkt->plen,
					 &fc, feat, ct_ok ? &fs : NULL);
		}
	} else {
		/* UDP/ICMP: không có stream → khớp payload gói đơn như cũ. */
		d = ips_evaluate(ips_cfg, rs, pkt->payload, pkt->plen,
				 &fc, feat, ct_ok ? &fs : NULL);
	}
	pthread_rwlock_unlock(&sr->rwlock);

	/* [3] Verdict + connmark.
	 *   - DROP      : NF_DROP + IPS_BLOCK → rule DROP đầu chain chặn flow.
	 *   - INSPECTED : ML checkpoint phán lành → set IPS_INSPECTED → offload
	 *                 (khỏi queue). Băng A đã có ! INSPECTED. Trước checkpoint:
	 *                 không đặt gì → cổng connbytes 0:K giữ soi liên tục, hết K
	 *                 thì tự offload. */
	uint32_t connmark = 0, cmask = 0;
	int accept = 1;

	if (d.verdict == IPS_DROP) {
		accept   = 0;
		connmark = SG_CMK_IPS_BLOCK;
		cmask    = SG_CMK_IPS_MASK;
	} else if (sig_inspected) {
		connmark = SG_CMK_IPS_INSPECTED;
		cmask    = SG_CMK_IPS_INSPECTED;
	}

	if (nfq_verdict(nfq, pkt->id, accept, connmark, cmask) < 0)
		fprintf(stderr, "ipsd: nfq_verdict failed: %m\n");
	if (accept) g_pkt_accept++; else g_pkt_drop++;
	/* Phân loại nguồn phát hiện (mọi verdict != PASS, kể cả ALERT ở detect). */
	if (d.verdict != IPS_PASS) {
		if (d.sig_rule == -2)      g_anomaly_hits++; /* L1-builtin flow anomaly */
		else if (d.sig_rule >= 0)  g_l2_hits++;      /* L2 content-signature */
		else                       g_ml_hits++;      /* ML */
	}

	/* [4] Log alert */
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
		"  -n        không đọc config từ mgmtd\n"
		"  -C        check-syntax: nạp + build -r file rồi thoát "
		"(0=hợp lệ, 1=lỗi)\n",
		prog, g_cfg.queue_num, DEFAULT_RULES);
}

/*
 * check_syntax — nạp + build ruleset từ path, KHÔNG mở NFQUEUE/mgmtd.
 * Dùng cho update an toàn: verify ruleset mới TRƯỚC khi swap vào production
 * (ipsd -C -r /tmp/new.rules). Trả 0 nếu hợp lệ, 1 nếu lỗi/0 rule.
 */
static int check_syntax(const char *path)
{
	struct sig_ruleset rs;
	struct sig_load_stats st;
	sig_ruleset_init(&rs);
	int added = sig_load_file(&rs, path, &st);
	if (added < 0) {
		fprintf(stderr, "ipsd -C: không mở được %s\n", path);
		sig_ruleset_free(&rs);
		return 1;
	}
	if (st.loaded == 0) {
		fprintf(stderr, "ipsd -C: %s không có rule hợp lệ "
			"(skip=%d err=%d)\n", path, st.skipped, st.errors);
		sig_ruleset_free(&rs);
		return 1;
	}
	if (sig_build(&rs) != 0) {
		fprintf(stderr, "ipsd -C: build AC thất bại cho %s\n", path);
		sig_ruleset_free(&rs);
		return 1;
	}
	fprintf(stderr, "ipsd -C: OK %s (%d rule, %d skip, %d err)\n",
		path, st.loaded, st.skipped, st.errors);
	sig_ruleset_free(&rs);
	return 0;
}

int main(int argc, char **argv)
{
	int no_mgmtd = 0;
	int do_check = 0;
	int opt;

	while ((opt = getopt(argc, argv, "q:r:dnC")) != -1) {
		switch (opt) {
		case 'q': g_cfg.queue_num = (uint16_t)atoi(optarg); break;
		case 'r': snprintf(g_cfg.rules_path, sizeof(g_cfg.rules_path),
				   "%s", optarg); break;
		case 'd': g_cfg.mode = IPS_MODE_DETECT; break;
		case 'n': no_mgmtd = 1; break;
		case 'C': do_check = 1; break;
		default: usage(argv[0]); return 1;
		}
	}

	/* [0] check-syntax mode: verify ruleset rồi thoát, không đụng kernel */
	if (do_check)
		return check_syntax(g_cfg.rules_path);

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

	/* Phase 4 (additive): IPC inspection server cho HTTPS-deep từ ssld. Dùng
	 * chung ruleset (rdlock) với NFQUEUE. Lỗi → log + chạy tiếp không IPC. */
	if (insp_ipc_start(&sr, &g_cfg) != 0)
		fprintf(stderr, "ipsd: insp_ipc server không khởi động được "
			"(HTTPS-deep sẽ dùng fallback per-chunk của ssld)\n");

	struct nfq_ctx nfq;
	if (nfq_open(&nfq, g_cfg.queue_num) < 0) {
		fprintf(stderr, "ipsd: cannot open NFQUEUE %u: %m\n",
			g_cfg.queue_num);
		sig_reload_free(&sr);
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
	/* SIGHUP → logrotate: đóng+mở lại alert log. KHÔNG SA_RESTART để select()
	 * bị ngắt ngay (select không tự restart kể cả có SA_RESTART), main loop
	 * thấy cờ và reopen ở vòng kế. */
	struct sigaction sa_hup = { .sa_handler = handle_hup };
	sigemptyset(&sa_hup.sa_mask);
	sigaction(SIGHUP, &sa_hup, NULL);
	/* SIGUSR1 đã được sig_reload_init đăng ký (→ self-pipe) */

	/* PID file cho công cụ xoay log ngoài (logrotate postrotate kill -HUP). */
	write_pidfile();

	fprintf(stderr, "ipsd: ready (%d rules, queue %u)\n",
		sr.active->n_rules, g_cfg.queue_num);

	/* ML chấm inline tại CHECKPOINT min(N,K,T) trong process_packet — không
	 * còn thread polling. Điểm ghi qua ml_record_score → ml_scores_flush. */

	/* [4] Main event loop */
	struct nfq_pkt pkt;

	while (!g_stop) {
		/* SIGHUP (logrotate) → đóng+mở lại alert log. Đặt ở đầu vòng để bắt
		 * cả trường hợp select() trả EINTR và `continue` bên dưới. */
		if (g_log_reopen) {
			g_log_reopen = 0;
			log_reopen();
		}

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
			if (nfq_recv(&nfq, &pkt) == 0) {
				g_pkt_seen++;
				process_packet(&nfq, &pkt, &sr, &ips_cfg);
			} else {
				g_recv_err++;
			}
		}
		write_rt_stats();   /* throttle tự nhiên: ≥1 lần/giây qua select timeout */
		ml_scores_flush();  /* đẩy điểm checkpoint ra /run/...scores */
	}

	/* [5] Graceful shutdown */
	fprintf(stderr, "ipsd: shutting down\n");
	unlink(PID_FILE);
	if (g_alert_fd >= 0) close(g_alert_fd);
	nfq_close(&nfq);
	for (int i = 0; i < FLOW_BUCKETS; i++)
		if (g_flows[i].key.used)
			reass_flow_free(&g_flows[i].rf);
	sig_reload_wait(&sr);
	sig_reload_free(&sr);

	return 0;
}
