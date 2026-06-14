/* SPDX-License-Identifier: MIT */
/*
 * main.c - stargazer-ipsd: IPS daemon for the Stargazer NGFW.
 *
 * Per-packet flow through NFQUEUE:
 *   nfq_recv → ctdump_query (CTA_ML + ACCT) → ctdump_to_flow_stats/features
 *   → [TCP] reass_segment (stream reassembly) + streaming AC as the L2 layer;
 *     [UDP/ICMP] single-packet payload match
 *   → ips_evaluate_full (L1-builtin → L1-user → L2 → ML)
 *   → nfq_verdict (ACCEPT/DROP + set connmark)
 *   → log_alert (if ALERT/DROP)
 *
 * Config is read from mgmtd (SG_CMD_CFG_GET "security_ips") at startup; if
 * mgmtd does not have that type yet, defaults are used. Ruleset reload via
 * SIGUSR1 (reass pool rebinds to the new automaton + re-scans existing streams).
 * Graceful shutdown via SIGTERM/SIGINT.
 */
#define _GNU_SOURCE
#include "nfq.h"
#include "ctdump.h"
#include "engine.h"
#include "ips_model.h"   /* ips_score — called at the checkpoint */
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
#include <sys/stat.h>     /* mkdir — ensure /etc/stargazer/logs exists */
#include <fcntl.h>        /* open O_APPEND — alert log fd kept open */
#include <arpa/inet.h>

/* mgmtd IPC — only used to read config, not required */
#include <sys/socket.h>
#include <sys/un.h>

#define MGMTD_SOCK      "/run/stargazer-mgmtd.sock"
#define DEFAULT_RULES   "/etc/stargazer/ips/rules/active.rules"
#define ALERT_LOG       "/etc/stargazer/logs/ips-alert.log"
#define PID_FILE        "/run/stargazer-ipsd.pid"   /* logrotate sends SIGHUP to this pid */

/* ---- config -------------------------------------------------------------- */

struct ipsd_config {
	int      enabled;
	int      mode;            /* IPS_MODE_DETECT / IPS_MODE_PREVENT */
	double   thr_block;       /* ML threshold → DROP  (default 0.95) */
	double   thr_alert;       /* ML threshold → ALERT (default 0.50) */
	uint32_t snapshot_n;      /* first N packets of each flow sent to NFQUEUE */
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

/* Count of alerts written — telemetry to diagnose an "empty alert log". */
unsigned long g_alert_logged;

/* The alert log fd is kept open for the daemon's lifetime → 1 write()/alert
 * instead of open+write+close (3 syscalls). During a burst (under scan/attack)
 * alerts pile up, and the per-alert cost sits directly on the packet path, so
 * it must be cheap. O_APPEND: the kernel always writes at end of file ⇒
 * `alerts-clear` (mgmtd open O_TRUNC) truncating the file to 0 creates no
 * sparse hole, and no manual fflush is needed because write() goes straight to
 * the kernel (no libc buffer → alerts appear immediately for mgmtd
 * read_last_lines). -1 = not yet open / open failed. */
static int g_alert_fd = -1;

/* SIGHUP = logrotate signalling "file rotated". The handler only sets a flag
 * (open() is NOT async-signal-safe → must not be called in the handler); the
 * main loop closes and reopens the fd. */
static volatile sig_atomic_t g_log_reopen;

static void handle_hup(int sig) { (void)sig; g_log_reopen = 1; }

/* SIGUSR2 → reload the per-profile selection maps (scope change) WITHOUT
 * rebuilding the automaton. Handled in the main loop (no SA_RESTART → wakes
 * select()). SIGUSR1 (full table reload) stays on the self-pipe. */
static volatile sig_atomic_t g_scope_reload;

static void handle_usr2(int sig) { (void)sig; g_scope_reload = 1; }

static void log_open(void)
{
	/* O_CLOEXEC: forked ip/dmesg do not inherit the fd. 0640:
	 * /etc/stargazer/logs is 0700 root, only root reads directly — mgmtd
	 * serves it to webd/cli. */
	g_alert_fd = open(ALERT_LOG,
			  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
}

static void log_init(void)
{
	/* /etc/stargazer/logs is the storage partition — ensure the dir exists. */
	mkdir("/etc/stargazer", 0755);
	mkdir("/etc/stargazer/logs", 0755);
	log_open();
	if (g_alert_fd < 0)
		fprintf(stderr, "ipsd: open %s failed: %m\n", ALERT_LOG);
}

/* SIGHUP → close the old fd, reopen by path (like Suricata). If logrotate has
 * already renamed the old file and created a new one of the same name, this
 * open attaches to the new empty file; if the file has NOT been rotated, it
 * just appends to the same file → harmless (idempotent), so SIGHUP is safe to
 * send at any time. */
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

	/* Date/Time = the moment the attack packet was RECORDED, taken from the
	 * kernel (NFQA_TIMESTAMP when the packet entered the queue). Absent
	 * (cap_sec=0, kernel did not set skb->tstamp) → fall back to the current
	 * time at log-write. Under a burst userspace lags behind the queue, so
	 * cap_sec reflects the actual attack time more accurately. */
	time_t now = (pkt->cap_sec > 0) ? (time_t)pkt->cap_sec : time(NULL);
	struct tm tm; localtime_r(&now, &tm);
	char ts[24]; strftime(ts, sizeof(ts), "%F %T", &tm);

	const char *msg = d->matched_msg[0] ? d->matched_msg :
		((d->reason == IPS_R_ML_BLOCK || d->reason == IPS_R_ML_ALERT)
			? "ML-ANOMALY" : "");
	(void)fc;   /* fc->proto is enum SIG_PROTO_*, NOT IP proto — use pkt */
	/* score < 0 = ML not scored (pure signature match) → print "n/a" for clarity. */
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

	/* fd not open (init failure / log partition just mounted) → try to
	 * reopen once. Still failing → fall through to stderr — never swallow an
	 * alert silently (honesty first). write() O_APPEND to a regular file is
	 * atomic ⇒ no torn lines between alerts even with multiple writers later. */
	if (g_alert_fd < 0)
		log_open();
	int fd = (g_alert_fd >= 0) ? g_alert_fd : STDERR_FILENO;
	if (write(fd, line, (size_t)ln) < 0 && fd != STDERR_FILENO) {
		/* fd broke mid-flight (ENOSPC/EIO/EBADF from the file being
		 * replaced) → reopen and retry; same failure → stderr. */
		log_reopen();
		int rfd = (g_alert_fd >= 0) ? g_alert_fd : STDERR_FILENO;
		if (write(rfd, line, (size_t)ln) < 0)
			fprintf(stderr, "ipsd: alert log write failed: %m\n");
	}
	g_alert_logged++;
}

/* ---- pid file ------------------------------------------------------------ */

/* logrotate (postrotate) reads PID_FILE to know who to send SIGHUP to. mgmtd
 * supervises ipsd via fork+exec so it already knows the pid; this file is for
 * the external log-rotation tool. */
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


/* ---- per-flow reassembly pool (P1) -------------------------------------- *
 * Direct-mapped (1 entry/bucket): hash the 5-tuple → bucket; collision →
 * evict (simple, with a hard memory cap: ≤ FLOW_BUCKETS flows). Each flow is
 * ~2*(K + K/8) bytes; 512 * ~36KB ≈ 18MB < the 32MB ceiling. Accessed only
 * from the main thread → no lock needed. (Time-based LRU is a later
 * improvement; collision-evict already caps memory safely.)                  */
#define FLOW_BUCKETS 512

/* CHECKPOINT inference — thresholds derived from statistical analysis of
 * CIC-IDS-2017 (2.83 million flows): score ML exactly once when the flow hits
 * the FIRST trigger among {FIN/RST, N packets, K bytes, T age}, provided no
 * signature has matched any packet yet. Rationale:
 *   FIN/RST → flow ENDS: score on the complete flow, CATCHING SHORT flows
 *             (PortScan ~2 packets/~0s) that never hit the packet/byte/time cap.
 *   N=24  → covers ~all DoS/DDoS (≤16 packets: 95-100%) + Patator (≤32: 100%).
 *   K=14KB→ just below the kernel 16KB byte-window (catch heavy flows before offload).
 *   T=12s → gap between normal flows (<2s) and slow-DoS (60-97s) → catch slow early. */
#define ML_CKP_PKTS    24u
#define ML_CKP_BYTES   14000u
#define ML_CKP_AGE_NS  12000000000ULL   /* 12 seconds (ns) */

/* now in CLOCK_MONOTONIC ns — same clock as the kernel first_ns (ktime_get_ns). */
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
	uint32_t          init_ip;    /* initiator: to_server = packet from (init_ip,init_port) */
	uint16_t          init_port;
	struct reass_flow rf;
	struct flowbit_state fb;      /* P5 — per-flow flowbits */
	uint8_t             ml_done;  /* ML scored at the checkpoint (once/flow) */
};

static struct flow_slot g_flows[FLOW_BUCKETS];

/* Canonical key: both directions of the same flow map to the same key. */
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

/* Get/create the slot for a TCP packet. *dir_out = REASS_TO_SERVER/CLIENT. NULL on OOM. */
static struct flow_slot *flow_get(const struct nfq_pkt *pkt,
				  const struct ac_automaton *ac, int *dir_out)
{
	struct flow_key k;
	flow_build_key(&k, pkt->src_ip, pkt->sport, pkt->dst_ip, pkt->dport,
		       pkt->proto);
	struct flow_slot *s = &g_flows[flow_hash(&k) % FLOW_BUCKETS];

	if (!flow_key_eq(&s->key, &k)) {
		if (s->key.used)
			reass_flow_free(&s->rf);        /* evict the old flow in this bucket */
		if (reass_flow_init(&s->rf, ac, 0) != 0) {
			s->key.used = 0;
			return NULL;
		}
		s->key       = k;
		s->init_ip   = pkt->src_ip;             /* first packet seen = initiator */
		s->init_port = pkt->sport;
		memset(&s->fb, 0, sizeof(s->fb));       /* P5 — new flow: clean flowbits */
		s->ml_done = 0;                         /* new flow: ML not yet scored */
	}
	int to_server = (pkt->src_ip == s->init_ip && pkt->sport == s->init_port);
	*dir_out = to_server ? REASS_TO_SERVER : REASS_TO_CLIENT;
	return s;
}

/* Context that gathers L2 results when the streaming AC hits on the reassembled stream. */
struct l2_match {
	const struct sig_ruleset *rs;
	struct reass_flow        *rf;
	struct flow_ctx           fc;
	struct flowbit_state     *fb;   /* P5 — flow flowbit bitset (to set/unset) */
	int best_idx;
	int best_action;
	struct match_buffers      bufs; /* P6 — protocol buffers (extracted once/feed) */
	int bufs_ready;
	int bufs_dir;
	uint32_t bufs_contig;
};
/* Pinpoint why L2 did not match: ac_raw = number of AC prefilter hits (before
 * sig_verify); flow_oom = packets that fell to the per-packet path (flow_get NULL). */
static unsigned long g_ac_raw, g_flow_oom, g_tcp_payload;
extern unsigned long g_reass_fed;   /* bytes actually fed into the AC (reass.c) */

static int l2_on_match(int rule_id, uint64_t end_off, int dir, void *ctx)
{
	(void)end_off;
	g_ac_raw++;                 /* AC prefilter hit (before sig_verify) */
	struct l2_match *m = ctx;
	uint32_t clen;
	const uint8_t *buf = reass_dir_buf(m->rf, dir, &clen);
	if (!buf)
		return 0;

	/* P6 — extract sticky buffers from this direction's stream (HTTP request
	 * / TLS SNI). Cache by (dir, contig): consume (P1 re-arm) makes the window
	 * SLIDE → contig changes → re-extract (avoid a stale buffer). */
	if (!m->bufs_ready || m->bufs_dir != dir || m->bufs_contig != clen) {
		bufs_init_raw(&m->bufs, buf, (int)clen);
		bufs_extract(&m->bufs, buf, (int)clen);
		m->fc.bufs    = &m->bufs;
		m->bufs_ready = 1;
		m->bufs_dir   = dir;
		m->bufs_contig = clen;
	}

	if (!sig_verify(m->rs, rule_id, buf, (int)clen, &m->fc))
		return 0;                               /* prefilter hit, verify missed */

	const struct sig_rule *r = &m->rs->rules[rule_id];
	sig_flowbits_apply(r, m->fb);                   /* P5 — set/unset/toggle */
	if (r->fb_noalert)
		return 0;                               /* only tag flowbits, no verdict */

	int action = sig_eff_action(r, m->fc.prof_id); /* per-profile action */
	if (r->fidelity == SIG_FID_ALERT)
		action = SIG_ALERT;                     /* P0 fidelity-cap */
	if (action > m->best_action) {
		m->best_action = action;
		m->best_idx    = rule_id;
	}
	return (m->best_action == SIG_DROP);            /* stop early once a DROP is found */
}

/* Fail-closed decision when stream reassembly is anomalous (gap/overload). */
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
		 "reassembly anomaly (gap/overflow) fail-closed");
	return d;
}

/* ---- runtime telemetry — inspect the NFQUEUE path on-device (no shell).
 * Writes /run/stargazer-ipsd.rt; handle_ips_status hooks it into `execute
 * diagnose ips status`. pkt_seen=0 → kernel is NOT delivering packets (queue
 * bind fail). pkt_seen>0 + pkt_accept>0 but traffic still stalls → verdict not
 * released. High recv_err → nfq_recv parse fail. -------------------------- */
static unsigned long g_pkt_seen, g_pkt_accept, g_pkt_drop, g_recv_err;
/* Classify the detection source:
 *   flow_anomaly = L1-builtin (SYN-flood/port-scan, NOT a signature)
 *   l2_sig       = content-based signature (user rule — 9000001/9000002…)
 *   ml           = ML scoring
 * l2_sig=0 while sending traffic with a pattern → content-signature did NOT
 * match (L2 bug). */
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

/* ---- process one packet from NFQUEUE ------------------------------------ */

static void process_packet(struct nfq_ctx *nfq, struct nfq_pkt *pkt,
			    struct sig_reload *sr,
			    const struct ips_config *ips_cfg)
{
	/* [0] A forward SYN packet (SYN set, ACK clear) carries
	 * Init_Win_bytes_forward — cache it for the ML scoring pass (the conntrack
	 * dump does NOT have this window). */
	if (pkt->proto == 6 && pkt->init_win >= 0 &&
	    (pkt->tcp_flags & SIG_TCP_SYN) && !(pkt->tcp_flags & SIG_TCP_ACK))
		ml_iwin_put(pkt->proto, pkt->src_ip, pkt->dst_ip,
			    pkt->sport, pkt->dport, pkt->init_win);

	/* [1] Get flow stats from conntrack */
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
	/* P6 — flow: established = reverse-direction traffic has been seen (proxy).
	 * to_server defaults to 1 (reset to the real dir for TCP below). */
	fc.established = (pkts_bwd > 0) ? 1 : 0;
	fc.to_server   = 1;

	/*
	 * Read the ruleset under a read-lock: reload runs on a background thread
	 * (sig_reload.c), swapping the active pointer then FREEING the old version.
	 * Without holding the rdlock here it would be use-after-free when sig_match
	 * is still walking the old AC as it gets freed. `d` is returned BY VALUE
	 * (fully copied) — sig_rule is only an index, no deref of the ruleset after
	 * unlock → safe to release the lock early.
	 */
	pthread_rwlock_rdlock(&sr->rwlock);
	const struct sig_ruleset *rs = sr->active;
	struct ips_decision d;
	int sig_inspected = 0;   /* ML-benign → connmark INSPECTED (offload) */

	if (pkt->proto == 6 /* TCP */) {
		/* L2 runs on the REASSEMBLED STREAM (P1): defeats segment-split/reorder evasion. */
		int dir;
		struct flow_slot *slot = flow_get(pkt, &rs->ac, &dir);
		if (slot) {
			fc.to_server = (dir == REASS_TO_SERVER) ? 1 : 0;   /* P6 */
			fc.fb = &slot->fb;                                 /* P5 */
			struct l2_match mm = { .rs = rs, .rf = &slot->rf,
					       .fc = fc, .fb = &slot->fb,
					       .best_idx = -1, .best_action = -1 };

			/* Hot-reload: ruleset changed → old node-state is meaningless
			 * + the old ac pointer is freed. Compare pointers (do NOT
			 * deref) then rebind: reset + re-scan the existing stream with
			 * the new automaton BEFORE feeding. Flowbit flag-ids also change
			 * with the ruleset → clear the bitset too. */
			if (slot->rf.ac != &rs->ac) {
				memset(&slot->fb, 0, sizeof(slot->fb));
				reass_flow_rebind(&slot->rf, &rs->ac,
						  l2_on_match, &mm);
			}

			int rrc = REASS_OK;
			if (pkt->payload && pkt->plen) {
				g_tcp_payload++;        /* TCP packet with payload reaching reass */
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

			/* CHECKPOINT: no signature has matched any packet + the flow
			 * hits the FIRST trigger {FIN/RST, N packets, K bytes, T age} →
			 * ML decides EXACTLY ONCE on the ACCUMULATED features. init_win
			 * comes from the cache (the current packet is not a SYN →
			 * pkt->init_win=-1). Once scored: benign/alert → offload
			 * (INSPECTED); malicious (prevent) → block. */
			if (d.verdict == IPS_PASS && d.sig_rule == -1 &&
			    !slot->ml_done && ct_ok && ctr.ml_valid) {
				uint32_t N = fs.pkts_fwd + fs.pkts_bwd;
				uint64_t B = ctr.ml.bytes_fwd + ctr.ml.bytes_bwd;
				uint64_t now = mono_ns();
				uint64_t age = (ctr.ml.first_ns && now > ctr.ml.first_ns)
					       ? now - ctr.ml.first_ns : 0;
				/* T1 — flow ends: score on the complete flow, catching
				 * SHORT flows (PortScan ~2 packets) that never hit the cap below. */
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
					/* This flow is now scored → offload unless DROP (DROP
					 * already offloads via IPS_BLOCK). Includes ALERT (detect mode). */
					if (d.verdict != IPS_DROP)
						sig_inspected = 1;
					ml_record_score(pkt->proto, pkt->src_ip,
						pkt->dst_ip, pkt->sport,
						pkt->dport, N, ctr.ml.syn_count,
						ctr.ml.ack_count, iwin, sc);
				}
			}
		} else {
			/* pool OOM → fall back to per-packet match (no reassembly) */
			g_flow_oom++;
			d = ips_evaluate(ips_cfg, rs, pkt->payload, pkt->plen,
					 &fc, feat, ct_ok ? &fs : NULL);
		}
	} else {
		/* UDP/ICMP: no stream → single-packet payload match as before. */
		d = ips_evaluate(ips_cfg, rs, pkt->payload, pkt->plen,
				 &fc, feat, ct_ok ? &fs : NULL);
	}
	pthread_rwlock_unlock(&sr->rwlock);

	/* [3] Verdict + connmark.
	 *   - DROP      : NF_DROP + IPS_BLOCK → the DROP rule at the head of the
	 *                 chain blocks the flow.
	 *   - INSPECTED : ML checkpoint ruled benign → set IPS_INSPECTED → offload
	 *                 (out of the queue). Rule A already has ! INSPECTED.
	 *                 Before the checkpoint: set nothing → the connbytes 0:K
	 *                 gate keeps inspecting continuously, then offloads itself
	 *                 once K is exhausted. */
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
	/* Classify the detection source (every verdict != PASS, including ALERT in detect). */
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
		"usage: %s [-q queue_num] [-r rules_path] [-d (detect)] [-n]\n"
		"  -q <n>    NFQUEUE number (default %u)\n"
		"  -r <path> rules file (default %s)\n"
		"  -d        detect mode (log only, no block)\n"
		"  -n        do not read config from mgmtd\n"
		"  -C        check-syntax: load + build the -r file then exit "
		"(0=valid, 1=error)\n",
		prog, g_cfg.queue_num, DEFAULT_RULES);
}

/*
 * check_syntax — load + build the ruleset from path, do NOT open NFQUEUE/mgmtd.
 * Used for safe updates: verify the new ruleset BEFORE swapping it into
 * production (ipsd -C -r /tmp/new.rules). Returns 0 if valid, 1 on error/0 rules.
 */
static int check_syntax(const char *path)
{
	struct sig_ruleset rs;
	struct sig_load_stats st;
	sig_ruleset_init(&rs);
	int added = sig_load_file(&rs, path, &st);
	if (added < 0) {
		fprintf(stderr, "ipsd -C: cannot open %s\n", path);
		sig_ruleset_free(&rs);
		return 1;
	}
	if (st.loaded == 0) {
		fprintf(stderr, "ipsd -C: %s has no valid rules "
			"(skip=%d err=%d)\n", path, st.skipped, st.errors);
		sig_ruleset_free(&rs);
		return 1;
	}
	if (sig_build(&rs) != 0) {
		fprintf(stderr, "ipsd -C: AC build failed for %s\n", path);
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
	int do_check = 0;
	int opt;

	while ((opt = getopt(argc, argv, "q:r:dnC")) != -1) {
		switch (opt) {
		case 'q': g_cfg.queue_num = (uint16_t)atoi(optarg); break;
		case 'r': snprintf(g_cfg.rules_path, sizeof(g_cfg.rules_path),
				   "%s", optarg); break;
		case 'd': g_cfg.mode = IPS_MODE_DETECT; break;
		case 'n': break;   /* accepted for compatibility (ips-update.sh runs
				    * `ipsd -C -r <tmp> -n`); ipsd takes all parameters
				    * from -q/-r/-d, not from mgmtd. */
		case 'C': do_check = 1; break;
		default: usage(argv[0]); return 1;
		}
	}

	/* [0] check-syntax mode: verify the ruleset then exit, do not touch the kernel */
	if (do_check)
		return check_syntax(g_cfg.rules_path);

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

	/* Phase 4 (additive): IPC inspection server for HTTPS-deep from ssld.
	 * Shares the ruleset (rdlock) with NFQUEUE. On error → log + keep running
	 * without IPC. */
	if (insp_ipc_start(&sr, &g_cfg) != 0)
		fprintf(stderr, "ipsd: insp_ipc server failed to start "
			"(HTTPS-deep will use ssld's per-chunk fallback)\n");

	struct nfq_ctx nfq;
	if (nfq_open(&nfq, g_cfg.queue_num) < 0) {
		fprintf(stderr, "ipsd: cannot open NFQUEUE %u: %m\n",
			g_cfg.queue_num);
		sig_reload_free(&sr);
		return 1;
	}

	/* ips_config from g_cfg */
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
	/* SIGHUP → logrotate: close+reopen the alert log. NO SA_RESTART so
	 * select() is interrupted immediately (select does not auto-restart even
	 * with SA_RESTART); the main loop sees the flag and reopens next iteration. */
	struct sigaction sa_hup = { .sa_handler = handle_hup };
	sigemptyset(&sa_hup.sa_mask);
	sigaction(SIGHUP, &sa_hup, NULL);
	/* SIGUSR1 is already registered by sig_reload_init (→ self-pipe) */
	/* SIGUSR2 → per-profile scope reload (no SA_RESTART so select() wakes). */
	struct sigaction sa_usr2 = { .sa_handler = handle_usr2 };
	sigemptyset(&sa_usr2.sa_mask);
	sigaction(SIGUSR2, &sa_usr2, NULL);
	/* Ignore SIGPIPE: the insp_ipc server writes to the ssld socket; if ssld
	 * closes the connection a write would otherwise kill ipsd with signal 13.
	 * EPIPE is handled at the call site instead. */
	signal(SIGPIPE, SIG_IGN);

	/* PID file for the external log-rotation tool (logrotate postrotate kill -HUP). */
	write_pidfile();

	fprintf(stderr, "ipsd: ready (%d rules, queue %u)\n",
		sr.active->n_rules, g_cfg.queue_num);

	/* ML scores inline at the min(N,K,T) CHECKPOINT in process_packet — no
	 * more polling thread. Scores are written via ml_record_score → ml_scores_flush. */

	/* [4] Main event loop */
	struct nfq_pkt pkt;
	int select_errs = 0;   /* consecutive non-EINTR select() errors */

	while (!g_stop) {
		/* SIGHUP (logrotate) → close+reopen the alert log. Placed at the top
		 * of the loop to also catch the case where select() returns EINTR and
		 * `continue` below. */
		if (g_log_reopen) {
			g_log_reopen = 0;
			log_reopen();
		}

		/* SIGUSR2 → per-profile scope changed: re-apply the maps onto the live
		 * ruleset (cheap, no automaton rebuild). */
		if (g_scope_reload) {
			g_scope_reload = 0;
			sig_reload_apply_scope(&sr);
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
			/* Don't die silently on a transient error — log and back off,
			 * then retry. Only give up after many consecutive failures
			 * (e.g. nfq.fd permanently bad), and say so loudly. */
			fprintf(stderr, "ipsd: select: %m\n");
			if (++select_errs >= 10) {
				fprintf(stderr,
					"ipsd: too many select errors — exiting\n");
				break;
			}
			usleep(100000);
			continue;
		}
		select_errs = 0;

		/* SIGUSR1 → reload the ruleset */
		if (FD_ISSET(sr.pipe_rd, &rfds))
			sig_reload_handle_signal(&sr);

		/* packet from NFQUEUE */
		if (FD_ISSET(nfq.fd, &rfds)) {
			if (nfq_recv(&nfq, &pkt) == 0) {
				g_pkt_seen++;
				process_packet(&nfq, &pkt, &sr, &ips_cfg);
			} else {
				g_recv_err++;
			}
		}
		write_rt_stats();   /* natural throttle: ≥1 time/second via the select timeout */
		ml_scores_flush();  /* push checkpoint scores to /run/...scores */
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
