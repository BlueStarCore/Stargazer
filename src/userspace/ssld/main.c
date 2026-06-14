/* SPDX-License-Identifier: MIT */
/*
 * main.c - stargazer-ssld: transparent TLS-inspection proxy cho Stargazer NGFW.
 *
 *   iptables REDIRECT flow TLS → ssld → accept → thread/kết nối →
 *   ssld_handle_conn (peek SNI → splice/bump). BUMP: terminate + giải mã +
 *   soi plaintext bằng signature engine + mã hóa lại.
 *
 * Chạy thật: cần root + rule REDIRECT (mgmtd dựng khi accept policy gán security_ssl-inspection-profile):
 *   -t nat -A PREROUTING -i lan -p tcp --dport 443 -j REDIRECT --to-ports 8443
 */
#define _GNU_SOURCE
#include "conn.h"
#include "tls_policy.h"
#include "ca.h"
#include "certcache.h"
#include "sig_rule.h"        /* ../ipsd: sig_ruleset, sig_load_file, sig_build */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/ssl.h>

#define DEFAULT_PORT   8443
#define DEFAULT_CACERT "/etc/stargazer/ssl/ca-cert.pem"
#define DEFAULT_CAKEY  "/etc/stargazer/ssl/ca-key.pem"
#define CERTCACHE_MAX  1024

static volatile sig_atomic_t g_stop;
static void handle_stop(int s) { (void)s; g_stop = 1; }
static struct ssld_stats g_stats;

struct conn_job {
	int                     fd;
	const struct ssld_ctx  *ctx;
};

static void *conn_thread(void *arg)
{
	struct conn_job *j = arg;
	ssld_handle_conn(j->fd, j->ctx, &g_stats);
	free(j);
	return NULL;
}

static int load_bypass_file(struct tls_policy *pol, const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "ssld: không mở được bypass file %s: %m\n", path);
		return -1;
	}
	char line[320];
	int n = 0;
	while (fgets(line, sizeof(line), f)) {
		char *p = line;
		while (*p == ' ' || *p == '\t') p++;
		if (*p == '#' || *p == '\n' || *p == '\0')
			continue;
		if (tls_policy_add_bypass(pol, p) == 0)
			n++;
	}
	fclose(f);
	return n;
}

static int make_listener(uint16_t port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
		.sin_port = htons(port),
	};
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		fprintf(stderr, "ssld: bind :%u thất bại: %m\n", port);
		close(fd);
		return -1;
	}
	if (listen(fd, 128) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"dùng: %s [-p port] [-b bypass_file] [-r rules] [-B] [-S] [-V]\n"
		"      [-c ca_cert] [-k ca_key]\n"
		"  -p <port>  cổng nghe REDIRECT (mặc định %d)\n"
		"  -b <file>  bypass list (domain | *.domain mỗi dòng)\n"
		"  -r <file>  ruleset signature để soi plaintext bump\n"
		"  -B         flow không SNI → SPLICE (mặc định BUMP)\n"
		"  -S         splice-only (TẮT bump — không giải mã)\n"
		"  -V         verify cert server thật (fail-closed nếu lỗi)\n"
		"  -c <file>  CA cert (mặc định %s)\n"
		"  -k <file>  CA key  (mặc định %s)\n",
		prog, DEFAULT_PORT, DEFAULT_CACERT, DEFAULT_CAKEY);
}

int main(int argc, char **argv)
{
	uint16_t port = DEFAULT_PORT;
	const char *bypass_file = NULL, *rules_file = NULL;
	const char *ca_cert = DEFAULT_CACERT, *ca_key = DEFAULT_CAKEY;
	int no_sni_splice = 0, splice_only = 0, verify_upstream = 0;
	int no_ipc = 0, ipc_failclosed = 0;   /* Phase 4 */
	int opt;

	while ((opt = getopt(argc, argv, "p:b:r:BSVQFc:k:h")) != -1) {
		switch (opt) {
		case 'p': port = (uint16_t)atoi(optarg); break;
		case 'b': bypass_file = optarg; break;
		case 'r': rules_file = optarg; break;
		case 'B': no_sni_splice = 1; break;
		case 'S': splice_only = 1; break;
		case 'V': verify_upstream = 1; break;
		case 'Q': no_ipc = 1; break;          /* P4: tắt IPC, soi per-chunk */
		case 'F': ipc_failclosed = 1; break;  /* P4: IPC lỗi → chặn flow */
		case 'c': ca_cert = optarg; break;
		case 'k': ca_key = optarg; break;
		case 'h': default: usage(argv[0]); return (opt == 'h') ? 0 : 1;
		}
	}

	/* policy */
	struct tls_policy pol;
	tls_policy_init(&pol);
	pol.no_sni = no_sni_splice ? TLS_NO_SNI_SPLICE : TLS_NO_SNI_BUMP;
	if (bypass_file) {
		int n = load_bypass_file(&pol, bypass_file);
		if (n >= 0)
			fprintf(stderr, "ssld: nạp %d bypass pattern\n", n);
	}

	/* CA + certcache (cho bump) */
	struct ca_ctx ca;
	struct certcache *cc = NULL;
	int bump_ready = 0;
	if (!splice_only) {
		if (ca_load_or_create(&ca, ca_cert, ca_key) == 0 &&
		    (cc = certcache_new(&ca, CERTCACHE_MAX)) != NULL) {
			bump_ready = 1;
			fprintf(stderr, "ssld: CA sẵn sàng (%s) — BUMP bật\n", ca_cert);
		} else {
			fprintf(stderr, "ssld: CA lỗi — chạy SPLICE-only\n");
		}
	}

	/* ruleset signature (tùy chọn) */
	struct sig_ruleset rs;
	struct sig_ruleset *rules = NULL;
	if (rules_file && bump_ready) {
		sig_ruleset_init(&rs);
		struct sig_load_stats ls;
		int added = sig_load_file(&rs, rules_file, &ls);
		if (added >= 0 && sig_build(&rs) == 0) {
			rules = &rs;
			fprintf(stderr, "ssld: nạp %d rule (soi plaintext bump)\n",
				added);
		} else {
			fprintf(stderr, "ssld: nạp rules %s lỗi — bump không soi\n",
				rules_file);
			sig_ruleset_free(&rs);
		}
	}

	struct ssld_ctx ctx = {
		.pol = &pol,
		.ca  = bump_ready ? &ca : NULL,
		.cc  = bump_ready ? cc  : NULL,
		.rules = rules,
		.verify_upstream = verify_upstream,
		.no_ipc = no_ipc,
		.ipc_failclosed = ipc_failclosed,
	};

	signal(SIGPIPE, SIG_IGN);
	struct sigaction sa = { .sa_handler = handle_stop };
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	int lfd = make_listener(port);
	if (lfd < 0)
		goto cleanup;
	fprintf(stderr, "ssld: nghe :%u mode=%s verify_upstream=%d\n",
		port, bump_ready ? "BUMP+splice" : "splice-only", verify_upstream);

	while (!g_stop) {
		int cfd = accept(lfd, NULL, NULL);
		if (cfd < 0) {
			if (errno == EINTR) continue;
			if (g_stop) break;
			fprintf(stderr, "ssld: accept: %m\n");
			continue;
		}
		struct conn_job *job = malloc(sizeof(*job));
		if (!job) { close(cfd); continue; }
		job->fd = cfd;
		job->ctx = &ctx;
		pthread_t th;
		if (pthread_create(&th, NULL, conn_thread, job) != 0) {
			close(cfd);
			free(job);
			continue;
		}
		pthread_detach(th);
	}

	fprintf(stderr, "ssld: dừng — total=%lu splice=%lu bump=%lu error=%lu\n",
		g_stats.n_total, g_stats.n_splice,
		g_stats.n_bump, g_stats.n_error);
	close(lfd);

cleanup:
	if (rules) sig_ruleset_free(&rs);
	if (cc) certcache_free(cc);
	if (bump_ready) ca_free(&ca);
	tls_policy_free(&pol);
	return 0;
}
