/* SPDX-License-Identifier: MIT */
/*
 * stargazer-webd.c — Embedded HTTP daemon for Stargazer NGFW
 *
 * Serves web UI static files and provides REST API by translating
 * JSON HTTP requests into IPC calls to stargazer-mgmtd.
 *
 * Architecture:
 *   Browser ──HTTP──► stargazer-webd ──IPC──► stargazer-mgmtd
 *                     (Mongoose HTTP)          (root, does all work)
 *                     (unprivileged)
 *
 * Startup: parse args → install signals → write PID → drop privileges →
 *          bind listeners → spawn pool → signal ready → seccomp → poll loop
 */

#define _GNU_SOURCE
#include "mongoose.h"
#include "webd_api.h"
#include "webd_ipc.h"
#include "webd_pool.h"
#include "webd_session.h"
#include "webd_sandbox.h"
#include "stargazer_ipc.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define WEBD_WWW_DIR       "/usr/share/stargazer/www"
#define WEBD_READY_FIFO    "/run/webd-ready"
#define WEBD_PID_FILE      "/run/stargazer-webd.pid"
#define WEBD_TLS_CERT      "/etc/stargazer/tls/cert.pem"
#define WEBD_TLS_KEY       "/etc/stargazer/tls/key.pem"
#define WEBD_SERVICE_USER  "__webd"
#define WEBD_UID           900
#define WEBD_GID           900
#define EXPIRE_INTERVAL    60   /* seconds between session expiry checks */

/* ── Globals ─────────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_rebind  = 0;
static struct mg_mgr         g_mgr;
static char                 *g_tls_cert = NULL;
static char                 *g_tls_key  = NULL;
static time_t                g_last_expire = 0;
int                          g_tls_active = 0;  /* set when TLS cert loaded */

/* WEBD_SEC_HEADERS defined in webd_api.h (shared with reply_json) */

/* TLS options for HTTPS listeners (initialized from g_tls_cert/g_tls_key) */
static struct mg_tls_opts g_tls_opts;

/* ── Signal handlers ─────────────────────────────────────────────────── */

static void sig_term(int sig)
{
	(void)sig;
	g_running = 0;
}

static void sig_hup(int sig)
{
	(void)sig;
	g_rebind = 1;
}

static void install_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_hup;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGHUP, &sa, NULL);

	signal(SIGPIPE, SIG_IGN);
}

/* ── PID file ────────────────────────────────────────────────────────── */

static void write_pidfile(void)
{
	FILE *f = fopen(WEBD_PID_FILE, "w");
	if (f) {
		fprintf(f, "%d\n", getpid());
		fclose(f);
	}
}

/* ── Readiness signal ────────────────────────────────────────────────── */

static void signal_ready(void)
{
	FILE *f = fopen(WEBD_READY_FIFO, "w");
	if (f) {
		fprintf(f, "ready");
		fclose(f);
	}
}

/* Forward declaration */
static void ev_handler(struct mg_connection *c, int ev, void *ev_data);

/* ── Per-interface listener binding ──────────────────────────────────── */

/*
 * Query mgmtd for interface list and their allowaccess settings.
 * For each interface with "http" in allowaccess → bind IP:80.
 * For each interface with "https" in allowaccess + TLS configured → bind IP:443.
 * Returns number of listeners created.
 */
static int bind_listeners(void)
{
	int count = 0;

	/* Get interface list from mgmtd */
	webd_ipc_response_t list_resp;
	if (webd_ipc_send(SG_CMD_CFG_LIST, WEBD_SERVICE_USER,
			  0, "system_interface\n", &list_resp) != 0) {
		fprintf(stderr, "webd: failed to query interface list\n");
		return 0;
	}

	if (list_resp.status != SG_OK || !list_resp.payload) {
		webd_ipc_resp_free(&list_resp);
		return 0;
	}

	/* Parse each interface */
	char *copy = strdup(list_resp.payload);
	webd_ipc_resp_free(&list_resp);
	if (!copy) return 0;

	char *saveptr = NULL;
	for (char *iface = strtok_r(copy, "\n", &saveptr);
	     iface;
	     iface = strtok_r(NULL, "\n", &saveptr)) {

		if (!iface[0]) continue;

		/* Get interface config */
		char get_payload[256];
		snprintf(get_payload, sizeof(get_payload),
			 "system_interface:%s\n", iface);

		webd_ipc_response_t iface_resp;
		if (webd_ipc_send(SG_CMD_CFG_GET, WEBD_SERVICE_USER,
				  0, get_payload, &iface_resp) != 0)
			continue;

		if (iface_resp.status != SG_OK || !iface_resp.payload) {
			webd_ipc_resp_free(&iface_resp);
			continue;
		}

		/* Extract mode, IP, and allowaccess */
		char mode[16] = "", ip[64] = "", allowaccess[256] = "";
		const char *p;
		if ((p = strstr(iface_resp.payload, "mode=")) != NULL) {
			const char *nl = strchr(p + 5, '\n');
			size_t len = nl ? (size_t)(nl - p - 5) : strlen(p + 5);
			if (len < sizeof(mode)) {
				memcpy(mode, p + 5, len);
				mode[len] = '\0';
			}
		}
		if ((p = strstr(iface_resp.payload, "ip=")) != NULL) {
			const char *nl = strchr(p + 3, '\n');
			size_t len = nl ? (size_t)(nl - p - 3) : strlen(p + 3);
			if (len < sizeof(ip)) {
				memcpy(ip, p + 3, len);
				ip[len] = '\0';
			}
		}
		if ((p = strstr(iface_resp.payload, "allowaccess=")) != NULL) {
			const char *nl = strchr(p + 12, '\n');
			size_t len = nl ? (size_t)(nl - p - 12) : strlen(p + 12);
			if (len < sizeof(allowaccess)) {
				memcpy(allowaccess, p + 12, len);
				allowaccess[len] = '\0';
			}
		}
		webd_ipc_resp_free(&iface_resp);

		/* Strip CIDR prefix from IP (e.g. "192.168.1.1/24" → "192.168.1.1") */
		char *slash = strchr(ip, '/');
		if (slash) *slash = '\0';

		/* DHCP interfaces have no static IP in the config DB.
		 * Query the kernel for the live address via ioctl so we bind
		 * to the correct interface rather than 0.0.0.0. */
		if (!ip[0] || strcmp(mode, "dhcp") == 0) {
			struct ifreq ifr;
			int s = socket(AF_INET, SOCK_DGRAM, 0);
			if (s >= 0) {
				memset(&ifr, 0, sizeof(ifr));
				snprintf(ifr.ifr_name, sizeof(ifr.ifr_name),
					 "%s", iface);
				if (ioctl(s, SIOCGIFADDR, &ifr) == 0) {
					struct sockaddr_in *sa =
						(struct sockaddr_in *)&ifr.ifr_addr;
					snprintf(ip, sizeof(ip), "%s",
						 inet_ntoa(sa->sin_addr));
				} else {
					ip[0] = '\0'; /* DHCP lease not yet assigned */
				}
				close(s);
			}
		}

		if (!ip[0]) continue;

		/* Check for http/https in allowaccess (space-separated tokens) */
		int has_http = 0, has_https = 0;
		{
			char tmp[256];
			snprintf(tmp, sizeof(tmp), "%s", allowaccess);
			char *sp = NULL;
			for (char *tk = strtok_r(tmp, " ", &sp); tk;
			     tk = strtok_r(NULL, " ", &sp)) {
				if (strcmp(tk, "http") == 0)  has_http = 1;
				if (strcmp(tk, "https") == 0) has_https = 1;
			}
		}

		if (has_http) {
			char url[128];
			snprintf(url, sizeof(url), "http://%s:80", ip);
			struct mg_connection *c = mg_http_listen(&g_mgr, url, ev_handler, NULL);
			if (c) {
				fprintf(stderr, "webd: listening on %s\n", url);
				count++;
			} else {
				fprintf(stderr, "webd: failed to bind %s\n", url);
			}
		}

		if (has_https && g_tls_cert && g_tls_key) {
			char url[128];
			snprintf(url, sizeof(url), "https://%s:443", ip);
			struct mg_connection *c = mg_http_listen(&g_mgr, url, ev_handler, NULL);
			if (c) {
				fprintf(stderr, "webd: listening on %s (TLS)\n", url);
				count++;
			} else {
				fprintf(stderr, "webd: failed to bind %s\n", url);
			}
		}
	}

	free(copy);
	return count;
}

/*
 * Rebind listeners: close all existing connections and re-query mgmtd.
 * Called when SIGHUP is received (allowaccess changed at runtime).
 */
static void rebind_listeners(void)
{
	fprintf(stderr, "webd: rebinding listeners (SIGHUP)\n");

	mg_mgr_free(&g_mgr);
	mg_mgr_init(&g_mgr);
	mg_wakeup_init(&g_mgr);  /* Recreate wakeup pipe (destroyed by mg_mgr_free) */
	g_mgr.userdata = NULL;

	int n = bind_listeners();
	fprintf(stderr, "webd: rebound %d listener(s)\n", n);
}

/* ── Mongoose event handler ──────────────────────────────────────────── */

static void ev_handler(struct mg_connection *c, int ev, void *ev_data)
{
	if (ev == MG_EV_ACCEPT) {
		/* Initialize TLS on accepted connections to HTTPS listeners */
		if (c->is_tls)
			mg_tls_init(c, &g_tls_opts);
	} else if (ev == MG_EV_HTTP_MSG) {
		struct mg_http_message *hm = (struct mg_http_message *)ev_data;

		/* API routes */
		if (hm->uri.len >= 5 &&
		    memcmp(hm->uri.buf, "/api/", 5) == 0) {
			webd_api_dispatch(hm, c);
			return;
		}

		/* Static file serving */
		static char static_hdrs[384];
		static char static_hdrs_hsts[512];
		static int static_hdrs_init = 0;
		if (!static_hdrs_init) {
			/* Strict CSP — all resources self-hosted, no external
			 * CDN. NGFW must be air-gapped. */
			snprintf(static_hdrs, sizeof(static_hdrs),
				"Cache-Control: no-cache\r\n"
				"X-Content-Type-Options: nosniff\r\n"
				"X-Frame-Options: DENY\r\n"
				"Content-Security-Policy: default-src 'self' 'unsafe-inline'; "
				"font-src 'self'\r\n");
			snprintf(static_hdrs_hsts, sizeof(static_hdrs_hsts),
				"%s" WEBD_HSTS_HEADER, static_hdrs);
			static_hdrs_init = 1;
		}
		struct mg_http_serve_opts opts = {
			.root_dir = WEBD_WWW_DIR,
			.ssi_pattern = NULL,
			.extra_headers = g_tls_active ? static_hdrs_hsts
						      : static_hdrs,
			/* Mongoose lacks woff2 in builtin MIME table */
			.mime_types = "woff2=font/woff2",
		};
		mg_http_serve_dir(c, hm, &opts);

	} else if (ev == MG_EV_WAKEUP) {
		/* Worker thread completed — send HTTP response */
		struct mg_str *data = (struct mg_str *)ev_data;
		if (data->len >= sizeof(work_result_t)) {
			work_result_t result;
			memcpy(&result, data->buf, sizeof(result));

			/* Build headers: base security + HSTS + any extra (Set-Cookie) */
			char hdrs[512];
			if (result.extra_hdrs[0])
				snprintf(hdrs, sizeof(hdrs), "%s%s",
					 webd_sec_headers(), result.extra_hdrs);
			else
				snprintf(hdrs, sizeof(hdrs), "%s",
					 webd_sec_headers());

			if (result.data && result.data_len > 0) {
				mg_http_reply(c, result.http_status,
					      hdrs,
					      "%.*s",
					      (int)result.data_len,
					      result.data);
			} else {
				mg_http_reply(c, result.http_status,
					      hdrs,
					      "{\"error\":\"Internal error\"}");
			}
			free(result.data);
		}
	}
}

/* ── Capability management ───────────────────────────────────────────── */

/* Linux capability header/data for capset(2) */
struct cap_header {
	uint32_t version;
	int      pid;
};

struct cap_data {
	uint32_t effective;
	uint32_t permitted;
	uint32_t inheritable;
};

#ifndef _LINUX_CAPABILITY_VERSION_3
#define _LINUX_CAPABILITY_VERSION_3 0x20080522
#endif

/* CAP_NET_BIND_SERVICE = bit 10 */
#define CAP_NET_BIND_SERVICE_BIT (1U << 10)

/*
 * Drop privileges to stargazer:stargazer (900:900).
 * Retain CAP_NET_BIND_SERVICE for SIGHUP rebind on ports 80/443.
 */
static int drop_privileges(void)
{
	/* Keep caps across setuid */
	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
		fprintf(stderr, "webd: PR_SET_KEEPCAPS failed: %s\n",
			strerror(errno));
		return -1;
	}

	/* Drop group */
	if (setgid(WEBD_GID) != 0) {
		fprintf(stderr, "webd: setgid(%d) failed: %s\n",
			WEBD_GID, strerror(errno));
		return -1;
	}

	/* Drop user */
	if (setuid(WEBD_UID) != 0) {
		fprintf(stderr, "webd: setuid(%d) failed: %s\n",
			WEBD_UID, strerror(errno));
		return -1;
	}

	/* Set caps to only CAP_NET_BIND_SERVICE */
	struct cap_header hdr;
	struct cap_data data[2];

	memset(&hdr, 0, sizeof(hdr));
	memset(data, 0, sizeof(data));
	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	hdr.pid = 0;

	data[0].effective   = CAP_NET_BIND_SERVICE_BIT;
	data[0].permitted   = CAP_NET_BIND_SERVICE_BIT;
	data[0].inheritable = 0;

	if (syscall(SYS_capset, &hdr, data) != 0) {
		fprintf(stderr, "webd: capset failed: %s\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

/* ── Graceful shutdown ───────────────────────────────────────────────── */

static void cleanup_sessions(void)
{
	/* Send SESSION_TAG_DEL for all active sessions (best-effort) */
	/* Sessions are already expired/destroyed by session_destroy_all() */
	session_destroy_all();
}

/* ── Usage ───────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [options]\n"
		"  --tls-cert PATH   TLS certificate file\n"
		"  --tls-key PATH    TLS private key file\n"
		"  -h, --help        Show this help\n",
		prog);
}

/* ── Main ────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
	/* Parse command-line arguments */
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--tls-cert") == 0 && i + 1 < argc)
			g_tls_cert = argv[++i];
		else if (strcmp(argv[i], "--tls-key") == 0 && i + 1 < argc)
			g_tls_key = argv[++i];
		else if (strcmp(argv[i], "-h") == 0 ||
			 strcmp(argv[i], "--help") == 0) {
			usage(argv[0]);
			return 0;
		} else {
			fprintf(stderr, "webd: unknown option: %s\n", argv[i]);
			usage(argv[0]);
			return 1;
		}
	}

	/* Validate TLS: both cert and key must be provided together */
	if ((g_tls_cert && !g_tls_key) || (!g_tls_cert && g_tls_key)) {
		fprintf(stderr,
			"webd: --tls-cert and --tls-key must both be provided\n");
		return 1;
	}

	/* Initialize TLS opts if cert+key provided */
	if (g_tls_cert && g_tls_key) {
		g_tls_opts.cert = mg_str(g_tls_cert);
		g_tls_opts.key  = mg_str(g_tls_key);
		g_tls_active = 1;
	}

	fprintf(stderr, "webd: starting stargazer-webd\n");

	/* Install signal handlers BEFORE writing PID file.
	 * mgmtd sends SIGHUP via our PID file on allowaccess changes. */
	install_signals();

	/* Write PID file while still root (/run is root-only) */
	write_pidfile();

	/* Drop privileges BEFORE IPC — mgmtd's SO_PEERCRED verifies
	 * that our UID matches the claimed username (__webd:900).
	 * Retain CAP_NET_BIND_SERVICE for ports 80/443. */
	if (getuid() == 0) {
		if (drop_privileges() != 0) {
			fprintf(stderr, "webd: privilege drop failed\n");
			return 1;
		}
	}

	/* Initialize Mongoose */
	mg_mgr_init(&g_mgr);
	mg_wakeup_init(&g_mgr);  /* Required for cross-thread mg_wakeup() */
	g_mgr.userdata = NULL;

	/* Set default event handler for all connections */
	g_mgr.dns4.url = "udp://127.0.0.1:53";

	/* Wait for mgmtd socket (up to 10s) — handles startup ordering
	 * and supervisor restart races.  Pattern: wait-for-it.sh / dockerize. */
	for (int i = 0; i < 100; i++) {
		struct stat st;
		if (stat(SG_MGMTD_SOCK, &st) == 0)
			break;
		usleep(100000); /* 100ms */
	}

	/* Bind listeners: query mgmtd for interface allowaccess config.
	 * CAP_NET_BIND_SERVICE allows binding ports 80/443 as non-root. */
	int n = bind_listeners();
	if (n == 0)
		fprintf(stderr,
			"webd: no listeners bound "
			"(no interface has http/https in allowaccess)\n");

	/* Spawn thread pool */
	webd_pool_init(&g_mgr);

	/* Signal readiness AFTER binding — "ready" means actually serving.
	 * FIFO is chmod 0666 by init so __webd (non-root) can write. */
	signal_ready();

	fprintf(stderr, "webd: ready (%d listener%s)\n",
		n, n == 1 ? "" : "s");

	/* Install seccomp sandbox */
#ifndef WEBD_NO_SANDBOX
	if (webd_sandbox_install() != 0)
		fprintf(stderr, "webd: sandbox install failed (continuing)\n");
#endif

	/* ── Main poll loop ──────────────────────────────────────────── */

	g_last_expire = time(NULL);

	while (g_running) {
		mg_mgr_poll(&g_mgr, 1000);

		/* Handle SIGHUP rebind */
		if (g_rebind) {
			g_rebind = 0;
			rebind_listeners();
		}

		/* Periodic session expiry check */
		time_t now = time(NULL);
		if (now - g_last_expire >= EXPIRE_INTERVAL) {
			session_expire_check();
			g_last_expire = now;
		}
	}

	/* ── Graceful shutdown ───────────────────────────────────────── */

	fprintf(stderr, "webd: shutting down\n");

	/* Stop thread pool (join workers) */
	webd_pool_shutdown();

	/* Clean up sessions */
	cleanup_sessions();

	/* Free Mongoose */
	mg_mgr_free(&g_mgr);

	/* Remove PID file */
	unlink(WEBD_PID_FILE);

	fprintf(stderr, "webd: stopped\n");
	return 0;
}
