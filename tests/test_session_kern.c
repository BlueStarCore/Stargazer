/*
 * test_session_kern.c — TUN-based session tracking test for Stargazer NGFW
 *
 * Creates two TUN interfaces to simulate a forwarded packet path:
 *
 *   [injected packet written to tun-sg-t0 fd]
 *         ↓
 *   kernel receives on tun-sg-t0 (10.88.0.0/24)
 *         ↓ NF_INET_FORWARD fires → session.ko creates entry
 *   kernel routes out tun-sg-t1 (10.88.1.0/24)
 *         ↓
 *   [reply packet written to tun-sg-t1 fd]
 *         ↓
 *   kernel receives reply → SESS_DIR_REPLY updates pkts_reply
 *
 * Tests:
 *   T29: /dev/net/tun accessible and two TUN interfaces created
 *   T30: /proc/stargazer/sessions readable
 *   T31: Session created after first injected UDP packet
 *   T32: Correct source/destination in session entry
 *   T33: pkts_orig=1 bytes_orig matches packet size after one packet
 *   T34: Reply packet updates pkts_reply in the same session
 *   T35: Session counters monotonically increase across multiple packets
 *
 * Cross-compile:
 *   aarch64-linux-gnu-gcc -O2 -static \
 *       -o tests/test_session_kern tests/test_session_kern.c
 *
 * Run on target (session.ko + pkt_forward.ko must be loaded):
 *   ./test_session_kern
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

/* ── Test infrastructure ─────────────────────────────────────────────────── */

static int g_pass = 0, g_fail = 0;

#define GREEN  "\033[92m"
#define RED    "\033[91m"
#define YELLOW "\033[93m"
#define RESET  "\033[0m"
#define BOLD   "\033[1m"

static void t_pass(const char *label)
{
	printf("  " GREEN "PASS" RESET " %s\n", label);
	g_pass++;
}

static void t_fail(const char *label, const char *detail)
{
	printf("  " RED "FAIL" RESET " %s\n", label);
	if (detail && detail[0])
		printf("       " YELLOW "↳ %s" RESET "\n", detail);
	g_fail++;
}

#define PASS(label)         t_pass(label)
#define FAIL(label, detail) t_fail(label, detail)
#define CHECK(cond, pass_msg, fail_msg, detail) \
	do { if (cond) PASS(pass_msg); else FAIL(fail_msg, detail); } while (0)

/* ── TUN helpers ─────────────────────────────────────────────────────────── */

static int tun_open(const char *name)
{
	struct ifreq ifr;
	int fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Run an 'ip' command and return its exit code */
static int run_ip(const char *fmt, ...)
{
	char cmd[256];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, ap);
	va_end(ap);

	/* Redirect stderr to suppress noise in test output */
	char full[300];
	snprintf(full, sizeof(full), "%s 2>/dev/null", cmd);
	return system(full);
}

/* ── IP packet builder ───────────────────────────────────────────────────── */

/* Simple one's-complement checksum for IP/UDP pseudo-header */
static uint16_t checksum(const void *data, size_t len)
{
	const uint16_t *p = data;
	uint32_t sum = 0;

	for (; len > 1; len -= 2)
		sum += *p++;
	if (len == 1)
		sum += *(const uint8_t *)p;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (uint16_t)~sum;
}

/*
 * build_udp_pkt — fill buf with a minimal IPv4/UDP packet.
 * Returns total packet length, or -1 if buf is too small.
 * UDP checksum is left at zero (optional per RFC 768 for IPv4).
 */
static int build_udp_pkt(uint8_t *buf, int buflen,
			  uint32_t src, uint32_t dst,
			  uint16_t sport, uint16_t dport,
			  const char *payload, int plen)
{
	int iphlen  = sizeof(struct iphdr);
	int udphlen = sizeof(struct udphdr);
	int total   = iphlen + udphlen + plen;

	if (total > buflen)
		return -1;

	memset(buf, 0, total);

	struct iphdr  *iph  = (struct iphdr *)buf;
	struct udphdr *udph = (struct udphdr *)(buf + iphlen);
	uint8_t       *data = buf + iphlen + udphlen;

	iph->version  = 4;
	iph->ihl      = 5;
	iph->tos      = 0;
	iph->tot_len  = htons((uint16_t)total);
	iph->id       = htons(0x5A47);   /* 'ZG' — Stargazer */
	iph->frag_off = htons(IP_DF);
	iph->ttl      = 64;
	iph->protocol = IPPROTO_UDP;
	iph->saddr    = src;
	iph->daddr    = dst;
	iph->check    = checksum(iph, iphlen);

	udph->source = htons(sport);
	udph->dest   = htons(dport);
	udph->len    = htons((uint16_t)(udphlen + plen));
	udph->check  = 0; /* omit UDP checksum (valid for IPv4) */

	if (plen > 0)
		memcpy(data, payload, plen);

	return total;
}

/* ── /proc/stargazer/sessions parser ────────────────────────────────────── */

struct sess_entry {
	uint8_t   proto;
	uint32_t  src_ip;
	uint16_t  src_port;
	uint32_t  dst_ip;
	uint16_t  dst_port;
	uint32_t  id;
	uint64_t  pkts_orig;
	uint64_t  pkts_reply;
	uint64_t  bytes_orig;
	uint64_t  bytes_reply;
	uint16_t  flags;
};

/* Parse one session line from /proc/stargazer/sessions.
 * Line format (from sess_seq_show):
 *   proto=%u src=%pI4:%u dst=%pI4:%u id=%u pkts=%llu/%llu bytes=%llu/%llu ...
 */
static bool parse_sess_line(const char *line, struct sess_entry *e)
{
	char src_s[16], dst_s[16];

	if (line[0] == '#')
		return false;

	int rc = sscanf(line,
		"proto=%hhu src=%15[^:]:%hu dst=%15[^:]:%hu id=%u "
		"pkts=%llu/%llu bytes=%llu/%llu",
		&e->proto,
		src_s, &e->src_port,
		dst_s, &e->dst_port,
		&e->id,
		&e->pkts_orig, &e->pkts_reply,
		&e->bytes_orig, &e->bytes_reply);

	if (rc < 10)
		return false;

	struct in_addr sa, da;
	if (inet_aton(src_s, &sa) == 0 || inet_aton(dst_s, &da) == 0)
		return false;

	e->src_ip = sa.s_addr;
	e->dst_ip = da.s_addr;

	/* Parse flags= field */
	const char *fp = strstr(line, "flags=");
	e->flags = fp ? (uint16_t)strtoul(fp + 6, NULL, 0) : 0;

	return true;
}

/*
 * find_session — search /proc/stargazer/sessions for an entry matching
 * the given 5-tuple.  Returns true and fills *out if found.
 */
static bool find_session(uint32_t src, uint16_t sport,
			  uint32_t dst, uint16_t dport,
			  uint8_t proto,
			  struct sess_entry *out)
{
	FILE *f = fopen("/proc/stargazer/sessions", "r");
	if (!f)
		return false;

	char line[512];
	while (fgets(line, sizeof(line), f)) {
		struct sess_entry e;
		if (!parse_sess_line(line, &e))
			continue;
		if (e.proto    == proto   &&
		    e.src_ip   == src     && e.src_port == sport &&
		    e.dst_ip   == dst     && e.dst_port == dport) {
			if (out)
				*out = e;
			fclose(f);
			return true;
		}
	}
	fclose(f);
	return false;
}

/* Total number of non-comment lines in /proc/stargazer/sessions */
static int session_count(void)
{
	FILE *f = fopen("/proc/stargazer/sessions", "r");
	if (!f)
		return -1;
	char line[512];
	int n = 0;
	while (fgets(line, sizeof(line), f))
		if (line[0] != '#')
			n++;
	fclose(f);
	return n;
}

/* ── Test IPs / ports ────────────────────────────────────────────────────── */

/* Use a 10.88.x.x range unlikely to conflict with live interfaces */
#define T0_IFACE     "tun-sg-t0"
#define T1_IFACE     "tun-sg-t1"
#define T0_CIDR      "10.88.0.1/24"
#define T1_CIDR      "10.88.1.1/24"

/* Packet endpoints — src is NOT assigned to any local interface so the
 * kernel treats the received packet as something to forward, not deliver
 * locally, triggering NF_INET_FORWARD.
 */
#define SRC_IP_S     "10.88.0.2"   /* "client" — not on any iface */
#define DST_IP_S     "10.88.1.2"   /* "server" — not on any iface */
#define SRC_PORT     ((uint16_t)55000)
#define DST_PORT     ((uint16_t)5353)

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
	int fd0 = -1, fd1 = -1;
	int rc = 0;
	uint8_t pkt[256];
	int pktlen;
	uint32_t src_ip, dst_ip;
	struct sess_entry se;
	char errbuf[128];

	printf("\n" BOLD "--- test_session_kern: TUN packet injection ---" RESET "\n\n");

	/* T29: Open /dev/net/tun and create two TUN interfaces */
	fd0 = tun_open(T0_IFACE);
	fd1 = tun_open(T1_IFACE);

	if (fd0 < 0 || fd1 < 0) {
		snprintf(errbuf, sizeof(errbuf),
			"/dev/net/tun: %s (is CONFIG_TUN=y in kernel?)",
			strerror(errno));
		FAIL("T29: Create TUN interfaces " T0_IFACE " + " T1_IFACE, errbuf);
		printf("\n  Cannot continue without TUN support.\n");
		rc = 1;
		goto cleanup;
	}
	PASS("T29: TUN interfaces " T0_IFACE " + " T1_IFACE " created");

	/* Configure IPs and bring interfaces up */
	run_ip("ip link set dev " T0_IFACE " up");
	run_ip("ip addr add " T0_CIDR " dev " T0_IFACE);
	run_ip("ip link set dev " T1_IFACE " up");
	run_ip("ip addr add " T1_CIDR " dev " T1_IFACE);

	/* Enable IP forwarding so the kernel will forward (not drop) packets */
	system("sysctl -qw net.ipv4.ip_forward=1");

	/* Temporarily allow our test subnets through iptables if present.
	 * pkt_forward.ko runs at NF_IP_PRI_FIRST (before iptables) so sessions
	 * are always created — but without these rules the packet would be
	 * dropped by iptables FORWARD DROP before reaching the server side.
	 * For session tracking correctness, we only need the FORWARD hook to
	 * fire, which happens regardless of iptables policy.
	 */
	run_ip("iptables -I FORWARD -s 10.88.0.0/24 -d 10.88.1.0/24 -j ACCEPT");
	run_ip("iptables -I FORWARD -s 10.88.1.0/24 -d 10.88.0.0/24 -j ACCEPT");

	/* Small settle time for interface + route setup */
	usleep(50000);

	/* T30: /proc/stargazer/sessions must be readable */
	{
		FILE *pf = fopen("/proc/stargazer/sessions", "r");
		if (pf) {
			fclose(pf);
			PASS("T30: /proc/stargazer/sessions readable (session.ko loaded)");
		} else {
			snprintf(errbuf, sizeof(errbuf),
				"open /proc/stargazer/sessions: %s — is session.ko loaded?",
				strerror(errno));
			FAIL("T30: /proc/stargazer/sessions readable", errbuf);
			rc = 1;
			goto cleanup_rules;
		}
	}

	inet_aton(SRC_IP_S, (struct in_addr *)&src_ip);
	inet_aton(DST_IP_S, (struct in_addr *)&dst_ip);

	/* Note the session count before injection */
	int before = session_count();

	/* T31: Inject first UDP packet — src=10.88.0.2:55000 dst=10.88.1.2:5353
	 * Written to fd0 (tun-sg-t0).  The kernel treats it as arriving on
	 * tun-sg-t0, sees the destination (10.88.1.2) is reachable via tun-sg-t1,
	 * and hits NF_INET_FORWARD → session.ko creates an entry.
	 */
	pktlen = build_udp_pkt(pkt, sizeof(pkt),
			       src_ip, dst_ip,
			       SRC_PORT, DST_PORT,
			       "stargazer", 9);
	if (pktlen < 0) {
		FAIL("T31: Build UDP packet", "build_udp_pkt failed (buffer too small)");
		rc = 1;
		goto cleanup_rules;
	}

	ssize_t written = write(fd0, pkt, pktlen);
	if (written != pktlen) {
		snprintf(errbuf, sizeof(errbuf),
			"write to " T0_IFACE ": %s", strerror(errno));
		FAIL("T31: Inject UDP packet via " T0_IFACE, errbuf);
		rc = 1;
		goto cleanup_rules;
	}

	/* Give the kernel a moment to process the packet through NF_INET_FORWARD */
	usleep(20000);

	int after = session_count();
	if (after > before) {
		PASS("T31: Session created after injecting first UDP packet "
		     "(" SRC_IP_S ":" "55000" " → " DST_IP_S ":" "5353" ")");
	} else {
		snprintf(errbuf, sizeof(errbuf),
			"Session count before=%d after=%d — FORWARD hook may not have fired. "
			"Check: ip_forward enabled? pkt_forward.ko loaded? routing correct?",
			before, after);
		FAIL("T31: Session created after injecting first UDP packet", errbuf);
		rc = 1;
		goto cleanup_rules;
	}

	/* T32: Session entry has correct 5-tuple */
	if (find_session(src_ip, SRC_PORT, dst_ip, DST_PORT, IPPROTO_UDP, &se)) {
		PASS("T32: Session entry has correct src=" SRC_IP_S ":" "55000"
		     " dst=" DST_IP_S ":" "5353" " proto=UDP");
	} else {
		FAIL("T32: Session entry with correct 5-tuple not found in procfs",
		     "procfs may show a different direction — check src/dst ordering");
		rc = 1;
		goto cleanup_rules;
	}

	/* T33: pkts_orig=1 and bytes_orig matches the injected packet size */
	{
		bool pkts_ok  = (se.pkts_orig  == 1);
		bool bytes_ok = (se.bytes_orig == (uint64_t)pktlen);
		char detail[128];

		if (pkts_ok) {
			PASS("T33a: pkts_orig=1 after one injected packet");
		} else {
			snprintf(detail, sizeof(detail),
				"pkts_orig=%llu (expected 1)",
				(unsigned long long)se.pkts_orig);
			FAIL("T33a: pkts_orig=1 after one injected packet", detail);
			rc = 1;
		}

		if (bytes_ok) {
			PASS("T33b: bytes_orig matches actual packet length");
		} else {
			snprintf(detail, sizeof(detail),
				"bytes_orig=%llu, injected pktlen=%d",
				(unsigned long long)se.bytes_orig, pktlen);
			FAIL("T33b: bytes_orig matches actual packet length", detail);
			rc = 1;
		}
	}

	/* T34: Inject reply packet (reversed 5-tuple) via tun-sg-t1.
	 * The session code checks both the forward key and the reversed key;
	 * a reply packet must increment pkts_reply in the SAME session entry.
	 */
	int reply_pktlen = build_udp_pkt(pkt, sizeof(pkt),
					  dst_ip, src_ip,           /* reversed */
					  DST_PORT, SRC_PORT,
					  "reply", 5);
	if (reply_pktlen < 0) {
		FAIL("T34: Build reply packet", "build_udp_pkt failed");
		rc = 1;
		goto cleanup_rules;
	}

	written = write(fd1, pkt, reply_pktlen);
	if (written != reply_pktlen) {
		snprintf(errbuf, sizeof(errbuf),
			"write to " T1_IFACE ": %s", strerror(errno));
		FAIL("T34: Inject reply packet via " T1_IFACE, errbuf);
		rc = 1;
		goto cleanup_rules;
	}

	usleep(20000);

	/* Re-read the session — same entry, same id, pkts_reply should be 1 */
	struct sess_entry se2;
	if (!find_session(src_ip, SRC_PORT, dst_ip, DST_PORT, IPPROTO_UDP, &se2)) {
		FAIL("T34: Original session still present after reply packet",
		     "Session disappeared — may have been deleted or key matching failed");
		rc = 1;
		goto cleanup_rules;
	}

	{
		bool id_same     = (se2.id == se.id);
		bool reply_ok    = (se2.pkts_reply == 1);
		bool orig_stable = (se2.pkts_orig  == se.pkts_orig);
		char detail[128];

		if (id_same) {
			PASS("T34a: Reply packet attributed to same session (id unchanged)");
		} else {
			snprintf(detail, sizeof(detail),
				"Session id changed: was %u now %u — reply created new entry",
				se.id, se2.id);
			FAIL("T34a: Reply packet attributed to same session", detail);
			rc = 1;
		}

		if (reply_ok) {
			PASS("T34b: pkts_reply=1 after reply packet");
		} else {
			snprintf(detail, sizeof(detail),
				"pkts_reply=%llu (expected 1)",
				(unsigned long long)se2.pkts_reply);
			FAIL("T34b: pkts_reply=1 after reply packet", detail);
			rc = 1;
		}

		if (orig_stable) {
			PASS("T34c: pkts_orig unchanged after reply packet (direction correct)");
		} else {
			snprintf(detail, sizeof(detail),
				"pkts_orig changed from %llu to %llu after reply",
				(unsigned long long)se.pkts_orig,
				(unsigned long long)se2.pkts_orig);
			FAIL("T34c: pkts_orig unchanged after reply packet", detail);
			rc = 1;
		}
	}

	/* T35: Send three more original-direction packets; verify counters grow */
	for (int i = 0; i < 3; i++) {
		pktlen = build_udp_pkt(pkt, sizeof(pkt),
				       src_ip, dst_ip,
				       SRC_PORT, DST_PORT,
				       "extra", 5);
		if (pktlen > 0)
			write(fd0, pkt, pktlen);
	}

	usleep(30000);

	struct sess_entry se3;
	if (!find_session(src_ip, SRC_PORT, dst_ip, DST_PORT, IPPROTO_UDP, &se3)) {
		FAIL("T35: Session still present after bulk packets", "Session vanished");
		rc = 1;
	} else {
		bool monotone = (se3.pkts_orig > se2.pkts_orig) &&
				(se3.bytes_orig > se2.bytes_orig);
		char detail[128];
		snprintf(detail, sizeof(detail),
			"pkts_orig: %llu→%llu  bytes_orig: %llu→%llu",
			(unsigned long long)se2.pkts_orig,
			(unsigned long long)se3.pkts_orig,
			(unsigned long long)se2.bytes_orig,
			(unsigned long long)se3.bytes_orig);
		if (monotone) {
			PASS("T35: Packet and byte counters increase monotonically");
			printf("       pkts_orig=%llu bytes_orig=%llu pkts_reply=%llu bytes_reply=%llu\n",
			       (unsigned long long)se3.pkts_orig,
			       (unsigned long long)se3.bytes_orig,
			       (unsigned long long)se3.pkts_reply,
			       (unsigned long long)se3.bytes_reply);
		} else {
			FAIL("T35: Counters not monotonically increasing", detail);
			rc = 1;
		}
	}

cleanup_rules:
	run_ip("iptables -D FORWARD -s 10.88.0.0/24 -d 10.88.1.0/24 -j ACCEPT");
	run_ip("iptables -D FORWARD -s 10.88.1.0/24 -d 10.88.0.0/24 -j ACCEPT");

cleanup:
	if (fd0 >= 0) close(fd0);
	if (fd1 >= 0) close(fd1);
	run_ip("ip link del " T0_IFACE);
	run_ip("ip link del " T1_IFACE);

	printf("\n" BOLD "--- Results: %d passed, %d failed ---" RESET "\n\n",
	       g_pass, g_fail);

	return (g_fail > 0) ? 1 : 0;
}
