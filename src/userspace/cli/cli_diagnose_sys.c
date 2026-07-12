/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose_sys.c — Pure C system diagnostics for Stargazer CLI
 *
 * IPC-only resource monitoring. All data comes from mgmtd via IPC —
 * no direct /proc or /sys reads. Works in the seccomp sandbox.
 *
 * Replaces the shell-based resource functions:
 *   execute diagnose resources [cpu|ram|disk|interface|all]
 *   execute diagnose top
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "cli_diagnose_sys.h"
#include "cli_ipc.h"

#include <ctype.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── CPU ─────────────────────────────────────────────────────────────── */

/* Fields from /proc/stat cpu line: user nice system idle iowait irq softirq steal */
#define CPU_FIELDS 8

struct cpu_sample {
	char name[16];
	unsigned long vals[CPU_FIELDS];
	unsigned long total;
	unsigned long idle; /* idle + iowait */
};

#define MAX_CPUS 64

/* Parse cpu samples from IPC response (text lines from mgmtd DIAG_CPU) */
static int parse_cpu_samples(const char *data, struct cpu_sample *out, int max)
{
	int count = 0;
	const char *p = data;

	while (*p && count < max) {
		/* Only parse lines starting with "cpu" */
		if (strncmp(p, "cpu", 3) != 0 ||
		    (p[3] != ' ' && !isdigit((unsigned char)p[3]))) {
			const char *nl = strchr(p, '\n');
			if (!nl) break;
			p = nl + 1;
			continue;
		}

		struct cpu_sample *s = &out[count];
		memset(s, 0, sizeof(*s));

		/* Parse name */
		int ni = 0;
		while (*p && *p != ' ' && ni < (int)sizeof(s->name) - 1)
			s->name[ni++] = *p++;
		s->name[ni] = '\0';

		/* Parse fields */
		for (int i = 0; i < CPU_FIELDS && *p; i++) {
			while (*p == ' ') p++;
			s->vals[i] = strtoul(p, NULL, 10);
			while (*p && *p != ' ' && *p != '\n') p++;
		}

		s->total = 0;
		for (int i = 0; i < CPU_FIELDS; i++)
			s->total += s->vals[i];
		s->idle = s->vals[3] + s->vals[4]; /* idle + iowait */

		count++;

		const char *nl = strchr(p, '\n');
		if (!nl) break;
		p = nl + 1;
	}
	return count;
}

/* Parse thermal_zoneN=<millidegrees> type=<name> lines from IPC response */
static void print_thermal_from_response(const char *data)
{
	printf("  Temperatures:\n");
	int found = 0;
	const char *p = data;

	while (*p) {
		if (strncmp(p, "thermal_zone", 12) == 0) {
			const char *eq = strchr(p, '=');
			const char *nl = strchr(p, '\n');
			if (eq) {
				int tv = atoi(eq + 1);
				int deg = tv / 1000;
				int frac = (tv % 1000) / 100;

				/* Extract type= field */
				char tname[48] = "sensor";
				const char *tp = strstr(p, "type=");
				if (tp && (!nl || tp < nl)) {
					const char *tv2 = tp + 5;
					int ti = 0;
					while (*tv2 && *tv2 != ' ' && *tv2 != '\n' &&
					       ti < (int)sizeof(tname) - 1)
						tname[ti++] = *tv2++;
					tname[ti] = '\0';
				}

				printf("    %-20s : %d.%d C\n",
				       tname, deg, frac);
				found = 1;
			}
			if (!nl) break;
			p = nl + 1;
			continue;
		}
		const char *nl = strchr(p, '\n');
		if (!nl) break;
		p = nl + 1;
	}

	/* hwmon sensors: "hwmon=<label> temp=<millidegrees>" */
	p = data;
	while (*p) {
		if (strncmp(p, "hwmon=", 6) == 0) {
			const char *nl = strchr(p, '\n');

			char label[48] = "sensor";
			const char *ls = p + 6;
			int li = 0;
			while (*ls && *ls != ' ' && *ls != '\n' &&
			       li < (int)sizeof(label) - 1)
				label[li++] = *ls++;
			label[li] = '\0';

			int tv = 0;
			const char *tp = strstr(p, "temp=");
			if (tp && (!nl || tp < nl))
				tv = atoi(tp + 5);

			printf("    %-20s : %d.%d C\n",
			       label, tv / 1000, (tv % 1000) / 100);
			found = 1;

			if (!nl) break;
			p = nl + 1;
			continue;
		}
		const char *nl = strchr(p, '\n');
		if (!nl) break;
		p = nl + 1;
	}

	if (!found)
		printf("    N/A (VM or sensor not exposed)\n");
}

void diag_show_cpu(void)
{
	printf("\n---CPU resources:\n");

	/* First IPC call for CPU data */
	struct ipc_response r1 = {0};
	if (ipc_send_str(SG_CMD_DIAG_CPU, "", &r1) != 0 ||
	    r1.status != SG_OK || !r1.payload) {
		printf("  (service unavailable)\n\n");
		ipc_resp_free(&r1);
		return;
	}

	struct cpu_sample s1[MAX_CPUS + 1];
	int n1 = parse_cpu_samples(r1.payload, s1, MAX_CPUS + 1);

	int cores = 0;
	for (int i = 0; i < n1; i++) {
		if (strcmp(s1[i].name, "cpu") != 0)
			cores++;
	}
	printf("  CPU cores: %d\n", cores);

	/* Wait 1s and sample again */
	usleep(1000000);

	struct ipc_response r2 = {0};
	if (ipc_send_str(SG_CMD_DIAG_CPU, "", &r2) != 0 ||
	    r2.status != SG_OK || !r2.payload) {
		ipc_resp_free(&r1);
		ipc_resp_free(&r2);
		printf("  (second sample failed)\n\n");
		return;
	}

	struct cpu_sample s2[MAX_CPUS + 1];
	int n2 = parse_cpu_samples(r2.payload, s2, MAX_CPUS + 1);

	/* Compute deltas */
	printf("  Utilization (1s window):\n");
	for (int i = 0; i < n1 && i < n2; i++) {
		if (strcmp(s1[i].name, s2[i].name) != 0)
			continue;
		unsigned long dt = s2[i].total - s1[i].total;
		unsigned long di = s2[i].idle - s1[i].idle;
		unsigned long pct_x100 = 0;
		if (dt > 0)
			pct_x100 = (dt - di) * 10000 / dt;

		if (strcmp(s1[i].name, "cpu") == 0)
			printf("    total : %lu.%02lu%%\n",
			       pct_x100 / 100, pct_x100 % 100);
		else
			printf("    %-5s : %lu.%02lu%%\n", s1[i].name,
			       pct_x100 / 100, pct_x100 % 100);
	}

	/* Thermal from second response (has latest data) */
	print_thermal_from_response(r2.payload);
	printf("\n");

	ipc_resp_free(&r1);
	ipc_resp_free(&r2);
}

/* ── RAM ─────────────────────────────────────────────────────────────── */

static long ram_parse(const char *payload, const char *key)
{
	const char *p = payload;
	size_t klen = strlen(key);
	while (*p) {
		if (strncmp(p, key, klen) == 0 && p[klen] == '=')
			return atol(p + klen + 1);
		const char *nl = strchr(p, '\n');
		if (!nl) break;
		p = nl + 1;
	}
	return 0;
}

void diag_show_ram(void)
{
	printf("\n---RAM resources:\n");

	struct ipc_response resp = {0};
	if (ipc_send_str(SG_CMD_DIAG_RAM, "", &resp) != 0 ||
	    resp.status != SG_OK || !resp.payload) {
		printf("  (service unavailable)\n\n");
		ipc_resp_free(&resp);
		return;
	}

	long mt     = ram_parse(resp.payload, "MemTotal");
	long mf     = ram_parse(resp.payload, "MemFree");
	long ma     = ram_parse(resp.payload, "MemAvailable");
	long buf    = ram_parse(resp.payload, "Buffers");
	long cached = ram_parse(resp.payload, "Cached");
	long slab   = ram_parse(resp.payload, "Slab");
	long st     = ram_parse(resp.payload, "SwapTotal");
	long sf     = ram_parse(resp.payload, "SwapFree");
	ipc_resp_free(&resp);

	if (mt <= 0) {
		printf("  N/A\n\n");
		return;
	}

	long mu = mt - ma;
	long pct_x100 = mu * 10000 / mt;
	printf("  Total:     %ld MiB\n", mt / 1024);
	printf("  Used:      %ld MiB (%ld.%02ld%%)\n",
	       mu / 1024, pct_x100 / 100, pct_x100 % 100);
	printf("  Free:      %ld MiB\n", mf / 1024);
	printf("  Available: %ld MiB\n", ma / 1024);
	printf("  Buffers:   %ld MiB\n", buf / 1024);
	printf("  Cached:    %ld MiB\n", cached / 1024);
	printf("  Slab:      %ld MiB\n", slab / 1024);
	if (st > 0) {
		long su = st - sf;
		printf("  Swap:      %ld / %ld MiB\n", su / 1024, st / 1024);
	} else {
		printf("  Swap:      disabled\n");
	}
	printf("\n");
}

/* ── Disk ────────────────────────────────────────────────────────────── */

static unsigned long disk_parse_val(const char *payload, const char *key)
{
	const char *p = payload;
	size_t klen = strlen(key);
	while (*p) {
		if (strncmp(p, key, klen) == 0 && p[klen] == '=')
			return strtoul(p + klen + 1, NULL, 10);
		const char *nl = strchr(p, '\n');
		if (!nl) break;
		p = nl + 1;
	}
	return 0;
}

static unsigned long long disk_parse_ull(const char *payload, const char *key)
{
	const char *p = payload;
	size_t klen = strlen(key);
	while (*p) {
		if (strncmp(p, key, klen) == 0 && p[klen] == '=')
			return strtoull(p + klen + 1, NULL, 10);
		const char *nl = strchr(p, '\n');
		if (!nl) break;
		p = nl + 1;
	}
	return 0;
}

static const char *disk_parse_str(const char *payload, const char *key,
				  char *out, size_t out_sz)
{
	const char *p = payload;
	size_t klen = strlen(key);
	while (*p) {
		if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
			const char *v = p + klen + 1;
			const char *nl = strchr(v, '\n');
			size_t vlen = nl ? (size_t)(nl - v) : strlen(v);
			if (vlen >= out_sz) vlen = out_sz - 1;
			memcpy(out, v, vlen);
			out[vlen] = '\0';
			return out;
		}
		const char *nl = strchr(p, '\n');
		if (!nl) break;
		p = nl + 1;
	}
	out[0] = '\0';
	return out;
}

static void disk_print_part(const char *label, const char *payload,
			    const char *prefix)
{
	char key[64];
	snprintf(key, sizeof(key), "%s_blocks", prefix);
	unsigned long blocks = disk_parse_val(payload, key);
	if (blocks == 0) {
		printf("  %-10s  not mounted\n", label);
		return;
	}
	snprintf(key, sizeof(key), "%s_bavail", prefix);
	unsigned long bavail = disk_parse_val(payload, key);
	snprintf(key, sizeof(key), "%s_frsize", prefix);
	unsigned long frsize = disk_parse_val(payload, key);

	unsigned long long total = (unsigned long long)blocks * frsize;
	unsigned long long avail = (unsigned long long)bavail * frsize;
	unsigned long long used  = total - avail;

	unsigned long long total_mb = total / (1024 * 1024);
	unsigned long long used_mb  = used  / (1024 * 1024);
	unsigned long long avail_mb = avail / (1024 * 1024);

	unsigned long pct_x100 = total > 0
		? (unsigned long)(used * 10000 / total) : 0;

	printf("  %-10s  Size: %4llu MiB  Used: %4llu MiB  Avail: %4llu MiB  Use: %lu.%02lu%%\n",
	       label, total_mb, used_mb, avail_mb,
	       pct_x100 / 100, pct_x100 % 100);
}

void diag_show_disk(void)
{
	printf("\n---Disk resources:\n");

	struct ipc_response resp = {0};
	if (ipc_send_str(SG_CMD_DIAG_DISK, "", &resp) != 0 ||
	    resp.status != SG_OK || !resp.payload) {
		printf("  N/A (service unavailable)\n\n");
		ipc_resp_free(&resp);
		return;
	}

	/* eMMC overall */
	char emmc_dev[32];
	disk_parse_str(resp.payload, "emmc_dev", emmc_dev, sizeof(emmc_dev));
	unsigned long long emmc_bytes = disk_parse_ull(resp.payload, "emmc_bytes");

	if (emmc_bytes > 0) {
		unsigned long long emmc_mb = emmc_bytes / (1024ULL * 1024);
		unsigned long long emmc_gb = emmc_mb / 1024;
		unsigned long long emmc_gb_frac = (emmc_mb % 1024) * 10 / 1024;
		printf("  eMMC (%s): %llu.%llu GiB total\n",
		       emmc_dev, emmc_gb, emmc_gb_frac);
	} else {
		printf("  eMMC: not detected\n");
	}

	printf("\n");

	/* Per-partition usage */
	disk_print_part("sgdata", resp.payload, "sgdata");
	disk_print_part("sglogs", resp.payload, "sglogs");

	ipc_resp_free(&resp);
	printf("\n");
}

/* ── Interface ───────────────────────────────────────────────────────── */

struct iface_sample {
	char name[32];
	unsigned long long rx_bytes;
	unsigned long long tx_bytes;
};

#define MAX_IFACES 32

/* Parse iface samples from IPC response: "iface=<name> rx_bytes=N tx_bytes=N speed=M" */
static int parse_iface_samples(const char *data, struct iface_sample *out, int max)
{
	int count = 0;
	const char *p = data;

	while (*p && count < max) {
		if (strncmp(p, "iface=", 6) != 0) {
			const char *nl = strchr(p, '\n');
			if (!nl) break;
			p = nl + 1;
			continue;
		}

		struct iface_sample *s = &out[count];
		memset(s, 0, sizeof(*s));

		/* Parse name */
		const char *ns = p + 6;
		const char *sp = ns;
		while (*sp && *sp != ' ' && *sp != '\n') sp++;
		size_t nlen = (size_t)(sp - ns);
		if (nlen >= sizeof(s->name))
			nlen = sizeof(s->name) - 1;
		memcpy(s->name, ns, nlen);
		s->name[nlen] = '\0';

		/* Parse rx_bytes */
		const char *rxp = strstr(p, "rx_bytes=");
		if (rxp) s->rx_bytes = strtoull(rxp + 9, NULL, 10);

		/* Parse tx_bytes */
		const char *txp = strstr(p, "tx_bytes=");
		if (txp) s->tx_bytes = strtoull(txp + 9, NULL, 10);

		count++;

		const char *nl = strchr(p, '\n');
		if (!nl) break;
		p = nl + 1;
	}
	return count;
}

/* Extract a field value from within a single iface line */
static const char *iface_field(const char *line, const char *line_end,
			       const char *key, char *out, size_t out_sz)
{
	size_t klen = strlen(key);
	const char *p = line;
	while (p < line_end) {
		if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
			const char *v = p + klen + 1;
			int i = 0;
			while (v < line_end && *v != ' ' && *v != '\n' &&
			       i < (int)out_sz - 1)
				out[i++] = *v++;
			out[i] = '\0';
			return out;
		}
		p++;
	}
	out[0] = '\0';
	return out;
}

void diag_show_interface(void)
{
	printf("\n---Interface resources:\n");

	/* First sample */
	struct ipc_response r1 = {0};
	if (ipc_send_str(SG_CMD_DIAG_IFACE_STATS, "", &r1) != 0 ||
	    r1.status != SG_OK || !r1.payload) {
		printf("  (service unavailable)\n\n");
		ipc_resp_free(&r1);
		return;
	}

	struct iface_sample s1[MAX_IFACES];
	int n1 = parse_iface_samples(r1.payload, s1, MAX_IFACES);

	/* Wait 1s */
	usleep(1000000);

	/* Second sample */
	struct ipc_response r2 = {0};
	if (ipc_send_str(SG_CMD_DIAG_IFACE_STATS, "", &r2) != 0 ||
	    r2.status != SG_OK || !r2.payload) {
		ipc_resp_free(&r1);
		ipc_resp_free(&r2);
		printf("  (second sample failed)\n\n");
		return;
	}

	struct iface_sample s2[MAX_IFACES];
	int n2 = parse_iface_samples(r2.payload, s2, MAX_IFACES);

	/* Print per-interface detail from latest response */
	const char *p = r2.payload;
	int iidx = 0;
	while (*p) {
		if (strncmp(p, "iface=", 6) != 0) {
			const char *nl = strchr(p, '\n');
			if (!nl) break;
			p = nl + 1;
			continue;
		}

		const char *nl = strchr(p, '\n');
		const char *line_end = nl ? nl : p + strlen(p);
		char val[64];

		/* Interface name */
		iface_field(p, line_end, "iface", val, sizeof(val));
		printf("\n  %s:\n", val);

		/* State + MAC + Speed + MTU */
		char state[16], mac[20], speed[16], mtu[8];
		iface_field(p, line_end, "state", state, sizeof(state));
		iface_field(p, line_end, "mac", mac, sizeof(mac));
		iface_field(p, line_end, "speed", speed, sizeof(speed));
		iface_field(p, line_end, "mtu", mtu, sizeof(mtu));

		printf("    State: %-8s  MAC: %-18s  MTU: %s\n",
		       state[0] ? state : "unknown",
		       mac[0] ? mac : "N/A",
		       mtu[0] ? mtu : "?");
		if (speed[0] && strcmp(speed, "-1") != 0)
			printf("    Speed: %s Mbps\n", speed);
		else
			printf("    Speed: no link\n");

		/* Counters */
		char rx_b[20], tx_b[20], rx_p[20], tx_p[20];
		char rx_e[20], tx_e[20], rx_d[20], tx_d[20];
		iface_field(p, line_end, "rx_bytes", rx_b, sizeof(rx_b));
		iface_field(p, line_end, "tx_bytes", tx_b, sizeof(tx_b));
		iface_field(p, line_end, "rx_pkts", rx_p, sizeof(rx_p));
		iface_field(p, line_end, "tx_pkts", tx_p, sizeof(tx_p));
		iface_field(p, line_end, "rx_errs", rx_e, sizeof(rx_e));
		iface_field(p, line_end, "tx_errs", tx_e, sizeof(tx_e));
		iface_field(p, line_end, "rx_drop", rx_d, sizeof(rx_d));
		iface_field(p, line_end, "tx_drop", tx_d, sizeof(tx_d));

		printf("    RX: %s bytes, %s pkts, %s errs, %s drops\n",
		       rx_b[0] ? rx_b : "0", rx_p[0] ? rx_p : "0",
		       rx_e[0] ? rx_e : "0", rx_d[0] ? rx_d : "0");
		printf("    TX: %s bytes, %s pkts, %s errs, %s drops\n",
		       tx_b[0] ? tx_b : "0", tx_p[0] ? tx_p : "0",
		       tx_e[0] ? tx_e : "0", tx_d[0] ? tx_d : "0");

		/* Throughput (1s delta) */
		if (iidx < n1 && iidx < n2 &&
		    strcmp(s1[iidx].name, s2[iidx].name) == 0) {
			long long drx = (long long)(s2[iidx].rx_bytes - s1[iidx].rx_bytes);
			long long dtx = (long long)(s2[iidx].tx_bytes - s1[iidx].tx_bytes);
			if (drx < 0) drx = 0;
			if (dtx < 0) dtx = 0;
			long long rx_kbs_x100 = drx * 100 / 1024;
			long long tx_kbs_x100 = dtx * 100 / 1024;
			printf("    Throughput: rx=%lld.%02lld KB/s  tx=%lld.%02lld KB/s\n",
			       rx_kbs_x100 / 100, rx_kbs_x100 % 100,
			       tx_kbs_x100 / 100, tx_kbs_x100 % 100);
		}

		iidx++;
		if (!nl) break;
		p = nl + 1;
	}

	printf("\n");
	ipc_resp_free(&r1);
	ipc_resp_free(&r2);
}

/* ── Top (live process monitor) ──────────────────────────────────────── */

struct proc_info {
	int    pid;
	char   comm[64];
	char   state;
	unsigned long utime;
	unsigned long stime;
	unsigned long vsize;
	long   rss;
	unsigned long cpu_bp;
	unsigned long ram_bp;
};

#define MAX_PROCS 1024

static int cmp_proc_cpu_bp(const void *a, const void *b)
{
	const struct proc_info *pa = a;
	const struct proc_info *pb = b;
	if (pb->cpu_bp > pa->cpu_bp) return 1;
	if (pb->cpu_bp < pa->cpu_bp) return -1;
	unsigned long ca = pa->utime + pa->stime;
	unsigned long cb = pb->utime + pb->stime;
	if (cb > ca) return 1;
	if (cb < ca) return -1;
	return 0;
}

/*
 * Parse proctop IPC response. Format:
 *   cpu <user> <nice> ...          (aggregate cpu line)
 *   mem_total_kb=N
 *   mem_avail_kb=N
 *   uptime=<seconds> <idle>
 *   loadavg=<1> <5> <15> ...
 *   proc=<pid> <comm> <state> <utime> <stime> <vsize> <rss>
 */
struct proctop_data {
	struct cpu_sample cpu;
	long mem_total_kb;
	long mem_avail_kb;
	char uptime[64];
	char loadavg[64];
	struct proc_info procs[MAX_PROCS];
	int nprocs;
};

static void parse_proctop(const char *data, struct proctop_data *out)
{
	memset(out, 0, sizeof(*out));
	const char *p = data;

	while (*p) {
		const char *nl = strchr(p, '\n');
		size_t llen = nl ? (size_t)(nl - p) : strlen(p);

		if (llen >= 4 && strncmp(p, "cpu ", 4) == 0) {
			/* Parse CPU aggregate */
			const char *cp = p + 4;
			for (int i = 0; i < CPU_FIELDS && *cp; i++) {
				while (*cp == ' ') cp++;
				out->cpu.vals[i] = strtoul(cp, NULL, 10);
				while (*cp && *cp != ' ' && *cp != '\n') cp++;
			}
			out->cpu.total = 0;
			for (int i = 0; i < CPU_FIELDS; i++)
				out->cpu.total += out->cpu.vals[i];
			out->cpu.idle = out->cpu.vals[3] + out->cpu.vals[4];
			snprintf(out->cpu.name, sizeof(out->cpu.name), "cpu");
		} else if (strncmp(p, "mem_total_kb=", 13) == 0) {
			out->mem_total_kb = atol(p + 13);
		} else if (strncmp(p, "mem_avail_kb=", 13) == 0) {
			out->mem_avail_kb = atol(p + 13);
		} else if (strncmp(p, "uptime=", 7) == 0) {
			size_t vlen = llen - 7;
			if (vlen >= sizeof(out->uptime))
				vlen = sizeof(out->uptime) - 1;
			memcpy(out->uptime, p + 7, vlen);
			out->uptime[vlen] = '\0';
		} else if (strncmp(p, "loadavg=", 8) == 0) {
			size_t vlen = llen - 8;
			if (vlen >= sizeof(out->loadavg))
				vlen = sizeof(out->loadavg) - 1;
			memcpy(out->loadavg, p + 8, vlen);
			out->loadavg[vlen] = '\0';
		} else if (strncmp(p, "proc=", 5) == 0 &&
			   out->nprocs < MAX_PROCS) {
			struct proc_info *pi = &out->procs[out->nprocs];
			memset(pi, 0, sizeof(*pi));

			const char *pp = p + 5;
			pi->pid = atoi(pp);

			/* Skip pid */
			while (*pp && *pp != ' ' && *pp != '\n') pp++;
			while (*pp == ' ') pp++;

			/* Comm (until next space) */
			int ci = 0;
			while (*pp && *pp != ' ' && *pp != '\n' &&
			       ci < (int)sizeof(pi->comm) - 1)
				pi->comm[ci++] = *pp++;
			pi->comm[ci] = '\0';
			while (*pp == ' ') pp++;

			/* State */
			pi->state = *pp ? *pp : '?';
			while (*pp && *pp != ' ' && *pp != '\n') pp++;
			while (*pp == ' ') pp++;

			/* utime, stime, vsize, rss */
			pi->utime = strtoul(pp, NULL, 10);
			while (*pp && *pp != ' ' && *pp != '\n') pp++;
			while (*pp == ' ') pp++;

			pi->stime = strtoul(pp, NULL, 10);
			while (*pp && *pp != ' ' && *pp != '\n') pp++;
			while (*pp == ' ') pp++;

			pi->vsize = strtoul(pp, NULL, 10);
			while (*pp && *pp != ' ' && *pp != '\n') pp++;
			while (*pp == ' ') pp++;

			pi->rss = strtol(pp, NULL, 10);

			out->nprocs++;
		}

		if (!nl) break;
		p = nl + 1;
	}
}

/*
 * Poll-based sleep that checks for 'q' or Ctrl+C every 100ms.
 * Returns 1 if user requested quit, 0 if sleep completed.
 */
static int interruptible_sleep_ms(int ms)
{
	int remaining = ms;
	while (remaining > 0) {
		if (ipc_check_quit_or_ctrl_c())
			return 1;
		int chunk = remaining < 100 ? remaining : 100;
		usleep((unsigned)(chunk * 1000));
		remaining -= chunk;
	}
	return ipc_check_quit_or_ctrl_c();
}

void diag_show_top(int interval, int max_procs)
{
	if (interval < 1) interval = 1;
	if (interval > 3600) interval = 3600;	/* upper-bound so interval*1000 cannot overflow int */
	if (max_procs < 1) max_procs = 20;

	/* RSS is now reported in kB directly from VmRSS (no page conversion) */

	/* Enter raw tty mode for q/Ctrl+C detection */
	ipc_install_interrupt_handler();

	/* First snapshot */
	struct ipc_response r1 = {0};
	if (ipc_send_str(SG_CMD_DIAG_PROCTOP, "", &r1) != 0 ||
	    r1.status != SG_OK || !r1.payload) {
		ipc_resp_free(&r1);
		printf("  (service unavailable)\n");
		ipc_restore_interrupt_handler();
		return;
	}

	struct proctop_data prev;
	parse_proctop(r1.payload, &prev);
	ipc_resp_free(&r1);

	for (;;) {
		struct ipc_response r2 = {0};
		if (ipc_send_str(SG_CMD_DIAG_PROCTOP, "", &r2) != 0 ||
		    r2.status != SG_OK || !r2.payload) {
			ipc_resp_free(&r2);
			if (interruptible_sleep_ms(interval * 1000))
				break;
			continue;
		}

		struct proctop_data cur;
		parse_proctop(r2.payload, &cur);
		ipc_resp_free(&r2);

		/* System-wide CPU% */
		unsigned long sys_cpu_bp = 0;
		unsigned long delta_total = 0;
		{
			unsigned long dt = cur.cpu.total - prev.cpu.total;
			unsigned long di = cur.cpu.idle - prev.cpu.idle;
			if (dt > 0)
				sys_cpu_bp = (dt - di) * 10000 / dt;
			delta_total = dt;
		}

		/* Memory */
		long mem_used_kb = cur.mem_total_kb - cur.mem_avail_kb;
		unsigned long sys_mem_bp = 0;
		if (cur.mem_total_kb > 0)
			sys_mem_bp = (unsigned long)(mem_used_kb * 10000 / cur.mem_total_kb);

		/* Per-process CPU% by matching PIDs */
		for (int i = 0; i < cur.nprocs; i++) {
			cur.procs[i].cpu_bp = 0;
			cur.procs[i].ram_bp = 0;

			if (delta_total > 0) {
				for (int j = 0; j < prev.nprocs; j++) {
					if (prev.procs[j].pid == cur.procs[i].pid) {
						unsigned long dt_proc =
							(cur.procs[i].utime + cur.procs[i].stime) -
							(prev.procs[j].utime + prev.procs[j].stime);
						cur.procs[i].cpu_bp = dt_proc * 10000 / delta_total;
						break;
					}
				}
			}

			if (cur.mem_total_kb > 0 && cur.procs[i].rss > 0)
				cur.procs[i].ram_bp = (unsigned long)(cur.procs[i].rss * 10000 / cur.mem_total_kb);
		}

		/* Sort by CPU% descending */
		qsort(cur.procs, (size_t)cur.nprocs, sizeof(cur.procs[0]),
		      cmp_proc_cpu_bp);

		/* Clear screen and print header */
		printf("\033[2J\033[H");

		/* Uptime */
		if (cur.uptime[0]) {
			unsigned long sec = strtoul(cur.uptime, NULL, 10);
			unsigned long days = sec / 86400;
			unsigned long hours = (sec % 86400) / 3600;
			unsigned long mins = (sec % 3600) / 60;
			printf("  Uptime: %lud %luh %lum", days, hours, mins);
		}

		/* Load average */
		if (cur.loadavg[0])
			printf("  Load: %s", cur.loadavg);
		printf("\n");

		/* Tasks / CPU / Memory summary */
		printf("  Tasks: %d", cur.nprocs);
		printf("    CPU: %lu.%02lu%%",
		       sys_cpu_bp / 100, sys_cpu_bp % 100);
		printf("    Mem: %lu.%02lu%% (%ld/%ld MiB)\n",
		       sys_mem_bp / 100, sys_mem_bp % 100,
		       mem_used_kb / 1024, cur.mem_total_kb / 1024);
		printf("\n");

		/* Column header */
		printf("  %-7s %-20s %5s %7s %7s %10s\n",
		       "PID", "NAME", "STATE", "CPU%", "MEM%", "RSS-KiB");
		printf("  %-7s %-20s %5s %7s %7s %10s\n",
		       "-------", "--------------------", "-----",
		       "-------", "-------", "----------");

		int show = cur.nprocs < max_procs ? cur.nprocs : max_procs;
		for (int i = 0; i < show; i++) {
			struct proc_info *pi = &cur.procs[i];
			long rss_kib = pi->rss;
			printf("  %-7d %-20.20s   %c   %3lu.%02lu  %3lu.%02lu  %10ld\n",
			       pi->pid, pi->comm, pi->state,
			       pi->cpu_bp / 100, pi->cpu_bp % 100,
			       pi->ram_bp / 100, pi->ram_bp % 100,
			       rss_kib);
		}
		printf("\n  Press 'q' to quit. Refreshing every %ds.\n",
		       interval);

		/* Rotate */
		prev = cur;

		if (interruptible_sleep_ms(interval * 1000))
			break;
	}

	ipc_restore_interrupt_handler();
}

/* ── Dispatcher ──────────────────────────────────────────────────────── */

void diag_show_resources(const char *which)
{
	if (!which || !*which || strcmp(which, "all") == 0) {
		diag_show_cpu();
		diag_show_ram();
		diag_show_disk();
		diag_show_interface();
	} else if (strcmp(which, "cpu") == 0) {
		diag_show_cpu();
	} else if (strcmp(which, "ram") == 0) {
		diag_show_ram();
	} else if (strcmp(which, "disk") == 0) {
		diag_show_disk();
	} else if (strcmp(which, "interface") == 0) {
		diag_show_interface();
	} else {
		printf("  Usage: execute diagnose resources [cpu|ram|disk|interface|all]\n");
	}
}
