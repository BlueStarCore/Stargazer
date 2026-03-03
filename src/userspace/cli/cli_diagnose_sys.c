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

/* Parse thermal_zoneN=<millidegrees> lines from IPC response */
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
				int zone = atoi(p + 12);
				int tv = atoi(eq + 1);
				printf("    thermal_zone%d : %d\u00b0C\n",
				       zone, tv / 1000);
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
		printf("  (mgmtd unavailable)\n\n");
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

void diag_show_ram(void)
{
	printf("\n---RAM resources:\n");

	struct ipc_response resp = {0};
	if (ipc_send_str(SG_CMD_DIAG_RAM, "", &resp) != 0 ||
	    resp.status != SG_OK || !resp.payload) {
		printf("  (mgmtd unavailable)\n\n");
		ipc_resp_free(&resp);
		return;
	}

	long mt = 0, ma = 0;
	const char *p = resp.payload;
	while (*p) {
		if (strncmp(p, "MemTotal=", 9) == 0)
			mt = atol(p + 9);
		else if (strncmp(p, "MemAvailable=", 13) == 0)
			ma = atol(p + 13);
		const char *nl = strchr(p, '\n');
		if (!nl) break;
		p = nl + 1;
	}
	ipc_resp_free(&resp);

	if (mt <= 0) {
		printf("  N/A\n\n");
		return;
	}

	long mu = mt - ma;
	long pct_x100 = mt > 0 ? mu * 10000 / mt : 0;
	printf("  Used: %ld.%02ld%% (%ld MiB / %ld MiB), Available: %ld MiB\n",
	       pct_x100 / 100, pct_x100 % 100,
	       mu / 1024, mt / 1024, ma / 1024);
	printf("\n");
}

/* ── Disk ────────────────────────────────────────────────────────────── */

void diag_show_disk(void)
{
	printf("\n---Disk resources:\n");

	struct ipc_response resp = {0};
	if (ipc_send_str(SG_CMD_DIAG_DISK, "", &resp) != 0 ||
	    resp.status != SG_OK || !resp.payload) {
		printf("  N/A (mgmtd unavailable)\n\n");
		ipc_resp_free(&resp);
		return;
	}

	unsigned long blocks = 0, bfree = 0, bavail = 0, frsize = 0;
	const char *p = resp.payload;
	while (*p) {
		if (strncmp(p, "blocks=", 7) == 0)
			blocks = strtoul(p + 7, NULL, 10);
		else if (strncmp(p, "bfree=", 6) == 0)
			bfree = strtoul(p + 6, NULL, 10);
		else if (strncmp(p, "bavail=", 7) == 0)
			bavail = strtoul(p + 7, NULL, 10);
		else if (strncmp(p, "frsize=", 7) == 0)
			frsize = strtoul(p + 7, NULL, 10);
		const char *nl = strchr(p, '\n');
		if (!nl) break;
		p = nl + 1;
	}
	ipc_resp_free(&resp);

	(void)bfree; /* bfree is for root; bavail is for unprivileged */

	unsigned long long total = (unsigned long long)blocks * frsize;
	unsigned long long avail = (unsigned long long)bavail * frsize;
	unsigned long long used  = total - avail;

	unsigned long long total_mb = total / (1024 * 1024);
	unsigned long long used_mb  = used  / (1024 * 1024);
	unsigned long long avail_mb = avail / (1024 * 1024);

	unsigned long pct_x100 = total > 0
		? (unsigned long)(used * 10000 / total) : 0;

	printf("  Filesystem  Size: %llu MiB  Used: %llu MiB  Avail: %llu MiB  Use%%: %lu.%02lu%%\n",
	       total_mb, used_mb, avail_mb,
	       pct_x100 / 100, pct_x100 % 100);
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

void diag_show_interface(void)
{
	printf("\n---Interface resources:\n");

	/* First sample */
	struct ipc_response r1 = {0};
	if (ipc_send_str(SG_CMD_DIAG_IFACE_STATS, "", &r1) != 0 ||
	    r1.status != SG_OK || !r1.payload) {
		printf("  (mgmtd unavailable)\n\n");
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

	printf("  Throughput (1s window):\n");
	for (int i = 0; i < n1 && i < n2; i++) {
		if (strcmp(s1[i].name, s2[i].name) != 0)
			continue;
		long long drx = (long long)(s2[i].rx_bytes - s1[i].rx_bytes);
		long long dtx = (long long)(s2[i].tx_bytes - s1[i].tx_bytes);
		if (drx < 0) drx = 0;
		if (dtx < 0) dtx = 0;

		long long rx_kbs_x100 = drx * 100 / 1024;
		long long tx_kbs_x100 = dtx * 100 / 1024;

		printf("    %-10s rx=%5lld.%02lld KB/s  tx=%5lld.%02lld KB/s\n",
		       s1[i].name,
		       rx_kbs_x100 / 100, rx_kbs_x100 % 100,
		       tx_kbs_x100 / 100, tx_kbs_x100 % 100);
	}

	/* Link speed from latest response */
	printf("  Link speed (best effort):\n");
	{
		const char *p = r2.payload;
		while (*p) {
			if (strncmp(p, "iface=", 6) == 0) {
				const char *ns = p + 6;
				const char *sp = ns;
				while (*sp && *sp != ' ' && *sp != '\n') sp++;
				char iname[32];
				size_t nlen = (size_t)(sp - ns);
				if (nlen >= sizeof(iname))
					nlen = sizeof(iname) - 1;
				memcpy(iname, ns, nlen);
				iname[nlen] = '\0';

				const char *spdp = strstr(p, "speed=");
				const char *nl = strchr(p, '\n');
				/* Only use speed= if it's on same line */
				if (spdp && (!nl || spdp < nl)) {
					char spd[32];
					const char *sv = spdp + 6;
					int si = 0;
					while (*sv && *sv != ' ' && *sv != '\n' &&
					       si < (int)sizeof(spd) - 1)
						spd[si++] = *sv++;
					spd[si] = '\0';
					printf("    %s: speed=%sMbps\n", iname, spd);
				} else {
					printf("    %s: speed=unknownMbps\n", iname);
				}
			}
			const char *nl = strchr(p, '\n');
			if (!nl) break;
			p = nl + 1;
		}
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
	if (max_procs < 1) max_procs = 20;

	long page_size_kb = sysconf(_SC_PAGESIZE);
	if (page_size_kb <= 0) page_size_kb = 4096;
	page_size_kb /= 1024;

	/* Enter raw tty mode for q/Ctrl+C detection */
	ipc_install_interrupt_handler();

	/* First snapshot */
	struct ipc_response r1 = {0};
	if (ipc_send_str(SG_CMD_DIAG_PROCTOP, "", &r1) != 0 ||
	    r1.status != SG_OK || !r1.payload) {
		ipc_resp_free(&r1);
		printf("  (mgmtd unavailable)\n");
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
				cur.procs[i].ram_bp = (unsigned long)(cur.procs[i].rss * page_size_kb * 10000 / cur.mem_total_kb);
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
			long rss_kib = pi->rss * page_size_kb;
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
