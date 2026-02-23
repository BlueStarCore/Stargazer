/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose_sys.c — Pure C system diagnostics for Stargazer CLI
 *
 * Zero-fork resource monitoring. Reads /proc and /sys directly instead
 * of forking shell commands. Works on BusyBox/ash (no bash needed).
 *
 * Replaces the shell-based resource functions from cli_debug.c:
 *   execute diagnose resources [cpu|ram|disk|interface|all]
 *   execute diagnose top
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "cli_diagnose_sys.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
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

static int read_cpu_samples(struct cpu_sample *out, int max)
{
	FILE *fp = fopen("/proc/stat", "r");
	if (!fp)
		return 0;

	int count = 0;
	char line[256];
	while (fgets(line, sizeof(line), fp) && count < max) {
		if (strncmp(line, "cpu", 3) != 0)
			continue;
		/* Match "cpu" (aggregate) and "cpuN" lines */
		if (line[3] != ' ' && !isdigit((unsigned char)line[3]))
			continue;

		struct cpu_sample *s = &out[count];
		memset(s, 0, sizeof(*s));

		/* Parse name */
		const char *p = line;
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
	}
	fclose(fp);
	return count;
}

void diag_show_cpu(void)
{
	printf("\n---CPU resources:\n");

	/* Count cores (cpuN lines, skip aggregate "cpu") */
	struct cpu_sample s1[MAX_CPUS + 1];
	int n1 = read_cpu_samples(s1, MAX_CPUS + 1);

	int cores = 0;
	for (int i = 0; i < n1; i++) {
		if (strcmp(s1[i].name, "cpu") != 0)
			cores++;
	}
	printf("  CPU cores: %d\n", cores);

	/* Wait 1s and sample again */
	usleep(1000000);

	struct cpu_sample s2[MAX_CPUS + 1];
	int n2 = read_cpu_samples(s2, MAX_CPUS + 1);

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

	/* Temperature */
	printf("  Temperatures:\n");
	int found_temp = 0;
	char path[128];
	for (int z = 0; z < 16; z++) {
		snprintf(path, sizeof(path),
			 "/sys/class/thermal/thermal_zone%d/temp", z);
		FILE *fp = fopen(path, "r");
		if (!fp)
			continue;
		char tbuf[32];
		if (fgets(tbuf, sizeof(tbuf), fp)) {
			int tv = atoi(tbuf);
			printf("    thermal_zone%d : %d°C\n", z, tv / 1000);
			found_temp = 1;
		}
		fclose(fp);
	}
	if (!found_temp)
		printf("    N/A (VM or sensor not exposed)\n");
	printf("\n");
}

/* ── RAM ─────────────────────────────────────────────────────────────── */

void diag_show_ram(void)
{
	printf("\n---RAM resources:\n");

	long mt = 0, ma = 0;
	FILE *fp = fopen("/proc/meminfo", "r");
	if (fp) {
		char line[128];
		while (fgets(line, sizeof(line), fp)) {
			if (strncmp(line, "MemTotal:", 9) == 0)
				mt = atol(line + 9);
			else if (strncmp(line, "MemAvailable:", 13) == 0)
				ma = atol(line + 13);
		}
		fclose(fp);
	}

	if (mt <= 0) {
		printf("  N/A\n\n");
		return;
	}

	long mu = mt - ma;
	/* Fixed-point: pct_x100 = mu * 10000 / mt */
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

	struct statvfs sv;
	if (statvfs("/", &sv) != 0) {
		printf("  N/A (statvfs failed)\n\n");
		return;
	}

	unsigned long long total = (unsigned long long)sv.f_blocks * sv.f_frsize;
	unsigned long long avail = (unsigned long long)sv.f_bavail * sv.f_frsize;
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

static int read_iface_samples(struct iface_sample *out, int max)
{
	FILE *fp = fopen("/proc/net/dev", "r");
	if (!fp)
		return 0;

	char line[512];
	int count = 0;

	/* Skip header lines */
	if (!fgets(line, sizeof(line), fp)) { fclose(fp); return 0; }
	if (!fgets(line, sizeof(line), fp)) { fclose(fp); return 0; }

	while (fgets(line, sizeof(line), fp) && count < max) {
		/* Format: "  iface: rx_bytes rx_packets ... tx_bytes tx_packets ..." */
		const char *p = line;
		while (*p == ' ') p++;

		const char *colon = strchr(p, ':');
		if (!colon)
			continue;

		struct iface_sample *s = &out[count];
		size_t nlen = (size_t)(colon - p);
		if (nlen >= sizeof(s->name))
			nlen = sizeof(s->name) - 1;
		memcpy(s->name, p, nlen);
		s->name[nlen] = '\0';

		/* Skip loopback */
		if (strcmp(s->name, "lo") == 0)
			continue;

		/* Parse rx_bytes (field 1 after colon) */
		p = colon + 1;
		while (*p == ' ') p++;
		s->rx_bytes = strtoull(p, NULL, 10);

		/* Skip 8 fields to reach tx_bytes (field 9) */
		for (int f = 0; f < 8; f++) {
			while (*p && *p != ' ') p++;
			while (*p == ' ') p++;
		}
		s->tx_bytes = strtoull(p, NULL, 10);

		count++;
	}
	fclose(fp);
	return count;
}

void diag_show_interface(void)
{
	printf("\n---Interface resources:\n");

	/* First sample */
	struct iface_sample s1[MAX_IFACES];
	int n1 = read_iface_samples(s1, MAX_IFACES);

	/* Wait 1s */
	usleep(1000000);

	/* Second sample */
	struct iface_sample s2[MAX_IFACES];
	int n2 = read_iface_samples(s2, MAX_IFACES);

	printf("  Throughput (1s window):\n");
	for (int i = 0; i < n1 && i < n2; i++) {
		if (strcmp(s1[i].name, s2[i].name) != 0)
			continue;
		long long drx = (long long)(s2[i].rx_bytes - s1[i].rx_bytes);
		long long dtx = (long long)(s2[i].tx_bytes - s1[i].tx_bytes);
		if (drx < 0) drx = 0;
		if (dtx < 0) dtx = 0;

		/* Fixed-point KB/s with 2 decimal places */
		long long rx_kbs_x100 = drx * 100 / 1024;
		long long tx_kbs_x100 = dtx * 100 / 1024;

		printf("    %-10s rx=%5lld.%02lld KB/s  tx=%5lld.%02lld KB/s\n",
		       s1[i].name,
		       rx_kbs_x100 / 100, rx_kbs_x100 % 100,
		       tx_kbs_x100 / 100, tx_kbs_x100 % 100);
	}

	/* Link speed via sysfs */
	printf("  Link speed (best effort):\n");
	DIR *dir = opendir("/sys/class/net");
	if (dir) {
		struct dirent *ent;
		while ((ent = readdir(dir)) != NULL) {
			if (ent->d_name[0] == '.')
				continue;
			if (strcmp(ent->d_name, "lo") == 0)
				continue;

			char path[512], spd[32];
			snprintf(path, sizeof(path),
				 "/sys/class/net/%s/speed", ent->d_name);
			FILE *fp = fopen(path, "r");
			if (fp) {
				if (fgets(spd, sizeof(spd), fp)) {
					size_t slen = strlen(spd);
					if (slen > 0 && spd[slen - 1] == '\n')
						spd[--slen] = '\0';
				} else {
					snprintf(spd, sizeof(spd), "unknown");
				}
				fclose(fp);
			} else {
				snprintf(spd, sizeof(spd), "unknown");
			}
			printf("    %s: speed=%sMbps\n", ent->d_name, spd);
		}
		closedir(dir);
	}
	printf("\n");
}

/* ── Top (process snapshot) ──────────────────────────────────────────── */

struct proc_info {
	int    pid;
	char   comm[64];
	char   state;
	unsigned long utime;
	unsigned long stime;
	unsigned long vsize;
	long   rss;
};

#define MAX_PROCS 1024

static int cmp_proc_cpu(const void *a, const void *b)
{
	const struct proc_info *pa = a;
	const struct proc_info *pb = b;
	unsigned long ca = pa->utime + pa->stime;
	unsigned long cb = pb->utime + pb->stime;
	if (cb > ca) return 1;
	if (cb < ca) return -1;
	return 0;
}

void diag_show_top(void)
{
	printf("\n  Process snapshot:\n");

	/* Uptime */
	FILE *fp = fopen("/proc/uptime", "r");
	if (fp) {
		char buf[64];
		if (fgets(buf, sizeof(buf), fp)) {
			/* Parse integer and fractional parts to avoid float */
			unsigned long sec = strtoul(buf, NULL, 10);
			unsigned long days = sec / 86400;
			unsigned long hours = (sec % 86400) / 3600;
			unsigned long mins = (sec % 3600) / 60;
			printf("  Uptime: %lud %luh %lum\n", days, hours, mins);
		}
		fclose(fp);
	}

	/* Load average */
	fp = fopen("/proc/loadavg", "r");
	if (fp) {
		char buf[64];
		if (fgets(buf, sizeof(buf), fp))
			printf("  Load avg: %.48s\n", buf);
		fclose(fp);
	}

	/* Memory summary */
	long mt = 0, ma = 0;
	fp = fopen("/proc/meminfo", "r");
	if (fp) {
		char line[128];
		while (fgets(line, sizeof(line), fp)) {
			if (strncmp(line, "MemTotal:", 9) == 0)
				mt = atol(line + 9);
			else if (strncmp(line, "MemAvailable:", 13) == 0)
				ma = atol(line + 13);
		}
		fclose(fp);
	}
	if (mt > 0)
		printf("  Memory: %ld MiB used / %ld MiB total\n",
		       (mt - ma) / 1024, mt / 1024);

	/* Scan /proc/<pid>/stat for each process */
	struct proc_info procs[MAX_PROCS];
	int nprocs = 0;

	DIR *dir = opendir("/proc");
	if (!dir) {
		printf("  Cannot open /proc\n\n");
		return;
	}

	struct dirent *ent;
	while ((ent = readdir(dir)) != NULL && nprocs < MAX_PROCS) {
		/* Only numeric directories */
		if (!isdigit((unsigned char)ent->d_name[0]))
			continue;

		char path[280];
		snprintf(path, sizeof(path), "/proc/%s/stat", ent->d_name);
		fp = fopen(path, "r");
		if (!fp)
			continue;

		char buf[512];
		if (!fgets(buf, sizeof(buf), fp)) {
			fclose(fp);
			continue;
		}
		fclose(fp);

		struct proc_info *pi = &procs[nprocs];
		memset(pi, 0, sizeof(*pi));

		/* Parse: pid (comm) state ... utime stime ... vsize rss
		 * Fields:  1   2     3  ...  14    15   ...   23    24  */
		pi->pid = atoi(buf);

		/* Find comm between '(' and ')' */
		const char *lp = strchr(buf, '(');
		const char *rp = strrchr(buf, ')');
		if (!lp || !rp || rp <= lp)
			continue;

		size_t clen = (size_t)(rp - lp - 1);
		if (clen >= sizeof(pi->comm))
			clen = sizeof(pi->comm) - 1;
		memcpy(pi->comm, lp + 1, clen);
		pi->comm[clen] = '\0';

		/* Fields after ')': skip to field 3 (state) */
		const char *p = rp + 1;
		while (*p == ' ') p++;
		pi->state = *p ? *p : '?';

		/* Skip fields 4..13 to reach field 14 (utime) */
		for (int f = 4; f <= 13 && *p; f++) {
			while (*p && *p != ' ') p++;
			while (*p == ' ') p++;
		}
		/* Now at field 14 (utime) */
		pi->utime = strtoul(p, NULL, 10);
		while (*p && *p != ' ') p++;
		while (*p == ' ') p++;
		/* Field 15 (stime) */
		pi->stime = strtoul(p, NULL, 10);

		/* Skip fields 16..22 to reach field 23 (vsize) */
		for (int f = 16; f <= 22 && *p; f++) {
			while (*p && *p != ' ') p++;
			while (*p == ' ') p++;
		}
		/* Field 23 (vsize) */
		pi->vsize = strtoul(p, NULL, 10);
		while (*p && *p != ' ') p++;
		while (*p == ' ') p++;
		/* Field 24 (rss in pages) */
		pi->rss = strtol(p, NULL, 10);

		nprocs++;
	}
	closedir(dir);

	/* Sort by CPU time descending */
	qsort(procs, (size_t)nprocs, sizeof(procs[0]), cmp_proc_cpu);

	/* Display top 20 */
	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) page_size = 4096;

	printf("\n  %-7s %-20s %5s %10s %10s\n",
	       "PID", "NAME", "STATE", "CPU-TICKS", "RSS-KiB");
	printf("  %-7s %-20s %5s %10s %10s\n",
	       "-------", "--------------------", "-----",
	       "----------", "----------");

	int show = nprocs < 20 ? nprocs : 20;
	for (int i = 0; i < show; i++) {
		struct proc_info *pi = &procs[i];
		long rss_kib = pi->rss * page_size / 1024;
		printf("  %-7d %-20.20s   %c   %10lu %10ld\n",
		       pi->pid, pi->comm, pi->state,
		       pi->utime + pi->stime, rss_kib);
	}
	printf("\n");
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
