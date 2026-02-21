/* SPDX-License-Identifier: MIT */
/*
 * cli_debug.c — Debug state manager for Stargazer CLI
 *
 * C replacement for the debug subtree of cmd_execute.
 * Manages /tmp/stargazer-debug.conf key=value state file.
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_debug.h"
#include "sg_validate.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DEBUG_STATE_FILE "/tmp/stargazer-debug.conf"
#define MAX_STATE_KEYS   32
#define MAX_KEY_LEN      64
#define MAX_VAL_LEN      64

/* ── Debug state I/O ──────────────────────────────────────────────────── */

const char *dbg_get(const char *key, const char *defval)
{
	static char result[MAX_VAL_LEN];

	FILE *fp = fopen(DEBUG_STATE_FILE, "r");
	if (!fp) {
		snprintf(result, sizeof(result), "%s", defval);
		return result;
	}

	char prefix[MAX_KEY_LEN + 2];
	snprintf(prefix, sizeof(prefix), "%s=", key);
	size_t plen = strlen(prefix);

	char line[128];
	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, prefix, plen) == 0) {
			size_t vlen = strlen(line + plen);
			if (vlen > 0 && line[plen + vlen - 1] == '\n')
				vlen--;
			if (vlen >= sizeof(result))
				vlen = sizeof(result) - 1;
			memcpy(result, line + plen, vlen);
			result[vlen] = '\0';
			fclose(fp);
			return result;
		}
	}
	fclose(fp);
	snprintf(result, sizeof(result), "%s", defval);
	return result;
}

void dbg_set(const char *key, const char *val)
{
	/* Read existing state */
	struct { char key[MAX_KEY_LEN]; char val[MAX_VAL_LEN]; } entries[MAX_STATE_KEYS];
	int count = 0;
	int found = 0;

	FILE *fp = fopen(DEBUG_STATE_FILE, "r");
	if (fp) {
		char line[128];
		while (fgets(line, sizeof(line), fp) && count < MAX_STATE_KEYS) {
			char *eq = strchr(line, '=');
			if (!eq) continue;
			size_t klen = (size_t)(eq - line);
			if (klen >= MAX_KEY_LEN) continue;
			memcpy(entries[count].key, line, klen);
			entries[count].key[klen] = '\0';

			const char *v = eq + 1;
			size_t vlen = strlen(v);
			if (vlen > 0 && v[vlen - 1] == '\n') vlen--;
			if (vlen >= MAX_VAL_LEN) vlen = MAX_VAL_LEN - 1;
			memcpy(entries[count].val, v, vlen);
			entries[count].val[vlen] = '\0';

			if (strcmp(entries[count].key, key) == 0) {
				snprintf(entries[count].val, MAX_VAL_LEN, "%s", val);
				found = 1;
			}
			count++;
		}
		fclose(fp);
	}

	if (!found && count < MAX_STATE_KEYS) {
		snprintf(entries[count].key, MAX_KEY_LEN, "%s", key);
		snprintf(entries[count].val, MAX_VAL_LEN, "%s", val);
		count++;
	}

	/* Write atomically: tmp + rename */
	char tmppath[128];
	snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d",
		 DEBUG_STATE_FILE, (int)getpid());

	fp = fopen(tmppath, "w");
	if (!fp) return;
	for (int i = 0; i < count; i++)
		fprintf(fp, "%s=%s\n", entries[i].key, entries[i].val);
	fclose(fp);
	rename(tmppath, DEBUG_STATE_FILE);
}

void dbg_reset(void)
{
	unlink(DEBUG_STATE_FILE);
}

int dbg_enabled(void)
{
	return strcmp(dbg_get("enabled", "0"), "1") == 0;
}

/* ── Helpers ──────────────────────────────────────────────────────────── */

/* Normalize enable/disable/on/off to "1"/"0". Returns NULL on invalid. */
static const char *bool_norm(const char *s)
{
	if (!s) return NULL;
	if (strcmp(s, "enable") == 0 || strcmp(s, "on") == 0 ||
	    strcmp(s, "1") == 0 || strcmp(s, "yes") == 0)
		return "1";
	if (strcmp(s, "disable") == 0 || strcmp(s, "off") == 0 ||
	    strcmp(s, "0") == 0 || strcmp(s, "no") == 0)
		return "0";
	return NULL;
}

/* Fork a command and print first N lines of output */
static void fork_print_lines(const char *const argv[], int max_lines)
{
	int pipefd[2];
	if (pipe(pipefd) < 0) return;

	pid_t pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return;
	}
	if (pid == 0) {
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);
		execvp(argv[0], (char *const *)argv);
		_exit(127);
	}

	close(pipefd[1]);
	FILE *fp = fdopen(pipefd[0], "r");
	if (!fp) {
		close(pipefd[0]);
		waitpid(pid, NULL, 0);
		return;
	}

	char line[512];
	int lines = 0;
	while (fgets(line, sizeof(line), fp) && lines < max_lines) {
		printf("  %s", line);
		lines++;
	}
	fclose(fp);
	waitpid(pid, NULL, 0);
}

/* Parse next space-delimited token from *pp, advance pointer */
static int next_token(const char **pp, char *out, size_t outsz)
{
	const char *p = *pp;
	while (*p == ' ') p++;
	if (!*p) { out[0] = '\0'; return 0; }

	const char *start = p;
	while (*p && *p != ' ') p++;
	size_t len = (size_t)(p - start);
	if (len >= outsz) len = outsz - 1;
	memcpy(out, start, len);
	out[len] = '\0';
	*pp = p;
	return 1;
}

/* ── Debug status ─────────────────────────────────────────────────────── */

static void print_status(void)
{
	printf("\n");
	printf("  Debug status:\n");
	printf("  Global debug:        %s\n",
	       strcmp(dbg_get("enabled", "0"), "1") == 0 ? "enable" : "disable");
	printf("  Option timestamp:    %s\n",
	       strcmp(dbg_get("opt_timestamp", "1"), "1") == 0 ? "enable" : "disable");
	printf("  Option actor:        %s\n",
	       strcmp(dbg_get("opt_actor", "1"), "1") == 0 ? "enable" : "disable");
	printf("  Option function:     %s\n",
	       strcmp(dbg_get("opt_function", "1"), "1") == 0 ? "enable" : "disable");
	printf("  Option hierarchy:    %s\n",
	       strcmp(dbg_get("opt_hierarchy", "1"), "1") == 0 ? "enable" : "disable");
	printf("  Flow trace:          %s\n",
	       strcmp(dbg_get("flow_trace", "0"), "1") == 0 ? "enable" : "disable");

	const char *fl = dbg_get("flow_limit", "0");
	if (strcmp(fl, "0") == 0)
		printf("  Flow limit:          unlimited\n");
	else
		printf("  Flow limit:          %s\n", fl);

	printf("  CLI debug:           %s\n",
	       strcmp(dbg_get("cli_debug", "0"), "1") == 0 ? "enable" : "disable");
	printf("  mgmtd debug:         %s\n",
	       strcmp(dbg_get("mgmtd_debug", "0"), "1") == 0 ? "enable" : "disable");
	printf("  Auth admin debug:    %s\n",
	       strcmp(dbg_get("auth_admin", "0"), "1") == 0 ? "enable" : "disable");
	printf("  Auth user debug:     %s\n",
	       strcmp(dbg_get("auth_user", "0"), "1") == 0 ? "enable" : "disable");
	printf("\n");
}

/* ── Resource monitoring ──────────────────────────────────────────────── */

void dbg_show_cpu(void)
{
	printf("\n---CPU resources:\n");

	/* Count cores */
	int cores = 0;
	FILE *fp = fopen("/proc/stat", "r");
	if (fp) {
		char line[256];
		while (fgets(line, sizeof(line), fp)) {
			if (strncmp(line, "cpu", 3) == 0 && isdigit((unsigned char)line[3]))
				cores++;
		}
		fclose(fp);
	}
	printf("  CPU cores: %d\n", cores);

	/* Utilization: read /proc/stat twice with 1s delay */
	/* Use shell+awk for the computation as in the original */
	const char *argv[] = {"sh", "-c",
		"s1=$(awk '/^cpu[0-9]* /{idle=$5+$6;total=0;for(i=2;i<=NF;i++)total+=$i;print $1,total,idle}' /proc/stat);"
		"sleep 1;"
		"s2=$(awk '/^cpu[0-9]* /{idle=$5+$6;total=0;for(i=2;i<=NF;i++)total+=$i;print $1,total,idle}' /proc/stat);"
		"paste <(echo \"$s1\") <(echo \"$s2\") | awk '"
		"BEGIN{printf \"  Utilization (1s window):\\n\"}"
		"{name=$1;t1=$2;i1=$3;t2=$5;i2=$6;"
		"dt=t2-t1;di=i2-i1;"
		"u=(dt>0)?((dt-di)*100.0/dt):0.0;"
		"if(name==\"cpu\")printf \"    total : %.2f%%\\n\",u;"
		"else printf \"    %-5s : %.2f%%\\n\",name,u;}'",
		NULL};
	fork_print_lines(argv, 64);

	/* Temperature */
	printf("  Temperatures:\n");
	int found_temp = 0;
	char path[128];
	for (int z = 0; z < 16; z++) {
		snprintf(path, sizeof(path),
			 "/sys/class/thermal/thermal_zone%d/temp", z);
		fp = fopen(path, "r");
		if (!fp) continue;
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

void dbg_show_ram(void)
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
	double pct = (mt > 0) ? (mu * 100.0 / mt) : 0.0;
	printf("  Used: %.2f%% (%ld MiB / %ld MiB), Available: %ld MiB\n",
	       pct, mu / 1024, mt / 1024, ma / 1024);
	printf("\n");
}

void dbg_show_disk(void)
{
	printf("\n---Disk resources:\n");
	const char *argv[] = {"df", "-P", "-h", "/", NULL};
	fork_print_lines(argv, 4);
	printf("\n");
}

void dbg_show_interface(void)
{
	printf("\n---Interface resources:\n");

	/* Throughput: read /proc/net/dev twice with 1s delay */
	const char *argv[] = {"sh", "-c",
		"i1=$(awk -F'[: ]+' '/:/{if($1!~\"lo\"){print $1,$3,$11}}' /proc/net/dev);"
		"sleep 1;"
		"i2=$(awk -F'[: ]+' '/:/{if($1!~\"lo\"){print $1,$3,$11}}' /proc/net/dev);"
		"paste <(echo \"$i1\") <(echo \"$i2\") | awk '"
		"BEGIN{printf \"  Throughput (1s window):\\n\"}"
		"{iface=$1;rx1=$2;tx1=$3;rx2=$5;tx2=$6;"
		"drx=rx2-rx1;dtx=tx2-tx1;"
		"if(drx<0)drx=0;if(dtx<0)dtx=0;"
		"printf \"    %-10s rx=%8.2f KB/s  tx=%8.2f KB/s\\n\",iface,drx/1024.0,dtx/1024.0;}'",
		NULL};
	fork_print_lines(argv, 64);

	/* Link speed */
	printf("  Link speed (best effort):\n");
	char path[128], spd[32];
	for (int pass = 0; pass < 2; pass++) {
		/* List interfaces from /sys/class/net */
		const char *netdir = "/sys/class/net";
		FILE *fp;
		/* Just iterate a reasonable number of known patterns */
		const char *ls_argv[] = {"ls", netdir, NULL};

		int pipefd[2];
		if (pipe(pipefd) < 0) break;
		pid_t pid = fork();
		if (pid < 0) { close(pipefd[0]); close(pipefd[1]); break; }
		if (pid == 0) {
			close(pipefd[0]);
			dup2(pipefd[1], STDOUT_FILENO);
			close(pipefd[1]);
			execvp(ls_argv[0], (char *const *)ls_argv);
			_exit(127);
		}
		close(pipefd[1]);
		fp = fdopen(pipefd[0], "r");
		if (!fp) { close(pipefd[0]); waitpid(pid, NULL, 0); break; }

		char iface[64];
		while (fgets(iface, sizeof(iface), fp)) {
			size_t len = strlen(iface);
			if (len > 0 && iface[len-1] == '\n') iface[--len] = '\0';
			if (strcmp(iface, "lo") == 0) continue;
			if (!*iface) continue;

			snprintf(path, sizeof(path),
				 "/sys/class/net/%s/speed", iface);
			FILE *sfp = fopen(path, "r");
			if (sfp) {
				if (fgets(spd, sizeof(spd), sfp)) {
					size_t slen = strlen(spd);
					if (slen > 0 && spd[slen-1] == '\n')
						spd[--slen] = '\0';
				} else {
					snprintf(spd, sizeof(spd), "unknown");
				}
				fclose(sfp);
			} else {
				snprintf(spd, sizeof(spd), "unknown");
			}
			printf("    %s: speed=%sMbps\n", iface, spd);
		}
		fclose(fp);
		waitpid(pid, NULL, 0);
		break; /* Only one pass needed */
	}
	printf("\n");
}

void dbg_show_resources(const char *which)
{
	if (!which || !*which || strcmp(which, "all") == 0) {
		dbg_show_cpu();
		dbg_show_ram();
		dbg_show_disk();
		dbg_show_interface();
	} else if (strcmp(which, "cpu") == 0) {
		dbg_show_cpu();
	} else if (strcmp(which, "ram") == 0) {
		dbg_show_ram();
	} else if (strcmp(which, "disk") == 0) {
		dbg_show_disk();
	} else if (strcmp(which, "interface") == 0) {
		dbg_show_interface();
	} else {
		printf("  Usage: execute debug resources [cpu|ram|disk|interface|all]\n");
	}
}

void dbg_show_top(void)
{
	printf("\n  Process snapshot:\n");
	const char *argv_top[] = {"top", "-bn1", NULL};
	const char *argv_ps[] = {"ps", "w", NULL};

	/* Try top first, fall back to ps */
	if (access("/usr/bin/top", X_OK) == 0 ||
	    access("/bin/top", X_OK) == 0) {
		fork_print_lines(argv_top, 25);
	} else {
		fork_print_lines(argv_ps, 25);
	}
	printf("\n");
}

/* ── Main dispatch ────────────────────────────────────────────────────── */

void cli_debug_dispatch(const char *args)
{
	if (!args)
		args = "";
	while (*args == ' ')
		args++;

	char sub[64];
	const char *rest = args;
	if (!next_token(&rest, sub, sizeof(sub)) || !sub[0]) {
		/* No subcommand — show status */
		print_status();
		return;
	}

	/* enable / disable */
	if (strcmp(sub, "enable") == 0 || strcmp(sub, "disable") == 0) {
		const char *bv = bool_norm(sub);
		dbg_set("enabled", bv);
		printf("  Debug %sd.\n", sub);
		return;
	}

	/* reset */
	if (strcmp(sub, "reset") == 0) {
		dbg_reset();
		printf("  Debug state reset. All debug features disabled and options restored.\n");
		return;
	}

	/* status */
	if (strcmp(sub, "status") == 0) {
		print_status();
		return;
	}

	/* option <name> <enable|disable> */
	if (strcmp(sub, "option") == 0) {
		char opt_name[32], opt_act[16];
		if (!next_token(&rest, opt_name, sizeof(opt_name)) || !opt_name[0]) {
			printf("  Usage: execute debug option <timestamp|actor|function|hierarchy> <enable|disable>\n");
			return;
		}

		const char *state_key = NULL;
		if (strcmp(opt_name, "timestamp") == 0)
			state_key = "opt_timestamp";
		else if (strcmp(opt_name, "actor") == 0)
			state_key = "opt_actor";
		else if (strcmp(opt_name, "function") == 0)
			state_key = "opt_function";
		else if (strcmp(opt_name, "hierarchy") == 0)
			state_key = "opt_hierarchy";
		else {
			printf("  Usage: execute debug option <timestamp|actor|function|hierarchy> <enable|disable>\n");
			return;
		}

		if (!next_token(&rest, opt_act, sizeof(opt_act)) || !opt_act[0]) {
			printf("  Usage: execute debug option %s <enable|disable>\n", opt_name);
			return;
		}
		const char *bv = bool_norm(opt_act);
		if (!bv) {
			printf("  Usage: execute debug option %s <enable|disable>\n", opt_name);
			return;
		}
		dbg_set(state_key, bv);
		printf("  Debug option %s %sd.\n", opt_name, opt_act);
		return;
	}

	/* cli [enable|disable] */
	if (strcmp(sub, "cli") == 0) {
		char act[16];
		if (!next_token(&rest, act, sizeof(act)) || !act[0])
			snprintf(act, sizeof(act), "enable");
		const char *bv = bool_norm(act);
		if (!bv) {
			printf("  Usage: execute debug cli [enable|disable]\n");
			return;
		}
		dbg_set("cli_debug", bv);
		printf("  Debug CLI %sd.\n", act);
		return;
	}

	/* mgmtd [enable|disable] */
	if (strcmp(sub, "mgmtd") == 0) {
		char act[16];
		if (!next_token(&rest, act, sizeof(act)) || !act[0])
			snprintf(act, sizeof(act), "enable");
		const char *bv = bool_norm(act);
		if (!bv) {
			printf("  Usage: execute debug mgmtd [enable|disable]\n");
			return;
		}
		dbg_set("mgmtd_debug", bv);
		printf("  Debug mgmtd %sd.\n", act);
		return;
	}

	/* auth <admin|user> [enable|disable] */
	if (strcmp(sub, "auth") == 0) {
		char role[16], act[16];
		if (!next_token(&rest, role, sizeof(role)) || !role[0]) {
			printf("  Usage: execute debug auth <admin|user> [enable|disable]\n");
			return;
		}
		const char *state_key = NULL;
		if (strcmp(role, "admin") == 0)
			state_key = "auth_admin";
		else if (strcmp(role, "user") == 0)
			state_key = "auth_user";
		else {
			printf("  Usage: execute debug auth <admin|user> [enable|disable]\n");
			return;
		}

		if (!next_token(&rest, act, sizeof(act)) || !act[0])
			snprintf(act, sizeof(act), "enable");
		const char *bv = bool_norm(act);
		if (!bv) {
			printf("  Usage: execute debug auth <admin|user> [enable|disable]\n");
			return;
		}
		dbg_set(state_key, bv);
		printf("  Debug auth %s %sd.\n", role, act);
		return;
	}

	/* flow trace [enable|disable] [limit <n>|unlimited] */
	if (strcmp(sub, "flow") == 0) {
		char tok1[16];
		if (!next_token(&rest, tok1, sizeof(tok1)) ||
		    strcmp(tok1, "trace") != 0) {
			printf("  Usage: execute debug flow trace [enable|disable] [limit <n>|unlimited]\n");
			return;
		}

		/* Optional enable/disable */
		char act[16] = "enable";
		const char *saved = rest;
		char peek[16];
		if (next_token(&saved, peek, sizeof(peek)) && peek[0]) {
			if (strcmp(peek, "enable") == 0 ||
			    strcmp(peek, "disable") == 0) {
				snprintf(act, sizeof(act), "%s", peek);
				rest = saved;
			}
		}

		const char *bv = bool_norm(act);
		if (!bv) {
			printf("  Usage: execute debug flow trace [enable|disable] [limit <n>|unlimited]\n");
			return;
		}
		dbg_set("flow_trace", bv);

		/* Optional limit */
		char lim_tok[16];
		if (next_token(&rest, lim_tok, sizeof(lim_tok)) && lim_tok[0]) {
			if (strcmp(lim_tok, "limit") == 0) {
				char lim_val[16];
				if (next_token(&rest, lim_val, sizeof(lim_val)) &&
				    lim_val[0]) {
					if (strcmp(lim_val, "unlimited") == 0) {
						dbg_set("flow_limit", "0");
					} else if (sg_is_uint_range(lim_val, 0, 999999)) {
						dbg_set("flow_limit", lim_val);
					} else {
						printf("  Invalid limit value: %s\n", lim_val);
						return;
					}
				}
			} else if (strcmp(lim_tok, "unlimited") == 0) {
				dbg_set("flow_limit", "0");
			} else {
				printf("  Usage: execute debug flow trace [enable|disable] [limit <n>|unlimited]\n");
				return;
			}
		}

		printf("  Debug flow trace %sd.\n", act);
		return;
	}

	/* top */
	if (strcmp(sub, "top") == 0) {
		dbg_show_top();
		return;
	}

	/* resources [cpu|ram|disk|interface|all] */
	if (strcmp(sub, "resources") == 0) {
		char which[16];
		if (!next_token(&rest, which, sizeof(which)) || !which[0])
			snprintf(which, sizeof(which), "all");
		dbg_show_resources(which);
		return;
	}

	/* Unknown subcommand */
	printf("  Usage: execute debug <enable|disable|reset|status|option|flow|cli|mgmtd|auth|top|resources>\n");
	printf("  Examples:\n");
	printf("    execute debug enable\n");
	printf("    execute debug option timestamp enable\n");
	printf("    execute debug flow trace enable limit 100\n");
	printf("    execute debug cli enable\n");
	printf("    execute debug mgmtd enable\n");
	printf("    execute debug auth admin enable\n");
	printf("    execute debug top\n");
	printf("    execute debug resources all\n");
	printf("    execute debug reset\n");
}
