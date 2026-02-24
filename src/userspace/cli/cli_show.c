/* SPDX-License-Identifier: MIT */
/*
 * cli_show.c — Show command implementations for Stargazer CLI
 *
 * C replacement for cmd_show shell script.
 * All subcommands: status, sessions, stats, interfaces, routes,
 * configure (FortiGate-style dump), config.
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_show.h"
#include "cli_ipc.h"
#include "sg_validate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* ── Helpers ──────────────────────────────────────────────────────────── */

/* Read entire contents of a file into a static buffer. Returns "" on failure. */
static const char *read_proc_file(const char *path,
				  char *buf, size_t bufsz)
{
	buf[0] = '\0';
	FILE *fp = fopen(path, "r");
	if (!fp)
		return buf;

	size_t used = 0;
	char line[512];
	while (fgets(line, sizeof(line), fp)) {
		size_t llen = strlen(line);
		if (used + llen + 1 >= bufsz)
			break;
		memcpy(buf + used, line, llen);
		used += llen;
	}
	buf[used] = '\0';
	fclose(fp);
	return buf;
}

/* Run a command and capture stdout. Caller must free result. */
static char *fork_capture(const char *const argv[])
{
	int pipefd[2];
	if (pipe(pipefd) < 0)
		return NULL;

	pid_t pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return NULL;
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

	size_t bufsz = 4096, used = 0;
	char *buf = malloc(bufsz);
	if (!buf) {
		close(pipefd[0]);
		waitpid(pid, NULL, 0);
		return NULL;
	}

	ssize_t n;
	char tmp[1024];
	while ((n = read(pipefd[0], tmp, sizeof(tmp))) > 0) {
		while (used + (size_t)n + 1 > bufsz) {
			bufsz *= 2;
			char *nb = realloc(buf, bufsz);
			if (!nb) {
				free(buf);
				close(pipefd[0]);
				waitpid(pid, NULL, 0);
				return NULL;
			}
			buf = nb;
		}
		memcpy(buf + used, tmp, (size_t)n);
		used += (size_t)n;
	}
	buf[used] = '\0';
	close(pipefd[0]);
	waitpid(pid, NULL, 0);
	return buf;
}

/* Print IPC payload or fallback message */
static void show_ipc_or_fallback(uint32_t cmd, const char *payload_str,
				 const char *header,
				 const char *const fallback_argv[])
{
	struct ipc_response resp = {0};
	if (ipc_available() &&
	    ipc_send_str(cmd, payload_str, &resp) == 0 &&
	    resp.status == SG_OK && resp.payload && resp.payload[0]) {
		if (header)
			printf("  %s\n", header);
		printf("%s", resp.payload);
		ipc_resp_free(&resp);
		return;
	}
	ipc_resp_free(&resp);

	/* Fallback */
	if (header)
		printf("  %s\n", header);
	if (fallback_argv) {
		char *out = fork_capture(fallback_argv);
		if (out) {
			printf("%s", out);
			free(out);
		}
	}
}

/* ── show status ──────────────────────────────────────────────────────── */

void show_status(void)
{
	struct ipc_response resp = {0};
	if (ipc_available() &&
	    ipc_send_str(SG_CMD_SHOW_STATUS, "", &resp) == 0 &&
	    resp.status == SG_OK && resp.payload && resp.payload[0]) {
		printf("%s", resp.payload);
		ipc_resp_free(&resp);
		return;
	}
	ipc_resp_free(&resp);

	/* Fallback: read /proc directly */
	printf("  === Stargazer Status ===\n");

	char modules[4096];
	read_proc_file("/proc/modules", modules, sizeof(modules));
	if (strstr(modules, "pkt_forward"))
		printf("  Module pkt_forward: loaded\n");
	else
		printf("  Module pkt_forward: not loaded\n");
	if (strstr(modules, "session"))
		printf("  Module session:     loaded\n");
	else
		printf("  Module session:     not loaded\n");

	char uptime[128];
	read_proc_file("/proc/uptime", uptime, sizeof(uptime));
	char *sp = strchr(uptime, ' ');
	if (sp) *sp = '\0';
	char *nl = strchr(uptime, '\n');
	if (nl) *nl = '\0';
	if (uptime[0])
		printf("  Uptime: %ss\n", uptime);
}

/* ── show sessions ────────────────────────────────────────────────────── */

void show_sessions(void)
{
	FILE *fp = fopen("/proc/stargazer/sessions", "r");
	if (fp) {
		printf("  === Active Sessions ===\n");
		char line[512];
		while (fgets(line, sizeof(line), fp))
			printf("%s", line);
		fclose(fp);
	} else {
		printf("  Session tracking not available (module not loaded)\n");
	}
}

/* ── show stats ───────────────────────────────────────────────────────── */

void show_stats(void)
{
	printf("  === Packet Statistics ===\n");

	struct ipc_response resp = {0};
	if (ipc_available() &&
	    ipc_send_str(SG_CMD_SHOW_STATS, "", &resp) == 0 &&
	    resp.status == SG_OK && resp.payload && resp.payload[0]) {
		printf("%s", resp.payload);
		ipc_resp_free(&resp);
		return;
	}
	ipc_resp_free(&resp);

	/* Fallback: fork dmesg */
	const char *argv[] = {"sh", "-c",
		"dmesg 2>/dev/null | grep -i 'pkt_forward\\|forwarded\\|dropped' | tail -10",
		NULL};
	char *out = fork_capture(argv);
	if (out) {
		printf("%s", out);
		free(out);
	}
}

/* ── show interfaces ──────────────────────────────────────────────────── */

void show_interfaces(void)
{
	const char *fallback[] = {"ip", "-brief", "link", NULL};
	show_ipc_or_fallback(SG_CMD_SHOW_IFACES, "",
			     "=== Network Interfaces ===", fallback);
}

/* ── show routes ──────────────────────────────────────────────────────── */

void show_routes(void)
{
	const char *fallback[] = {"ip", "route", NULL};
	show_ipc_or_fallback(SG_CMD_SHOW_ROUTES, "",
			     "=== Routing Table ===", fallback);
}

/* Check whether a value should be quoted in FortiGate-style output. */
static int value_needs_quote(const char *type, const char *key)
{
	const char *kind = sg_reg_value_kind(type, key);
	return strcmp(kind, "string") == 0;
}

/* ── show configure (FortiGate-style dump) ────────────────────────────── */

/*
 * Iterate all known config types from sg_validate's type_table.
 * For each, query mgmtd via IPC to get entries, then format in
 * FortiGate "config ... / edit ... / set ... / next / end" style.
 */
void show_configure(void)
{
	printf("  === Running Configuration ===\n\n");

	/* Walk all types known to the registry */
	const sg_type_info_t *types = sg_reg_types();

	for (int t = 0; types[t].name; t++) {
		const char *type = types[t].name;
		int mode = (int)types[t].mode;

		const char *label = sg_reg_type_label(type);

		if (mode == CFG_TABLE) {
			/* Get list of IDs */
			struct ipc_response lresp = {0};
			if (!ipc_available() ||
			    ipc_send_str(SG_CMD_CFG_LIST, type, &lresp) != 0 ||
			    lresp.status != SG_OK || !lresp.payload ||
			    !lresp.payload[0]) {
				ipc_resp_free(&lresp);
				continue;
			}

			printf("config %s\n", label);

			/* Parse newline-separated IDs */
			char *ids = lresp.payload;
			char *id = ids;
			while (id && *id) {
				char *nl = strchr(id, '\n');
				if (nl) *nl = '\0';
				if (!*id) { if (nl) id = nl + 1; else break; continue; }

				printf("  edit \"%s\"\n", id);

				/* Get entry data */
				char section[512];
				snprintf(section, sizeof(section), "%s:%s",
					 type, id);
				struct ipc_response dresp;
				if (ipc_send_str(SG_CMD_CFG_GET, section,
						 &dresp) == 0 &&
				    dresp.status == SG_OK && dresp.payload) {
					/* Parse key=value lines */
					const char *p = dresp.payload;
					while (*p) {
						const char *eol = strchr(p, '\n');
						size_t llen = eol ? (size_t)(eol - p) : strlen(p);
						if (llen > 0) {
							const char *eq = memchr(p, '=', llen);
							if (eq) {
								size_t klen = (size_t)(eq - p);
								/* Skip builtin marker */
								if (klen == 7 && strncmp(p, "builtin", 7) == 0) {
									p += llen;
									if (eol) p++;
									continue;
								}
								/* Mask passwords */
								if (klen == 8 && strncmp(p, "password", 8) == 0) {
									printf("    set password ********\n");
								} else {
									char kbuf[64];
									size_t kl = klen;
									if (kl >= sizeof(kbuf))
										kl = sizeof(kbuf) - 1;
									memcpy(kbuf, p, kl);
									kbuf[kl] = '\0';
									if (value_needs_quote(type, kbuf))
										printf("    set %.*s \"%.*s\"\n",
										       (int)klen, p,
										       (int)(llen - klen - 1), eq + 1);
									else
										printf("    set %.*s %.*s\n",
										       (int)klen, p,
										       (int)(llen - klen - 1), eq + 1);
								}
							}
						}
						p += llen;
						if (eol) p++;
					}
				}
				ipc_resp_free(&dresp);

				printf("  next\n");
				if (!nl) break;
				id = nl + 1;
			}
			printf("end\n\n");
			ipc_resp_free(&lresp);
		} else {
			/* CFG_SINGLE — id is implicitly "0" */
			struct ipc_response gresp = {0};
			char section[256];
			snprintf(section, sizeof(section), "%s", type);
			if (!ipc_available() ||
			    ipc_send_str(SG_CMD_CFG_GET, section, &gresp) != 0 ||
			    gresp.status != SG_OK || !gresp.payload ||
			    !gresp.payload[0]) {
				ipc_resp_free(&gresp);
				continue;
			}

			printf("config %s\n", label);

			const char *p = gresp.payload;
			while (*p) {
				const char *eol = strchr(p, '\n');
				size_t llen = eol ? (size_t)(eol - p) : strlen(p);
				if (llen > 0) {
					const char *eq = memchr(p, '=', llen);
					if (eq) {
						size_t klen = (size_t)(eq - p);
						if (klen == 7 && strncmp(p, "builtin", 7) == 0) {
							p += llen;
							if (eol) p++;
							continue;
						}
						char kbuf[64];
						size_t kl = klen;
						if (kl >= sizeof(kbuf))
							kl = sizeof(kbuf) - 1;
						memcpy(kbuf, p, kl);
						kbuf[kl] = '\0';
						if (value_needs_quote(type, kbuf))
							printf("  set %.*s \"%.*s\"\n",
							       (int)klen, p,
							       (int)(llen - klen - 1), eq + 1);
						else
							printf("  set %.*s %.*s\n",
							       (int)klen, p,
							       (int)(llen - klen - 1), eq + 1);
					}
				}
				p += llen;
				if (eol) p++;
			}
			printf("end\n\n");
			ipc_resp_free(&gresp);
		}
	}
}

/* ── show firmware ────────────────────────────────────────────────────── */

void show_firmware(void)
{
	struct ipc_response resp = {0};
	if (ipc_available() &&
	    ipc_send_str(SG_CMD_FW_STATUS, "", &resp) == 0 &&
	    resp.status == SG_OK && resp.payload && resp.payload[0]) {
		printf("%s", resp.payload);
		ipc_resp_free(&resp);
		return;
	}
	ipc_resp_free(&resp);

	/* Fallback: compiled-in version */
	printf("  === Firmware Status ===\n");
#ifdef VERSION
	printf("  Running version: %s\n", VERSION);
#else
	printf("  Running version: unknown\n");
#endif
}

/* ── show config (modules + sysctl) ───────────────────────────────────── */

void show_config(void)
{
	printf("  === Stargazer Configuration ===\n");
	printf("  Modules:\n");

	FILE *fp = fopen("/etc/modules-load.d/stargazer.conf", "r");
	if (fp) {
		char line[256];
		while (fgets(line, sizeof(line), fp))
			printf("    %s", line);
		fclose(fp);
	}

	printf("  Sysctl:\n");
	fp = fopen("/etc/sysctl.d/10-stargazer.conf", "r");
	if (fp) {
		char line[256];
		while (fgets(line, sizeof(line), fp)) {
			/* Skip comments and empty lines */
			if (line[0] == '#' || line[0] == '\n')
				continue;
			printf("    %s", line);
		}
		fclose(fp);
	}
}

