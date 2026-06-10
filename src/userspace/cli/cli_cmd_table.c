/* SPDX-License-Identifier: MIT */
/*
 * cli_cmd_table.c — Table-driven command registry for Stargazer CLI
 *
 * Single declarative table drives registration, dispatch, and auto-usage
 * for all CLI commands.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "cli_cmd_table.h"
#include "cli_dispatch.h"
#include "cli_readline.h"
#include "cli_configure.h"
#include "cli_diagnose.h"
#include "cli_diagnose_sys.h"
#include "cli_diagnose_bootlog.h"
#include "cli_debug.h"
#include "cli_show.h"
#include "cli_ipc.h"
#include "sg_validate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Error display helper ─────────────────────────────────────────────── */

/*
 * Print an IPC error with numeric status code for troubleshooting.
 * Output: "  Error [501]: I/O error\n"
 * The code lets engineers correlate with daemon journal entries.
 */
static void print_ipc_error(const char *prefix, const struct ipc_response *r)
{
	const char *msg = r->extra[0] ? r->extra : sg_status_str(r->status);
	printf("  %s [%u]: %s\n", prefix, r->status, msg);
}

/* ── Thin handler wrappers ────────────────────────────────────────────── */

static int cmd_help(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	cli_print_help();
	return 0;
}

static int cmd_exit(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	printf("  Goodbye.\n");
	return 1;
}

static int cmd_show_status(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	show_status();
	return 0;
}

static int cmd_show_sessions(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	show_sessions();
	return 0;
}

static int cmd_show_stats(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	show_stats();
	return 0;
}

static int cmd_show_interfaces(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	show_interfaces();
	return 0;
}

static int cmd_show_routes(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	show_routes();
	return 0;
}

static int cmd_show_configure(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	show_configure();
	return 0;
}

static int cmd_show_config(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	show_config();
	return 0;
}

#define CMD_MAX_ARGS     32  /* max tokens in configure argument list */
#define CMD_MAX_SHOWN    64  /* max subcommands in auto-usage output  */

static int cmd_configure(const char *args, const char *permissions)
{
	(void)permissions;
	const char *argv[CMD_MAX_ARGS];
	int argc = 0;
	char args_copy[CLI_MAX_LINE];

	if (args && args[0]) {
		snprintf(args_copy, sizeof(args_copy), "%s", args);
		char *tok = args_copy;
		while (*tok && argc < CMD_MAX_ARGS - 1) {
			while (*tok == ' ')
				tok++;
			if (!*tok)
				break;
			argv[argc++] = tok;
			while (*tok && *tok != ' ')
				tok++;
			if (*tok)
				*tok++ = '\0';
		}
	}
	argv[argc] = NULL;
	cli_configure(argc, argv);
	return 0;
}

static int cmd_show_firmware(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	show_firmware();
	return 0;
}

/*
 * Parse a key=value line from firmware progress state.
 * Copies the value for 'key' into 'out' (max outsz bytes).
 */
static void fw_parse_val(const char *data, const char *key,
			 char *out, size_t outsz)
{
	out[0] = '\0';
	if (!data || !key || outsz == 0)
		return;
	size_t klen = strlen(key);
	const char *p = data;
	while ((p = strstr(p, key)) != NULL) {
		/* Must be at start of line or start of string */
		if (p != data && *(p - 1) != '\n') {
			p += klen;
			continue;
		}
		if (p[klen] != '=') {
			p += klen;
			continue;
		}
		const char *val = p + klen + 1;
		const char *eol = strchr(val, '\n');
		size_t vlen = eol ? (size_t)(eol - val) : strlen(val);
		if (vlen >= outsz)
			vlen = outsz - 1;
		memcpy(out, val, vlen);
		out[vlen] = '\0';
		return;
	}
}

static int cmd_fw_upgrade(const char *args, const char *permissions)
{
	(void)permissions;

	/* Require a URL argument */
	if (!args || !*args) {
		printf("  Usage: execute firmware upgrade <url>\n");
		printf("  Supported schemes: http://, https://, tftp://\n");
		return 0;
	}

	/* Validate URL scheme */
	if (strncmp(args, "http://", 7) != 0 &&
	    strncmp(args, "https://", 8) != 0 &&
	    strncmp(args, "tftp://", 7) != 0) {
		printf("  Invalid URL: must start with http://, https://, or tftp://\n");
		return 0;
	}

	/* Confirm with admin — switch to canonical echo mode so keystrokes are
	 * visible (terminal is in raw/no-echo mode between readline calls). */
	printf("  WARNING: This will download firmware, install it, and reboot the device.\n");
	printf("  Carefully read change logs before proceeding.\n");
	printf("  Do you want to continue? [y/N] ");
	fflush(stdout);

	cli_term_echo_on();
	char confirm[16] = {0};
	int cancelled = (!fgets(confirm, sizeof(confirm), stdin) ||
			 (confirm[0] != 'y' && confirm[0] != 'Y'));
	cli_term_echo_off();

	if (cancelled) {
		printf("  Firmware upgrade cancelled.\n");
		return 0;
	}

	/* Build payload and send IPC */
	char payload[SG_PAYLOAD_MAX];
	snprintf(payload, sizeof(payload), "url=%s\n", args);

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_UPGRADE_START, payload, &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		print_ipc_error("Firmware upgrade failed", &resp);
		ipc_resp_free(&resp);
		return 0;
	}
	ipc_resp_free(&resp);

	/* Poll for progress updates */
	printf("\n");
	fflush(stdout);

	ipc_install_interrupt_handler();

	int last_step = -1;
	int lines_printed = 0;
	int have_inline = 0;   /* true if an in-place progress line is active */
	char last_msg[256] = {0};
	for (int i = 0; i < 240; i++) {  /* 240 * 500ms = 120s timeout */
		if (ipc_stream_interrupted()) {
			if (have_inline)
				printf("\n");
			/* Send cancel to mgmtd so the child process stops.
			 * Check the send return: ipc_send zero-fills cr and
			 * SG_OK==0, so cr.status alone cannot distinguish a real
			 * OK from a failed connection. */
			struct ipc_response cr;
			if (ipc_send_str(SG_CMD_UPGRADE_CANCEL, "", &cr) != 0) {
				printf("  Could not deliver cancel to mgmtd; "
				       "upgrade may still be running.\n");
				ipc_resp_free(&cr);
				ipc_clear_interrupt();
				have_inline = 0;
				usleep(500000);
				continue;
			}
			if (cr.status != SG_OK) {
				/* Cancel rejected (e.g. past point of no return) */
				printf("  %s\n",
				       cr.extra[0] ? cr.extra
						   : sg_status_str(cr.status));
				ipc_resp_free(&cr);
				ipc_clear_interrupt();
				have_inline = 0;
				usleep(500000);
				continue;
			}
			ipc_resp_free(&cr);
			printf("  Firmware upgrade cancelled.\n");
			break;
		}

		struct ipc_response pr;
		if (ipc_send_str(SG_CMD_UPGRADE_PROGRESS, "", &pr) != 0) {
			if (have_inline)
				printf("\n");
			if (ipc_stream_interrupted())
				printf("  Interrupted.\n");
			else
				printf("  Connection lost — device may be rebooting.\n");
			break;
		}

		if (pr.status != SG_OK || !pr.payload) {
			ipc_resp_free(&pr);
			usleep(500000);
			continue;
		}

		char step_s[16], total_s[16], status[32], message[256];
		fw_parse_val(pr.payload, "step", step_s, sizeof(step_s));
		fw_parse_val(pr.payload, "total", total_s, sizeof(total_s));
		fw_parse_val(pr.payload, "status", status, sizeof(status));
		fw_parse_val(pr.payload, "message", message, sizeof(message));

		int step = atoi(step_s);
		int total = atoi(total_s);

		/* When the step advances and we have an in-place progress
		 * line, overwrite it with 100% before moving on.
		 * This handles the race where mgmtd advances to the
		 * next step before the CLI polls the final progress. */
		if (step > last_step && last_step > 0 && have_inline) {
			if (last_step == 1) {
				/* Download step: show 100% with protocol */
				const char *via = strstr(last_msg, " via ");
				if (via)
					printf("\r\033[K  [1/%d] "
					       "Downloading firmware..."
					       " 100%%%s",
					       total, via);
				else
					printf("\r\033[K  [1/%d] "
					       "Downloading firmware..."
					       " 100%%", total);
				fflush(stdout);
			} else {
				char *pct = strstr(last_msg, "% ");
				if (!pct)
					pct = strstr(last_msg, "%(");
				if (pct) {
					char *np = pct;
					while (np > last_msg &&
					       np[-1] >= '0' &&
					       np[-1] <= '9')
						np--;
					printf("\r\033[K  [%d/%d] "
					       "%.*s100%%",
					       last_step, total,
					       (int)(np - last_msg),
					       last_msg);
					fflush(stdout);
				}
			}
		}

		/* Print step log lines (step transitions) as in-place
		 * lines so that subsequent progress updates within the
		 * same step can overwrite them via \r. */
		int new_lines = 0;
		const char *sep = strstr(pr.payload, "\n---\n");
		if (sep) {
			const char *log = sep + 5;
			int line_num = 0;
			const char *lp = log;
			while (*lp) {
				const char *eol = strchr(lp, '\n');
				size_t llen = eol ? (size_t)(eol - lp) : strlen(lp);
				if (llen > 0 && line_num >= lines_printed) {
					if (have_inline)
						printf("\n");
					printf("  %.*s", (int)llen, lp);
					fflush(stdout);
					have_inline = 1;
					lines_printed = line_num + 1;
					new_lines++;
				}
				line_num++;
				if (!eol) break;
				lp = eol + 1;
			}
		}

		/* For current step's message: update in-place.
		 * Skip if we just printed new log lines (they already
		 * show the step transition) or if the message hasn't
		 * changed since last displayed. */
		if (message[0] && total > 0 && !new_lines &&
		    strcmp(message, last_msg) != 0) {
			printf("\r\033[K  [%d/%d] %s", step, total, message);
			fflush(stdout);
			have_inline = 1;
		}

		last_step = step;
		snprintf(last_msg, sizeof(last_msg), "%s", message);

		if (strcmp(status, "done") == 0) {
			if (have_inline)
				printf("\n");
			printf("\n  System is rebooting now...\n");
			ipc_resp_free(&pr);
			/* Block until SIGTERM — prevent CLI from
			 * returning to prompt before reboot. */
			for (;;) pause();
		}
		if (strcmp(status, "error") == 0) {
			if (have_inline)
				printf("\n");
			if (message[0])
				printf("\n  Firmware upgrade failed: %s\n",
				       message);
			else
				printf("\n  Firmware upgrade failed.\n");
			ipc_resp_free(&pr);
			break;
		}
		if (strcmp(status, "cancelled") == 0) {
			if (have_inline)
				printf("\n");
			printf("\n  Firmware upgrade cancelled.\n");
			ipc_resp_free(&pr);
			break;
		}
		if (strcmp(status, "idle") == 0) {
			if (have_inline)
				printf("\n");
			ipc_resp_free(&pr);
			break;
		}

		ipc_resp_free(&pr);
		usleep(500000);
	}

	ipc_restore_interrupt_handler();

	if (last_step < 0)
		printf("  Timed out waiting for upgrade progress.\n");

	return 0;
}

static int cmd_sys_shutdown(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_SYS_POWEROFF, "", &resp) != 0) {
		printf("  Error: could not contact management daemon.\n");
	} else if (resp.status == SG_OK) {
		printf("  System shutting down...\n");
		ipc_resp_free(&resp);
		/* Block until SIGTERM arrives — prevents the CLI from
		 * returning to the prompt and printing "stargazer>" before
		 * the shutdown script kills us. */
		for (;;) pause();
	} else {
		print_ipc_error("Error", &resp);
	}
	ipc_resp_free(&resp);
	return 0;
}

static int cmd_sys_reboot(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_SYS_REBOOT, "", &resp) != 0) {
		printf("  Error: could not contact management daemon.\n");
	} else if (resp.status == SG_OK) {
		printf("  System rebooting...\n");
		ipc_resp_free(&resp);
		for (;;) pause();
	} else {
		print_ipc_error("Error", &resp);
	}
	ipc_resp_free(&resp);
	return 0;
}

/*
 * Double confirmation for factory reset — requires uppercase Y both times.
 * Stricter than FortiGate's single y/n prompt, appropriate for a security
 * appliance where accidental factory reset could be catastrophic.
 *
 * cli_term_echo_on() switches to canonical mode with echo so fgets()
 * works like a normal terminal (user sees what they type, line editing,
 * Enter submits).  cli_term_echo_off() restores quiet mode afterward.
 */
static int confirm_factory_reset(void)
{
	char buf[16] = {0};
	int ok = 0;

	printf("\n  WARNING: This will erase ALL configuration and logs.\n");
	printf("  The device will return to factory defaults.\n");
	printf("  You must be the first to login after boot — "
	       "the default admin has no password.\n\n");

	cli_term_echo_on();

	printf("  This will delete all your saved and running "
	       "configuration, are you sure? [Y/n] ");
	fflush(stdout);
	if (!fgets(buf, sizeof(buf), stdin) || buf[0] != 'Y') {
		printf("  Aborted.\n");
		goto out;
	}

	printf("  Are you really sure? [Y/n] ");
	fflush(stdout);
	if (!fgets(buf, sizeof(buf), stdin) || buf[0] != 'Y') {
		printf("  Aborted.\n");
		goto out;
	}
	ok = 1;

out:
	cli_term_echo_off();
	return ok;
}

static int cmd_sys_factory_reboot(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	if (!confirm_factory_reset())
		return 0;
	printf("  Begin resetting device to factory defaults...\n");
	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_SYS_FACTORY_RESET,
			 "action=reboot\n", &resp) != 0) {
		printf("  Error: could not contact management daemon.\n");
	} else if (resp.status == SG_OK) {
		printf("  Factory reset complete. Rebooting...\n");
		ipc_resp_free(&resp);
		for (;;) pause();
	} else {
		print_ipc_error("Error", &resp);
	}
	ipc_resp_free(&resp);
	return 0;
}

static int cmd_sys_factory_shutdown(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;
	if (!confirm_factory_reset())
		return 0;
	printf("  Begin resetting device to factory defaults...\n");
	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_SYS_FACTORY_RESET,
			 "action=shutdown\n", &resp) != 0) {
		printf("  Error: could not contact management daemon.\n");
	} else if (resp.status == SG_OK) {
		printf("  Factory reset complete. Shutting down...\n");
		ipc_resp_free(&resp);
		for (;;) pause();
	} else {
		print_ipc_error("Error", &resp);
	}
	ipc_resp_free(&resp);
	return 0;
}

static int cmd_diag_top(const char *args, const char *permissions)
{
	(void)permissions;
	int interval = 1;
	int max_procs = 20;

	if (args && *args) {
		const char *p = args;
		while (*p == ' ') p++;
		if (*p) {
			interval = atoi(p);
			if (interval < 1) interval = 1;
			if (interval > 3600) interval = 3600;	/* avoid *1000 int overflow */
			/* Skip to next arg */
			while (*p && *p != ' ') p++;
			while (*p == ' ') p++;
			if (*p) {
				max_procs = atoi(p);
				if (max_procs < 1) max_procs = 1;
			}
		}
	}
	diag_show_top(interval, max_procs);
	return 0;
}

static int cmd_diag_resources(const char *args, const char *permissions)
{
	(void)permissions;
	const char *which = args;
	if (which) {
		while (*which == ' ')
			which++;
	}
	if (!which || !*which)
		which = "all";
	diag_show_resources(which);
	return 0;
}

/* ── NTP diagnostic handler ──────────────���───────────────────────────── */

static int cmd_diag_ntp(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_DIAG_NTP, "", &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		print_ipc_error("Error", &resp);
		ipc_resp_free(&resp);
		return 0;
	}

	/* Parse key=value lines from response */
	char server[128] = {0}, status[16] = {0};
	char pid[16] = {0}, timebuf[64] = {0};
	const char *p = resp.payload;
	while (p && *p) {
		const char *eol = strchr(p, '\n');
		size_t len = eol ? (size_t)(eol - p) : strlen(p);
		char line[256];
		if (len >= sizeof(line)) len = sizeof(line) - 1;
		memcpy(line, p, len);
		line[len] = '\0';

		char *eq = strchr(line, '=');
		if (eq) {
			*eq = '\0';
			const char *val = eq + 1;
			if (strcmp(line, "server") == 0)
				snprintf(server, sizeof(server), "%s", val);
			else if (strcmp(line, "status") == 0)
				snprintf(status, sizeof(status), "%s", val);
			else if (strcmp(line, "pid") == 0)
				snprintf(pid, sizeof(pid), "%s", val);
			else if (strcmp(line, "time") == 0)
				snprintf(timebuf, sizeof(timebuf), "%s", val);
		}

		if (!eol) break;
		p = eol + 1;
	}

	printf("  NTP server : %s\n", server[0] ? server : "(none)");
	printf("  NTP status : %s", status);
	if (strcmp(status, "running") == 0 && pid[0] &&
	    strcmp(pid, "0") != 0)
		printf(" (pid %s)", pid);
	printf("\n");
	printf("  System time: %s\n", timebuf[0] ? timebuf : "(unknown)");

	ipc_resp_free(&resp);
	return 0;
}

/* ── Disk diagnostic handlers ──────────────��──────────────────────────── */

static int cmd_diag_disk_list(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_DISK_LIST, "", &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		print_ipc_error("Error", &resp);
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

static int cmd_diag_disk_info(const char *args, const char *permissions)
{
	(void)permissions;

	if (!args || !*args) {
		printf("  Usage: execute diagnose disk info <device|partition>\n");
		printf("  Example: execute diagnose disk info mmcblk0\n");
		printf("           execute diagnose disk info mmcblk0p3\n");
		return 0;
	}

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_DISK_INFO, args, &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		print_ipc_error("Error", &resp);
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

static int cmd_diag_disk_smart(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_DISK_SMART, "", &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		print_ipc_error("Error", &resp);
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

/* ── Session diagnostic handler ──────────────────────────────────────── */

static int cmd_diag_session(const char *args, const char *permissions)
{
	(void)permissions;

	const char *sub = args;
	while (sub && *sub == ' ')
		sub++;

	/* ── status: live connection table (conntrack) ──────────────── */
	if (!sub || !*sub || strcmp(sub, "status") == 0) {
		struct ipc_response resp = {0};
		int rc = ipc_send_str(SG_CMD_SHOW_SESSIONS, "", &resp);
		if (rc != 0 || resp.status != SG_OK) {
			printf("  Connection tracking not available.\n");
			ipc_resp_free(&resp);
			return 0;
		}
		printf("  === Active Connections (conntrack) ===\n");
		if (resp.payload && resp.payload[0])
			printf("%s", resp.payload);
		else
			printf("  No active connections.\n");
		ipc_resp_free(&resp);
		return 0;
	}

	/* ── stats: conntrack flow count + pkt_forward counters ─────── */
	if (strcmp(sub, "stats") == 0) {
		struct ipc_response resp = {0};
		int rc = ipc_send_str(SG_CMD_SESSION_STATS, "", &resp);
		if (rc != 0 || resp.status != SG_OK) {
			print_ipc_error("Error", &resp);
			ipc_resp_free(&resp);
			return 0;
		}
		const char *p = resp.payload ? resp.payload : "";
		long long active = 0, forwarded = 0, dropped = 0, anomaly_dropped = 0;
		int ct_ok = 0, pkt_fwd_loaded = 0;
		const char *kv;
		kv = strstr(p, "conntrack_available=");
		if (kv) ct_ok            = (int)strtol(kv + 20, NULL, 10);
		kv = strstr(p, "pkt_forward_loaded=");
		if (kv) pkt_fwd_loaded   = (int)strtol(kv + 19, NULL, 10);
		kv = strstr(p, "active=");
		if (kv) active           = strtoll(kv + 7, NULL, 10);
		kv = strstr(p, "forwarded=");
		if (kv) forwarded        = strtoll(kv + 10, NULL, 10);
		kv = strstr(p, "\ndropped=");
		if (kv) dropped          = strtoll(kv + 9, NULL, 10);
		kv = strstr(p, "anomaly_dropped=");
		if (kv) anomaly_dropped  = strtoll(kv + 16, NULL, 10);

		printf("  === Session Statistics ===\n");
		printf("  conntrack      : %s\n", ct_ok          ? C_GREEN "available" C_NC : C_RED "unavailable" C_NC);
		printf("  pkt_forward.ko : %s\n", pkt_fwd_loaded ? C_GREEN "loaded" C_NC : C_RED "not loaded" C_NC);
		printf("  Active flows   : %lld\n", active);
		if (pkt_fwd_loaded) {
			printf("  Forwarded      : %lld\n", forwarded);
			printf("  Dropped        : %lld\n", dropped);
			printf("  L3/L4 anomaly  : %lld\n", anomaly_dropped);
		}
		ipc_resp_free(&resp);
		return 0;
	}

	/* ── clear: flush all sessions ───────────────────────────────── */
	if (strcmp(sub, "clear") == 0) {
		printf("  WARNING: This will drop all active sessions.\n");
		printf("  Existing connections will be interrupted.\n");
		printf("  Continue? [y/N] ");
		fflush(stdout);
		cli_term_echo_on();
		char confirm[8] = {0};
		if (!fgets(confirm, sizeof(confirm), stdin) ||
		    (confirm[0] != 'y' && confirm[0] != 'Y')) {
			cli_term_echo_off();
			printf("  Cancelled.\n");
			return 0;
		}
		cli_term_echo_off();

		struct ipc_response resp = {0};
		int rc = ipc_send_str(SG_CMD_SESSION_CLEAR, "", &resp);
		if (rc != 0 || resp.status != SG_OK) {
			print_ipc_error("Error", &resp);
			ipc_resp_free(&resp);
			return 0;
		}
		const char *p = resp.payload ? resp.payload : "";
		long long flushed = 0;
		const char *kv = strstr(p, "flushed=");
		if (kv) flushed = strtoll(kv + 8, NULL, 10);
		printf("  Flushed %lld session(s).\n", flushed);
		ipc_resp_free(&resp);
		return 0;
	}

	/* ── ml: per-flow ML features (conntrack CTA_ML) ─────────────── */
	if (strcmp(sub, "ml") == 0) {
		struct ipc_response resp = {0};
		int rc = ipc_send_str(SG_CMD_SESSION_ML, "", &resp);
		if (rc != 0 || resp.status != SG_OK) {
			print_ipc_error("Error", &resp);
			ipc_resp_free(&resp);
			return 0;
		}
		printf("  === Per-flow ML Features ===\n");
		if (resp.payload && resp.payload[0])
			printf("%s", resp.payload);
		else
			printf("  No flows with features.\n");
		ipc_resp_free(&resp);
		return 0;
	}

	printf("  Unknown subcommand: %s\n", sub);
	printf("  Usage: execute diagnose session [status|stats|clear|ml]\n");
	return 0;
}

/* ── Selftest suite table ─────────────────────────────────────────────── */

/*
 * Each suite has a name (for CLI selection) and a runner function.
 * Runner signature variants:
 *   - "perms" variant: takes (mode, permissions, out)
 *   - "plain" variant: takes (mode, out)
 *
 * We unify them through a wrapper that carries 'permissions' via
 * a file-scoped variable (selftest is single-threaded, non-reentrant).
 */
static const char *st_permissions;

typedef int (*st_runner_t)(int mode, diag_result_t *out);

static int st_run_permissions(int mode, diag_result_t *out)
{
	return cli_diagnose_test_permissions(mode, st_permissions, out);
}

static int st_run_configure(int mode, diag_result_t *out)
{
	return cli_diagnose_test_configure(mode, out);
}

static int st_run_firewall(int mode, diag_result_t *out)
{
	return cli_diagnose_test_firewall(mode, out);
}

static int st_run_upgrade(int mode, diag_result_t *out)
{
	return cli_diagnose_test_upgrade(mode, out);
}

static int st_run_sandbox(int mode, diag_result_t *out)
{
	return cli_diagnose_test_sandbox(mode, out);
}

static int st_run_database(int mode, diag_result_t *out)
{
	return cli_diagnose_test_database(mode, out);
}

static int st_run_disk(int mode, diag_result_t *out)
{
	return cli_diagnose_test_disk(mode, out);
}

static int st_run_dhcp(int mode, diag_result_t *out)
{
	return cli_diagnose_test_dhcp(mode, out);
}

static int st_run_supervisor(int mode, diag_result_t *out)
{
	return cli_diagnose_test_supervisor(mode, out);
}

static int st_run_webd(int mode, diag_result_t *out)
{
	return cli_diagnose_test_webd(mode, out);
}

static int st_run_busybox(int mode, diag_result_t *out)
{
	return cli_diagnose_test_busybox(mode, out);
}

static int st_run_session(int mode, diag_result_t *out)
{
	return cli_diagnose_test_session(mode, out);
}

static const struct {
	const char  *name;
	st_runner_t  run;
} selftest_suites[] = {
	{ "permissions", st_run_permissions },
	{ "configure",   st_run_configure },
	{ "firewall",    st_run_firewall },
	{ "upgrade",     st_run_upgrade },
	{ "sandbox",     st_run_sandbox },
	{ "database",    st_run_database },
	{ "disk",        st_run_disk },
	{ "dhcp",        st_run_dhcp },
	{ "supervisor",  st_run_supervisor },
	{ "webd",        st_run_webd },
	{ "busybox",     st_run_busybox },
	{ "session",     st_run_session },
	{ NULL,          NULL }
};

/*
 * Run one or more selftest suites and print summary.
 *
 * Usage:
 *   execute diagnose selftest              — all suites, basic mode
 *   execute diagnose selftest full         — all suites, full mode (IPC)
 *   execute diagnose selftest disk         — disk suite only, full mode
 *   execute diagnose selftest database     — database suite only, full mode
 *
 * Selecting a specific suite always runs in full mode (mode=1),
 * since targeting a single suite implies you want the thorough check.
 */
static int cmd_diag_selftest(const char *args, const char *permissions)
{
	int mode = 0;
	int suite_idx = -1;  /* -1 = all suites */

	st_permissions = permissions;

	if (args) {
		while (*args == ' ')
			args++;
		if (*args) {
			if (strcmp(args, "full") == 0) {
				mode = 1;
			} else {
				/* Look up suite name */
				for (int i = 0; selftest_suites[i].name; i++) {
					if (strcmp(args,
						   selftest_suites[i].name) == 0) {
						suite_idx = i;
						break;
					}
				}
				if (suite_idx < 0) {
					printf("  Unknown suite: %s\n", args);
					printf("  Available suites:");
					for (int i = 0; selftest_suites[i].name; i++)
						printf(" %s",
						       selftest_suites[i].name);
					printf("\n  Usage: execute diagnose selftest"
					       " [full | <suite>]\n");
					return 0;
				}
				/* Single suite always runs full */
				mode = 1;
			}
		}
	}

	int fail = 0;
	diag_result_t r, totals = {0, 0, 0};

	int first_idx = 0;
	int last_idx = 0;
	while (selftest_suites[last_idx].name)
		last_idx++;
	last_idx--;

	if (suite_idx >= 0) {
		first_idx = suite_idx;
		last_idx = suite_idx;
	}

	for (int i = first_idx; i <= last_idx; i++) {
		r = (diag_result_t){0, 0, 0};
		fail += selftest_suites[i].run(mode, &r);
		totals.passed += r.passed;
		totals.failed += r.failed;
		totals.total  += r.total;
	}

	printf("\n  ══════════════════════════════════════\n");
	printf("  Total: %d/%d passed", totals.passed, totals.total);
	if (totals.failed > 0)
		printf(C_RED ", %d FAILED" C_NC, totals.failed);
	printf("\n");
	if (fail == 0)
		printf(C_GREEN "  All test suites passed." C_NC "\n");
	else
		printf(C_RED "  %d test suite(s) had failures." C_NC "\n", fail);
	printf("  ══════════════════════════════════════\n\n");
	return 0;
}

static int cmd_diag_pentest(const char *args, const char *permissions)
{
	int mode = 0;
	if (args) {
		while (*args == ' ')
			args++;
		if (strcmp(args, "full") == 0)
			mode = 1;
		else if (*args != '\0') {
			printf("  Unknown argument: %s\n", args);
			printf("  Usage: execute diagnose pentest [full]\n");
			return 0;
		}
	}
	diag_result_t r = {0, 0, 0};
	int fail = cli_diagnose_test_pentest(mode, permissions, &r);

	printf("  ══════════════════════════════════════\n");
	printf("  Pentest: %d/%d passed", r.passed, r.total);
	if (r.failed > 0)
		printf(C_RED ", %d FAILED" C_NC, r.failed);
	printf("\n");
	if (fail == 0)
		printf(C_GREEN "  All pentest checks passed." C_NC "\n");
	else
		printf(C_RED "  %d pentest check(s) failed." C_NC "\n", r.failed);
	printf("  ══════════════════════════════════════\n\n");
	return 0;
}

static int cmd_diag_fw_policy(const char *args, const char *permissions)
{
	(void)permissions;

	/* Check if "nat" subcommand was passed (already resolved by dispatcher) */
	const char *table = "filter";
	if (args && *args) {
		const char *p = args;
		while (*p == ' ')
			p++;
		if (strncmp(p, "nat", 3) == 0)
			table = "nat";
	}

	char payload[SG_PAYLOAD_MAX];
	snprintf(payload, sizeof(payload), "table=%s\n", table);

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_DIAG_FW_IPTABLES, payload, &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		print_ipc_error("Failed", &resp);
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

static int cmd_diag_nat_policy(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_DIAG_FW_IPTABLES, "table=nat\n", &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		print_ipc_error("Failed", &resp);
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

static int cmd_diag_fw_ipset(const char *args, const char *permissions)
{
	(void)permissions;

	const char *p = args ? args : "";
	while (*p == ' ')
		p++;
	if (!*p) {
		printf("  Usage: execute diagnose firewall ipset <address-object>\n");
		return 0;
	}

	char payload[SG_PAYLOAD_MAX];
	snprintf(payload, sizeof(payload), "name=%s\n", p);

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_DIAG_FW_IPSET, payload, &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		print_ipc_error("Failed", &resp);
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

static int cmd_diag_ips_status(const char *args, const char *permissions)
{
	(void)args; (void)permissions;
	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_IPS_STATUS, "", &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}
	if (resp.status != SG_OK) {
		print_ipc_error("Failed", &resp);
	} else if (resp.payload && resp.payload_len > 0) {
		printf("%s", resp.payload);
	}
	ipc_resp_free(&resp);
	return 0;
}

static int cmd_diag_ips_alerts(const char *args, const char *permissions)
{
	(void)permissions;
	char payload[64] = "";
	if (args && args[0])
		snprintf(payload, sizeof(payload), "lines=%s\n", args);
	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_IPS_ALERTS, payload, &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}
	if (resp.status != SG_OK)
		print_ipc_error("Failed", &resp);
	else if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);
	ipc_resp_free(&resp);
	return 0;
}

static int cmd_ips_reload(const char *args, const char *permissions)
{
	(void)args; (void)permissions;
	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_IPS_REBUILD, "", &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}
	if (resp.status != SG_OK)
		print_ipc_error("IPS reload failed", &resp);
	else if (resp.payload && resp.payload_len > 0)
		printf("%s\n", resp.payload);
	else
		printf("IPS service reloaded.\n");
	ipc_resp_free(&resp);
	return 0;
}

static int cmd_ips_update_now(const char *args, const char *permissions)
{
	(void)args; (void)permissions;
	printf("Downloading enabled rulesets — this may take a moment...\n");
	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_IPS_UPDATE_NOW, "", &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}
	if (resp.status != SG_OK)
		print_ipc_error("IPS update failed", &resp);
	else if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);
	else
		printf("Update complete.\n");
	ipc_resp_free(&resp);
	return 0;
}

static int cmd_show_ips_profiles(const char *args, const char *permissions)
{
	(void)args; (void)permissions;

	/* List all IPS profiles */
	struct ipc_response lresp;
	if (ipc_send_str(SG_CMD_CFG_LIST, "security_ips-profile", &lresp) != 0 ||
	    lresp.status != SG_OK || !lresp.payload || !lresp.payload[0]) {
		ipc_resp_free(&lresp);
		printf("  No IPS profiles configured.\n");
		return 0;
	}

	/* Walk each profile ID */
	char *ids = lresp.payload;
	char *id = ids;
	while (id && *id) {
		char *nl = strchr(id, '\n');
		if (nl) *nl = '\0';
		if (!*id) { if (nl) id = nl + 1; else break; continue; }

		/* Fetch profile fields */
		char sec[256];
		snprintf(sec, sizeof(sec), "security_ips-profile:%s", id);
		struct ipc_response gresp;
		if (ipc_send_str(SG_CMD_CFG_GET, sec, &gresp) == 0 &&
		    gresp.status == SG_OK && gresp.payload) {
			char status[32]  = "enable";
			char comment[128] = "";
			sg_kv_get(gresp.payload, "status",  status,  sizeof(status));
			sg_kv_get(gresp.payload, "comment", comment, sizeof(comment));
			printf("  %-20s  %-8s  %s\n", id, status,
			       comment[0] ? comment : "(no comment)");
		}
		ipc_resp_free(&gresp);

		/* Fetch filters for this profile */
		struct ipc_response fresp;
		if (ipc_send_str(SG_CMD_CFG_LIST, "security_ips-filter", &fresp) == 0 &&
		    fresp.status == SG_OK && fresp.payload && fresp.payload[0]) {
			char *fid = fresp.payload;
			int first = 1;
			while (fid && *fid) {
				char *fnl = strchr(fid, '\n');
				if (fnl) *fnl = '\0';
				if (!*fid) { if (fnl) fid = fnl + 1; else break; continue; }

				char fsec[256];
				snprintf(fsec, sizeof(fsec), "security_ips-filter:%s", fid);
				struct ipc_response fgresp;
				if (ipc_send_str(SG_CMD_CFG_GET, fsec, &fgresp) == 0 &&
				    fgresp.status == SG_OK && fgresp.payload) {
					char fp[64] = "", ftype[32] = "", fval[128] = "", faction[32] = "default";
					sg_kv_get(fgresp.payload, "profile", fp,      sizeof(fp));
					sg_kv_get(fgresp.payload, "type",    ftype,   sizeof(ftype));
					sg_kv_get(fgresp.payload, "value",   fval,    sizeof(fval));
					sg_kv_get(fgresp.payload, "action",  faction, sizeof(faction));
					if (strcmp(fp, id) == 0) {
						if (first) { printf("    Filters:\n"); first = 0; }
						printf("      %-10s  %-40s  %s\n", ftype, fval, faction);
					}
				}
				ipc_resp_free(&fgresp);
				if (fnl) fid = fnl + 1; else break;
			}
		}
		ipc_resp_free(&fresp);

		if (nl) id = nl + 1; else break;
	}
	ipc_resp_free(&lresp);
	return 0;
}

static int cmd_show_ips_filters(const char *args, const char *permissions)
{
	(void)permissions;

	if (!args || !args[0]) {
		printf("  Usage: show ips filter <profile-name>\n");
		return 0;
	}

	/* Validate profile exists */
	char sec[256];
	snprintf(sec, sizeof(sec), "security_ips-profile:%s", args);
	struct ipc_response gresp;
	if (ipc_send_str(SG_CMD_CFG_GET, sec, &gresp) != 0 ||
	    gresp.status != SG_OK) {
		ipc_resp_free(&gresp);
		printf("  Profile '%s' not found.\n", args);
		return 0;
	}
	ipc_resp_free(&gresp);

	/* List all filters, show ones for this profile */
	struct ipc_response lresp;
	if (ipc_send_str(SG_CMD_CFG_LIST, "security_ips-filter", &lresp) != 0 ||
	    lresp.status != SG_OK || !lresp.payload || !lresp.payload[0]) {
		ipc_resp_free(&lresp);
		printf("  No filters for profile '%s'.\n", args);
		return 0;
	}

	int found = 0;
	char *fid = lresp.payload;
	while (fid && *fid) {
		char *nl = strchr(fid, '\n');
		if (nl) *nl = '\0';
		if (!*fid) { if (nl) fid = nl + 1; else break; continue; }

		char fsec[256];
		snprintf(fsec, sizeof(fsec), "security_ips-filter:%s", fid);
		struct ipc_response fgresp;
		if (ipc_send_str(SG_CMD_CFG_GET, fsec, &fgresp) == 0 &&
		    fgresp.status == SG_OK && fgresp.payload) {
			char fp[64] = "", ftype[32] = "", fval[128] = "", faction[32] = "default", fstatus[16] = "enable";
			sg_kv_get(fgresp.payload, "profile", fp,      sizeof(fp));
			sg_kv_get(fgresp.payload, "type",    ftype,   sizeof(ftype));
			sg_kv_get(fgresp.payload, "value",   fval,    sizeof(fval));
			sg_kv_get(fgresp.payload, "action",  faction, sizeof(faction));
			sg_kv_get(fgresp.payload, "status",  fstatus, sizeof(fstatus));
			if (strcmp(fp, args) == 0) {
				if (!found) printf("  Filters for profile '%s':\n", args);
				printf("    %-10s  %-40s  action=%-8s  %s\n",
				       ftype, fval, faction, fstatus);
				found++;
			}
		}
		ipc_resp_free(&fgresp);
		if (nl) fid = nl + 1; else break;
	}
	ipc_resp_free(&lresp);

	if (!found)
		printf("  No filters for profile '%s'.\n", args);
	return 0;
}

static int cmd_ssl_cacert(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_SSL_CACERT, "", &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}
	if (resp.status != SG_OK) {
		print_ipc_error("Failed", &resp);
		ipc_resp_free(&resp);
		return 0;
	}
	/* In nguyên PEM ra stdout — admin copy/scp về cài vào client trust store */
	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);
	ipc_resp_free(&resp);
	return 0;
}

static int cmd_diag_fw_conntrack(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_DIAG_FW_CONNTRACK, "", &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		print_ipc_error("Failed", &resp);
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);
	else
		printf("  No active connections.\n");

	ipc_resp_free(&resp);
	return 0;
}

static int cmd_diag_routes(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_DIAG_ROUTES, "", &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		print_ipc_error("Failed", &resp);
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

static int cmd_diag_dhcp_client(const char *args, const char *permissions)
{
	(void)permissions;

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_DIAG_DHCP_CLIENT, args ? args : "", &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		print_ipc_error("Failed", &resp);
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

static void print_chunk(const char *data, size_t len)
{
	fwrite(data, 1, len, stdout);
	fflush(stdout);
}

static int cmd_ping(const char *args, const char *permissions)
{
	(void)permissions;

	if (!args || !*args) {
		printf("  Usage: execute ping <IPv4/IPv6-address-or-hostname>\n");
		return 0;
	}

	char payload[SG_PAYLOAD_MAX];
	snprintf(payload, sizeof(payload), "target=%s\n", args);

	int st = ipc_send_stream(SG_CMD_NET_PING, payload, print_chunk);
	if (st < 0)
		printf("  Error: could not contact management daemon.\n");
	else if (st != SG_OK)
		printf("  Ping failed: %s\n", sg_status_str((sg_status_t)st));
	return 0;
}

static int cmd_traceroute(const char *args, const char *permissions)
{
	(void)permissions;

	if (!args || !*args) {
		printf("  Usage: execute traceroute <IPv4/IPv6-address-or-hostname>\n");
		return 0;
	}

	char payload[SG_PAYLOAD_MAX];
	snprintf(payload, sizeof(payload), "target=%s\n", args);

	int st = ipc_send_stream(SG_CMD_NET_TRACEROUTE, payload, print_chunk);
	if (st < 0)
		printf("  Error: could not contact management daemon.\n");
	else if (st != SG_OK)
		printf("  Traceroute failed: %s\n", sg_status_str((sg_status_t)st));
	return 0;
}

static int cmd_nslookup(const char *args, const char *permissions)
{
	(void)permissions;

	if (!args || !*args) {
		printf("  Usage: execute nslookup <hostname-or-IP>\n");
		return 0;
	}

	char payload[SG_PAYLOAD_MAX];
	snprintf(payload, sizeof(payload), "target=%s\n", args);

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_NET_NSLOOKUP, payload, &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		print_ipc_error("Nslookup failed", &resp);
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

static int cmd_arping(const char *args, const char *permissions)
{
	(void)permissions;

	if (!args || !*args) {
		printf("  Usage: execute arping <IPv4-address> [interface]\n");
		return 0;
	}

	/* Parse: first word = target, optional second word = interface */
	char target[256], iface[64];
	target[0] = '\0';
	iface[0] = '\0';

	const char *p = args;
	while (*p == ' ')
		p++;
	const char *end = p;
	while (*end && *end != ' ')
		end++;
	size_t tlen = (size_t)(end - p);
	if (tlen >= sizeof(target))
		tlen = sizeof(target) - 1;
	memcpy(target, p, tlen);
	target[tlen] = '\0';

	if (*end) {
		p = end + 1;
		while (*p == ' ')
			p++;
		if (*p) {
			snprintf(iface, sizeof(iface), "%s", p);
			/* Trim trailing spaces */
			size_t ilen = strlen(iface);
			while (ilen > 0 && iface[ilen - 1] == ' ')
				iface[--ilen] = '\0';
		}
	}

	char payload[SG_PAYLOAD_MAX];
	if (iface[0])
		snprintf(payload, sizeof(payload),
			 "target=%s\niface=%s\n", target, iface);
	else
		snprintf(payload, sizeof(payload), "target=%s\n", target);

	int st = ipc_send_stream(SG_CMD_NET_ARPING, payload, print_chunk);
	if (st < 0)
		printf("  Error: could not contact management daemon.\n");
	else if (st != SG_OK)
		printf("  Arping failed: %s\n", sg_status_str((sg_status_t)st));
	return 0;
}

/* ── Log command handlers ─────────────────────────────────────────────── */

static int cmd_log_audit(const char *args, const char *permissions)
{
	(void)permissions;
	char payload[32] = "";
	if (args && *args) {
		/* Optional line count argument */
		snprintf(payload, sizeof(payload), "%s", args);
	}

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_LOG_AUDIT, payload, &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		print_ipc_error("Error", &resp);
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

static int cmd_log_system(const char *args, const char *permissions)
{
	(void)permissions;
	char payload[32] = "";
	if (args && *args) {
		/* Optional line count argument */
		snprintf(payload, sizeof(payload), "%s", args);
	}

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_LOG_SYSTEM, payload, &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		print_ipc_error("Error", &resp);
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

static int cmd_log_mgmtd(const char *args, const char *permissions)
{
	(void)permissions;
	char payload[32] = "";
	if (args && *args)
		snprintf(payload, sizeof(payload), "%s", args);

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_LOG_MGMTD, payload, &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		print_ipc_error("Error", &resp);
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

static int cmd_log_clear_audit(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_LOG_CLEAR_AUDIT, "", &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		print_ipc_error("Error", &resp);
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

/* ── Command table (generated from X-macro definitions) ───────────────── */

#define X(p, d, perm, ma, h) {p, d, perm, ma, h},
static const cmd_entry_t cmd_table[] = {
#include "sg_cmd_defs.h"
	{NULL, NULL, NULL, 0, NULL}  /* sentinel */
};
#undef X

/* ── Argument validation ─────────────────────────────────────────────── */

static int count_tokens(const char *s)
{
	int n = 0;
	while (*s) {
		while (*s == ' ') s++;
		if (*s) { n++; while (*s && *s != ' ') s++; }
	}
	return n;
}

static int cmd_validate_args(const cmd_entry_t *e, const char *args)
{
	if (e->max_args < 0)  return 0;  /* variadic */
	if (!args || !*args)  return 0;  /* no args given */
	int n = count_tokens(args);
	if (n > e->max_args) {
		printf("  Error: too many arguments for '%s'\n", e->path);
		return -1;
	}
	return 0;
}

/* ── Permission OR check ──────────────────────────────────────────────── */

/*
 * Check if user has any of the comma-separated permissions in 'required'.
 * E.g. required="configure,admin" matches if user has "configure" OR "admin".
 * NULL required = no permission needed (always allowed).
 */
static int cmd_check_perm(const char *user_perms, const char *required)
{
	if (!required)
		return 1;

	char buf[256];
	snprintf(buf, sizeof(buf), "%s", required);

	char *tok = buf;
	while (*tok) {
		char *comma = strchr(tok, ',');
		if (comma)
			*comma = '\0';
		if (has_permission(user_perms, tok))
			return 1;
		if (!comma)
			break;
		tok = comma + 1;
	}
	return 0;
}

/* ── Registration ─────────────────────────────────────────────────────── */

void cmd_register_all(const char *permissions)
{
	/* Register commands from the table */
	for (int i = 0; cmd_table[i].path; i++) {
		if (!cmd_check_perm(permissions, cmd_table[i].perm))
			continue;
		cli_register(cmd_table[i].path, cmd_table[i].desc);
	}

	/* Auto-register configure commands from config type registry */
	const sg_type_info_t *types = sg_reg_types();
	for (int i = 0; types[i].name; i++) {
		if (!has_permission(permissions, types[i].perm))
			continue;
		const char *label = sg_reg_type_label(types[i].name);
		char path[256];
		snprintf(path, sizeof(path), "configure %s", label);
		cli_register(path, types[i].desc);
	}
}

/* ── Dispatch ─────────────────────────────────────────────────────────── */

/*
 * Check if 'input' starts with 'prefix' at a word boundary.
 * The prefix must match completely, and the next char in input must be
 * space or end-of-string.
 */
static int starts_with_path(const char *input, const char *prefix)
{
	size_t plen = strlen(prefix);
	if (strncmp(input, prefix, plen) != 0)
		return 0;
	return input[plen] == '\0' || input[plen] == ' ';
}

int cmd_dispatch(const char *resolved, const char *permissions)
{
	if (!resolved)
		return 0;
	while (*resolved == ' ')
		resolved++;
	if (!*resolved)
		return 0;

	/* CLI debug trace */
	if (dbg_enabled() &&
	    strcmp(dbg_get("cli_debug", "0"), "1") == 0)
		fprintf(stderr, "[CLI-DBG] dispatch: %s\n", resolved);

	/* 1. Find longest matching handler */
	const cmd_entry_t *best = NULL;
	size_t best_len = 0;

	for (int i = 0; cmd_table[i].path; i++) {
		if (!cmd_table[i].handler)
			continue;
		size_t plen = strlen(cmd_table[i].path);
		if (plen <= best_len)
			continue;
		if (starts_with_path(resolved, cmd_table[i].path)) {
			best = &cmd_table[i];
			best_len = plen;
		}
	}

	/* 2. If found, permission check + call */
	if (best) {
		if (!cmd_check_perm(permissions, best->perm)) {
			printf("  Permission denied: requires '%s'\n",
			       best->perm);
			return 0;
		}

		const char *args = resolved + best_len;
		while (*args == ' ')
			args++;

		if (dbg_enabled() &&
		    strcmp(dbg_get("cli_debug", "0"), "1") == 0)
			fprintf(stderr, "[CLI-DBG] handler: %s args=\"%s\"\n",
				best->path, args);

		if (cmd_validate_args(best, args) != 0)
			return 0;
		return best->handler(args, permissions);
	}

	/* 3. Auto-usage: resolved is a prefix of table entries */
	size_t rlen = strlen(resolved);
	int found_prefix = 0;

	/* Collect direct child subcommands (one level deeper) */
	const char *shown[CMD_MAX_SHOWN];
	int nshown = 0;

	for (int i = 0; cmd_table[i].path; i++) {
		const char *path = cmd_table[i].path;
		size_t plen = strlen(path);

		/* path must start with resolved + space */
		if (plen <= rlen)
			continue;
		if (strncmp(path, resolved, rlen) != 0)
			continue;
		if (path[rlen] != ' ')
			continue;
		if (!cmd_check_perm(permissions, cmd_table[i].perm))
			continue;

		/* Extract the next word after the prefix */
		const char *child = path + rlen + 1;
		const char *sp = strchr(child, ' ');
		size_t clen = sp ? (size_t)(sp - child) : strlen(child);

		/* Deduplicate */
		int dup = 0;
		for (int j = 0; j < nshown; j++) {
			if (strlen(shown[j]) == clen &&
			    strncmp(shown[j], child, clen) == 0) {
				dup = 1;
				break;
			}
		}
		if (dup)
			continue;

		if (!found_prefix) {
			printf("  Available subcommands:\n");
			found_prefix = 1;
		}

		/* Find the entry for exactly "resolved child" for its desc */
		char full[512];
		snprintf(full, sizeof(full), "%.*s", (int)(rlen + 1 + clen),
			 path);
		const char *desc = "";
		for (int k = 0; cmd_table[k].path; k++) {
			if (strcmp(cmd_table[k].path, full) == 0) {
				desc = cmd_table[k].desc;
				break;
			}
		}

		printf("    %-20.*s %s\n", (int)clen, child, desc);

		if (nshown < CMD_MAX_SHOWN - 1)
			shown[nshown++] = child;
	}

	if (found_prefix)
		return 0;

	/* 4. Truly unknown */
	printf("  Unknown command: %s\n", resolved);
	printf("  Type 'help' or '?' for available commands.\n");
	return 0;
}
