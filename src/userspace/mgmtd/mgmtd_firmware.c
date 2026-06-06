/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_firmware.c — Firmware upgrade handlers for stargazer-mgmtd
 *
 * Extracted from stargazer-mgmtd.c to keep the monolith manageable.
 * Contains:
 *   - Firmware state file management
 *   - UPGRADE_STATUS, UPGRADE_START, UPGRADE_PROGRESS, UPGRADE_CANCEL handlers
 *
 * Cancel mechanism:
 *   The parent process creates /tmp/sg-fw-cancel when it receives
 *   SG_CMD_UPGRADE_CANCEL.  The child process checks for this file
 *   at natural checkpoints (between steps 1-4, and inside the download
 *   poll loop).  Steps 5+ are past the point of no return.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include "mgmtd_internal.h"
#include "mgmtd_apply.h"

/* ── Firmware upgrade state file ─────────────────────────────────────────── */

#define FW_STATE_FILE     "/tmp/sg-fw-upgrade.state"
#define FW_STATE_FILE_TMP "/tmp/sg-fw-upgrade.state.tmp"
#define FW_CANCEL_FILE    "/tmp/sg-fw-cancel"
#define FW_DL_FILE        "/tmp/sg-fw-download/firmware.tar.gz"
/* webd stages each upload at a unique mkstemp path "/tmp/sg-fw-upload.*"
 * passed in the IPC payload; handle_upgrade_from_file validates it by
 * prefix (no fixed shared name — see the race fix). */

/*
 * Write firmware upgrade progress to state file atomically.
 * The child process calls this at each step so the parent (serving
 * UPGRADE_PROGRESS polls) always reads a complete, consistent file.
 *
 * A step history log is appended after a "---" separator so the CLI
 * can print all steps even if polling missed some (fast steps).
 */
#define FW_STEPS_LOG_MAX 2048
static char fw_steps_log[FW_STEPS_LOG_MAX];
static size_t fw_steps_log_len;
static int fw_last_logged_step = -1;

static void fw_write_state(int step, int total, const char *status,
			   const char *message, const char *version)
{
	/* Only append to step log when step NUMBER changes (not every
	 * progress message within the same step like download KB updates) */
	if (strcmp(status, "running") == 0 && message && message[0] &&
	    step != fw_last_logged_step) {
		char entry[256];
		int n = snprintf(entry, sizeof(entry), "[%d/%d] %s\n",
				 step, total, message);
		/* snprintf returns the untruncated length; clamp to what
		 * entry holds so a long message cannot make memcpy over-read. */
		if (n > 0 && (size_t)n >= sizeof(entry))
			n = (int)sizeof(entry) - 1;
		if (n > 0 && fw_steps_log_len + (size_t)n < FW_STEPS_LOG_MAX) {
			memcpy(fw_steps_log + fw_steps_log_len, entry, (size_t)n);
			fw_steps_log_len += (size_t)n;
			fw_steps_log[fw_steps_log_len] = '\0';
		}
		fw_last_logged_step = step;
	}

	FILE *fp = fopen(FW_STATE_FILE_TMP, "w");
	if (!fp)
		return;
	fchmod(fileno(fp), 0600);
	fprintf(fp, "step=%d\ntotal=%d\nstatus=%s\nmessage=%s\nversion=%s\n",
		step, total, status, message, version ? version : "");
	/* Append step history log after separator */
	if (fw_steps_log_len > 0)
		fprintf(fp, "---\n%s", fw_steps_log);
	fclose(fp);
	rename(FW_STATE_FILE_TMP, FW_STATE_FILE);
}

/* ── Legacy run_cmd (local copy for firmware child process) ──────────────── */

static char *fw_run_cmd(const char *cmd)
{
	FILE *fp = popen(cmd, "r");
	if (!fp) return NULL;

	size_t bufsize = 4096, used = 0;
	char *buf = malloc(bufsize);
	if (!buf) { pclose(fp); return NULL; }

	char line[1024];
	while (fgets(line, sizeof(line), fp)) {
		size_t llen = strlen(line);
		while (used + llen + 1 > bufsize) {
			bufsize *= 2;
			char *nb = realloc(buf, bufsize);
			if (!nb) { free(buf); pclose(fp); return NULL; }
			buf = nb;
		}
		memcpy(buf + used, line, llen);
		used += llen;
	}
	buf[used] = '\0';
	pclose(fp);
	return buf;
}

static void fw_run_cmd_ignore(const char *cmd)
{
	free(fw_run_cmd(cmd));
}

/* ── Cancel check (child process only) ───────────────────────────────────── */

/*
 * fw_cancel_cleanup — clean up temp files.
 * Called by fw_check_cancel() when cancel is detected.
 */
static void fw_cancel_cleanup(void)
{
	fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
	unlink(FW_CANCEL_FILE);
}

/*
 * fw_check_cancel — check if the cancel flag file exists.
 *
 * If cancelled: writes "cancelled" state, cleans up, closes DB, and
 * calls _exit(1).  Does NOT return in that case.
 *
 * If not cancelled: returns 0.
 */
static int fw_check_cancel(void)
{
	if (access(FW_CANCEL_FILE, F_OK) != 0)
		return 0;

	mgmt_log("INFO", "firmware upgrade cancelled by user");
	fw_write_state(0, 6, "cancelled",
		       "Firmware upgrade cancelled by user.", "");
	fw_cancel_cleanup();
	sg_db_close();
	_exit(1);
	/* NOTREACHED */
	return 1;
}

/* ── Firmware handlers ───────────────────────────────────────────────────── */

/* g_listen_fd is needed by the UPGRADE_START child to close the listen socket */
extern int g_listen_fd;

int handle_upgrade_status(int client_fd, const char *user,
			  const char *payload, const sg_request_hdr_t *hdr)
{
	(void)user; (void)payload; (void)hdr;
	char result[2048];
	int off = 0;

	off += snprintf(result + off, sizeof(result) - (size_t)off,
			"  === Firmware Status ===\n");

	/* Running version from build-time define or runtime file */
#ifdef VERSION
	off += snprintf(result + off, sizeof(result) - (size_t)off,
			"  Running version: %s\n", VERSION);
#else
	{
		char verbuf[64] = {0};
		FILE *vf = fopen("/tmp/stargazer-fw-version", "r");
		if (vf) {
			if (fgets(verbuf, sizeof(verbuf), vf)) {
				char *nl = strchr(verbuf, '\n');
				if (nl) *nl = '\0';
			}
			fclose(vf);
		}
		off += snprintf(result + off, sizeof(result) - (size_t)off,
				"  Running version: %s\n",
				verbuf[0] ? verbuf : "unknown");
	}
#endif

	/* Kernel version via uname() */
	struct utsname uts;
	if (uname(&uts) == 0)
		off += snprintf(result + off, sizeof(result) - (size_t)off,
				"  Kernel version: %s\n", uts.release);

	/* Check for staged firmware */
	FILE *mf = fopen("/tmp/sg-fw-staged/manifest.txt", "r");
	if (mf) {
		char line[256];
		char staged_ver[256] = {0};
		while (fgets(line, sizeof(line), mf)) {
			if (strncmp(line, "version=", 8) == 0) {
				char *nl = strchr(line + 8, '\n');
				if (nl) *nl = '\0';
				snprintf(staged_ver, sizeof(staged_ver),
					 "%s", line + 8);
			}
		}
		fclose(mf);
		if (staged_ver[0])
			off += snprintf(result + off,
					sizeof(result) - (size_t)off,
					"  Staged version: %s\n",
					staged_ver);
	}

	/* Firmware partition device (raw FIT image, GPT name "firmware").
	 * BusyBox blkid does NOT show PARTLABEL (it reads filesystem
	 * superblocks, not GPT entries).  A raw FIT partition has no
	 * filesystem, so blkid returns nothing.  Instead, read the GPT
	 * partition name from sysfs: /sys/class/block/<dev>/uevent
	 * contains PARTNAME=<gpt_name> on all kernels with GPT support. */
	{
		const char *kcands[] = {
			"mmcblk0p4", "mmcblk1p4", NULL
		};
		char *kdev = NULL;
		for (int i = 0; kcands[i]; i++) {
			char devpath[64];
			snprintf(devpath, sizeof(devpath),
				 "/dev/%s", kcands[i]);
			if (access(devpath, F_OK) != 0)
				continue;
			/* Read GPT partition name from sysfs uevent */
			char uevent[128];
			snprintf(uevent, sizeof(uevent),
				 "/sys/class/block/%s/uevent", kcands[i]);
			FILE *f = fopen(uevent, "r");
			if (!f)
				continue;
			char line[256];
			while (fgets(line, sizeof(line), f)) {
				if (strncmp(line, "PARTNAME=", 9) == 0) {
					char *name = line + 9;
					/* Strip trailing newline */
					size_t nl = strlen(name);
					if (nl > 0 && name[nl - 1] == '\n')
						name[nl - 1] = '\0';
					if (strcmp(name, "firmware") == 0 ||
					    strcmp(name, "kernel") == 0) {
						kdev = malloc(strlen(devpath) + 1);
						if (kdev)
							strcpy(kdev, devpath);
					}
					break;
				}
			}
			fclose(f);
			if (kdev)
				break;
		}
		if (kdev) {
			off += snprintf(result + off,
					sizeof(result) - (size_t)off,
					"  Firmware partition: %s\n", kdev);
		} else {
			off += snprintf(result + off,
					sizeof(result) - (size_t)off,
					"  Firmware partition: not found\n");
		}
		free(kdev);
	}

	(void)off;
	send_ok(client_fd, NULL, result);
	return 0;
}

/*
 * fw_child_upgrade_steps — steps 2-6 of the firmware upgrade, run in the
 * child process after firmware.tar.gz is present at FW_DL_FILE.
 *
 * source_label: written to the audit log, e.g. "url=https://..." or
 *               "source=upload".
 *
 * Always exits the child process via _exit(); never returns.
 */
static void __attribute__((noreturn))
fw_child_upgrade_steps(const char *fw_user, const char *source_label)
{
	/* Step 2: Extract firmware package */
	fw_write_state(2, 6, "running", "Extracting firmware package...", "");
	char *exout = fw_run_cmd("tar -xzf " FW_DL_FILE
				 " -C /tmp/sg-fw-staged/ 2>&1");
	if (access("/tmp/sg-fw-staged/manifest.txt", F_OK) != 0) {
		mgmt_log("ERROR", "firmware extract failed or missing manifest: %s",
			 exout ? exout : "(no output)");
		free(exout);
		fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
		fw_write_state(2, 6, "error",
			       "Invalid firmware package (missing manifest.txt)", "");
		sg_db_close();
		_exit(1);
	}
	free(exout);

	/* Read manifest */
	char manifest[2048] = {0};
	FILE *mf = fopen("/tmp/sg-fw-staged/manifest.txt", "r");
	if (mf) {
		size_t rd = fread(manifest, 1, sizeof(manifest) - 1, mf);
		manifest[rd] = '\0';
		fclose(mf);
	}

	char fw_version[64], fit_sha[128];
	extract_val(manifest, "version", fw_version, sizeof(fw_version));
	extract_val(manifest, "fit_sha256", fit_sha, sizeof(fit_sha));

	if (!fw_version[0] || !fit_sha[0]) {
		fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
		fw_write_state(2, 6, "error",
			       "Incomplete manifest (missing version or fit_sha256)", "");
		sg_db_close();
		_exit(1);
	}

	/* Verify stargazer.itb exists */
	if (access("/tmp/sg-fw-staged/stargazer.itb", F_OK) != 0) {
		fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
		fw_write_state(2, 6, "error",
			       "Invalid firmware package (missing stargazer.itb)", "");
		sg_db_close();
		_exit(1);
	}

	/* Cancel check: before step 3 */
	fw_check_cancel();

	/* Step 3: Verify FIT image checksum */
	fw_write_state(3, 6, "running", "Verifying FIT image checksum...", "");
	char *fsum = fw_run_cmd("sha256sum /tmp/sg-fw-staged/stargazer.itb 2>/dev/null "
			     "| cut -d' ' -f1");

	if (fsum) { char *nl = strchr(fsum, '\n'); if (nl) *nl = '\0'; }

	if (!fsum || strcmp(fsum, fit_sha) != 0) {
		mgmt_log("ERROR", "firmware checksum mismatch: "
			 "fit=%s (expect %s)",
			 fsum ? fsum : "null", fit_sha);
		free(fsum);
		fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
		fw_write_state(3, 6, "error",
			       "Firmware checksum verification failed", "");
		sg_db_close();
		_exit(1);
	}
	free(fsum);

	mgmt_log("INFO", "firmware v%s verified, installing...", fw_version);

	/* Cancel check: before step 4 */
	fw_check_cancel();

	/* Step 4: Find firmware partition via sysfs PARTNAME */
	fw_write_state(4, 6, "running", "Locating firmware partition...", "");
	char kpart[64] = {0};
	{
		const char *candidates[] = {
			"mmcblk0p4", "mmcblk1p4", NULL
		};
		for (int i = 0; candidates[i]; i++) {
			char devpath[64];
			snprintf(devpath, sizeof(devpath),
				 "/dev/%s", candidates[i]);
			if (access(devpath, F_OK) != 0)
				continue;
			char uevent[128];
			snprintf(uevent, sizeof(uevent),
				 "/sys/class/block/%s/uevent",
				 candidates[i]);
			FILE *f = fopen(uevent, "r");
			if (!f)
				continue;
			char line[256];
			while (fgets(line, sizeof(line), f)) {
				if (strncmp(line, "PARTNAME=", 9) == 0) {
					char *name = line + 9;
					size_t nl = strlen(name);
					if (nl > 0 && name[nl - 1] == '\n')
						name[nl - 1] = '\0';
					if (strcmp(name, "firmware") == 0 ||
					    strcmp(name, "kernel") == 0) {
						snprintf(kpart, sizeof(kpart),
							 "%s", devpath);
					}
					break;
				}
			}
			fclose(f);
			if (kpart[0])
				break;
		}
	}

	if (!kpart[0]) {
		fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
		fw_write_state(4, 6, "error",
			       "Firmware partition not found "
			       "(expected \"firmware\" or \"kernel\")", "");
		sg_db_close();
		_exit(1);
	}

	mgmt_log("INFO", "firmware partition: %s", kpart);

	/* Last cancel checkpoint — after this we are committed. */
	fw_check_cancel();

	/* ── Point of no return ── Steps 5 and 6 run to completion ── */

	/* Step 5: Write FIT image raw to kernel partition */
	fw_write_state(5, 6, "running",
		       "Writing FIT image to kernel partition...", "");

	char ddcmd[512];
	snprintf(ddcmd, sizeof(ddcmd),
		 "dd if=/tmp/sg-fw-staged/stargazer.itb of='%s' bs=512k 2>&1",
		 kpart);
	char *ddout = fw_run_cmd(ddcmd);
	if (ddout)
		mgmt_log("INFO", "dd output: %s", ddout);
	free(ddout);

	/* Verify: read back and compare sha256 */
	{
		struct stat fit_st;
		if (stat("/tmp/sg-fw-staged/stargazer.itb", &fit_st) != 0) {
			fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
			fw_write_state(5, 6, "error", "Cannot stat FIT image", "");
			sg_db_close();
			_exit(1);
		}
		char vfycmd[512];
		snprintf(vfycmd, sizeof(vfycmd),
			 "dd if='%s' bs=512k count=%ld iflag=count_bytes 2>/dev/null "
			 "| sha256sum | cut -d' ' -f1",
			 kpart, (long)fit_st.st_size);
		char *vfysum = fw_run_cmd(vfycmd);
		if (vfysum) {
			char *nl = strchr(vfysum, '\n');
			if (nl) *nl = '\0';
		}
		if (!vfysum || strcmp(vfysum, fit_sha) != 0) {
			mgmt_log("ERROR", "FIT readback verify failed: "
				 "got=%s expected=%s",
				 vfysum ? vfysum : "null", fit_sha);
			free(vfysum);
			fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
			fw_write_state(5, 6, "error",
				       "FIT image write verification failed", "");
			sg_db_close();
			_exit(1);
		}
		free(vfysum);
	}

	/* Step 6: Sync and finalize */
	fw_write_state(6, 6, "running", "Syncing...", "");
	fw_run_cmd_ignore("sync");
	fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download");

	/* Audit log */
	char audit_msg[1200];
	snprintf(audit_msg, sizeof(audit_msg),
		 "version=%s %s", fw_version, source_label);
	(void)audit_log(fw_user, "firmware_upgrade", audit_msg);

	mgmt_log("INFO", "firmware v%s installed successfully", fw_version);

	char done_msg[256];
	snprintf(done_msg, sizeof(done_msg),
		 "Firmware v%s installed successfully. Rebooting...",
		 fw_version);
	fw_write_state(6, 6, "done", done_msg, fw_version);

	/* Stamp integrity flag so new firmware recognizes this as a seeded DB */
	sg_db_set_val("system_meta", "0", "seeded", "1");

	/* Close DB and back up before reboot */
	sg_db_close();
	{
		const char *cp_argv[] = {"cp", "-f", SG_DB_PATH,
					 SG_DB_PATH ".pre-upgrade", NULL};
		free(safe_exec(cp_argv));
	}
	/* 5 s: give the 2 s JS polling at least two ticks to read done=true
	 * before the process dies and connections start failing. */
	usleep(5000000);
	fw_run_cmd_ignore("/sbin/reboot");
	_exit(0);
}

int handle_upgrade_start(int client_fd, const char *user, const char *payload, const sg_request_hdr_t *hdr)
{
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'admin' permission");
		return 0;
	}
	if (!payload || hdr->payload_len == 0) {
		send_error(client_fd, SG_ERR_MISSING_ARG, "Missing URL");
		return 0;
	}

	/* Extract URL from payload */
	char url[1024];
	extract_val(payload, "url", url, sizeof(url));
	if (!url[0]) {
		send_error(client_fd, SG_ERR_MISSING_ARG, "Missing URL");
		return 0;
	}

	/* Validate URL scheme */
	if (strncmp(url, "http://", 7) != 0 &&
	    strncmp(url, "https://", 8) != 0 &&
	    strncmp(url, "tftp://", 7) != 0) {
		send_error(client_fd, SG_ERR_INVALID_ARG,
			   "URL must start with http://, https://, or tftp://");
		return 0;
	}

	/* Check if upgrade already running */
	{
		char state_check[256] = {0};
		FILE *sf = fopen(FW_STATE_FILE, "r");
		if (sf) {
			size_t rd = fread(state_check, 1, sizeof(state_check) - 1, sf);
			state_check[rd] = '\0';
			fclose(sf);
			if (strstr(state_check, "status=running")) {
				send_error(client_fd, SG_ERR_IN_USE,
					   "Firmware upgrade already in progress");
				return 0;
			}
		}
	}

	/* Clear any stale cancel flag from a previous run */
	unlink(FW_CANCEL_FILE);

	/* Reset step log state for fresh upgrade */
	fw_steps_log[0] = '\0';
	fw_steps_log_len = 0;
	fw_last_logged_step = -1;

	/* Write initial state and respond immediately */
	fw_write_state(0, 6, "running", "Starting firmware upgrade...", "");
	send_ok(client_fd, NULL, "Firmware upgrade started\n");

	/* Save username for child audit log */
	char fw_user[SG_USERNAME_MAX];
	snprintf(fw_user, sizeof(fw_user), "%s", user);

	/* Fork: parent returns to accept loop, child performs upgrade */
	pid_t pid = fork();
	if (pid < 0) {
		mgmt_log("ERROR", "firmware upgrade fork failed: %s",
			 strerror(errno));
		fw_write_state(0, 6, "error", "Internal error: fork failed", "");
		return 0;
	}

	if (pid > 0) {
		/* Parent — return to main accept loop */
		return 0;
	}

	/* ── Child process ─────────────────────────────────────── */

	/* Close fds we don't need */
	close(client_fd);
	if (g_listen_fd >= 0)
		close(g_listen_fd);

	/* Redirect stderr to log file to prevent timestamp
	 * contamination of console output */
	int logfd = open("/tmp/sg-fw-upgrade.log",
			 O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (logfd >= 0) {
		dup2(logfd, STDERR_FILENO);
		close(logfd);
	}

	/* Re-open database (parent keeps its connection) */
	sg_db_close();
	if (sg_db_open(SG_DB_PATH) != 0)
		mgmt_log("WARN", "firmware child: failed to reopen db");

	/* Prepare working directories */
	fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
	fw_run_cmd_ignore("mkdir -p /tmp/sg-fw-download /tmp/sg-fw-staged");

	/* Determine protocol label for progress messages */
	const char *proto_label;
	if (strncmp(url, "tftp://", 7) == 0)
		proto_label = "TFTP";
	else if (strncmp(url, "https://", 8) == 0)
		proto_label = "HTTPS";
	else if (strncmp(url, "http://", 7) == 0)
		proto_label = "HTTP";
	else {
		fw_write_state(1, 6, "error", "Unsupported URL scheme", "");
		sg_db_close();
		_exit(1);
	}

	/* Step 1: Download firmware package (non-blocking with progress) */
	{
		char init_msg[128];
		snprintf(init_msg, sizeof(init_msg),
			 "Downloading firmware... (0 KB) via %s", proto_label);
		fw_write_state(1, 6, "running", init_msg, "");
	}
	mgmt_log("INFO", "firmware upgrade: downloading from %s", url);

	/* (No HTTP HEAD size probe: the progress loop below reports on-disk
	 * KB only — the previously-probed Content-Length was never consumed,
	 * so the extra wget --spider fork was pure latency. Removed.) */

	pid_t dl_pid = -1;

	if (strncmp(url, "tftp://", 7) == 0) {
		/* Parse tftp://host/path */
		const char *hp = url + 7;
		const char *slash = strchr(hp, '/');
		if (!slash || !slash[1]) {
			fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
			fw_write_state(1, 6, "error",
				       "TFTP URL must be tftp://host/path", "");
			sg_db_close();
			_exit(1);
		}
		char thost[256];
		size_t hlen = (size_t)(slash - hp);
		if (hlen >= sizeof(thost)) hlen = sizeof(thost) - 1;
		memcpy(thost, hp, hlen);
		thost[hlen] = '\0';
		const char *tremote = slash + 1;

		/* TFTP return traffic is handled by nf_conntrack_tftp +
		 * ESTABLISHED,RELATED rule in SG_IN_<iface> chain.
		 * See mgmtd_init_firewall() for CT helper setup. */
		dl_pid = fork();
		if (dl_pid == 0) {
			/* Capture tftp output for diagnostics */
			int efd = open("/tmp/sg-fw-tftp.log",
				       O_WRONLY | O_CREAT | O_TRUNC, 0600);
			if (efd >= 0) {
				dup2(efd, STDOUT_FILENO);
				dup2(efd, STDERR_FILENO);
				close(efd);
			}
			execlp("tftp", "tftp", "-g",
			       "-l", FW_DL_FILE,
			       "-r", tremote, thost, NULL);
			_exit(127);
		}
	} else {
		dl_pid = fork();
		if (dl_pid == 0) {
			execlp("wget", "wget", "-T", "30", "-O", FW_DL_FILE,
			       url, NULL);
			_exit(127);
		}
	}

	if (dl_pid < 0) {
		fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
		fw_write_state(1, 6, "error", "Download fork failed", "");
		sg_db_close();
		_exit(1);
	}

	/* Poll download file size while wget/tftp runs */
	int dl_status = 0;
	for (;;) {
		struct stat st;
		long kb = 0;
		if (stat(FW_DL_FILE, &st) == 0)
			kb = (long)(st.st_size / 1024);
		char msg[128];
		snprintf(msg, sizeof(msg),
			 "Downloading firmware... (%ld KB) via %s",
			 kb, proto_label);
		fw_write_state(1, 6, "running", msg, "");

		int wret = waitpid(dl_pid, &dl_status, WNOHANG);
		if (wret != 0)
			break;

		/* Cancel check during download — kill the download child */
		if (access(FW_CANCEL_FILE, F_OK) == 0) {
			kill(dl_pid, SIGTERM);
			waitpid(dl_pid, NULL, 0);
			mgmt_log("INFO", "firmware upgrade cancelled during download");
			fw_write_state(0, 6, "cancelled",
				       "Firmware upgrade cancelled by user.", "");
			fw_cancel_cleanup();
			sg_db_close();
			_exit(1);
		}

		usleep(500000);
	}

	if (!WIFEXITED(dl_status) || WEXITSTATUS(dl_status) != 0 ||
	    access(FW_DL_FILE, F_OK) != 0) {
		int dl_exit = WIFEXITED(dl_status) ?
			      WEXITSTATUS(dl_status) : -1;
		/* Read tftp/wget error output for diagnostics */
		char dl_err[256] = {0};
		FILE *elf = fopen("/tmp/sg-fw-tftp.log", "r");
		if (!elf)
			elf = fopen("/tmp/sg-fw-upgrade.log", "r");
		if (elf) {
			size_t rd = fread(dl_err, 1, sizeof(dl_err) - 1, elf);
			dl_err[rd] = '\0';
			/* Trim trailing whitespace */
			while (rd > 0 && (dl_err[rd-1] == '\n' ||
					  dl_err[rd-1] == ' '))
				dl_err[--rd] = '\0';
			fclose(elf);
		}
		mgmt_log("ERROR", "firmware download failed (exit=%d): %s",
			 dl_exit, dl_err[0] ? dl_err : "(no output)");
		fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
		char errmsg[384];
		if (dl_err[0])
			snprintf(errmsg, sizeof(errmsg),
				 "Download failed: %s", dl_err);
		else
			snprintf(errmsg, sizeof(errmsg),
				 "Download failed (exit code %d)", dl_exit);
		fw_write_state(1, 6, "error", errmsg, "");
		sg_db_close();
		_exit(1);
	}

	/* Download complete — write final [1/6] with 100% */
	{
		char done_msg[128];
		snprintf(done_msg, sizeof(done_msg),
			 "Downloading firmware... 100%% via %s", proto_label);
		fw_write_state(1, 6, "running", done_msg, "");
	}

	/* Cancel check: before step 2 */
	fw_check_cancel();

	/* Steps 2-6: extract, verify, locate partition, write, reboot. */
	char src_label[1100];
	snprintf(src_label, sizeof(src_label), "url=%s", url);
	fw_child_upgrade_steps(fw_user, src_label);
	/* noreturn */
}

int handle_upgrade_progress(int client_fd, const char *user,
			    const char *payload, const sg_request_hdr_t *hdr)
{
	(void)user; (void)payload; (void)hdr;
	/* Poll firmware upgrade progress from state file */
	char state[512] = {0};
	FILE *sf = fopen(FW_STATE_FILE, "r");
	if (!sf) {
		send_ok(client_fd, NULL,
			"step=0\ntotal=0\nstatus=idle\n"
			"message=No upgrade in progress\nversion=\n");
		return 0;
	}
	size_t rd = fread(state, 1, sizeof(state) - 1, sf);
	state[rd] = '\0';
	fclose(sf);

	/* Send response first, then clean up terminal state files.
	 * If we delete before sending and the device reboots during the
	 * write, the client never sees done=true. */
	send_ok(client_fd, NULL, state);
	if (strstr(state, "status=done") || strstr(state, "status=error") ||
	    strstr(state, "status=cancelled"))
		unlink(FW_STATE_FILE);
	return 0;
}

int handle_upgrade_cancel(int client_fd, const char *user,
			  const char *payload, const sg_request_hdr_t *hdr)
{
	(void)payload; (void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'admin' permission");
		return 0;
	}

	/* Check current upgrade state to decide action:
	 *   - Running at step >= 5: reject (past point of no return)
	 *   - Running at step <  5: create cancel flag for child
	 *   - Not running / no state: clean up any stale cancel flag
	 */
	int active = 0;
	{
		char state_buf[512] = {0};
		FILE *sf = fopen(FW_STATE_FILE, "r");
		if (sf) {
			size_t rd = fread(state_buf, 1,
					  sizeof(state_buf) - 1, sf);
			state_buf[rd] = '\0';
			fclose(sf);

			char cur_status[32], cur_step[16];
			extract_val(state_buf, "status",
				    cur_status, sizeof(cur_status));
			extract_val(state_buf, "step",
				    cur_step, sizeof(cur_step));
			int step = atoi(cur_step);

			if (strcmp(cur_status, "running") == 0) {
				if (step >= 5) {
					char msg[SG_EXTRA_MAX];
					snprintf(msg, sizeof(msg),
						 "Cannot cancel: firmware "
						 "install is past the point "
						 "of no return (step %d/6)",
						 step);
					mgmt_log("WARN",
						 "cancel rejected by %s "
						 "at step %d", user, step);
					send_error(client_fd,
						   SG_ERR_IN_USE, msg);
					return 0;
				}
				active = 1;
			}
		}
	}

	if (!active) {
		/* No active upgrade — clean up any stale cancel flag */
		unlink(FW_CANCEL_FILE);
		mgmt_log("INFO", "firmware cancel by %s (no active upgrade)",
			 user);
		send_ok(client_fd, NULL, "Cancel requested\n");
		return 0;
	}

	/* Create the cancel flag file — the child picks it up on next check */
	int fd = open(FW_CANCEL_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		send_error(client_fd, SG_ERR_SYSTEM_FAIL,
			   "Failed to create cancel flag");
		return 0;
	}
	close(fd);

	mgmt_log("INFO", "firmware upgrade cancel requested by %s", user);
	send_ok(client_fd, NULL, "Cancel requested\n");
	return 0;
}

/* ── Upgrade from pre-uploaded file ─────────────────────────────────── */

/*
 * handle_upgrade_from_file — install firmware already written by webd to
 * a per-upload staging file.  The child moves it to FW_DL_FILE, then runs steps 2-6
 * via fw_child_upgrade_steps().
 */
int handle_upgrade_from_file(int client_fd, const char *user,
			     const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'admin' permission");
		return 0;
	}

	/* Validate the upload path: it must be one of webd's mkstemp staging
	 * files, "/tmp/sg-fw-upload.<suffix>" where <suffix> is non-empty and
	 * strictly [A-Za-z0-9] (exactly what mkstemp produces). The strict
	 * charset rules out path traversal, extra '/', AND shell
	 * metacharacters — the path is later interpolated into a cp fallback
	 * command, so anything looser would be a command-injection vector. */
	char path[256] = {0};
	if (payload && hdr->payload_len > 0)
		extract_val(payload, "path", path, sizeof(path));
	{
		static const char PFX[] = "/tmp/sg-fw-upload.";
		size_t pfxlen = sizeof(PFX) - 1;
		int valid = (strncmp(path, PFX, pfxlen) == 0) &&
			    (path[pfxlen] != '\0');
		for (const char *s = path + pfxlen; valid && *s; s++) {
			if (!((*s >= 'A' && *s <= 'Z') ||
			      (*s >= 'a' && *s <= 'z') ||
			      (*s >= '0' && *s <= '9')))
				valid = 0;
		}
		if (!valid) {
			send_error(client_fd, SG_ERR_INVALID_ARG,
				   "Invalid firmware path");
			return 0;
		}
	}

	if (access(path, F_OK) != 0) {
		send_error(client_fd, SG_ERR_NOT_FOUND,
			   "Firmware upload file not found");
		return 0;
	}

	/* Check if upgrade already running */
	{
		char state_check[256] = {0};
		FILE *sf = fopen(FW_STATE_FILE, "r");
		if (sf) {
			size_t rd = fread(state_check, 1,
					  sizeof(state_check) - 1, sf);
			state_check[rd] = '\0';
			fclose(sf);
			if (strstr(state_check, "status=running")) {
				/* Drop this upload's staging file — the
				 * in-progress upgrade owns its own. */
				unlink(path);
				send_error(client_fd, SG_ERR_IN_USE,
					   "Firmware upgrade already in progress");
				return 0;
			}
		}
	}

	/* Clear stale cancel flag and reset step log */
	unlink(FW_CANCEL_FILE);
	fw_steps_log[0] = '\0';
	fw_steps_log_len = 0;
	fw_last_logged_step = -1;

	/* Write initial state and reply immediately */
	fw_write_state(1, 6, "running",
		       "Firmware upload complete, preparing installation...", "");
	send_ok(client_fd, NULL, "Firmware upgrade started\n");

	char fw_user[SG_USERNAME_MAX];
	snprintf(fw_user, sizeof(fw_user), "%s", user);

	pid_t pid = fork();
	if (pid < 0) {
		mgmt_log("ERROR", "firmware upgrade (upload) fork failed: %s",
			 strerror(errno));
		fw_write_state(0, 6, "error", "Internal error: fork failed", "");
		unlink(path);	/* no child will consume the staging file */
		return 0;
	}

	if (pid > 0)
		return 0;

	/* ── Child process ─────────────────────────────────────── */

	close(client_fd);
	if (g_listen_fd >= 0)
		close(g_listen_fd);

	int logfd = open("/tmp/sg-fw-upgrade.log",
			 O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (logfd >= 0) {
		dup2(logfd, STDERR_FILENO);
		close(logfd);
	}

	sg_db_close();
	if (sg_db_open(SG_DB_PATH) != 0)
		mgmt_log("WARN", "firmware child: failed to reopen db");

	fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
	fw_run_cmd_ignore("mkdir -p /tmp/sg-fw-download /tmp/sg-fw-staged");

	/* Move THIS request's uploaded file (validated above) to the expected
	 * download path. Using the per-request path, not a shared constant,
	 * is what makes concurrent uploads independent. */
	if (rename(path, FW_DL_FILE) != 0) {
		/* rename fails across filesystems — fall back to cp+rm.
		 * cpcmd must hold the validated path (<=255) twice plus the
		 * fixed dest and shell text. */
		char cpcmd[768];
		snprintf(cpcmd, sizeof(cpcmd),
			 "cp -f '%s' '%s' && rm -f '%s'",
			 path, FW_DL_FILE, path);
		fw_run_cmd_ignore(cpcmd);
	}

	if (access(FW_DL_FILE, F_OK) != 0) {
		fw_write_state(1, 6, "error",
			       "Failed to stage uploaded firmware file", "");
		sg_db_close();
		_exit(1);
	}

	fw_child_upgrade_steps(fw_user, "source=upload");
	/* noreturn */
}

/* ── Test setup handler (for selftest suite) ─────────────────────────── */

int handle_upgrade_test_setup(int client_fd, const char *user,
			      const char *payload, const sg_request_hdr_t *hdr)
{
	(void)hdr;
	const char *perms = get_user_permissions(user);
	if (!has_permission(perms, "admin")) {
		send_error(client_fd, SG_ERR_PERM_DENIED,
			   "Requires 'admin' permission");
		return 0;
	}

	if (!payload || !payload[0]) {
		send_error(client_fd, SG_ERR_MISSING_ARG, "Missing action");
		return 0;
	}

	char action[32];
	extract_val(payload, "action", action, sizeof(action));

	if (strcmp(action, "write_state") == 0) {
		/* Write a firmware state file with given parameters */
		char step[16], total[16], status[32], message[256], version[64];
		extract_val(payload, "step", step, sizeof(step));
		extract_val(payload, "total", total, sizeof(total));
		extract_val(payload, "status", status, sizeof(status));
		extract_val(payload, "message", message, sizeof(message));
		extract_val(payload, "version", version, sizeof(version));

		FILE *fp = fopen(FW_STATE_FILE_TMP, "w");
		if (!fp) {
			send_error(client_fd, SG_ERR_IO_FAIL,
				   "Cannot write state file");
			return 0;
		}
		fchmod(fileno(fp), 0600);
		fprintf(fp, "step=%s\ntotal=%s\nstatus=%s\n"
			"message=%s\nversion=%s\n",
			step, total, status, message, version);
		fclose(fp);
		rename(FW_STATE_FILE_TMP, FW_STATE_FILE);
		send_ok(client_fd, NULL, NULL);

	} else if (strcmp(action, "clean") == 0) {
		/* Remove both state file and cancel flag */
		unlink(FW_STATE_FILE);
		unlink(FW_CANCEL_FILE);
		send_ok(client_fd, NULL, NULL);

	} else if (strcmp(action, "query") == 0) {
		/* Report whether state file and cancel flag exist */
		int sf = (access(FW_STATE_FILE, F_OK) == 0) ? 1 : 0;
		int cf = (access(FW_CANCEL_FILE, F_OK) == 0) ? 1 : 0;
		char result[64];
		snprintf(result, sizeof(result),
			 "state_file=%d\ncancel_flag=%d\n", sf, cf);
		send_ok(client_fd, NULL, result);

	} else {
		send_error(client_fd, SG_ERR_INVALID_ARG,
			   "Unknown action (use write_state/clean/query)");
	}

	return 0;
}
