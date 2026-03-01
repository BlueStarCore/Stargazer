/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_firmware.c — Firmware upgrade handlers for stargazer-mgmtd
 *
 * Extracted from stargazer-mgmtd.c to keep the monolith manageable.
 * Contains:
 *   - Firmware state file management
 *   - FW_STATUS, FW_UPGRADE, FW_PROGRESS handlers
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
#include <sys/wait.h>

#include "mgmtd_internal.h"
#include "mgmtd_apply.h"

/* ── Firmware upgrade state file ─────────────────────────────────────────── */

#define FW_STATE_FILE     "/tmp/sg-fw-upgrade.state"
#define FW_STATE_FILE_TMP "/tmp/sg-fw-upgrade.state.tmp"

/*
 * Write firmware upgrade progress to state file atomically.
 * The child process calls this at each step so the parent (serving
 * FW_PROGRESS polls) always reads a complete, consistent file.
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

/* ── Firmware handlers ───────────────────────────────────────────────────── */

/* g_listen_fd is needed by the FW_UPGRADE child to close the listen socket */
extern int g_listen_fd;

int handle_fw_status(int client_fd, const char *user,
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

	/* Boot partition device */
	const char *bdev_argv[] = {"findfs", "LABEL=boot", NULL};
	char *bdev = safe_exec(bdev_argv);
	if (!bdev || !bdev[0]) {
		free(bdev);
		const char *blkid_argv[] = {"blkid", "-L", "boot", NULL};
		bdev = safe_exec(blkid_argv);
	}
	if (bdev && bdev[0]) {
		char *nl = strchr(bdev, '\n');
		if (nl) *nl = '\0';
		off += snprintf(result + off, sizeof(result) - (size_t)off,
				"  Boot partition: %s\n", bdev);
	} else {
		off += snprintf(result + off, sizeof(result) - (size_t)off,
				"  Boot partition: not found\n");
	}
	free(bdev);

	(void)off;
	send_ok(client_fd, NULL, result);
	return 0;
}

int handle_fw_upgrade(int client_fd, const char *user,
		      const char *payload, const sg_request_hdr_t *hdr)
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
	fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged /tmp/sg-fw-boot");
	fw_run_cmd_ignore("mkdir -p /tmp/sg-fw-download /tmp/sg-fw-staged /tmp/sg-fw-boot");

	/* Step 1: Download firmware package (non-blocking with progress) */
	fw_write_state(1, 6, "running", "Downloading firmware... (0 KB)", "");
	mgmt_log("INFO", "firmware upgrade: downloading from %s", url);

	#define FW_DL_FILE "/tmp/sg-fw-download/firmware.tar.gz"

	/* Pre-flight: probe remote file size via HTTP HEAD request.
	 * Uses wget --spider -S to get Content-Length header.
	 * Falls back to -1 (unknown) for TFTP or if --spider
	 * is unsupported (minimal BusyBox builds). */
	long total_bytes = -1;
	if (strncmp(url, "http", 4) == 0) {
		int hp[2];
		if (pipe(hp) == 0) {
			pid_t hpid = fork();
			if (hpid == 0) {
				close(hp[0]);
				dup2(hp[1], STDOUT_FILENO);
				dup2(hp[1], STDERR_FILENO);
				close(hp[1]);
				execlp("wget", "wget", "--spider",
				       "-S", "-T", "5", url, NULL);
				_exit(127);
			}
			if (hpid > 0) {
				close(hp[1]);
				char hbuf[4096];
				size_t hused = 0;
				/* Read with timeout — don't block forever */
				struct pollfd pfd;
				pfd.fd = hp[0];
				pfd.events = POLLIN;
				while (hused < sizeof(hbuf) - 1 &&
				       poll(&pfd, 1, 6000) > 0 &&
				       (pfd.revents & POLLIN)) {
					ssize_t r = read(hp[0], hbuf + hused,
							 sizeof(hbuf) - 1 - hused);
					if (r <= 0) break;
					hused += (size_t)r;
				}
				hbuf[hused] = '\0';
				close(hp[0]);
				waitpid(hpid, NULL, 0);
				/* Parse Content-Length (case-insensitive) */
				const char *scan = hbuf;
				while (*scan) {
					if ((*scan == 'C' || *scan == 'c') &&
					    strncasecmp(scan, "Content-Length:", 15) == 0) {
						const char *v = scan + 15;
						while (*v == ' ') v++;
						long cl = atol(v);
						if (cl > 0)
							total_bytes = cl;
						break;
					}
					scan++;
				}
				if (total_bytes > 0)
					mgmt_log("INFO", "firmware size: %ld bytes",
						 total_bytes);
			} else {
				close(hp[0]);
				close(hp[1]);
			}
		}
	}

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
			execlp("wget", "wget", "-O", FW_DL_FILE,
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
	long total_kb = total_bytes > 0 ? (total_bytes + 1023) / 1024 : -1;
	int dl_status = 0;
	for (;;) {
		int wret = waitpid(dl_pid, &dl_status, WNOHANG);
		if (wret != 0)
			break;
		struct stat st;
		long kb = 0;
		if (stat(FW_DL_FILE, &st) == 0)
			kb = (long)(st.st_size / 1024);
		char msg[128];
		if (total_kb > 0) {
			int pct = (int)(kb * 100 / total_kb);
			if (pct > 99) pct = 99;
			snprintf(msg, sizeof(msg),
				 "Downloading firmware... %d%% (%ld/%ld KB)",
				 pct, kb, total_kb);
		} else {
			snprintf(msg, sizeof(msg),
				 "Downloading firmware... (%ld KB)", kb);
		}
		fw_write_state(1, 6, "running", msg, "");
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

	/* Show final download size */
	{
		struct stat st;
		long kb = 0;
		if (stat(FW_DL_FILE, &st) == 0)
			kb = (long)(st.st_size / 1024);
		char msg[128];
		if (total_kb > 0)
			snprintf(msg, sizeof(msg),
				 "Downloading firmware... 100%% (%ld/%ld KB) done",
				 kb, total_kb);
		else
			snprintf(msg, sizeof(msg),
				 "Downloading firmware... (%ld KB) done", kb);
		fw_write_state(1, 6, "running", msg, "");
	}

	/* Step 2: Extract firmware package */
	fw_write_state(2, 6, "running", "Extracting firmware package...", "");
	char *exout = fw_run_cmd("tar -xzf /tmp/sg-fw-download/firmware.tar.gz "
			      "-C /tmp/sg-fw-staged/ 2>&1");
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

	char fw_version[64], kernel_sha[128], initramfs_sha[128];
	extract_val(manifest, "version", fw_version, sizeof(fw_version));
	extract_val(manifest, "kernel_sha256", kernel_sha, sizeof(kernel_sha));
	extract_val(manifest, "initramfs_sha256", initramfs_sha,
		    sizeof(initramfs_sha));

	if (!fw_version[0] || !kernel_sha[0] || !initramfs_sha[0]) {
		fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
		fw_write_state(2, 6, "error",
			       "Incomplete manifest (missing version or checksums)", "");
		sg_db_close();
		_exit(1);
	}

	/* Step 3: Verify checksums */
	fw_write_state(3, 6, "running", "Verifying checksums...", "");
	char *ksum = fw_run_cmd("sha256sum /tmp/sg-fw-staged/kernel 2>/dev/null "
			     "| cut -d' ' -f1");
	char *isum = fw_run_cmd("sha256sum /tmp/sg-fw-staged/initramfs.gz 2>/dev/null "
			     "| cut -d' ' -f1");

	/* Trim trailing newlines */
	if (ksum) { char *nl = strchr(ksum, '\n'); if (nl) *nl = '\0'; }
	if (isum) { char *nl = strchr(isum, '\n'); if (nl) *nl = '\0'; }

	if (!ksum || !isum ||
	    strcmp(ksum, kernel_sha) != 0 ||
	    strcmp(isum, initramfs_sha) != 0) {
		mgmt_log("ERROR", "firmware checksum mismatch: "
			 "kernel=%s (expect %s) initramfs=%s (expect %s)",
			 ksum ? ksum : "null", kernel_sha,
			 isum ? isum : "null", initramfs_sha);
		free(ksum);
		free(isum);
		fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
		fw_write_state(3, 6, "error",
			       "Firmware checksum verification failed", "");
		sg_db_close();
		_exit(1);
	}
	free(ksum);
	free(isum);

	mgmt_log("INFO", "firmware v%s verified, installing...", fw_version);

	/* Step 4: Find and mount boot partition */
	fw_write_state(4, 6, "running", "Mounting boot partition...", "");
	const char *bdev_argv[] = {"findfs", "LABEL=boot", NULL};
	char *bdev = safe_exec(bdev_argv);
	if (!bdev || !bdev[0]) {
		free(bdev);
		const char *blkid_argv[] = {"blkid", "-L", "boot", NULL};
		bdev = safe_exec(blkid_argv);
	}
	if (!bdev || !bdev[0]) {
		free(bdev);
		/* Scan common device paths */
		const char *candidates[] = {
			"/dev/mmcblk0p1", "/dev/mmcblk1p1",
			"/dev/vda1", "/dev/sda1", NULL
		};
		for (int i = 0; candidates[i]; i++) {
			if (access(candidates[i], F_OK) != 0)
				continue;
			char bcmd[256];
			snprintf(bcmd, sizeof(bcmd),
				 "blkid -s LABEL -o value '%s' 2>/dev/null",
				 candidates[i]);
			char *lbl = fw_run_cmd(bcmd);
			if (lbl) {
				char *nl = strchr(lbl, '\n');
				if (nl) *nl = '\0';
				if (strcmp(lbl, "boot") == 0) {
					bdev = malloc(strlen(candidates[i]) + 1);
					if (bdev)
						strcpy(bdev, candidates[i]);
					free(lbl);
					break;
				}
				free(lbl);
			}
		}
	}

	if (!bdev || !bdev[0]) {
		free(bdev);
		fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
		fw_write_state(4, 6, "error",
			       "Boot partition (LABEL=boot) not found", "");
		sg_db_close();
		_exit(1);
	}

	/* Trim trailing newline from device path */
	{
		char *nl = strchr(bdev, '\n');
		if (nl) *nl = '\0';
	}

	/* Mount boot partition */
	char mntcmd[512];
	snprintf(mntcmd, sizeof(mntcmd),
		 "mount '%s' /tmp/sg-fw-boot 2>&1", bdev);
	char *mntout = fw_run_cmd(mntcmd);
	if (access("/tmp/sg-fw-boot/kernel", F_OK) != 0 &&
	    access("/tmp/sg-fw-boot/initramfs.gz", F_OK) != 0) {
		/* Boot partition mounted but seems empty — still ok
		 * for first firmware install */
		mgmt_log("WARN", "boot partition %s appears empty", bdev);
	}
	free(mntout);

	/* Verify mount succeeded by checking mountpoint */
	char *mpcheck = fw_run_cmd("mountpoint -q /tmp/sg-fw-boot && echo ok 2>/dev/null");
	if (!mpcheck || strncmp(mpcheck, "ok", 2) != 0) {
		mgmt_log("ERROR", "failed to mount boot partition %s", bdev);
		free(mpcheck);
		free(bdev);
		fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
		fw_write_state(4, 6, "error",
			       "Failed to mount boot partition", "");
		sg_db_close();
		_exit(1);
	}
	free(mpcheck);

	/* Log boot partition space before install */
	char *df_before = fw_run_cmd("df -h /tmp/sg-fw-boot 2>/dev/null | tail -1");
	mgmt_log("INFO", "boot partition before install: %s",
		 df_before ? df_before : "(unknown)");
	free(df_before);

	/* Remove existing files to free space (64MB partition can't
	 * hold old + new simultaneously with a ~44MB kernel) */
	fw_run_cmd_ignore("rm -f /tmp/sg-fw-boot/kernel "
		      "/tmp/sg-fw-boot/initramfs.gz "
		      "/tmp/sg-fw-boot/kernel.bak "
		      "/tmp/sg-fw-boot/initramfs.gz.bak 2>/dev/null");

	/* Step 5: Install firmware files */
	fw_write_state(5, 6, "running",
		       "Installing kernel and initramfs...", "");

	int install_ok = 1;

	char *cpk = fw_run_cmd("cp /tmp/sg-fw-staged/kernel /tmp/sg-fw-boot/kernel 2>&1");
	if (cpk && cpk[0])
		mgmt_log("WARN", "kernel copy: %s", cpk);
	free(cpk);

	char *vk = fw_run_cmd("cmp -s /tmp/sg-fw-staged/kernel /tmp/sg-fw-boot/kernel "
			   "&& echo ok");
	if (!vk || strncmp(vk, "ok", 2) != 0) {
		mgmt_log("ERROR", "kernel verify failed");
		install_ok = 0;
	}
	free(vk);

	char *cpi = fw_run_cmd("cp /tmp/sg-fw-staged/initramfs.gz /tmp/sg-fw-boot/initramfs.gz 2>&1");
	if (cpi && cpi[0])
		mgmt_log("WARN", "initramfs copy: %s", cpi);
	free(cpi);

	char *vi = fw_run_cmd("cmp -s /tmp/sg-fw-staged/initramfs.gz /tmp/sg-fw-boot/initramfs.gz "
			   "&& echo ok");
	if (!vi || strncmp(vi, "ok", 2) != 0) {
		mgmt_log("ERROR", "initramfs verify failed");
		install_ok = 0;
	}
	free(vi);

	if (!install_ok) {
		char *df_fail = fw_run_cmd("df -h /tmp/sg-fw-boot 2>/dev/null | tail -1");
		mgmt_log("ERROR", "firmware install failed, boot partition: %s",
			 df_fail ? df_fail : "(unknown)");
		free(df_fail);
		fw_run_cmd_ignore("sync");
		fw_run_cmd_ignore("umount /tmp/sg-fw-boot 2>/dev/null");
		free(bdev);
		fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download /tmp/sg-fw-staged");
		fw_write_state(5, 6, "error", "Firmware install failed", "");
		sg_db_close();
		_exit(1);
	}

	/* Copy manifest to boot partition for version tracking */
	fw_run_cmd_ignore("cp /tmp/sg-fw-staged/manifest.txt /tmp/sg-fw-boot/manifest.txt 2>/dev/null");

	/* Step 6: Sync, unmount, and finalize */
	fw_write_state(6, 6, "running",
		       "Syncing and unmounting boot partition...", "");
	fw_run_cmd_ignore("sync");
	fw_run_cmd_ignore("umount /tmp/sg-fw-boot 2>/dev/null");
	free(bdev);

	/* Cleanup download artifacts */
	fw_run_cmd_ignore("rm -rf /tmp/sg-fw-download");

	/* Audit log */
	char audit_msg[1200];
	snprintf(audit_msg, sizeof(audit_msg),
		 "version=%s url=%s", fw_version, url);
	(void)audit_log(fw_user, "firmware_upgrade", audit_msg);

	mgmt_log("INFO", "firmware v%s installed successfully", fw_version);

	char done_msg[256];
	snprintf(done_msg, sizeof(done_msg),
		 "Firmware v%s installed successfully. Rebooting...",
		 fw_version);
	fw_write_state(6, 6, "done", done_msg, fw_version);

	/* Close DB and back up before reboot */
	sg_db_close();
	{
		const char *cp_argv[] = {"cp", "-f", SG_DB_PATH,
					 SG_DB_PATH ".pre-upgrade",
					 NULL};
		free(safe_exec(cp_argv));
	}
	usleep(100000);
	fw_run_cmd_ignore("/sbin/reboot");
	_exit(0);
}

int handle_fw_progress(int client_fd, const char *user,
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

	/* If terminal state (done/error), clean up the file */
	if (strstr(state, "status=done") || strstr(state, "status=error"))
		unlink(FW_STATE_FILE);

	send_ok(client_fd, NULL, state);
	return 0;
}
