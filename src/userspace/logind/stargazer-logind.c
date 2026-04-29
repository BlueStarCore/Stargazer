/* SPDX-License-Identifier: MIT */
/*
 * stargazer-logind — Stargazer NGFW login daemon (privilege-separated)
 *
 * Flow:
 *   Phase 1 (full root):
 *     1. Cache user data (getpwnam — if user not found, still proceed)
 *     2. initgroups (if user found), open /dev/console
 *   Phase 1.5:
 *     3. Install seccomp-bpf sandbox (logind_drop_privileges)
 *   Phase 2 (sandboxed, still root UID):
 *     4. Prompt for password (always, even if user not in /etc/passwd)
 *     5. Authenticate via IPC to mgmtd (SG_CMD_AUTH_LOGIN)
 *     6. Handle forced password change via IPC (SG_CMD_AUTH_CHANGE_PW)
 *     7. Notify login success via IPC (SG_CMD_AUTH_LOGIN_OK)
 *   Phase 3:
 *     8. Drop privileges (setgid/setuid)
 *     9. exec user shell
 *
 * All privileged operations (shadow, DB, audit) are delegated to mgmtd.
 * After seccomp install, logind cannot open files, fork, or exec arbitrary
 * binaries. It can only talk to the terminal and mgmtd over AF_UNIX IPC.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "stargazer_ipc.h"

#define MAX_PASS_LEN      256
#define EXIT_SIGINT       130  /* Convention: 128 + SIGINT(2) */

/* ── SIGINT handling (Ctrl+C returns to login prompt) ───────────────────── */

static volatile sig_atomic_t g_interrupted = 0;
static struct termios g_saved_termios;
static int g_termios_saved = 0;

static void sigint_handler(int sig)
{
	(void)sig;
	g_interrupted = 1;
	/* Restore terminal echo immediately (async-signal-safe via tcsetattr) */
	if (g_termios_saved)
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_termios);
}

/*
 * Install SIGINT handler using sigaction WITHOUT SA_RESTART.
 * This ensures read() inside fgets() returns EINTR immediately
 * when Ctrl+C is pressed, rather than being silently restarted.
 */
static void install_sigint_handler(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigint_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;  /* explicitly NO SA_RESTART */
	sigaction(SIGINT, &sa, NULL);
}

/* ── Password prompt (echo disabled) ────────────────────────────────────── */

static int read_password(const char *prompt, char *buf, size_t buflen)
{
	struct termios new;

	if (g_interrupted)
		return -2;

	fprintf(stderr, "%s", prompt);
	fflush(stderr);

	g_termios_saved = 0;
	if (tcgetattr(STDIN_FILENO, &g_saved_termios) == 0) {
		new = g_saved_termios;
		new.c_lflag &= ~ECHO;
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &new);
		g_termios_saved = 1;
	}

	if (!fgets(buf, (int)buflen, stdin)) {
		if (g_termios_saved)
			tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_termios);
		g_termios_saved = 0;
		fprintf(stderr, "\n");
		return g_interrupted ? -2 : -1;
	}

	if (g_termios_saved)
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_termios);
	g_termios_saved = 0;
	fprintf(stderr, "\n");

	if (g_interrupted)
		return -2;

	/* Strip trailing newline */
	size_t len = strlen(buf);
	if (len > 0 && buf[len - 1] == '\n')
		buf[len - 1] = '\0';

	return 0;
}

/* ── IPC client (self-contained) ───────────────────────────────────────── */

static ssize_t logind_safe_write(int fd, const void *buf, size_t len)
{
	size_t done = 0;
	while (done < len) {
		ssize_t n = write(fd, (const char *)buf + done, len - done);
		if (n <= 0) {
			if (n < 0 && errno == EINTR) continue;
			return -1;
		}
		done += (size_t)n;
	}
	return (ssize_t)done;
}

static ssize_t logind_safe_read(int fd, void *buf, size_t len)
{
	size_t done = 0;
	while (done < len) {
		ssize_t n = read(fd, (char *)buf + done, len - done);
		if (n <= 0) {
			if (n < 0 && errno == EINTR) continue;
			return n == 0 ? (ssize_t)done : -1;
		}
		done += (size_t)n;
	}
	return (ssize_t)done;
}

/*
 * Send IPC request to mgmtd and receive response.
 * Returns 0 on successful IPC exchange, -1 on transport failure.
 */
static int logind_ipc(uint32_t cmd, const char *username,
		      const char *payload_str,
		      uint32_t *out_status,
		      char *out_extra, size_t extra_sz,
		      char **out_payload)
{
	int ret = -1;
	*out_status = SG_ERR_SYSTEM_FAIL;
	if (out_extra) out_extra[0] = '\0';
	if (out_payload) *out_payload = NULL;

	size_t plen = payload_str ? strlen(payload_str) : 0;
	if (plen > SG_PAYLOAD_MAX) return -1;

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) return -1;

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SG_MGMTD_SOCK);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto out;

	sg_request_hdr_t req;
	memset(&req, 0, sizeof(req));
	req.magic       = SG_MSG_MAGIC;
	req.version     = SG_MSG_VERSION;
	req.cmd         = cmd;
	req.payload_len = (uint32_t)plen;
	req.session_tag = 0;  /* logind has no session */
	snprintf(req.username, sizeof(req.username), "%s", username);

	if (logind_safe_write(fd, &req, sizeof(req)) < 0) goto out;
	if (plen > 0 && logind_safe_write(fd, payload_str, plen) < 0) goto out;

	sg_response_hdr_t rhdr;
	if (logind_safe_read(fd, &rhdr, sizeof(rhdr)) < (ssize_t)sizeof(rhdr))
		goto out;
	if (rhdr.magic != SG_MSG_MAGIC) goto out;

	*out_status = rhdr.status;
	if (out_extra) {
		size_t csz = extra_sz < SG_EXTRA_MAX ? extra_sz : SG_EXTRA_MAX;
		memcpy(out_extra, rhdr.extra, csz);
		out_extra[csz - 1] = '\0';
	}

	if (rhdr.payload_len > 0 && rhdr.payload_len <= SG_RESPONSE_MAX &&
	    out_payload) {
		*out_payload = malloc(rhdr.payload_len + 1);
		if (*out_payload) {
			if (logind_safe_read(fd, *out_payload,
					     rhdr.payload_len) <
			    (ssize_t)rhdr.payload_len) {
				free(*out_payload);
				*out_payload = NULL;
				goto out;
			}
			(*out_payload)[rhdr.payload_len] = '\0';
		}
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

/* ── Interactive password change via IPC ───────────────────────────────── */

/*
 * Returns 0 on success, -1 on error, -2 on Ctrl+C.
 */
static int ipc_password_change(const char *username, const char *source)
{
	char pw1[MAX_PASS_LEN], pw2[MAX_PASS_LEN];
	int rc;

	fprintf(stderr, "\n");
	if (strcmp(source, "first-login") == 0) {
		/* First-login: message already printed in main(), skip header */
	} else if (strcmp(source, "admin-flag") == 0) {
		fprintf(stderr, " PASSWORD CHANGE REQUIRED\n");
		fprintf(stderr, " Account '%s' must change password now.\n\n",
			username);
	} else {
		fprintf(stderr, " NOTICE: Password Policy Changed\n");
		fprintf(stderr, " Your current password does not meet the "
				"updated\n global password policy. "
				"You must set a new password.\n\n");
	}

	while (1) {
		rc = read_password("New password: ", pw1, sizeof(pw1));
		if (rc == -2) return -2;
		if (rc != 0) return -1;

		if (strlen(pw1) == 0) {
			fprintf(stderr, "Password cannot be empty.\n\n");
			continue;
		}

		rc = read_password("Retype password: ", pw2, sizeof(pw2));
		if (rc == -2) {
			explicit_bzero(pw1, sizeof(pw1));
			return -2;
		}
		if (rc != 0) {
			explicit_bzero(pw1, sizeof(pw1));
			return -1;
		}

		if (strcmp(pw1, pw2) != 0) {
			fprintf(stderr, "Passwords don't match. Try again.\n\n");
			explicit_bzero(pw1, sizeof(pw1));
			explicit_bzero(pw2, sizeof(pw2));
			continue;
		}
		explicit_bzero(pw2, sizeof(pw2));

		/* Send to mgmtd for validation + shadow update */
		char payload[MAX_PASS_LEN + SG_USERNAME_MAX + 64];
		snprintf(payload, sizeof(payload), "%s\n%s\n%s\n",
			 username, pw1, source);
		explicit_bzero(pw1, sizeof(pw1));

		uint32_t status;
		char extra[SG_EXTRA_MAX];
		rc = logind_ipc(SG_CMD_AUTH_CHANGE_PW, username, payload,
				&status, extra, sizeof(extra), NULL);
		explicit_bzero(payload, sizeof(payload));

		if (rc != 0) {
			fprintf(stderr,
				"Communication error with management daemon.\n\n");
			return -1;
		}

		if (status == SG_OK) {
			fprintf(stderr, "\n  Password set successfully.\n\n");
			return 0;
		}

		if (status == SG_ERR_POLICY_FAIL) {
			fprintf(stderr, "  %s\n\n",
				extra[0] ? extra : "Policy violation");
			continue;
		}

		fprintf(stderr, "  Password change failed: %s\n\n",
			extra[0] ? extra : "Unknown error");
		continue;
	}
}

/* ── Privilege drop: seccomp-bpf sandbox ───────────────────────────────── */

/*
 * aarch64 syscall numbers (from asm-generic/unistd.h).
 * The aarch64 ABI uses the generic syscall table.
 */
#define SC_dup3             24
#define SC_fcntl            25
#define SC_ioctl            29
#define SC_close            57
#define SC_read             63
#define SC_write            64
#define SC_writev           66
#define SC_exit_group       94
#define SC_set_tid_address  96
#define SC_futex            98
#define SC_set_robust_list  99
#define SC_nanosleep       101
#define SC_clock_gettime   113
#define SC_rt_sigaction    134
#define SC_rt_sigprocmask  135
#define SC_rt_sigreturn    139
#define SC_setgid          144
#define SC_setuid          146
#define SC_setsid          157
#define SC_prctl           167
#define SC_getpid          172
#define SC_getuid          174
#define SC_gettid          178
#define SC_socket          198
#define SC_connect         203
#define SC_sendto          206
#define SC_recvfrom        207
#define SC_getsockopt      209
#define SC_brk             214
#define SC_munmap          215
#define SC_mremap          216
#define SC_execve          221
#define SC_mmap            222
#define SC_mprotect        226
#define SC_madvise         233
#define SC_getrandom       278
#define SC_newfstatat       79
#define SC_readv            65

/* Terminal ioctl values */
#define IOCTL_TCGETS     0x5401
#define IOCTL_TCSETS     0x5402
#define IOCTL_TCSETSW    0x5403
#define IOCTL_TCSETSF    0x5404
#define IOCTL_TIOCGWINSZ 0x5413
#define IOCTL_TIOCSCTTY  0x540E

/* AF_UNIX = 1, SOCK_STREAM = 1 */
#define AF_UNIX_VAL     1
#define SOCK_STREAM_VAL 1

/* PROT_EXEC = 0x4 */
#define PROT_EXEC_VAL 4

/* BPF convenience macros */
#define SC_ALLOW(nr) \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

/*
 * seccomp_data offsets (hardcoded because offsetof(struct seccomp_data, ...)
 * confuses the BPF_STMT macro with musl's cross-compiler).
 *   nr=0, arch=4, ip=8, args[0]=16, args[1]=24, args[2]=32
 */
#define OFF_NR   0
#define OFF_ARCH 4
#define OFF_ARG0 16
#define OFF_ARG1 24
#define OFF_ARG2 32

/*
 * Build modes for the default seccomp action:
 *   SANDBOX_LOG_ONLY:  SECCOMP_RET_LOG — violations logged in dmesg,
 *     syscall proceeds normally. Use for testing without killing.
 *   Default:           SECCOMP_RET_KILL_PROCESS — production mode.
 */
/* TODO: Remove SANDBOX_LOG_ONLY after testing */
#define SANDBOX_LOG_ONLY
#ifdef SANDBOX_LOG_ONLY
#define SECCOMP_RET_DEFAULT SECCOMP_RET_LOG
#else
#define SECCOMP_RET_DEFAULT SECCOMP_RET_KILL_PROCESS
#endif

static int logind_drop_privileges(void)
{
	/* Phase 1 complete: user data cached, console FD opened.
	 * Now lock down the process. */

	/* 1. Prevent privilege escalation */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		fprintf(stderr, "logind: security hardening failed (step 1): %s\n",
			strerror(errno));
		return -1;
	}

	/* 2. Prevent core dumps leaking passwords */
	prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

	/* 3. seccomp-bpf filter */
	struct sock_filter filter[] = {
		/* ── Verify architecture is aarch64 ──────────────── */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

		/* ── Load syscall number ─────────────────────────── */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),

		/* ── I/O on pre-opened fds ───────────────────────── */
		SC_ALLOW(SC_read),
		SC_ALLOW(SC_readv),
		SC_ALLOW(SC_write),
		SC_ALLOW(SC_writev),
		SC_ALLOW(SC_close),

		/* ── socket(): only AF_UNIX + SOCK_STREAM ────────── */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SC_socket, 0, 7),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX_VAL, 0, 4),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG1),
		BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xFF),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM_VAL, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),

		/* ── IPC socket ops ──────────────────────────────── */
		SC_ALLOW(SC_connect),
		SC_ALLOW(SC_sendto),
		SC_ALLOW(SC_recvfrom),
		SC_ALLOW(SC_getsockopt),

		/* ── dup3 (musl dup2 wrapper on aarch64) ─────────── */
		SC_ALLOW(SC_dup3),

		/* ── ioctl(): only terminal ioctls ───────────────── *
		 * If not ioctl, skip 10 instructions forward.       */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SC_ioctl, 0, 10),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG1),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IOCTL_TCGETS, 6, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IOCTL_TCSETS, 5, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IOCTL_TCSETSW, 4, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IOCTL_TCSETSF, 3, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IOCTL_TIOCGWINSZ, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IOCTL_TIOCSCTTY, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_DEFAULT),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* Reload syscall number */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),

		/* ── Session / privilege drop (one-time) ─────────── */
		SC_ALLOW(SC_setsid),
		SC_ALLOW(SC_setgid),
		SC_ALLOW(SC_setuid),

		/* ── exec shell ──────────────────────────────────── */
		SC_ALLOW(SC_execve),

		/* ── Memory management ───────────────────────────── */

		/* mmap: deny PROT_EXEC (arg2 & 0x4 must be 0) */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SC_mmap, 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG2),
		BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_EXEC_VAL),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_DEFAULT),

		SC_ALLOW(SC_munmap),
		SC_ALLOW(SC_mremap),
		SC_ALLOW(SC_madvise),

		/* mprotect: deny PROT_EXEC (arg2 & 0x4 must be 0) */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SC_mprotect, 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG2),
		BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_EXEC_VAL),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_DEFAULT),

		SC_ALLOW(SC_brk),

		/* ── Signals ─────────────────────────────────────── */
		SC_ALLOW(SC_rt_sigaction),
		SC_ALLOW(SC_rt_sigprocmask),
		SC_ALLOW(SC_rt_sigreturn),

		/* ── Timing ──────────────────────────────────────── */
		SC_ALLOW(SC_clock_gettime),
		SC_ALLOW(SC_nanosleep),

		/* ── Identity ────────────────────────────────────── */
		SC_ALLOW(SC_getpid),
		SC_ALLOW(SC_getuid),
		SC_ALLOW(SC_gettid),

		/* ── musl internals ──────────────────────────────── */
		SC_ALLOW(SC_futex),
		SC_ALLOW(SC_getrandom),
		SC_ALLOW(SC_set_tid_address),
		SC_ALLOW(SC_set_robust_list),

		/* ── Misc ────────────────────────────────────────── */
		SC_ALLOW(SC_fcntl),
		SC_ALLOW(SC_newfstatat),
		SC_ALLOW(SC_exit_group),

		/* ── Default: KILL ───────────────────────────────── */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_DEFAULT),
	};

	struct sock_fprog prog = {
		.len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
		fprintf(stderr, "logind: process restriction failed (step 3): %s\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: stargazer-logind <username>\n");
		return 1;
	}

	const char *username = argv[1];

	/* ── Phase 0: Signal handlers ────────────────────────────────── */
	install_sigint_handler();
	signal(SIGQUIT, SIG_IGN);

	/* ── Phase 1: Cache user data (requires root + file access) ── */

	/*
	 * getpwnam() reads /etc/passwd — must happen before seccomp
	 * blocks openat(). Cache all fields since the returned pointer
	 * is static and may be overwritten.
	 *
	 * If the user doesn't exist in /etc/passwd, we still proceed
	 * to the password prompt so the attacker cannot distinguish
	 * "user not found" from "bad password" by timing or behavior.
	 * mgmtd's AUTH_LOGIN handles non-existent users with constant-
	 * time crypt to prevent timing side-channels.
	 */
	struct passwd *pw = getpwnam(username);
	int user_found = (pw != NULL);
	uid_t cached_uid = pw ? pw->pw_uid : 65534;
	gid_t cached_gid = pw ? pw->pw_gid : 65534;
	char cached_shell[256], cached_home[256];
	snprintf(cached_shell, sizeof(cached_shell), "%s",
		 (pw && pw->pw_shell && pw->pw_shell[0])
			? pw->pw_shell : "/bin/sh");
	snprintf(cached_home, sizeof(cached_home), "%s",
		 (pw && pw->pw_dir) ? pw->pw_dir : "/");

	/*
	 * initgroups() reads /etc/group — must happen before seccomp.
	 * Setting supplementary groups as root is harmless; they only
	 * take effect after setuid(). Skip if user doesn't exist.
	 */
	if (user_found && initgroups(username, cached_gid) != 0)
		perror("initgroups");

	/*
	 * Check if password is empty (first-login scenario).
	 * getspnam() reads /etc/shadow — must happen before seccomp.
	 * If shadow password is empty, we'll skip authentication and
	 * go straight to password creation (better UX than prompting
	 * for a password that doesn't exist yet).
	 */
	int empty_password = 0;
	if (user_found) {
		struct spwd *sp = getspnam(username);
		if (sp && sp->sp_pwdp && sp->sp_pwdp[0] == '\0')
			empty_password = 1;
	}

	/*
	 * Open console fd for later use (before seccomp blocks openat).
	 * The actual dup2() + TIOCSCTTY happen in Phase 3.
	 */
	int console_fd = open("/dev/console", O_RDWR);

	/* ── Phase 1.5: Install seccomp sandbox ──────────────────────── */
	if (logind_drop_privileges() != 0) {
		fprintf(stderr, "stargazer-logind: security initialization failed\n");
		return 1;
	}

	/*
	 * From this point on:
	 *   - open/openat BLOCKED (no file access)
	 *   - fork/clone  BLOCKED (no process creation)
	 *   - ptrace      BLOCKED (no debugging)
	 *   - Only AF_UNIX sockets allowed (IPC to mgmtd)
	 */

	/* ── Phase 2: Authentication via IPC (sandboxed) ─────────────── */

	/*
	 * First-login fast path: if password is empty, skip authentication
	 * and go straight to password creation. Better UX than prompting
	 * "Password:" when no password exists yet.
	 */
	if (empty_password) {
		fprintf(stderr,
			"\n"
			" FIRST LOGIN\n"
			" No password set for account '%s'.\n"
			" You must create a password now.\n\n",
			username);

		int rc = ipc_password_change(username, "first-login");
		if (rc == -2) return EXIT_SIGINT;
		if (rc != 0)  return 1;

		fprintf(stderr,
			" Password created successfully.\n"
			" Please log in again with your new password.\n\n");
		return 0;
	}

	/*
	 * Normal authentication flow (password exists)
	 */
	char password[MAX_PASS_LEN];
	int pw_rc = read_password("Password: ", password, sizeof(password));
	if (pw_rc == -2) {
		explicit_bzero(password, sizeof(password));
		return EXIT_SIGINT;
	}
	if (pw_rc != 0) {
		return 1;
	}

	/* Send credentials to mgmtd for authentication */
	char auth_payload[MAX_PASS_LEN + SG_USERNAME_MAX + 4];
	snprintf(auth_payload, sizeof(auth_payload), "%s\n%s\n",
		 username, password);
	explicit_bzero(password, sizeof(password));

	uint32_t status;
	char extra[SG_EXTRA_MAX];
	char *resp_payload = NULL;
	int ipc_rc = logind_ipc(SG_CMD_AUTH_LOGIN, username, auth_payload,
				&status, extra, sizeof(extra), &resp_payload);
	explicit_bzero(auth_payload, sizeof(auth_payload));

	if (ipc_rc != 0) {
		fprintf(stderr,
			"stargazer-logind: cannot contact management daemon\n");
		return 1;
	}

	if (status != SG_OK) {
		/* Don't reveal whether it's bad password vs locked — same msg */
		fprintf(stderr, "Invalid credentials\n");
		free(resp_payload);
		return 1;
	}

	/*
	 * Defense-in-depth: if mgmtd authenticated a user that doesn't
	 * exist in /etc/passwd, we cannot safely setuid/exec.  This
	 * should never happen (mgmtd checks shadow which requires a
	 * passwd entry), but catch it here rather than exec as nobody.
	 */
	if (!user_found) {
		fprintf(stderr, "Internal error: user not in passwd\n");
		free(resp_payload);
		return 1;
	}

	/* Parse response: "enforce_change=0|1\npolicy_mismatch=0|1\n" */
	int enforce_change = 0, policy_mismatch = 0;
	if (resp_payload) {
		const char *p;
		p = strstr(resp_payload, "enforce_change=");
		if (p) enforce_change = atoi(p + 15);
		p = strstr(resp_payload, "policy_mismatch=");
		if (p) policy_mismatch = atoi(p + 16);
		free(resp_payload);
		resp_payload = NULL;
	}

	/* Handle forced password changes */
	if (enforce_change) {
		int rc = ipc_password_change(username, "admin-flag");
		if (rc == -2) return EXIT_SIGINT;
		if (rc != 0)  return 1;
		/* Admin flag change satisfies policy too */
		policy_mismatch = 0;
	}

	if (policy_mismatch) {
		int rc = ipc_password_change(username, "policy-mismatch");
		if (rc == -2) return EXIT_SIGINT;
		if (rc != 0)  return 1;
	}

	/* Audit successful login */
	char login_payload[SG_USERNAME_MAX + 4];
	snprintf(login_payload, sizeof(login_payload), "%s\n", username);
	logind_ipc(SG_CMD_AUTH_LOGIN_OK, username, login_payload,
		   &status, extra, sizeof(extra), NULL);

	/* ── Phase 3: Privilege drop + exec ──────────────────────────── */

	/* Restore signals to default before exec */
	signal(SIGINT, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);

	/*
	 * Establish clean session and redirect stdio to /dev/console.
	 *
	 * setsid() creates a new session so the CLI is isolated from the
	 * login shell's process group.  TIOCSCTTY(0) attempts to set the
	 * controlling terminal.
	 */
	(void)setsid();
	if (console_fd >= 0) {
		(void)ioctl(console_fd, TIOCSCTTY, 0);
		dup2(console_fd, STDIN_FILENO);
		dup2(console_fd, STDOUT_FILENO);
		dup2(console_fd, STDERR_FILENO);
		if (console_fd > STDERR_FILENO)
			close(console_fd);
	}

	/*
	 * Drop to actual user credentials.
	 * After setuid(), the process cannot regain root.
	 */
	if (setgid(cached_gid) != 0) {
		perror("setgid");
		return 1;
	}
	if (setuid(cached_uid) != 0) {
		perror("setuid");
		return 1;
	}

	/* Set environment */
	setenv("HOME", cached_home, 1);
	setenv("SHELL", cached_shell, 1);
	setenv("USER", username, 1);
	setenv("LOGNAME", username, 1);
	setenv("STARGAZER_USER", username, 1);
	setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 0);
	setenv("TMOUT", "900", 1); /* 15-min idle session timeout */

	/* exec user shell */
	execl(cached_shell, cached_shell, (char *)NULL);
	perror("exec");
	return 1;
}
