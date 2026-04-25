/* SPDX-License-Identifier: MIT */
/*
 * cli_sandbox.c — seccomp-bpf + Landlock + capability sandbox
 *
 * After cli_sandbox_install(), the CLI process can only:
 *   - Read/write on pre-opened fds (terminal, IPC sockets)
 *   - Open AF_UNIX sockets (for new IPC connections to mgmtd)
 *   - Terminal ioctls (TIOCGWINSZ, TCGETS/TCSETS variants)
 *   - Memory management (mmap, brk, munmap, mprotect, madvise, mremap)
 *     Note: mmap/mprotect deny PROT_EXEC to prevent RWX shellcode
 *   - Signal handling, timing, identity queries
 *   - prctl: only PR_GET_SECCOMP, PR_GET_NO_NEW_PRIVS, PR_SET_NAME
 *
 * Everything else — especially openat, execve, fork/clone, and
 * non-AF_UNIX sockets — triggers SECCOMP_RET_KILL_PROCESS.
 *
 * Defense-in-depth layers:
 *   1. Landlock: deny all filesystem access (openat returns EACCES)
 *   2. Capabilities: drop all capabilities
 *   3. PR_SET_NO_NEW_PRIVS: prevent privilege escalation
 *   4. PR_SET_DUMPABLE(0): prevent core dumps leaking data
 *   5. seccomp-bpf: allowlist of ~40 syscalls, arg checks on
 *      socket(AF_UNIX+SOCK_STREAM), ioctl(terminal), mmap/mprotect(!EXEC),
 *      prctl(GET_SECCOMP/GET_NO_NEW_PRIVS/SET_NAME)
 */

#define _GNU_SOURCE
#include "cli_sandbox.h"

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

/* ── Landlock (optional defense-in-depth) ──────────────────────────────── */

/*
 * Landlock syscall wrappers. These are raw syscalls because musl
 * doesn't provide libc wrappers for Landlock.
 */

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self  446
#endif

/* Landlock ABI v1 access bits (all filesystem operations) */
#define LANDLOCK_ACCESS_FS_ALL ( \
	(1ULL << 0)  /* EXECUTE */      | \
	(1ULL << 1)  /* WRITE_FILE */   | \
	(1ULL << 2)  /* READ_FILE */    | \
	(1ULL << 3)  /* READ_DIR */     | \
	(1ULL << 4)  /* REMOVE_DIR */   | \
	(1ULL << 5)  /* REMOVE_FILE */  | \
	(1ULL << 6)  /* MAKE_CHAR */    | \
	(1ULL << 7)  /* MAKE_DIR */     | \
	(1ULL << 8)  /* MAKE_REG */     | \
	(1ULL << 9)  /* MAKE_SOCK */    | \
	(1ULL << 10) /* MAKE_FIFO */    | \
	(1ULL << 11) /* MAKE_BLOCK */   | \
	(1ULL << 12) /* MAKE_SYM */     \
)

struct landlock_ruleset_attr {
	__u64 handled_access_fs;
};

static int install_landlock(void)
{
	struct landlock_ruleset_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.handled_access_fs = LANDLOCK_ACCESS_FS_ALL;

	int ruleset_fd = (int)syscall(__NR_landlock_create_ruleset,
				      &attr, sizeof(attr), 0);
	if (ruleset_fd < 0) {
		/* ENOSYS = kernel too old, EOPNOTSUPP = disabled in boot params.
		 * Both are graceful fallbacks — seccomp alone is still strong. */
		if (errno == ENOSYS || errno == EOPNOTSUPP)
			return 0;
		return -1;
	}

	/* Add NO path rules → deny all filesystem access.
	 * Pre-opened fds still work (Landlock restricts open, not read/write). */
	if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) != 0) {
		close(ruleset_fd);
		return -1;
	}

	close(ruleset_fd);
	return 0;
}

/* ── Capability drop ───────────────────────────────────────────────────── */

/*
 * Drop all capabilities. We use prctl() which doesn't need libcap.
 * After this, even if the binary is setuid, it has no special powers.
 */

/* Linux capability header/data structures for capset(2) */
struct cap_header {
	__u32 version;
	int   pid;
};

struct cap_data {
	__u32 effective;
	__u32 permitted;
	__u32 inheritable;
};

#ifndef _LINUX_CAPABILITY_VERSION_3
#define _LINUX_CAPABILITY_VERSION_3 0x20080522
#endif

static int drop_capabilities(void)
{
	/* Set all capability sets to zero */
	struct cap_header hdr;
	struct cap_data data[2]; /* v3 uses 2 data structs for 64 caps */

	memset(&hdr, 0, sizeof(hdr));
	memset(data, 0, sizeof(data));
	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	hdr.pid = 0; /* self */

	if (syscall(SYS_capset, &hdr, data) != 0)
		return -1;

	return 0;
}

/* ── seccomp-bpf filter ────────────────────────────────────────────────── */

/*
 * aarch64 syscall numbers (from asm-generic/unistd.h)
 * The aarch64 ABI uses the generic syscall table.
 */
#define SC_fcntl            25
#define SC_ioctl            29
#define SC_ftruncate        46
#define SC_openat           56
#define SC_close            57
#define SC_lseek            62
#define SC_read             63
#define SC_write            64
#define SC_readv            65
#define SC_writev           66
#define SC_ppoll            73
#define SC_newfstatat       79
#define SC_exit_group       94
#define SC_set_tid_address  96
#define SC_futex            98
#define SC_set_robust_list  99
#define SC_nanosleep       101
#define SC_clock_gettime   113
#define SC_clock_nanosleep 115
#define SC_rt_sigaction    134
#define SC_rt_sigprocmask  135
#define SC_rt_sigreturn    139
#define SC_prctl           167
#define SC_gettimeofday    169
#define SC_getpid          172
#define SC_getuid          174
#define SC_gettid          178
#define SC_socket          198
#define SC_connect         203
#define SC_sendto          206
#define SC_recvfrom        207
#define SC_setsockopt      208
#define SC_getsockopt      209
#define SC_brk             214
#define SC_munmap          215
#define SC_mremap          216
#define SC_mmap            222
#define SC_mprotect        226
#define SC_madvise         233
#define SC_getrandom       278

/* Terminal ioctl values */
#define IOCTL_TCGETS     0x5401
#define IOCTL_TCSETS     0x5402
#define IOCTL_TCSETSW    0x5403
#define IOCTL_TCSETSF    0x5404
#define IOCTL_TCFLSH     0x540B
#define IOCTL_TIOCGWINSZ 0x5413

/* AF_UNIX = 1, SOCK_STREAM = 1 */
#define AF_UNIX_VAL     1
#define SOCK_STREAM_VAL 1

/* PROT_EXEC = 0x4 */
#define PROT_EXEC_VAL 4

/*
 * BPF convenience macros.
 *
 * SC_ALLOW: unconditionally allow a syscall.
 * The pattern is: if (nr == X) return ALLOW; else fall through.
 */
#define SC_ALLOW(nr) \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

/*
 * seccomp_data layout on aarch64:
 *   offset  0: int   nr          (syscall number)
 *   offset  4: __u32 arch        (audit arch)
 *   offset  8: __u64 instruction_pointer
 *   offset 16: __u64 args[0]
 *   offset 24: __u64 args[1]
 *   offset 32: __u64 args[2]
 *   offset 40: __u64 args[3]
 *   offset 48: __u64 args[4]
 *   offset 56: __u64 args[5]
 */
#define OFF_NR   offsetof(struct seccomp_data, nr)
#define OFF_ARCH offsetof(struct seccomp_data, arch)
/*
 * Hardcoded offsets for args[0] and args[1] because offsetof() with
 * array subscripts inside BPF_STMT macros confuses the C preprocessor.
 * seccomp_data layout: nr(4) + arch(4) + ip(8) + args[6×8]
 *   args[0] = offset 16, args[1] = offset 24
 */
#define OFF_ARG0 16
#define OFF_ARG1 24
#define OFF_ARG2 32

/*
 * SIGSYS handler for SANDBOX_TRAP_MODE: prints the blocked syscall number
 * to stderr, then the process continues (the blocked call returns -ENOSYS).
 */
#ifdef SANDBOX_TRAP_MODE
static void sigsys_handler(int sig, siginfo_t *info, void *ctx)
{
	(void)sig; (void)ctx;
	char buf[128];
	int n = snprintf(buf, sizeof(buf),
			 "\n[SANDBOX-TRAP] blocked syscall=%d\n",
			 info->si_syscall);
	if (n > 0)
		(void)write(STDERR_FILENO, buf, (size_t)n);
}
#endif

static int install_seccomp(void)
{
	/*
	 * Build modes for the default seccomp action:
	 *   SANDBOX_TRAP_MODE: SECCOMP_RET_TRAP — sends SIGSYS (caught by
	 *     handler above which prints the syscall#), blocked call returns
	 *     -ENOSYS. Use for debugging which syscalls need to be allowed.
	 *   SANDBOX_LOG_ONLY:  SECCOMP_RET_LOG — violations logged in dmesg,
	 *     syscall proceeds normally. Use for testing without killing.
	 *   Default:           SECCOMP_RET_KILL_PROCESS — production mode.
	 */
#ifdef SANDBOX_TRAP_MODE
	#define SECCOMP_RET_DEFAULT SECCOMP_RET_TRAP
#elif defined(SANDBOX_LOG_ONLY)
	#define SECCOMP_RET_DEFAULT SECCOMP_RET_LOG
#else
	#define SECCOMP_RET_DEFAULT SECCOMP_RET_KILL_PROCESS
#endif

	struct sock_filter filter[] = {
		/* ── Verify architecture is aarch64 ──────────────── */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

		/* ── Load syscall number ─────────────────────────── */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),

		/* ── I/O on pre-opened fds ───────────────────────── */
		SC_ALLOW(SC_read),
		SC_ALLOW(SC_write),
		SC_ALLOW(SC_readv),
		SC_ALLOW(SC_writev),
		SC_ALLOW(SC_close),
		SC_ALLOW(SC_lseek),
		SC_ALLOW(SC_ftruncate),

		/* ── Multiplexing ────────────────────────────────── */
		SC_ALLOW(SC_ppoll),

		/* ── socket(): only AF_UNIX + SOCK_STREAM ────────── */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SC_socket, 0, 7),
		/* Load arg0 (domain) — low 32 bits on LE aarch64 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX_VAL, 0, 4),
		/* Load arg1 (type) and mask off SOCK_CLOEXEC|SOCK_NONBLOCK */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG1),
		BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xFF),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM_VAL, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* Reload syscall number for subsequent checks */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),

		/* ── IPC socket ops ──────────────────────────────── */
		SC_ALLOW(SC_connect),
		SC_ALLOW(SC_sendto),
		SC_ALLOW(SC_recvfrom),
		SC_ALLOW(SC_getsockopt),
		SC_ALLOW(SC_setsockopt),

		/* ── ioctl(): only allowed terminal ioctls ───────── *
		 * If not ioctl, skip 9 instructions to land at mmap.
		 * The accumulator still holds NR (BPF_JUMP doesn't
		 * clobber it), so no reload needed on the skip path. */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SC_ioctl, 0, 9),
		/* Load arg1 (ioctl command) — low 32 bits */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG1),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IOCTL_TIOCGWINSZ, 5, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IOCTL_TCGETS, 4, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IOCTL_TCSETS, 3, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IOCTL_TCSETSW, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IOCTL_TCSETSF, 1, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IOCTL_TCFLSH, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		/* Unrecognized ioctl command → deny */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_DEFAULT),

		/* ── Memory management ───────────────────────────── */

		/* mmap: deny PROT_EXEC (arg2 & 0x4 must be 0) */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SC_mmap, 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG2),
		BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_EXEC_VAL),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_DEFAULT),

		SC_ALLOW(SC_munmap),

		/* mprotect: deny PROT_EXEC (arg2 & 0x4 must be 0) */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SC_mprotect, 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG2),
		BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_EXEC_VAL),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_DEFAULT),

		SC_ALLOW(SC_madvise),
		SC_ALLOW(SC_mremap),
		SC_ALLOW(SC_brk),

		/* ── Signals ─────────────────────────────────────── */
		SC_ALLOW(SC_rt_sigaction),
		SC_ALLOW(SC_rt_sigprocmask),
		SC_ALLOW(SC_rt_sigreturn),

		/* ── Timing ──────────────────────────────────────── */
		SC_ALLOW(SC_clock_gettime),
		SC_ALLOW(SC_clock_nanosleep),
		SC_ALLOW(SC_nanosleep),
		SC_ALLOW(SC_gettimeofday),

		/* ── Identity / introspection ────────────────────── */
		SC_ALLOW(SC_getuid),
		SC_ALLOW(SC_getpid),
		SC_ALLOW(SC_gettid),

		/* prctl: only allow specific operations */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SC_prctl, 0, 6),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_GET_SECCOMP, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_GET_NO_NEW_PRIVS, 1, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_NAME, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),

		/* ── musl internals ──────────────────────────────── */
		SC_ALLOW(SC_futex),
		SC_ALLOW(SC_getrandom),
		SC_ALLOW(SC_set_tid_address),
		SC_ALLOW(SC_set_robust_list),

		/* ── Misc (musl stdio/fstat) ─────────────────────── */
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

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0)
		return -1;

	return 0;
}

/* ── Public API ────────────────────────────────────────────────────────── */

int cli_sandbox_install(void)
{
	/* 1. Landlock: deny all filesystem access (graceful fallback) */
	if (install_landlock() != 0) {
		fprintf(stderr, "sandbox: landlock install failed: %s\n",
			strerror(errno));
		return -1;
	}

	/* 2. Drop all capabilities */
	if (drop_capabilities() != 0) {
		fprintf(stderr, "sandbox: capability drop failed: %s\n",
			strerror(errno));
		return -1;
	}

	/* 3. Prevent privilege escalation */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		fprintf(stderr, "sandbox: PR_SET_NO_NEW_PRIVS failed: %s\n",
			strerror(errno));
		return -1;
	}

	/* 4. Prevent core dumps leaking IPC data (non-fatal) */
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
		fprintf(stderr, "sandbox: PR_SET_DUMPABLE failed: %s\n",
			strerror(errno));

	/* 5. In TRAP mode, install SIGSYS handler before seccomp so we can
	 *    catch and report blocked syscalls instead of dying silently. */
#ifdef SANDBOX_TRAP_MODE
	{
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_sigaction = sigsys_handler;
		sa.sa_flags = SA_SIGINFO;
		sigemptyset(&sa.sa_mask);
		sigaction(SIGSYS, &sa, NULL);
	}
#endif

	/* 6. Install seccomp-bpf filter (must be after Landlock, because
	 *    Landlock uses its own syscalls that seccomp would block) */
	if (install_seccomp() != 0) {
		fprintf(stderr, "sandbox: seccomp install failed: %s\n",
			strerror(errno));
		return -1;
	}

	return 0;
}
