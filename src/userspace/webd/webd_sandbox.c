/* SPDX-License-Identifier: MIT */
/*
 * webd_sandbox.c — seccomp-bpf lockdown for stargazer-webd
 *
 * Installed after privilege drop and thread pool creation.
 * Allows network I/O (Mongoose HTTP serving), AF_UNIX IPC,
 * threading primitives (futex), and static file reads.
 *
 * Blocks: fork, clone, clone3, execve, ptrace, openat O_RDWR,
 *         non-AF_UNIX/AF_INET sockets.
 */

#define _GNU_SOURCE
#include "webd_sandbox.h"

#include <errno.h>
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

/* aarch64 syscall numbers (asm-generic/unistd.h) */
#define SC_openat           56
#define SC_close            57
#define SC_unlinkat         35
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
#define SC_getpid          172
#define SC_getuid          174
#define SC_gettid          178
#define SC_socket          198
#define SC_bind            200
#define SC_listen          201
#define SC_accept4         202
#define SC_connect         203
#define SC_getsockname     204
#define SC_getpeername     205
#define SC_sendto          206
#define SC_recvfrom        207
#define SC_setsockopt      208
#define SC_getsockopt      209
#define SC_brk             214
#define SC_munmap          215
#define SC_mremap          216
#define SC_fcntl            25
#define SC_mmap            222
#define SC_mprotect        226
#define SC_madvise         233
#define SC_getrandom       278
#define SC_epoll_create1    20
#define SC_epoll_ctl        21
#define SC_epoll_pwait      22
#define SC_ioctl            29

/* Socket constants */
#define AF_UNIX_VAL     1
#define AF_INET_VAL     2
#define SOCK_STREAM_VAL 1

/* ioctl request numbers */
#define SIOCGIFADDR_VAL 0x8915  /* get interface IPv4 address (read-only) */

/* PROT_EXEC = 0x4 */
#define PROT_EXEC_VAL   4

/* O_WRONLY=1, O_RDWR=2 */
#define O_ACCMODE_MASK  3
#define O_RDONLY_VAL    0
#define O_WRONLY_VAL    1

/* seccomp_data offsets */
#define OFF_NR   offsetof(struct seccomp_data, nr)
#define OFF_ARCH offsetof(struct seccomp_data, arch)
#define OFF_ARG0 16
#define OFF_ARG1 24
#define OFF_ARG2 32

/* BPF convenience: unconditionally allow a syscall */
#define SC_ALLOW(nr) \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

#ifdef SANDBOX_LOG_ONLY
	#define SECCOMP_RET_DEFAULT SECCOMP_RET_LOG
#else
	#define SECCOMP_RET_DEFAULT SECCOMP_RET_KILL_PROCESS
#endif

int webd_sandbox_install(void)
{
	/* PR_SET_NO_NEW_PRIVS must be set before seccomp */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		fprintf(stderr, "webd: PR_SET_NO_NEW_PRIVS failed: %s\n",
			strerror(errno));
		return -1;
	}

	/* Prevent core dumps */
	prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

	struct sock_filter filter[] = {
		/* ── Verify architecture ─────────────────────────── */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

		/* ── Load syscall number ─────────────────────────── */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),

		/* ── I/O ─────────────────────────────────────────── */
		SC_ALLOW(SC_read),
		SC_ALLOW(SC_write),
		SC_ALLOW(SC_readv),
		SC_ALLOW(SC_writev),
		SC_ALLOW(SC_close),
		SC_ALLOW(SC_lseek),

		/* ── Polling (Mongoose uses epoll on Linux) ──────── */
		SC_ALLOW(SC_ppoll),
		SC_ALLOW(SC_epoll_create1),
		SC_ALLOW(SC_epoll_ctl),
		SC_ALLOW(SC_epoll_pwait),

		/* ── socket(): AF_UNIX or AF_INET only ───────────── */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SC_socket, 0, 8),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX_VAL, 4, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET_VAL, 3, 0),
		/* Unknown domain → deny */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_DEFAULT),
		/* skip to here on match: mask type, check SOCK_STREAM */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG1),
		BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xFF),
		/* Allow SOCK_STREAM (1) unconditionally for AF_UNIX/AF_INET */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

		/* ── Network ops ─────────────────────────────────── */
		SC_ALLOW(SC_accept4),
		SC_ALLOW(SC_connect),
		SC_ALLOW(SC_bind),
		SC_ALLOW(SC_listen),
		SC_ALLOW(SC_getsockname),
		SC_ALLOW(SC_getpeername),
		SC_ALLOW(SC_sendto),
		SC_ALLOW(SC_recvfrom),
		SC_ALLOW(SC_setsockopt),
		SC_ALLOW(SC_getsockopt),

		/* ── openat: O_RDONLY (file serving) and O_WRONLY (firmware
		 *    upload staging to /tmp/sg-fw-upload.<rand>, opened
		 *    O_WRONLY|O_CREAT|O_EXCL — NOT mkstemp, which is O_RDWR);
		 *    O_RDWR is never required and remains blocked. */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SC_openat, 0, 6),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG2),
		BPF_STMT(BPF_ALU | BPF_AND | BPF_K, O_ACCMODE_MASK),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_RDONLY_VAL, 1, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_WRONLY_VAL, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_DEFAULT),

		/* ── Memory management ───────────────────────────── */
		/* mmap: deny PROT_EXEC */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SC_mmap, 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG2),
		BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_EXEC_VAL),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_DEFAULT),

		SC_ALLOW(SC_munmap),

		/* mprotect: deny PROT_EXEC */
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

		/* ── Identity / introspection ────────────────────── */
		SC_ALLOW(SC_getuid),
		SC_ALLOW(SC_getpid),
		SC_ALLOW(SC_gettid),

		/* ── prctl: limited operations ───────────────────── */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SC_prctl, 0, 6),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_GET_SECCOMP, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_GET_NO_NEW_PRIVS, 1, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_NAME, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),

		/* ── Threading (mutex/condvar after sandbox) ──────── */
		SC_ALLOW(SC_futex),
		SC_ALLOW(SC_getrandom),
		SC_ALLOW(SC_set_tid_address),
		SC_ALLOW(SC_set_robust_list),

		/* ── Misc ────────────────────────────────────────── */
		SC_ALLOW(SC_fcntl),
		SC_ALLOW(SC_newfstatat),
		/* unlinkat: clean up this process's own firmware staging temp
		 * (/tmp/sg-fw-upload.*) on the upload error paths. unlink() is
		 * unlinkat on aarch64; without this, an upload error path would
		 * be killed by the filter. Bounded: webd can already create and
		 * O_TRUNC files it owns, so deleting its own temps adds little. */
		SC_ALLOW(SC_unlinkat),
		SC_ALLOW(SC_exit_group),

		/* ── ioctl: SIOCGIFADDR only ─────────────────────
		 * Required by bind_listeners()/rebind_listeners() to read the
		 * kernel-assigned IP of DHCP interfaces after lease acquisition. */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SC_ioctl, 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG1),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIOCGIFADDR_VAL, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_DEFAULT),

		/* ── Default: KILL ───────────────────────────────── */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_DEFAULT),
	};

	struct sock_fprog prog = {
		.len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
		fprintf(stderr, "webd: seccomp install failed: %s\n",
			strerror(errno));
		return -1;
	}

	return 0;
}
