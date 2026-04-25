# CLI Process Isolation — Architecture Flow

## Overview

The Stargazer CLI operates as a **pure terminal-to-IPC bridge** after sandbox
installation. All privileged operations (file reads, process spawning, network
access, firewall rules) are proxied through mgmtd — a root daemon that
validates permissions per-request.

```
                        TRUST BOUNDARY
                             │
   ┌─────────────────────────┼──────────────────────────────┐
   │  Unprivileged (sandbox) │  Privileged (root)           │
   │                         │                              │
   │  ┌──────────────────┐   │   ┌────────────────────┐     │
   │  │                  │   │   │                    │     │
   │  │  stargazer-cli   │───────│  stargazer-mgmtd   │     │
   │  │                  │ IPC   │                    │     │
   │  │  seccomp-bpf     │ Unix  │  root daemon       │     │
   │  │  Landlock        │ sock  │  SQLite config DB  │     │
   │  │  no capabilities │   │   │  /proc, /sys reads │     │
   │  │  no_new_privs    │   │   │  iptables exec     │     │
   │  │                  │   │   │  shadow file access │     │
   │  └──────┬───────────┘   │   └────────────────────┘     │
   │         │               │                              │
   │    ┌────┴────┐          │                              │
   │    │ Terminal │          │                              │
   │    │ (tty)   │          │                              │
   │    └─────────┘          │                              │
   └─────────────────────────┼──────────────────────────────┘
                             │
```

---

## 1. Boot → Login → CLI Startup

```
┌─────────────────────────────────────────────────────────────────────┐
│ BOOT (init script)                                                  │
│                                                                     │
│  1. Mount filesystems, mount /etc/stargazer (persistent partition)   │
│     ├── Restore /etc/shadow from /etc/stargazer/shadow              │
│     ├── Restore /etc/passwd from /etc/stargazer/passwd              │
│     └── Restore /etc/group  from /etc/stargazer/group               │
│  2. Ensure stargazer group exists (first boot: create; else: no-op) │
│  3. Load kernel modules (/etc/init.d/stargazer start)               │
│  4. Start stargazer-mgmtd (root daemon, FIFO readiness)            │
│     ├── Open /etc/stargazer/stargazer.db (0600)                     │
│     ├── Seed defaults (admin user, profiles, password policy)       │
│     ├── Sync network interfaces from kernel                         │
│     ├── Initialize firewall (INPUT DROP, allow loopback+return)     │
│     ├── Replay config (system_admin → ensure group membership)      │
│     ├── Create /run/stargazer-mgmtd.sock (0660 root:stargazer)     │
│     ├── Signal readiness via FIFO (/run/mgmtd-ready)               │
│     └── Enter accept() loop (single-threaded)                       │
│  5. Init blocks on FIFO read (zero-CPU wait for mgmtd ready)       │
│  6. Start login loop: setsid -c /sbin/stargazer-login               │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ LOGIN (stargazer-login → stargazer-logind)                          │
│                                                                     │
│  stargazer-login (shell script, runs as root):                      │
│    1. Ensure admin account exists in /etc/passwd                    │
│    2. Prompt "login: " → read username                              │
│    3. Normalize to lowercase (prevent lockout bypass)               │
│    4. Check lockout state (escalating: 2m → 4m → ... → 1hr)        │
│    5. Exec stargazer-logind <username>                              │
│                                                                     │
│  stargazer-logind (C binary, runs as root):                         │
│    1. Prompt "Password: " with echo disabled                        │
│    2. Authenticate against /etc/shadow (bcrypt hash)                │
│    3. If enforce_change_password flag set → force password change    │
│    4. Audit log the result (success/fail)                           │
│    5. Drop privileges: setuid/setgid to user's UID/GID             │
│    6. Set environment: STARGAZER_USER, HOME, USER                   │
│    7. execl("/sbin/stargazer-cli")                                  │
│       ─── process image replaced, now running as unprivileged ───   │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
```

---

## 2. CLI Startup — Two Stages

The CLI opens exactly one file — `/dev/tty` — then immediately locks down.
Everything else (WHOAMI, history, debug state) happens via IPC inside the
sandbox. There is no "pre-sandbox" stage beyond the terminal open.

```
┌─────────────────────────────────────────────────────────────────────┐
│ STAGE 1: SANDBOX INSTALLATION (3 steps before lockdown)             │
│                                                                     │
│  1. Read $STARGAZER_USER from environment                           │
│  2. ipc_init(user) → store username for IPC calls                   │
│  3. cli_term_init() → open("/dev/tty") ← ONLY file open            │
│     └── This is the terminal fd. Cannot be opened via IPC because   │
│         it is a kernel device bound to the calling process's ctty.  │
│                                                                     │
│  ════════════════════════════════════════════════════════            │
│  cli_sandbox_install() — all 5 layers installed here.               │
│  After this point: openat, execve, fork, clone → SIGKILL            │
│  ════════════════════════════════════════════════════════            │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STAGE 2: SANDBOXED INITIALIZATION + REPL                            │
│                                                                     │
│  All initialization below runs INSIDE the sandbox.                  │
│  Every operation uses either pre-opened fds or AF_UNIX IPC.         │
│                                                                     │
│  4. WHOAMI via IPC → fetch profile + permissions from mgmtd         │
│     ├── Retries 5x with 200ms backoff (mgmtd may be starting)      │
│     └── Response: "profile=read-write\npermissions=monitor,...\n"    │
│  5. Register commands based on permissions                          │
│  6. Load history via IPC → SG_CMD_HISTORY_LOAD                      │
│     └── mgmtd reads /tmp/stargazer_cli_history_<user>, returns text │
│  7. Print banner                                                    │
│                                                                     │
│  Debug state loads lazily on first access via IPC                   │
│  (SG_CMD_DEBUG_STATE_GET). See §5 "IPC Deadlock Prevention".        │
│                                                                     │
│  ── REPL loop ───────────────────────────────────────────────────── │
│                                                                     │
│  while (line = cli_readline("stargazer> ")) {                       │
│    1. Resolve abbreviations: "exe sys shut" → "execute sys shut"    │
│    2. Check session revision via IPC (detect account changes)       │
│    3. Dispatch to handler:                                          │
│       ├── show status      → IPC(SG_CMD_SHOW_STATUS)               │
│       ├── show interfaces  → IPC(SG_CMD_SHOW_IFACES)               │
│       ├── show routes      → IPC(SG_CMD_SHOW_ROUTES)               │
│       ├── configure        → IPC(CFG_GET/SET/DEL) interactive       │
│       ├── exe diagnose cpu → IPC(SG_CMD_DIAG_CPU) x2 with delta    │
│       ├── exe diagnose top → IPC(SG_CMD_DIAG_PROCTOP) poll loop    │
│       ├── exe ping <host>  → IPC(SG_CMD_NET_PING) streaming        │
│       ├── debug enable     → IPC(SG_CMD_DEBUG_STATE_SET)            │
│       └── selftest full    → IPC(SG_CMD_PING) + prctl() checks     │
│    4. Fetch debug traces from mgmtd (if debug enabled)              │
│    5. Refresh session baseline after config-changing commands        │
│  }                                                                  │
│                                                                     │
│  On exit:                                                           │
│    cli_hist_save_ipc(user) → IPC(SG_CMD_HISTORY_SAVE)              │
│    cli_hist_load_ipc()     ← IPC(SG_CMD_HISTORY_LOAD) at startup   │
│    (both directions via mgmtd, no direct file access)               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Seccomp-BPF Allowlist

The BPF filter checks each syscall against this allowlist. Anything not
listed triggers instant process termination.

```
┌─────────────────────────────────────────────────────────────────────┐
│ ALLOWED (with restrictions)                                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  I/O on pre-opened fds:                                             │
│    read(63)  write(64)  readv(65)  writev(66)                       │
│    close(57)  lseek(62)  ftruncate(46)                              │
│                                                                     │
│  Multiplexing:                                                      │
│    ppoll(73)                                                        │
│                                                                     │
│  IPC (AF_UNIX only — arg0 checked):                                 │
│    socket(198) ← only if domain == AF_UNIX (1)                      │
│    connect(203)  sendto(206)  recvfrom(207)                         │
│    getsockopt(209)  setsockopt(208)                                 │
│                                                                     │
│  Terminal (ioctl arg1 checked):                                     │
│    ioctl(29) ← only TIOCGWINSZ, TCGETS, TCSETS, TCSETSW,           │
│                TCSETSF, TCFLSH                                      │
│                                                                     │
│  Memory (musl allocator):                                           │
│    mmap(222)  munmap(215)  mprotect(226)  madvise(233)              │
│    mremap(216)  brk(214)                                            │
│                                                                     │
│  Signals:                                                           │
│    rt_sigaction(134)  rt_sigprocmask(135)  rt_sigreturn(139)        │
│                                                                     │
│  Timing:                                                            │
│    clock_gettime(113)  clock_nanosleep(115)                         │
│    nanosleep(101)  gettimeofday(169)                                │
│                                                                     │
│  Identity / introspection:                                          │
│    getuid(174)  getpid(172)  gettid(178)  prctl(167)               │
│                                                                     │
│  musl internals:                                                    │
│    futex(98)  getrandom(278)  set_tid_address(96)                   │
│    set_robust_list(99)                                              │
│                                                                     │
│  Misc:                                                              │
│    fcntl(25)  newfstatat(79)  exit_group(94)                        │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│ BLOCKED (everything else → SECCOMP_RET_KILL_PROCESS)                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Filesystem:  openat  unlinkat  renameat  mkdirat  fchmodat         │
│  Process:     execve  execveat  clone  clone3  fork  vfork          │
│  Network:     socket(AF_INET)  socket(AF_INET6)                     │
│  Privilege:   mount  umount2  ptrace  chroot  pivot_root            │
│  ioctl:       any non-terminal ioctl command                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. IPC Protocol Flow

Every CLI operation after sandbox follows this pattern:

```
  CLI (sandboxed)                          mgmtd (root)
  ─────────────                            ────────────
       │                                        │
       │  1. socket(AF_UNIX)                    │
       │  2. connect(/run/stargazer-mgmtd.sock) │
       │─────────────────────────────────────── │
       │         sg_request_hdr_t               │
       │  ┌──────────────────────────┐          │
       │  │ magic:   0x5347 ("SG")   │          │
       │  │ version: 1               │          │
       │  │ cmd:     SG_CMD_*        │─────────▶│ 3. Verify SO_PEERCRED (uid)
       │  │ user:    "admin"         │          │ 4. Check permissions
       │  │ payload: "key=val\n..."  │          │ 5. Execute as root:
       │  └──────────────────────────┘          │    ├── read /proc, /sys
       │                                        │    ├── query SQLite DB
       │                                        │    ├── fork/exec iptables
       │                                        │    └── write config files
       │                                        │
       │◀─────────────────────────────────────  │
       │         sg_response_hdr_t              │
       │  ┌──────────────────────────┐          │
       │  │ magic:   0x5347          │          │
       │  │ status:  SG_OK / SG_ERR  │          │
       │  │ extra:   "hint text"     │          │
       │  │ payload: "result data"   │          │
       │  └──────────────────────────┘          │
       │                                        │
       │  6. close(fd)                          │ 7. close(fd)
       │                                        │
```

### Streaming variant (ping, traceroute, dmesg):

```
  CLI                                      mgmtd
  ───                                      ─────
       │  request                               │
       │──────────────────────────────────────▶ │
       │                                        │ fork child process
       │◀─ chunk (extra[0]=='+', payload=line)  │ ◀── child stdout
       │◀─ chunk (extra[0]=='+', payload=line)  │ ◀── child stdout
       │  ... poll tty for Ctrl+C ...           │
       │◀─ final (extra[0]!=='+', status=OK)    │ child exits
       │                                        │
```

---

## 5. IPC Deadlock Prevention

mgmtd is single-threaded: it reads one request at a time. If the CLI opens
a connection and then tries to open a second connection before sending the
first request, mgmtd deadlocks (blocked reading socket #1, can't accept #2).

This matters because `ipc_send()` needs to check debug flags (`dbg_enabled()`)
which on first call loads debug state via its own IPC request. If that check
happens after `connect()`, the inner IPC call deadlocks mgmtd.

**Solution:** Compute debug flags **before** opening the connection.

```
  ipc_send(SHOW_STATUS):
    │
    ├── dbg_enabled()                    ← BEFORE connect()
    │     │
    │     └── mem_load_once() (first call only)
    │           │
    │           └── ipc_send(DEBUG_STATE_GET)     ← inner call
    │                 ├── dbg_enabled() → mem_loaded=1 → returns (no recursion)
    │                 ├── socket() → connect() → send → recv → close
    │                 └── done (mgmtd is FREE now)
    │
    │   inner IPC complete, debug flags resolved
    │
    ├── socket()
    ├── connect()                        ← mgmtd accepts, starts reading
    ├── safe_write(header + debug_flags) ← sent immediately, no second IPC
    ├── safe_write(payload)
    ├── safe_read(response)
    └── close()
```

**Why it's safe from infinite recursion:**

`mem_load_once()` sets `mem_loaded = 1` as its first action, before doing
anything else. When the inner `ipc_send()` calls `dbg_enabled()` →
`mem_load_once()`, it sees `mem_loaded == 1` and returns immediately.
No infinite loop.

```
  dbg_enabled() → mem_load_once()
    mem_loaded = 1                  ← set FIRST
    ipc_send(DEBUG_STATE_GET)
      dbg_enabled() → mem_load_once()
        mem_loaded == 1 → return    ← stops here
      returns 0 (no data yet)
    ← response arrives, data parsed into memory
  ← dbg_enabled() returns actual value
```

**Why not use threads in mgmtd?** See the design rationale:

- mgmtd runs as root — threads share memory space, a bug in one thread
  can corrupt another thread's state (config DB, audit log, iptables rules)
- Locking every shared resource (SQLite, audit log, firewall state) creates
  deadlock and race condition risks in a security-critical daemon
- SQLite serializes writes internally — threads don't speed up the DB path
- Each IPC request takes ~1-10ms — no concurrency bottleneck exists
- Single-threaded code is easier to audit for a firewall daemon

---

## 6. What the CLI Can No Longer Do After Sandbox

```
  BEFORE sandbox              AFTER sandbox              WHO does it instead
  ──────────────              ─────────────              ────────────────────
  fopen("/proc/stat")    →    BLOCKED (openat)      →   mgmtd reads, sends via IPC
  fopen("/proc/meminfo") →    BLOCKED (openat)      →   mgmtd: SG_CMD_DIAG_RAM
  opendir("/proc")       →    BLOCKED (openat)      →   mgmtd: SG_CMD_DIAG_PROCTOP
  statvfs("/")           →    BLOCKED (statfs)      →   mgmtd: SG_CMD_DIAG_DISK
  fork() + exec("ip")   →    BLOCKED (clone+execve) →  mgmtd: SG_CMD_SHOW_IFACES
  fopen(history_file)    →    BLOCKED (openat)      →   mgmtd: SG_CMD_HISTORY_LOAD (IPC)
  fwrite(history_file)   →    BLOCKED (openat)      →   mgmtd: SG_CMD_HISTORY_SAVE (IPC)
  fopen(debug_conf)      →    BLOCKED (openat)      →   mgmtd: SG_CMD_DEBUG_STATE_GET
                                                         (lazy IPC load on first access)
  socket(AF_INET)        →    BLOCKED (arg check)   →   mgmtd: SG_CMD_NET_PING
  access(file, F_OK)     →    BLOCKED (faccessat)   →   try-connect on AF_UNIX
```

---

## 7. File Permission Hardening

mgmtd hardens file permissions at startup since it is now the sole accessor:

```
  Path                                     Mode   Owner         Why
  ────                                     ────   ─────         ───
  /etc/stargazer/                          0700   root:root     Config directory
  /etc/stargazer/stargazer.db              0600   root:root     SQLite config DB
  /var/log/stargazer-audit.log             0600   root:root     Audit trail
  /run/stargazer-mgmtd.sock               0660   root:stargazer IPC socket
  /run/stargazer-session.rev               0600   root:root     Session tracking
  /tmp/stargazer-debug.conf                0600   root:root     Debug state
  /tmp/stargazer_cli_history_<uid>         0600   root:root     CLI history
  /tmp/sg-fw-upgrade.state                 0600   root:root     Firmware state
```

---

## 8. Defense-in-Depth: What Each Layer Stops

```
  Attack scenario                        Stopped by
  ────────────────                       ──────────
  CLI reads /etc/stargazer/stargazer.db  Landlock (openat → EACCES)
                                         seccomp (openat → SIGKILL)
                                         File perms (0600 root:root)

  CLI spawns a shell                     seccomp (execve → SIGKILL)
                                         seccomp (clone → SIGKILL)
                                         no_new_privs (no setuid gain)

  CLI opens TCP socket to exfiltrate     seccomp (socket AF_INET → SIGKILL)

  CLI escalates via setuid binary        Capabilities dropped (all zero)
                                         no_new_privs set
                                         seccomp blocks execve anyway

  CLI reads audit log via ioctl          seccomp (non-terminal ioctl → SIGKILL)

  CLI ptrace's mgmtd                     seccomp (ptrace → SIGKILL)
                                         Capabilities dropped

  CLI mounts overlay filesystem          seccomp (mount → SIGKILL)
                                         Capabilities dropped (CAP_SYS_ADMIN)

  Attacker gets code exec in CLI         All layers active — can only talk to
                                         mgmtd via IPC. mgmtd validates every
                                         request with SO_PEERCRED + permissions.
```
