# CLI Sandbox — Conceptual Flowchart

## The Core Problem

```
  An attacker who gains code execution inside the CLI process
  should NOT be able to:

    - Read the config database or audit logs
    - Spawn shells or run arbitrary programs
    - Make network connections to exfiltrate data
    - Escalate privileges to root
    - Access any file on the filesystem

  The CLI should be a dumb pipe: keystrokes in, text out.
  Everything else goes through a single guarded gate.
```

---

## System Actors

```
  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────────┐
  │          │    │          │    │          │    │              │
  │  Human   │    │  logind  │    │   CLI    │    │    mgmtd     │
  │  (tty)   │    │  (root)  │    │ (locked) │    │   (root)     │
  │          │    │          │    │          │    │              │
  └──────────┘    └──────────┘    └──────────┘    └──────────────┘
   Untrusted       Gatekeeper      Prisoner         Privileged
                   (one-time)      (permanent)       Worker
```

---

## Flow 1: How a User Gets Into the CLI

```
                    ┌─────────┐
                    │  BOOT   │
                    └────┬────┘
                         │
                         ▼
              ┌──────────────────┐
              │  init starts     │
              │  mgmtd (root)    │──────────────────┐
              │  login loop      │                  │
              └────────┬─────────┘                  │
                       │                            │
                       ▼                            ▼
              ┌────────────────┐          ┌─────────────────┐
              │  "login: "     │          │  mgmtd listens  │
              │  prompt shown  │          │  on Unix socket  │
              └────────┬───────┘          │  (waiting for    │
                       │                  │   CLI requests)  │
              user types "admin"          └─────────────────┘
                       │
                       ▼
              ┌────────────────┐
              │  Is account    │──── yes ──▶ "Account locked.
              │  locked out?   │             Try again later."
              └────────┬───────┘                   │
                       │ no                        │
                       ▼                     back to login
              ┌────────────────┐
              │  "Password: "  │
              │  (echo off)    │
              └────────┬───────┘
                       │
              user types password
                       │
                       ▼
              ┌────────────────┐
              │  Check against │
              │  /etc/shadow   │
              │  (bcrypt hash) │
              └────────┬───────┘
                       │
                ┌──────┴──────┐
                │             │
              wrong        correct
                │             │
                ▼             ▼
         ┌───────────┐  ┌──────────────┐
         │ Increment  │  │ Must change  │──── no ────┐
         │ fail count │  │ password?    │             │
         │ (escalate  │  └──────┬───────┘             │
         │  lockout)  │         │ yes                  │
         └─────┬──────┘         ▼                     │
               │         ┌──────────────┐             │
         back to login   │ Force new pw │             │
                         │ (policy chk) │             │
                         └──────┬───────┘             │
                                │                     │
                                ▼                     ▼
                       ┌─────────────────────────────────┐
                       │  DROP PRIVILEGES                 │
                       │                                  │
                       │  Was: root (uid 0)               │
                       │  Now: admin (uid 1000)           │
                       │                                  │
                       │  setuid(1000), setgid(1000)      │
                       │  Set $STARGAZER_USER=admin       │
                       └────────────────┬────────────────┘
                                        │
                                        ▼
                               ┌─────────────────┐
                               │  exec() the CLI │
                               │  binary          │
                               │                  │
                               │  (replaces       │
                               │   logind process │
                               │   image entirely)│
                               └────────┬────────┘
                                        │
                                        ▼
                                   CLI starts
                                   (see Flow 2)
```

---

## Flow 2: CLI Startup — Immediate Sandbox

```
  ╔══════════════════════════════════════════════════════════════════╗
  ║  BEFORE SANDBOX (only 3 steps, no file reads)                  ║
  ╚══════════════════════════════════════════════════════════════════╝

              ┌─────────────────────┐
              │  CLI process starts │
              │  as uid 1000        │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  ipc_init(user)     │◀─── Store username for
              │  cli_term_init()    │     future IPC calls.
              │  (opens /dev/tty)   │     Open terminal device.
              └──────────┬──────────┘
                         │
              /dev/tty is the ONLY file open.
              Cannot be done via IPC — it's a
              kernel device bound to this
              process's controlling terminal.
                         │
                         │
  ╔══════════════════════╪═══════════════════════════════════════════╗
  ║  LOCK THE DOOR (irreversible, one-way)                         ║
  ╚══════════════════════╪═══════════════════════════════════════════╝
                         │
                         ▼
              ┌─────────────────────┐
              │  1. Landlock:       │
              │     Block ALL       │     open("/etc/passwd") → DENIED
              │     file opens      │     open("/proc/stat")  → DENIED
              │                     │     open("anything")     → DENIED
              └──────────┬──────────┘
                         │              (read/write on ALREADY
                         │               open fds still works)
                         ▼
              ┌─────────────────────┐
              │  2. Drop ALL        │
              │     capabilities    │     CAP_SYS_ADMIN  → gone
              │                     │     CAP_NET_RAW    → gone
              │     (64 bits → 0)   │     CAP_DAC_OVERRIDE → gone
              └──────────┬──────────┘     ... all 64 → gone
                         │
                         ▼
              ┌─────────────────────┐
              │  3. no_new_privs    │     Even if you somehow
              │                     │     exec a setuid binary,
              │     (prevent        │     you gain nothing.
              │      escalation)    │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  4. Disable core    │     Crash won't dump
              │     dumps           │     memory with IPC
              │                     │     secrets to disk.
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  5. seccomp-bpf:    │
              │     Allowlist of    │     fork()   → KILLED
              │     ~40 syscalls    │     execve() → KILLED
              │                     │     open()   → KILLED
              │     Everything else │     socket(TCP) → KILLED
              │     → instant kill  │     ptrace() → KILLED
              └──────────┬──────────┘     mount()  → KILLED
                         │
                         │
          ══════════════════════════════
           POINT OF NO RETURN
           The process can never undo
           any of these restrictions.
           Not even root could.
          ══════════════════════════════
                         │
                         │
  ╔══════════════════════╪═══════════════════════════════════════════╗
  ║  THE CAGE (everything below runs inside the sandbox)           ║
  ║  (can only: read tty, write tty, talk to mgmtd via IPC)       ║
  ╚══════════════════════╪═══════════════════════════════════════════╝
                         │
                         ▼
              ┌─────────────────────┐       ┌─────────────────┐
              │  "Who am I?"        │──IPC──▶│  mgmtd: lookup  │
              │  Ask mgmtd for      │       │  admin's profile │
              │  profile/permissions │◀──────│  → "read-write"  │
              └──────────┬──────────┘       │  → permissions   │
                         │                  └─────────────────┘
                         ▼
              ┌─────────────────────┐       ┌─────────────────┐
              │  Load history       │──IPC──▶│  mgmtd reads    │
              │  via IPC            │       │  history file    │
              │  (SG_CMD_HISTORY_   │◀──────│  for this user   │
              │   LOAD)             │       └─────────────────┘
              └──────────┬──────────┘
                         │
              Debug state also loads LAZILY
              via IPC on first access.
              See "IPC Deadlock Prevention".
                         │
                         ▼
              ┌─────────────────────┐
              │  Print banner       │
              │  "Stargazer NGFW"   │
              │  Enter REPL loop    │
              └──────────┬──────────┘
                         │
                         ▼
                    (see Flow 3)
```

---

## Flow 3: Every Command Goes Through the Gate

```
  ┌───────────────────────────────────────────────────────────────────┐
  │                                                                   │
  │                      ┌──────────────┐                             │
  │                      │ stargazer>   │ ◀─── prompt                 │
  │                      └──────┬───────┘                             │
  │                             │                                     │
  │                    user types command                              │
  │                             │                                     │
  │                             ▼                                     │
  │                   ┌──────────────────┐                            │
  │                   │ Resolve abbrevs  │                            │
  │                   │ "sh sta" →       │                            │
  │                   │ "show status"    │                            │
  │                   └────────┬─────────┘                            │
  │                            │                                      │
  │                ┌───────────┴───────────┐                          │
  │                │                       │                          │
  │           needs data               local only                     │
  │           from system              (help, exit,                   │
  │                │                    abbreviation)                  │
  │                │                       │                          │
  │                ▼                       ▼                          │
  │  ┌──────────────────────┐    ┌──────────────────┐                │
  │  │  Build IPC request   │    │  Handle locally   │                │
  │  │                      │    │  (no IPC needed)  │                │
  │  │  cmd = SHOW_STATUS   │    └────────┬─────────┘                │
  │  │  user = "admin"      │             │                          │
  │  │  payload = ""        │          print result                   │
  │  └──────────┬───────────┘             │                          │
  │             │                         │                          │
  │             ▼                         │                          │
  │             │                         │                          │
  │ ════════════╪═══════ SANDBOX WALL ════╪═══════════════           │
  │             │     (AF_UNIX only)      │                          │
  │             ▼                         │                          │
  │  ┌──────────────────────┐             │                          │
  │  │  mgmtd receives      │             │                          │
  │  │                       │             │                          │
  │  │  1. Verify caller UID │             │                          │
  │  │     (SO_PEERCRED)     │             │                          │
  │  │                       │             │                          │
  │  │  2. Look up user's    │             │                          │
  │  │     permissions       │             │                          │
  │  │                       │             │                          │
  │  │  3. Permission OK?    │             │                          │
  │  │     ├─ no → DENIED    │             │                          │
  │  │     └─ yes ↓          │             │                          │
  │  │                       │             │                          │
  │  │  4. Do the privileged │             │                          │
  │  │     work AS ROOT:     │             │                          │
  │  │     • read /proc      │             │                          │
  │  │     • query SQLite DB │             │                          │
  │  │     • run iptables    │             │                          │
  │  │     • write configs   │             │                          │
  │  │                       │             │                          │
  │  │  5. Send result back  │             │                          │
  │  └──────────┬────────────┘             │                          │
  │             │                          │                          │
  │ ════════════╪══════════════════════════╪═══════════════           │
  │             │                          │                          │
  │             ▼                          │                          │
  │  ┌──────────────────────┐             │                          │
  │  │  CLI formats and     │◀────────────┘                          │
  │  │  prints result       │                                        │
  │  │  to terminal         │                                        │
  │  └──────────┬───────────┘                                        │
  │             │                                                     │
  │             ▼                                                     │
  │         back to prompt                                            │
  │                                                                   │
  └───────────────────────────────────────────────────────────────────┘
```

---

## Flow 4: What Happens When Each Command Type Runs

```
  "show status"
  ─────────────
    CLI                              mgmtd
     │── SG_CMD_SHOW_STATUS ────────▶│
     │                               │── read /proc/uptime
     │                               │── read /proc/version
     │                               │── query interface count from DB
     │◀── status text ──────────────│
     │
     print to terminal


  "show interfaces"
  ─────────────────
    CLI                              mgmtd
     │── SG_CMD_SHOW_IFACES ───────▶│
     │                               │── fork+exec: ip -brief link
     │                               │── capture stdout
     │◀── interface list ───────────│
     │
     print table


  "execute diagnose cpu"
  ──────────────────────
    CLI                              mgmtd
     │── SG_CMD_DIAG_CPU ──────────▶│
     │                               │── read /proc/stat
     │                               │── read thermal zones
     │◀── raw CPU jiffies ──────────│
     │
     │   (sleep 1 second)
     │
     │── SG_CMD_DIAG_CPU ──────────▶│
     │                               │── read /proc/stat again
     │◀── raw CPU jiffies ──────────│
     │
     compute delta, print percentages


  "execute ping 10.0.0.1"
  ────────────────────────
    CLI                              mgmtd
     │── SG_CMD_NET_PING ──────────▶│
     │                               │── fork child: ping -c4 10.0.0.1
     │◀── streaming chunk ──────────│◀── child stdout line
     │   print line                  │
     │◀── streaming chunk ──────────│◀── child stdout line
     │   print line                  │
     │   (poll tty for Ctrl+C)       │
     │◀── final response ───────────│   child exits
     │
     done


  "configure"
  ───────────
    CLI                              mgmtd
     │
     │  (enter config context)
     │
     │  user: "set hostname myfw"
     │── SG_CMD_CFG_SET ───────────▶│
     │   type=system_settings        │── validate fields
     │   hostname=myfw               │── write to SQLite
     │◀── OK ───────────────────────│
     │
     │  user: "end"
     │── SG_CMD_CFG_APPLY ─────────▶│
     │   type=system_settings        │── apply to running system
     │                               │── hostname myfw
     │◀── OK ───────────────────────│


  "execute debug enable"
  ──────────────────────
    CLI                              mgmtd
     │
     │  update in-memory state
     │  (key: "enabled" = "1")
     │
     │── SG_CMD_DEBUG_STATE_SET ───▶│
     │   payload: "enabled=1\n"      │── atomic write to
     │                               │   /tmp/stargazer-debug.conf
     │◀── OK ───────────────────────│


  "exit" (on CLI shutdown)
  ────────────────────────
    CLI                              mgmtd
     │
     │── SG_CMD_HISTORY_SAVE ──────▶│
     │   payload: history lines      │── atomic write to
     │                               │   /tmp/sg_cli_history_admin
     │◀── OK ───────────────────────│
     │
     process exits
```

---

## Flow 5: Attack Scenarios — What Gets Blocked and Where

```
  SCENARIO: Attacker gets code execution inside CLI process
  ─────────────────────────────────────────────────────────

  Attacker tries:                  What happens:
  ──────────────                   ──────────────

  open("/etc/stargazer/db")   ──▶  Layer 1 (Landlock): EACCES
                                   Layer 5 (seccomp):  SIGKILL
                                   File perms:         0600 root
                                   │
                                   └── Three independent walls.
                                       Must bypass ALL three.


  fork() + exec("/bin/sh")    ──▶  Layer 5 (seccomp): SIGKILL on fork()
                                   Even if fork worked:
                                   Layer 5: SIGKILL on execve()
                                   Even if execve worked:
                                   Layer 3: no_new_privs (no setuid gain)
                                   Layer 2: no capabilities


  socket(AF_INET, ...)        ──▶  Layer 5 (seccomp): checks arg0
                                   AF_INET ≠ AF_UNIX → SIGKILL
                                   │
                                   └── Cannot make TCP/UDP connections.
                                       Only AF_UNIX to mgmtd.


  ioctl(fd, EVIL_CMD)         ──▶  Layer 5 (seccomp): checks arg1
                                   Only 6 terminal ioctls allowed.
                                   Anything else → SIGKILL


  Send fake IPC to mgmtd      ──▶  mgmtd checks SO_PEERCRED
  pretending to be root            Kernel reports real UID (1000)
                                   Cannot fake UID over Unix socket.
                                   │
                                   └── mgmtd looks up permissions
                                       for uid 1000 (admin).
                                       Only gets admin's permissions.


  ptrace(mgmtd_pid)           ──▶  Layer 5 (seccomp): SIGKILL
                                   Layer 2: no CAP_SYS_PTRACE


  mount overlay on /etc        ──▶  Layer 5 (seccomp): SIGKILL
                                   Layer 2: no CAP_SYS_ADMIN


  Write to /proc/sysrq        ──▶  Layer 1 (Landlock): EACCES
                                   Layer 5 (seccomp): SIGKILL on open


  Read /var/log/audit.log     ──▶  Layer 1 (Landlock): EACCES
                                   Layer 5 (seccomp): SIGKILL on open
                                   File perms: 0600 root


  Core dump to extract         ──▶  Layer 4: PR_SET_DUMPABLE(0)
  IPC data from memory              No core file created.
```

---

## Flow 6: The Big Picture — Trust Relationships

```
                    TRUSTS NOTHING
                         │
                         ▼
  ┌─────────────────────────────────────────────────┐
  │                    KERNEL                        │
  │                                                  │
  │   seccomp-bpf    Landlock    capabilities        │
  │   (syscall gate)  (fs gate)  (privilege gate)    │
  │                                                  │
  └──────────┬──────────────────────┬───────────────┘
             │                      │
        enforces on             enforces on
             │                      │
             ▼                      ▼
  ┌──────────────────┐   ┌──────────────────────┐
  │                  │   │                      │
  │  CLI process     │   │  mgmtd process       │
  │  (prisoner)      │   │  (trusted worker)    │
  │                  │   │                      │
  │  CAN:            │   │  CAN:                │
  │  • read tty      │   │  • read all files    │
  │  • write tty     │   │  • write config DB   │
  │  • talk to mgmtd │   │  • exec iptables     │
  │                  │   │  • manage users       │
  │  CANNOT:         │   │                      │
  │  • open files    │   │  VALIDATES:           │
  │  • run programs  │   │  • caller UID         │
  │  • use network   │   │  • permissions        │
  │  • gain privs    │   │  • input safety       │
  │                  │   │  • rate limits         │
  └────────┬─────────┘   └──────────┬───────────┘
           │                        │
      only path                reads/writes
      to outside                as root
      world                         │
           │                        ▼
           │              ┌──────────────────┐
           └─── IPC ─────▶│  Unix socket     │
              (AF_UNIX)    │  /run/stargazer  │
                           │  -mgmtd.sock     │
                           │                  │
                           │  0660            │
                           │  root:stargazer  │
                           └──────────────────┘

  The CLI is a terminal emulator that happens to speak IPC.
  It has no more power than a dumb serial console.
```

---

## IPC Deadlock Prevention — Why Debug State Uses Lazy IPC

mgmtd is single-threaded. If the CLI opens two connections at once,
mgmtd deadlocks (blocked reading the first, can't process the second).

Every `ipc_send()` needs to check `dbg_enabled()`, which on first call
loads debug state via its own IPC call. This creates a nested IPC problem.

**The deadlock (if we did it wrong):**

```
  ipc_send(SHOW_STATUS):                 mgmtd:
    socket()                               │
    connect() ──────────────────────────▶ accept(), read(conn1)
    │                                      │ waiting for request...
    │ dbg_enabled()                        │
    │   └── mem_load_once()                │
    │         └── ipc_send(DEBUG_GET):     │
    │               socket()               │
    │               connect() ──────────▶  │ (can't accept, busy
    │               send(request) ───────▶ │  reading conn1)
    │               read(response) ◀─ BLOCKS
    │                                      │
    │ (never reaches safe_write            │ (never reads conn2)
    │  for conn1)                          │
    │                                      │
    └── DEADLOCK ──────────────────────────┘
```

**The fix: compute debug flags BEFORE connect()**

```
  ipc_send(SHOW_STATUS):                 mgmtd:
    │                                      │
    │ dbg_enabled()                        │ (idle, no connections)
    │   └── mem_load_once()                │
    │         └── ipc_send(DEBUG_GET):     │
    │               socket()               │
    │               connect() ───────────▶ accept(), read(conn)
    │               send(request) ───────▶ process DEBUG_GET
    │               read(response) ◀────── send response
    │               close() ───────────    close()
    │         ← data loaded                │ (idle again)
    │   ← returns actual value             │
    │                                      │
    │ socket()                             │
    │ connect() ──────────────────────────▶ accept(), read(conn)
    │ send(header with debug flags) ──────▶ process SHOW_STATUS
    │ read(response) ◀────────────────────  send response
    │ close()                               close()
    │                                      │
    └── NO DEADLOCK ───────────────────────┘
```

**No infinite recursion** because `mem_load_once()` sets `mem_loaded = 1`
as its first action. The inner `ipc_send()` → `dbg_enabled()` →
`mem_load_once()` sees the flag and returns immediately.

---

## Why This Order Matters

```
  ┌────────────────────────────────────────────────────────────┐
  │                                                            │
  │  1. Landlock FIRST                                         │
  │     └── Because Landlock uses its own syscalls              │
  │         (landlock_create_ruleset, landlock_restrict_self)   │
  │         If seccomp was first, these would be blocked.       │
  │                                                            │
  │  2. Drop capabilities SECOND                               │
  │     └── capset() is a syscall. Must happen before          │
  │         seccomp blocks it.                                  │
  │                                                            │
  │  3. no_new_privs THIRD                                     │
  │     └── Required by seccomp. Cannot install a seccomp      │
  │         filter without this flag set first.                 │
  │                                                            │
  │  4. Disable core dumps FOURTH                              │
  │     └── Uses prctl(). Safe to do anytime, but logically    │
  │         belongs before the final lockdown.                  │
  │                                                            │
  │  5. seccomp-bpf LAST                                       │
  │     └── The final wall. After this, no syscall outside     │
  │         the ~40 allowlist will ever succeed again.          │
  │         This is irreversible — even root cannot remove it.  │
  │                                                            │
  └────────────────────────────────────────────────────────────┘
```
