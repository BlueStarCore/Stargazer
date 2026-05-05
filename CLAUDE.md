# CLAUDE.md — Stargazer NGFW

## Project
- **Stargazer**: Custom Linux-based NGFW for **Banana Pi BPI-R4** (ARM64).
- **Output**: Bootable ARM64 image (StargazerOS).
- **Version**: `VERSION` file; use `@VERSION@` placeholder (Makefile substitutes).
- **License**: MIT overall; **kernel modules are GPL-2.0-only**.

## Phase documentation
Each phase has a detailed design document in `Phase/`:
- `Phase/phase2.md` — Session tracking: RCU hash table, TCP state machine, procfs, CLI diagnostics.

## Core Architecture

### Kernel data-plane
- **`pkt_forward.ko`** — Netfilter `NF_INET_FORWARD` hook. Validates IPv4, does session lookup/create/update, enforces `SESS_BLOCKED`. SMP-safe with atomic counters.
- **`session.ko`** — RCU hash table of 5-tuple sessions. TCP state machine (non-SYN drop, RST sequence validation, per-state timeouts). Exports API to `pkt_forward.ko`.
- **`session_test.ko`** — Kernel self-test module. Exercises session API without a network stack; writes results to `/proc/stargazer/session_test`.
- **Planned**: IPS module + ML scoring daemon, feed score via netlink.

### Load order
`session.ko` → `pkt_forward.ko` (enforced by `MODULE_SOFTDEP`). `session_test.ko` loaded/unloaded on demand by mgmtd.

## Target & Build
- **Target**: BPI-R4 (MT7988A, ARM64).
- **Host**: Ubuntu 22.04 x86_64, cross-compile with `aarch64-linux-gnu-gcc`.
- **Build**: root `Makefile` (kernel → modules → rootfs → iso).

### Key commands
```
make all | make kernel | make modules | make rootfs | make iso | make test
```

## Userspace

### CLI (`src/userspace/cli/`)
- **Binary**: `/sbin/stargazer-cli` — native C, statically linked, sandboxed.
- **Readline**: `cli_readline.c` — embedded readline with tab completion, history, `?` help.
- **Command abbreviation**: `cli_resolve_cmd()` — FortiOS-style prefix expansion (e.g. `exe sys shut`).
- **Configure**: `cli_configure.c` — FortiOS-style contexts (table/entry/single), all in-process.
- **Dispatch**: `cli_dispatch.c` — routes commands to show/execute/debug/diagnose handlers.
- **Commands**: defined in `src/userspace/common/sg_cmd_defs.h` (X-macro table).
- Only low-level system queries (`ip`, `dmesg`) fork external binaries.

### mgmtd (`src/userspace/mgmtd/`)
- **Root daemon**: `stargazer-mgmtd` — privileged operations via Unix socket IPC (`/run/stargazer-mgmtd.sock`).
- **IPC protocol**: binary request/response defined in `stargazer_ipc.h`.
- **Config backend**: `sg_db.c` — SQLite database at `/etc/stargazer/stargazer.db`.
- Schema: `src/userspace/usr/libexec/stargazer/db_schema.sql`.

### logind (`src/userspace/logind/`)
- **Login daemon**: `stargazer-logind` — password auth, policy enforcement, audit logging via SQLite.

### Shared (`src/userspace/common/`)
- `sg_validate.c` — input validation (safe ID, IPv4, CIDR, config type registry).
- `password_policy.c` — shared password policy rules.

### Init
- `src/userspace/etc/init.d/stargazer` — loads modules + sysctl at boot.

## Key source files
| File | Role |
|---|---|
| `src/modules/pkt_forward.c` | Netfilter FORWARD hook — data plane |
| `src/modules/session.c` | Session table: RCU hash, TCP state machine, reaper |
| `src/modules/session.h` | Shared API between session.ko and pkt_forward.ko |
| `src/modules/session_test.c` | Kernel self-test for session API |
| `src/userspace/cli/cli_readline.c` | Zero-fork readline with abbreviation resolution |
| `src/userspace/cli/cli_configure.c` | Interactive config contexts (table/entry/single) |
| `src/userspace/cli/cli_cmd_table.c` | All CLI command handlers |
| `src/userspace/common/sg_cmd_defs.h` | X-macro command registration table |
| `src/userspace/mgmtd/sg_db.c` | SQLite config backend |
| `src/userspace/mgmtd/mgmtd_diag.c` | Diagnostic IPC handlers (session, disk, NTP…) |
| `src/userspace/mgmtd/stargazer_ipc.h` | IPC command IDs and wire protocol |

## Constraints
- The firewall is always in a dangerous position — honesty first. Tests verify real behavior. Errors say what is actually wrong. Outputs show actual data. Buffers are always checked. A build that silently breaks is broken.
- No floats in kernel code (use fixed-point or integer arithmetic).
- RCU for read-heavy session tables; per-session spinlock for mutations.
- Cross-compile only; QEMU for kernel/module tests.
- Create a plan and explain why before making changes.

## Commit style
- Plain human language.
- Short summary line, then detailed explanation of what was added, changed, or removed vs the previous commit.
- Do not add `Co-Authored-By` lines.

## Next (Phase 3)
- Netlink family to export session table to ML scoring daemon.
- ML daemon reads sessions, writes `ml_score` and `SESS_BLOCKED` flag back.
- IPS module: signature-based payload inspection, hooks into session on match.
- `diagnose session list/filter` with field-level filtering.
