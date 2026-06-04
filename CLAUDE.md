# CLAUDE.md — Stargazer NGFW

## Project
- **Stargazer**: Custom Linux-based NGFW for **Banana Pi BPI-R4** (ARM64).
- **Output**: Bootable ARM64 image (StargazerOS).
- **Version**: `VERSION` file; use `@VERSION@` placeholder (Makefile substitutes).
- **License**: MIT overall; **kernel modules are GPL-2.0-only**.

## Phase documentation
Each phase has a detailed design document in `Phase/`:
- `Phase/phase2.md` — Connection-state tracking on `nf_conntrack`, anomaly screening, per-flow ML features, connmark policy re-evaluation.
- `Phase/fqdn.md` — FQDN address objects: per-object `hash:ip` ipsets, accumulate-mode DNS refresh, `fqdn-ttl`, fail-closed ledger, debugging runbook.

## Core Architecture

### Kernel data-plane
- **`nf_conntrack`** (stock kernel) — owns all per-flow connection state and NAT. The single source of truth for flows; everything else reads or annotates it. No custom session table.
- **`pkt_forward.ko`** — Netfilter `NF_INET_FORWARD` hook. Stateless anomaly screen + feature tap: validates IPv4, drops L3/L4 attack patterns (Land, source routing, NULL/XMAS/FIN scans, SYN-with-data, Ping of Death), then accounts per-flow ML features into the conntrack `NF_CT_EXT_ML` extension (`ml_account()`). Holds no per-session state, enforces no blocks. SMP-safe atomic counters; stats at `/proc/stargazer/pkt_forward_stats`.
- **Kernel patches** (in `../stargazer-kernel`, see below) — `struct nf_conn_ml` / `NF_CT_EXT_ML` conntrack extension (`include/net/netfilter/nf_conntrack_ml.h`), allocated on every flow in `init_conntrack`, exported as binary attribute `CTA_ML` (=27) on the ctnetlink dump path. Userspace mirrors the struct as `sg_nf_conn_ml` in `mgmtd_diag.c` — **keep the two layouts field-for-field identical**.
- **Policy re-evaluation** — firewall policy is enforced by iptables; each flow carries a connmark `policy_id` (bits 8–31) + DIRTY bit (bit 0). On policy change mgmtd marks the affected flows dirty via ctnetlink (`conntrack_mark_dirty_by_policy`), falling back to a full conntrack flush — never leave stale fast-path flows (fail-closed).
- **Planned**: IPS module + ML scoring daemon (see Phase 3).

### Module loading
`pkt_forward.ko` softdeps on `nf_defrag_ipv4` (`MODULE_SOFTDEP`). Boot modules listed in `/etc/modules-load.d/stargazer.conf` (`af_packet`, `pkt_forward`), loaded by `/etc/init.d/stargazer`.

## Target & Build
- **Target**: BPI-R4 (MT7988A, ARM64).
- **Host**: Ubuntu 22.04 x86_64, cross-compile with `aarch64-linux-gnu-gcc`.
- **Build**: root `Makefile` (kernel → modules → rootfs → iso).
- **Kernel tree**: sibling checkout at `../stargazer-kernel` (`make kernel-source` fetches it). Carries the Stargazer conntrack-ML patches: `nf_conntrack_ml.h`, `NF_CT_EXT_ML` registration in `nf_conntrack_extend.{h,c}`, ext alloc in `nf_conntrack_core.c`, `CTA_ML` dump in `nf_conntrack_netlink.c`.

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
- **FQDN address objects**: each fqdn-type `firewall_address` owns one `hash:ip` ipset with per-entry timeouts (`mgmtd_ipset.c`, raw netlink — no ipset binary). FORWARD rules match it via `-m set --match-set`; `mgmtd_fqdn.c` re-resolves every 60s in a detached worker (+ a kick after every chain rebuild) and **merges** answers into the set — round-robin DNS returns one answer per query, so swap-replace would make deny rules flicker. Entries not re-confirmed within `fqdn-ttl` seconds expire (`config system settings`, 60–86400, default 3600 — stamped per-entry on every ADD, change re-stamps existing members via `fqdn_restamp_all`); bounded over-blocking, never under-blocking. Resolve failure re-adds current members to keep their timeouts alive (an emptied set would silently un-match DENY rules). `execute diagnose firewall ipset <object>` dumps membership + expiry. Wildcards rejected at validation — they need DNS snooping (Phase 3). NAT rules cannot use fqdn objects (fail-closed skip).

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
| `src/modules/pkt_forward.c` | Netfilter FORWARD hook — anomaly screen + ML feature tap |
| `../stargazer-kernel/include/net/netfilter/nf_conntrack_ml.h` | `struct nf_conn_ml` — per-flow ML feature vector (kernel side) |
| `src/userspace/mgmtd/mgmtd_apply_firewall.c` | iptables policy apply + connmark dirty-flow re-evaluation |
| `src/userspace/cli/cli_readline.c` | Zero-fork readline with abbreviation resolution |
| `src/userspace/cli/cli_configure.c` | Interactive config contexts (table/entry/single) |
| `src/userspace/cli/cli_cmd_table.c` | All CLI command handlers |
| `src/userspace/common/sg_cmd_defs.h` | X-macro command registration table |
| `src/userspace/mgmtd/sg_db.c` | SQLite config backend |
| `src/userspace/mgmtd/mgmtd_diag.c` | Diagnostic IPC handlers (session, disk, NTP…) |
| `src/userspace/mgmtd/stargazer_ipc.h` | IPC command IDs and wire protocol |

## Constraints
- The firewall is always in a dangerous position — honesty first. Tests verify real behavior. Errors say what is actually wrong. Outputs show actual data. Buffers are always checked. A build that silently breaks is broken.
- No floats in kernel code (use fixed-point or integer arithmetic; ML features stored as sums/sums-of-squares so consumers derive mean/variance).
- Flow state belongs to `nf_conntrack` — annotate it (extensions, connmark), never duplicate it. ML extension mutations under `ct->lock` (`spin_lock_bh`).
- Cross-compile only; QEMU for kernel/module tests.
- Create a plan and explain why before making changes.

## Commit style
- Plain human language.
- Short summary line, then detailed explanation of what was added, changed, or removed vs the previous commit.
- Do not add `Co-Authored-By` lines.

## Next (Phase 3)
- Flow export to the ML daemon already works: ctnetlink dump carries `CTA_ML` (consumed today by `handle_session_ml`, SG_CMD_SESSION_ML).
- ML scoring daemon: read `CTA_ML` dumps, write `ml_score` back into the extension, block flagged flows.
- IPS module: signature-based payload inspection, flags the flow's conntrack entry on match.
- Wildcard FQDN (`*.example.com`): DNS-response snooping (NFQUEUE on UDP/53) feeding the same ipsets — shares payload-inspection infrastructure with the IPS module.
- `diagnose session list/filter` with field-level filtering.
