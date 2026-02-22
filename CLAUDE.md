 # CLAUDE.md — Stargazer NGFW (concise)

  ## Project
  - **Stargazer**: Custom Linux-based NGFW for **Banana Pi BPI-R4** (ARM64).
  - **Output**: Bootable ARM64 image (StargazerOS).
  - **Version**: `VERSION` file; use `@VERSION@` placeholder (Makefile substitutes).
  - **License**: MIT overall; **kernel modules are GPL-2.0-only**.

  ## Core Architecture (summary)
  - **Kernel data-plane**: `pkt_forward.ko` (Netfilter `NF_INET_FORWARD`).
    - Accept valid IPv4, drop invalid, atomic counters.
  - **Session tracking**: `session.c` exists (RCU hash), **not wired yet**.
  - **Planned**: IPS + ML scoring (userspace daemon), feed score via netlink/ioctl.

  ## Target & Build
  - **Target**: BPI-R4 (MT7988A, ARM64).
  - **Host**: Ubuntu 22.04 x86_64, cross-compile with `aarch64-linux-gnu-gcc`.
  - **Build**: root `Makefile` (kernel → modules → rootfs → iso).

  ### Key commands
  make all | make kernel | make modules | make rootfs | make iso | make test

  ## Userspace

  ### CLI (`src/userspace/cli/`)
  - **Binary**: `/sbin/stargazer-cli` — native C, statically linked.
  - **Readline**: `cli_readline.c` — embedded readline with tab completion, history, `?` help.
  - **Command abbreviation**: `cli_resolve_cmd()` — FortiOS-style prefix expansion (e.g. `exe sys shut`).
  - **Configure**: `cli_configure.c` — FortiOS-style contexts (table/entry/single), all in-process.
  - **Dispatch**: `cli_dispatch.c` — routes commands to show/execute/debug/diagnose handlers.
  - **Diagnostics**: `cli_diagnose.c` (permission tests), `cli_diagnose_config.c` (config + abbreviation tests).
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

  ## Repo highlights
  - `src/modules/pkt_forward.c` — active data-plane hook.
  - `src/modules/session.c` — session table (RCU), not wired.
  - `src/userspace/cli/cli_readline.c` — zero-fork readline with abbreviation resolution.
  - `src/userspace/cli/cli_configure.c` — interactive config contexts (table/entry/single).
  - `src/userspace/mgmtd/sg_db.c` — SQLite config backend.

  ## Constraints
  - No floats in kernel code (use fixed-point).
  - RCU for read-heavy session tables.
  - Cross-compile only; QEMU for tests.

  ## Commit style
  - Write commit messages in plain human language.
  - Should explain which features is added, changed or deleted compare to the last commit. Start with a short summary, then explain the details — but not too much.
  - Do not add `Co-Authored-By` lines.

  ## Next (if continuing)
  - Wire `session.c` into `pkt_forward.c`.
  - Add procfs/netlink export for sessions.
  - IPS module + ML daemon integration.

  ---
