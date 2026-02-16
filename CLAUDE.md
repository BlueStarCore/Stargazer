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
```
make all | make kernel | make modules | make rootfs | make iso | make test
```

## Userspace
- **Init**: `src/userspace/init` → `/etc/init.d/stargazer` loads modules + sysctl.
- **CLI**: `/sbin/stargazer-cli` (POSIX sh), custom readline in `cli_input.sh`.
- **Configure**: `/usr/libexec/stargazer/cmd_configure` (FortiOS-style contexts).
- **Login**: `/sbin/stargazer-login` ensures default admin/profile files exist.

### Admin/Profile storage (runtime)
- `/etc/stargazer/profiles.conf`: `name:permissions:description` (built-in prefixed `*`).
- `/etc/stargazer/admins.conf`: `username:profile`.
- Passwords stored in `/etc/shadow` (SHA-512 if `mkpasswd` available).

## Repo highlights
- `src/modules/pkt_forward.c` — active data-plane hook.
- `src/modules/session.c` — session table (RCU), not wired.
- `src/userspace/usr/libexec/stargazer/cli_input.sh` — zero-fork completion.
- `src/userspace/usr/libexec/stargazer/cmd_configure` — interactive config contexts.

## Constraints
- No floats in kernel code (use fixed-point).
- RCU for read-heavy session tables.
- Cross-compile only; QEMU for tests.

## Next (if continuing)
- Wire `session.c` into `pkt_forward.c`.
- Add procfs/netlink export for sessions.
- IPS module + ML daemon integration.
