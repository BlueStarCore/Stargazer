# Parallel Development Plan — DNS/DHCP + NAT Enhancements

## Overview

The mgmtd monolith (`stargazer-mgmtd.c`) has been refactored. Each apply
handler now lives in its own `.c` file so we can develop DNS+DHCP and NAT
enhancements in parallel without merge conflicts.

Base commit: `e8dddbe` on `develop`.

---

## Assignments

| Area | Owner | Branch |
|------|-------|--------|
| DNS forwarding + DHCP server | **Vinh** | `dev-dns-dhcp` (create from `develop`) |
| NAT enhancements | **Tan** | `dev-nat` (create from `develop`) |

---

## Repository Layout (after refactor)

```
src/userspace/mgmtd/
  mgmtd_apply.h            # Shared header — helper declarations, VALBUFSZ, handler prototypes
  mgmtd_apply_route.c      # apply_route_static()     — DO NOT TOUCH
  mgmtd_apply_iface.c      # apply_settings() + apply_interface()  — DO NOT TOUCH
  mgmtd_apply_nat.c        # apply_nat()              — Tan owns this
  mgmtd_apply_dns.c        # apply_dns()              — Vinh owns this (stub)
  mgmtd_apply_dhcp.c       # apply_dhcp()             — Vinh owns this (stub)
  stargazer-mgmtd.c        # Dispatcher + admin handlers (coordinated edits only)
  stargazer_ipc.h           # IPC protocol + reserved command ranges
  Makefile                  # Already includes all new .c files

src/userspace/common/
  sg_validate.c             # Config registry — types and field definitions
  sg_validate.h             # Public validation API
```

---

## How It Works

`apply_config()` in `stargazer-mgmtd.c` is now a thin dispatcher:

```c
if (strcmp(type, "network_route_static") == 0)
    return apply_route_static(id, data, result, rsize);
if (strcmp(type, "system_settings") == 0)
    return apply_settings(id, data, result, rsize);
if (strcmp(type, "system_interface") == 0)
    return apply_interface(id, data, result, rsize);
if (strcmp(type, "network_nat") == 0)
    return apply_nat(id, data, result, rsize);
if (strcmp(type, "network_dns") == 0)
    return apply_dns(id, data, result, rsize);
if (strcmp(type, "network_dhcp-server") == 0)
    return apply_dhcp(id, data, result, rsize);
// admin handlers remain inline below...
```

### Handler signature

Every handler follows the same pattern:

```c
sg_status_t apply_xxx(const char *id, const char *data,
                      char *result, size_t rsize);
```

- `id` — entry identifier (e.g. "1", "pool1", "0" for singletons)
- `data` — key=value block from the database (`"key1=val1\nkey2=val2\n"`)
- `result` — write a human-readable status message here
- `rsize` — size of result buffer
- Return `SG_OK` on success, or an appropriate `sg_status_t` error code

### Available helpers (via `#include "mgmtd_apply.h"`)

| Function | Purpose |
|----------|---------|
| `extract_val(data, "key", buf, sizeof(buf))` | Pull a value from key=value data block |
| `safe_exec(argv)` | Fork+exec with no shell; returns malloc'd stdout (caller frees) |
| `iface_exists(name)` | Check `/sys/class/net/<name>` exists |
| `read_iface_mtu_limits(name, &min, &max)` | Query driver min/max MTU |
| `mgmt_log(level, fmt, ...)` | Log to stderr (`"INFO"`, `"WARN"`, `"ERROR"`) |

### Validation helpers (via `sg_validate.h`, included by `mgmtd_apply.h`)

`sg_is_ipv4()`, `sg_is_cidr()`, `sg_is_iface_name()`, `sg_is_uint_range()`,
`sg_is_safe_id()`, etc.

---

## Vinh — DNS + DHCP

### Your files

| File | What to do |
|------|------------|
| `mgmtd_apply_dns.c` | Replace stub with real DNS forwarding apply logic |
| `mgmtd_apply_dhcp.c` | Replace stub with real DHCP server apply logic |
| `sg_validate.c` | Add/modify fields under `network_dns` and `network_dhcp-server` sections if needed |
| `stargazer_ipc.h` | Add IPC commands in the **700-799** range when needed |

### Config fields already registered

**network_dns** (CFG_SINGLE, id="0"):

| Field | Kind | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `primary` | ipv4 | yes | — | Primary DNS server |
| `secondary` | ipv4 | yes | — | Secondary DNS server |
| `listen-on` | ipv4 | no | — | Listen address for DNS |
| `port` | uint:1:65535 | no | 53 | DNS listening port |
| `cache-size` | uint:0:100000 | no | 10000 | DNS cache size (entries) |
| `status` | enum:enable,disable | yes | enable | Enable or disable DNS |

**network_dhcp-server** (CFG_TABLE, id=user-chosen):

| Field | Kind | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `interface` | iface | yes | — | Interface to serve DHCP |
| `start-ip` | ipv4 | yes | — | Pool start address |
| `end-ip` | ipv4 | yes | — | Pool end address |
| `netmask` | ipv4 | yes | — | Subnet mask for clients |
| `gateway` | ipv4 | no | — | Default gateway for clients |
| `dns-server` | ipv4 | no | — | DNS server for clients |
| `domain-name` | safe-id | no | — | Domain name for clients |
| `lease-time` | uint:60:604800 | yes | 86400 | Lease time in seconds |
| `status` | enum:enable,disable | yes | enable | Enable or disable this pool |

### IPC command range

```
SG_CMD_DNS_*  = 700-749
SG_CMD_DHCP_* = 750-799
```

Add your enum values in `stargazer_ipc.h` under the reserved comment block.

### Boot replay

Both types are already wired into `mgmtd_replay_config()`:
- `"network_dns"` in `single_types[]`
- `"network_dhcp-server"` in `table_types[]`

Your apply handlers will be called automatically on boot for any saved entries.

---

## Tan — NAT Enhancements

### Your files

| File | What to do |
|------|------------|
| `mgmtd_apply_nat.c` | Modify existing `apply_nat()` with new NAT features |
| `sg_validate.c` | Add/modify fields under the `network_nat` section if needed |
| `stargazer_ipc.h` | Add IPC commands in the **800-849** range when needed |

### Current NAT fields (network_nat, CFG_TABLE)

| Field | Kind | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `type` | enum:snat,dnat | yes | — | NAT type |
| `srcintf` | iface | yes | — | Source interface |
| `dstintf` | iface | yes | — | Destination interface |
| `srcaddr` | cidr-or:any,all | yes | — | Source address or subnet |
| `dstaddr` | cidr-or:any,all | yes | — | Destination address or subnet |
| `dstport` | uint:1:65535 | yes | — | Destination port |
| `mapped-ip` | ipv4 | yes | — | Translated IP address |
| `mapped-port` | uint:1:65535 | yes | — | Translated port |
| `status` | enum:enable,disable | yes | enable | Enable or disable this rule |

### IPC command range

```
SG_CMD_NAT_* = 800-849
```

### Existing apply logic

`mgmtd_apply_nat.c` already handles SNAT (MASQUERADE via iptables) and
DNAT (port forward via PREROUTING). It includes duplicate-rule detection
(`iptables -C` check before `-A`). NAT chains are flushed before replay
in `mgmtd_replay_config()`.

---

## Coordination Rules

### Files you can edit freely (no conflicts)

- **Vinh**: `mgmtd_apply_dns.c`, `mgmtd_apply_dhcp.c`
- **Tan**: `mgmtd_apply_nat.c`

### Files that need coordination (PR review)

| File | How to avoid conflicts |
|------|----------------------|
| `mgmtd_apply.h` | Only add new prototypes at the end. Don't modify existing declarations. |
| `sg_validate.c` | Each person edits only their own section (marked by comment blocks). |
| `stargazer_ipc.h` | Each person uses only their assigned range (7xx or 8xx). |
| `stargazer-mgmtd.c` | Avoid editing unless adding a new dispatcher entry. Talk first. |
| `Makefile` | Only if adding new `.c` files. |

### Things NOT to touch

- `mgmtd_apply_route.c` — stable, no owner changes needed
- `mgmtd_apply_iface.c` — stable, no owner changes needed
- Admin handler code inside `stargazer-mgmtd.c` (lines after the dispatcher)

---

## Build & Test

```bash
# Clean build (must pass with -Wall -Wextra -Werror):
rm -f build/mgmtd/stargazer-mgmtd build/cli/stargazer-cli && make test-build

# Quick mgmtd-only rebuild:
make -C src/userspace/mgmtd BUILD_DIR=../../../build/mgmtd \
  CROSS_COMPILE=.cache/aarch64-linux-musl-cross/bin/aarch64-linux-musl-
```

All code must compile clean under `-Wall -Wextra -Werror` before pushing.

---

## Known Issues

- **MTU validation** does not pass `execute diagnose test-configure full`.
  This is a pre-existing issue, not related to this refactor. Will be fixed
  separately.

---

## Workflow

1. Create your feature branch from `develop`
2. Work in your owned files
3. `make test-build` before every push
4. PR back to `develop` — tag the other member for review if touching shared files
5. Keep your branch rebased on `develop` to pick up each other's changes
