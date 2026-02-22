# DNS Design — Two-Tier Architecture

## Overview

Stargazer needs DNS at two levels:

1. **System resolver** — nameservers the firewall itself uses (NTP, package
   updates, mgmtd hostname lookups).
2. **DNS forwarding service** — a forwarder daemon that serves LAN clients,
   so the firewall acts as their DNS gateway.

Both tiers are independently configured and can point at different upstream
servers.

---

## Tier 1: System Resolver

### Config location

Add two fields to the existing `system_settings` (CFG_SINGLE):

| Field           | Type | Default | Description                     |
|-----------------|------|---------|---------------------------------|
| `dns-primary`   | ipv4 | (none)  | Primary nameserver for the box  |
| `dns-secondary` | ipv4 | (none)  | Secondary nameserver (optional) |

### CLI example

```
config system settings
  set dns-primary 1.1.1.1
  set dns-secondary 8.8.8.8
end
```

### Apply handler

When these fields change, the apply handler:

1. Writes `/etc/resolv.conf` with the configured nameservers:
   ```
   # Managed by stargazer-mgmtd — do not edit
   nameserver 1.1.1.1
   nameserver 8.8.8.8
   ```
2. If both fields are empty, writes a minimal resolv.conf with no
   `nameserver` lines (system has no external DNS).
3. File is written atomically (write to temp, rename).

### Scope

Only affects processes running on the firewall: mgmtd, NTP client, package
tools, diagnostic commands (`execute ping`, `diagnose nslookup`).

---

## Tier 2: DNS Forwarding Service

### Purpose

LAN clients point at the firewall as their DNS server. The firewall runs a
lightweight forwarder that proxies queries to configured upstream servers.

### Config location

Uses the existing `network_dns` (CFG_SINGLE):

| Field            | Type                    | Default  | Description                                   |
|------------------|-------------------------|----------|-----------------------------------------------|
| `primary`        | ipv4                    | (none)   | Primary upstream DNS for forwarding            |
| `secondary`      | ipv4                    | (none)   | Secondary upstream DNS for forwarding          |
| `listen-on`      | interface name list     | (none)   | Interfaces where the forwarder listens         |
| `port`           | uint:1:65535            | 53       | Listening port                                 |
| `cache-size`     | uint:0:50000            | 1000     | Max cached entries (0 = disable cache)         |
| `status`         | enum:enable,disable     | disable  | Enable or disable the forwarding service       |

### CLI example

```
config network dns
  set primary 1.1.1.1
  set secondary 8.8.8.8
  set listen-on lan1 lan2
  set cache-size 5000
  set status enable
end
```

### Daemon: `stargazer-dnsd`

A small single-threaded UDP/TCP DNS forwarder, following the same patterns as
mgmtd (musl static, single process, syslog).

**Lifecycle:**

- Started by mgmtd's apply handler when `status=enable`.
- Stopped by mgmtd when `status=disable` or config is deleted.
- mgmtd sends SIGHUP on config changes; the daemon re-reads its config from
  the database.
- PID file at `/run/stargazer-dnsd.pid`.

**Request flow:**

```
LAN client ──UDP/TCP:53──▶ stargazer-dnsd
                             │
                             ├─ cache hit? → reply from cache
                             │
                             └─ cache miss → forward to primary upstream
                                             (fallback to secondary on timeout)
                                             → cache response → reply to client
```

### Interface binding

- `listen-on` takes a space-separated list of interface names (e.g. `lan1 lan2`).
- The daemon binds to the IP addresses currently assigned to those interfaces.
- If an interface has no IP, it is skipped with a syslog warning.
- On SIGHUP the daemon re-resolves interface IPs (handles address changes).
- Only listens on explicitly listed interfaces — never binds to 0.0.0.0.

### Interaction with firewall policy

- DNS traffic to the forwarder must be allowed by firewall policy like any
  other service.
- The `allowaccess` field on `system_interface` should include `dns` when the
  interface is listed in `listen-on`. This can be validated at apply time (warn
  if missing, but do not auto-modify).

---

## Relationship Between Tiers

| Aspect           | Tier 1 (system resolver)         | Tier 2 (DNS forwarder)            |
|------------------|----------------------------------|-----------------------------------|
| Config type      | `system_settings`                | `network_dns`                     |
| Consumers        | Firewall processes               | LAN clients                       |
| Mechanism        | `/etc/resolv.conf`               | `stargazer-dnsd` daemon           |
| Upstream servers | `dns-primary`, `dns-secondary`   | `primary`, `secondary`            |
| Can differ?      | Yes — the box and LAN clients can use different upstreams              |

Keeping them separate means the firewall can use a hardened resolver (e.g.
internal corporate DNS) while LAN clients use a different provider, or vice
versa.

---

## Implementation Order

1. **Add `dns-primary`/`dns-secondary` to `system_settings`** in the config
   field registry (`sg_validate.c`). Write the resolv.conf apply handler in
   mgmtd. This is self-contained and testable immediately.

2. **Add new fields to `network_dns`** (`listen-on`, `port`, `cache-size`,
   `status`) in the config field registry.

3. **Write `stargazer-dnsd`** — the forwarding daemon. Start with UDP-only,
   add TCP later. Cache is a simple hash table with TTL expiry.

4. **Add apply handler for `network_dns`** in mgmtd — start/stop/reload the
   daemon.

5. **Add `dns` to `allowaccess` enum** on `system_interface` so interfaces
   can explicitly permit DNS access.

---

## Open Questions

- **DNSSEC validation**: should the forwarder validate DNSSEC, or pass
  responses through as-is? Recommendation: pass-through initially, add
  optional validation later.
- **DNS-over-TLS/HTTPS**: out of scope for initial implementation. Can be
  added as upstream transport option later.
- **Split DNS**: per-domain forwarding rules (e.g. forward `*.corp.local` to
  internal DNS). Not needed initially but the config schema should not
  preclude it — a future `network_dns-forward-zone` table type could handle
  this.
