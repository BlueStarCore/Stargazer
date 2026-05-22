# Stargazer OS — System Workflow

Reference design: FortiOS architectural patterns applied to BPI-R4 (MT7988A, ARM64).

---

## 1. Boot Sequence

```
Power-on
    │
    ▼
BL2 (MediaTek ATF) — loads from eMMC boot partition
    │  verifies GPT, loads BL31+BL33
    ▼
U-Boot (BL33) — initialises DRAM, PCIe, SFP
    │  loads FIT image (stargazer.itb) from eMMC
    ▼
Linux kernel + device tree
    │  mounts rootfs (squashfs overlay on eMMC data partition)
    ▼
init (BusyBox)
    │
    ├─► /etc/init.d/stargazer
    │       harden_perms()            ← chmod 0600 module/sysctl conf, 0700 /etc/stargazer
    │       harden_firewall()         ← iptables -P FORWARD DROP; ip6tables deny-all
    │       apply_sysctl()            ← ip_forward=1, rp_filter, conntrack limits
    │       load_modules()            ← insmod from /lib/modules/stargazer/:
    │           af_packet.ko          ← required for udhcpc PF_PACKET sockets
    │           session.ko            ← session table + TCP state machine
    │           pkt_forward.ko        ← Netfilter FORWARD hook
    │       (init waits on /run/mgmtd-ready FIFO before continuing — 30 s timeout)
    │
    ├─► stargazer-mgmtd              ← privileged management daemon
    │       supervises stargazer-webd ← HTTPS web UI server (NOT launched by init)
    ├─► sg-flowd                     ← NetFlow v9 exporter (optional)
    └─► stargazer-logind             ← per-login process, exec'd by stargazer-login
                                        (not a persistent daemon)
```

**FortiOS parallel:** FortiOS bootloader (BIOS/UEFI) → Linux kernel → `init` → `miglogd` / `cmdbsvr` / `httpsd`. Stargazer follows the same split: kernel data plane loads first, management plane daemons second.

---

## 2. Plane Separation

```
┌─────────────────────────────────────────────────────────┐
│  DATA PLANE  (kernel space)                             │
│                                                         │
│  pkt_forward.ko  ──►  session.ko                        │
│  NF_INET_FORWARD       RCU hash table                   │
│  hook                  TCP state machine                │
│                        SESS_BLOCKED enforcement         │
└─────────────────────────────────────────────────────────┘
         │ /proc/stargazer/sessions
         │ /proc/stargazer/session_ctl
         ▼
┌─────────────────────────────────────────────────────────┐
│  MANAGEMENT PLANE  (userspace)                          │
│                                                         │
│  stargazer-mgmtd   ── Unix socket ──  stargazer-cli     │
│  (root, privileged)  /run/stargazer-  (sandboxed)       │
│                       mgmtd.sock      stargazer-webd    │
│                                                         │
│  SQLite config DB (/etc/stargazer/stargazer.db)         │
└─────────────────────────────────────────────────────────┘
         │ Netlink (sg_flow genl family)
         ▼
┌─────────────────────────────────────────────────────────┐
│  EXPORT PLANE  (userspace)                              │
│                                                         │
│  sg-flowd   ── UDP ──► NetFlow v9 collector             │
│  sg-mld     ── Netlink ──► session SESS_BLOCKED         │
│  (Phase 3 ML scoring daemon — not yet implemented)      │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Packet Processing Pipeline

Every IPv4 packet forwarded through the router passes through this pipeline in order:

```
NIC RX
  │
  ▼
[Kernel IP stack]
  │  ip_forward=1, routing decision
  ▼
nf_defrag_ipv4  (PRE_ROUTING, priority -400)
  │  reassembles fragments before any FORWARD hook fires
  ▼
pkt_forward hook  (FORWARD, priority -399)
  │
  ├─ is_valid_ipv4()
  │     fail ──► NF_DROP  (pkts_dropped++)
  │
  ├─ extract_key()  ── fill 5-tuple (src_ip, dst_ip, src_port, dst_port, proto)
  │     fail ──► NF_DROP + pr_warn_ratelimited  (genuinely malformed or NOTRACK fragment)
  │
  ├─ TCP && !SYN?
  │     sess_lookup_bidir()        ← never creates; stateful enforcement
  │     NULL && asymmetric_mode?
  │         sess_lookup_or_create() ← HA/asymmetric routing pickup
  │     NULL ──► NF_DROP  (mid-stream with no session)
  │
  ├─ IPPROTO_ICMP (all ICMP — errors and echo alike)
  │     sess_icmp_error_lookup()   ← type 3/11/12: find parent TCP/UDP session
  │     NULL ──► sess_lookup_or_create()   ← echo/other: create normal ICMP session
  │
  ├─ everything else (TCP SYN, UDP)
  │     sess_lookup_or_create()
  │
  ├─ s == NULL (any protocol) ──► NF_DROP  (pkts_dropped++)
  │     TCP non-SYN: mid-stream with no session
  │     TCP SYN / UDP / ICMP / other: table full or kmalloc failed
  │     there is no untracked-accept path — every packet must have a session
  │
  ├─ record ifindex_in / ifindex_out  (set-once, cmpxchg)
  │
  ├─ s->flags & SESS_BLOCKED? ──► NF_DROP  (pkts_blocked++)
  │
  ├─ TCP: sess_tcp_check(s, skb, dir)
  │     RST out-of-window   ──► NF_DROP
  │     SYN into ESTABLISHED──► NF_DROP
  │     state machine advance (NONE→SYN_SENT→SYN_RECV→ESTABLISHED→…)
  │
  ├─ sess_update(s, skb, dir)
  │     pkts, bytes, IAT, TCP flags, pkt len min/max per direction
  │
  └─ NF_ACCEPT  (pkts_forwarded++)

NIC TX
```

---

## 4. Session Lifecycle

```
[CREATE]
  First packet of new flow
      └──► sess_lookup_or_create()
               spin_lock_bh(table_lock)
               double-check both directions under lock (race resolution)
               also verifies found session has not expired (adaptive TTL may crush to 0)
               kmalloc session, jhash key, hash_add_rcu
               spin_lock(lru_lock)        ← lock order: table_lock → lru_lock
               list_add_tail → sess_lru   ← LRU tail (most-recently-used)
               spin_unlock(lru_lock)
               spin_unlock_bh(table_lock)
               SESS_NEW netlink event ──► sg-flowd (ignored), sg-mld (Phase 3)

[ACTIVE]
  Every subsequent packet
      └──► sess_update()  ── stats accumulate
      └──► SESS_BLOCKED check on every packet (READ_ONCE, no lock)
      └──► sess_tcp_check()  ── state machine advances

[EXPIRY]
  sess_reaper (delayed_work, fixed 1 Hz — interval never shortened under load)
      └──► Phase 1: incremental bucket scan under spin_lock_bh(table_lock) + spin_lock(lru_lock)
               gc_aggressive=false: scan 64 buckets/tick  (full table in ~16 s)
               gc_aggressive=true:  scan 256 buckets/tick (full table in ~4 s)
               gc_idx cursor advances each tick — wraps at 1024
               sess_pf_timeout(): effective TTL shrinks linearly above pf_adaptive_start,
                                   crushed to 0 at pf_adaptive_end (FreeBSD PF formula)
               TCP ESTABLISHED excluded from TTL scaling (protect live connections)
               expired → hash_del_rcu() + list_del_init(lru_node) + call_rcu()
               SESS_EXPIRED netlink event sent after locks released ──► sg-flowd
      └──► Phase 2 (aggressive mode only): LRU-head sweep
               evict up to 32 oldest sessions per tick satisfying same TTL condition
      └──► Hysteresis: gc_aggressive latched ON at active >= pf_adaptive_start,
               cleared only when active < 85% of pf_adaptive_start

  Inline expiry in sess_lookup() (Technique 3):
      ktime_get() >= expires_at? → unlink immediately on hot hash chains
      prevents expired entries accumulating between 1 Hz ticks

  Inline emergency eviction in sess_lookup_or_create() (Weapon 2):
      active >= pf_max_states → pf_purge_expired_states_emergency()
      walks up to 64 LRU head entries, evicts zero-TTL or idle-past-TTL sessions
      freed == 0 → increment sess_pf_drops, return NULL → NF_DROP

[SCORE / BLOCK]  (Phase 3)
  sg-mld writes via Netlink:
      SG_FLOW_CMD_SESS_SCORE ──► kernel writes ml_score (s32 × 1000) to session
      SG_FLOW_CMD_SESS_BLOCK ──► kernel sets SESS_BLOCKED bit (0x0002) in session.flags
                                  next packet hits SESS_BLOCKED check ──► NF_DROP
  Note: SESS_MARKED (0x0004) is also defined — flagged suspicious but still forwarded.
```

---

## 5. Management Daemon (mgmtd)

Single privileged daemon, root, Unix domain socket `/run/stargazer-mgmtd.sock`.
All config mutations and privileged reads go through mgmtd — CLI and Web UI
never touch the filesystem or kernel directly.

```
CLI / Web UI
    │ binary IPC request  (sg_request_hdr_t + payload)
    ▼
stargazer-mgmtd
    │
    ├─ Config reads/writes  ──►  SQLite  (/etc/stargazer/stargazer.db)
    │                            sg_db.c
    │
    ├─ Network apply        ──►  ip link / ip addr / ip route
    │   mgmtd_apply_iface.c       (forked, sandboxed)
    │   mgmtd_apply_route.c
    │   mgmtd_apply_nat.c   ──►  iptables -t nat
    │   mgmtd_apply_dhcp.c  ──►  dnsmasq config rewrite + SIGHUP
    │   mgmtd_apply_dns.c   ──►  /etc/resolv.conf rewrite
    │   mgmtd_apply_ntp.c   ──►  chronyd config rewrite + SIGHUP
    │
    ├─ Firewall apply       ──►  iptables -F / -A  (mgmtd_apply_firewall.c)
    │
    ├─ Diagnostics          ──►  /proc/stargazer/* reads  (mgmtd_diag.c)
    │
    ├─ Firmware upgrade     ──►  wget / tftp download, tar extract,
    │   mgmtd_firmware.c          sha256 verify, dd to eMMC partition, reboot
    │
    └─ User management      ──►  SQLite users table  (mgmtd_user.c)
```

**FortiOS parallel:** `cmdbsvr` (config bus) + `httpsd`/`sshd` clients. Stargazer's mgmtd is a simplified single-daemon equivalent.

---

## 6. CLI Architecture

Binary: `/sbin/stargazer-cli`, statically linked, runs in a sandboxed process.
Communicates with mgmtd over the Unix socket.

```
User input
    │
    ▼
cli_readline.c          ← zero-fork readline: tab completion, history, '?' help
    │
    ▼
cli_resolve_cmd()       ← FortiOS-style prefix abbreviation
    │                      e.g. "exe sys shut" → "execute system shutdown"
    ▼
cli_dispatch.c          ← routes to show / execute / configure / diagnose
    │
    ├─ show commands    ──► IPC request to mgmtd ──► formatted output
    ├─ execute commands ──► IPC request to mgmtd ──► action + result
    ├─ configure context──► cli_configure.c
    │                        FortiOS-style table/entry/single contexts
    │                        set/unset/get/show within context
    │                        commit on exit
    └─ diagnose commands──► IPC request to mgmtd ──► raw diagnostic output
```

Command definition: X-macro table in `sg_cmd_defs.h`. Adding a new command
requires one entry there plus a handler in `cli_cmd_table.c`.

---

## 7. Web UI Architecture

```
Browser
    │  HTTPS
    ▼
stargazer-webd  (Mongoose HTTP server, single-threaded event loop)
    │
    ├─ Static files    ──► /www/home.html, /www/js/app.js, /www/css/
    │
    ├─ Session auth    ──► webd_session.c  (cookie tokens, SQLite sessions table)
    │
    ├─ API endpoints   ──► webd_api.c
    │   /api/...            ──► webd_ipc.c ──► mgmtd Unix socket ──► response JSON
    │
    └─ Monitor endpoints──► webd_pool.c  (background worker pool)
        /monitor/...         ──► mgmtd IPC ──► JSON

app.js (single-page)
    │
    ├─ Page navigation  ── hash-based routing (#interfaces, #firewall, etc.)
    ├─ api()            ── fetch wrapper → /api/* endpoints
    ├─ renderSessions() ── client-side pagination + search
    └─ renderXxx()      ── one render function per page, called on nav
```

**FortiOS parallel:** `httpsd` serves the GUI; API calls go to `cmdbsvr` via internal IPC. Stargazer's webd+mgmtd split is the same pattern.

---

## 8. Config Database Schema

SQLite at `/etc/stargazer/stargazer.db`. Schema in `db_schema.sql`.

Key tables:

| Table | Contents |
|---|---|
| `interfaces` | WAN/LAN port config (IP, mode, MTU, admin state) |
| `firewall_rules` | Policy rules (src/dst/service/action/order) |
| `nat_rules` | MASQUERADE / DNAT rules |
| `routes` | Static routes |
| `dhcp_pools` | DHCP server pools per interface |
| `dns_config` | Upstream resolvers |
| `ntp_config` | NTP server list |
| `users` | Login accounts (hashed password, role) |
| `audit_log` | Command audit trail with timestamp + user |

All config writes go through `sg_validate.c` before reaching SQLite —
input validation (safe ID, IPv4, CIDR, type registry) is enforced at the IPC
boundary in mgmtd, not in the CLI.

---

## 9. NetFlow / ML Export Pipeline

```
session.ko
    │ SESS_EXPIRED netlink multicast (sg_flow genl family)
    │ Attributes: 5-tuple, pkts/bytes/IAT/TCP flags/pkt lengths per direction
    ▼
sg-flowd  (userspace, subscribes to sg_flow_events multicast group)
    │
    ├─ SESS_NEW     ──► ignored (reserved for Phase 4 real-time ML feed)
    └─ SESS_EXPIRED ──► NetFlow v9 UDP record ──► external collector
                        Template 256: all sg_flow_attr fields
                        Sequence number + uptime in header

sg-mld  (Phase 3 — ML scoring daemon, NOT YET IMPLEMENTED)
    │
    ├─ subscribes to SESS_NEW
    ├─ reads session features
    ├─ sends SG_FLOW_CMD_SESS_SCORE (ml_score × 1000)
    └─ sends SG_FLOW_CMD_SESS_BLOCK → kernel sets SESS_BLOCKED
```

---

## 10. Firmware Upgrade Workflow

```
CLI: execute firmware upgrade <url>
    │  URL validated (http:// https:// tftp:// only)
    ▼
mgmtd forks child process
    │
    ├─ [0/6] start
    ├─ [1/6] download
    │         http/https: wget -T 30 -O /tmp/sg-fw-download/firmware.tar.gz
    │         tftp: tftp -g -r <path> <host>
    │         progress polled via stat() + WNOHANG every 500ms
    │
    ├─ [2/6] extract
    │         tar -xzf firmware.tar.gz -C /tmp/sg-fw-staged/ --strip-components=1
    │         checks: manifest.txt present
    │
    ├─ [3/6] verify
    │         sha256sum stargazer.itb vs manifest.txt fit_sha256
    │
    ├─ [4/6] locate partition
    │         check /dev/mmcblk0p4 then /dev/mmcblk1p4
    │         reads /sys/class/block/<dev>/uevent for PARTNAME=firmware or PARTNAME=kernel
    │
    ├─ [5/6] write + verify
    │         dd if=stargazer.itb of=<partition> bs=512k
    │         readback: dd if=<partition> bs=512k count=<fit_size> | sha256sum
    │         abort on sha256 mismatch
    │
    └─ [6/6] reboot
              sync
              stamp DB seeded flag; back up DB to <db>.pre-upgrade
              sleep 5s  (allow JS poll to read done=true before connection drops)
              /sbin/reboot

CLI polls SG_CMD_UPGRADE_PROGRESS every 500ms → displays [N/6] progress line

Web UI file-upload path (SG_CMD_UPGRADE_FROM_FILE):
    Browser uploads .tar.gz → webd → /tmp/sg-fw-upload.tar.gz
    mgmtd moves file to staging area as step 1; steps 2-6 are identical to URL path
```

---

## 11. Authentication and Audit

```
Console / SSH login
    ▼
stargazer-logind
    │  password hash check (bcrypt) against SQLite users table
    │  password policy enforcement (length, complexity, history)
    │  account lockout after N failures
    │  writes audit_log: timestamp, user, src_ip, success/fail
    ▼
shell / stargazer-cli

Every CLI command that mutates config or executes an action:
    ▼
mgmtd writes audit_log entry: timestamp, user, command, result
```

---

## 12. Phase Roadmap

| Phase | Status | Description |
|---|---|---|
| 1 | Done | Basic routing OS: interfaces, DHCP, NAT, static routes, CLI, Web UI, firmware upgrade |
| 2 | Done | Stateful session tracking: RCU table, TCP state machine, procfs, NetFlow export |
| 3 | Planned | ML scoring daemon (sg-mld): session feature extraction, SESS_SCORE + SESS_BLOCKED feedback, `diagnose session list/filter` |
| 4 | Planned | IPS module: signature-based payload inspection, hooks into session on match. IPv6 support. |
| 5 | Planned | IPv6 support, VPN (WireGuard/IPsec), HA (VRRP + state sync) |

---

## 13. Key Design Principles (FortiOS-aligned)

1. **Kernel enforces, userspace configures** — policy enforcement (SESS_BLOCKED, TCP state drops) happens in the kernel data plane on every packet, not in userspace rules that can be bypassed.

2. **Single privileged daemon** — all config mutations go through mgmtd. CLI and Web UI are sandboxed clients with no direct filesystem or kernel access.

3. **Stateful by default, strict** — non-SYN TCP drops and RST validation are hardcoded, not configurable. Asymmetric mode is an explicit opt-in.

4. **Fixed-point arithmetic in kernel** — no floats. ML scores are `s32` × 1000.

5. **Honesty over silence** — if a build breaks, it fails loudly. Errors say what is actually wrong. Buffers are always checked.

6. **Audit everything** — every login attempt and every config mutation is logged with user, timestamp, and result.
