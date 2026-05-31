# Phase 2 — Connection-State Tracking on nf_conntrack + Per-Flow ML Features

> Stargazer NGFW · v0.2.1 · BPI-R4 (MT7988A, ARM64)
>
> **This document supersedes the original Phase 2 "custom session.ko" design.**
> The bespoke RCU session hash table, its TCP state machine, the session-based
> block enforcement, and the DoS-policy rate limiters have been removed. All
> connection-state tracking now runs on the Linux kernel's `nf_conntrack`, with
> a small per-flow ML feature vector carried as a conntrack extension.

---

## 1. Overview

Phase 2 originally shipped a custom kernel module, `session.ko`, that maintained
its own 5-tuple session table, ran a TCP state machine, and enforced
`SESS_BLOCKED`. `pkt_forward.ko` drove that table from the `NF_INET_FORWARD`
hook, and a DoS policy layered token-bucket rate limiting on top.

That design has been retired. What this phase delivers now:

- **Connection-state tracking moved onto `nf_conntrack`.** The kernel's mature,
  SMP-safe connection tracker owns all per-flow state (and NAT). Stargazer no
  longer maintains a parallel session table.
- **`pkt_forward.ko` reduced to a stateless anomaly screen.** It validates IPv4,
  drops L3/L4 attack patterns (Land, source-routing, NULL/XMAS/FIN scans, SYN
  with data, Ping of Death), and accounts per-flow ML features. It holds no
  per-session state and enforces no blocks.
- **Per-flow ML features stored in conntrack and exported.** A new conntrack
  extension, `struct nf_conn_ml` (`NF_CT_EXT_ML`), is allocated on every tracked
  flow, populated per packet, and exported as a binary netlink attribute
  (`CTA_ML`) on the conntrack dump path.
- **DoS policy + `session.ko` removed.** The custom module, its self-test, the
  session header, and the entire DoS-policy configuration/validation/CLI/IPC
  surface are deleted.

Policy enforcement is delegated to **iptables** using a connmark "generation"
scheme so that a policy change re-evaluates only the affected live flows.

---

## 2. Architecture

Division of labour after the migration:

| Component | Responsibility |
|---|---|
| **nf_conntrack** (kernel) | All connection state, the TCP state machine, and NAT. Source of truth for flows. |
| **iptables FORWARD chain** | Policy enforcement: `INVALID` drop, connmark-generation fast-path/re-eval, ACCEPT/DROP per configured rule. |
| **pkt_forward.ko** | Stateless anomaly screen (IPv4 validation + L3/L4 anomaly drop) and per-packet ML feature accounting into the conntrack ML extension. |
| **ipset / ML scoring daemon** | Active blocking based on `ml_score`. **Deferred** — no model and `CONFIG_IP_SET` is off. The `ml_score` field exists and is exportable, but nothing writes it back or blocks on it yet. |

### Packet path through FORWARD

`pkt_forward.ko` registers at `NF_IP_PRI_CONNTRACK_DEFRAG + 1`: after IPv4
defragmentation, but **before** conntrack tracking and the filter table. This
drops malformed/attack packets before the kernel spends work tracking them.

```
            ingress
               |
               v
    +--------------------------+   NF_IP_PRI_CONNTRACK_DEFRAG
    |  nf_defrag_ipv4          |   (reassemble fragments)
    +--------------------------+
               |
               v
    +--------------------------+   NF_IP_PRI_CONNTRACK_DEFRAG + 1
    |  pkt_forward forward_hook|
    |   1. is_valid_ipv4()     |--> NF_DROP (malformed)
    |   2. TCP linearity pull  |--> NF_DROP
    |   3. anomaly screen:     |--> NF_DROP (pkts_anomaly_dropped++)
    |      ip / tcp / icmp     |
    |   4. ml_account()        |   (populate nf_conn_ml extension)
    |   -> NF_ACCEPT           |
    +--------------------------+
               |
               v
    +--------------------------+   NF_IP_PRI_CONNTRACK
    |  nf_conntrack            |   lookup/create flow; alloc nf_conn_ml ext
    +--------------------------+
               |
               v
    +--------------------------+   filter table FORWARD (priority 0)
    |  iptables policy         |
    |   -m conntrack INVALID   |--> DROP
    |   ESTABLISHED,RELATED    |
    |     + connmark gen==cur  |--> ACCEPT (fast-path)
    |   policy rules           |--> CONNMARK stamp + ACCEPT, or DROP
    +--------------------------+
               |
               v
    +--------------------------+
    |  NAT + conntrack confirm |
    +--------------------------+
               |
               v
            egress
```

---

## 3. Files created / changed

### Kernel repository — `../stargazer-kernel`, branch `stargazer/6.12-main` (base Linux 6.12.69)

| File | Change |
|---|---|
| `include/net/netfilter/nf_conntrack_ml.h` | **New.** Defines `struct nf_conn_ml`, `nf_conn_ml_find()`, and the priming allocator `nf_ct_ml_ext_add()`. |
| `include/net/netfilter/nf_conntrack_extend.h` | Add `NF_CT_EXT_ML` to `enum nf_ct_ext_id` (before `NF_CT_EXT_NUM`). |
| `net/netfilter/nf_conntrack_extend.c` | Register `[NF_CT_EXT_ML] = sizeof(struct nf_conn_ml)` in the length table; add `+ sizeof(struct nf_conn_ml)` to `total_extension_size()`; `BUILD_BUG_ON(NF_CT_EXT_NUM > 11)`. |
| `net/netfilter/nf_conntrack_core.c` | Call `nf_ct_ml_ext_add(ct, GFP_ATOMIC)` in `init_conntrack()` (line ~1802). |
| `net/netfilter/nf_conntrack_netlink.c` | Add `ctnetlink_dump_ml()` (emits `CTA_ML`); call it from `ctnetlink_dump_extinfo()` on the dump path. |
| `include/uapi/linux/netfilter/nfnetlink_conntrack.h` | Add `CTA_ML` to `enum ctattr_type` (value 27, before `__CTA_MAX`). |

**Kernel commits:**
`871b399` — *netfilter: conntrack: add NF_CT_EXT_ML per-flow feature extension*;
`27fa419` — *netfilter: ctnetlink: export NF_CT_EXT_ML as CTA_ML in conntrack dumps*.

### Stargazer repository

| File | Change |
|---|---|
| `src/modules/pkt_forward.c` | Rewritten: stateless anomaly screen + `ml_account()` into the conntrack ML extension. All session/DoS code removed. |
| `src/modules/Makefile` | `obj-m += pkt_forward.o` only (dropped `session.o`, `session_test.o`). |
| `src/userspace/mgmtd/mgmtd_diag.c` | Conntrack readers: `handle_show_sessions`, `handle_session_stats`, `handle_session_clear` (netlink CT_DELETE), `handle_session_ml` (netlink CT_GET+DUMP, parses `CTA_ML`); `ct_emit_line()`, `ct_ml_emit()`, `conntrack_flush_all()`. |
| `src/userspace/mgmtd/mgmtd_apply_firewall.c` | `rebuild_forward_chain()` connmark-generation re-eval; `connmark_supported()` probe; flush fallback. |
| `src/userspace/mgmtd/stargazer-mgmtd.c` | Dispatch for `SG_CMD_SESSION_*`; DoS dispatcher/apply-order entries removed. |
| `src/userspace/mgmtd/stargazer_ipc.h` | IPC command IDs; `SG_CMD_SESSION_BLOCKS` removed. |
| `src/userspace/cli/cli_cmd_table.c`, `cli_show.c`, `cli_diagnose_session.c` | `show sessions`, `execute diagnose session {status,stats,clear,ml}`, selftest SESS-01..05; DoS `blocks` command removed. |
| `src/userspace/webd/webd_pool.c` | `flow_monitor_sessions()` → `/monitor/sessions` JSON. |
| `src/userspace/webui/www/home.html`, `js/app.js` | Session table, filters, dashboard session gauge. |
| `src/userspace/common/sg_validate.c` | `system_dos-policy` type + 18 fields and validation removed. |
| `etc/sysctl.d/10-stargazer.conf` | `nf_conntrack_max`, `nf_conntrack_acct=1`, `nf_conntrack_timestamp=1`. |
| `etc/modules-load.d/stargazer.conf` | Load `pkt_forward` (and `af_packet`); session module removed. |
| `Makefile` | `KERNEL_DIR` points at separate `../stargazer-kernel`; `KERNEL_BRANCH := stargazer/6.12-main`; `MODULE_NAME := pkt_forward`. |
| **`src/modules/session.c`** | **DELETED** (1760 lines). |
| **`src/modules/session.h`** | **DELETED** (198 lines). |
| **`src/modules/session_test.c`** | **DELETED** (180 lines). |

**Stargazer migration commits:**
`020287d` (remove DoS + session.ko, switch data plane to nf_conntrack) →
`03b47f0` (CLI/diagnostics to conntrack) →
`8079799` (web monitor to conntrack) →
`d263419` (flush conntrack on policy apply) →
`fb79d7e` (connmark-generation surgical re-eval) →
`cfe0ec2` (pkt_forward populates ML extension) →
`17f8ffb` (read-only ML viewer `execute diagnose session ml`).

---

## 4. Data structures added

### `struct nf_conn_ml` (kernel)

Defined in `include/net/netfilter/nf_conntrack_ml.h`. Per-flow ML feature vector,
**48 bytes** (44 bytes of fields, padded to the 8-byte `u64` alignment), indexed
by direction `[0]=IP_CT_DIR_ORIGINAL`, `[1]=IP_CT_DIR_REPLY`.

```c
struct nf_conn_ml {
    u64   first_ns;      /* ktime of the first packet (flow start)    */
    u64   last_ns;       /* ktime of the last packet (IAT + duration) */
    u64   iat_sum_ns;    /* sum of inter-arrival gaps (both dirs)     */
    u32   iat_count;     /* number of gaps accumulated                */
    u16   tcp_flags[2];  /* OR of TCP flag bits seen, per direction   */
    u16   len_min[2];    /* smallest L3 packet length, per direction  */
    u16   len_max[2];    /* largest  L3 packet length, per direction  */
    s32   ml_score;      /* score written back by the ML daemon       */
};
```

| Field | Type | Meaning |
|---|---|---|
| `first_ns` | `u64` | `ktime_get_ns()` of the first packet — flow start. |
| `last_ns` | `u64` | `ktime` of the most recent packet — gives duration (`last_ns - first_ns`) and the previous-packet timestamp for IAT. |
| `iat_sum_ns` | `u64` | Sum of inter-arrival gaps across both directions. |
| `iat_count` | `u32` | Number of gaps accumulated; average IAT = `iat_sum_ns / iat_count`. |
| `tcp_flags[2]` | `u16` | OR of TCP flag bits seen per direction (FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10, URG 0x20). |
| `len_min[2]` | `u16` | Smallest L3 packet length per direction (primed to `U16_MAX`). |
| `len_max[2]` | `u16` | Largest L3 packet length per direction. |
| `ml_score` | `s32` | Score written back by the ML daemon. Currently unused (0); no daemon writes it yet. |

> The header notes that packet/byte counts come from the standard ACCT extension;
> `nf_conn_ml` holds only what ACCT/TSTAMP do not (timing, length spread,
> accumulated flags) plus the ML score.

### Registration as conntrack extension `NF_CT_EXT_ML`

1. **Enum** (`nf_conntrack_extend.h`): `NF_CT_EXT_ML` added before `NF_CT_EXT_NUM`.
2. **Length table** (`nf_conntrack_extend.c`):
   `[NF_CT_EXT_ML] = sizeof(struct nf_conn_ml)` (48 bytes), and
   `total_extension_size()` adds `+ sizeof(struct nf_conn_ml)`.
3. **Offset guard:** `BUILD_BUG_ON(NF_CT_EXT_NUM > 11)` keeps the per-conntrack
   `u8 offset[NF_CT_EXT_NUM]` table within range.
4. **Allocation** (`init_conntrack()` in `nf_conntrack_core.c`):
   `nf_ct_ml_ext_add(ct, GFP_ATOMIC)` on the not-yet-confirmed conntrack. The
   helper primes `len_min[0]` and `len_min[1]` to `U16_MAX` so the first packet
   in each direction sets the minimum.

The extension is compiled unconditionally (no `CONFIG` guard) and is therefore
present on every conntrack-enabled build.

### Userspace mirror — `struct sg_nf_conn_ml`

`mgmtd_diag.c` defines a byte-compatible mirror so the netlink `CTA_ML` blob can
be cast directly (emitted host-byte-order, no endian conversion):

```c
struct sg_nf_conn_ml {
    uint64_t first_ns, last_ns, iat_sum_ns;
    uint32_t iat_count;
    uint16_t tcp_flags[2];      /* [orig, reply] */
    uint16_t len_min[2], len_max[2];
    int32_t  ml_score;
};
```

---

## 5. Workflows

### (a) Packet path through FORWARD

`forward_hook()` in `pkt_forward.c` runs in order:

1. **IPv4 validation** — `is_valid_ipv4()` pulls the IP header, checks
   `version == 4` and `IHL >= 5`; `NF_DROP` on failure.
2. **TCP linearity** — for `IPPROTO_TCP`, pull 20 bytes of TCP header; `NF_DROP`
   on failure.
3. **Anomaly screen** — `is_ip_anomaly()`, then `is_tcp_anomaly()` (TCP only),
   then `is_icmp_anomaly()`. On any hit: `pkts_anomaly_dropped++`,
   `pkts_dropped++`, return `NF_DROP`.
4. **ML accounting** — `ml_account(skb, proto)` for accepted packets.
5. **Accept** — `pkts_forwarded++`, return `NF_ACCEPT` (on to conntrack, policy,
   NAT).

**Anomaly patterns dropped:**

| Helper | Patterns |
|---|---|
| `is_ip_anomaly` | Land attack (`saddr == daddr`); IP source routing (LSRR type 131, SSRR type 137) when IP options present. |
| `is_tcp_anomaly` | NULL scan (no control bits); XMAS (FIN+URG+PSH); FIN without ACK; SYN carrying data. |
| `is_icmp_anomaly` | Ping of Death (`tot_len > 65500` after reassembly). |

**`ml_account()`** retrieves the flow with `nf_ct_get(skb, &ctinfo)` and its
extension with `nf_conn_ml_find(ct)` (returns early if either is NULL — untracked
packets are skipped), resolves direction via `CTINFO2DIR(ctinfo)`, then under
`spin_lock_bh(&ct->lock)`:

- `now = ktime_get_ns()`; set `first_ns` on first packet; otherwise add the gap
  to `iat_sum_ns` and bump `iat_count`; always update `last_ns`.
- Update `len_min[dir]` / `len_max[dir]`.
- For TCP, OR the flag bitmap into `tcp_flags[dir]`.

### (b) Policy-change connmark-generation re-evaluation

When firewall policy changes, `rebuild_forward_chain()` re-evaluates only the
flows the change affects, instead of dropping every connection.

`connmark_supported()` runs a one-time probe: it builds a temp chain and tests
`-m connmark --mark 0/0xff -j CONNMARK --set-xmark 0/0xff`, caching the result.

**Connmark path** (`SG_CMK_MASK = 0xFF`, generation cycles `1..255`, never 0):

1. Bump `fwd_policy_gen = (fwd_policy_gen % 255) + 1`. Flush the FORWARD chain
   (policy `DROP` covers the rebuild window).
2. Foundation rules:
   ```
   -A FORWARD -m conntrack --ctstate INVALID -j DROP
   -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED \
              -m connmark --mark 0x<gen>/0xff -j ACCEPT
   ```
   Only flows stamped with the **current** generation take the fast-path;
   stale-generation and NEW flows fall through to be re-evaluated.
3. Policy rules (highest sequence first):
   - **ACCEPT** rules are preceded by a `CONNMARK --set-xmark 0x<gen>/0xff` stamp,
     then `-j ACCEPT`.
   - **DENY/DROP** rules do **not** stamp — those flows stay stale-gen and fall
     to the policy `DROP`.
4. On the next packet of each live flow:
   - **Still allowed** → matches a rule → re-stamped with the new gen → fast-path,
     uninterrupted.
   - **Newly denied** → falls through the ESTABLISHED rule (gen no longer matches)
     → hits the policy `DROP`.
   - **Management/SSH** flows that remain allowed are re-stamped and untouched.

**Fallback (no connmark support):** `conntrack_flush_all()` (netlink
`CT_DELETE`) clears the whole table; all flows re-establish, which can briefly
interrupt management traffic.

### (c) ML feature lifecycle

```
  collect                export                     view
  -------                ------                     ----
  ml_account()  ----->   CTA_ML via         ----->  execute diagnose session ml
  (per packet,           ctnetlink dump             (CLI)  ->  SG_CMD_SESSION_ML
   updates nf_conn_ml)   (ctnetlink_dump_ml,         |
                          dump path only)            v
                                              mgmtd handle_session_ml:
                                              in-process netlink CT_GET + NLM_F_DUMP,
                                              parses each msg's CTA_ML blob
```

- **Collect:** `ml_account()` updates `nf_conn_ml` per packet (see 5a).
- **Export:** `ctnetlink_dump_ml()` does `nla_put(skb, CTA_ML, sizeof(*ml), ml)`
  — the whole 48-byte struct as a host-order binary blob. It returns 0 silently
  if the extension is absent. It is wired into `ctnetlink_dump_extinfo()` on the
  **dump path only** (active query/dump), **not** event notifications — so
  `CONFIG_NF_CONNTRACK_EVENTS` is **not** required.
- **View:** `handle_session_ml()` opens an in-process `AF_NETLINK` socket, sends
  `IPCTNL_MSG_CT_GET | NLM_F_REQUEST | NLM_F_DUMP` (family `AF_INET`), reads to
  `NLMSG_DONE`, and `ct_ml_emit()` parses each message's `CTA_ML` into one line.

> Packet and byte counts come from the standard `nf_conntrack` **ACCT** extension
> (requires `nf_conntrack_acct=1`), not from `nf_conn_ml`.

ML line emitted by `ct_ml_emit()`:
```
proto=<u> src=<ip>:<u> dst=<ip>:<u> iat_avg_us=<llu> dur_ms=<llu> \
  len_o=<u>-<u> len_r=<u>-<u> flags_o=0x<x> flags_r=0x<x> score=<d>
```

---

## 6. CLI & Web

### CLI commands

| Command | IPC | Output |
|---|---|---|
| `show sessions` | `SG_CMD_SHOW_SESSIONS` | `active=N` header + key=value rows from conntrack. |
| `execute diagnose session [status]` | `SG_CMD_SHOW_SESSIONS` | "=== Active Connections (conntrack) ===" + rows. |
| `execute diagnose session stats` | `SG_CMD_SESSION_STATS` | `conntrack_available`, `pkt_forward_loaded`, `active`, `forwarded`, `dropped`, `anomaly_dropped`. |
| `execute diagnose session clear` | `SG_CMD_SESSION_CLEAR` | Y/N confirm → "Flushed N session(s)". |
| `execute diagnose session ml` | `SG_CMD_SESSION_ML` | "=== Per-flow ML Features ===" + `CTA_ML` lines. |
| `execute diagnose selftest session` | — | SESS-01..05 (conntrack avail, pkt_forward loaded, header, `active=`, `forwarded=`). |

Normalized conntrack line (from `ct_emit_line()`, requires `nf_conntrack_acct=1`):
```
proto=<proto> state=<state> src=<ip>:<port> dst=<ip>:<port> pkts=<n> bytes=<n>
```

### Web `/monitor/sessions` (GET)

`flow_monitor_sessions()` (webd) calls `SG_CMD_SHOW_SESSIONS`, parses the text,
and returns:

```json
{
  "active": <number>,
  "loaded": <boolean>,
  "sessions": [
    { "proto": "tcp", "state": "ESTABLISHED",
      "src": "192.168.1.100:54321", "dst": "8.8.8.8:443",
      "pkts": "45", "bytes": "98765" }
  ]
}
```

If conntrack is unavailable (`resp.extra == "not_available"`):
`{"active":0,"loaded":false,"sessions":[]}`. Comment/empty lines and rows missing
`proto` are skipped.

**Web UI** (`page-fw-sessions`): columns PROTO, SOURCE, DESTINATION, STATE
(colored dot), PACKETS, BYTES (`formatBytes()`); search (150 ms debounce),
protocol/state dropdowns, clear-filters; pagination 10/25/50 (default 25);
summary "Active: N". The dashboard **session gauge** (`gauge-sessions`) reads
`/system/resources` (`sessions` / `sessions_max`, hard max 65536), polled every
5 s and paused when the tab is hidden.

---

## 7. IPC commands

| ID | `SG_CMD_*` | Handler | Source | Perm | Purpose |
|---|---|---|---|---|---|
| 650 | `SG_CMD_SHOW_SESSIONS` | `handle_show_sessions` | `/proc/net/nf_conntrack` (file I/O) | monitor | Normalized conntrack flow lines. |
| 655 | `SG_CMD_SESSION_CLEAR` | `handle_session_clear` | netlink `CT_DELETE` (`conntrack_flush_all`) | admin | Flush entire conntrack table in-process. |
| 656 | `SG_CMD_SESSION_STATS` | `handle_session_stats` | `/proc/net/nf_conntrack` count + `/proc/stargazer/pkt_forward_stats` | monitor | Active flow count + pkt_forward counters. |
| 659 | `SG_CMD_SESSION_ML` | `handle_session_ml` | netlink `CT_GET \| NLM_F_DUMP`, parse `CTA_ML` | monitor | Per-flow ML feature blobs. |

All handlers check permission first, read state via procfs or in-process netlink
(never fork), buffer through `struct dynbuf`, and respond within
`SG_RESPONSE_MAX` (65536 bytes).

**Retired IDs** (kept reserved in the header for reference): `654`
(was `SG_CMD_DIAG_SESSION`, session.ko self-test), `657` (was
`SG_CMD_SESSION_GC_INTERVAL`, session.ko GC knob), `658` (reserved); and the
former `SG_CMD_SESSION_BLOCKS` DoS handler is removed entirely.

---

## 8. Build & kernel config

- **Separate kernel repo:** `../stargazer-kernel`, branch `stargazer/6.12-main`,
  base Linux 6.12.69. The root `Makefile` sets `KERNEL_DIR` to it.
- **Module target:** `MODULE_NAME := pkt_forward`; `src/modules/Makefile` builds
  only `pkt_forward.o`. `pkt_forward.ko` declares
  `MODULE_SOFTDEP("pre: nf_defrag_ipv4")`.
- **`/etc/modules-load.d/stargazer.conf`:** `af_packet`, `pkt_forward` (session
  module removed).

**Conntrack sysctls** (`/etc/sysctl.d/10-stargazer.conf`):

```
net.netfilter.nf_conntrack_max       = 131072   # max tracked flows
net.netfilter.nf_conntrack_acct      = 1        # per-flow pkts/bytes (ct_emit_line)
net.netfilter.nf_conntrack_timestamp = 1        # flow timestamps for ML features
```

**Kernel `.config` facts:**

| Symbol | State | Note |
|---|---|---|
| `CONFIG_NF_CONNTRACK` | `y` | Core requirement. |
| `CONFIG_NF_CT_NETLINK` | `y` | Required for `CTA_ML` export and netlink flush/dump. |
| `CONFIG_NF_CONNTRACK_MARK` | `y` | connmark — required by connmark-generation re-eval. |
| `CONFIG_NF_CONNTRACK_EVENTS` | **off** | Not needed; ML export is dump-only, not event-emitted. |
| `CONFIG_IP_SET` | **off** | → ipset-based blocking deferred. |
| `CONFIG_NF_CONNTRACK_TIMESTAMP` | off (build) | `nf_conn_ml.first_ns/last_ns` carry timing instead. |
| `CONFIG_NF_CONNTRACK_LABELS` | off | Orthogonal to ML feature. |

`NF_CT_EXT_ML` is compiled unconditionally on conntrack-enabled builds.

---

## 9. Removed

- **`session.ko` / `session.h` / `session_test.ko`** — the custom RCU session
  table, TCP state machine, reaper, and kernel self-test. **Why:** `nf_conntrack`
  already provides robust, SMP-safe state tracking, NAT, and a netlink interface;
  maintaining a parallel table duplicated effort and risk. State now lives in one
  place.
- **DoS policy** — the `system_dos-policy` config type and its 18 fields,
  validation, the `apply_dos_policy()`/`update_protected_ifmask()` mgmtd code,
  the `handle_session_blocks` IPC handler / `SG_CMD_SESSION_BLOCKS`, the
  `execute diagnose session blocks` CLI command, and the in-kernel DoS machinery
  (per-source token buckets, block list, port-scan bloom filter, half-open cap,
  per-packet ICMP limiter, `dos_blocks` ring buffer + procfs). **Why:** that
  logic belongs in the connmark-driven iptables policy and the future ML/ipset
  path, not in a bespoke module. The stateless **anomaly** screen and its
  `anomaly_dropped` counter are retained.

---

## 10. Status & deferred work

**Done:**

- Connection state + NAT on `nf_conntrack`.
- `pkt_forward.ko` as a stateless anomaly screen with ML feature accounting.
- ML feature **collect** (`ml_account`) → **export** (`CTA_ML` via ctnetlink
  dump) → **view** (`execute diagnose session ml`, `handle_session_ml`).
- connmark-generation surgical policy re-evaluation with flush fallback.
- CLI session commands, `/monitor/sessions` JSON, web table + dashboard gauge.

**Deferred (until a model exists):**

- **ipset-based active blocking** — `CONFIG_IP_SET` is off; no blocking on
  `ml_score` yet.
- **ML scoring daemon** — nothing currently writes `nf_conn_ml.ml_score`; the
  field is exported and ready, but scoring/feedback is future work (aligns with
  the Phase 3 ML daemon + IPS plans).
