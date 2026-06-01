# Phase 2 — Connection-State Tracking on nf_conntrack + Per-Flow ML Features

> Stargazer NGFW · v0.2.1 · BPI-R4 (MT7988A, ARM64)

---

## 1. Overview

Phase 2 tracks connection state on the Linux kernel's `nf_conntrack`, screens
traffic for malformed/attack packets, and tags every flow with a per-flow ML
feature vector carried as a conntrack extension. Firewall policy is enforced by
iptables, with a per-flow connmark `policy_id` so a policy (or routing) change
re-evaluates the affected live flows instead of dropping every connection.

What this phase delivers:

- **Connection state on `nf_conntrack`.** The kernel's SMP-safe connection
  tracker owns all per-flow state and NAT. It is the single source of truth for
  flows; everything else reads or annotates it.
- **`pkt_forward.ko` — a stateless anomaly screen + feature tap.** From the
  `NF_INET_FORWARD` hook it validates IPv4, drops L3/L4 attack patterns (Land,
  source routing, NULL/XMAS/FIN scans, SYN-with-data, Ping of Death), and
  accounts per-flow ML features. It holds no per-session state and enforces no
  blocks.
- **Per-flow ML features in conntrack.** A conntrack extension,
  `struct nf_conn_ml` (`NF_CT_EXT_ML`), is allocated on every tracked flow,
  filled per packet (timing, packet-length spread, accumulated TCP flags, the
  flow's in/out interface), and exported as a binary netlink attribute
  (`CTA_ML`) on the conntrack dump path.
- **Per-flow policy re-evaluation.** A connmark `policy_id` + DIRTY bit lets a
  policy change mark the relevant live flows dirty; their next packet
  re-traverses the FORWARD chain and is re-stamped (still allowed) or dropped
  (now denied). A routing change dirties all flows for the same reason.
- **Session visibility.** The session table shows each flow's owning policy
  name and its in/out interfaces, in the CLI and the web monitor.

All data-plane operations are in-process: state is read from
`/proc/net/nf_conntrack` and ctnetlink; flushing and dirtying go over NFNETLINK.
Nothing shells out to `conntrack` or `iptables` for per-flow work.

---

## 2. Architecture

| Component | Responsibility |
|---|---|
| **nf_conntrack** (kernel) | All connection state, the TCP state machine, and NAT. Source of truth for flows; carries the ML feature extension. |
| **pkt_forward.ko** | Stateless anomaly screen (IPv4 validation + L3/L4 anomaly drop) and per-packet ML feature accounting into the conntrack ML extension. |
| **iptables FORWARD chain** | Policy enforcement: `INVALID` drop, connmark DIRTY-bit fast-path / per-flow `policy_id` re-eval, ACCEPT/DROP per configured rule. |
| **mgmtd** | Builds the chain, dirties live flows on policy/route change (NFNETLINK), reads conntrack for diagnostics, resolves policy names and interfaces for display. |
| **ipset / ML scoring daemon** | Active blocking on `ml_score`. **Deferred** — no model and `CONFIG_IP_SET` is off. `ml_score` exists and is exportable, but nothing writes it back or blocks on it yet. |

### Packet path through FORWARD

`pkt_forward.ko` registers at `NF_IP_PRI_CONNTRACK_DEFRAG + 1`: after IPv4
defragmentation but **before** the filter table, so malformed/attack packets are
dropped before policy work. Conntrack itself runs at PRE/POST_ROUTING; the ML
extension is allocated when the flow is created, and `ml_account()` fills it
from the FORWARD hook (where the real ingress/egress interfaces are known).

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
    |   3. anomaly screen      |--> NF_DROP (pkts_anomaly_dropped++)
    |      ip / tcp / icmp     |
    |   4. ml_account(iif,oif) |   (fill nf_conn_ml extension)
    |   -> NF_ACCEPT           |
    +--------------------------+
               |
               v
    +--------------------------+   filter table FORWARD (priority 0)
    |  iptables policy         |
    |   ctstate INVALID        |--> DROP
    |   ESTABLISHED,RELATED     |
    |     + DIRTY clear         |--> ACCEPT (fast-path)
    |   policy rules            |--> CONNMARK stamp + ACCEPT, or DROP
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
| `include/net/netfilter/nf_conntrack_ml.h` | **New.** `struct nf_conn_ml`, `nf_conn_ml_find()`, and the priming allocator `nf_ct_ml_ext_add()`. |
| `include/net/netfilter/nf_conntrack_extend.h` | Add `NF_CT_EXT_ML` to `enum nf_ct_ext_id` (before `NF_CT_EXT_NUM`). |
| `net/netfilter/nf_conntrack_extend.c` | Register `[NF_CT_EXT_ML] = sizeof(struct nf_conn_ml)`; add it to `total_extension_size()`; `BUILD_BUG_ON(NF_CT_EXT_NUM > 11)`. |
| `net/netfilter/nf_conntrack_core.c` | Call `nf_ct_ml_ext_add(ct, GFP_ATOMIC)` in `init_conntrack()`. |
| `net/netfilter/nf_conntrack_netlink.c` | `ctnetlink_dump_ml()` emits `CTA_ML`; called from `ctnetlink_dump_extinfo()` on the dump path. |
| `include/uapi/linux/netfilter/nfnetlink_conntrack.h` | Add `CTA_ML` to `enum ctattr_type` (value 27). |

**Kernel commits:** `871b399` (add `NF_CT_EXT_ML` extension) → `27fa419`
(export `CTA_ML` in conntrack dumps) → `8b612166` (record per-flow in/out
interface in the ML extension).

### Stargazer repository

| File | Change |
|---|---|
| `src/modules/pkt_forward.c` | Stateless anomaly screen; `ml_account()` fills the ML extension per packet, including the flow's original-direction ingress/egress ifindex from the hook state. |
| `src/userspace/mgmtd/mgmtd_diag.c` | Conntrack readers `handle_show_sessions` / `handle_session_stats` / `handle_session_clear` (netlink `CT_DELETE`) / `handle_session_ml` (netlink `CT_GET`+`DUMP`, parses `CTA_ML`); `ct_emit_line()`; the policy-name map (`ct_policy_map_build`) and interface map (`ct_iface_map_build`); `conntrack_flush_all()`; `conntrack_mark_dirty_by_policy()`. |
| `src/userspace/mgmtd/mgmtd_apply_firewall.c` | `rebuild_forward_chain()` builds the INVALID drop, the DIRTY-bit fast-path, and per-policy `CONNMARK --set-xmark` stamps; `connmark_supported()` probe; `conntrack_reeval_after_policy_change()`. |
| `src/userspace/mgmtd/mgmtd_sequence.c/.h` | `cmkid_auto_assign()` — stable per-policy connmark id. |
| `src/userspace/mgmtd/stargazer-mgmtd.c` | Assign/backfill `cmkid`; choose the dirty scope (`policy_reeval_scope`) and call `conntrack_reeval_after_policy_change()` on policy create/edit/delete/reorder/cascade and on static-route change. |
| `src/userspace/common/sg_validate.c/.h` | `cmkid` registered as a hidden internal field (`SG_FLD_HIDDEN` flag on `struct field_entry`); `sg_reg_is_hidden_key()`. |
| `src/userspace/cli/cli_configure.c` | `set`/`unset` reject hidden internal fields. |
| `src/userspace/webd/webd_pool.c` | `flow_monitor_sessions()` → `/monitor/sessions` JSON, including each flow's `policy`, `iif`, `oif`. |
| `src/userspace/webui/www/home.html`, `js/app.js` | Session table with POLICY / IN / OUT columns, filters, dashboard session gauge. |
| `etc/sysctl.d/10-stargazer.conf` | `nf_conntrack_max`, `nf_conntrack_acct=1`, `nf_conntrack_timestamp=1`. |
| `etc/modules-load.d/stargazer.conf` | Load `af_packet`, `pkt_forward`. |
| `Makefile` | `KERNEL_DIR` → `../stargazer-kernel`; `KERNEL_BRANCH := stargazer/6.12-main`; `MODULE_NAME := pkt_forward`. |

**Stargazer commits (most recent):** `cfe0ec2` (pkt_forward fills the ML
extension) → `17f8ffb` (read-only ML viewer) → `f57c269` (per-flow `policy_id`
re-evaluation + policy/interface session columns) → `190bec3` (dirty live flows
on static-route change).

---

## 4. Data structures

### `struct nf_conn_ml` (kernel)

Defined in `include/net/netfilter/nf_conntrack_ml.h`. Per-flow ML feature vector,
**120 bytes**, with the two-element arrays indexed by direction
`[0]=IP_CT_DIR_ORIGINAL`, `[1]=IP_CT_DIR_REPLY`.

```c
struct nf_conn_ml {
    u64   first_ns;          /* ktime of the first packet (flow start)    */
    u64   last_ns;           /* ktime of the last packet (IAT + duration) */
    u64   iat_sum_ns;        /* sum of inter-arrival gaps, both dirs (ns) */
    u32   iat_count;         /* number of gaps accumulated                */
    u16   tcp_flags[2];      /* OR of TCP flag bits seen, per direction   */
    u16   len_min[2];        /* smallest L3 packet length, per direction  */
    u16   len_max[2];        /* largest  L3 packet length, per direction  */
    s32   ml_score;          /* score written back by the ML daemon       */
    u16   iif;               /* ingress ifindex, original dir (0=unset)   */
    u16   oif;               /* egress  ifindex, original dir (0=unset)   */
    u64   flow_iat_sq_sum;   /* sum of squared inter-arrival gaps (us^2)  */
    ktime_t last_seen_fwd;   /* ktime of the last forward packet (0=none) */
    u64   fwd_iat_sum;       /* sum of forward gaps (us)                  */
    u64   fwd_iat_sq_sum;    /* sum of squared forward gaps (us^2)        */
    u64   pktlen_sum;        /* sum of L3 packet lengths (bytes)          */
    u64   pktlen_sq_sum;     /* sum of squared L3 packet lengths          */
    u32   flow_iat_min;      /* smallest inter-arrival gap (us; U32_MAX)  */
    u32   fwd_iat_count;     /* number of forward gaps accumulated        */
    u32   syn_count;         /* TCP packets seen with SYN set             */
    u32   ack_count;         /* TCP packets seen with ACK set             */
    u32   psh_count;         /* TCP packets seen with PSH set             */
    u32   urg_count;         /* TCP packets seen with URG set             */
};
```

The kernel never computes mean/variance/std (no floating point). It only
accumulates the integer sums, counts, sum-of-squares, and min/max; a consumer
derives the statistics: `mean = sum/count`,
`variance = sq_sum/count - mean^2`, `std = sqrt(variance)`.

| Field | Meaning |
|---|---|
| `first_ns` / `last_ns` | First and most-recent packet `ktime_get_ns()`; duration = `last_ns - first_ns`. |
| `iat_sum_ns` / `iat_count` / `flow_iat_sq_sum` / `flow_iat_min` | Inter-arrival gaps over both directions: sum (ns) and count → mean; sum-of-squares (µs²) → variance/std; minimum (µs, primed `U32_MAX`). Gaps are reduced to µs before squaring so the square fits `u64`. |
| `last_seen_fwd` / `fwd_iat_sum` / `fwd_iat_sq_sum` / `fwd_iat_count` | Same statistics (µs) restricted to the **forward** (original) direction. `last_seen_fwd` is the previous forward packet time used to measure each forward gap. |
| `tcp_flags[2]` | OR of TCP flag bits seen per direction (FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10, URG 0x20) — presence, not frequency. |
| `syn_count` / `ack_count` / `psh_count` / `urg_count` | Per-flag packet counts (frequency), complementing the `tcp_flags` presence bitmaps. |
| `len_min[2]` / `len_max[2]` / `pktlen_sum` / `pktlen_sq_sum` | Packet length: per-direction min/max (`len_min` primed `U16_MAX`); flow-wide sum and sum-of-squares (bytes) → mean/variance/std. |
| `ml_score` | Score written back by the ML daemon. Currently 0 — no daemon writes it yet. |
| `iif` / `oif` | Original-direction ingress/egress `ifindex`, recorded once on the first packet. 0 = unset (a flow that never crossed FORWARD, e.g. traffic to the firewall itself). |

> Packet/byte counts come from the standard conntrack **ACCT** extension;
> `nf_conn_ml` holds only what ACCT/TSTAMP do not (timing statistics, length
> spread, TCP flag presence and counts, interface) plus the ML score.

### Registration as conntrack extension `NF_CT_EXT_ML`

1. **Enum** (`nf_conntrack_extend.h`): `NF_CT_EXT_ML` before `NF_CT_EXT_NUM`.
2. **Length table** (`nf_conntrack_extend.c`):
   `[NF_CT_EXT_ML] = sizeof(struct nf_conn_ml)`, and `total_extension_size()`
   adds it; `BUILD_BUG_ON(NF_CT_EXT_NUM > 11)` keeps the per-conntrack offset
   table in range.
3. **Allocation** (`init_conntrack()`): `nf_ct_ml_ext_add(ct, GFP_ATOMIC)` on the
   not-yet-confirmed conntrack. The helper zero-fills the extension and primes
   the minima (`len_min[0]`/`len_min[1]` to `U16_MAX`, `flow_iat_min` to
   `U32_MAX`); the remaining fields start at 0.

Compiled unconditionally (no `CONFIG` guard) — present on every
conntrack-enabled build.

### Userspace mirror — `struct sg_nf_conn_ml`

`mgmtd_diag.c` defines a byte-compatible mirror so the host-byte-order `CTA_ML`
blob can be copied directly. It must be kept in lockstep with the kernel struct.

```c
struct sg_nf_conn_ml {
    uint64_t first_ns, last_ns, iat_sum_ns;
    uint32_t iat_count;
    uint16_t tcp_flags[2];
    uint16_t len_min[2], len_max[2];
    int32_t  ml_score;
    uint16_t iif, oif;
    uint64_t flow_iat_sq_sum;
    int64_t  last_seen_fwd;   /* kernel ktime_t (s64) */
    uint64_t fwd_iat_sum, fwd_iat_sq_sum;
    uint64_t pktlen_sum, pktlen_sq_sum;
    uint32_t flow_iat_min, fwd_iat_count;
    uint32_t syn_count, ack_count, psh_count, urg_count;
};
```

---

## 5. Workflows

### (a) Packet path & anomaly screen

`forward_hook()` in `pkt_forward.c` runs in order:

1. **IPv4 validation** — `is_valid_ipv4()` checks `version == 4`, `IHL >= 5`;
   `NF_DROP` on failure.
2. **TCP linearity** — for `IPPROTO_TCP`, pull 20 bytes of TCP header; `NF_DROP`
   on failure.
3. **Anomaly screen** — `is_ip_anomaly()`, `is_tcp_anomaly()` (TCP), then
   `is_icmp_anomaly()`. On any hit: `pkts_anomaly_dropped++`, `pkts_dropped++`,
   `NF_DROP`.
4. **ML accounting** — `ml_account(skb, proto, iif, oif)` with the hook's
   `state->in`/`state->out` ifindexes.
5. **Accept** — `pkts_forwarded++`, `NF_ACCEPT`.

| Helper | Patterns dropped |
|---|---|
| `is_ip_anomaly` | Land (`saddr == daddr`); IP source routing (LSRR 131, SSRR 137). |
| `is_tcp_anomaly` | NULL scan (no control bits); XMAS (FIN+URG+PSH); FIN without ACK; SYN carrying data. |
| `is_icmp_anomaly` | Ping of Death (`tot_len > 65500` after reassembly). |

`ml_account()` gets the flow (`nf_ct_get`) and its extension (`nf_conn_ml_find`),
skips untracked packets, resolves `dir = CTINFO2DIR(ctinfo)`, then under
`spin_lock_bh(&ct->lock)`:

- On the **first original-direction** packet (when `iif == 0`), record `iif`/`oif`.
- Set `first_ns` on the first packet, else add the gap to `iat_sum_ns` and bump
  `iat_count`; always update `last_ns`.
- Update `len_min[dir]`/`len_max[dir]`; for TCP, OR the flag bitmap into
  `tcp_flags[dir]`.

### (b) Policy-change re-evaluation — per-flow `policy_id` (DIRTY bit)

When firewall policy changes, live flows are re-evaluated against the rebuilt
FORWARD chain instead of every connection being dropped. Each permitted flow
carries the **policy_id** (a stable per-policy `cmkid`) of the rule that allowed
it; a policy change flags the relevant flows **dirty** so their next packet
re-traverses the chain.

`connmark_supported()` runs a one-time probe (builds a temp chain and tests
`-m connmark --mark 0/0xff -j CONNMARK --set-xmark 0/0xff`), caching the result.
The probe mask is capability-only and never touches live traffic; the actual
fast-path/stamp masks are the `0x1`/`0xFFFFFF01` values above.

**Connmark layout** (`mgmtd_apply_firewall.c`, mirrored in `mgmtd_diag.c`):

```
bit 0      DIRTY                 SG_CMK_DIRTY      0x00000001
bit 1-7    reserved (0)
bit 8-31   policy_id (cmkid)     SG_CMK_PID_SHIFT  8
stamp mask (set pid, clear DIRTY)  SG_CMK_STAMP_MASK 0xFFFFFF01
```

`cmkid` is a monotonic per-policy id (`cmkid_auto_assign()` on create, backfilled
in `mgmtd_reconcile_config`); unlike `sequence` it never changes on reorder, so a
flow's stamp keeps pointing at the same policy. It is an **internal field**:
`struct field_entry` carries an `SG_FLD_HIDDEN` flag so `cmkid` is hidden from
`show`/config export and rejected by CLI `set`/`unset`, while the config engine
still accepts it for the internal write path.

1. **Foundation rules:**
   ```
   -A FORWARD -m conntrack --ctstate INVALID -j DROP
   -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED \
              -m connmark ! --mark 0x1/0x1 -j ACCEPT
   ```
   A flow with DIRTY **clear** takes the fast-path ACCEPT; DIRTY-set and NEW
   flows fall through to the policy rules.
2. **Policy rules** (highest sequence first):
   - **ACCEPT** rules are preceded by `CONNMARK --set-xmark
     0x<cmkid<<8>/0xffffff01` (writes policy_id, clears DIRTY), then `-j ACCEPT`.
   - **DENY/DROP** rules do **not** stamp — a dirty denied flow stays dirty and
     falls to the policy `DROP`.
3. **Dirtying** is a separate step from the chain rebuild:
   `conntrack_reeval_after_policy_change(pid)` →
   `conntrack_mark_dirty_by_policy(pid)` sets the DIRTY bit on live flows over
   in-process NFNETLINK (a CT dump, then masked `CT_NEW` updates). `pid == 0`
   dirties **all** flows; `pid == cmkid` dirties only that policy's flows. The
   scope is chosen per operation, defaulting to 0 on any doubt — under-dirtying
   would fail open:
   - **Narrow** (`pid = cmkid(P)`) — *deleting P*, or an *in-place edit* that
     changes only its action/comment (no selector/sequence/disabled→enabled
     change). Only the flows P already permitted can change verdict, and they
     carry `cmkid(P)`. `policy_reeval_scope()` makes the edit decision by diffing
     old vs new.
   - **Dirty-all** (`pid = 0`) — *creating* a policy, *enabling* a disabled one,
     *reordering*, any *selector edit*, and *address/service cascade* rebuilds.
     These can re-shadow flows owned by **other** policies (different cmkid), so
     a narrow pass would miss them.
   Boot replay does not re-evaluate.
4. **On the next packet of each dirtied flow:**
   - **Still allowed** → matches a rule → re-stamped (policy_id set, DIRTY
     cleared) → fast-path again. The conntrack entry is kept, so the flow
     continues; only a brief reply-direction-only window can blip until the
     original direction re-stamps.
   - **Newly denied** → no ACCEPT rule matches → hits the policy `DROP`.
   - **Management/SSH** is in INPUT, not FORWARD — untouched.

**Fail-safe.** If connmark is unsupported, or `conntrack_mark_dirty_by_policy()`
cannot confirm it marked every flow — a dump without a clean `NLMSG_DONE`, an
allocation failure, or every masked update failing or timing out —
`conntrack_reeval_after_policy_change()` flushes the whole table
(`conntrack_flush_all()`, netlink `CT_DELETE`). A failed re-eval can never leave
a now-denied flow on the clean fast-path.

### (c) Routing-change re-evaluation

A `firewall_policy` can match on `srcintf`/`dstintf`, and a static-route change
can move an established flow to a different egress interface. Because the
fast-path accepts an ESTABLISHED flow without re-checking its interface, a flow
that should now be denied on its new egress would keep being accepted. So
changing or deleting a `network_route_static` entry calls
`conntrack_reeval_after_policy_change(0)` (dirty-all — routing can't be narrowed
by cmkid). The next packet re-traverses FORWARD, where the post-routing egress
interface is matched against the current policies. Boot replay does not dirty.

> NAT changes do **not** dirty: a NAT binding is fixed per-flow once the flow is
> established, and the DIRTY/FORWARD path does not re-run the nat table, so
> dirtying would have no effect. NAT changes apply to new flows only.

### (d) ML feature lifecycle

```
  collect                export                     view
  -------                ------                     ----
  ml_account()  ----->   CTA_ML via         ----->  execute diagnose session ml
  (per packet,           ctnetlink dump             (CLI) -> SG_CMD_SESSION_ML
   fills nf_conn_ml)     (ctnetlink_dump_ml)         |
                                                     v
                                          mgmtd handle_session_ml:
                                          in-process netlink CT_GET + NLM_F_DUMP,
                                          parses each msg's CTA_ML blob
```

- **Collect:** `ml_account()` fills `nf_conn_ml` per packet (5a).
- **Export:** `ctnetlink_dump_ml()` does `nla_put(skb, CTA_ML, sizeof(*ml), ml)`
  — the whole 48-byte struct as a host-order blob — on the **dump path only**,
  so `CONFIG_NF_CONNTRACK_EVENTS` is **not** required.
- **View:** `handle_session_ml()` opens an in-process `AF_NETLINK` socket, sends
  `IPCTNL_MSG_CT_GET | NLM_F_DUMP` (family `AF_INET`), reads to `NLMSG_DONE`, and
  `ct_ml_emit()` parses each message's `CTA_ML` into one line:
  ```
  proto=<u> src=<ip>:<u> dst=<ip>:<u> iat_avg_us=<llu> flow_iat_min=<llu> \
    flow_iat_sq_sum=<llu> dur_ms=<llu> fwd_iat_count=<u> fwd_iat_sum=<llu> \
    fwd_iat_sq_sum=<llu> len_o=<u>-<u> len_r=<u>-<u> pktlen_sum=<llu> \
    pktlen_sq_sum=<llu> flags_o=0x<x> flags_r=0x<x> \
    syn=<u> ack=<u> psh=<u> urg=<u> score=<d>
  ```

---

## 6. Session visibility — policy name & interfaces

The session table annotates each conntrack flow with its owning policy name and
its in/out interfaces. `handle_show_sessions()` builds two maps once per listing
and overlays them onto the `/proc/net/nf_conntrack` rows:

- **Policy name.** The connmark is already in `/proc`. `ct_emit_line()` derives
  `cmkid = mark >> 8` and `ct_policy_map_build()` resolves `cmkid → policy name`
  (the friendly `name`, else the DB id). Unstamped or stale → `-`.
- **In/out interface.** conntrack does not track interfaces, so they come from
  the ML extension. `ct_iface_map_build()` dumps conntrack over ctnetlink, reads
  `iif`/`oif` from each flow's `CTA_ML`, and keys them by the original 5-tuple
  (matching the `/proc` row). `if_indextoname()` turns the ifindex into a name.
  Flows that never crossed FORWARD (local/INPUT) carry no interface → `-`.

Normalized line from `ct_emit_line()`:
```
proto=<p> state=<S> src=<ip>:<port> dst=<ip>:<port> pkts=<n> bytes=<n> policy=<name> iif=<if> oif=<if>
```

A connection to the firewall itself (INPUT, e.g. the web UI) shows `policy=-` and
`iif=-`/`oif=-` — it is not governed by a FORWARD policy and crossed no forward
interface; only transit traffic carries them.

---

## 7. CLI & Web

### CLI commands

| Command | IPC | Output |
|---|---|---|
| `show sessions` | `SG_CMD_SHOW_SESSIONS` | `active=N` header + key=value rows (proto/state/src/dst/pkts/bytes/policy/iif/oif). |
| `execute diagnose session [status]` | `SG_CMD_SHOW_SESSIONS` | "=== Active Connections (conntrack) ===" + rows. |
| `execute diagnose session stats` | `SG_CMD_SESSION_STATS` | `conntrack_available`, `pkt_forward_loaded`, `active`, `forwarded`, `dropped`, `anomaly_dropped`. |
| `execute diagnose session clear` | `SG_CMD_SESSION_CLEAR` | Y/N confirm → "Flushed N session(s)". |
| `execute diagnose session ml` | `SG_CMD_SESSION_ML` | "=== Per-flow ML Features ===" + `CTA_ML` lines. |

### Web `/monitor/sessions` (GET)

`flow_monitor_sessions()` (webd) calls `SG_CMD_SHOW_SESSIONS`, parses the text,
and returns:

```json
{
  "active": 1,
  "loaded": true,
  "sessions": [
    { "proto": "tcp", "state": "ESTABLISHED",
      "src": "192.168.1.100:54321", "dst": "8.8.8.8:443",
      "pkts": "45", "bytes": "98765",
      "policy": "allow-lan-out", "iif": "lan", "oif": "wan1" }
  ]
}
```

If conntrack is unavailable: `{"active":0,"loaded":false,"sessions":[]}`.

**Web UI** (`page-fw-sessions`): columns PROTO, SOURCE, DESTINATION, STATE
(colored dot), POLICY, IN, OUT, PACKETS, BYTES (`formatBytes()`); search
(debounced), protocol/state dropdowns, clear-filters; pagination 10/25/50
(default 25); summary "Active: N". The dashboard **session gauge**
(`gauge-sessions`) reads `/system/resources` (`sessions` / `sessions_max`),
polled every 5 s and paused when the tab is hidden.

---

## 8. IPC commands

| ID | `SG_CMD_*` | Handler | Source | Perm | Purpose |
|---|---|---|---|---|---|
| 650 | `SG_CMD_SHOW_SESSIONS` | `handle_show_sessions` | `/proc/net/nf_conntrack` + ctnetlink `CTA_ML` (iif/oif overlay) | monitor | Normalized flow lines with policy + interfaces. |
| 655 | `SG_CMD_SESSION_CLEAR` | `handle_session_clear` | netlink `CT_DELETE` (`conntrack_flush_all`) | admin | Flush the whole conntrack table in-process. |
| 656 | `SG_CMD_SESSION_STATS` | `handle_session_stats` | `/proc/net/nf_conntrack` count + `/proc/stargazer/pkt_forward_stats` | monitor | Active flow count + pkt_forward counters. |
| 659 | `SG_CMD_SESSION_ML` | `handle_session_ml` | netlink `CT_GET \| NLM_F_DUMP`, parse `CTA_ML` | monitor | Per-flow ML feature blobs. |

All handlers check permission first, read state via procfs or in-process netlink
(never fork), buffer through `struct dynbuf`, and respond within
`SG_RESPONSE_MAX` (65536 bytes).

---

## 9. Build & kernel config

- **Separate kernel repo:** `../stargazer-kernel`, branch `stargazer/6.12-main`,
  base Linux 6.12.69; the root `Makefile` sets `KERNEL_DIR`.
- **Module target:** `MODULE_NAME := pkt_forward`; `pkt_forward.ko` declares
  `MODULE_SOFTDEP("pre: nf_defrag_ipv4")`.
- **`/etc/modules-load.d/stargazer.conf`:** `af_packet`, `pkt_forward`.

**Conntrack sysctls** (`/etc/sysctl.d/10-stargazer.conf`):

```
net.netfilter.nf_conntrack_max       = 131072   # max tracked flows
net.netfilter.nf_conntrack_acct      = 1        # per-flow pkts/bytes (ct_emit_line)
net.netfilter.nf_conntrack_timestamp = 1        # flow timestamps
```

**Kernel `.config` facts:**

| Symbol | State | Note |
|---|---|---|
| `CONFIG_NF_CONNTRACK` | `y` | Core requirement. |
| `CONFIG_NF_CT_NETLINK` | `y` | Required for `CTA_ML` export and netlink flush/dump. |
| `CONFIG_NF_CONNTRACK_MARK` | `y` | connmark — required by the `policy_id` DIRTY-bit re-eval. |
| `CONFIG_NF_CONNTRACK_EVENTS` | **off** | Not needed; ML export is dump-only. |
| `CONFIG_IP_SET` | **off** | → ipset-based blocking deferred. |
| `CONFIG_NETFILTER_SYNPROXY` (and the `IP_NF_TARGET_SYNPROXY` / `IP6_NF_TARGET_SYNPROXY` / `NFT_SYNPROXY` targets that select it) | **off** | Frees its conntrack extension slot for `NF_CT_EXT_ML`. Unused (no SYNPROXY rules). |
| `CONFIG_NET_ACT_CT` | **off** | Frees its conntrack extension slot. Unused (tc act_ct; the firewall uses iptables). |

> **Conntrack extension budget.** `struct nf_ct_ext` stores each extension's
> offset in a `u8`, so the **sum of all enabled conntrack extensions must be
> ≤ 255 bytes** (`BUILD_BUG_ON(total_extension_size() > 255)`). `nf_conn_ml` is
> 120 bytes; with NAT/help/seqadj/acct also present, SYNPROXY and NET_ACT_CT are
> disabled above to keep the total under the limit. Re-enabling either while
> `nf_conn_ml` is this large fails the build — shrink the struct or free another
> extension first.
>
> The kernel `struct nf_conn_ml` and the userspace `struct sg_nf_conn_ml` must
> stay byte-compatible. Any change to the struct requires rebuilding the kernel,
> `pkt_forward.ko`, and mgmtd together, then reflashing.

---

## 10. Status & deferred work

**Done:**

- Connection state + NAT on `nf_conntrack`.
- `pkt_forward.ko` stateless anomaly screen + ML feature accounting (timing,
  length spread, TCP flags, interfaces).
- ML feature **collect** → **export** (`CTA_ML`) → **view**
  (`execute diagnose session ml`).
- Per-flow `policy_id` re-evaluation (narrow / dirty-all) with the fail-safe
  flush fallback; routing-change re-evaluation.
- Session visibility: policy name + in/out interfaces, in the CLI and the web
  monitor.

**Deferred (until a model exists):**

- **ipset-based active blocking** — `CONFIG_IP_SET` is off; no blocking on
  `ml_score` yet.
- **ML scoring daemon** — nothing writes `nf_conn_ml.ml_score`; the field is
  exported and ready, but scoring/feedback is future work.
