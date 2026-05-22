# Phase 2 — Stateful Session Tracking

## Goal

Wire a stateful session table into the packet forwarding path so that every
IPv4 packet traversing the router is associated with a tracked session. The
session carries per-flow statistics (packet counts, byte counts, inter-arrival
times, TCP flags) that feed Phase 3's ML scoring engine, and enforces a
`SESS_BLOCKED` flag that lets policy or ML drop a flow without touching
iptables rules.

The design follows FortiOS behavior: stateful enforcement is done in the kernel
on every packet, not in userspace rules. Non-SYN TCP drops and RST sequence
validation are hardcoded, not configurable.

---

## Components

| Component | File | Role |
|---|---|---|
| Session table | `src/modules/session.c` | RCU hash table, LRU list, single 1 Hz GC reaper, PF adaptive eviction, procfs |
| Public API | `src/modules/session.h` | Structs and exported symbols |
| Packet hook | `src/modules/pkt_forward.c` | Calls session API on every FORWARD packet |
| Kernel self-test | `src/modules/session_test.c` | Tests API without a network stack |
| mgmtd handlers | `src/userspace/mgmtd/mgmtd_diag.c` | IPC for status, stats, clear, inject test |
| CLI commands | `src/userspace/cli/cli_cmd_table.c` | `execute diagnose session *` |
| Selftest suite | `src/userspace/cli/cli_diagnose_session.c` | SESS-01..12 |

---

## How a packet flows through Phase 2

IPv4 fragments are reassembled by `nf_defrag_ipv4` at `NF_INET_PRE_ROUTING`
(priority -400) before the FORWARD hook fires.  `pkt_forward.ko` depends on
this via `MODULE_SOFTDEP("pre: nf_defrag_ipv4")` and enables it explicitly
with `nf_defrag_ipv4_enable(&init_net)` at module load.

```
NIC → kernel → NF_INET_PRE_ROUTING
                      │
                      ▼
              nf_defrag_ipv4           reassemble fragments (priority -400)
                      │ complete packet
                      ▼
              NF_INET_FORWARD hook (pkt_forward.ko, priority -399)
                      │
                      ▼
              is_valid_ipv4()          invalid IP header → NF_DROP (pkts_dropped++)
                      │ ok
                      ▼
              extract_key()            malformed L4 header → NF_DROP (pkts_dropped++, pr_warn_ratelimited)
                      │ ok
                      ▼
              tcp_is_syn = tcph->syn   (safe: extract_key pulled TCP header)
                      │
                      ▼
          ┌───────────────────────────┐
          │ TCP && !syn               │ TCP && syn (or non-TCP)
          │ sess_lookup_bidir()       │ sess_lookup_or_create()
          │ (never creates)           │
          └───────────────────────────┘
                      │
                      ▼
              s == NULL?
              └── ALL protocols → NF_DROP (pkts_dropped++)
                  (TCP non-SYN: no matching flow; all others: table full or OOM)
                      │
                      ▼ s != NULL
              record ifindex_in/out on first packet (WRITE_ONCE, set-once)
                      │
                      ▼
              s->flags & SESS_BLOCKED? → NF_DROP (pkts_blocked++)
                      │ not blocked
                      ▼
              TCP: sess_tcp_check(s, skb, dir)
              ├── NF_DROP (RST injection / SYN into ESTABLISHED) → pkts_dropped++
              └── NF_ACCEPT → continue
                      │
                      ▼
              sess_update(s, skb, dir)   update stats, IAT, TCP flags
                      │
                      ▼
              NF_ACCEPT (pkts_forwarded++)
```

---

## Session table

### Data structure

```c
struct sess_key {           /* 5-tuple, packed (no padding) */
    __be32 src_ip, dst_ip;
    __be16 src_port, dst_port;
    u8     proto;
} __packed;

struct session {
    struct hlist_node   node;       /* RCU hash table linkage */
    struct list_head    lru_node;   /* LRU list: head=oldest, tail=newest */
    struct sess_key     key;        /* stored in ORIG direction */
    u32                 id;
    u16                 flags;      /* SESS_ACTIVE | SESS_BLOCKED | SESS_MARKED */
    u8                  tcp_state;  /* SESS_TCP_* state machine */
    struct sess_tcp_win tcp_win[2]; /* per-direction RST validation state */
    u32                 ifindex_in, ifindex_out;
    struct sess_stats   stats;      /* pkts, bytes, IAT, TCP flags per direction */
    s32                 ml_score;   /* fixed-point × 1000, written by ML daemon */
    ktime_t             expires_at;
    spinlock_t          lock;
    struct rcu_head     rcu;
};
```

`lru_node` is new in Phase 2. Every session is simultaneously a member of the
RCU hash table (via `node`) and the LRU doubly-linked list (via `lru_node`).
The LRU list head is the oldest session; the tail is the most-recently-used.
`sess_update()` calls `list_move_tail()` on every forwarded packet to maintain
this ordering.

### Hash table

- 1024 buckets (`SESSION_TABLE_BITS = 10`), hard cap `pf_max_states` (default
  65536, tunable via module parameter).
- Hash seed randomized with `get_random_bytes()` at module load — prevents
  hash-bucket collision (DoS) attacks.
- Readers use `rcu_read_lock()` — no contention on the read path.
- Writers take `table_lock` (spinlock) to insert or delete.
- The create path re-checks both directions under `table_lock` to resolve the
  race where two CPUs both miss the lockless lookup.

### Locking model

Two spinlocks protect the session data structures:

| Lock | Protects | Acquired from |
|---|---|---|
| `table_lock` | Hash table (`hash_add_rcu`, `hash_del_rcu`) and LRU list mutations | Any path that inserts or removes sessions |
| `lru_lock` | `sess_lru` list pointer writes | `sess_update()` (alone); all other callers hold `table_lock` first |

**Lock ordering rule:** always acquire `table_lock` before `lru_lock`.
`lru_lock` may be taken alone only in `sess_update()`, which touches the LRU
tail on every forwarded packet without touching the hash table. Keeping the two
locks separate means the high-frequency packet path (`sess_update`) never blocks
on the GC's incremental bucket scan, and vice versa.

The per-session `s->lock` (spinlock) guards mutable session fields
(`tcp_state`, `expires_at`, stats) and is taken independently of both global
locks.

### Direction model

The first packet that creates a session defines the **original** (`SESS_DIR_ORIG`)
direction. Subsequent packets matching the reversed 5-tuple are the **reply**
(`SESS_DIR_REPLY`) direction. This is identical to Linux conntrack and FortiOS.

`sess_lookup_or_create()` tries the key as-is (ORIG), then reversed (REPLY),
then creates. `sess_lookup_bidir()` does the same but never creates — used for
non-SYN TCP so mid-stream injected packets have no session to match.

---

## Expiry and GC

### Single 1 Hz reaper (`sess_reaper_fn`)

One `DECLARE_DELAYED_WORK` item, `sess_reaper`, always rescheduled at exactly
`HZ` (one second). The tick interval is never shortened under load. All
load-adaptive behavior happens inside the tick itself via three interlocking
techniques.

**Why a fixed 1 Hz tick?**  On Cortex-A53 each context switch costs ~10–50 µs.
Shortening the GC interval under a SYN flood (e.g., 10 Hz) would add 10 extra
wakeups/s × 50 µs = 500 µs of pure scheduler overhead per second, plus
cache-thrash between the GC and RX-softirq stacks. Keeping it at 1 Hz
eliminates all of this; the inline emergency path (Weapon 2) absorbs any excess
within the fixed cadence.

#### Weapon 1a — Adaptive timeout scaling (`sess_pf_timeout`)

Implements the FreeBSD `pf(4)` formula:

```
factor = (adaptive_end - active_cnt) / (adaptive_end - adaptive_start)
effective_timeout = base_timeout * factor
```

Behavior across the three zones:

| Zone | Condition | Effect |
|---|---|---|
| Normal | `active_cnt <= pf_adaptive_start` | `factor = 1.0` — full base TTL, no scaling |
| Pressure | `active_cnt` in `(start, end)` | `factor` ∈ `(0, 1)` — TTL shrinks linearly |
| Saturation | `active_cnt >= pf_adaptive_end` | `factor = 0` — TTL crushed to 0; immediate eviction candidate |

**TCP ESTABLISHED is excluded from scaling.** Killing live connections during a
SYN flood harms legitimate users. The attack surface is half-open states:
`SYN_SENT` (120 s base) and `SYN_RECV` (60 s base) collapse to zero first, well
before `ESTABLISHED` (3600 s base) would be affected.

All arithmetic is integer-only — no floats (kernel constraint).

#### Weapon 1b — Incremental scanning (gc_idx cursor)

The GC does not scan all 1024 buckets per tick. Instead it advances a cursor
`gc_idx` by a fixed window:

| Mode | Buckets per tick | Full-table coverage |
|---|---|---|
| Normal (below `pf_adaptive_start`) | `GC_SCAN_NORMAL = 64` | ~16 s |
| Aggressive (at or above `pf_adaptive_start`) | `GC_SCAN_AGGRESSIVE = 256` | ~4 s |

This bounds `table_lock` hold time to ~25 µs (normal) or ~100 µs (aggressive)
per tick, preventing head-of-line blocking for new-session creation on other
CPUs even at 90% table fill.

#### Weapon 1c — Hysteresis (`gc_aggressive` latch)

`gc_aggressive` is set `true` when `active >= pf_adaptive_start` and cleared
only when `active < 85% of pf_adaptive_start`. The 15% band prevents mode
oscillation when the table drains and refills near the boundary — alternating
between 64 and 256 buckets/tick on consecutive seconds without actually draining.

#### Phase 1 — Incremental hash bucket scan

Within the scan window `[gc_idx, gc_idx + scan_size)`, every session in every
bucket is tested with `sess_pf_timeout()`. If the effective timeout is 0, or if
idle time since `last_seen` exceeds the effective timeout, the session is
unlinked from both the hash table and the LRU list, decremented from
`sess_active`, incremented in `sess_expired`, and queued for RCU-deferred free.
GenL notifications (`SG_FLOW_CMD_SESS_EXPIRED`) are sent outside the spinlock.

#### Phase 2 — LRU-head early eviction (aggressive mode only)

In addition to the bucket scan, when `gc_aggressive` is true the reaper walks
from the LRU list head (oldest sessions) and evicts up to `GC_LRU_EVICT_MAX = 32`
sessions per tick that satisfy the same `sess_pf_timeout()` condition. This
drains the attack surface in temporal order (LRU, oldest first) in parallel with
the spatial-order bucket scan, allowing the GC to wipe thousands of half-open
SYN states in a single pass under a flood.

### Inline expiry in `sess_lookup` — Technique 3

On every hash chain hit, `sess_lookup()` checks `ktime_get() >= s->expires_at`
before returning the session. If expired, it acquires `table_lock`, re-checks
under the lock (another CPU may have refreshed the TTL), and if still expired:
unlinks from hash and LRU, decrements `sess_active`, increments `sess_expired`,
calls `call_rcu()`, and returns `NULL`. This prevents dead sessions accumulating
in hot chains between 1 Hz GC ticks, keeping lookup O(1) in common cases.

### Weapon 2 — Inline emergency eviction (`pf_purge_expired_states_emergency`)

When `sess_lookup_or_create()` detects `active_cnt >= pf_max_states`, it calls
`pf_purge_expired_states_emergency()` synchronously in the packet (softirq)
context before attempting allocation.

The function walks from the LRU list head and scans up to
`PF_EMERGENCY_SCAN_MAX = 64` entries, evicting any session where
`sess_pf_timeout() == 0` OR `idle_ns >= effective_timeout * NSEC_PER_SEC`.
Weapon 1 (TTL scaling) pre-crushes TTLs as the table fills, so the LRU head is
the most likely location to find zero-TTL entries.

**Does NOT send genl notifications** — avoids `skb` allocation in the DDoS hot
path.

Two outcomes:

- `freed > 0` — at least one slot was reclaimed; allocation proceeds normally.
- `freed == 0` — table is saturated with non-expired active sessions. The caller
  increments `sess_pf_drops` and returns `NULL`, causing `pkt_forward.ko` to
  return `NF_DROP`. The packet is discarded at the NIC driver layer without
  allocating any kernel state.

**Why inline and not a wakeup?** Context switches cost 10–50 µs on Cortex-A53.
Under a 1 Mpps SYN flood, waking a GC thread per packet would burn 10–50
CPU-seconds per second in scheduler overhead alone. Running inline in the same
softirq costs only the bounded scan time (~640 ns for 64 entries) — no context
switch, no cache thrash between stacks.

### Non-TCP timeouts

Non-TCP session idle timeouts are fixed:

| Protocol | Timeout |
|---|---|
| UDP | 180 s |
| ICMP | 60 s |
| Other | 300 s |

### TCP per-state timeouts

| State | Timeout |
|---|---|
| NONE / SYN_SENT | 120 s |
| SYN_RECV | 60 s |
| ESTABLISHED | 3600 s |
| FIN_WAIT | 120 s |
| CLOSE_WAIT | 60 s |
| LAST_ACK | 30 s |
| TIME_WAIT | 120 s |
| CLOSE | 10 s |
| SYN_SENT2 | 60 s |

---

## Module parameters

Tunable at load time via `modprobe session param=value`:

| Parameter | Type | Permissions | Default | Description |
|---|---|---|---|---|
| `pf_max_states` | `uint` | 0444 | 65536 (`MAX_SESSIONS`) | Hard session cap. No new sessions are created at or above this count. |
| `pf_adaptive_start` | `uint` | 0644 | 75% of `pf_max_states` | Active count at which TTL scaling begins. |
| `pf_adaptive_end` | `uint` | 0644 | 90% of `pf_max_states` | Active count at which TTL is crushed to 0. |
| `sess_asymmetric_mode` | `bool` | 0644 | `N` | Allow mid-stream TCP pickup (see below). |

Zero values for `pf_adaptive_start` and `pf_adaptive_end` at load time are
resolved in `session_init()` to 75% and 90% of `pf_max_states` respectively,
so the ratios hold for any table size.

Example override:

```
modprobe session pf_max_states=100000 pf_adaptive_start=60000 pf_adaptive_end=90000
```

If the supplied thresholds are inconsistent (`start >= end` or `end > max`), the
module logs a warning and falls back to the default percentages.

---

## TCP state machine (`sess_tcp_check`)

Called from `forward_hook` **before** `sess_update`, under `rcu_read_lock()`.
Takes `s->lock` (spinlock) internally.

```
NONE ──SYN(orig)──► SYN_SENT ──SYN+ACK(reply)──► SYN_RECV ──ACK(orig)──► ESTABLISHED
                                                                                │
                                              FIN(orig) ──────────────────► FIN_WAIT ──FIN(reply)──► TIME_WAIT
                                              FIN(reply) ─────────────────► CLOSE_WAIT ──FIN(orig)──► LAST_ACK ──ACK(reply)──► CLOSE
                                              RST (any state, valid seq) ──────────────────────────────────────────────────► CLOSE
```

### Enforced rules (hardcoded, not configurable)

**Non-SYN TCP without session** — `sess_lookup_bidir()` returns NULL → `NF_DROP`.
Prevents accepting mid-stream packets that arrive after a reboot or are injected
by an attacker.

**SYN injection into ESTABLISHED** — a SYN arriving on a session in state
`SESS_TCP_ESTABLISHED` is `NF_DROP`. An attacker cannot reset an established
connection by injecting a SYN.

**RST sequence validation** — a RST is only accepted if its sequence number
falls within the peer's receive window:

```
peer_win_scaled = peer_win << peer_scale    (RFC 7323 window scaling)
valid if: (seq - peer_ack) < peer_win_scaled
```

An out-of-window RST → `NF_DROP` and `pkts_invalid++`. This blocks RST
injection attacks where the attacker sends RSTs with arbitrary sequence numbers
to tear down connections.

**Window scale parsing** — `tcp_parse_wscale()` walks TCP options on SYN and
SYN-ACK to extract the scale factor (RFC 7323). Stored per-direction in
`tcp_win[dir].scale`. Valid range 0–14 per RFC.

---

## Session statistics (`sess_stats`)

Updated by `sess_update()` on every accepted packet, split by direction:

```c
struct sess_stats {
    u64     pkts_orig,  pkts_reply;
    u64     bytes_orig, bytes_reply;
    ktime_t first_seen, last_seen;
    u64     iat_sum_ns;     /* sum of inter-arrival times */
    u32     iat_count;
    u16     tcp_flags_orig, tcp_flags_reply;  /* OR of all flags seen */
    u32     init_win_orig;                    /* initial window size */
    struct sess_pkt_len len_orig, len_reply;  /* min/max packet lengths */
};
```

These fields are designed as ML features for Phase 3. `iat_sum_ns / iat_count`
gives mean inter-arrival time. `tcp_flags_orig` catches Xmas/NULL scans. `len_*`
min/max captures payload size distribution.

---

## procfs visibility

`/proc/stargazer/sessions` — seq_file, readable by mgmtd (monitor permission):

```
# Stargazer sessions  active=3 created=1024 expired=1021 invalid=2 pf_drops=0
# pf_max=65536 adaptive_start=49152 adaptive_end=58982 gc_aggressive=0
# proto src dst id pkts(o/r) bytes(o/r) age_ms expire_ms ml flags tcp_state
proto=6 src=192.168.1.10:54321 dst=8.8.8.8:443 id=42 pkts=7/5 bytes=840/3200 age_ms=1200 expire_ms=2800 ml=0 flags=0x1 dev=2/3 tcp_state=3
```

The header is two lines. Line 1 contains the per-session counters. Line 2
contains the current PF tunable values and GC mode.

`/proc/stargazer/session_ctl` — write-only (mode 0200). Writing `flush` calls
`sess_flush_all()` which removes all sessions from the table. Used by
`execute diagnose session clear`.

---

## IPC commands (CLI → mgmtd → kernel)

| ID | Command | Permission | Action |
|---|---|---|---|
| 650 | `SG_CMD_SHOW_SESSIONS` | monitor | Read `/proc/stargazer/sessions` raw |
| 654 | `SG_CMD_DIAG_SESSION` | monitor | Status (no payload) or inject test (payload=`inject`) |
| 655 | `SG_CMD_SESSION_CLEAR` | admin | Read active count, write `flush` to session_ctl |
| 656 | `SG_CMD_SESSION_STATS` | monitor | Parse procfs header + check `/sys/module/pkt_forward` |

---

## CLI commands

```
show sessions                              — live session table (monitor)

execute diagnose session status            — same as show sessions, with module check
execute diagnose session stats             — counters + session.ko/pkt_forward.ko loaded?
execute diagnose session clear             — flush all sessions (admin, confirmation required)

execute diagnose selftest session          — run SESS-01..07 (basic) + SESS-08..12 (full)
execute diagnose selftest session full     — alias for full mode
```

### Selftest: what each test checks

| ID | Mode | What it checks |
|---|---|---|
| SESS-01 | basic | `session.ko` loaded (`SESSION_STATS` IPC returns `session_loaded=1`) |
| SESS-02 | basic | `pkt_forward.ko` loaded (`/sys/module/pkt_forward` exists) |
| SESS-03 | basic | procfs header has `active=` field |
| SESS-04 | basic | procfs header has `created=` field |
| SESS-05 | basic | procfs header has `expired=` field |
| SESS-06 | basic | procfs header has `invalid=` field |
| SESS-07 | basic | procfs column header line `# proto src dst …` present |
| SESS-08 | full | `session_test.ko` loaded and ran without error |
| SESS-09 | full | `sessions_created=1` in session_test procfs output |
| SESS-10 | full | `pkts_orig=1` (orig direction tracked) |
| SESS-11 | full | `bytes_orig=32` (byte accounting correct) |
| SESS-12 | full | `bidirectional=1` (reply direction matched) |

---

## session_test.ko

A loadable kernel module that calls the session API directly without sending
real packets. On `module_init()` it:

1. Builds a synthetic `struct sess_key` (UDP 10.0.0.1:1000 → 10.0.0.2:2000).
2. Calls `sess_lookup_or_create()` — creates the session.
3. Calls `sess_update()` with a fake 32-byte packet in ORIG direction.
4. Reverses the key and calls `sess_lookup_or_create()` — must find the same
   session in REPLY direction (bidirectional lookup).
5. Calls `sess_update()` in REPLY direction.
6. Calls `sess_delete()`.
7. Writes results to `/proc/stargazer/session_test`:

```
sessions_created=1
pkts_orig=1
pkts_reply=1
bytes_orig=32
bidirectional=1
```

mgmtd loads the module (`insmod`), waits 50ms, reads the procfs file, and
unloads (`rmmod`). This happens for every `execute diagnose selftest session`
run in full mode.

---

## Module counters

### pkt_forward.ko (exit log)
```
pkt_forward: unloaded (fwd=N drop=N block=N)
```
- `fwd` — packets accepted and forwarded (all tracked; no untracked path exists).
- `drop` — packets dropped: invalid IP, malformed TCP, non-SYN without session,
  table full (TCP), TCP state machine rejections (RST injection, SYN into ESTABLISHED).
- `block` — packets dropped because `SESS_BLOCKED` was set by policy/ML.

### session.ko (procfs header)
```
active=N created=N expired=N invalid=N pf_drops=N
```
- `active` — sessions currently in the table.
- `created` — total sessions ever created.
- `expired` — sessions removed by the GC reaper or inline expiry.
- `invalid` — TCP state machine drops (RST injection + SYN injection).
- `pf_drops` — sessions dropped because the table was full and no expired
  sessions could be reclaimed (PF_DROP path). A non-zero and rising value
  under sustained load indicates the table is saturated with active (non-expired)
  sessions; consider raising `pf_max_states` or lowering `pf_adaptive_start`.

---

## Asymmetric routing mode

Enabled via module parameter (default off):

```
modprobe session sess_asymmetric_mode=1
# or at runtime:
echo 1 > /sys/module/session/parameters/sess_asymmetric_mode
```

When on, two behaviors change:

1. Non-SYN TCP with no existing session is allowed to create one (pickup), instead of being dropped. `pkt_forward.ko` calls `sess_lookup_or_create()` as a fallback after `sess_lookup_bidir()` returns NULL.

2. Data arriving on a half-open session (state NONE or SYN_SENT) promotes it directly to ESTABLISHED instead of staying half-open. This handles HA failover where the SYN+ACK took a different path.

Keep this off unless the network topology requires it — it weakens stateful enforcement.

## ICMP error → parent session mapping

ICMP type 3 (Destination Unreachable), 11 (Time Exceeded), and 12 (Parameter Problem) embed the original IP+L4 header that caused the error. `sess_icmp_error_lookup()` in `session.c`:

1. Pulls and checks the ICMP type.
2. Pulls the embedded IP header + first 8 bytes of embedded L4.
3. Builds a `sess_key` from the embedded 5-tuple.
4. Calls `sess_lookup_bidir()` — the embedded header is in ORIG direction, but `bidir` handles both.

In `forward_hook`, ICMP packets try `sess_icmp_error_lookup()` first. If the parent TCP/UDP session is found, the ICMP error packet uses that session for the `SESS_BLOCKED` check and `sess_update()` (bytes counted in the parent flow's stats). If no parent session exists (e.g., the original flow expired), a new ICMP-keyed session is created normally.

## Simultaneous TCP open (RFC 793 §3.4)

Tracked via the `SESS_TCP_SYN_SENT2` state (value 9):

```
NONE ──SYN(orig)──► SYN_SENT ──SYN(reply, no ACK)──► SYN_SENT2
                                                            │
                                              SYN+ACK(either side)
                                                            │
                                                       SYN_RECV ──ACK──► ESTABLISHED
```

When a SYN arrives from the reply direction while in `SYN_SENT`, the session moves to `SYN_SENT2` (60s timeout) instead of being silently ignored. The first SYN+ACK from either direction then transitions to `SYN_RECV`, and the normal final ACK → ESTABLISHED path follows.

## Known limitations (deferred to Phase 3+)

- **NAT blindness** — the session key is the pre-NAT 5-tuple. Reply packets from a NAT'd connection arrive with the translated addresses and will not match the original session key. Requires adding `nat_key` to the session struct and NAT-awareness in `extract_key()`.
