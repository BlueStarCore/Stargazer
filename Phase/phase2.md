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
| Session table | `src/modules/session.c` | RCU hash table, reaper, procfs |
| Public API | `src/modules/session.h` | Structs and exported symbols |
| Packet hook | `src/modules/pkt_forward.c` | Calls session API on every FORWARD packet |
| Kernel self-test | `src/modules/session_test.c` | Tests API without a network stack |
| mgmtd handlers | `src/userspace/mgmtd/mgmtd_diag.c` | IPC for status, stats, clear, inject test |
| CLI commands | `src/userspace/cli/cli_cmd_table.c` | `execute diagnose session *` |
| Selftest suite | `src/userspace/cli/cli_diagnose_session.c` | SESS-01..12 |

---

## How a packet flows through Phase 2

```
NIC → kernel → NF_INET_FORWARD hook (pkt_forward.ko)
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
              ├── TCP → NF_DROP (pkts_dropped++)
              └── non-TCP → NF_ACCEPT untracked (UDP/ICMP ok without session)
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

### Hash table

- 1024 buckets (`SESSION_TABLE_BITS = 10`), max 65536 sessions.
- Hash seed randomized with `get_random_bytes()` at module load — prevents
  hash-bucket collision (DoS) attacks.
- Readers use `rcu_read_lock()` — no contention on the read path.
- Writers take `table_lock` (spinlock) to insert or delete.
- The create path re-checks both directions under `table_lock` to resolve the
  race where two CPUs both miss the lockless lookup.

### Direction model

The first packet that creates a session defines the **original** (`SESS_DIR_ORIG`)
direction. Subsequent packets matching the reversed 5-tuple are the **reply**
(`SESS_DIR_REPLY`) direction. This is identical to Linux conntrack and FortiOS.

`sess_lookup_or_create()` tries the key as-is (ORIG), then reversed (REPLY),
then creates. `sess_lookup_bidir()` does the same but never creates — used for
non-SYN TCP so mid-stream injected packets have no session to match.

### Expiry and reaper

Sessions have a `expires_at` timestamp. A delayed work (`sess_reaper`) runs
every 30 seconds under `table_lock`, removes expired entries, and schedules
itself again. Freed sessions go through `call_rcu()` so readers holding
`rcu_read_lock()` always see a valid pointer.

Non-TCP timeouts are fixed: UDP 180s, ICMP 60s, other 300s.
TCP timeouts are per-state:

| State | Timeout |
|---|---|
| NONE / SYN_SENT | 120s |
| SYN_RECV | 60s |
| ESTABLISHED | 3600s |
| FIN_WAIT | 120s |
| CLOSE_WAIT | 60s |
| LAST_ACK | 30s |
| TIME_WAIT | 120s |
| CLOSE | 10s |

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
# Stargazer sessions  active=3 created=1024 expired=1021 invalid=2
# proto src dst id pkts(o/r) bytes(o/r) age_ms expire_ms ml flags tcp_state
proto=6 src=192.168.1.10:54321 dst=8.8.8.8:443 id=42 pkts=7/5 bytes=840/3200 age_ms=1200 expire_ms=2800 ml=0 flags=0x1 dev=2/3 tcp_state=3
```

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
- `fwd` — packets accepted and forwarded (includes untracked non-TCP).
- `drop` — packets dropped: invalid IP, malformed TCP, non-SYN without session,
  table full (TCP), TCP state machine rejections (RST injection, SYN into ESTABLISHED).
- `block` — packets dropped because `SESS_BLOCKED` was set by policy/ML.

### session.ko (procfs header)
```
active=N created=N expired=N invalid=N
```
- `active` — sessions currently in the table.
- `created` — total sessions ever created.
- `expired` — sessions removed by the reaper.
- `invalid` — TCP state machine drops (RST injection + SYN injection).

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
