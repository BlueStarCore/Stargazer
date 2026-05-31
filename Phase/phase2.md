# Phase 2 — Stateful Session Tracking

> ⚠️ **TRẠNG THÁI (đang tái kiến trúc):** Tính năng **DoS policy đã được GỠ BỎ**
> (Phase 1 của lộ trình chuyển sang `nf_conntrack`). Các phần mô tả DoS bên dưới
> (token bucket per-source, block list, port scan, half-open cap, `/proc/stargazer/dos_blocks`,
> config `system_dos-policy`) **không còn trong code**. `pkt_forward.ko` hiện chỉ còn
> session tracking + anomaly detection + defrag. Kế hoạch: bỏ `session.ko` (Phase 2) và
> thay bằng module trích xuất feature ML + chặn bằng ipset (Phase 3). Tài liệu này sẽ
> được viết lại sau khi kiến trúc mới ổn định.

## 1. Overview

Phase 2 delivers stateful packet tracking for the Stargazer NGFW. Two kernel modules implement the data plane:

| Module | File | Role |
|--------|------|------|
| `session.ko` | `session.c` / `session.h` | RCU hash table, TCP state machine, session reaper, procfs |
| `pkt_forward.ko` | `pkt_forward.c` | Netfilter FORWARD hook, DoS protection, policy enforcement |
| `session_test.ko` | `session_test.c` | Kernel self-test, loaded/unloaded on demand by mgmtd |

**Load order** is enforced by `MODULE_SOFTDEP("pre: session nf_defrag_ipv4")` in `pkt_forward.c`. The kernel loads `session.ko` and `nf_defrag_ipv4` before `pkt_forward.ko`. `session_test.ko` carries its own `MODULE_SOFTDEP("pre: session")` and is loaded and unloaded on demand by `handle_diag_session()` in `mgmtd_diag.c`.

**Direction model** follows the FortiOS / Linux conntrack convention: the first packet that creates a session defines the "original" direction (`SESS_DIR_ORIG = 0`). Subsequent packets matching the reversed 5-tuple are accounted as "reply" (`SESS_DIR_REPLY = 1`). `sess_lookup_or_create()` tries the key as-is first, then reversed, and only allocates a new session on a complete miss.

---

## 2. Session Struct

### 5-tuple key

```c
struct sess_key {
    __be32  src_ip;
    __be32  dst_ip;
    __be16  src_port;
    __be16  dst_port;
    u8      proto;
} __packed;
```

`__packed` ensures no padding bytes exist so `memcmp()` and `jhash()` operate over identical byte sequences on any architecture. For non-TCP/UDP protocols both port fields are set to 0 by `extract_key()`.

### Session entry

```c
struct session {
    struct hlist_node   node;
    struct list_head    lru_node;
    struct sess_key     key;
    u32                 id;
    u16                 flags;
    u8                  tcp_state;
    u8                  zero_win_dir;
    struct sess_tcp_win tcp_win[2];
    u32                 ifindex_in;
    u32                 ifindex_out;
    u32                 policy_id;
    struct sess_stats   stats;
    s32                 ml_score;
    ktime_t             expires_at;
    ktime_t             zero_win_since;
    spinlock_t          lock;
    struct rcu_head     rcu;
};
```

### Field descriptions

| Field | Type | Owner / Writer | Purpose |
|-------|------|----------------|---------|
| `node` | `hlist_node` | session.ko bucket lock | Hash chain linkage; removed via `hash_del_rcu()` under the per-bucket spinlock |
| `lru_node` | `list_head` | `lru_lock` spinlock | Global LRU list; tail = most recently used, head = oldest (eviction target) |
| `key` | `sess_key` | session.ko at create | Immutable after insertion; the canonical ORIG-direction 5-tuple |
| `id` | `u32` | session.ko at create | Monotonically increasing session ID from `atomic_inc_return(&next_id)` |
| `flags` | `u16` | pkt_forward.ko, ML/policy | Bitmask; see flags table below |
| `tcp_state` | `u8` | `sess_tcp_check()` under `s->lock` | Current TCP state machine state; one of `SESS_TCP_*` constants |
| `zero_win_dir` | `u8` | `sess_tcp_check()` under `s->lock` | Direction (`SESS_DIR_ORIG`/`SESS_DIR_REPLY`) that last set `zero_win_since`; prevents the sender side from resetting the zombie timer |
| `tcp_win[2]` | `sess_tcp_win` | `sess_tcp_check()` under `s->lock` | Per-direction ACK sequence, window size, and window scale for RST validation |
| `ifindex_in` | `u32` | pkt_forward.ko, first-packet set-once via `cmpxchg` | Ingress interface index at session creation |
| `ifindex_out` | `u32` | pkt_forward.ko, first-packet set-once | Egress interface index at session creation |
| `policy_id` | `u32` | `post_filter_hook()` under `s->lock` | Firewall policy sequence number stamped by iptables MARK rule; 0 = unset (Phase 3) |
| `stats` | `sess_stats` | `sess_update()` under `s->lock` | Per-direction packet/byte counters, timestamps, IAT, TCP flags, packet length min/max |
| `ml_score` | `s32` | ML scoring daemon (Phase 3) | Fixed-point score scaled × 1000; negative = suspicious |
| `expires_at` | `ktime_t` | `sess_tcp_check()` and `sess_update()` | Absolute expiry time; reaper compares against `ktime_get()` |
| `zero_win_since` | `ktime_t` | `sess_tcp_check()` under `s->lock` | Monotonic time when TCP window first became zero; 0 = not active |
| `lock` | `spinlock_t` | – | Protects `flags`, `tcp_state`, `tcp_win`, `stats`, `expires_at`, `zero_win_since`, `policy_id` |
| `rcu` | `rcu_head` | session.ko | Passed to `call_rcu()` for deferred `kfree()` after removal from hash |

### Flags bitmask

| Constant | Value | Set by | Cleared by | Meaning |
|----------|-------|--------|------------|---------|
| `SESS_ACTIVE` | `0x0001` | `sess_alloc()` at create | Never cleared | Session is live in the table |
| `SESS_BLOCKED` | `0x0002` | ML scoring daemon / policy | Manual clear | `pkt_forward.ko` drops all packets for this session |
| `SESS_MARKED` | `0x0004` | IPS/ML (Phase 3) | – | Session flagged as suspicious; reserved for Phase 3 |
| `SESS_DIRTY` | `0x0008` | `sess_mark_all_dirty()` on policy rebuild | `post_filter_hook()` after iptables accepts packet | Session must be re-evaluated against current policy on next packet |

### Per-direction TCP window state

```c
struct sess_tcp_win {
    u32  ack_seq;   /* last ACK sequence number seen FROM this direction */
    u16  win;       /* last advertised window FROM this direction (unscaled) */
    u8   scale;     /* window scale factor from SYN/SYN-ACK option (0..14)  */
    u8   _pad;
};
```

Used by the RST sequence validation in `sess_tcp_check()`. The peer window is computed as `(u32)win << scale` before the range check.

### Traffic statistics

```c
struct sess_stats {
    u64             pkts_orig;
    u64             pkts_reply;
    u64             bytes_orig;
    u64             bytes_reply;
    ktime_t         first_seen;
    ktime_t         last_seen;
    u64             iat_sum_ns;
    u32             iat_count;
    u16             tcp_flags_orig;
    u16             tcp_flags_reply;
    u32             init_win_orig;
    struct sess_pkt_len  len_orig;
    struct sess_pkt_len  len_reply;
};
```

`iat_sum_ns / iat_count` gives mean inter-arrival time in nanoseconds, used as a ML feature. `tcp_flags_orig` and `tcp_flags_reply` are cumulative OR of all TCP flag bytes seen in each direction. `init_win_orig` captures the TCP window from the first packet for ML feature extraction. `len_orig.min` and `len_orig.max` (and their reply counterparts) track packet length distribution.

---

## 3. Session Table

### Hash table

```c
static DEFINE_HASHTABLE(sess_table, SESSION_TABLE_BITS);  /* 2^16 = 65536 buckets */
static spinlock_t bucket_locks[SESSION_TABLE_SIZE];
```

- **Bucket count**: 65536 (`SESSION_TABLE_BITS = 16`), matching `MAX_SESSIONS`.
- **Hash function**: `jhash()` over the full `sess_key` struct (13 bytes, `__packed`) with a randomized seed `sess_hash_rnd` initialized from the kernel RNG at `session_init()`. The random seed prevents hash-bucket collision attacks (hash DoS).
- **Bucket index**: `hash_min(jhash(key, sizeof(*key), sess_hash_rnd), SESSION_TABLE_BITS)`.

### Concurrency model

Reads use RCU: callers must hold `rcu_read_lock()` across any lookup and subsequent dereference of the returned pointer. Writes (insert, delete) acquire the single `bucket_locks[b]` spinlock for the affected bucket. No global table lock exists.

When two bucket locks must be held simultaneously (the create path for a new session, which checks both the ORIG and REPLY bucket to handle simultaneous-open races), they are acquired in ascending index order to prevent AB/BA deadlock. The helper functions `lock_two_buckets()` and `unlock_two_buckets()` implement this ordering. When `ob == rb` (hash collision between orig and reply keys), only one lock is taken.

Lock ordering is strict and never violated:

```
bucket_locks[lower_index] -> bucket_locks[higher_index] -> lru_lock -> session->lock
```

`lru_lock` may be taken alone (hot path in `sess_update()`), without holding any `bucket_locks[]` entry.

### LRU list

```c
static DEFINE_SPINLOCK(lru_lock);
static LIST_HEAD(sess_lru);
```

All live sessions are linked into a global LRU list via `session->lru_node`. Head = oldest (eviction target), tail = most recently used. `sess_update()` calls `list_move_tail()` under `lru_lock` on every forwarded packet to touch the session. The emergency eviction path (`pf_purge_expired_states_emergency()`) scans from the LRU head to find idle sessions.

`sess_update()` guards the LRU touch with `list_empty(&s->lru_node)`: the reaper calls `list_del_init()` before `call_rcu()`, leaving `lru_node` self-linked. If `sess_update()` races with eviction in the RCU window, `list_empty()` returns true and the re-insertion is skipped, preventing a double `call_rcu()`.

### Memory layout

Each `struct session` is allocated with `kzalloc(sizeof(*s), GFP_ATOMIC)` on the packet path. Freed via `call_rcu()` → `sess_free_rcu()` → `kfree()`. Maximum live sessions is bounded by `pf_max_states` (default: 65536). At ~400 bytes per session, peak memory use is approximately 26 MB.

---

## 4. Session Lifecycle

### Creation: `sess_lookup_or_create()`

1. Lockless RCU lookup in the ORIG direction via `sess_lookup()`.
2. Lockless RCU lookup in the REPLY direction via `sess_lookup()` on the reversed key.
3. If both miss:
   a. Half-open cap check: if `key->proto == IPPROTO_TCP` and `sess_halfopen >= max_halfopen`, increment `sess_rejected_halfopen` and return NULL.
   b. Table-full check: if `sess_active >= pf_max_states`, call `pf_purge_expired_states_emergency()`. If it returns 0 (nothing freed), increment `sess_pf_drops` and return NULL.
   c. Allocate with `sess_alloc()` (`kzalloc`, `GFP_ATOMIC`).
   d. Acquire both bucket locks in ascending index order.
   e. Re-check capacity and half-open cap under lock.
   f. Re-check both directions under lock (race: another CPU may have inserted a matching session).
   g. `hash_add_rcu()`, increment `sess_active` and `sess_created`, link to LRU tail, release locks.
4. Set `*dir_out = SESS_DIR_ORIG` and return.

`sess_alloc()` sets `expires_at` to `now + sess_timeout_for_proto(proto)` in seconds, initializes `stats.len_orig.min = U32_MAX` (so the first packet correctly sets the minimum), and calls `spin_lock_init(&s->lock)`.

### Lookup

**`sess_lookup(key)`**: Iterates `hash_for_each_possible_rcu()` matching on `sess_key_eq()`. Implements inline expired-session cleanup (Technique 3): if `ktime_get() >= s->expires_at`, acquires the bucket lock, re-checks expiry, and if still expired calls `hash_del_rcu()`, `list_del_init()`, `atomic64_dec(&sess_active)`, `atomic64_inc(&sess_expired)`, `call_rcu()`, then returns NULL. The double-check under the lock prevents a race where another CPU refreshed `expires_at` between the lockless test and the lock acquisition.

**`sess_lookup_bidir(key, dir_out)`**: Calls `sess_lookup(key)` (ORIG), then `sess_lookup(reversed_key)` (REPLY). Sets `*dir_out` to match. Returns NULL only if both miss.

**`sess_icmp_error_lookup(skb, dir_out)`**: Handles ICMP type 3 (Destination Unreachable), 11 (Time Exceeded), and 12 (Parameter Problem). Extracts the embedded original IP + L4 header using `pskb_may_pull()`, builds a `sess_key` from the inner packet's 5-tuple, validates that `outer_iph->daddr == inner_key.src_ip` (ICMP forgery check), then calls `sess_lookup_bidir()`. Returns NULL for non-error ICMP types, malformed embedded headers, or forgery detection.

### Update: `sess_update()`

Called from `forward_hook` after `sess_tcp_check()` returns `NF_ACCEPT`. Takes `s->lock`, increments per-direction counters (`pkts_orig`/`pkts_reply`, `bytes_orig`/`bytes_reply`), updates `len_orig`/`len_reply` min/max, accumulates IAT, calls `accumulate_tcp_flags()`, updates `stats.last_seen`, refreshes `expires_at` for non-TCP protocols (TCP expiry is owned by `sess_tcp_check()`), releases `s->lock`, then moves the session to the LRU tail under `lru_lock`.

### Expiry and reaper

**GC reaper** (`sess_reaper_fn`): A `DECLARE_DELAYED_WORK` item scheduled at `HZ/10` (10 Hz). Uses an incremental bucket cursor `gc_idx` that advances `scan_size` buckets per run and wraps at `SESSION_TABLE_SIZE`, matching FreeBSD pf's `pf_purge_thread` design. One full sweep completes in `gc_sweep_interval` seconds (default 16 s, range 5–3600 s). In aggressive mode (entered when `sess_active >= pf_adaptive_start`), `scan_size` is multiplied by 4.

For each session in the scanned buckets, the reaper computes `eff = sess_pf_timeout(s, active_cnt)` (the PF adaptive timeout) and compares idle time against `eff`. Sessions where `idle_ns >= eff * NSEC_PER_SEC` (or `eff == 0`) are removed: `hash_del_rcu()` under the bucket lock, `list_del_init()` under `lru_lock`, `atomic64_dec(&sess_active)`, `atomic64_inc(&sess_expired)`, `call_rcu()`.

**PF adaptive timeout** (`sess_pf_timeout()`): Implements the FreeBSD pf formula:

```
factor = (adaptive_end - active) / (adaptive_end - adaptive_start)
effective_timeout = base_timeout * factor
```

- `active <= pf_adaptive_start` (default 75% of max): full base TTL, no scaling.
- `active` between start and end: TTL shrinks linearly.
- `active >= pf_adaptive_end` (default 90% of max): TTL = 0, session is an immediate eviction candidate.

TCP ESTABLISHED sessions are excluded from TTL scaling to avoid disrupting live connections under a SYN flood.

**Emergency eviction** (`pf_purge_expired_states_emergency()`): Called inline in the packet creation path when the table is full. Scans up to `PF_EMERGENCY_SCAN_MAX` (64) entries from the LRU head. Phase 1 collects candidate pointers under `lru_lock` (caller's `rcu_read_lock()` keeps them valid). Phase 2 acquires each session's bucket lock, checks `hlist_unhashed()` (guard against concurrent GC eviction), removes from hash and LRU, schedules deferred free. Returns the number freed; 0 triggers `NF_DROP` at the caller.

**`sess_free_rcu()`**: The RCU callback. Corrects `sess_halfopen` counter for sessions evicted mid-handshake and corrects `src_est_table` for ESTABLISHED sessions reaped by GC without a FIN/RST.

---

## 5. TCP State Machine

### States

| Constant | Value | Description |
|----------|-------|-------------|
| `SESS_TCP_NONE` | 0 | No packet seen yet (initial state after create) |
| `SESS_TCP_SYN_SENT` | 1 | SYN from ORIG direction, awaiting SYN-ACK |
| `SESS_TCP_SYN_RECV` | 2 | SYN-ACK from REPLY, awaiting final ACK |
| `SESS_TCP_ESTABLISHED` | 3 | Three-way handshake complete |
| `SESS_TCP_FIN_WAIT` | 4 | FIN from ORIG (active close) |
| `SESS_TCP_CLOSE_WAIT` | 5 | FIN from REPLY (passive close) |
| `SESS_TCP_LAST_ACK` | 6 | FIN from ORIG after CLOSE_WAIT |
| `SESS_TCP_TIME_WAIT` | 7 | Both FINs exchanged |
| `SESS_TCP_CLOSE` | 8 | RST seen or fully closed |
| `SESS_TCP_SYN_SENT2` | 9 | Simultaneous open: both sides sent SYN |

### Per-state timeouts (module params, all writable at runtime via sysfs)

| State | Module param | Default (s) |
|-------|-------------|-------------|
| `SESS_TCP_NONE` | `sess_tt_tcp_none` | 120 |
| `SESS_TCP_SYN_SENT` | `sess_tt_tcp_syn_sent` | 120 |
| `SESS_TCP_SYN_RECV` | `sess_tt_tcp_syn_recv` | 60 |
| `SESS_TCP_ESTABLISHED` | `sess_tt_tcp_est` | 3600 |
| `SESS_TCP_FIN_WAIT` | `sess_tt_tcp_fin_wait` | 120 |
| `SESS_TCP_CLOSE_WAIT` | `sess_tt_tcp_close_wait` | 60 |
| `SESS_TCP_LAST_ACK` | `sess_tt_tcp_last_ack` | 30 |
| `SESS_TCP_TIME_WAIT` | `sess_tt_tcp_time_wait` | 120 |
| `SESS_TCP_CLOSE` | `sess_tt_tcp_close` | 10 |
| `SESS_TCP_SYN_SENT2` | `sess_tt_tcp_syn_sent2` | 60 |

Non-TCP protocol timeouts: UDP 180 s (`sess_tt_udp`), ICMP 60 s (`sess_tt_icmp`), other 300 s (`sess_tt_other`).

### State machine (`sess_tcp_check()`)

`sess_tcp_check()` must be called from `forward_hook` inside `rcu_read_lock()`, before `sess_update()`. It acquires `s->lock` internally.

**RST handling**: Before the state machine switch, if `tcph->rst` is set, the sequence number is validated against the peer's receive window: `tcp_in_window(seq, peer_ack, peer_win)` where `peer_win = (u32)tcp_win[1-dir].win << tcp_win[1-dir].scale`. If `peer_ack != 0` and `peer_win > 0` and the sequence is outside the window, the packet is dropped (`NF_DROP`) and `pkts_invalid` is incremented. A valid RST transitions to `SESS_TCP_CLOSE`.

**State transitions**:

```
NONE / SYN_SENT:
  SYN (no ACK), dir=ORIG  -> SYN_SENT      (records ORIG window scale)
  SYN (no ACK), dir=REPLY -> SYN_SENT2     (simultaneous open)
  SYN+ACK,      dir=REPLY -> SYN_RECV      (records REPLY window scale)
  non-SYN, asymmetric_mode -> ESTABLISHED  (mid-stream pickup)

SYN_SENT2:
  SYN+ACK (either dir)    -> SYN_RECV

SYN_RECV:
  ACK (no SYN, no FIN), dir=ORIG -> ESTABLISHED

ESTABLISHED:
  SYN                     -> NF_DROP (SYN injection attack)
  FIN, dir=ORIG           -> FIN_WAIT
  FIN, dir=REPLY          -> CLOSE_WAIT

FIN_WAIT:
  FIN, dir=REPLY          -> TIME_WAIT

CLOSE_WAIT:
  FIN, dir=ORIG           -> LAST_ACK

LAST_ACK:
  ACK, dir=REPLY          -> CLOSE

TIME_WAIT / CLOSE: no further transitions
```

**Post-transition effects**:
- `expires_at` is updated to `now + tcp_state_timeout(new_state)` on every packet.
- `tcp_win[dir].ack_seq` and `tcp_win[dir].win` are updated whenever `tcph->ack` is set.
- Window scale is parsed from SYN and SYN-ACK options via `tcp_parse_wscale()` and stored in `tcp_win[dir].scale` (clamped to 0–14 per RFC 7323).
- Half-open counter (`sess_halfopen`): incremented when entering a half-open state, decremented when leaving one.
- Per-source ESTABLISHED cap: when `new_state == SESS_TCP_ESTABLISHED` and the prior state was not ESTABLISHED, `src_est_check_and_inc(s->key.src_ip)` is called. If the cap is exceeded, the completing ACK is dropped and the session stays in `SYN_RECV` until its TTL expires.
- `src_est_dec()` is called whenever a session leaves `SESS_TCP_ESTABLISHED` for any reason, and also from `sess_free_rcu()` for ESTABLISHED sessions reaped by GC.

**Non-SYN drop enforcement**: In `forward_hook`, non-SYN TCP packets that miss both lookups are dropped unconditionally (no `sess_lookup_or_create()` call). In asymmetric mode (`sess_asymmetric_mode == true`), a non-SYN miss is permitted to create a new session, which `sess_tcp_check()` will immediately promote to `SESS_TCP_ESTABLISHED`.

**Zero-window zombie protection**: When `zero_win_timeout > 0` and the session is ESTABLISHED, if a side advertises `win == 0`, `zero_win_since` is set and `zero_win_dir` records the direction. If the zero-window condition persists for more than `zero_win_timeout` seconds (default 60 s), `expires_at` is crushed to `now + 5s`. Only a non-zero window advertisement from `zero_win_dir` (the receiver) clears `zero_win_since`; packets from the sender do not reset the timer.

**Malformed TCP drops**: `doff < 5` (header smaller than 20 bytes) triggers `NF_DROP` and `pkts_invalid++`.

---

## 6. DoS Protection (pkt_forward.ko)

### 10-step forward_hook pipeline

```c
static unsigned int forward_hook(void *priv, struct sk_buff *skb,
                                 const struct nf_hook_state *state)
```

| Step | What | Scope | Drop counter |
|------|------|-------|-------------|
| [1] | IPv4 + L4 header validation (`is_valid_ipv4`, `extract_key`) | All interfaces | `pkts_dropped` |
| [2] | L3/L4 anomaly detection (`is_ip_anomaly`, `is_tcp_anomaly`, `is_icmp_anomaly`) | All interfaces | `pkts_anomaly_dropped` |
| [3] | Block list check (`src_block_check`) | Protected interfaces | `pkts_dropped` |
| [4] | Per-source aggregate packet rate (`src_rate_check` on `pkt_rate`) | Protected interfaces, disabled by default | `pkts_pkt_rate_dropped` |
| [4b] | Per-source ICMP echo/query rate (`icmp_is_floodable` + `src_rate_check` on `icmp_rate`) | Protected interfaces, per-packet, ICMP error types exempt | `pkts_icmp_dropped` |
| [5] | Per-source half-open SYN cap (`src_halfopen_check`) | Protected interfaces, TCP SYN only | `pkts_halfopen_src_dropped` |
| [6] | Port scan detection (`src_scan_check`) | Protected interfaces, TCP SYN only | `pkts_scan_dropped` |
| [7] | Session lookup/create with per-protocol rate limiting (`src_dos_check`, TCP/UDP only) | Protected interfaces | `pkts_syn_dropped` / `pkts_udp_dropped` |
| [8] | `SESS_BLOCKED` enforcement | All | `pkts_blocked` |
| [9] | TCP state machine (`sess_tcp_check`) | TCP sessions | `pkts_dropped` |
| [10] | Stats update (`sess_update`) | All | – |

`is_protected` is evaluated once per packet from `protected_ifmask`: `idx = state->in->ifindex; is_protected = idx < BITS_PER_LONG && (protected_ifmask >> idx) & 1`. When `protected_ifmask == 0`, the entire DoS subsystem (steps 3–7) is bypassed with a single branch.

**ICMP rate limiting is per-packet (step 4b), not per-session.** ICMP is connectionless: a flood to a single destination is one session, so a per-new-session check (as used for TCP SYN and UDP at step 7) would never see the 2nd..Nth packet. `icmp_is_floodable()` rate-limits every ICMP echo/query packet but exempts ICMP error types (Destination Unreachable / Time Exceeded / Parameter Problem) so Path-MTU discovery and traceroute keep working under load.

### Anomaly detection (step 2, unconditional)

**`is_ip_anomaly()`**:
- Land attack: `iph->saddr == iph->daddr`.
- IP source routing: scans IP options for LSRR (type 131) or SSRR (type 137).

**`is_tcp_anomaly()`** (called only when `extract_key()` succeeded for TCP):
- NULL scan: no control bits set (`fin | syn | rst | psh | ack | urg == 0`).
- XMAS scan: `fin && urg && psh`.
- FIN without ACK: invalid per RFC 793.
- SYN with data: `syn && !ack && tot_len > ip_hlen + tcp_hlen`.

**`is_icmp_anomaly()`**: Ping of Death: `protocol == IPPROTO_ICMP && ntohs(iph->tot_len) > 65500`. IPv4 defrag (`nf_defrag_ipv4`) has already reassembled fragments before this hook fires.

### Token-bucket rate limiters

`src_rate_check(tbl, src, rate, burst)` uses a lock-free approximate hash array (`SRC_RATE_SLOTS = 4096`). Each slot tracks one source IP with token count, refill rate, and last-refill timestamp. Collisions cause the slot to be taken over by the displacing IP; the prior IP loses its rate state and gets a fresh burst. This is intentional: perfect accuracy is unnecessary for flood detection.

`src_dos_check(src, proto)` selects the appropriate table (SYN / UDP), runs the rate check, and on flooding calls `src_block_add(src, reason)` and increments the appropriate drop counter. It is called on new-session creation for TCP SYN and UDP only; ICMP is rate-limited per-packet at step 4b.

Every `src_block_add(src, reason)` also appends a `(jiffies, src_ip, reason)` entry to the block-event ring buffer (see `/proc/stargazer/dos_blocks`).

### Per-source half-open SYN cap (step 5)

`src_halfopen_check(src)` uses a 4096-slot sliding-window counter. The window is `HALFOPEN_WINDOW_SEC = 120` seconds. When `count >= max_halfopen_per_src` within the window, `src_block_add(src)` is called and `pkts_halfopen_src_dropped` is incremented. This catches low-rate SYN floods that stay under the token-bucket threshold but accumulate half-open sessions over time.

### Port scan detection (step 6)

`src_scan_check(src, dst_port, dst_ip)` uses a 32-bit bloom filter per source (`src_scan[SRC_RATE_SLOTS]`). Each unique `(dst_port, dst_ip)` pair from a source maps to one bit via `jhash_2words()`. When `hweight32(bloom) >= scan_threshold`, the source is blocked. The filter resets after `scan_window` seconds. Called only for TCP SYNs.

### Block list

`src_block[SRC_BLOCK_SLOTS]` is an array of 65536 `struct src_block_slot` entries. `src_block_add(src)` stamps `expires = jiffies + src_block_dur * HZ`. `src_block_check(src)` does lazy expiry: if the slot has expired, it clears `expires` and returns false. This avoids a separate timer thread; the hot path O(1) check handles expiry inline.

### Default thresholds

| Parameter | Default | Description |
|-----------|---------|-------------|
| `protected_ifmask` | 0 (disabled) | Bitmask of protected ifindices |
| `syn_flood_thr` | 200 | TCP SYN new-session rate/s per source |
| `syn_flood_burst` | 400 | Token-bucket burst for SYN |
| `udp_flood_thr` | 1000 | UDP new-session rate/s per source |
| `udp_flood_burst` | 2000 | Token-bucket burst for UDP |
| `icmp_flood_thr` | 100 | ICMP echo/query rate per source (packets/s, per-packet) |
| `icmp_flood_burst` | 200 | Token-bucket burst for ICMP |
| `src_block_dur` | 30 s | How long a violating source stays blocked |
| `max_halfopen_per_src` | 10 | Max half-open TCP sessions per source in 120 s window |
| `pkt_flood_thr` | 0 (disabled) | Per-source aggregate packet rate cap (pkts/s) |
| `pkt_flood_burst` | 20000 | Token-bucket burst for aggregate rate |
| `scan_threshold` | 20 | Unique dst-port/IP combos before block |
| `scan_window` | 10 s | Bloom filter reset window |

---

## 7. Policy Marking

### How policy_id is stamped

When a firewall policy is applied to the FORWARD chain, each ACCEPT rule is preceded by an iptables `MARK --set-mark` rule that writes the policy's sequence number into `skb->mark` bits 29–16 (14 bits, range 1–16383):

```
STARGAZER_POLICY_MARK_MASK  = 0x3FFF0000
STARGAZER_POLICY_MARK_SHIFT = 16
```

This range does not overlap with `STARGAZER_DIRTY_MARK` (bit 7, `0x00000080`).

### `post_filter_hook`

Registered at `NF_IP_PRI_FILTER + 1`. Fires after iptables has accepted a packet (if iptables drops the packet, traversal stops and this hook is never reached).

Fast path: if neither `STARGAZER_DIRTY_MARK` nor `STARGAZER_POLICY_MARK_MASK` bits are set in `skb->mark`, return `NF_ACCEPT` immediately without a session lookup.

When either bit region is set:
1. Clear both regions from `skb->mark`.
2. Call `extract_key()` and `sess_lookup_bidir()`.
3. Acquire `s->lock`.
4. If `SESS_DIRTY` was set: clear `s->flags &= ~SESS_DIRTY`.
5. If `policy_seq > 0`: `WRITE_ONCE(s->policy_id, policy_seq)`.
6. Release `s->lock`.

### `SESS_DIRTY` re-evaluation flow

`sess_mark_all_dirty()` iterates all 65536 buckets (one `bucket_locks[b]` at a time) and sets `SESS_DIRTY` in every session's `flags`. This is called when the firewall policy is rebuilt.

In `forward_hook`, before the TCP state machine, if `READ_ONCE(s->flags) & SESS_DIRTY` is set: `skb->mark |= STARGAZER_DIRTY_MARK`. The iptables ESTABLISHED,RELATED rule is expected to match on `! --mark STARGAZER_DIRTY_MARK`, causing dirty-session packets to skip the fast-path ESTABLISHED rule and fall through to policy rules for re-evaluation. The `post_filter_hook` clears `SESS_DIRTY` after iptables accepts the packet.

---

## 8. Procfs Interface

All entries are under `/proc/stargazer/`, a directory created by `session.ko` at `session_init()` and exported as `struct proc_dir_entry *sg_proc_root` (symbol exported with `EXPORT_SYMBOL_GPL`).

### `/proc/stargazer/sessions` (mode 0444)

Implemented via `seq_file` with a custom `sess_seq_ops` that iterates the hash table bucket by bucket under `rcu_read_lock()`.

**Header lines** (lines beginning with `#`):

```
# Stargazer sessions  active=N created=N expired=N invalid=N pf_drops=N
# halfopen=N rejected_halfopen=N max_halfopen=N
# est_src_drops=N max_est_per_src=N zero_win_timeout=N
# pf_max=N adaptive_start=N adaptive_end=N gc_sweep_interval=N gc_aggressive=N
# proto src dst id pkts(o/r) bytes(o/r) age_ms expire_ms ml flags dev policy_id tcp_state
```

**Session lines**:

```
proto=N src=A.B.C.D:P dst=E.F.G.H:Q id=N pkts=N/N bytes=N/N age_ms=N expire_ms=N ml=N flags=0xN dev=N/N policy_id=N [tcp_state=N]
```

| Field | Source |
|-------|--------|
| `proto` | `s->key.proto` |
| `src` | `s->key.src_ip:ntohs(s->key.src_port)` |
| `dst` | `s->key.dst_ip:ntohs(s->key.dst_port)` |
| `id` | `s->id` |
| `pkts` | `s->stats.pkts_orig / s->stats.pkts_reply` |
| `bytes` | `s->stats.bytes_orig / s->stats.bytes_reply` |
| `age_ms` | `ktime_to_ms(now - s->stats.first_seen)` |
| `expire_ms` | `ktime_to_ms(s->expires_at - now)` (negative = expired) |
| `ml` | `s->ml_score` |
| `flags` | `s->flags` (hex) |
| `dev` | `s->ifindex_in / s->ifindex_out` |
| `policy_id` | `s->policy_id` |
| `tcp_state` | `s->tcp_state` (TCP only) |

### `/proc/stargazer/session_ctl` (mode 0200, CAP_NET_ADMIN required)

Write-only control interface. Accepted commands:

| Command | Effect |
|---------|--------|
| `flush` | Calls `sess_flush_all()`: removes all sessions from hash and LRU, schedules deferred free via `call_rcu()`. Does not call `rcu_barrier()`. |
| `mark_dirty` | Calls `sess_mark_all_dirty()`: sets `SESS_DIRTY` in all sessions. |

### `/proc/stargazer/pkt_forward_stats` (mode 0444)

Simple `single_open` seq_file. One `key=value` line per counter:

| Key | Source |
|-----|--------|
| `pkts_forwarded` | Packets that reached `NF_ACCEPT` |
| `pkts_dropped` | All drops (sum of all drop paths) |
| `pkts_blocked` | Dropped due to `SESS_BLOCKED` |
| `pkts_syn_dropped` | Per-source TCP SYN token-bucket exceeded |
| `pkts_udp_dropped` | Per-source UDP token-bucket exceeded |
| `pkts_icmp_dropped` | Per-source ICMP token-bucket exceeded |
| `pkts_anomaly_dropped` | L3/L4 anomaly (land, XMAS, NULL scan, etc.) |
| `pkts_halfopen_src_dropped` | Per-source half-open sliding-window cap |
| `pkts_pkt_rate_dropped` | Per-source aggregate packet rate exceeded |
| `pkts_scan_dropped` | Port scan bloom filter threshold exceeded |
| `protected_ifmask` | Current value of the `protected_ifmask` module param |

### `/proc/stargazer/dos_blocks` (mode 0444)

Block-event ring buffer (`DOS_BLOCK_LOG_SIZE = 256` entries, lock-free, oldest first). Every `src_block_add()` records `(jiffies, src_ip, reason)`. `dos_blocks_show()` computes age at read time from `jiffies`, so there are no wall-clock concerns in the kernel.

```
# Stargazer DoS block log (<total> events, showing last <n>)
# age_sec src reason
age_sec=12 src=203.0.113.7 reason=syn_flood
age_sec=4  src=203.0.113.9 reason=icmp_flood
```

`reason` is one of: `syn_flood`, `udp_flood`, `icmp_flood`, `pkt_rate`, `halfopen`, `scan` (enum `dos_block_reason`). Surfaced to operators via `execute diagnose session blocks`.

### `/proc/stargazer/session_test` (mode 0444)

Created by `session_test.ko` at `module_init()`. Key=value output:

| Key | Meaning |
|-----|---------|
| `sessions_created` | 1 if `sess_lookup_or_create()` returned `dir == SESS_DIR_ORIG` |
| `pkts_orig` | `s->stats.pkts_orig` after one `sess_update()` call |
| `pkts_reply` | `sr->stats.pkts_reply` after one `sess_update()` call |
| `bytes_orig` | `s->stats.bytes_orig` (should equal `ST_PKT_LEN = 32`) |
| `bidirectional` | 1 if reverse lookup returned `dir == SESS_DIR_REPLY` |

---

## 9. IPC and Diagnostics

### Wire format (stargazer_ipc.h)

**Request** (`sg_request_hdr_t`, packed, 84 bytes fixed header + variable payload):

```
magic:2 | version:1 | debug_flags:1 | cmd:4 | username[64] | payload_len:4 | session_tag:8 | payload[...]
```

**Response** (`sg_response_hdr_t`, packed, 268 bytes fixed header + variable payload):

```
magic:2 | version:1 | _pad:1 | status:4 | extra[256] | payload_len:4 | payload[...]
```

`SG_USERNAME_MAX = 64`, `SG_EXTRA_MAX = 256`, `SG_MSG_MAGIC = 0x5347` ("SG"), `SG_MSG_VERSION = 2`. `SG_RESPONSE_MAX = 65536` bytes, `SG_PAYLOAD_MAX = 4096` bytes.

### Session-related IPC commands

| Command ID | Name | Permission | Handler | Description |
|-----------|------|------------|---------|-------------|
| 650 | `SG_CMD_SHOW_SESSIONS` | monitor | `handle_show_sessions()` | Reads `/proc/stargazer/sessions`, enriches with `policy_name` from SQLite |
| 654 | `SG_CMD_DIAG_SESSION` | monitor (status) / admin (inject) | `handle_diag_session()` | Status mode: returns raw procfs. Inject mode: insmod/rmmod `session_test.ko` |
| 655 | `SG_CMD_SESSION_CLEAR` | admin | `handle_session_clear()` | Reads active count, writes `flush` to `session_ctl`, returns `flushed=N` |
| 656 | `SG_CMD_SESSION_STATS` | monitor | `handle_session_stats()` | Parses counters from `/proc/stargazer/sessions` and `/proc/stargazer/pkt_forward_stats` |
| 657 | `SG_CMD_SESSION_GC_INTERVAL` | admin | `handle_session_gc_interval()` | GET: reads `/sys/module/session/parameters/gc_sweep_interval`. SET: writes new value |
| 658 | `SG_CMD_SESSION_BLOCKS` | monitor | `handle_session_blocks()` | Reads `/proc/stargazer/dos_blocks` (recent DoS block events) |

### Policy-name enrichment (`handle_show_sessions()`)

Before returning the session table, `handle_show_sessions()` queries the SQLite database for all `firewall_policy` entries, building a map of `policy_id -> policy_name` (up to `SESS_POLICY_MAP_MAX = 256` entries). It then does a second pass over the procfs output: for each non-comment line containing `policy_id=N` where `N > 0`, it appends ` policy_name=<name>` if a match exists. Uses `struct dynbuf` for the output buffer to avoid a fixed-size limit. Falls back to the raw procfs buffer on allocation failure.

### `handle_session_stats()` parsing

Reads both `/proc/stargazer/sessions` (for `active`, `created`, `expired`, `invalid`, `halfopen`, `rejected_halfopen`, `est_src_drops`) and `/proc/stargazer/pkt_forward_stats` (for all flood drop counters) using `strstr()` substring search on the raw text. Module load status is detected via `read_small_file()` return value (< 0 = not loaded) for `session.ko` and `access("/sys/module/pkt_forward", F_OK)` for `pkt_forward.ko`. Returns all parsed counters as a `key=value` text payload.

---

## 10. CLI Commands

All commands under `execute diagnose session` require at minimum "monitor" permission. Commands that modify state require "admin".

### Session diagnostic commands

| Command | IPC cmd | Permission | Output |
|---------|---------|------------|--------|
| `execute diagnose session` | `SG_CMD_DIAG_SESSION` | monitor | Raw `/proc/stargazer/sessions` with header and per-session lines |
| `execute diagnose session status` | `SG_CMD_DIAG_SESSION` | monitor | Same as above |
| `execute diagnose session stats` | `SG_CMD_SESSION_STATS` | monitor | Formatted counters table with module load status |
| `execute diagnose session blocks` | `SG_CMD_SESSION_BLOCKS` | monitor | Recent DoS block events: `age_sec`, source IP, reason |
| `execute diagnose session clear` | `SG_CMD_SESSION_CLEAR` | admin | Confirmation prompt, then `Flushed N session(s).` |
| `execute diagnose session gc-interval [N]` | `SG_CMD_SESSION_GC_INTERVAL` | admin | GET: `GC sweep interval : N seconds`. SET: `GC sweep interval set to N seconds.` |
| `show sessions` | `SG_CMD_SHOW_SESSIONS` | monitor | Enriched session table with `policy_name` appended to lines |

### `execute diagnose session stats` example output

```
  === Session Statistics ===
  session.ko     : loaded
  pkt_forward.ko : loaded
  Active sessions: 1243
  Created        : 98432
  Expired        : 97189
  Invalid (drops): 14
  Half-open TCP  : 3  (rejected: 0)
  Est. src drops : 0

  --- DoS Drop Counters ---
  L3/L4 anomaly  : 0
  SYN flood/src  : 0
  SYN halfopen/s : 0
  UDP flood      : 0
  ICMP flood     : 0
  Pkt rate       : 0
  Port scan      : 0
```

### Self-test command

```
execute diagnose selftest session
execute diagnose selftest session full
```

Invokes `cli_diagnose_test_session()` which in turn triggers `handle_diag_session()` with payload `inject`, causing mgmtd to `insmod session_test.ko`, read `/proc/stargazer/session_test`, and `rmmod session_test`. The CLI displays pass/fail for each `SESS-*` test case.

---

## 11. Self-Test Module (session_test.ko)

`session_test.ko` exercises the `session.ko` public API directly, without a network stack. It is built as a separate module with `MODULE_SOFTDEP("pre: session")`.

### What it tests

Test 5-tuple: `10.88.0.2:55000 → 10.88.1.2:5353` (UDP, `ST_PKT_LEN = 32`). The `10.88.x.x` subnet is reserved for Stargazer self-tests.

| Test ID | Operation | Verification |
|---------|-----------|-------------|
| SESS-06/07 | `sess_lookup_or_create(&orig_key, &dir)` inside `rcu_read_lock()` | `dir == SESS_DIR_ORIG`; session pointer non-NULL |
| SESS-07 | `sess_update(s, skb, SESS_DIR_ORIG)` | `s->stats.pkts_orig == 1`, `s->stats.bytes_orig == 32` |
| SESS-09/10 | `sess_lookup_or_create(&reply_key, &dir2)` | `dir2 == SESS_DIR_REPLY`; returns same session |
| SESS-10 | `sess_update(sr, skb, SESS_DIR_REPLY)` | `sr->stats.pkts_reply == 1` |
| Cleanup | `sess_lookup(&orig_key)` then `sess_delete(s_del)` outside `rcu_read_lock()` | Session removed cleanly |

### Load/unload

Load (normal): `insmod /lib/modules/stargazer/session_test.ko`

Unload: `rmmod session_test`

`session_test_exit()` removes `/proc/stargazer/session_test`.

mgmtd (`handle_diag_session()` with `inject` payload) automates the load/wait/read/unload sequence. It calls `usleep(50000)` (50 ms) after `insmod` to allow `module_init()` to complete before reading procfs. Requires admin permission.

### Results location

`/proc/stargazer/session_test` — created by `session_test.ko` in `module_init()`, placed under the shared `sg_proc_root` directory owned by `session.ko`.

---

## 12. Module Parameters

### session.ko

All parameters are writable at runtime via `/sys/module/session/parameters/<name>` unless noted (mode 0444 = read-only at runtime).

| Parameter | Default | Mode | Description |
|-----------|---------|------|-------------|
| `sess_asymmetric_mode` | false | 0644 | Allow mid-stream TCP pickup for asymmetric routing / ECMP / HA. When true, non-SYN TCP without a session creates one and immediately promotes it to ESTABLISHED. |
| `pf_max_states` | 65536 | 0444 | Hard session table cap. No new sessions above this count. Cannot exceed `MAX_SESSIONS`. |
| `pf_adaptive_start` | 0 (resolved to 75% of max) | 0644 | Begin TTL scaling above this active session count. |
| `pf_adaptive_end` | 0 (resolved to 90% of max) | 0644 | TTL crushed to 0 at this count. |
| `gc_sweep_interval` | 16 s | 0644 | Seconds for GC to complete one full table sweep. Range: 5–3600. Also writable via `SG_CMD_SESSION_GC_INTERVAL`. |
| `max_halfopen` | 1024 | 0644 | Global hard cap on half-open TCP sessions (`SYN_SENT` + `SYN_RECV` + `SYN_SENT2`). |
| `max_est_per_src` | 64 | 0644 | Max ESTABLISHED sessions per source IP (0 = disabled). Approximate: uses a 4096-slot lock-free hash table. |
| `zero_win_timeout` | 60 s | 0644 | Seconds TCP window=0 before session TTL is crushed to 5 s. Set to 0 to disable. |
| `sess_tt_tcp_none` | 120 s | 0644 | TCP pre-handshake timeout |
| `sess_tt_tcp_syn_sent` | 120 s | 0644 | TCP SYN_SENT (half-open) timeout |
| `sess_tt_tcp_syn_recv` | 60 s | 0644 | TCP SYN_RECV timeout |
| `sess_tt_tcp_est` | 3600 s | 0644 | TCP ESTABLISHED idle timeout |
| `sess_tt_tcp_fin_wait` | 120 s | 0644 | TCP FIN_WAIT timeout |
| `sess_tt_tcp_close_wait` | 60 s | 0644 | TCP CLOSE_WAIT timeout |
| `sess_tt_tcp_last_ack` | 30 s | 0644 | TCP LAST_ACK timeout |
| `sess_tt_tcp_time_wait` | 120 s | 0644 | TCP TIME_WAIT timeout |
| `sess_tt_tcp_close` | 10 s | 0644 | TCP CLOSE (RST) timeout |
| `sess_tt_tcp_syn_sent2` | 60 s | 0644 | TCP simultaneous-open timeout |
| `sess_tt_udp` | 180 s | 0644 | UDP session idle timeout |
| `sess_tt_icmp` | 60 s | 0644 | ICMP session idle timeout |
| `sess_tt_other` | 300 s | 0644 | Other protocol session timeout |

### pkt_forward.ko

| Parameter | Default | Mode | Description |
|-----------|---------|------|-------------|
| `protected_ifmask` | 0 | 0644 | Bitmask of protected interface ifindices; bit N = ifindex N is protected. When 0, entire DoS subsystem is disabled. Supports up to 64 interfaces (BITS_PER_LONG on ARM64). |
| `syn_flood_thr` | 200 | 0644 | TCP SYN new-session rate limit per source (sessions/s) |
| `syn_flood_burst` | 400 | 0644 | TCP SYN token-bucket burst capacity |
| `udp_flood_thr` | 1000 | 0644 | UDP new-session rate limit per source (sessions/s) |
| `udp_flood_burst` | 2000 | 0644 | UDP token-bucket burst capacity |
| `icmp_flood_thr` | 100 | 0644 | ICMP echo/query rate limit per source (packets/s, per-packet; error types exempt) |
| `icmp_flood_burst` | 200 | 0644 | ICMP token-bucket burst capacity |
| `src_block_dur` | 30 s | 0644 | Duration a violating source stays in the block list |
| `max_halfopen_per_src` | 10 | 0644 | Max half-open TCP sessions per source in 120 s window (0 = disabled) |
| `pkt_flood_thr` | 0 | 0644 | Per-source aggregate packet rate cap in pkts/s (0 = disabled) |
| `pkt_flood_burst` | 20000 | 0644 | Per-source aggregate packet rate burst |
| `scan_threshold` | 20 | 0644 | Unique (dst_port, dst_ip) combos per window before source is blocked (0 = disabled) |
| `scan_window` | 10 s | 0644 | Port scan bloom filter window in seconds |

---

## 13. Data-Flow Diagram

```
  NIC (ingress)
       |
       v
  nf_defrag_ipv4 (PRE_ROUTING, reassemble fragments)
       |
       v
  ┌──────────────────────────────────────────────────────────────────┐
  │  forward_hook  (NF_INET_FORWARD, priority -399)                  │
  │                                                                  │
  │  [1] IPv4+L4 validation (extract_key)             ──► DROP       │
  │  [2] Anomaly detection (land/XMAS/NULL/PoD/SSRR)  ──► DROP       │
  │  [3] Block list check (protected ifaces only)     ──► DROP       │
  │  [4] Aggregate pkt rate (pkt_flood_thr, disabled) ──► DROP       │
  │  [4b] ICMP echo/query rate (per-packet, err-exempt) ──► DROP     │
  │  [5] Per-src half-open SYN cap (SYN only)         ──► DROP       │
  │  [6] Port scan bloom filter (SYN only)            ──► DROP       │
  │                                                                  │
  │  rcu_read_lock()                                                 │
  │  [7] Protocol dispatch:                                          │
  │      TCP non-SYN ──► sess_lookup_bidir()     ─── miss ──► DROP   │
  │      TCP SYN     ──► src_dos_check()         ─── flood ──► DROP  │
  │                  ──► sess_lookup_or_create() ─── full ──► DROP   │
  │                        │                                         │
  │                        v                                         │
  │                   ┌──────────────┐                               │
  │                   │ SESSION TABLE │  (RCU hash, 65536 buckets)   │
  │                   │  session.ko   │                               │
  │                   └──────────────┘                               │
  │                        │  session pointer (valid in RCU section) │
  │                        v                                         │
  │      record ifindex_in/out (cmpxchg, first-packet only)         │
  │                                                                  │
  │  [8] SESS_BLOCKED?  ──yes──► DROP (pkts_blocked++)               │
  │                                                                  │
  │  [8b] SESS_DIRTY?   ──yes──► skb->mark |= DIRTY_MARK             │
  │                                                                  │
  │  [9] TCP: sess_tcp_check()  ──► NF_DROP on state violation       │
  │           (updates expires_at, tcp_state, tcp_win[])             │
  │                                                                  │
  │  [10] sess_update()                                              │
  │       (pkts/bytes/iat/flags/len stats, LRU touch)                │
  │  rcu_read_unlock()                                               │
  │                                                                  │
  │  pkts_forwarded++  ──► NF_ACCEPT                                 │
  └──────────────────────────────────────────────────────────────────┘
       |
       v
  iptables FORWARD chain (priority 0)
    - ESTABLISHED,RELATED rule (skips packets with DIRTY_MARK)
    - Policy rules (may stamp skb->mark bits 16-29 with policy sequence)
    - ACCEPT / DROP
       |
       | (on ACCEPT only)
       v
  ┌──────────────────────────────────────────────────────────────────┐
  │  post_filter_hook  (NF_INET_FORWARD, priority +1)                │
  │                                                                  │
  │  Fast path: neither DIRTY_MARK nor POLICY_MARK set?             │
  │  ──yes──► NF_ACCEPT immediately (zero session-table cost)        │
  │                                                                  │
  │  rcu_read_lock()                                                 │
  │  sess_lookup_bidir()                                             │
  │  s->lock:                                                        │
  │    DIRTY_MARK set?  ──► s->flags &= ~SESS_DIRTY                  │
  │    POLICY_MARK set? ──► WRITE_ONCE(s->policy_id, policy_seq)     │
  │  rcu_read_unlock()                                               │
  │                                                                  │
  │  NF_ACCEPT                                                       │
  └──────────────────────────────────────────────────────────────────┘
       |
       v
  NIC (egress)


  Parallel path — GC reaper (10 Hz delayed_work):
  ┌─────────────────────────────────────────────────────────────────┐
  │  sess_reaper_fn                                                  │
  │    scan_size buckets per run (SESSION_TABLE_SIZE / interval*10)  │
  │    aggressive mode (4×) when active >= pf_adaptive_start         │
  │    for each session: eff = sess_pf_timeout(s, active)            │
  │      if idle_ns >= eff * NSEC_PER_SEC:                           │
  │        hash_del_rcu + list_del_init + call_rcu(sess_free_rcu)    │
  └─────────────────────────────────────────────────────────────────┘

  Inline emergency eviction (called from sess_lookup_or_create):
  ┌─────────────────────────────────────────────────────────────────┐
  │  pf_purge_expired_states_emergency()                             │
  │    scan up to PF_EMERGENCY_SCAN_MAX (64) LRU head entries        │
  │    evict those with eff==0 or idle >= eff                        │
  │    returns freed count; 0 ──► NF_DROP at caller                 │
  └─────────────────────────────────────────────────────────────────┘
```
