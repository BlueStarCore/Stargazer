# FQDN Address Objects — DNS-Resolved Firewall Rules over ipset

> Stargazer NGFW · v0.2.1 · BPI-R4 (MT7988A, ARM64)

---

## 1. Overview

FQDN address objects let a firewall policy match a *domain name* instead of a
static IP/subnet:

```
config firewall address
  edit "example.com"
    set type fqdn
    set fqdn example.com
  next
end

config firewall policy
  edit "5"
    set dstaddr example.com
    set action drop
  next
end
```

The rule chain never changes when DNS answers change. Each fqdn-type
`firewall_address` owns one kernel `hash:ip` ipset; the FORWARD rule matches
the **set** (`-m set --match-set sgF_<object> dst`), and a refresh engine in
mgmtd keeps the set's membership in sync with DNS. Everything is in-process
raw netlink — the box carries no `ipset` binary.

What this delivers:

- **`type fqdn` on `firewall_address`** — validated by `sg_is_fqdn()`
  (RFC-1123: labels 1–63 of `[A-Za-z0-9-]`, no edge hyphens, total ≤ 253,
  ≥ 1 dot, last label not all-digits). Wildcards (`*.example.com`) are
  rejected at validation — see §7.
- **One ipset per object** — `sgF_<object>` (hashed suffix when the name
  would exceed the kernel's 31-char set-name limit), created with per-entry
  timeout support.
- **Accumulate-mode refresh** — every 60 s (and immediately after every
  chain rebuild) a detached worker resolves each object's FQDN and **merges**
  the answers into its set. Entries the resolver stops confirming expire in
  the kernel after `fqdn-ttl` seconds.
- **`fqdn-ttl` system setting** — global per-entry lifetime
  (`config system settings`, 60–86400 s, default 3600), applied to existing
  members immediately on change.
- **`execute diagnose firewall ipset <object>`** — dumps the live set:
  members, per-entry remaining lifetime, configured TTL.

## 2. Why accumulate, not replace (the round-robin lesson)

The first implementation atomically *replaced* the set with each resolve
(fill temp set → `IPSET_CMD_SWAP` → destroy temp). On-device testing against
a round-robin-DNS domain showed why that is wrong:

- The domain rotates between (at least) two addresses — call them
  `192.0.2.10` and `203.0.113.7` — one answer per query.
- Each refresh left the set holding **only the latest single answer**, while
  clients held cached answers from earlier rotations.
- Result: the DENY rule *flickered* — 7 ping packets dropped, then 7 passed
  as the set rotated under the client.

Accumulate-mode fixes this structurally:

- Every resolve **ADDs** its answers; a re-add refreshes the entry's kernel
  timeout (adds run without `NLM_F_EXCL`).
- Over a few cycles the set converges on the domain's whole rotation pool.
- Entries not re-confirmed within `fqdn-ttl` expire in the kernel — bounded
  **over-blocking** (a moved domain stays matched for at most the TTL),
  never under-blocking.

## 3. Components

| Piece | File | Role |
|---|---|---|
| Validator | `src/userspace/common/sg_validate.c` | `sg_is_fqdn()`, registry rows (`type`, `fqdn`, `fqdn-ttl`), `sg_check_entry_semantics()` (type=fqdn ⇒ fqdn set & subnet empty, and vice versa) |
| ipset ops | `src/userspace/mgmtd/mgmtd_ipset.c` | Raw NFNETLINK (`NFNL_SUBSYS_IPSET`): ensure / add / destroy / list / members; revision probe; per-entry TIMEOUT stamping |
| Refresh engine | `src/userspace/mgmtd/mgmtd_fqdn.c` | 60 s tick + post-rebuild kick; double-forked worker (init reaps); keep-alive; `fqdn_restamp_all()`; set destruction on object delete/rename |
| Rule emission | `src/userspace/mgmtd/mgmtd_apply_firewall.c` | `resolve_address_ex()` → `ADDR_IPSET` → `-m set --match-set <set> src|dst` |
| Setting | `src/userspace/mgmtd/mgmtd_apply_iface.c` | `apply_settings()` wires `fqdn-ttl` + immediate restamp |
| Diagnostics | `stargazer-mgmtd.c` (`SG_CMD_DIAG_FW_IPSET`=634), `cli_cmd_table.c` | Membership dump over `IPSET_CMD_LIST` |
| Kernel | `scripts/build_kernel.sh` | `CONFIG_IP_SET=y`, `CONFIG_IP_SET_HASH_IP=y`, `CONFIG_NETFILTER_XT_SET=y` (built-in: the flat module loader has no dependency resolution) |

The worker is double-forked (wrapper exits immediately, worker is reparented
to init) so the single-threaded mgmtd main loop never waits on DNS. The DB
snapshot happens **parent-side** — the forked child must never touch the
inherited SQLite handle. Workers self-serialize on
`/run/stargazer-fqdn.lock` (`flock` non-blocking): a slow resolver run that
outlasts the 60 s tick makes the next round skip instead of piling up
concurrent workers.

## 4. Failure semantics (fail-closed ledger)

Every failure path answers one question: *can this make a DENY rule silently
stop matching?* If yes, it is not allowed to happen quietly.

| Event | Behaviour |
|---|---|
| Resolve fails (DNS outage) | Worker re-adds the set's **current** members, refreshing their timeouts — the set never drains. Logged every failing cycle. |
| Resolve succeeds with zero A records | Treated exactly like a failure (an answer that would empty a DENY set is never trusted). |
| ipset support missing from kernel | `resolve_address_ex()` returns SKIP → the rule is omitted and logged `ERROR`. |
| `CREATE` clashes with an existing set (default-timeout differs after an `fqdn-ttl` change) | Tolerated (`EEXIST`): the create-time default never applies — every ADD stamps the entry timeout explicitly. **Not** tolerating this broke every update after a TTL change. |
| Fresh object, first resolve pending | Unenforced for < 1 s (kicked worker) — known window. |
| Object deleted / renamed | Set destroyed (`ENOENT` tolerated); rename re-kicks the refresh for the new name. |
| FQDN object in a NAT rule | SKIP, logged — DNAT/SNAT to a moving target is not meaningful. |
| `fqdn-ttl` lowered/raised | `fqdn_restamp_all()` re-adds all current members immediately with the new TTL — no waiting out the old one. |

## 5. `fqdn-ttl` tuning

```
config system settings
  set fqdn-ttl 3600        # 60 – 86400 seconds
end
```

- **Lower** → faster un-blocking after a domain moves; needs the rotation
  pool to be re-confirmed more often (refresh samples one answer per minute).
- **Higher** → better coverage of large/slow round-robin pools; longer
  over-blocking tail.
- The apply handler re-checks the range independently of the validator — a
  corrupt DB cannot set TTL 0 (0 = permanent entries = unbounded
  over-blocking).

## 6. Debugging runbook

```
stargazer> execute diagnose firewall ipset example.com
  Object : example.com
  FQDN   : example.com
  ipset  : sgF_example.com
  TTL    : 3600s (system settings fqdn-ttl)
  Members: 2

192.0.2.10  expires 3584s
203.0.113.7  expires 3569s
```

- **Set does not exist** → no FORWARD rule references the object yet
  (rules are built on policy apply).
- **Members: 0** → the resolver worker has not populated it — check
  `/var/log/stargazer-mgmtd.log` for `fqdn:` lines.
- **Rule seems not to match** → compare the set against what the *client*
  resolves (`nslookup` on the client); a missing IP there is DNS divergence
  (see §7), not a rule failure. `iptables -L FORWARD -v -n` packet counters
  prove matching.
- Standalone netlink self-test (accumulate, timeouts, EEXIST tolerance,
  hashed names): `build/sg_ipset_test` (ARM64, static), also usable as a raw
  set viewer: `sg_ipset_test list sgF_<object>`.

## 7. Known limits (and the Phase 3 answer)

- **DNS divergence**: the firewall sees its *own* resolver's answers. A
  client using a different resolver — or the same CDN domain answering by
  geography — can connect to an IP the firewall never saw. Accumulate-mode
  narrows this (the pool converges over minutes); it cannot close it.
- **DoH/DoT bypass**: a browser resolving over HTTPS gets answers the
  firewall cannot observe at all.
- **Wildcards** (`*.example.com`): periodic resolution cannot enumerate
  subdomains — rejected at validation.

All three share one fix: **DNS-response snooping** (NFQUEUE on UDP/53),
feeding the same ipsets with the answers clients actually received. That is
Phase 3 work and shares payload-inspection infrastructure with the IPS
module. ISDB-style service objects (vendor IP-range feeds / ASN prefix
lists into `hash:net` sets) are a further candidate on the same ipset
foundation.
