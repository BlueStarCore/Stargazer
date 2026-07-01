# Stargazer NGFW — Full IPS Pipeline Workflow (ipsd + ssld + ML)

This document describes the **actual runtime path** (read from the codebase) a flow
takes through the IPS subsystem, unifying three features that share one engine:

- **IPS** — signature inspection (Aho-Corasick on reassembled streams).
- **SSL inspection** — TLS MITM (`ssld`) so the engine can see HTTPS plaintext.
- **ML** — LightGBM flow-anomaly scoring (tl2cgen-compiled C).

Sources: `src/modules/pkt_forward.c`, `src/userspace/mgmtd/mgmtd_apply_*.c`,
`src/userspace/ipsd/*`, `src/userspace/ssld/*`, `Machine Learning/*`.

---

## 1. Architecture principles

- **`nf_conntrack` is the single source of truth** for every flow: state + NAT +
  `CTA_ML` (raw feature accumulator) + `connmark` (policy_id, DIRTY,
  IPS_BLOCK/INSPECTED, IPS profile id).
- The **kernel only taps features and drops L3/L4 anomalies**. All
  signature/ML *decisions* happen in **userspace** (`ipsd`), enforced back via
  `connmark` + iptables, or (HTTPS) via an IPC verdict to `ssld`.
- There are **two payload-inspection doors sharing one engine**:
  - **Cleartext / non-TLS** → NFQUEUE → `ipsd` main loop.
  - **HTTPS** → REDIRECT → `ssld` decrypts → plaintext over AF_UNIX → `ipsd` insp server.
- **ML scores a 14-feature vector** (not raw packets), **once per flow**.
- **Fail-safe / fail-closed:** no IPS policy → no NFQUEUE emitted → `ipsd` idle.
  SSL inspection off → `ssld` not launched. CA write failure → splice-only.

---

## 2. Top-level diagram

```
                 WAN  ⇄  [ BPI-R4 / StargazerOS ]  ⇄  LAN
═══════════════════════════ KERNEL DATA-PLANE ═══════════════════════════
 FORWARD packet
   │
   ├─▶ pkt_forward.ko (NF_INET_FORWARD)
   │     • Anomaly screen: Land, source-route, NULL/XMAS/FIN scan,
   │       SYN+data, Ping-of-Death  → NF_DROP (no state, no log)
   │     • ml_account(): tap features → conntrack NF_CT_EXT_ML (CTA_ML)
   │
   ├─▶ nf_conntrack : flow state + CTA_ML + ACCT counters + connmark
   │
   └─▶ iptables FORWARD  (mgmtd_apply_firewall.c)
         • fast-path: ESTABLISHED & !DIRTY → ACCEPT (skip inspection)
         • connmark has IPS_BLOCK? → DROP (flow already convicted)
         • policy ACCEPT + ips-profile≠none → MARK = profile-id, then:
              ├─ TLS:443 + SSL inspection active → REDIRECT → ssld ──────┐
              └─ else → connbytes 0:16K both → NFQUEUE Q# ─────────────┐ │
                        (first window only; window exhausted → offload) │ │
══════════════════════════════════════════════════════════════════════ │ │
 USERSPACE                                                              │ │
                                                                        │ │
  ┌── ssld (one process per SSL-inspection profile) ◀────────────────────┘
  │   1) tls_clienthello.c: peek ClientHello, extract SNI (no OpenSSL)
  │   2) tls_policy.c: SNI ∈ bypass list → SPLICE, else → BUMP
  │   3) BUMP: ca.c/certcache.c forge leaf (CN/SAN=SNI) signed by Stargazer CA;
  │            bump.c: SSL_accept(client, fake) + SSL_connect(origin, VERIFY_PEER)
  │            → plaintext both directions (fail-closed if origin cert bad)
  │      │
  │      ├─▶ INSP_OPEN  {srv_ip/port (orig dst), SNI, leg client→ssld}
  │      ├─▶ INSP_DATA  {dir, plaintext chunk ≤16K}   (AF_UNIX SEQPACKET)
  │      └─▶ INSP_CLOSE
  │      ◀── INSP_VERDICT {PASS|ALERT|DROP, src(sig/ML), score, sid, msg}
  │            DROP → block page / RST to client;  ALERT → log
  │                                                       │
  │                       ┌───────────────────────────────▼──────────────┐
  │                       │ ipsd insp_ipc server (1 handler thread / flow)│
  │                       │  reass + streaming AC + verify + flowbits     │ ◀─ L2 sig
  │                       │  prof_id ← CTA_MARK of (client→server) tuple   │
  │                       │  ML: ctdump(client→server) → feature → score  │ ◀─ ML (HTTPS)
  │                       └──────────────────────────────────────────────┘
  │
  └── ipsd NFQUEUE main loop ◀────────────────────────────────────────────┘
        process_packet():
          [0] SYN fwd packet → ml_iwin_put: cache Init_Win_bytes_forward
          [1] ctdump_query (ctnetlink) → CTA_ML + ACCT of THIS flow
                 → ctdump_to_features → feat[14]
          [2] cascade: L2 content signature (reass + AC on REASSEMBLED stream)
                 └─ ML CHECKPOINT (only if no sig match & !ml_done):
                       trigger = FIN/RST | N≥pkts | B≥bytes | age≥T
                       → ips_score(feat) → ips_fuse → ml_done=1
          [3] verdict → nfq_verdict(ACCEPT) + connmark:
                 DROP → IPS_BLOCK (leading DROP rule kills whole flow)
                 benign ML → IPS_INSPECTED (offload, stop queueing)
          [4] log_alert → shared alert file

  Shared engine : reass.c · ac.c · sig_rule.c · fusion.c · model/predict.c
  Shared alerts : ipsd + ssld → /etc/stargazer/logs/ips-alert.log
                  → `execute diagnose ips alerts`
  Scores        : /run/stargazer-ipsd.scores → `execute diagnose ips scores`
```

---

## 3. Stage-by-stage

### 3.1 Kernel data-plane — `pkt_forward.ko`
Netfilter `NF_INET_FORWARD` hook, per packet:
1. IPv4 validation; pull TCP header linear.
2. **Anomaly screen** (`is_ip_anomaly`/`is_tcp_anomaly`/`is_icmp_anomaly`):
   Land, LSRR/SSRR source routing, NULL/XMAS/FIN scans, SYN+data, Ping-of-Death
   → `NF_DROP`. Increments `pkts_anomaly_dropped` (one aggregate counter; **no
   per-packet log, no per-type attribution** — visible only at
   `/proc/stargazer/pkt_forward_stats`).
3. **`ml_account()`** — accounts per-flow features into `NF_CT_EXT_ML`
   (`struct nf_conn_ml`): IAT sum/sq/min, packet-length sum/sq, per-direction
   bytes, TCP flag counts, len min/max. Integer/fixed-point only (no floats in
   kernel); consumers derive mean/variance. Mutations under `ct->lock`.

Exported to userspace as binary attribute **`CTA_ML`** (=27) on the ctnetlink
dump path. Userspace mirrors the struct as `sg_nf_conn_ml` — **layouts must stay
field-for-field identical**.

### 3.2 iptables gating — `mgmtd_apply_firewall.c` / `mgmtd_apply_ips.c` / `mgmtd_apply_ssl.c`
Decides whether a flow even reaches an inspector:
- **Fast-path:** `ESTABLISHED && !DIRTY` → `ACCEPT`.
- **`connmark IPS_BLOCK`** → `DROP`.
- **Policy ACCEPT + ips-profile≠none** → `MARK = profile-id`, then either:
  - **TLS:443 with SSL inspection active** → `REDIRECT` to the profile's `ssld`
    port (BASE+idx). A flow that is REDIRECTed **never hits the FORWARD NFQUEUE
    rule**.
  - **else** → `connbytes 0:16K both → NFQUEUE Q#`. Only the first ~16 KB window
    of each flow is queued; window exhausted → offloaded. Cost scales with **new
    flows**, not bandwidth.
- **Per-policy IPS profile id** is stamped into the connmark (bits 3–7). For the
  redirected (ssld) leg it is stamped in the `SG_SSLD` chain (filter INPUT),
  because that leg never traverses the FORWARD MARK rule.
- Ruleset compiled per profile (`mgmtd_ips_compile.c`): dedup by **SID**, AC
  merges duplicate prefixes/patterns; per-profile selection + action maps in
  `/etc/stargazer/ips/profiles/<id>.rules` ("sid action").

### 3.3 Cleartext door — `ipsd` NFQUEUE main loop (`main.c`)
Per queued packet (`process_packet`):
0. SYN-forward → `ml_iwin_put` caches `Init_Win_bytes_forward` (conntrack dump
   does not carry the TCP window).
1. `ctdump_query` (ctnetlink) → this flow's `CTA_ML` + `ACCT` → `feature_extract`
   → `feat[14]` in CICFlowMeter order.
2. **Decision cascade** (`ips_evaluate_full`, `engine.c`):
   - **L1 removed** — the old flow-anomaly / no-content "L1" layer was deleted
     (it flagged every new connection as an unfinished handshake → mass FPs).
   - **L2 content signature** — reassembly (`reass.c`) + **streaming
     Aho-Corasick** (`ac.c`) on the **reassembled stream**, then offset/PCRE
     verify (`sig_rule.c`). A match **short-circuits** (skips ML).
   - **ML checkpoint** — only if no signature matched and `!ml_done`. Fires once
     per flow at `FIN/RST` or `N≥pkts | B≥bytes | age≥T`.
3. **Verdict + connmark:** DROP → set `IPS_BLOCK`; benign ML → `IPS_INSPECTED`
   (offload). `nfq_verdict(ACCEPT)` for the packet itself; the leading
   connmark-DROP rule enforces the kill on subsequent packets.
4. `log_alert` → shared file.

### 3.4 HTTPS door — `ssld` (`ssld/main.c`, `conn.c`, `bump.c`, `ca.c`, `tls_policy.c`)
One process per SSL-inspection profile, one thread per connection:
1. `origdst_get` (SO_ORIGINAL_DST) recovers the real server (REDIRECT hides it).
   Loop-guard rejects connections whose origdst == ssld's own listen address.
2. `peek_clienthello` → `tls_clienthello.c` parses the ClientHello byte-by-byte
   (no OpenSSL, bounds-checked) → **SNI**.
3. `tls_policy_decide(SNI)`:
   - no SNI → BUMP (or SPLICE if `no-sni=splice`),
   - SNI ∈ bypass list (exact or `*.domain`) → **SPLICE** (raw relay),
   - else → **BUMP**.
4. **BUMP:** forge a leaf cert (CN/SAN=SNI) via `ca.c`/`certcache.c`, signed by
   the **persistent Stargazer CA** (`/etc/stargazer/ssl/ca-{cert,key}.pem`,
   generated once, reused across restarts). `bump.c`: `SSL_accept` to client +
   `SSL_connect` to origin (`VERIFY_PEER`, fail-closed). Decrypts both ways.
5. Pushes plaintext to `ipsd` via **INSP_OPEN / INSP_DATA / INSP_CLOSE** and
   blocks on **INSP_VERDICT** (inline prevent). DROP → block page / RST.

**SSL inspection modes** (config `security_ssl-inspection-profile inspection-mode`):

| Mode | Steer (REDIRECT)? | ssld | Decrypt? | Payload sig / ML |
|---|---|---|---|---|
| `no-inspection` | No | not involved | No | none (flow may still hit NFQUEUE if IPS on → ML on encrypted metadata) |
| `certificate` | Yes (always) | `-S` splice-only | No | none (SNI visible only) |
| `deep` | Yes, **iff policy IPS on** | bump | **Yes** | full L2 sig + ML on decrypted leg |

### 3.5 IPC bridge — `ipsd` insp server (`insp_ipc.c`)
AF_UNIX SOCK_SEQPACKET at `/run/stargazer-ipsd-insp.sock`. Each ssld connection =
one handler thread owning a virtual flow:
- `INSP_OPEN` fixes `proto/dport/prof_id`. ssld sends `profile_id=0`; ipsd
  **recovers the real IPS profile id from the connmark** of the redirected flow.
  > **Tuple note (fixed):** the connmark/CTA_ML lookup keys on the **ORIGINAL
  > conntrack tuple `(client → server:443)`** — the pre-DNAT destination — *not*
  > `(client → firewall:ssld_port)`, which matches no tuple. Using the wrong
  > tuple left `prof_id=0`, so per-profile `block` silently downgraded to the
  > rule's base action (alert).
- `INSP_DATA` → reass + streaming AC + verify (same engine as the NFQUEUE path),
  per-profile action via `sig_eff_action(rule, prof_id)`; `fidelity` cap may
  force ALERT for rules with unsupported keywords.
- If no signature matched → **ML checkpoint** on the leg's `CTA_ML`
  (`INSP_ML_PKTS=24` / `INSP_ML_BYTES=14000`), scored once.
- Returns `INSP_VERDICT {action, src (0=sig / 1=ML), score, sid, msg}`. ssld logs
  with the matching reason vocabulary (`signature` vs `ml-alert`/`ml-block`).

### 3.6 Signature engine internals (shared)
- `reass.c` — byte-window reassembly (handles patterns spanning packets/TLS records).
- `ac.c` — Aho-Corasick automaton, streaming match over the reassembled bytes.
- `sig_rule.c` — Snort/Suricata-style rule parse + match: `content` (with
  `|hex|`, nocase, offset/depth/distance/within), sticky buffers
  (`http_uri/header/method/body`, **`tls.sni`**), PCRE (libpcre2, JIT off),
  byte_test/byte_jump, flowbits, flow direction.
  - **Fidelity:** unsupported narrowing keyword → rule clamped to
    `SIG_FID_ALERT` (may only ALERT, never DROP) — never enforce a constraint
    the engine can't fully evaluate.
  - **Per-profile action:** `base_action` (rule's own) + `prof_mask` (which
    profiles include it) + `prof_drop_mask` (which selected DROP). `sig_eff_action`
    resolves DROP/ALERT for the flow's `prof_id`.
- `fusion.c` — merges signature + ML: signature wins; ML only runs when nothing
  matched. `score ≥ thr_block` → DROP, `≥ thr_alert` → ALERT.

### 3.7 ML pipeline
**Offline** (`Machine Learning/`):
- `stargazer_train_export.ipynb` trains a **LightGBM** model → `stargazer_ids*.txt`.
- `feature_order.json` is the **feature-order contract** (14 features → being
  extended to 17 for Infiltration: + Total Length Fwd/Bwd, Flow Duration).
- Treelite/tl2cgen compiles the model to pure C → `ipsd/model/predict.c`.

**Online** (`ipsd`):
1. `feature.c` builds `feat[14]` from three sources: `CTA_ML` (kernel tap),
   `ACCT` counters (`pkts_fwd/bwd`), cached `init_win`. Order **must** match
   `feature_order.json`.
2. `ips_model.c` `ips_score(feat)` → `predict(pred_margin=0)` → sigmoid →
   probability ∈ [0,1].
3. Scored **once per flow** at the checkpoint. `fusion.c` decides PASS/ALERT/DROP.

> **Known caveat:** ML on the **HTTPS leg** scores the *client→ssld proxy leg*,
> whose features differ from the end-to-end flows the model trained on → risk of
> systematic false positives (e.g. a near-constant score on normal HTTPS).
> Consider disabling ML on the insp path, raising insp thresholds, or retraining
> on leg features.

---

## 4. Enforcement & connmark bits

| Bit(s) | Meaning | Set by | Read by |
|---|---|---|---|
| bit 0 | DIRTY (policy changed) | mgmtd on policy change | FORWARD fast-path |
| bits 8–31 | policy_id | iptables MARK | policy re-eval |
| bits 3–7 | IPS profile id | FORWARD MARK / `SG_SSLD` CONNMARK | ipsd (`sig_eff_action`, insp prof_id) |
| IPS_BLOCK | flow convicted → kernel DROP | ipsd after DROP verdict | FORWARD leading rule |
| IPS_INSPECTED | benign → stop queueing | ipsd after benign ML | NFQUEUE gate |

- **Cleartext DROP** is enforced in-kernel via `IPS_BLOCK` connmark.
- **HTTPS DROP** is enforced by `ssld` (block page / RST) from the `INSP_VERDICT`
  — it does not need `IPS_BLOCK`.

---

## 5. Observability

- **Alerts:** `ipsd` (NFQUEUE) and `ssld` (HTTPS) append to the **same file**
  `/etc/stargazer/logs/ips-alert.log` → `execute diagnose ips alerts`.
  Line format: `TS ACTION proto=6 src=… dst=… reason=… score=… sid=… msg=…`
  - `reason=signature` → signature match (`sid≠0`, `score=n/a`).
  - `reason=ml-alert` / `ml-block` → ML detection (`sid=0`, numeric score).
- **Scores:** `ml_record_score` → `/run/stargazer-ipsd.scores` →
  `execute diagnose ips scores`.
- **Kernel anomaly drops:** `/proc/stargazer/pkt_forward_stats` (aggregate only).

---

## 6. Cost / gating summary

- **No IPS policy** → no NFQUEUE → `ipsd` idle → ~0 cost.
- **IPS on** → base RAM (AC automaton) + CPU per **new flow** (16 KB window +
  connmark fast-path), not per bandwidth.
- **SSL inspection on** → one `ssld` per profile → crypto CPU + TLS state per
  **concurrent HTTPS connection**; off → HTTPS untouched.

---

## 7. File reference

| Stage | File |
|---|---|
| Anomaly screen + CTA_ML tap | `src/modules/pkt_forward.c` |
| Kernel feature struct | `../stargazer-kernel/include/net/netfilter/nf_conntrack_ml.h` |
| iptables policy + NFQUEUE + connmark | `src/userspace/mgmtd/mgmtd_apply_firewall.c` |
| IPS steering + per-profile compile | `src/userspace/mgmtd/mgmtd_apply_ips.c`, `mgmtd_ips_compile.c` |
| SSL steering + ssld lifecycle + profid connmark | `src/userspace/mgmtd/mgmtd_apply_ssl.c` |
| NFQUEUE loop + cascade + ML checkpoint | `src/userspace/ipsd/main.c` |
| ctnetlink CTA_ML/ACCT/CTA_MARK reader | `src/userspace/ipsd/ctdump.c` |
| 14-feature vector | `src/userspace/ipsd/feature.c` |
| Signature engine | `reass.c`, `ac.c`, `sig_rule.c` |
| Sig + ML fusion | `src/userspace/ipsd/fusion.c` |
| LightGBM model (tl2cgen) | `src/userspace/ipsd/ips_model.c`, `model/predict.c` |
| HTTPS↔ipsd IPC server | `src/userspace/ipsd/insp_ipc.c`, `insp_ipc.h` |
| SNI parser | `src/userspace/ipsd/tls_clienthello.c` |
| SPLICE/BUMP policy | `src/userspace/ipsd/tls_policy.c` |
| ssld bump / conn / CA | `src/userspace/ssld/bump.c`, `conn.c`, `ca.c`, `certcache.c` |
| Offline ML training/export | `Machine Learning/stargazer_train_export.ipynb`, `feature_order.json` |
```
