# Stargazer NGFW — Chế độ "Protecting Server" (Reverse TLS Inspection + IPS/ML)

> Tài liệu tổng hợp toàn bộ codebase liên quan tới chế độ **protecting-server**:
> control-plane (cấu hình + áp rule), data-plane (kernel), ssld (reverse TLS MITM),
> ipsd (signature + ML). Mọi tham chiếu đều ghi `file:line` để tra ngược.
>
> Cập nhật: 2026-06-24. Nguồn: đọc trực tiếp source `src/userspace/{ssld,ipsd,mgmtd,cli,common,webd,webui}`,
> `src/modules/pkt_forward.c`, và các doc `docs/ips-*.md`, `Phase/phase2.md`, `Phase/phase4-ips-ssl-ipc.md`.

---

## 1. Khái niệm: Forward bump vs Protecting-server (reverse)

Stargazer có **một engine inspection**, dùng cho hai hướng TLS khác nhau:

| | **multiple-clients** (forward bump) | **protecting-server** (reverse) |
|---|---|---|
| Hướng traffic | Outbound: client nội bộ → Internet | Inbound: client ngoài → server nội bộ |
| Cert trả cho client | **Giả mạo** (forge leaf ký bằng CA của Stargazer) | **THẬT** (cert/key của server được import) |
| Client cần cài CA? | Có | **Không** (client validate cert thật như bình thường) |
| Đích re-encrypt | Original dst (`SO_ORIGINAL_DST`) | Backend nội bộ (`protect-backend`) từ revmap |
| Cờ ssld | (mặc định, forge) | `-S` (tắt forge) `-R <revfile>` |
| Trigger | SNI bypass list | Khớp revmap (VIP:port [+SNI]) |

Sơ đồ reverse (trích `src/userspace/ssld/revmap.h:5-12`):

```
external client ──TLS#1 (REAL server cert)── ssld ──TLS#2── internal backend
                                              │
                                         plaintext → inspect() → ipsd
```

Điểm cốt lõi: ssld đóng vai **reverse proxy MITM**. Nó kết thúc TLS với client bằng
**chứng chỉ thật của server** (nên client không cần cài CA), giải mã, soi plaintext qua
ipsd, rồi mã hoá lại tới backend nội bộ.

---

## 2. Bản đồ thành phần

| Lớp | Thành phần | File chính | Vai trò trong protecting-server |
|---|---|---|---|
| Control | CLI / WebUI | `cli/cli_configure.c`, `webui/www/home.html`, `js/app.js` | Nhập profile, ẩn/hiện field theo mode |
| Control | Validation | `common/sg_validate.c` | Schema `security_ssl-inspection-profile`, lọc field theo mode |
| Control | mgmtd | `mgmtd/mgmtd_apply_ssl.c`, `mgmtd_apply_nat.c`, `stargazer-mgmtd.c` | Sinh REDIRECT, viết revmap, spawn ssld, import cert |
| Data (kernel) | `pkt_forward.ko` | `modules/pkt_forward.c` | Anomaly screen + nạp đặc trưng ML vào conntrack ext |
| Data (kernel) | conntrack ML ext | `../stargazer-kernel/.../nf_conntrack_ml.h` | `nf_conn_ml` per-flow, export `CTA_ML` |
| Proxy | ssld | `ssld/{main,conn,bump,revmap,origdst}.c` | Reverse TLS terminate, giải mã, đẩy plaintext qua IPC |
| Detection | ipsd | `ipsd/{main,insp_ipc,feature,ml_eval,fusion}.c`, `ipsd/ac.c`, `ipsd/sig_rule.c`, `ipsd/model/predict.c` | Signature (Aho-Corasick) + ML (LightGBM), trả verdict |

---

## 3. Schema cấu hình (`security_ssl-inspection-profile`)

Định nghĩa: `src/userspace/common/sg_validate.c:137-159`. Lọc field theo mode:
`sg_ssl_field_allowed()` tại `sg_validate.c:814-844` (CLI và Web cùng enforce).

**Field chung:**
- `name` (safe-id, bắt buộc), `status` (enable/disable), `comment`
- `inspection-mode` = `multiple-clients` | `protecting-server` (mặc định `multiple-clients`)
- `exempt` (danh sách SNI bỏ qua)

**Chỉ protecting-server:**
- `server-cert` → ref tới `system_certificate` (cert/key thật của server)
- `protect-vip` (ipv4) — IP/VIP mà client ngoài truy cập
- `protect-backend` (ipv4) — server thật nội bộ
- `protect-backend-port` (1..65535, mặc định 443)
- `protect-sni` (tuỳ chọn) — ghim theo SNI

**Chỉ multiple-clients:** `inspection-method`, `no-sni`, `untrusted-server-cert`,
`unsupported`, `block-sni`.

Cấu hình mẫu (CLI):
```
config security ssl-inspection-profile web-protect
    set inspection-mode protecting-server
    set server-cert real-server-cert
    set protect-vip 203.0.113.10
    set protect-backend 10.0.0.20
    set protect-backend-port 443
next
```
Rồi gán profile vào một firewall policy `action accept` với `set ssl-profile web-protect`
(và `set ips-status enable` + `set ips-profile <id>` để bật IPS).

---

## 4. Control-plane: mgmtd áp cấu hình

Khi `SG_CMD_CFG_SET` ghi profile (`stargazer-mgmtd.c:5258-5900`), thay đổi profile kích hoạt
rebuild NAT + FORWARD và `ssld_sync()` (`stargazer-mgmtd.c:5823-5900`). Trình tự:

### 4.1 Sinh rule REDIRECT (nat PREROUTING)
`emit_ssl_steering()` — `mgmtd_apply_ssl.c:152-213`. Với mỗi firewall policy `accept`+`enable`
có `ssl-profile` hợp lệ và IPS bật (`ssl_steer_allowed`):

```
-A PREROUTING [-i <srcintf>] [-d <protect-vip>] -p tcp --dport 443 -j REDIRECT --to-ports <8443+idx>
```

- **Scope theo VIP** (`mgmtd_apply_ssl.c:189-205`): protecting-server bắt buộc thêm `-d <protect-vip>`,
  nếu không rule sẽ tóm **mọi** :443 trên interface → forge cert sai cho dịch vụ khác.
- Mỗi profile bật được cấp cổng `ssld_port = 8443 + index`.
- Rule nhúng atomic vào `*nat` restore (`mgmtd_apply_nat.c`, `iptables-restore --noflush`).

### 4.2 Mở INPUT cho cổng ssld
`ssld_input_access_sync()` — `mgmtd_apply_ssl.c:313-417`. Sau REDIRECT gói trở thành local-dest
tới `firewall:ssld_port`; chain `SG_SSLD` (jump ở đầu INPUT) ACCEPT các gói này, và có thể
stamp connmark IPS profile id.

### 4.3 Viết reverse map cho ssld
`write_reverse_to()` — `mgmtd_apply_ssl.c:240-259`. Ghi `/etc/stargazer/ssl/reverse-<profile>.rev`:
```
<vip>:443 <cert.pem> <key.pem> <backend_ip>:<bport> <sni|->
```
Thiếu field bắt buộc → trả -1 → bỏ `-R` → ssld chạy không inspect inbound (fail-safe, server vẫn reachable).

### 4.4 Spawn ssld
`ssld_sync()` — `mgmtd_apply_ssl.c:426-633`. Một ssld instance / profile, cổng `8443+idx`.
Với protecting-server (`mgmtd_apply_ssl.c:568-576`):
- `-S` — **tắt forward-forge** (chỉ reverse + splice), bất kỳ thứ gì không khớp VIP/thiếu cert → splice (không forge sai).
- `-R <revfile>` — nạp reverse map.
- `-c SSL_CACERT -k SSL_CAKEY` — CA (dùng cho forward mode; reverse không forge nên không cần).

### 4.5 Import chứng chỉ server
`handle_cert_import()` — `mgmtd_apply_ssl.c:692-782`, lệnh `SG_CMD_CERT_IMPORT` (695).
PEM được stage, validate, copy vào `/etc/stargazer/ssl/certs/<name>/{cert.pem,key.pem}`,
metadata lưu bảng `system_certificate`; nếu có profile protecting-server tham chiếu → `ssld_sync()`.

---

## 5. PIPELINE protecting-server (sơ đồ tổng)

```
                                         ┌──────────────────── CONTROL PLANE ────────────────────┐
  Admin (CLI / WebUI)                    │ sg_validate schema ─► mgmtd_apply_ssl:                  │
     │  config ssl-inspection-profile    │   • REDIRECT nat PREROUTING -d VIP --dport443 →:8443+i  │
     ▼  (mode=protecting-server, cert,   │   • /etc/stargazer/ssl/reverse-<prof>.rev              │
   mgmtd  vip, backend, port)            │   • spawn ssld -S -R <rev>                              │
                                         └────────────────────────────────────────────────────────┘

  ── DATA PLANE (một kết nối inbound HTTPS) ───────────────────────────────────────────────────────

   External client                BPI-R4 (Stargazer)                                Internal backend
   203.0.113.x  ──TLS#1──►  ┌───────────────────────────────────────────────┐  ──TLS#2──►  10.0.0.20:443
   (HTTPS→VIP:443)          │                                                 │
                            │ [nat PREROUTING] REDIRECT --dport443 -d VIP     │
                            │        → local :8443+idx (ssld)                 │
                            │                                                 │
                            │ ┌─────────────────── ssld ───────────────────┐ │
                            │ │ accept()                main.c:237          │ │
                            │ │ origdst_get(SO_ORIGINAL_DST) conn.c:605     │ │  ← học VIP:port client nhắm tới
                            │ │ peek_clienthello (MSG_PEEK) conn.c:631      │ │  ← rút SNI (không tiêu thụ ClientHello)
                            │ │ revmap_match(vip,port,sni)  revmap.c:153    │ │  ← tra rev_server: cert/key thật + backend
                            │ │ bump_run(reverse=1)         bump.c:106      │ │
                            │ │   • connect_tcp(backend)    bump.c:121      │ │  ──► TCP tới 10.0.0.20:443
                            │ │   • TLS#2 client-side       bump.c:152      │ │  ──► handshake với backend (TLS thật)
                            │ │   • TLS#1 server-side: dùng CERT THẬT       │ │  ◄── handshake với client bằng cert thật
                            │ │       SSL_CTX_use_certificate bump.c:170    │ │
                            │ │   • pump_ssl 2 chiều        bump.c:214-253  │ │
                            │ │       SSL_read → PLAINTEXT                   │ │
                            │ │       conn_inspect(buf,dir) conn.c:410      │ │
                            │ │         └─ cửa sổ 16KB/chiều rồi offload     │ │
                            │ └──────────┬──────────────────────────────────┘ │
                            │            │ AF_UNIX SOCK_SEQPACKET              │
                            │            │ /run/stargazer-ipsd-insp.sock       │
                            │            │ INSP_OPEN / INSP_DATA(plaintext)    │
                            │            ▼                                     │
                            │ ┌─────────────────── ipsd ───────────────────┐ │
                            │ │ insp_conn_thread        insp_ipc.c:211      │ │
                            │ │ ① SIGNATURE: reass + Aho-Corasick streaming │ │
                            │ │      ac_search_stream → sig_verify          │ │
                            │ │ ② ML (leg client→ssld):                     │ │
                            │ │      ctdump CTA_ML(tuple gốc) insp_ipc:115  │ │
                            │ │      feature_extract (17 feat) feature.c:50 │ │
                            │ │      ips_score → predict() (LightGBM)       │ │
                            │ │      ips_fuse(sig,ml,thr)     fusion.c      │ │
                            │ │ ③ verdict ──────────────────────────────►  │ │
                            │ └──────────┬──────────────────────────────────┘ │
                            │            │ INSP_VERDICT {PASS|ALERT|DROP}      │
                            │            ▼                                     │
                            │ ssld nhận verdict (conn.c:382):                 │
                            │   DROP → block page HTTP 403 (nếu chưa gửi byte)│
                            │          conn.c:560 ssld_send_block_page         │
                            │          + log ips-alert.log                     │
                            │   PASS/ALERT → relay tiếp 2 chiều               │
                            └─────────────────────────────────────────────────┘
```

---

## 6. ssld — chi tiết reverse MITM

File: `src/userspace/ssld/{main,conn,bump,revmap,origdst}.c`.

### 6.1 Accept & nhận diện đích
- `make_listener()` bind `INADDR_ANY:<port>` — `main.c:77-99`; accept loop `main.c:236-255`,
  mỗi conn một detached pthread → `ssld_handle_conn()` `conn.c:598`.
- `origdst_get()` — `origdst.c:11-22`, `getsockopt(SOL_IP, SO_ORIGINAL_DST)` lấy VIP:port gốc
  trước REDIRECT. Có guard chống loop nối thẳng vào cổng ssld (`conn.c:616-624`).
- `peek_clienthello()` — `conn.c:207-229`, dùng `MSG_PEEK` (không tiêu thụ) → `tls_parse_clienthello`
  rút SNI. Byte vẫn nằm trong socket buffer cho handshake sau.

### 6.2 Quyết định reverse
`conn.c:639-673`: nếu có `ctx->revmap` → `revmap_match(vip, port, sni)` (`revmap.c:153-170`,
khớp `vip==0||==dst` && `vport==0||==dport` && `sni==""||==sni`). Khớp → dựng `insp_ctx`,
mở IPC (`ssld_ipc_open`, `conn.c:428-467`), cấu hình `bump_cfg{ reverse=1, srv_cert, srv_chain,
srv_key, upstream=&rev->backend, inspect=conn_inspect, on_block=conn_on_block }` rồi `bump_run`.

### 6.3 bump_run reverse
`bump.c:106-265`:
1. Kết nối backend `connect_tcp(upstream)` `bump.c:121`; TLS#2 client-side handshake `bump.c:127-152`
   (`verify_upstream=0` vì backend nội bộ tin cậy).
2. TLS#1 server-side: **dùng cert/key thật** `SSL_CTX_use_certificate/PrivateKey` `bump.c:170-171`,
   gửi kèm chain `add_extra_chain_cert` `bump.c:182`; `SSL_accept` với client `bump.c:205`.
   (Forward mode `bump.c:184-199` mới forge cert qua `certcache_get`.)
3. Pump 2 chiều `bump.c:214-253` qua `pump_ssl()` `bump.c:65-90`: `SSL_read` → plaintext →
   gọi `cfg->inspect(buf, n, to_server, ud)`; trả `-2` nghĩa là BLOCK. Nếu không block → `SSL_write` sang đầu kia.
4. Block page: `bump.c:244-252`, chỉ chèn khi **chưa có byte response nào tới client** (`cli_written==0`).

### 6.4 Đẩy plaintext qua IPC
`conn_inspect()` `conn.c:410-423`: giới hạn **cửa sổ 16KB/chiều** (`INSP_WINDOW`), quá thì offload (return 0).
Trong cửa sổ → `conn_inspect_ipc()` `conn.c:358-403`: gửi `INSP_DATA{dir, chunk_id, len, plaintext}`
qua `/run/stargazer-ipsd-insp.sock` rồi **blocking** `recv` verdict (`conn.c:381-382`).
Không IPC (`-no-ipc`) → fallback `conn_inspect_local()` `conn.c:338-353` chạy `sig_match` per-chunk tại chỗ.

`ssld_ipc_open()` `conn.c:428-467` gửi `INSP_OPEN{srv_ip, srv_port, profile_id, sni, leg_cli_ip/port, leg_fw_ip/port}` —
leg tuple cần cho ML chấm trên chân client→ssld.

---

## 7. ipsd — signature + ML cho đường HTTPS

File: `src/userspace/ipsd/{main,insp_ipc,feature,ml_eval,fusion,engine}.c`, `ac.c`, `sig_rule.c`, `reass.c`, `model/predict.c`.

### 7.1 IPC server
`insp_ipc_start()` `main.c:723` → acceptor thread, mỗi kết nối một `insp_conn_thread`
(`insp_ipc.c:211-338`). Giao thức `insp_ipc.h`:
`INSP_OPEN(1)`, `INSP_DATA(2)`, `INSP_CLOSE(3)`, `INSP_SCORE(4)`, `INSP_VERDICT(128)`;
action `INSP_PASS=0 / INSP_ALERT=1 / INSP_DROP=2`, `src` 0=signature 1=ML.

### 7.2 Signature (Aho-Corasick + verify)
- `INSP_DATA` → feed reassembly + streaming AC `insp_handle_data()` `insp_ipc.c:151-206`,
  callback `insp_on_match()` `insp_ipc.c:80-105`.
- AC sparse CSR `ac.c` (`ac_search_stream` `ac.h:88`), prefilter longest content.
- `sig_verify()` (`sig_rule.c`) kiểm full rule: content/offset/depth/distance/within/flags/flowbits/http_*/tls_sni.
  Phân loại fidelity: `SIG_FID_FULL` (được DROP) vs `SIG_FID_ALERT` (chỉ alert) `sig_rule.h:63-65`.
- Khớp signature → **short-circuit**, lấy verdict signature ngay (`engine.c:57-94`).
- Sau giải mã, ipsd set `fc.dport = 80` để rule HTTP khớp (port thật giữ ở `srv_port`).

### 7.3 ML (LightGBM) — chấm trên leg client→ssld
- ipsd query `CTA_ML` của **tuple gốc** (client→server:443) qua ctdump bằng leg IP/port từ `INSP_OPEN`
  (`insp_ipc.c:115-148`). HTTPS không có plaintext-flow của riêng nó nên dùng thống kê flow gốc.
- `feature_extract()` `feature.c:50-101` dựng **17 đặc trưng** (khớp CICFlowMeter, `feature.h:19-40`):
  IAT (std/min/mean, fwd std), pktlen (var/std, fwd/bwd mean, bwd std), đếm cờ SYN/ACK/PSH/URG,
  down/up ratio, init-win fwd, total len fwd, flow duration.
- `ips_score()` → `predict()` (LightGBM xuất qua tl2cgen, `model/predict.c`) → P(attack)∈[0,1].
- Checkpoint một lần/flow tại trigger đầu tiên: ≥24 gói, ≥14KB, hoặc ≥12s, hoặc FIN/RST (`ml_eval.h:28-30`).
- `ips_fuse()` (`fusion.c`): signature thắng; nếu không có sig thì so `thr_block=0.95` (DROP) /
  `thr_alert=0.50` (ALERT); mode `detect` hạ DROP→ALERT.

### 7.4 (Đối chiếu) đường plaintext qua NFQUEUE
Traffic không-TLS đi đường khác: kernel NFQUEUE → `nfq_recv()` `main.c:818` → `process_packet()` →
`ctdump_query` → cùng feature+signature+ML → `nfq_verdict()` set connmark `IPS_BLOCK(bit1)` /
`IPS_INSPECTED(bit2)`, iptables `-m connmark 0x2/0x2 -j DROP` enforce. Protecting-server **không** đi
đường này (đã REDIRECT vào ssld), nhưng dùng chung engine.

---

## 8. Verdict & enforcement (protecting-server)

| Verdict | ipsd → ssld | Hành động ssld |
|---|---|---|
| `INSP_PASS` | action=0 | relay tiếp 2 chiều |
| `INSP_ALERT` | action=1 | relay tiếp, ghi `ips-alert.log` |
| `INSP_DROP` | action=2 | nếu chưa gửi byte cho client → `ssld_send_block_page` HTTP 403 (`conn.c:560-590`); đóng conn; log |

Khác với plaintext (enforce bằng connmark+iptables ở kernel), protecting-server enforce **trong ssld**
(đóng TLS session / chèn block page). Alert log: `/etc/stargazer/logs/ips-alert.log` (`main.c:51`),
stats IPC: `/run/stargazer-ipsd-insp.stat`.

---

## 9. Lưu ý / cạm bẫy đã biết

1. **Xung đột DNAT vs REDIRECT cho VIP được bảo vệ.** Nếu VIP còn một rule DNAT (VIP→backend) thì
   gói bị DNAT trước, REDIRECT-vào-ssld không khớp → ssld không bump (bump=0), IPS chỉ soi ciphertext.
   Khắc phục: **xoá DNAT cho VIP đang protecting-server** (để REDIRECT vào ssld đảm nhận, ssld tự
   re-encrypt tới `protect-backend`). Đây là lý do `protect-backend` tồn tại — ssld thay vai trò DNAT.
2. **ML chấm trên leg client→ssld, không end-to-end.** Đặc trưng của chân proxy lệch so với flow
   training đầy đủ → rủi ro false-positive hệ thống. Cân nhắc nâng ngưỡng hoặc retrain trên leg features.
3. **Client không cần cài CA** (ưu điểm reverse) nhưng **cert/key thật phải import đúng** qua
   `SG_CMD_CERT_IMPORT`; thiếu cert → revmap không ghi → ssld splice (không inspect) thay vì forge sai.
4. **Cửa sổ inspect 16KB/chiều.** Quá ngưỡng ssld offload (relay không soi) để giữ throughput — payload
   tấn công nằm sau 16KB sẽ lọt. Đồng nhất với cleartext window.
5. **Layout `nf_conn_ml` kernel ↔ `sg_nf_conn_ml` userspace phải khớp byte** (`_Static_assert`).

---

## 10. Bảng tra file:line

| Chức năng | File:line |
|---|---|
| Schema profile | `common/sg_validate.c:137-159`; lọc mode `:814-844` |
| Sinh REDIRECT (VIP scope) | `mgmtd/mgmtd_apply_ssl.c:152-213` (`:189-205`) |
| INPUT access SG_SSLD | `mgmtd/mgmtd_apply_ssl.c:313-417` |
| Viết revmap | `mgmtd/mgmtd_apply_ssl.c:240-259` |
| Spawn ssld (-S/-R) | `mgmtd/mgmtd_apply_ssl.c:426-633` (`:568-576`) |
| Import cert | `mgmtd/mgmtd_apply_ssl.c:692-782` |
| Rebuild trigger | `mgmtd/stargazer-mgmtd.c:5823-5900` |
| ssld accept loop | `ssld/main.c:236-255`; listener `:77-99` |
| SO_ORIGINAL_DST | `ssld/origdst.c:11-22` |
| peek ClientHello | `ssld/conn.c:207-229`, gọi `:631` |
| revmap struct/match | `ssld/revmap.h:30-39`; `revmap.c:153-170`; load `:82-151` |
| reverse decision | `ssld/conn.c:639-673` |
| bump_run reverse | `ssld/bump.c:106-265` (cert thật `:166-183`, pump `:214-253`) |
| conn_inspect / IPC | `ssld/conn.c:410-423` / `:358-403`; open `:428-467` |
| block page | `ssld/conn.c:560-590` |
| IPC proto | `ipsd/insp_ipc.h` (types/actions) |
| insp handler | `ipsd/insp_ipc.c:211-338`; data `:151-206`; ML leg `:115-148` |
| Aho-Corasick | `ipsd/ac.c`, `ac.h:88-91` |
| signature verify | `ipsd/sig_rule.c`; fidelity `sig_rule.h:63-65` |
| feature extract (17) | `ipsd/feature.c:50-101`; `feature.h:19-40` |
| ML predict / fuse | `ipsd/model/predict.c`; `ipsd/ml_eval.h:28-30`; `ipsd/fusion.c` |
| NFQUEUE (plaintext) | `ipsd/main.c:818`, `nfq.c:415-480` |
| kernel anomaly+ML tap | `modules/pkt_forward.c:50-140`, `:170-280` |
| conntrack ML ext | `../stargazer-kernel/include/net/netfilter/nf_conntrack_ml.h` |

---

*Liên quan: `docs/ips-ssl-ml-pipeline.md`, `docs/ips-pipeline-full.md`, `docs/ips-master-plan.md`,
`Phase/phase2.md`, `Phase/phase4-ips-ssl-ipc.md`.*
