# Phase 4 — Hợp nhất IPS + SSL inspection qua IPC

> Stargazer NGFW · v0.2.4 · BPI-R4 (MT7988A, ARM64)

---

## 1. Tổng quan

Phase 4 nối **lưu lượng HTTPS đã giải mã** (do `ssld` thực hiện) vào **chính engine
phát hiện stateful của `ipsd`** (ráp dòng + Aho-Corasick streaming + verify đa-buffer
+ flowbits), thay cho việc `ssld` tự gọi `sig_match` rời rạc trên từng buffer
`SSL_read`. 

Nguyên tắc xuyên suốt: **mọi thay đổi là cộng thêm (additive) và có cổng bật/tắt
(gated)** — khi SSL inspection tắt (no inspection), toàn hệ thống chạy **y hệt** pipeline cleartext
hiện tại; struct chia sẻ `nf_conn_ml`/`CTA_ML` và đường NFQUEUE **không bị đụng**.

Phase này giao:

- **Kênh IPC inspection** (`ipsd` server ⇄ `ssld` client) chở plaintext + verdict.
- **Virtual flow** trong `ipsd` tái dùng nguyên `reass_flow`/`verify_rule` để soi
  plaintext HTTPS với đầy đủ trạng thái (chống né cắt-record, flowbits xuyên request).
- **(Pha 2, opt-in)** ML cho HTTPS bằng hook `LOCAL_IN` gated, **không** đổi layout
  `CTA_ML`.

---

## 2. Mục tiêu & Ràng buộc

### 2.1 Mục tiêu
- HTTPS-deep được soi bằng engine stateful đầy đủ (như cleartext), không còn soi
  per-chunk → bắt được pattern vắt qua nhiều TLS record / nhiều lần `SSL_read`.
- (Pha 2) ML cho HTTPS khả thi mà **không** sửa struct/wire-format chia sẻ.

### 2.2 Ràng buộc cứng (không-mục-tiêu)
- **KHÔNG đổi** pipeline cleartext NFQUEUE: code `process_packet`, verdict connmark,
  iptables, đều giữ nguyên.
- **KHÔNG đổi** `nf_conn_ml` / `sg_nf_conn_ml` / `CTA_ML` ở Pha 1
  (giữ `_Static_assert(sizeof(struct sg_nf_conn_ml) == 144)`).
- Tắt SSL inspection → hành vi **byte-for-byte** như hôm nay.

---

## 3. Nguyên tắc cô lập (đảm bảo "không ảnh hưởng code cũ")

| # | Cam kết | Cách đảm bảo |
|---|---|---|
| I1 | NFQUEUE path không đụng | IPC server là **thread/fd mới**, file mới `insp_ipc.c`; không sửa `process_packet` |
| I2 | Engine dùng lại read-only | virtual-flow chỉ là **caller mới** của `reass_segment`/`verify_rule`; ruleset `rwlock` đã hỗ trợ nhiều reader đồng thời |
| I3 | Struct/wire-format bất biến (Pha 1) | IPC chỉ chở plaintext + verdict; không đụng `CTA_ML` |
| I4 | Gated toàn bộ | SSL off → `ssld` không chạy → IPC im → tùy chọn không start IPC server |
| I5 | Có fallback | IPC lỗi → `ssld` quay về `sig_match` per-chunk hoặc fail-open theo config |

---

## 4. Kiến trúc thành phần

```
        ┌──────────────────────────── ipsd ────────────────────────────┐
        │  main thread (NFQUEUE)   ── KHÔNG ĐỔI ──► verdict connmark     │
        │  reload thread           ── KHÔNG ĐỔI ──► swap ruleset (rwlock)│
        │  ▲ rdlock(ruleset) dùng chung                                  │
        │  │                                                            │
        │  └─ INSPECTION thread(s)  ◄── MỚI ──►  engine (reass/AC/verify)│
        │        ▲  /run/stargazer-ipsd-insp.sock (SOCK_SEQPACKET)       │
        └────────┼──────────────────────────────────────────────────────┘
                 │ OPEN/DATA/CLOSE    ▲ VERDICT
        ┌────────┼──────────── ssld ──────────────┐     ┌─ kernel ─────────────┐
        │ proxy bump: SSL_read → IPC client →      │     │ pkt_forward FORWARD   │
        │   chờ VERDICT → SSL_write / đóng          │     │   (KHÔNG ĐỔI)         │
        │ (thay conn_inspect per-chunk)            │     │ [Pha2] LOCAL_IN hook  │
        └──────────────────────────────────────────┘     │   GATED theo SSL      │
                 ▲ REDIRECT :443                          └───────────────────────┘
        ┌─ mgmtd ─ launch ssld, bật/tắt gate, config IPC/ML ─┐
```

- `ipsd` **thêm** một (hoặc nhiều) inspection thread; main-loop NFQUEUE và reload
  thread **không đổi**.
- `ssld` **thay** `conn_inspect` (per-chunk `sig_match`) bằng IPC client.
- `pkt_forward.ko` **không đổi** trên FORWARD; Pha 2 thêm hook `LOCAL_IN` gated.

---

## 5. Kênh IPC inspection

### 5.1 Vận tải
- Unix domain socket `SOCK_SEQPACKET` tại `/run/stargazer-ipsd-insp.sock`.
- `ipsd` = server (accept trong inspection thread); `ssld` = client (một socket
  cho mỗi kết nối proxy, hoặc dùng pool).

### 5.2 Virtual flow (trong ipsd) — tái dùng `reass_flow`
```
insp_flow {
    struct reass_flow    rf;        // feed seq tăng đều → luôn contiguous, KHÔNG fail-closed
    struct flowbit_state fb;
    struct flow_ctx      fc;        // proto=TCP, dport=srv_port, prof_id, to_server theo dir
    uint32_t             next_off[2];
    uint8_t              ml_done;
}
feed: reass_segment(&rf, dir, next_off[dir], data, len, l2_on_match, &mm);
      next_off[dir] += len;
```
Plaintext đã in-order (kernel ráp TCP + OpenSSL ráp record) → seq tăng đều →
không bao giờ gap → không fail-closed. Cửa sổ 16KB áp cho plaintext **giống hệt**
cleartext (nhất quán). Toàn bộ AC streaming + `bufs_extract` (HTTP/TLS) +
`verify_rule` + flowbits được **dùng lại 100%**.

### 5.3 Giao thức
```c
/* SOCK_SEQPACKET: mỗi message = 1 datagram, không cần tự framing */
enum { INSP_OPEN=1, INSP_DATA=2, INSP_CLOSE=3, INSP_VERDICT=128 };

struct insp_hdr { uint16_t type; uint16_t flags; uint32_t conn_id; };

struct insp_open {                  // ssld → ipsd
    uint32_t srv_ip;  uint16_t srv_port;     // → fc.dport
    uint8_t  profile_id;                     // → fc.prof_id (scope rule theo profile)
    char     sni[256];                       // host cho log
    /* [Pha2] leg_tuple cho ML: */
    uint32_t leg_cli_ip; uint16_t leg_cli_port; uint16_t leg_fw_port;
};

struct insp_data {                  // ssld → ipsd ; theo sau là `len` byte plaintext
    uint8_t  dir;                   // 0=to_server, 1=to_client
    uint32_t chunk_id; uint32_t len;
};

struct insp_verdict {               // ipsd → ssld
    uint32_t chunk_id;
    uint8_t  action;                // 0=PASS, 1=ALERT, 2=DROP
    uint8_t  src;                   // 0=signature, 1=ML
    float    score;                 // điểm ML (nếu có)
    uint32_t sid; char msg[128];
};
```

### 5.4 State machine một kết nối
```
ssld: OPEN ─► (DATA ─► chờ VERDICT)* ─► CLOSE
ipsd:  alloc insp_flow ─► feed+inspect mỗi DATA ─► trả VERDICT ─► free khi CLOSE
```

### 5.5 Ngữ nghĩa inline
- **Prevent mode**: `ssld` gửi `DATA` rồi **block chờ `VERDICT`** trước khi
  `SSL_write` sang phía kia. `DROP` → đóng kết nối; else forward.
- **Detect mode**: gửi `DATA` fire-and-forget, `SSL_write` ngay; verdict async để log.

---

## 6. Hai datapath song song

| | Cleartext (HTTP / non-443) | HTTPS-deep (ssld) |
|---|---|---|
| Đường vào | NFQUEUE trên FORWARD | REDIRECT → ssld → IPC |
| Ráp dòng | ipsd tự ráp (sliding-window + bitmap) | kernel ráp TCP + OpenSSL record → virtual-flow |
| Engine | reass + AC + verify (+ ML) | **cùng** reass + AC + verify qua IPC |
| Verdict | **connmark** BLOCK / INSPECTED | **đóng kết nối** (DROP) / log (ALERT) |
| ML | có (CTA_ML flow forwarded) | Pha 2 (leg accounting) |

---

## 7. Concurrency

- `ipsd`: main(NFQUEUE) + reload + **N inspection thread**. Mỗi inspection thread
  `rdlock(ruleset)` khi soi (dùng chung với NFQUEUE — an toàn vì `verify_rule`
  read-only). `insp_flow` thuộc sở hữu thread xử lý → **không cần lock mới**.
- Reload ruleset giữa chừng: virtual-flow so `rf.ac != &rs->ac` →
  `reass_flow_rebind` (đúng như đường NFQUEUE).
- `ssld`: thread-per-conn (cũ); block round-trip IPC ở prevent mode.

---

## 8. Pha 2 — ML cho HTTPS (Đường A, gated, không đổi struct)

Ý tưởng: cho kernel tích lũy `CTA_ML` trên **leg client→ssld**; `ssld` báo tuple
leg qua IPC; `ipsd` đọc `CTA_ML` của leg như flow thường.

Leg client→ssld là proxy tốt cho flow gốc: client không biết bị proxy → gửi đúng
TLS record / kích thước / nhịp như gửi tới server thật; SYN/Init_Win của leg =
của client thật → **feature leg ≈ feature flow gốc**.

- **Kernel**: thêm hook `LOCAL_IN` gọi lại `ml_account()`, **tái dùng 14 field cũ**
  (không thêm field). **Gate** bằng cờ `ml_account_local` (sysctl / module-param);
  off → không register → kernel y hệt cũ.
- **IPC**: `INSP_OPEN` mang `leg_tuple` (ssld lấy bằng `getpeername`/`getsockname`
  trên client_fd).
- **ipsd**: trên mỗi `DATA`, nếu chưa match + `!ml_done` + đủ ngưỡng
  (N≥16 ∥ B≥14KB ∥ age≥8s) → `ctdump_query(leg_tuple)` → `ips_score` →
  `ips_fuse` → ML verdict trong `VERDICT`. `ml_done` đặt 1 lần/conn.
- **Cam kết I3 giữ nguyên**: không đụng layout `CTA_ML` (giữ `_Static_assert 144`).

> Hướng thay thế (Đường B, không đụng kernel): train model HTTPS riêng trên đặc
> trưng `ssld` có sẵn sau giải mã — JA3/JA3S, cipher, version, SNI, cert chain,
> HTTP method/URI/header, entropy body. Mạnh hơn cho mối đe dọa mã hóa, nhưng phải
> train model mới. Có thể fuse cả A + B.

---

## 9. Cấu hình (mgmtd / CLI / DB)

- `security ssl-inspection-profile` (**đã có**): `inspection-mode deep` → ssld bump → IPC.
- Cờ mới (mặc định an toàn):
  - `ips ipc-inspect enable|disable` — mặc định enable khi có ssld; disable → ssld
    fallback per-chunk.
  - `ips ipc-failmode open|closed` — mặc định **open** cho HTTPS (tránh chặn toàn
    web khi ipsd hiccup).
  - `ips ml-https enable|disable` — mặc định **disable**; bật → mgmtd set
    `ml_account_local=1` (register hook kernel).

---

## 10. Failure modes

| Sự cố | Hành xử | Ảnh hưởng cleartext IPS |
|---|---|---|
| ipsd down / socket lỗi | ssld theo `ipc-failmode` (open: forward+log / closed: drop) hoặc fallback `sig_match` | **Không** (tách biệt) |
| IPC chậm (backpressure) | ssld block → TCP flow-control → không mất gói | Không |
| Reload ruleset | rdlock + rebind virtual-flow | Không |
| Kernel hook ML off | không register | Bằng 0 (gated) |

---

## 11. Rollout theo pha

- **Pha 0 — IPC signature**: thêm IPC server (ipsd) + IPC client (ssld) thay
  `conn_inspect` per-chunk. HTTPS được soi signature **có-state đầy đủ**.
  *Pipeline cũ + struct + kernel: 0 thay đổi.*
- **Pha 1 — vận hành**: config fail-mode, telemetry, fallback per-chunk.
- **Pha 2 — ML HTTPS (opt-in)**: gated `LOCAL_IN` accounting + leg_tuple +
  checkpoint. *Reuse field, gated → cũ bất biến.*

---

## 12. Telemetry mới (không đụng cũ)

- `/run/stargazer-ipsd-insp.stat`: `conns_open`, `chunks`, `sig_hits_https`,
  `ml_hits_https`, `ipc_fail`, `blocked_https`.
- `ssld` log giữ nguyên + thêm dòng verdict đến từ IPC.

---

## 13. Verification / Regression

- **SSL off** → so byte-for-byte hành vi cũ: `/run/stargazer-ipsd.rt`, ML cleartext,
  throughput, `_Static_assert 144`. Kỳ vọng **không khác**.
- **HTTPS bump** → test pattern **vắt qua 2 TLS record** bị bắt (chứng minh state
  IPC > per-chunk cũ).
- **Fail-mode**: kill `ipsd` → `ssld` theo open/closed đúng cấu hình.
- **Pha 2**: `ml-https` off → kernel hook không register; on → leg `CTA_ML` có,
  ML chấm 1 lần/conn.

---

## 14. Rủi ro & giảm thiểu

| Rủi ro | Giảm thiểu |
|---|---|
| Đổi struct `CTA_ML` phá ML cũ | **Cấm** ở Pha 1; Pha 2 reuse field, không đổi size |
| IPC round-trip giảm throughput HTTPS | chunk 16KB (ít message), soi tới hết K, shard inspection thread |
| ipsd thành điểm chết cho cả HTTPS | fail-mode **open** mặc định + fallback per-chunk |
| Inspection thread block bởi PCRE | tách thread riêng, không đụng NFQUEUE main loop |

---

## 15. Tóm tắt

Thêm một kênh **IPC** (ipsd server thread ⇄ ssld client) để đẩy plaintext giải mã
qua **chính engine reass + AC + verify** của ipsd. Mọi thay đổi **additive + gated**
nên tắt SSL là pipeline cũ **bất biến**. ML cho HTTPS để Pha 2, dùng hook
`LOCAL_IN` gated **reuse field** — không đụng struct chia sẻ.

---

## Phụ lục A — Bảng file (dự kiến chỉnh sửa)

| File | Thay đổi | Loại |
|---|---|---|
| `ipsd/insp_ipc.c`, `.h` | server socket + protocol + bảng `conn_id→insp_flow` | **mới** |
| `ipsd/main.c` | thêm inspection thread / fd vào `select`; handler OPEN/DATA/CLOSE dùng lại `reass_segment`+`l2_on_match` | thêm (không sửa `process_packet`) |
| `ssld/conn.c` | thay `conn_inspect` per-chunk → IPC client (giữ chữ ký: trả 1=DROP) | sửa hàm cục bộ |
| `ssld/main.c` | OPEN khi vào bump, CLOSE khi xong; pool socket | thêm |
| `mgmtd/mgmtd_apply_ssl.c` | cờ `ipc-inspect`/`ipc-failmode`/`ml-https`; set `ml_account_local` | thêm |
| `../stargazer-kernel` (Pha 2) | hook `LOCAL_IN` gated, **reuse 14 field** | thêm, gated |
