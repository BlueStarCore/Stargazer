# Hướng dẫn thiết kế lại / nâng cấp IPS engine (cho AI coding agent)

> Mục tiêu: nâng `stargazer-ipsd` từ "match per-packet, tập con keyword nhỏ" lên một engine
> đủ sức nạp **toàn bộ `emerging-all.rules`** (ET Open, ~40k+ luật), match **hiệu quả + đúng
> ngữ nghĩa Snort**, chống **lỗi đầu vào** và **né tránh có chủ đích**, đồng thời **không phá
> tương thích** với pipeline + IPC + DB hiện có.
>
> Tài liệu này chia thành **gói việc (work package) tăng dần**. Mỗi gói độc lập build/test được,
> có cờ tương thích ngược. Làm theo thứ tự P0 → P6. AI agent: đọc trọn một gói trước khi code,
> tôn trọng phần "Tương thích" và "Xử lý lỗi/tấn công" — đó là điều kiện chấp nhận.

---

## 0. Hiện trạng (bám code thật)

| Thành phần | File | Hỗ trợ hiện tại |
|---|---|---|
| Parser luật | `sig_rule.c::parse_options` | `content`, `\|hex\|`, `nocase`, `offset`, `depth`, `flags`, `sid`, `rev`, `msg`. **Mọi keyword khác bị bỏ qua âm thầm** (dòng `else: field chưa hỗ trợ`). |
| Cấu trúc luật | `sig_rule.h` | `struct sig_rule` (content[], fast pattern idx, dport_list, flags_set); `struct sig_content` (data,len,nocase,offset,depth); `struct sig_flow_rule` (luật không content → L1). |
| Prefilter | `sig_rule.c::sig_build` + `ac.c` | Aho-Corasick trên **content dài nhất** mỗi luật (nocase=1 dùng làm lọc thô). |
| Verify | `sig_rule.c::verify_rule` | proto + dport + flags + **chuỗi content theo thứ tự** (biến `pos`), `offset`/`depth` tính TUYỆT ĐỐI từ đầu payload. **Không** distance/within/pcre/byte_test. |
| Match đơn vị | `main.c::process_packet` + `nfq.c` | **Per-packet**: mỗi gói NFQUEUE match payload L4 độc lập. **Không ghép luồng**. |
| Cổng vào | `mgmtd_apply_firewall.c` (~dòng 678) | `connbytes 0:N-1 --connbytes-mode packets --connbytes-dir original`, N mặc định 8. |
| Pipeline | `engine.c::ips_evaluate` | L1-builtin → L1-user → L2 (AC) → ML. Short-circuit. |
| Hạ tầng sẵn có để tái dùng | `tls_clienthello.c`, `tls_policy.c`, `ctdump.c` | Parse SNI từ ClientHello; tra trạng thái/đếm từ conntrack. |

**Vấn đề khi nạp `emerging-all.rules` hoặc (các bộ rules snort tách nhỏ theo từng loại tấn công) nguyên trạng:**
1. Luật có `distance/within/pcre/byte_test` → bị tước điều kiện thu hẹp → **match rộng hơn ý định → báo nhầm / chặn nhầm**.
2. Luật reputation (không content, danh sách IP) → rơi vào `sig_flow_rule` thành **catch-all match mọi flow** (bug đã biết).
3. Match per-packet → **né bằng cắt content qua 2 segment** (đã phân tích).
4. Cửa sổ 8 gói 1 chiều → **né bằng nhồi gói / đổi chiều / MSS nhỏ**.
5. Parser chưa hardening → luật dị dạng / hex sai / offset tràn số có thể gây lỗi.

---

## P0 — Phân loại luật + an toàn lúc nạp (NỀN TẢNG, làm trước tiên)

**Mục tiêu:** không luật nào được "match một phần mà coi như đủ"; reputation đi đúng đường; báo cáo độ phủ thật.

**File:** `sig_rule.c` (`sig_parse_line`, `parse_options`), `sig_rule.h` (struct + enum), `mgmtd_ips_compile.c` (phân loại lúc compile).

### Cấu trúc dữ liệu thêm
```c
/* sig_rule.h */
enum sig_fidelity {
    SIG_FID_FULL  = 0,   /* mọi keyword đều hỗ trợ → được DROP            */
    SIG_FID_ALERT = 1,   /* có keyword thu hẹp chưa hỗ trợ → KẸP mức ALERT */
};
/* thêm vào struct sig_rule và struct sig_flow_rule: */
uint8_t fidelity;        /* enum sig_fidelity                              */
uint8_t has_unsup;       /* bitmask keyword chưa hỗ trợ (để log/đếm)       */
```

### Logic phân loại trong `parse_options`
Khi gặp keyword, phân 3 nhóm:
- **Chú thích (bỏ qua an toàn):** `reference`, `metadata`, `classtype`, `priority`, `gid`, `target`, `msg`, `sid`, `rev`. Không ảnh hưởng match.
- **Thu hẹp điều kiện (chưa hỗ trợ ở P0):** `pcre`, `byte_test`, `byte_jump`, `distance`, `within`, `isdataat`, `dsize`, `urilen`. → set `r->fidelity = SIG_FID_ALERT` + bật bit trong `has_unsup`.
- **Cốt tử (content còn lại quá yếu):** nếu sau khi parse, luật có 0 content HOẶC chỉ 1 content `len <= 2` mà lại còn keyword thu hẹp → **trả về mã SKIP** (đừng nạp).

### Chặn catch-all (sửa bug reputation)
Trong nhánh `r->n_content == 0` của `sig_parse_line` (tạo `sig_flow_rule`):
```
NẾU proto == SIG_PROTO_ANY && n_dport == 0 && flags_set == 0:
    → KHÔNG nạp làm L1 (đây là luật reputation/IP-list hoặc luật hỏng)
    → trả mã SKIP_REPUTATION; ghi sid vào bộ đếm
```
(Đường reputation đúng = compile danh sách IP vào ipset ở `mgmtd` — xem `docs/ips-architecture-decision-record.md`. P0 chỉ cần **chặn catch-all**.)

### Đếm độ phủ (bắt buộc)
`struct sig_load_stats` thêm: `loaded_full`, `loaded_alert`, `skipped_unsupported`, `skipped_reputation`. Xuất qua IPC `SG_CMD_IPS_STATUS` để UI/CLI hiển thị "% thực sự enforce". **Đây là yêu cầu trung thực, không được giấu.**

### flowbits lan truyền (chuẩn bị cho P5)
Ở P0 chỉ cần: nếu luật dùng `flowbits` → `fidelity = SIG_FID_ALERT` (chưa theo dõi trạng thái thì không được DROP dựa trên cờ chưa có).

### Áp `fidelity` vào verdict
Trong `engine.c::ips_evaluate` (và `fusion`): khi luật khớp, nếu `rule.fidelity == SIG_FID_ALERT` thì **ép verdict tối đa = IPS_ALERT** dù action luật là DROP.

### Xử lý lỗi
- Parser phải sống sót: hex lẻ nibble, `|` không đóng, quote không cân, `offset/depth` âm hoặc > payload max, số tràn (`strtol` + range check), content > `SIG_CONTENT_MAX` (cắt + đếm error, không tràn buffer), dòng > 8KB (đã có `buf[8192]` — thêm guard nếu vượt thì SKIP).
- Một luật hỏng **chỉ bỏ luật đó**, không làm hỏng cả lần nạp.

### Test
`sig_test.c`: luật chỉ-content (FULL, DROP), luật content+pcre (ALERT-cap), luật reputation IP-list (SKIP, không catch-all), luật hex hỏng (error, không crash). Kiểm `load_stats` đếm đúng.

### Tương thích
Luật đang chạy (chỉ content) → `fidelity=FULL` → hành vi y nguyên. Chỉ thêm trường vào struct (memset=0 nên mặc định FULL). IPC chỉ **thêm** field đếm, không đổi field cũ.

---

## P1 — Ghép luồng + cửa sổ theo byte, 2 chiều, soi-lại-mỗi-transaction (DATA-PLANE)

**Mục tiêu:** đóng né tránh cắt-segment / nhồi-gói / đổi-chiều; soi trên dòng đã ghép.

**File:** mới `reass.c/.h` trong ipsd; sửa `main.c::process_packet`; sửa cổng ở `mgmtd_apply_firewall.c`; `ac.c` (thêm chế độ streaming).

### Đổi cổng kernel (mgmtd)
Thay rule connbytes:
```
# cũ: --connbytes 0:N-1 --connbytes-mode packets --connbytes-dir original
# mới:
-m connbytes --connbytes 0:K --connbytes-mode bytes --connbytes-dir both \
   -m connmark ! --mark IPS_INSPECTED -j NFQUEUE --queue-num Q
# band watch (soi quá K cho flow nghi ngờ):
-m connmark --mark IPS_WATCH -j NFQUEUE --queue-num Q
```
`K` = `snapshot-bytes` (mặc định 16384) — đây là **byte mỗi transaction** (re-arm mỗi request), không phải mỗi flow. `IPS_WATCH` = giữ flow trong queue để soi **mọi** transaction keep-alive; `IPS_INSPECTED` = thả flow CHỈ khi `Connection: close`/non-HTTP/flow-end (KHÔNG thả sau N transaction). Bit `IPS_WATCH`/`IPS_INSPECTED` phải **tách rời** policy_id (bit 8-31) và DIRTY (bit 0) — khai báo bản đồ bit trong header + assert compile-time.

### Cấu trúc reassembly (per-flow, per-direction)
```c
/* reass.h */
#define REASS_MAX_BYTES    16384   /* K mặc định mỗi chiều, cấu hình per-profile */
#define REASS_GAP_LIMIT     4096   /* lỗ trống tối đa trước khi coi là bất thường */
struct reass_dir {
    uint8_t  *buf;          /* vòng/đệm tuyến tính tối đa REASS_MAX_BYTES        */
    uint32_t  base_seq;     /* seq ứng với buf[0]                                */
    uint32_t  next_seq;     /* byte liên tục đã có tới đâu (để feed AC)          */
    uint32_t  scanned;      /* đã quét tới đâu (AC giữ state, không quét lại)    */
    /* danh sách đoạn out-of-order chờ lấp lỗ (bounded)                          */
};
struct reass_flow {
    struct reass_dir to_server, to_client;
    uint32_t  inspected_bytes;   /* tổng đã soi, so với K                        */
    int       proto_kind;        /* HTTP / TLS / DNS / UNKNOWN                   */
    /* trạng thái máy phân tích giao thức (P1 chỉ cần HTTP request boundary)      */
};
```

### Thuật toán
1. Mỗi gói: tra `reass_flow` theo conntrack tuple (pool có **trần tổng** + LRU evict).
2. Đặt payload TCP vào đúng vị trí theo seq. Gói đúng thứ tự → nối vào `next_seq`. Out-of-order → giữ tạm (bounded).
3. Khi `next_seq` tiến (có byte liên tục mới) → **feed phần mới vào AC theo kiểu streaming, GIỮ state node** (không quét lại từ đầu). Aho-Corasick vốn streaming: lưu node hiện tại trong `reass_dir`, mỗi lần feed tiếp tục từ node đó.
4. `distance/within/offset/depth` tính theo **vị trí trong dòng đã ghép** (xem P2).
5. **Soi-lại-mỗi-transaction (HTTP) — soi MỌI transaction, KHÔNG cap số transaction:** parser nhận dấu hiệu request mới (`GET/POST/PUT/HEAD/...` ở đầu dòng sau `\r\n\r\n`) → reset ngân sách K cho transaction đó (re-arm). Quét header + đầu thân tới K byte của transaction, đọc `Content-Length` → **nhảy qua phần thân còn lại** (chỉ đếm), tới request kế → re-arm tiếp. Flow giữ trong NFQUEUE (`IPS_WATCH`) suốt đời keep-alive.
6. **Thả flow CHỈ khi:** `Connection: close`, hết HTTP (non-keep-alive), hoặc flow kết thúc — **KHÔNG thả sau N transaction.** Thả → set `IPS_INSPECTED`.

> ⚠️ **Quan trọng (đã research firewall thật):** KHÔNG cap số transaction tích lũy (kiểu "soi 8 transaction đầu rồi thả"). Không Suricata/Snort/FortiGate nào làm vậy — đó là lỗ hổng (attacker gửi N request lành rồi exploit ở #N+1). Mọi transaction tuần tự **phải** được soi. Xem mục "Mô hình per-transaction" dưới.

### Mô hình per-transaction (chuẩn theo Suricata/Snort — đã research)
Firewall thật **soi mọi transaction**; cái họ giới hạn là 3 thứ ORTHOGONAL, **không phải** số transaction tích lũy:

| Giới hạn | Suricata default | Snort 3 | Stargazer | Bản chất |
|---|---|---|---|---|
| **Byte mỗi transaction** (re-arm mỗi tx) | body-limit **3KB** | `request_depth` | **K=16KB** | quét đầu mỗi transaction, nhảy thân — đây là cái K của bạn, ĐÚNG |
| **Transaction ĐỒNG THỜI** (concurrency, chống DoS) | `max-tx` **512** | `max_pipelined` **99** | `MAX_LIVE_TX` (vd 256) | đếm tx **pipelined chưa trả lời**; vượt → **anomaly event**, KHÔNG thả |
| **Stream depth per-flow** (backstop RAM) | `reassembly.depth` **1MB** | — | trần tổng pool | chống ngốn RAM |

**Khác biệt sống còn:** `MAX_LIVE_TX` đếm transaction **đang chạy đồng thời** (pipelined chưa xong), **KHÔNG** phải tích lũy. Transaction **xong → free state ngay** (RAM phẳng dù flow có hàng nghìn tx tuần tự). Vượt `MAX_LIVE_TX` → raise event "too_many_transactions" + có thể block flow, **tuyệt đối không** "thả fast-path bỏ soi". Đây là chỗ thiết kế cũ (`MAX_WATCH_TX`) sai — đã sửa.

```c
struct reass_flow {
    ...
    uint32_t live_tx;          /* tx pipelined chưa hoàn tất — guard concurrency */
    uint32_t tx_budget_used;   /* byte đã quét trong tx HIỆN TẠI (so với K)      */
    uint32_t body_remaining;   /* byte thân còn bỏ qua (từ Content-Length)        */
};
/* mỗi tx hoàn tất → live_tx--, free state tx đó.  live_tx > MAX_LIVE_TX → anomaly. */
```

### Intelligent-mode: ngân sách soi THÍCH ỨNG (THUẬT TOÁN CORE — luôn bật)
Đây là **thuật toán lõi** quyết định soi-thân-bao-nhiêu cho mỗi transaction, **luôn bật, không có cờ tắt** — theo đúng FortiGate (v7.0+ đã bỏ toggle, làm always-on). Thay hằng K cố định bằng **budget thích ứng theo Content-Type**. Hoạt động **TRONG** transaction; **không** ảnh hưởng nguyên tắc "soi mọi transaction".

**Quan hệ với transaction (phụ thuộc, không thay thế):**
```
Transaction parsing  = RANH GIỚI request + đọc Content-Type   ← nền tảng
Intelligent-mode     = DÙNG Content-Type để đặt budget thân    ← chạy TRÊN nền đó
```
Intelligent-mode lấy input (Content-Type, vị trí kết thúc thân) **từ** transaction parsing — nên cần cả hai, không bỏ transaction được.

**Logic quyết định (sau khi parse HTTP header của transaction):**
```
Mặc định: budget = K (soi đủ).  Chỉ HẠ budget khi CHẮC CHẮN lành-tĩnh:

  [tĩnh, rủi ro thấp]  image/* , text/css , application/javascript ,
                       font/* , audio/* , video/*   + magic byte KHỚP loại
        → soi header + magic byte (vài KB) → OFFLOAD thân sớm

  [động / rủi ro cao]  text/html , application/json , POST body ,
                       application/octet-stream , loại lạ / thiếu Content-Type
        → soi đủ K (mặc định)

  [không parse được / nghi ngờ]
        → giữ soi (IPS_WATCH), KHÔNG offload (fail-safe)
```
→ **Nguyên tắc fail-safe:** không-chắc thì soi đủ; chỉ "thông minh bỏ qua" khi tự tin lành-tĩnh. Vì vậy always-on vẫn an toàn.

**Cấu trúc:** thêm vào `reass_flow` (P1) trường `tx_budget` đặt động sau khi parse Content-Type (mặc định = K). HTTP parser đã có ở P1/P6 → tái dùng.

**Xử lý lỗi / chống lừa (BẮT BUỘC):**
- **Không tin Content-Type của attacker mù quáng:** dù khai `image/png`, vẫn **luôn soi magic byte đầu** trước khi quyết offload. Magic không khớp loại khai (vd khai image nhưng là `MZ`) → soi đủ K, không offload.
- Thiếu/sai Content-Type → budget đầy K (an toàn).
- Chunked/streaming không rõ độ dài → không offload (giữ soi).

**Honesty (giống FortiGate, ghi vào ledger):** offload heuristic → exploit chôn sâu trong file loại "lành" (vd giấu trong ảnh giả có magic đúng) → **lọt**. Đây là giới hạn cùng bản chất FortiGate. Nhu cầu "soi mọi byte file" thuộc về **lớp AV file/sandbox** (future, tách khỏi IPS) — không phải việc của IPS, nên IPS không cần cờ tắt intelligent-mode. Stargazer làm bản **cơ bản** (whitelist loại tĩnh + check magic), đủ bắt phần lớn lợi ích (offload thân file tĩnh = phần nặng nhất).

**Test:** Content-Type=image + magic khớp + thân lành → offload sớm (byte soi < K); khai image nhưng magic `MZ` → soi đủ K, không offload; Content-Type=html → soi đủ K; thiếu Content-Type → soi đủ K; không parse được → giữ soi.

### Chi phí NFQUEUE & hướng sửa data-plane (vì sao real engine soi được hết)
Real engine (Suricata AF_PACKET/DPDK, FortiGate NTurbo) **sở hữu packet path**, ghép+match trong thread của nó → **không** trả phí copy per-packet. Stargazer NFQUEUE trả phí kernel↔user **mỗi gói** → giữ flow keep-alive trong queue cả đời là đắt. Vì vậy **không cap transaction** (lỗ hổng), mà **giảm phí data-plane** (future work, theo độ khó tăng dần):
1. **Batch NFQUEUE:** `--queue-maxlen` lớn + GSO (`NFQA_CFG_F_GSO`) + verdict theo lô → khấu hao syscall.
2. **First-pass trong kernel:** ghép + AC prefilter ngay trong `pkt_forward.ko` (đã sở hữu hook FORWARD); chỉ đẩy flow nghi-ngờ lên ipsd → bỏ copy per-packet cho flow lành.
3. **AF_PACKET worker model** (như Suricata): ghép+match cùng thread sở hữu gói → bỏ hẳn round-trip. Hợp BPI-R4 4 nhân.

→ Trước mắt (P1): soi mọi transaction qua `IPS_WATCH`, chấp nhận phí NFQUEUE; tối ưu data-plane để sau. **Không** đánh đổi bằng bỏ soi transaction.

### Streaming AC: thay đổi `ac.c`
Thêm API giữ state qua nhiều lần feed:
```c
int ac_search_stream(const struct ac_automaton *ac, int32_t *state /*in/out*/,
                     const uint8_t *text, size_t len, uint32_t stream_off,
                     int (*on_match)(int id, uint32_t end_off, void *), void *ctx);
```
`state` khởi tạo 0 (root), được lưu trong `reass_dir`. `end_off` là vị trí byte trong **dòng** (không phải trong gói) — cần cho verify offset/depth/distance.

### Xử lý lỗi / chống tấn công (BẮT BUỘC)
- **Lỗ trống quá `REASS_GAP_LIMIT`:** dữ liệu chất đống sau một lỗ nhỏ mãi không lấp → **bất thường** → alert + fail-closed flow đó. (Chống mánh "giữ lỗ trống vắt kiệt buffer" — xem giải thích evasion.)
- **Buffer/đoạn out-of-order tràn:** không ghép được trong K → fail-closed (block flow), KHÔNG âm thầm cho qua.
- **Overlap segment dữ liệu khác nhau:** chọn chính sách nhất quán (ưu tiên byte ĐẾN TRƯỚC, kiểu first-wins) + log; chuẩn hóa inline đầy đủ để P-tương-lai.
- **Trần tổng bộ nhớ:** `total_reass_bytes <= cap` (mặc định 32MB). Vượt → evict LRU / fail theo `fail-mode`.
- **Seq wrap / seq vô lý / RST giả:** bounds-check mọi số học seq (so sánh kiểu `(int32_t)(a-b) < 0`), bỏ đoạn ngoài cửa sổ.
- IP fragment: GIỮ NGUYÊN — `nf_defrag_ipv4` đã ráp trước conntrack, ipsd thấy gói đã ráp (đúng). Không xử lại.

### Test
`reass_test.c`: gói đúng thứ tự, đảo thứ tự, trùng lặp, overlap, lỗ trống > limit (phải alert+block), content cắt qua 2-3 segment (phải bắt), keep-alive **nhiều request — exploit ở request #50 VẪN phải bắt** (chứng minh không cap tích lũy), pipelined vượt `MAX_LIVE_TX` → anomaly (không thả), `live_tx` về 0 sau khi mọi tx xong (RAM phẳng), tràn trần bộ nhớ.

### Tương thích
Pipeline `ips_evaluate` không đổi chữ ký — chỉ đổi **nguồn** payload từ "gói lẻ" sang "đoạn dòng đã ghép". `mgmtd` đổi rule string (giữ fallback connbytes-packets nếu kernel thiếu `connbytes-mode bytes` — đã có hàm `connbytes_supported`, mở rộng để probe mode bytes). UDP/DNS không có stream → bỏ qua reassembly, match thẳng payload gói (DNS gói đơn).

---

## P2 — Content modifier: distance / within / isdataat / dsize (RẺ, GIÁ TRỊ CAO NHẤT)

**Mục tiêu:** đúng ngữ nghĩa định vị tương đối — đóng phần lớn luật ET đang bị kẹp ALERT oan ở P0.

**File:** `sig_rule.h` (mở rộng `sig_content` + `sig_rule`), `sig_rule.c` (`parse_options`, `verify_rule`).

### Cấu trúc
```c
/* sig_content thêm: */
int  distance;      /* -1 = không đặt; >=0 hoặc âm: lệch so với CUỐI content trước */
int  within;        /* -1 = không đặt; số byte tối đa kể từ cuối content trước     */
uint8_t relative;   /* 1 nếu content này dùng distance/within (định vị tương đối)  */
/* sig_rule thêm: */
int  dsize_min, dsize_max;  /* -1 = không đặt                                      */
```

### Ngữ nghĩa Snort (PHẢI đúng)
- `offset`/`depth`: **tuyệt đối** từ đầu buffer — chỉ áp khi content **không** có distance/within.
- `distance`: bắt đầu dò cách **cuối match content trước** `distance` byte (có thể âm).
- `within`: content phải nằm **trong `within` byte** kể từ cuối match trước.
- `isdataat:N[,relative]`: kiểm có ≥ N byte (tuyệt đối hoặc từ vị trí hiện tại).
- `dsize:>N / <N / N / N<>M`: độ dài payload (dòng đã ghép cho TCP, gói cho UDP).

### Sửa `verify_rule`
Thay vòng lặp `pos` hiện tại bằng:
```
last_end = 0
for mỗi content c:
    nếu c.relative:
        lo = last_end + c.distance
        hi = (c.within >= 0) ? lo + c.within : len
    ngược lại (tuyệt đối):
        base = (c.offset>=0)? c.offset : 0
        lo = base;  hi = (c.depth>=0)? base + c.depth : len
    clamp lo,hi vào [0,len]; nếu lo>hi → fail
    s = mem_find(p, c.data, c.len, c.nocase, lo, hi)
    nếu s<0 → fail
    last_end = s + c.len
kiểm dsize nếu đặt
```
Luật chỉ-content cũ (không relative) → đi nhánh tuyệt đối → **hành vi như cũ** (tương thích).

### Quan trọng
P2 **phụ thuộc P1**: distance/within chỉ đúng trên **dòng đã ghép**. Trên gói lẻ sẽ sai khi match qua biên gói.

### Xử lý lỗi
- `distance`/`within`/`offset`/`depth` parse có range-check (chống tràn số → chỉ số mảng âm/khổng lồ).
- `lo/hi` luôn clamp `[0,len]` trước `mem_find` (đã có một phần — kiểm lại mọi nhánh).
- Sau khi đủ điều kiện P2, các luật từ `SIG_FID_ALERT` → có thể nâng `SIG_FID_FULL` (vì giờ đã hỗ trợ distance/within). Cập nhật phân loại ở P0.

### Test
Luật multi-content với distance/within (khớp đúng vị trí, trượt khi sai vị trí), dsize biên, content cắt qua segment + distance (cần P1).

### Tương thích
Trường mới mặc định -1 (không đặt) → luật cũ không đổi hành vi.

---

## P3 — byte_test / byte_jump (CẤU TRÚC GIAO THỨC NHỊ PHÂN)

**Mục tiêu:** mở khóa luật đọc trường độ dài/giá trị (DNS, SMB, RPC...).

**File:** `sig_rule.h` (thêm danh sách byte-op), `sig_rule.c` (parse + verify).

### Cấu trúc
```c
struct sig_byteop {
    uint8_t  kind;       /* BYTE_TEST | BYTE_JUMP                         */
    uint8_t  nbytes;     /* 1..8                                          */
    uint8_t  relative;   /* tính từ vị trí hiện tại                       */
    uint8_t  flags;      /* little/big endian, string/hex, oper (<,>,=,&) */
    int32_t  value;      /* so sánh (byte_test) / cộng thêm (byte_jump)   */
    int32_t  offset;
    int32_t  post_offset;/* byte_jump post_offset                         */
};
/* sig_rule: struct sig_byteop byteops[SIG_MAX_BYTEOP]; int n_byteop; cursor map */
```
Vì byte_test/byte_jump xen kẽ với content theo thứ tự, cần lưu **thứ tự thao tác** (một danh sách op hợp nhất content+byteop) hoặc gắn byteop vào "sau content thứ i".

### Verify
Khi tới byte_jump: đọc `nbytes` tại vị trí hiện tại, dịch con trỏ match theo giá trị đọc được (+post_offset). byte_test: đọc + so sánh, sai → fail. **Bounds-check tuyệt đối** mỗi lần đọc N byte (chống đọc ngoài buffer — đây là điểm tấn công kinh điển).

### Xử lý lỗi/tấn công
- `nbytes>8`, offset/giá trị tràn → bỏ op (đếm error).
- Giá trị đọc từ payload (attacker kiểm soát) dùng để dịch con trỏ → **clamp kết quả vào [0,len]**, không bao giờ để jump ra ngoài buffer.

### Test
`byte_jump` đọc trường độ dài DNS rồi nhảy tới QNAME; `byte_test` so sánh cờ; input cố tình cho giá trị nhảy khổng lồ (phải clamp, không crash).

### Tương thích
Luật không có byteop → `n_byteop=0` → verify bỏ qua. Sau P3, các luật chỉ thiếu byte_test/jump nâng được lên FULL.

---

## P4 — pcre (ĐỘ PHỦ LỚN NHẤT, NẶNG — cân nhắc scope)

**Mục tiêu:** hỗ trợ regex — rất nhiều luật ET dùng. Nhưng nặng + rủi ro ReDoS.

**File:** `sig_rule.h/c`; link thư viện regex (PCRE2 cross-compile, hoặc engine con an toàn).

### Thiết kế
- pcre là **bước verify cuối** (sau prefilter AC + content anchoring), **không bao giờ** làm fast pattern.
- Modifier `R` (relative) → match từ vị trí cuối content trước. `i`,`s`,`m` map sang cờ regex.
- Buffer-specific (`U`=uri, `H`=header...) → cần P6 buffer HTTP; chưa có thì luật pcre-buffer → ALERT-cap.

### Chống ReDoS (BẮT BUỘC)
- Dùng PCRE2 với `pcre2_set_match_limit` + `set_depth_limit` + **JIT off hoặc giới hạn thời gian** mỗi match.
- Ngân sách thời gian tổng mỗi gói; vượt → bỏ match đó + đếm, không treo ipsd.
- Compile regex một lần lúc nạp (cache), không compile mỗi gói.

### Tương thích / scope
- Có thể để P4 **tùy chọn build** (`#ifdef HAVE_PCRE`). Không có pcre → luật pcre giữ `SIG_FID_ALERT` (P0). Đây là quyết định scope hợp lệ cho KLTN — ghi rõ % luật pcre trong báo cáo.

### Test
Luật pcre relative khớp/trượt; regex ác (catastrophic backtracking) phải bị cắt theo match-limit, không treo.

---

## P5 — flowbits (TRẠNG THÁI ĐA GÓI/ĐA LUẬT)

**Mục tiêu:** phát hiện nhiều bước + **tránh làm sống lại alert bị tắt**.

**File:** `sig_rule.h/c`, kho cờ trong `reass_flow` (P1) hoặc bảng phụ theo conntrack.

### Cấu trúc
```c
/* per-flow: bitset cờ (tên cờ → id, bảng toàn cục lúc nạp) */
struct flowbit_state { uint64_t bits[ /* số cờ / 64 */ ]; };
/* sig_rule: thao tác flowbits: set|unset|toggle|isset|isnotset + flag_id */
```

### Logic
- `isset/isnotset`: điều kiện match (kiểm bit trước khi verdict).
- `set/unset/toggle`: tác dụng phụ sau khi luật khớp.
- `noalert`: luật chỉ set cờ, không tự báo.
- **Lan truyền bỏ qua:** nếu một luật *set* cờ bị SKIP (do keyword khác chưa hỗ trợ) → mọi luật *isset* cờ đó phải bị hạ ALERT/SKIP (vì điều kiện tiền đề không bao giờ đúng/sai đúng cách). Dựng đồ thị phụ thuộc cờ lúc nạp.

### Tương thích
Luật không flowbits → không đụng. flowbits cần state per-flow → tái dùng `reass_flow` của P1.

---

## P6 — flow keyword + HTTP buffers (TINH CHỈNH ĐỘ CHÍNH XÁC)

**Mục tiêu:** lọc đúng chiều/trạng thái (rẻ, sẵn dữ liệu) + buffer giao thức cho pcre/content sticky.

**File:** `sig_rule.c` (parse `flow:`), `engine.c`/verify, parser HTTP trong P1.

- `flow:established,to_server|to_client,stateless`: dùng `ctdump` (đã có trạng thái + hướng). Rẻ. Lọc bớt báo nhầm và là điều kiện của RẤT nhiều luật.
- HTTP sticky buffers (`http_uri`, `http_header`, `http_client_body`...): parser HTTP (P1) tách vùng; content/pcre có modifier buffer match trên đúng vùng. Đây là bước nâng độ chính xác + mở khóa pcre-buffer.
- SNI buffer: tái dùng `tls_clienthello.c` — content match trên `tls.sni` (đã có sẵn parser). Đóng phần lớn luật "domain in TLS SNI" như sid 2068337 trong ruleset người dùng.

---

## P7 — IPS Profile = FortiGate IPS Sensor (chọn ACTION cho từng signature/category)

**Mục tiêu:** Khi thêm signature hoặc category vào một IPS profile, cho admin **chọn action** (`default`/`block`/`alert`/`pass`) cho từng entry — **trước khi** gắn profile vào firewall policy. Đúng mô hình **IPS sensor của FortiGate** (và tab Policy của OPNsense / drop-filter của suricata-update): rule gốc giữ nguyên, **profile quyết định action** theo category/signature. Bối cảnh: ET Open hầu như toàn `alert`, nên **không thể dựa action gốc để chặn** — action phải do profile áp.

### Hiện trạng (bám code thật) — đã có một nửa
- **DB schema ĐÃ CÓ action:** `security_ips-filter` có field `action` `enum:default,block,alert,pass` (`sg_validate.c`). Mỗi entry = `{profile, type(category|signature), value, action, status}`.
- **Backend compile CHƯA áp action:** `struct ips_filter` (`mgmtd_ips_compile.h`) **chỉ có** `type` + `value`, **thiếu `action`**. `ips_compile_filters` ghi rule **giữ nguyên action gốc** (comment: "Action của từng rule GIỮ NGUYÊN (không override)"). → entry `block` hiện **không chặn** vì rule gốc vẫn `alert`.
- **UI:** modal "Add Signatures" + bảng filter đã có (`app.js`), nhưng cần thêm cột chọn action per entry.

→ **Việc cốt lõi của P7: nối action từ DB → compile → rewrite action token trong active.rules.** Đây là mắt xích đang đứt.

### Ánh xạ FortiGate → Stargazer

| FortiGate IPS sensor | Stargazer |
|---|---|
| Một entry (signature/filter) | một row `security_ips-filter` |
| Enable / Disable entry | field `status` (`enable`/`disable`) |
| Signature override | type=`signature`, value=`<sid>` |
| Filter (theo category/severity) | type=`category`, value=`<category>` |
| Action: Block | `block` (→ rewrite rule thành `drop`) |
| Action: Monitor | `alert` (chỉ cảnh báo, cho qua) |
| Action: Pass | `pass` (loại rule khỏi profile) |
| Action: Default (giữ action rule) | `default` |

**Mỗi entry mang HAI thuộc tính độc lập (đúng FortiGate):**
- `status` = **có soi entry này không** (enable/disable).
- `action` = **khi match thì làm gì** (block/alert/pass/default).

→ Bật/tắt **một mình không quyết định chặn**. Vì ET Open gần như toàn `alert`, một entry `enable` + `action=default` → chỉ **cảnh báo**. Muốn **chặn** phải đặt `action=block`. Đây là điểm cốt lõi của mô hình FortiGate: **action mới là thứ chặn, không phải enable.**

### Backend — compile áp action (FILE CHÍNH)
**File:** `mgmtd_ips_compile.h` (struct), `mgmtd_ips_compile.c` (`write_rule_line`, `append_rules`, `append_sid`, `ips_compile_filters`), caller trong `mgmtd_apply_ips.c` (đọc `security_ips-filter` từ DB → mảng `ips_filter`).

1. **Thêm action vào struct:**
```c
/* mgmtd_ips_compile.h */
enum ips_filter_action { IPS_FA_DEFAULT=0, IPS_FA_BLOCK, IPS_FA_ALERT, IPS_FA_PASS };
struct ips_filter {
    int  type;            /* IPS_FT_CATEGORY | IPS_FT_SIGNATURE */
    char value[128];
    int  action;          /* enum ips_filter_action  ← THÊM     */
};
```

2. **Rewrite action token khi ghi rule** (`write_rule_line` nhận thêm `action`):
```
default → giữ token đầu của rule nguyên trạng (alert/drop...)
block   → thay token đầu thành "drop"
alert   → thay token đầu thành "alert"
pass    → KHÔNG ghi rule (loại khỏi profile — whitelist)
```
Cụ thể: tìm token đầu (tới khoảng trắng đầu tiên), thay bằng action map, giữ phần còn lại của dòng (header + options) nguyên.

3. **Precedence (signature override > category > default)** — giống FortiGate:
   - Build map `sid → action` từ các filter type=`signature` (cụ thể nhất, thắng).
   - Khi ghi rule của một category, nếu `sid` của rule có trong map signature-override → dùng action đó thay action của category.
   - Trùng sid (category + signature override) → **chỉ ghi một lần**, theo action signature.

4. **Tương tác với P0 fidelity:**
   - `block` chỉ thực sự DROP nếu rule `fidelity == FULL` (P0). Rule partial-match (pcre/byte_test chưa hỗ trợ) → dù chọn `block` vẫn **kẹp ALERT** (không rewrite thành drop, hoặc rewrite nhưng ipsd cap). Ghi rõ để không tạo false-DROP.

### Verdict theo action (thuần per-entry, như FortiGate)
Detect-vs-prevent được quyết định **hoàn toàn qua action per-entry** (giống FortiGate: Monitor = detect, Block = prevent). Muốn một profile chạy IDS-only → đặt các entry `action=alert`. Không có master switch global.

| Entry action | Rule fidelity | Verdict |
|---|---|---|
| block | FULL | **DROP** |
| block | partial (P0) | ALERT (kẹp, không false-DROP) |
| alert | bất kỳ | ALERT |
| pass | — | bỏ qua (không soi) |
| default | — | giữ action gốc của rule (ET → thường ALERT) |

→ Thứ tự áp: `pass` loại trước → `action` (block/alert) → `fidelity` kẹp (partial-match không DROP).

### CLI / backend config
**File:** `cli_cmd_table.c` / `sg_cmd_defs.h` (đã có context `security ips-filter`), `sg_validate.c` (action đã trong schema).
```
config security ips-filter
    edit <id>
        set profile <name>
        set type signature        # hoặc category
        set value 2068337         # sid hoặc tên category
        set status enable         # enable|disable  (có soi entry này không)
        set action block          # default|block|alert|pass  (khi match làm gì) ← điểm chính
    next
end
```
→ Field `action` đã validate sẵn; chỉ cần đảm bảo `mgmtd_apply_ips.c` đọc `action` từ DB và truyền vào `ips_filter.action` khi compile.

### UI (web)
**File:** `webui/www/home.html` (modal + bảng filter), `webui/www/js/app.js` (pendingFilters, addFilter).
- **Modal "Add Signatures":** mỗi dòng signature có **dropdown action** (Default/Block/Alert/Pass) bên cạnh nút chọn. Mặc định `Default`.
- **Thêm category:** ô chọn action khi thêm.
- **Bảng filter của profile:** cột "Action" hiển thị + **sửa được tại chỗ** (dropdown). `default` hiển thị kèm hint "giữ action gốc của rule".
- `addFilter(type, value, action)` đã có tham số action (pendingFilters) — chỉ cần nối dropdown vào và POST `action` lên `/config/security_ips-filter`.
- **Áp dụng trước khi gắn policy:** toàn bộ chọn action diễn ra trong trang IPS profile; chỉ khi profile được gắn vào firewall policy (ACCEPT + ips-profile) thì mới có hiệu lực — đúng luồng FortiGate (cấu hình sensor xong mới gắn vào policy).

### Luồng đầy đủ (sau P7)
```
1. Admin mở IPS profile → "Add Signatures" → chọn sid + action=Block
                        → "Add Category" scan + action=Alert
2. Lưu → ghi security_ips-filter {profile, type, value, action}
3. mgmtd_apply_ips: đọc filter từ DB → ips_filter[] (kèm action)
4. ips_compile_filters: ghi active.rules, REWRITE action token theo filter
   (signature override > category > default; pass → loại)
5. SIGUSR1 ipsd → nạp active.rules (rule đã mang action đúng)
6. Gắn profile vào firewall policy → có hiệu lực
```

### Tương thích
- `action=default` → giữ action gốc → hành vi y hệt hiện tại (không phá gì).
- Schema không đổi (action đã có). Chỉ thêm field vào `struct ips_filter` + logic rewrite + UI dropdown.
- Profile cũ chưa set action → coi như `default`.

### Test
- `mgmtd_ips_compile_test.c`: filter signature action=block → output rule có token đầu `drop`; action=alert → `alert`; action=pass → rule bị loại; action=default → giữ nguyên. Precedence: category=alert + signature-override=block cho cùng sid → rule ghi `drop`, chỉ một lần. Rule fidelity=partial + block → vẫn alert (không drop).

---

## Bảng ưu tiên & phụ thuộc

| Gói | Đóng được gì | Phụ thuộc | Công sức | Bắt buộc cho KLTN? |
|---|---|---|---|---|
| **P0** Phân loại + an toàn nạp | bug catch-all, báo nhầm do match-một-phần, độ phủ thật | — | thấp | **CÓ (khẩn)** |
| **P1** Reassembly + byte-window 2 chiều + re-arm | né cắt-segment/đổi-chiều/MSS/nhồi-gói | P0 | cao | **CÓ (giá trị cao nhất)** |
| **P2** distance/within/dsize | đúng ngữ nghĩa, gỡ ALERT-cap cho nhiều luật | P1 | vừa | **CÓ** |
| **P3** byte_test/byte_jump | luật nhị phân (DNS/SMB) | P2 | cao | Nên |
| **P4** pcre | độ phủ lớn nhất | P2 | cao | Tùy scope (ghi rõ %) |
| **P5** flowbits | đa bước + chống sống-lại-alert | P1 | vừa | Nên |
| **P6** flow + HTTP/SNI buffers | độ chính xác, bớt báo nhầm | P1 | vừa | Nên |
| **P7** IPS profile = FortiGate sensor (action per entry) | cho admin chọn block/alert/pass per signature/category | P0 (fidelity) | vừa | **CÓ** (quyết định chặn) |

> **P7 độc lập với P1-P6:** nó là tầng quản lý/policy, không phải engine matching. Có thể làm song song. Chỉ phụ thuộc P0 (fidelity, để `block` không false-DROP rule partial-match).

## Nguyên tắc xuyên suốt (mọi gói tuân thủ)
1. **Không bao giờ "khớp một phần = khớp đủ".** Thiếu điều kiện thu hẹp → KẸP ALERT, không DROP.
2. **Không âm thầm cho qua.** Không ghép được / quá tải / lỗi parse → fail-closed hoặc đếm+alert, tuyệt đối không lặng lẽ pass.
3. **Bounds-check mọi truy cập payload** (offset/depth/distance/within/byte_test jump) trước khi đọc; clamp `[0,len]`.
4. **Trần tài nguyên cứng** (bộ nhớ reassembly, thời gian pcre, số op) — chống cạn kiệt có chủ đích.
5. **Báo cáo độ phủ thật** (loaded_full/alert/skipped) qua IPC — trung thực với báo cáo.
6. **Tương thích ngược:** thêm field mặc định trung tính (memset=0); luật chỉ-content giữ nguyên hành vi; IPC chỉ thêm, không đổi field cũ; giữ fallback khi kernel thiếu tính năng.
7. **Mỗi gói có test** trong `*_test.c` chạy host (QEMU không bắt buộc cho logic thuần) + ca tấn công có chủ đích (cắt segment, lỗ trống, regex ác, jump khổng lồ).

## Bản đồ connmark (khai báo + assert compile-time)
```
bit 0      : DIRTY (policy re-eval)
bit 1      : IPS_BLOCK      (đã có)
bit 2      : IPS_INSPECTED  (thả khi Connection:close / non-HTTP / flow-end)
bit 3      : IPS_WATCH      (giữ soi MỌI transaction keep-alive — không cap số tx)
bit 8-31   : policy_id
```
Assert `IPS_*` không chồng `policy_id`/`DIRTY`. Xóa `IPS_*` khi conntrack teardown (tránh tuple tái dùng kế thừa cờ chặn).

## Giới hạn còn lại (ghi vào honesty ledger của báo cáo)
- Payload chôn sâu sau K byte trong **một** transaction khổng lồ → không soi (giới hạn cùng bản chất FortiGate intelligent-mode).
- Nội dung **mã hóa TLS** → lớp signature mù; chỉ có SNI/JA3/reputation/ML, tới khi `ssld` hoàn thiện.
- Reassembly overlap target-based đầy đủ (chuẩn hóa inline) để tương lai; P1 chỉ chính-sách-nhất-quán + phát hiện bất thường.
- IPv4 only (`pkt_forward` v4).
