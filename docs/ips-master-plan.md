# Master Plan — Hybrid IPS cho Stargazer NGFW

> **Bản kế hoạch chủ đạo** cho việc triển khai tiếp tính năng IPS. Tài liệu này **thay thế phần đã lỗi thời** trong `ips-architecture.md` và `ips-implementation-guide.md` (hai bản đó viết khi data-plane còn dùng `session.ko`; nay đã chuyển sang **nf_conntrack** — commit `020287d`). Giữ lại hai bản cũ làm tham chiếu lịch sử (đặc biệt phần mã Aho-Corasick mẫu).
>
> - Kết hợp **signature-based** (Aho-Corasick, rule kiểu ET OPEN) + **anomaly-based** (LightGBM đã train).
> - Cơ chế lấy gói + inline prevention: **NFQUEUE N gói đầu** mỗi flow.
> - Nhịp: **sprint khóa luận ~2 tuần (10 ngày làm việc)**.
> - Quy ước dự án: *plan trước, code sau* — tài liệu này là kế hoạch, chưa commit thay đổi mã.

---

## 0. Trạng thái hiện tại (đã có vs còn thiếu)

Trước khi lập kế hoạch, phải nhìn đúng những gì codebase đã có — nhiều thứ trong hai doc cũ **đã xong rồi**.

### ✅ Đã hoàn tất

| Thành phần | Bằng chứng trong code |
|---|---|
| Data-plane chuyển sang **nf_conntrack** | `src/modules/pkt_forward.c`; commit `020287d` (gỡ `session.ko`) |
| **14 ML feature** điền vào conntrack extension mỗi gói | `ml_account()` trong `pkt_forward.c:166`; `struct nf_conn_ml` trong `stargazer-kernel/include/net/netfilter/nf_conntrack_ml.h` |
| Chống tràn số nguyên (IAT về µs trước khi bình phương, clamp) | `pkt_forward.c:198-230` (comment rõ) |
| **Export feature lên userspace** qua ctnetlink `CTA_ML` (GET/DUMP) | `nf_conntrack_ml.h` (mô tả CTA_ML); `mgmtd_diag.c:1901 ct_ml_emit()` đã parse được |
| `struct sg_nf_conn_ml` mirror userspace + lệnh `execute diagnose session ml` | `mgmtd_diag.c:1857`, `:1980 handle_session_ml()` |
| Anomaly L3/L4 **stateless** (NULL/XMAS/land/source-route/PoD/SYN+data) | `is_ip_anomaly`/`is_tcp_anomaly`/`is_icmp_anomaly` trong `pkt_forward.c` |
| **Model LightGBM → C** (tl2cgen), 14 cột khớp | `Machine Learning/ips_c/{main.c,header.h,recipe.json}`; `feature_order.json`; `stargazer_ids.txt` |
| **CICFlowMeter** để test feature parity | `CICFlowMeter/` (có `micro.pcap` + `micro.pcap_Flow.csv` mẫu) |

**14 feature đã chốt** (thứ tự cột train — `feature_order.json`, đối chiếu `stargazer_ids.txt`):

```
0  Flow IAT Std            7  Bwd Packet Length Mean
1  Flow IAT Min            8  SYN Flag Count
2  Flow IAT Mean           9  ACK Flag Count
3  Fwd IAT Std            10  PSH Flag Count
4  Packet Length Variance 11  URG Flag Count
5  Packet Length Std      12  Down/Up Ratio
6  Fwd Packet Length Mean 13  Init_Win_bytes_forward
```

> **Lưu ý quan trọng:** model là binary classifier `objective=binary sigmoid:1` (`stargazer_ids.txt:7`). `predict()` của tl2cgen trả **margin (log-odds)**; phải gọi `postprocess()` (sigmoid) để ra xác suất 0–1 rồi mới so threshold. `Init_Win_bytes_forward` (feature 13) **chưa có** trong `nf_conn_ml` — xem Gap ở §3.4.

### ❌ Còn thiếu (phạm vi của plan này)

1. **Verdict write-back + enforcement** — `forward_hook` hiện chỉ `NF_ACCEPT`; chưa ai ghi `ml_score`; chưa chặn theo điểm.
2. **`stargazer-ipsd`** — daemon userspace: NFQUEUE → feature → signature → LightGBM → fusion → verdict.
3. **Signature engine** — Aho-Corasick + parser rule kiểu ET OPEN + lớp flow-rule.
4. **Cơ chế cập nhật CSDL signature** — kho rule có version, import/cập nhật, reload an toàn.
5. **Cấu hình CLI + GUI kiểu FortiGate** — config type `security_ips`, context CLI, trang Security/IPS.

---

## 1. Kiến trúc logic (đầy đủ thành phần + luồng)

### 1.1. Nguyên tắc phân tầng (ranh giới float)

Ràng buộc cứng của dự án: **không float trong kernel**. LightGBM (tl2cgen) dùng `double` dày đặc → mọi inference ở userspace. Ranh giới:

```
┌──────────────────────── KERNEL (chỉ số nguyên) ─────────────────────────┐
│ pkt_forward.ko                                                          │
│   [1] validate IPv4                                                     │
│   [2] anomaly screen stateless (NULL/XMAS/land/PoD…)        → NF_DROP    │
│   [3] ml_account(): cộng dồn 14 accumulator vào NF_CT_EXT_ML (u64/u32)  │
│   [4] enforcement: connmark BLOCK? → NF_DROP                            │
│   [5] cần soi payload (N gói đầu, chưa có verdict)? → NF_QUEUE          │
│ nf_conntrack: state, NAT, export CTA_ML qua ctnetlink dump             │
└───────────────────────────────────┬─────────────────────────────────────┘
            NFQUEUE (payload + verdict)  │  ctnetlink dump (flow-stats)  │ connmark
┌───────────────────────────────────┴─────────────────────────────────────┐
│ stargazer-ipsd (userspace — float thoải mái)                            │
│   feature extraction (14) → signature L1 (flow) + L2 (Aho-Corasick)     │
│                           → LightGBM predict()+postprocess() → fusion    │
│                           → verdict: set connmark + nfq ACCEPT/DROP       │
└──────────────────────────────────────────────────────────────────────────┘
```

### 1.2. Luồng dữ liệu chi tiết (mô hình NFQUEUE N gói đầu)

Đây là mô hình **flow-based inspection** giống FortiGate: soi N gói đầu của mỗi flow rồi "offload" phần còn lại bằng connmark — không bắt mọi gói phải lên userspace.

```
         packet ─► FORWARD hook (pkt_forward.ko)
                     │
   [enforcement] connmark == BLOCK?  ──Yes─► NF_DROP (fast path, không update)
                     │No
   [accounting] ml_account → NF_CT_EXT_ML (14 accumulator)
                     │
   connmark == INSPECTED (đã có verdict ACCEPT)? ─Yes─► NF_ACCEPT (offload)
                     │No
   gói thứ ≤ N của flow? ──Yes─► NF_QUEUE → ipsd
                     │No
                     └─► NF_ACCEPT (flow chưa kịp verdict trong N gói → cho qua,
                          nhưng vẫn tiếp tục accounting; verdict trễ vẫn set connmark)

   ── ipsd nhận gói từ NFQUEUE ──────────────────────────────────────────────
   1. parse IP/TCP/UDP; lấy payload L4; lấy ctmark + tuple (NFQA_CT)
   2. đọc flow-stats: dump CTA_ML theo tuple (tái dùng parser mgmtd) → 14 feature
   3. signature L1 (flow rule: cờ/đếm/port) ──► khớp? ─Yes─► verdict NGAY (short-circuit, KHỎI chạy ML)
   4. signature L2 (Aho-Corasick payload)   ──► khớp? ─Yes─► verdict NGAY (short-circuit)
   5. CHỈ KHI không signature nào khớp → LightGBM: predict()+sigmoid → score
   6. fusion → verdict (signature thắng; ML chỉ quyết khi không có sig):
        sig DROP / score≥block  → set connmark=BLOCK, nfq verdict DROP, log alert
        score≥alert (< block)   → log alert, connmark=INSPECTED, nfq ACCEPT  (mode detect)
        ngược lại               → connmark=INSPECTED, nfq ACCEPT
      (mode=detect: không bao giờ set BLOCK, chỉ log)
```

**Tại sao kết hợp NFQUEUE + connmark thay vì chỉ NFQUEUE từng gói:** queue *mọi* gói lên userspace giết throughput trên BPI-R4. Soi N gói đầu là đủ cho feature CIC (vốn được cắt ngắn ở §2.3) và cho payload signature (mã độc/exploit string nằm ở đầu request); sau khi có verdict, connmark đẩy quyết định xuống kernel fast-path. Đây chính là mô hình *flow-based inspection với offload* mà FortiGate dùng.

### 1.3. Bảng thành phần và vai trò

| Lớp | Thành phần | Vai trò | Tình trạng |
|---|---|---|---|
| Kernel | `pkt_forward.ko` | accounting (✅) + enforcement connmark (❌) + NF_QUEUE N gói đầu (❌) | sửa thêm |
| Kernel | nf_conntrack + `nf_conntrack_ml.h` | state, export CTA_ML | ✅ |
| Userspace | `stargazer-ipsd` | NFQUEUE → feature → signature → ML → fusion → verdict | mới |
| Userspace | `ac.{c,h}` | Aho-Corasick multi-pattern | mới |
| Userspace | `sig_rule.{c,h}` | parser rule ET-OPEN-subset + flow rule | mới |
| Userspace | `feature.{c,h}` | 14 feature + parity CICFlowMeter | mới |
| Userspace | `model/` | `predict.c` (tl2cgen) — copy từ `Machine Learning/ips_c/` | có sẵn, ghép vào |
| Quản lý | `mgmtd` | config type `security_ips`, supervisor `ipsd`, IPC status | sửa thêm |
| Quản lý | `cli` | context `config security ips`, `diagnose ips …` | sửa thêm |
| Quản lý | `webd` | trang Security/IPS, nối Sessions ↔ `ml_score` | sửa thêm |
| Dữ liệu | `/etc/stargazer/ips/rules/` + SQLite | kho signature có version + update | mới |

---

## 2. Cơ sở nghiên cứu / chứng minh kiến trúc

Mỗi quyết định lớn đều dựa trên công bố đã có — phần này là "chứng minh" cho khóa luận.

### 2.1. Vì sao hybrid (signature + anomaly)?
- **Signature** bắt tấn công **đã biết**, false-positive thấp, giải thích được — nhưng mù với biến thể/zero-day.
- **Anomaly/ML** bắt tấn công **lạ** — nhưng false-positive cao và khó giải thích; Sommer & Paxson cảnh báo rõ về việc dùng ML cho NIDS (S&P 2010). Hai lớp **bù khuyết** nhau; cách fusion là đóng góp của khóa luận.
- Khảo sát nền tảng: García-Teodoro et al. (Computers & Security 2009); Buczak & Guven (IEEE Comm. Surveys & Tutorials 2016).

### 2.2. Vì sao Aho-Corasick cho signature?
- Snort/Suricata dùng **multi-pattern matching (MPM)** họ Aho-Corasick vì quét payload **một lần** bắt mọi pattern: `O(n + Σ|pattern| + #match)`, **không phụ thuộc số rule** lúc quét — KMP/BM đơn-pattern là `O(K·n)`, không scale với hàng nghìn rule.
- Gốc: Aho & Corasick, *"Efficient string matching: an aid to bibliographic search"*, CACM 1975.
- Trong IDS: Norton (Sourcefire), *"Optimizing Pattern Matching for Intrusion Detection"* 2004 (Snort `ac`/`ac-bnfa`); Tuck et al., *"Deterministic Memory-Efficient String Matching Algorithms for Intrusion Detection"*, IEEE INFOCOM 2004 (nén bộ nhớ AC bằng bitmap/path-compression).
- Các họ liên quan để so sánh trong báo cáo: Commentz-Walter (1979, BM+AC), Wu-Manber (1994, agrep).
- **Vì sao không Hyperscan:** Wang et al., *"Hyperscan: A Fast Multi-pattern Regex Matcher for Modern CPUs"*, NSDI 2019 — mạnh nhưng **x86 SIMD**, không chạy ARM BPI-R4. Bản port ARM **Vectorscan** ghi vào "future work".
- Kết luận: tự viết AC (DFA đầy đủ) ~300–400 dòng C, không dependency, link tĩnh musl — vừa đúng kỹ thuật vừa thể hiện hiểu biết.

### 2.3. Vì sao chấp nhận feature "partial-flow" (N gói đầu)?
- Feature CIC được tính trên **cả flow**, nhưng inline IPS không thể đợi flow kết thúc. Chuẩn của khóa luận: **train/đánh giá lại model trên flow đã cắt ở N gói** để khớp điều kiện runtime — biến hạn chế thành một điểm đánh giá.
- Bộ dữ liệu & công cụ feature: Sharafaldin, Lashkari, Ghorbani, *"Toward Generating a New Intrusion Detection Dataset…"* (CIC-IDS2017), ICISSP 2018; CICFlowMeter (Lashkari et al.).

### 2.4. Vì sao LightGBM + tl2cgen?
- LightGBM: Ke et al., *"LightGBM: A Highly Efficient Gradient Boosting Decision Tree"*, NeurIPS 2017. Tree-model → **scale-invariant** ⇒ nếu train có `StandardScaler` thì **bỏ được** khi convert (chỉ cần đúng thứ tự cột).
- Convert: treelite + tl2cgen → `predict()` C độc lập, link tĩnh (đã làm: `Machine Learning/ips_c/`).

### 2.5. Vì sao rule tương thích ET OPEN?
- Tận dụng kho rule cộng đồng (Emerging Threats Open / Proofpoint) thay vì tự viết từ đầu. ET OPEN dùng **cú pháp rule Snort/Suricata**. Ta parse một **subset** (`msg, sid, content, nocase, offset, depth, flags, proto, port`) — đủ để nạp rule thật, bỏ qua field chưa hỗ trợ.

> Bibliography đầy đủ ở §10.

---

## 3. Đặc tả kỹ thuật các thành phần mới

### 3.1. Kernel — enforcement + NFQUEUE (sửa `pkt_forward.c`)

Dùng **connmark** (đã có hạ tầng dirty-flow connmark — commit `fb79d7e`, `f57c269`). Dành 2 bit trong connmark:

```
SG_CMK_IPS_BLOCK     (1<<X)  /* flow xấu → mọi gói sau DROP */
SG_CMK_IPS_INSPECTED (1<<Y)  /* đã có verdict ACCEPT → offload, khỏi queue */
```

`forward_hook` chèn (sau accounting):
```
mark = nf_ct read connmark
if (mark & SG_CMK_IPS_BLOCK)     → NF_DROP
if (mark & SG_CMK_IPS_INSPECTED) → NF_ACCEPT
if (ips_enabled && pkts_seen(ct) <= FEATURE_SNAPSHOT_N) → return NF_QUEUE_NR(queue)
return NF_ACCEPT
```
- `ips_enabled` + `queue` lấy từ tham số module hoặc procfs (mgmtd bật/tắt).
- `pkts_seen(ct)` lấy từ ACCT extension (đã bật) hoặc `iat_count+1` trong `nf_conn_ml`.
- **An toàn:** mọi truy cập connmark dưới `ct->lock`; nếu không có ct (untracked) → NF_ACCEPT.

`ipsd` set connmark qua **NFQA_CT (CTA_MARK)** kèm trong message verdict của libnetfilter_queue — không cần API kernel mới. Tùy chọn ghi `ml_score` vào `nf_conn_ml` để hiển thị: stretch (cần ctnetlink SET cho CTA_ML hoặc 1 procfs `/proc/stargazer/verdict`); sprint có thể bỏ qua, score chỉ sống ở log/ipsd.

### 3.2. Aho-Corasick (`ac.c/ac.h`)
- DFA đầy đủ (mỗi node 256 cạnh sau build) → search 1 chuyển trạng thái/byte.
- **Mã mẫu đã có sẵn** trong `ips-implementation-guide.md §3.2–3.3` (init/add/build BFS failure+goto+output-link/search) — dùng lại, chỉ cần đưa vào `src/userspace/ipsd/`.
- Bộ nhớ mỗi node 256×4B = 1KB; vài trăm pattern ≈ vài MB — chấp nhận ở userspace. Nếu ruleset lớn: nén DFA (Tuck 2004) ghi "future work".
- Binary-safe: search theo `len`, không dựa `\0`. `nocase` áp **cả lúc add lẫn search**. Mọi `malloc/realloc` kiểm NULL.

### 3.3. Định dạng rule (ET OPEN compatible) + `sig_rule.{c,h}`

Cú pháp Snort/Suricata; parse subset:
```
alert tcp any any -> $HOME_NET 80 (msg:"WEB SQLi UNION SELECT"; \
      flow:to_server,established; content:"UNION"; nocase; content:"SELECT"; \
      nocase; distance:0; sid:2008538; rev:5;)
```
Mô hình nội bộ:
```c
struct sig_rule {
    uint32_t sid;            /* khớp ET OPEN sid */
    uint8_t  proto;          /* TCP/UDP/ICMP/ANY */
    uint16_t dport;          /* 0 = any */
    uint8_t  flags_set, flags_clear;  /* lớp 1 (flow) — từ 'flags:' */
    /* lớp 2 (payload) */
    uint8_t *content; int content_len; int nocase;
    int      offset, depth;  /* cửa sổ tìm; -1 = không giới hạn */
    char     msg[128];
    uint8_t  action;         /* DROP / ALERT */
    char     category[32];   /* file/category để bật-tắt theo nhóm */
};
```
- Field hỗ trợ MVP: `msg, sid, rev, content, nocase, offset, depth, flags, proto, port, action`. Bỏ qua (parse-skip có log) field chưa support (`pcre, byte_test, flowbits…`) — rule vẫn nạp được phần content.
- `nocase` rule gom vào 1 automaton; rule case-sensitive vào automaton thứ 2.
- `on_match(sid, end_pos)` → kiểm `offset/depth` + `dport/proto/flow-dir` → nếu đủ thì verdict theo `action`.
- Lớp 1 (flow rule) **không cần payload**: bảng dấu hiệu NULL/XMAS/SYN-flood/port-scan/known-bad-port — dùng lại `syn_count/ack_count/...` của `nf_conn_ml`.

### 3.4. Feature extraction (`feature.{c,h}`) + parity

Đọc `nf_conn_ml` (qua dump CTA_ML, tái dùng parser `mgmtd_diag.c ct_ml_emit`) → tính 14 feature:

| # | Feature | Công thức từ `nf_conn_ml` |
|---|---|---|
|0|Flow IAT Std| `sqrt( sample_var(flow_iat_sq_sum, iat_sum_us, iat_count) )` (µs) |
|1|Flow IAT Min| `flow_iat_min` (µs; nếu == U32_MAX → 0) |
|2|Flow IAT Mean| `iat_sum_ns/iat_count` → µs |
|3|Fwd IAT Std| từ `fwd_iat_sum, fwd_iat_sq_sum, fwd_iat_count` |
|4|Packet Length Variance| từ `pktlen_sum, pktlen_sq_sum, n` (xem chú ý double-count gói đầu §5 doc cũ) |
|5|Packet Length Std| `sqrt(#4)` |
|6|Fwd Packet Length Mean| `bytes_fwd/pkts_fwd` (lấy bytes/pkts từ ACCT) |
|7|Bwd Packet Length Mean| `bytes_bwd/pkts_bwd` |
|8–11|SYN/ACK/PSH/URG Count| `syn_count/ack_count/psh_count/urg_count` |
|12|Down/Up Ratio| `pkts_bwd/pkts_fwd` (chia nguyên rồi mới ép double) |
|13|**Init_Win_bytes_forward**| **GAP** — `nf_conn_ml` chưa lưu; xem dưới |

> **GAP feature 13:** model cần `Init_Win_bytes_forward` = `ntohs(tcp window)` của **gói SYN forward đầu tiên**. `nf_conn_ml` chưa có field này. Hai lựa chọn: **(a)** thêm `u16 init_win_fwd` vào `nf_conn_ml` + set trong `ml_account` ở gói fwd đầu (đụng kernel + lại sát ngân sách extension 255B — cần kiểm `sizeof`); **(b)** ipsd tự đọc window từ **gói SYN trong NFQUEUE** (vì N gói đầu đã lên userspace). **Khuyến nghị (b)** cho sprint — không đụng kernel, không tốn ngân sách extension. Đây là điểm phải chốt ngày N3.

- **Định nghĩa "Packet Length":** `ml_account` dùng `ntohs(iph->tot_len)` = **độ dài L3 toàn gói**. Phải xác nhận CICFlowMeter lúc train tính cùng định nghĩa (CICFlowMeter có thể dùng độ dài payload). Bài test parity ngày N3 sẽ phát hiện lệch.
- **Std/Var sample (n−1):** CIC dùng phương sai mẫu. Tính bằng `(sq_sum - sum*sum/n)/(n-1)`.

### 3.5. Decision fusion (`fusion.{c,h}`)
```
signature DROP hit                     → DROP + connmark BLOCK   (ưu tiên cao nhất, khỏi chạy ML)
score ≥ ml_threshold_block             → DROP + connmark BLOCK
ml_threshold_alert ≤ score < block     → ALERT only (log), ACCEPT
score < ml_threshold_alert             → ACCEPT
mode == detect                         → không bao giờ BLOCK, chỉ log
```
Threshold lưu trong config DB; chỉnh qua CLI/GUI. `score` = `sigmoid(predict())` ∈ [0,1].

### 3.6. Cơ chế cập nhật CSDL signature

```
/etc/stargazer/ips/
├── rules/
│   ├── emerging-scan.rules      (ET OPEN, theo category)
│   ├── emerging-exploit.rules
│   └── local.rules              (rule tự viết)
├── enabled.conf                 (category bật/tắt)
└── version                      (signature_set version + checksum)
```
- **Metadata trong SQLite** (`sg_db.c`): bảng `ips_signature_set(version, source, installed_at, rule_count, sha256)`.
- **Import/Update:** mgmtd nhận file rule (qua CLI `execute ips update file <path>` hoặc upload GUI), **validate** (parse thử, đếm rule lỗi), ghi vào `rules/` **atomically** (ghi `.tmp` rồi `rename`), cập nhật version trong DB.
- **Reload không gián đoạn:** ipsd dựng automaton **mới** từ ruleset mới, `ac_build()` xong **mới swap con trỏ** (RCU-style userspace / hoán đổi dưới mutex) rồi `ac_free()` cái cũ — không có cửa sổ "rỗng rule".
- **Mô hình tham chiếu:** Suricata-Update (quản lý ruleset theo source/category, enable-disable, reload SIGUSR2). Online fetch (HTTPS tải ruleset ET OPEN) đánh dấu **stretch** — sprint làm import file là đủ.

### 3.7. Quản lý kiểu FortiGate (CLI + GUI)

FortiGate tách: **IPS signatures** (CSDL) → **IPS sensor/profile** (chọn signature + action) → gắn profile vào **firewall policy**. Bản rút gọn cho Stargazer:

- **Config type `security_ips`** (đăng ký trong `sg_validate.c`, schema `db_schema.sql`):
  `enabled`, `mode` (detect/prevent), `ml_threshold_block`, `ml_threshold_alert`, `signature_set`, `snapshot_n` (N gói).
- **CLI** (`cli_configure.c` + `sg_cmd_defs.h`): context **single** `config security ips`:
  ```
  config security ips
      set status enable
      set mode prevent
      set ml-threshold-block 0.8
      set ml-threshold-alert 0.5
  end
  execute ips update file /tmp/emerging.rules
  diagnose ips status            # ipsd up?, ruleset version, #rule, #alert
  diagnose ips signatures        # list rule đang nạp
  diagnose session ml            # (đã có) xem feature + score
  ```
- **mgmtd**: seed config mặc định; `supervisor_start("ipsd", …, SRC_CONFIG)` chỉ khi `status enable`; dải IPC `SG_CMD` **700** cho status/update.
- **GUI** (`webd`): mục **Security → IPS** — trang trạng thái (ipsd, ruleset version, đếm alert), form config (mode/threshold), bảng **alert log**, nút **import ruleset**. Nối trang **Sessions** hiển thị cột `ml_score` (lấy từ dump CTA_ML).
- **Logging:** alert IPS ghi vào partition `sglogs` (`/etc/stargazer/logs`), 1 dòng/alert: `ts, src, dst, proto, sid/msg, score, action`.

---

## 4. Bản đồ thay đổi codebase

| File | Loại |
|---|---|
| `src/modules/pkt_forward.c` | sửa: connmark enforcement + NF_QUEUE N gói đầu + procfs `ips_enable` |
| `src/modules/Makefile` | (kiểm) đảm bảo build OK |
| `src/userspace/ipsd/{main,nfq,feature,ac,sig_rule,fusion,log,ipc}.{c,h}` | **mới** |
| `src/userspace/ipsd/model/predict.{c,h}` | copy từ `Machine Learning/ips_c/` |
| `Makefile` (root) | sửa: target `ipsd` (musl static), rootfs + test initramfs, cài rule mặc định |
| `src/userspace/common/sg_validate.c` | sửa: đăng ký config type `security_ips` |
| `src/userspace/usr/libexec/stargazer/db_schema.sql` | sửa: bảng config + `ips_signature_set` |
| `src/userspace/mgmtd/{sg_db.c,mgmtd_diag.c,stargazer_ipc.h}` | sửa: config + supervisor + IPC 700 |
| `src/userspace/cli/{cli_configure.c,cli_cmd_table.c}` + `common/sg_cmd_defs.h` | sửa: context + lệnh |
| `webd` (theo `docs/webui-structure.md`) | sửa: trang Security/IPS + cột ml_score |

---

## 5. Kế hoạch theo ngày (10 ngày) + tài liệu tham khảo mỗi ngày

> **Critical path** (demo tối thiểu): N1 → N2 → N3 → N5 → N6. Trễ thì cắt **stretch** trước (payload-AC N7 phần online-update, netlink, ml_score writeback). Aho-Corasick (N4) làm/test **độc lập trên host**, có thể chạy song song N1–N3.

### Tuần 1 — Inline transport + feature + ML chạy được

#### N1 — Kernel: enforcement connmark + NFQUEUE N gói đầu
- Thêm bit `SG_CMK_IPS_BLOCK/INSPECTED`; `forward_hook`: fast-path DROP nếu BLOCK, ACCEPT nếu INSPECTED, `NF_QUEUE` cho N gói đầu khi `ips_enabled`. procfs `/proc/stargazer/ips_enable` + queue-num.
- **Kiểm chứng:** `make modules` pass; bật queue, `nft`/iptables `NFQUEUE` rule, gói tới được queue (test bằng `nfqueue` echo daemon).
- **Tài liệu:** `pkt_forward.c` (hook hiện tại), connmark trong commit `fb79d7e`/`f57c269`; `man iptables-extensions` (NFQUEUE, connmark, connbytes); netfilter.org NFQUEUE doc; `nf_conntrack_ml.h`.

#### N2 — `stargazer-ipsd` skeleton + NFQUEUE I/O
- Khung daemon musl static (theo `mgmtd`/`webd`): mở NFQUEUE qua **libnetfilter_queue**, đọc gói, parse IP/TCP/UDP, lấy payload + `NFQA_CT` (ctmark/tuple), trả verdict ACCEPT (pass-through). Stub đọc config qua IPC.
- **Kiểm chứng:** boot QEMU, traffic forward đi qua ipsd (counter tăng), verdict ACCEPT không làm rớt kết nối.
- **Tài liệu:** `src/userspace/mgmtd/` (vòng đời daemon, IPC socket), root `Makefile` target musl; libnetfilter_queue API (`nfq_open/create_queue/set_mode/nfq_set_verdict2`, ví dụ `nf-queue.c`); `stargazer_ipc.h`.

#### N3 — Feature extraction + parity với CICFlowMeter (Complete)
- Đọc `nf_conn_ml` qua dump CTA_ML (tái dùng parser `ct_ml_emit`); dựng vector 14 feature; **chốt GAP feature 13** (đọc TCP window từ gói SYN trong NFQUEUE — phương án (b) §3.4). Test parity: chạy CICFlowMeter trên `CICFlowMeter/micro.pcap`, so từng feature với `feature.c`.
- **Kiểm chứng:** sai số từng feature rất nhỏ trên pcap mẫu; xác nhận định nghĩa "Packet Length".
- **Tài liệu:** `feature_order.json`, `stargazer_ids.txt` (`feature_infos` để biết range), `nf_conntrack_ml.h` (ý nghĩa field), `mgmtd_diag.c:1901` (parser CTA_ML), `CICFlowMeter/src` (định nghĩa FlowFeature) + `micro.pcap_Flow.csv`; CIC-IDS2017 paper (ICISSP 2018).

#### N4 — Aho-Corasick engine + unit test trên host (song song) (Complete)
- Đưa AC từ `ips-implementation-guide.md §3` vào `ipsd/ac.{c,h}`; viết `ac_test.c` (he/she/his/hers; nocase; payload rỗng; pattern > payload; byte `0x00`).
- **Kiểm chứng:** unit test xanh trên host (native gcc) **trước khi** nhúng.
- **Tài liệu:** `ips-implementation-guide.md §3`; Aho & Corasick (CACM 1975); Norton/Sourcefire 2004; Tuck et al. (INFOCOM 2004).

#### N5 — Ghép LightGBM + fusion → demo chặn
- Copy `Machine Learning/ips_c/{main.c→predict.c,header.h}` vào `ipsd/model/`; nối `feature → predict() → postprocess()(sigmoid) → score`; fusion theo threshold; verdict DROP → set connmark BLOCK (NFQA_CT) + nfq DROP.
- **Kiểm chứng demo:** replay/sinh flow tấn công → score cao → gói tiếp theo của flow bị DROP (connmark); flow lành → ACCEPT + INSPECTED (offload).
- **Tài liệu:** `ips_c/header.h` (chữ ký `predict/postprocess`), `recipe.json`; LightGBM paper (Ke 2017); tl2cgen docs; fusion §3.5 (bản này) + `ips-architecture.md §9`.

### Tuần 2 — Signature + cập nhật ruleset + quản lý + test

#### N6 — Signature L1 (flow rule) + fusion ordering + mode
- Bảng flow-rule (NULL/XMAS/SYN-flood/port-scan/known-bad-port) dùng `*_count` của `nf_conn_ml`; fusion đúng thứ tự ưu tiên; mode detect/prevent.
- **Kiểm chứng:** `nmap -sN`/`-sX` từ lanvm → rule hit → DROP + alert; mode detect chỉ log.
- **Tài liệu:** `ips-architecture.md §10.2`; Snort rule semantics (flags); §3.5 bản này; `scripts/run_lanvm.sh`.

#### N7 — Signature L2 (payload) + parser rule ET-OPEN-subset (Complete)
- Parser rule (`msg/sid/content/nocase/offset/depth/flags/proto/port/action`) → `ac_add_pattern` → `ac_build`; `on_match` kiểm offset/depth/port/proto; chạy AC trên payload N gói đầu (đã có từ NFQUEUE).
- **Kiểm chứng:** nạp một file ET OPEN thật (vd `emerging-scan.rules`); gửi payload chứa `UNION SELECT` → AC match → DROP; rule lỗi bị skip có log.
- **Tài liệu:** Snort/Suricata rule docs; ET OPEN ruleset (định dạng); `ips-implementation-guide.md §4`; Suricata MPM.

#### N8 — Kho signature + cơ chế cập nhật + reload an toàn (50% Complete)
- Layout `/etc/stargazer/ips/` (§3.6); bảng SQLite `ips_signature_set`; `execute ips update file …` (validate → ghi atomic → bump version → reload AC swap); category enable/disable.
- **Kiểm chứng:** import ruleset mới → version đổi, rule mới có hiệu lực, không có cửa sổ rỗng-rule; rule hỏng không phá ruleset đang chạy.
- **Tài liệu:** `sg_db.c`, `db_schema.sql`; Suricata-Update (mô hình quản lý ruleset/category/reload); §3.6 bản này.

#### N9 — Quản lý FortiGate-style: config type + CLI + GUI
- mgmtd config type `security_ips` (`sg_validate.c`, schema) + seed + `supervisor_start(ipsd)` + IPC 700 status; CLI context `config security ips` + `diagnose ips status/signatures`; GUI Security/IPS (status, config, alert log, import) + cột `ml_score` ở Sessions.
- **Kiểm chứng:** bật/tắt IPS qua CLI/GUI → ipsd tự start/stop; chỉnh threshold có hiệu lực; xem alert + flow trên web.
- **Tài liệu:** `sg_validate.c` (registry), `cli_configure.c` + `sg_cmd_defs.h` (context mẫu), `stargazer_ipc.h` (dải lệnh), `sg_db.c`; `docs/webui-structure.md`; FortiGate IPS UX (sensor/signature/profile) làm tham chiếu thiết kế.

#### N10 — Logging + test tổng hợp + evaluation (+ stretch)
- Alert log vào `sglogs`; test E2E trên QEMU: nmap/hping3 từ lanvm + replay pcap CIC-IDS2017; tinh chỉnh threshold; viết phần evaluation (confusion matrix, FP/FN, độ trễ inline, throughput offload). **Stretch:** ghi `ml_score` về kernel (procfs/ctnetlink SET); online fetch ruleset; nâng transport.
- **Kiểm chứng:** báo cáo đánh giá; tất cả test ở §6 pass.
- **Tài liệu:** cơ chế logging hiện có (`sglogs`); `scripts/run_lanvm.sh`, `scripts/qemu-selftest.py`; CIC-IDS2017; Sommer & Paxson (S&P 2010) để khung hóa phần đánh giá ML-NIDS.

---

## 6. Kế hoạch test ("tests verify real behavior")

| Test | Cách làm | Pass khi |
|---|---|---|
| AC unit | `ac_test.c` trên host | khớp tập match kỳ vọng; binary-safe |
| Feature parity | CICFlowMeter vs `feature.c` trên `micro.pcap` | sai số từng feature rất nhỏ |
| Enforcement | set connmark BLOCK thủ công | gói sau của flow bị NF_DROP |
| NFQUEUE path | bật ipsd pass-through | kết nối forward vẫn thông |
| Signature L1 | `nmap -sN/-sX` từ lanvm | rule hit → DROP + alert |
| Signature L2 | payload `UNION SELECT` | AC match → DROP |
| ML E2E | replay pcap tấn công CIC | score cao → DROP gói tiếp theo |
| Ruleset update | import file rule mới | version đổi, reload không rỗng-rule |
| Mode detect | `mode=detect` | chỉ log, không drop |

Môi trường: QEMU (`make test`); traffic tấn công từ VM phụ (`scripts/run_lanvm.sh`) hoặc replay CIC-IDS2017.

---

## 7. Rủi ro & điểm phải chốt

1. **Feature parity** (rủi ro lớn nhất): định nghĩa "Packet Length" (L3 toàn gói trong `ml_account` vs payload trong CICFlowMeter) và quy tắc IAT/double-count gói đầu phải khớp lúc train — test N3 quyết định.
2. **Feature 13 `Init_Win_bytes_forward`**: chốt phương án (b) đọc từ gói SYN trong NFQUEUE (N3).
3. **`StandardScaler` lúc train?** Nếu có thì bỏ được khi convert (tree scale-invariant) — xác nhận với notebook `stargazer_train_export.ipynb`.
4. **Ngân sách conntrack extension 255B**: nếu chọn thêm field vào `nf_conn_ml` (phương án (a) feature 13) phải kiểm `sizeof(struct nf_conn_ml)` + tổng extension ≤ 255 (commit `b60fb46` đã sát ngân sách, đã phải tắt SYNPROXY/NET_ACT_CT).
5. **Partial-flow accuracy**: nên train/eval lại trên flow cắt N gói (N10).
6. **Throughput**: N gói đầu phải đủ nhỏ để không nghẽn NFQUEUE trên BPI-R4; đo ở N10.
7. **CONFIG kernel**: bật `CONFIG_NETFILTER_NETLINK_QUEUE` (kiểm trong cấu hình kernel `stargazer-kernel`).

---

## 8. Thứ tự thực thi (critical path)

```
N1 connmark+NFQUEUE ─┐
N2 ipsd skeleton    ─┤→ N3 feature+parity → N5 ML+fusion → N6 sig L1
N4 AC (host, song song)┘                         (DEMO tối thiểu xong sau N5)
N7 sig L2 (payload) → N8 ruleset update → N9 CLI/GUI → N10 log+eval(+stretch)
```

---

## 9. Tài liệu nội bộ hay dùng (tra nhanh)

| Cần gì | Xem ở đâu |
|---|---|
| Field ML + ý nghĩa | `stargazer-kernel/include/net/netfilter/nf_conntrack_ml.h` |
| Accounting logic | `src/modules/pkt_forward.c:166` (`ml_account`) |
| Parser CTA_ML userspace | `src/userspace/mgmtd/mgmtd_diag.c:1857,1901` |
| Thứ tự 14 feature | `Machine Learning/feature_order.json`, `stargazer_ids.txt` |
| Model C | `Machine Learning/ips_c/{main.c,header.h,recipe.json}` |
| AC mẫu | `docs/ips-implementation-guide.md §3` |
| Định nghĩa feature gốc | `CICFlowMeter/src`, `CICFlowMeter/micro.pcap_Flow.csv` |
| Config registry/CLI | `src/userspace/common/{sg_validate.c,sg_cmd_defs.h}`, `cli/cli_configure.c` |
| IPC | `src/userspace/mgmtd/stargazer_ipc.h` |
| Web UI | `docs/webui-structure.md` |
| Lịch sử thiết kế IPS | `docs/ips-architecture.md`, `docs/ips-implementation-guide.md` (một phần đã lỗi thời) |

---

## 10. Bibliography (chứng minh kiến trúc)

1. A. V. Aho, M. J. Corasick. *Efficient string matching: an aid to bibliographic search.* CACM 18(6), 1975.
2. M. Roesch. *Snort: Lightweight Intrusion Detection for Networks.* LISA 1999.
3. M. Norton (Sourcefire). *Optimizing Pattern Matching for Intrusion Detection.* 2004.
4. N. Tuck, T. Sherwood, B. Calder, G. Varghese. *Deterministic Memory-Efficient String Matching Algorithms for Intrusion Detection.* IEEE INFOCOM 2004.
5. X. Wang et al. *Hyperscan: A Fast Multi-pattern Regex Matcher for Modern CPUs.* USENIX NSDI 2019. (Vectorscan = bản port ARM.)
6. B. Commentz-Walter. *A String Matching Algorithm Fast on the Average.* ICALP 1979.
7. S. Wu, U. Manber. *A Fast Algorithm for Multi-Pattern Searching.* 1994 (agrep).
8. G. Ke et al. *LightGBM: A Highly Efficient Gradient Boosting Decision Tree.* NeurIPS 2017.
9. I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani. *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization (CIC-IDS2017).* ICISSP 2018. (CICFlowMeter.)
10. R. Sommer, V. Paxson. *Outside the Closed World: On Using Machine Learning for Network Intrusion Detection.* IEEE S&P 2010.
11. P. García-Teodoro et al. *Anomaly-based network intrusion detection: Techniques, systems and challenges.* Computers & Security, 2009.
12. A. L. Buczak, E. Guven. *A Survey of Data Mining and Machine Learning Methods for Cyber Security Intrusion Detection.* IEEE Comm. Surveys & Tutorials, 2016.
13. OISF. *Suricata User Guide* (rule format, MPM, Suricata-Update). Proofpoint *Emerging Threats Open* ruleset.
14. netfilter.org. *libnetfilter_queue / NFQUEUE* documentation; DMLC *treelite / tl2cgen* documentation.

---

*Bản kế hoạch chủ đạo. Theo quy ước dự án, chưa có thay đổi mã nguồn nào được commit cho tới khi các điểm ở §7 được chốt và kế hoạch được duyệt.*
