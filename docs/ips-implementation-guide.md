# Hướng dẫn triển khai kỹ thuật — IPS cho Stargazer NGFW

> Bản đồng hành với `ips-master-plan.md`. Bản kia trả lời **"làm cái gì, theo nhịp nào, vì sao"**; bản này trả lời **"code cụ thể ra sao"** trên đúng codebase hiện tại.
> Thuật toán pattern matching: **Aho-Corasick** (tự viết, không dependency, link tĩnh musl).
>
> **Cập nhật kiến trúc (2026-06):** data-plane đã bỏ `session.ko` và chuyển sang **nf_conntrack** (commit `020287d`). 14 ML feature nằm trong conntrack extension `struct nf_conn_ml` (`stargazer-kernel/include/net/netfilter/nf_conntrack_ml.h`), điền bởi `ml_account()` trong `pkt_forward.c`, export lên userspace qua ctnetlink `CTA_ML`. Enforcement dùng **connmark + NFQUEUE N gói đầu** (đã chốt trong master plan), **không** dùng `sess_set_verdict`/`SESS_MARKED` nữa. Tài liệu này đã được viết lại cho kiến trúc đó; phần Aho-Corasick (§3) giữ nguyên vì độc lập với transport.
>
> Theo quy ước dự án ("create a plan first before make any changes"), tài liệu này là **kế hoạch hiện thực**. Code mẫu bên dưới là bản tham chiếu để dán vào source khi bắt tay, **chưa được commit vào cây mã**.

---

## 0. Bản đồ thay đổi trên codebase

| Lớp | File | Loại thay đổi |
|---|---|---|
| Kernel — data-plane | `src/modules/pkt_forward.c` | Sửa: enforcement connmark (BLOCK/INSPECTED) + `NF_QUEUE` N gói đầu + procfs bật/tắt IPS. `ml_account()` (accounting 17 feature) **đã có** |
| Kernel — conntrack | `stargazer-kernel/.../nf_conntrack_ml.h` | **Đã có**: `struct nf_conn_ml` + export `CTA_ML`. Chỉ đụng nếu thêm `init_win_fwd` (xem §2.4) |
| Userspace — daemon | `src/userspace/ipsd/` | **Mới**: `stargazer-ipsd` |
| Userspace — NFQUEUE | `src/userspace/ipsd/nfq.{c,h}` | **Mới**: mở queue, đọc payload + ctmark, trả verdict + set connmark |
| Userspace — AC | `src/userspace/ipsd/ac.{c,h}` | **Mới**: engine Aho-Corasick |
| Userspace — rule | `src/userspace/ipsd/sig_rule.{c,h}` | **Mới**: parser rule ET-OPEN-subset + lớp 1 flow rule |
| Userspace — feature | `src/userspace/ipsd/feature.{c,h}` | **Mới**: 17 feature từ `CTA_ML` + parity |
| Userspace — ML | `src/userspace/ipsd/model/` | **Mới**: `predict.{c,h}` (copy từ `Machine Learning/ips_c/`) |
| Build | `Makefile` (root) | Sửa: target `ipsd`, đưa vào rootfs/test |
| Quản lý | `mgmtd`, `cli`, `webui` | Sửa: config type `security_ips` |

---

## 1. Quyết định kiến trúc cho pattern matching

**Aho-Corasick chạy ở USERSPACE (`ipsd`), không ở kernel.** Lý do:

1. Payload signature cần **đọc nội dung gói** → phải lấy gói lên userspace qua **NFQUEUE** (chỉ N gói đầu của flow). Đằng nào payload đã ở userspace.
2. Dựng automaton từ ruleset động (cấp phát, realloc, parse string) **dễ và an toàn ở userspace** hơn nhiều so với trong kernel.
3. Giữ kernel mỏng — đúng nguyên tắc "kernel chỉ làm số nguyên + enforcement".

Lớp signature theo **flow** (lớp 1, không cần payload) thì chỉ là vài chục phép so sánh số nguyên — có thể đặt ở kernel hoặc userspace; tài liệu này đặt cả hai lớp signature trong `ipsd` cho gọn, kernel chỉ giữ enforcement qua connmark.

```
                 kernel                          │            userspace (ipsd)
 ┌─────────────────────────────────────────┐    │   ┌──────────────────────────────────┐
 │ pkt_forward → nf_conntrack (đếm,integer)│    │   │ feature extraction → 17 feature  │
 │   ml_account → NF_CT_EXT_ML ────────────┼────┼──►│   (đọc CTA_ML qua ctnetlink dump) │
 │   N gói đầu → NF_QUEUE (payload) ────────┼────┼──►│ signature lớp 1 (flow rule)      │
 │                                          │    │   │ signature lớp 2 (Aho-Corasick)   │
 │ enforcement:                             │    │   │ ML LightGBM                      │
 │   connmark BLOCK → NF_DROP               │◄───┼───│ decision fusion → verdict        │
 │   connmark INSPECTED → NF_ACCEPT(offload)│    │   │   set connmark (NFQA_CT) + nfq    │
 └─────────────────────────────────────────┘    │   │   verdict ACCEPT/DROP             │
                                                 │   └──────────────────────────────────┘
```

> Verdict đi xuống kernel qua **connmark** đính trong message verdict của NFQUEUE (`NFQA_CT` → `CTA_MARK`) — không cần API kernel mới. `pkt_forward` đọc connmark ở fast-path: `BLOCK` → drop mọi gói sau; `INSPECTED` → cho qua, khỏi queue (offload). Đây là mô hình *flow-based inspection* của FortiGate.

---

## 2. Lớp A — Kernel: enforcement connmark + NFQUEUE (concrete)

Accounting 17 feature (`ml_account` → `NF_CT_EXT_ML`) **đã có** trong `pkt_forward.c` và export qua `CTA_ML` — không phải viết lại. Phần cần thêm là **enforcement** (đọc connmark) và **đẩy N gói đầu lên userspace** (`NF_QUEUE`).

### 2.1. Bit connmark cho IPS

Dùng connmark (đã có hạ tầng dirty-flow connmark — commit `fb79d7e`, `f57c269`). Chọn 2 bit chưa dùng, đặt cạnh các define connmark sẵn có:

```c
#define SG_CMK_IPS_BLOCK     (1u << 16)  /* flow xấu → mọi gói sau DROP        */
#define SG_CMK_IPS_INSPECTED (1u << 17)  /* đã có verdict ACCEPT → offload queue */
```

> Kiểm tra không đụng dải bit mà connmark dirty-flow/policy-id đang dùng (xem các define connmark hiện có trong `pkt_forward.c` / phần conntrack reader của mgmtd).

### 2.2. Tham số bật/tắt + queue number

`ipsd` chỉ chạy khi IPS được bật; kernel cần biết bật/tắt và số queue. Dùng module param + procfs ghi được:

```c
static bool ips_enabled;          /* mgmtd ghi qua /proc/stargazer/ips_enable */
static u16  ips_queue_num = 0;    /* số NFQUEUE ipsd lắng nghe                */
static u32  ips_snapshot_n = 8;   /* soi N gói đầu mỗi flow (FEATURE_SNAPSHOT_N) */
```

### 2.3. Enforcement trong `forward_hook`

Chèn vào sau bước `ml_account()` (gói đã qua validate + anomaly screen). Đếm số gói lấy từ ACCT extension hoặc `nf_conn_ml.iat_count + 1`:

```c
enum ip_conntrack_info ctinfo;
struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

if (ct) {
    u32 mark = READ_ONCE(ct->mark);

    /* fast path: flow đã bị đánh dấu xấu → chặn ngay */
    if (mark & SG_CMK_IPS_BLOCK) {
        atomic64_inc(&pkts_dropped);
        return NF_DROP;
    }
    /* đã có verdict ACCEPT → offload, khỏi queue lại */
    if (mark & SG_CMK_IPS_INSPECTED)
        return NF_ACCEPT;

    /* cần soi: queue N gói đầu lên ipsd để lấy payload + chấm điểm.
     * ct_pkts() = tổng gói của flow, lấy từ ACCT extension hoặc nf_conn_ml.iat_count+1. */
    if (READ_ONCE(ips_enabled) && ct_pkts(ct) <= READ_ONCE(ips_snapshot_n)) {
        /* NF_QUEUE_NR: bao verdict + số queue. Nếu không có listener thì
         * NFQUEUE mặc định DROP — phải đảm bảo ipsd chạy trước khi bật, hoặc
         * dùng cờ NF_QUEUE_FLAG_BYPASS để fail-open. */
        return NF_QUEUE_NR(READ_ONCE(ips_queue_num));
    }
}
atomic64_inc(&pkts_forwarded);
return NF_ACCEPT;
```

> **Fail-open vs fail-closed:** quyết định hành vi khi `ipsd` chết — bypass (cho qua, an toàn cho mạng) hay drop (chặt chẽ). Mặc định khuyến nghị **bypass** cho thiết bị inline (tránh đứt mạng khi daemon lỗi); ghi rõ lựa chọn này trong báo cáo.

### 2.4. (Tùy chọn) ghi `ml_score` về kernel để hiển thị

`nf_conn_ml.ml_score` đã có field nhưng chưa ai ghi. Để `diagnose session ml` hiện điểm: hoặc thêm ctnetlink SET cho `CTA_ML`, hoặc 1 procfs `/proc/stargazer/verdict` nhận `(tuple, score)`. **Stretch** — sprint có thể bỏ qua, score sống ở log/ipsd. (Tương tự, feature 13 `Init_Win_bytes_forward`: khuyến nghị `ipsd` đọc TCP window từ gói SYN trong NFQUEUE thay vì thêm field kernel — xem master plan §3.4.)

---

## 3. Aho-Corasick engine (trọng tâm)

### 3.1. Vì sao Aho-Corasick, không phải KMP

- **KMP** khớp **1 mẫu/lần** → có K rule phải quét K lần: O(K·n). Không scale.
- **Aho-Corasick** dựng **một automaton từ TẤT CẢ mẫu**, quét payload **một lần** bắt mọi mẫu: O(n + Σ|mẫu| + số_match), **không phụ thuộc K khi quét**. Đây là lý do Snort/Suricata dùng họ thuật toán này.
- Hyperscan/Vectorscan mạnh hơn (regex, SIMD) nhưng Hyperscan **x86-only** (không chạy ARM BPI-R4) và nặng → để dành "future work". Xem phân tích trong lịch sử thiết kế.

### 3.2. Cấu trúc dữ liệu — `ac.h`

Dùng **DFA đầy đủ** (mỗi node có đủ 256 cạnh sau khi build) → vòng lặp search chỉ 1 phép chuyển trạng thái/byte, không cần đi theo fail link lúc chạy.

```c
#ifndef SG_AC_H
#define SG_AC_H
#include <stdint.h>
#include <stddef.h>

#define AC_ALPHABET 256

struct ac_node {
    int32_t next[AC_ALPHABET];  /* goto/DFA: -1 khi đang build, đủ sau ac_build */
    int32_t fail;               /* failure link (chỉ dùng lúc build)            */
    int32_t out;                /* id pattern KẾT THÚC tại node này, -1 nếu không*/
    int32_t out_link;           /* link tới node output gần nhất theo fail, -1   */
};

struct ac_automaton {
    struct ac_node *nodes;
    int32_t n_nodes, cap_nodes;
    int     nocase;             /* 1 = không phân biệt hoa thường */
    int     built;              /* chặn search trước khi build     */
};

int  ac_init(struct ac_automaton *ac, int nocase);
int  ac_add_pattern(struct ac_automaton *ac, const uint8_t *pat, int len, int id);
int  ac_build(struct ac_automaton *ac);
/* on_match trả !=0 để dừng sớm. Trả về số match. */
int  ac_search(const struct ac_automaton *ac, const uint8_t *text, size_t len,
               int (*on_match)(int id, size_t end_pos, void *ctx), void *ctx);
void ac_free(struct ac_automaton *ac);
#endif
```

### 3.3. Hiện thực — `ac.c`

```c
#include "ac.h"
#include <stdlib.h>
#include <string.h>

static inline uint8_t norm(int nocase, uint8_t c)
{
    return (nocase && c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
}

static int ac_new_node(struct ac_automaton *ac)
{
    if (ac->n_nodes == ac->cap_nodes) {
        int32_t ncap = ac->cap_nodes ? ac->cap_nodes * 2 : 256;
        struct ac_node *p = realloc(ac->nodes, (size_t)ncap * sizeof(*p));
        if (!p) return -1;                 /* buffer check bắt buộc */
        ac->nodes = p;
        ac->cap_nodes = ncap;
    }
    struct ac_node *n = &ac->nodes[ac->n_nodes];
    for (int i = 0; i < AC_ALPHABET; i++) n->next[i] = -1;
    n->fail = -1; n->out = -1; n->out_link = -1;
    return ac->n_nodes++;
}

int ac_init(struct ac_automaton *ac, int nocase)
{
    memset(ac, 0, sizeof(*ac));
    ac->nocase = nocase ? 1 : 0;
    return ac_new_node(ac) == 0 ? 0 : -1;  /* node 0 = root */
}

int ac_add_pattern(struct ac_automaton *ac, const uint8_t *pat, int len, int id)
{
    if (ac->built || len <= 0) return -1;
    int32_t u = 0;
    for (int i = 0; i < len; i++) {
        uint8_t c = norm(ac->nocase, pat[i]);
        if (ac->nodes[u].next[c] == -1) {
            int v = ac_new_node(ac);
            if (v < 0) return -1;
            ac->nodes[u].next[c] = v;       /* lưu ý: realloc có thể đổi con trỏ */
        }
        u = ac->nodes[u].next[c];
    }
    ac->nodes[u].out = id;                   /* pattern kết thúc tại đây */
    return 0;
}

/* BFS dựng failure + DFA goto + output link */
int ac_build(struct ac_automaton *ac)
{
    int32_t *queue = malloc((size_t)ac->n_nodes * sizeof(int32_t));
    if (!queue) return -1;
    int head = 0, tail = 0;

    /* depth-1: fail = root, và điền cạnh trống của root về chính root */
    for (int c = 0; c < AC_ALPHABET; c++) {
        int32_t v = ac->nodes[0].next[c];
        if (v == -1) {
            ac->nodes[0].next[c] = 0;        /* DFA: root đọc ký tự lạ → ở lại root */
        } else {
            ac->nodes[v].fail = 0;
            queue[tail++] = v;
        }
    }

    while (head < tail) {
        int32_t u = queue[head++];
        for (int c = 0; c < AC_ALPHABET; c++) {
            int32_t v = ac->nodes[u].next[c];
            int32_t f = ac->nodes[u].fail;
            if (v == -1) {
                ac->nodes[u].next[c] = ac->nodes[f].next[c];  /* DFA goto */
            } else {
                ac->nodes[v].fail = ac->nodes[f].next[c];
                int32_t vf = ac->nodes[v].fail;
                ac->nodes[v].out_link =
                    (ac->nodes[vf].out != -1) ? vf : ac->nodes[vf].out_link;
                queue[tail++] = v;
            }
        }
    }
    free(queue);
    ac->built = 1;
    return 0;
}

int ac_search(const struct ac_automaton *ac, const uint8_t *text, size_t len,
              int (*on_match)(int, size_t, void *), void *ctx)
{
    if (!ac->built) return -1;
    int32_t st = 0, hits = 0;
    for (size_t i = 0; i < len; i++) {        /* vòng lặp bị chặn bởi len */
        uint8_t c = norm(ac->nocase, text[i]);
        st = ac->nodes[st].next[c];
        for (int32_t t = st; t != -1; t = ac->nodes[t].out_link) {
            if (ac->nodes[t].out != -1) {
                hits++;
                if (on_match && on_match(ac->nodes[t].out, i, ctx))
                    return hits;              /* dừng sớm theo yêu cầu caller */
            }
        }
    }
    return hits;
}

void ac_free(struct ac_automaton *ac)
{
    free(ac->nodes);
    memset(ac, 0, sizeof(*ac));
}
```

**Ghi chú đúng tinh thần "a buffer is always checked":**
- Mọi `realloc`/`malloc` đều kiểm tra NULL trước khi dùng.
- `ac_search` chỉ duyệt đúng `len` byte payload (len lấy từ NFQUEUE, đã bounded) — không đọc quá biên.
- `nocase` xử lý bằng `norm()` áp **cả lúc add lẫn lúc search** → nhất quán.
- Bộ nhớ: mỗi node 256×4 = 1KB. Với vài trăm pattern (vài nghìn node) ≈ vài MB — chấp nhận được ở userspace. Nếu ruleset lớn, đổi `next[256]` sang map thưa (đánh đổi tốc độ) — ghi rõ là tối ưu về sau.

### 3.4. Kiểm thử đơn vị (bắt buộc trước khi tin)

`ac_test.c` chạy trên host (native gcc), độc lập với build ARM:

```c
/* patterns: "he","she","his","hers" — ví dụ kinh điển của Aho-Corasick */
/* text = "ushers" → kỳ vọng: "she"(@3), "he"(@3), "hers"(@5) */
```

Test phải phủ: pattern là tiền tố của pattern khác (`he`⊂`hers`), overlap (`she`/`he`), `nocase`, payload rỗng, pattern dài hơn payload, byte 0x00 trong payload (binary-safe — dùng `len`, không dựa `\0`).

---

## 4. Rule: parser subset-Snort nạp vào Aho-Corasick

### 4.1. Mô hình rule

```c
struct sig_rule {
    int   id;
    uint8_t proto;            /* TCP/UDP/ANY */
    uint16_t dport;           /* 0 = any   */
    uint8_t  flags_set, flags_clear;  /* lớp 1 (flow) */
    /* lớp 2 (payload) */
    uint8_t *content;  int content_len;  int nocase;
    int      offset, depth;   /* giới hạn cửa sổ tìm trong payload, -1 = không giới hạn */
    char     msg[64];
    uint8_t  action;          /* DROP / ALERT */
};
```

### 4.2. Luồng nạp

```
đọc /etc/stargazer/ips/rules/*.rules   (ET-OPEN-subset; xem master plan §3.6)
   → parse từng dòng (field hỗ trợ: msg, sid, rev, content, nocase, offset, depth, flags, port/proto, action)
   → field chưa support (pcre, byte_test, flowbits…) → skip có log, vẫn nạp phần content
   → rule có content → ac_add_pattern(ac, content, len, rule_index)   // map về sid
   → sau khi nạp hết → ac_build(ac)
```

Ví dụ dòng rule (tương thích ET OPEN):
```
alert tcp any any -> $HOME_NET 80 (msg:"WEB SQLi UNION SELECT"; \
      content:"UNION"; nocase; content:"SELECT"; nocase; sid:2008538; rev:5;)
```

`on_match(id, end_pos, ctx)` tra `rule[id]` → kiểm `offset/depth` (vị trí match có nằm trong cửa sổ cho phép không), kiểm `dport/proto` của flow → nếu khớp đủ thì ghi verdict theo `rule.action`.

> **Lưu ý nocase:** đã hạ hoa-thường trong AC → khi `nocase=1` add pattern bản thường; khi rule **phân biệt** hoa thường thì cần một automaton riêng (hoặc thêm cờ kiểm tra lại trên text gốc tại `end_pos`). MVP: gom toàn bộ rule `nocase` vào một automaton, rule case-sensitive vào automaton thứ hai.

### 4.3. Lớp 1 — flow rule (không cần Aho-Corasick)

Duyệt tuyến tính danh sách rule cho mỗi flow, so cờ/đếm — dùng lại đúng `syn_count/ack_count/...` đã có trong `nf_conn_ml`. Bảng dấu hiệu (NULL/XMAS/SYN-flood/port-scan/known-bad-port) xem `ips-master-plan.md §3.3` (và bảng chi tiết ở `ips-architecture.md §10.2`).

---

## 5. `stargazer-ipsd` — khung daemon

Theo đúng khuôn `mgmtd`/`webd`: musl static, single-binary.

```
src/userspace/ipsd/
├── main.c            vòng đời, nạp config từ mgmtd qua IPC
├── nfq.c/.h          mở NFQUEUE (libnetfilter_queue): đọc gói + payload + NFQA_CT,
│                     trả verdict ACCEPT/DROP kèm set connmark (CTA_MARK)
├── ctdump.c/.h       dump CTA_ML theo tuple để lấy flow-stats (tái dùng parser kiểu mgmtd_diag)
├── feature.c/.h      nf_conn_ml → 17 feature (parity CICFlowMeter)
├── ac.c/.h           Aho-Corasick (mục 3)
├── sig_rule.c/.h     parser rule ET-OPEN-subset + lớp 1 flow rule + on_match
├── fusion.c/.h       gộp signature + ML → verdict (master plan §3.5)
├── model/
│   ├── predict.c        copy từ Machine Learning/ips_c/main.c (không sửa tay)
│   └── predict.h        copy từ Machine Learning/ips_c/header.h
└── log.c/.h          ghi alert vào sglogs
```

Vòng chính (event-driven theo NFQUEUE, không poll):
```
1. nạp rule → ac_build();  nạp model (link tĩnh)
2. mỗi gói từ NFQUEUE:
   a. parse IP/TCP/UDP; lấy payload L4, ctmark, tuple; lấy TCP window (gói SYN → feature 13)
   b. ctdump: đọc nf_conn_ml theo tuple → feature.c dựng vector 17 feature
   c. sig_rule lớp 1 (flow): hit → verdict DROP
   d. ac_search(payload) → hit → verdict DROP
   e. ML: predict(feature) → postprocess() (sigmoid) → score ∈ [0,1]
   f. fusion: signature ưu tiên; else theo ngưỡng score (block/alert); mode detect→chỉ log
   g. verdict: DROP → set connmark BLOCK (NFQA_CT) + nfq DROP; ACCEPT → connmark INSPECTED + nfq ACCEPT
   h. log nếu alert/drop
```

---

## 6. Build system

### 6.1. Kernel modules — `src/modules/Makefile`
```makefile
obj-m += pkt_forward.o     # đã có; chỉ sửa code thêm enforcement + NF_QUEUE
```
> Không còn `session.o`/`sg_procfs.o` — accounting + export đã nằm trong `pkt_forward.ko` + nf_conntrack. Kiểm `CONFIG_NETFILTER_NETLINK_QUEUE` đã bật trong cấu hình kernel `stargazer-kernel`.

### 6.2. Root `Makefile` — target `ipsd`

Theo khuôn target `webd`/`mgmtd` (musl static, `-static`). `model/predict.c` build cùng cụm; cần link `libnetfilter_queue` + `libmnl` (build tĩnh cho musl). Đưa binary vào `rootfs` và `test` initramfs; cài rule mặc định vào `/etc/stargazer/ips/rules/`.

```makefile
ipsd: $(MUSL_CC)
	$(MUSL_CC) -static -O2 -Wall -Iinclude \
	    src/userspace/ipsd/*.c src/userspace/ipsd/model/predict.c \
	    -lnetfilter_queue -lmnl -lm \
	    -o $(BUILD_DIR)/ipsd/stargazer-ipsd
```

> Cùng toolchain `aarch64-linux-musl-gcc` với các daemon khác để ABI nhất quán. `predict.c` dùng `math.h` (sigmoid) nên cần `-lm`.

---

## 7. Tích hợp quản lý (mgmtd/CLI/web)

Xem master plan §3.7 (mô hình FortiGate). Tóm tắt nối dây:
- mgmtd: config type `security_ips` (`enabled`, `mode`, `ml_threshold_block`, `ml_threshold_alert`, `signature_set`, `snapshot_n`); `supervisor_start("ipsd")` chỉ khi bật; IPC dải `SG_CMD` 700 cho status/update ruleset.
- CLI: context `config security ips` + `execute ips update file …`, `diagnose ips status/signatures`.
- Web UI: mục Security/IPS (status, config, alert log, import ruleset); nối trang Sessions với `ml_score` lấy từ dump `CTA_ML`.

---

## 8. Kế hoạch test (theo tinh thần "tests verify real behavior")

| Test | Cách làm | Pass khi |
|---|---|---|
| AC unit | `ac_test.c` trên host | khớp tập match kỳ vọng (he/she/his/hers; binary-safe) |
| Feature parity | CICFlowMeter vs `feature.c` trên cùng pcap | sai số từng feature rất nhỏ |
| Enforcement | set connmark BLOCK thủ công (`conntrack -U ... -m <mark>`) | gói sau của flow bị `NF_DROP` |
| NFQUEUE path | bật ipsd pass-through (verdict ACCEPT) | kết nối forward vẫn thông |
| Signature lớp 1 | nmap NULL/XMAS scan từ lanvm | rule hit → DROP + alert log |
| Signature lớp 2 (AC) | gửi payload chứa `UNION SELECT` | AC match → DROP |
| ML end-to-end | replay pcap tấn công CIC qua QEMU | score cao → DROP gói tiếp theo |
| Mode detect | bật `mode=detect` | chỉ log, **không** drop |

Môi trường: QEMU (`make test`), traffic tấn công sinh từ một VM phụ (lanvm) bằng nmap/hping3, hoặc replay pcap CIC-IDS-2017.

---

## 9. Thứ tự thực thi (critical path)

1. **Kernel enforcement + NF_QUEUE** (mục 2) → `make modules` pass; set connmark BLOCK thủ công thấy DROP.
2. **ipsd skeleton + NFQUEUE I/O** (mục 5) → gói forward qua ipsd, verdict ACCEPT pass-through.
3. **AC engine + unit test** (mục 3) → xanh trên host *trước khi* nhúng vào ipsd.
4. **feature + parity test** (đọc CTA_ML; chốt feature 13 từ gói SYN).
5. **Nối ML** (predict + sigmoid + fusion) → demo flow tấn công bị chặn (connmark BLOCK).
6. **Signature lớp 1 (flow) + fusion**, rồi **lớp 2 (AC trên payload NFQUEUE)** + parser ET-OPEN-subset + cập nhật ruleset.
7. Quản lý (mgmtd/CLI/web), cuối cùng ghi `ml_score` về kernel / nâng transport (stretch).

Bước 3 (Aho-Corasick) **làm và test độc lập trên host** được ngay, không phụ thuộc kernel — nên có thể tiến hành song song với bước 1–2. Lịch theo ngày chi tiết: xem **`ips-master-plan.md` §5**.

---

## 10. Điểm phải chốt trước khi code

Đã chốt: thứ tự 14 cột feature (`feature_order.json`), đơn vị IAT = **µs** (đã code trong `ml_account`), transport = **NFQUEUE N gói đầu + connmark**, định dạng model = LightGBM → C qua tl2cgen (`Machine Learning/ips_c/`). Còn phải xác nhận:

1. **"Packet Length" = toàn gói (L3) hay payload?** `ml_account` đang dùng `tot_len` (L3). Test parity (mục 8) so với CICFlowMeter lúc train.
2. **Feature 13 `Init_Win_bytes_forward`** chưa có trong `nf_conn_ml` → đọc TCP window từ gói SYN trong NFQUEUE (khuyến nghị) hay thêm field kernel (đụng ngân sách extension 255B).
3. **`StandardScaler` lúc train?** Nếu có thì bỏ được khi convert (tree scale-invariant) — kiểm `stargazer_train_export.ipynb`.
4. **Fail-open vs fail-closed** khi ipsd chết (mục 2.3).

Chi tiết rủi ro + nghiên cứu nền: **`ips-master-plan.md` §2, §7**.

---

*Bản hướng dẫn hiện thực. Chưa có thay đổi mã nguồn nào được commit cho tới khi các điểm mục 10 được chốt và kế hoạch được duyệt.*
