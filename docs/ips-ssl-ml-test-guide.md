# Hướng dẫn Test toàn diện — IPS + SSL Inspection + Machine Learning

> Stargazer NGFW. Mục tiêu: mô phỏng **từ hành vi vô ý/lành tính → tấn công cơ bản
> → tấn công phức tạp**, qua cả **HTTP rõ** lẫn **HTTPS đã giải mã**, để đánh giá
> hiệu quả của ba lớp phòng thủ:
>
> 1. **Anomaly screen (kernel `pkt_forward.ko`)** — chặn dị thường L3/L4 ngay tại FORWARD.
> 2. **IPS signature engine (`ipsd`)** — Aho-Corasick + reassembly + flowbits trên payload.
> 3. **SSL inspection (`ssld`)** — MITM giải mã TLS rồi đẩy plaintext sang ipsd qua IPC (Phase 4).
> 4. **Machine Learning** — chấm điểm hành vi flow từ đặc trưng conntrack `CTA_ML`, hợp nhất (`ips_fuse`).
>
> Mọi lệnh trong tài liệu này đã được kiểm chứng so với mã nguồn (registry
> `sg_validate.c`, bảng lệnh `sg_cmd_defs.h`). Không có lệnh bịa.

---

## 0. Mô hình test

```
   ┌────────────┐         ┌──────────────────────────┐        ┌───────────┐
   │  Client    │  LAN    │   Stargazer NGFW          │  WAN   │ Internet  │
   │ Ubuntu +   ├────────►│  pkt_forward.ko (FORWARD) ├───────►│  / target │
   │ Chrome,    │         │  ipsd (NFQUEUE + IPC)     │        │  VM       │
   │ curl,nmap  │◄────────┤  ssld (REDIRECT :8443)    │◄───────┤           │
   └────────────┘         └──────────────────────────┘        └───────────┘
```

- **Client**: máy đi qua firewall (đặt default gateway = IP LAN của Stargazer).
  Dùng `curl`, `nmap`, `hping3`, trình duyệt Chrome.
- **Stargazer**: BPI-R4 thật hoặc QEMU. Quan sát qua CLI (`stargazer-cli`).
- Hai lớp datapath chạy song song:
  - **HTTP rõ** → kernel screen + NFQUEUE → ipsd soi trực tiếp.
  - **HTTPS** → `ssld` REDIRECT, giải mã, đẩy plaintext sang ipsd qua IPC.

> ⚠️ SSL inspection cần client **tin chứng chỉ CA của Stargazer** (mục 1.3). Nếu
> không cài CA, browser sẽ báo lỗi cert thay vì cho ta quan sát nội dung.

---

## 1. Chuẩn bị — bật toàn bộ stack (làm 1 lần)

Vào CLI Stargazer, gõ `configure` (hoặc `config`). Cú pháp FortiOS:
`edit <tên>` mở entry, `set <khóa> <giá-trị>`, `next` lưu entry, `end` thoát context.

### 1.1. Bật IPS engine + IPC + ML

```
config security ips
    set status enable
    set mode prevent            # prevent = chặn; detect = chỉ cảnh báo (mục 8)
    set ipc-inspect enable      # Phase 4: soi HTTPS có-state qua IPC
    set ipc-failmode open       # ipsd lỗi → vẫn cho qua + log (đổi 'closed' ở mục 8)
    set ml-https enable         # Pha 2: ML cho HTTPS (mặc định disable — bật để test)
end
```

### 1.2. Tạo IPS profile + chọn category cần chặn

```
config security ips-profile
    edit default
        set status enable
        set categories all       # hoặc "scan,web-application-attack"
    next
end

# (tuỳ chọn) ép action cho 1 category cụ thể thành block:
config security ips-filter
    edit 1
        set profile default
        set type category
        set value web-application-attack
        set action block         # default|block|alert|pass
        set status enable
    next
end
```

> Ruleset đi kèm (`emerging-scan.rules`, ~770 rule ET-OPEN) phủ chủ yếu:
> `attempted-recon`, `network-scan`, `web-application-attack`, `attempted-admin`,
> `trojan-activity`. Đây là nhóm signature ta sẽ kích hoạt ở mục 5–6.

### 1.3. Tạo SSL deep-inspection profile

```
config security ssl-inspection-profile
    edit deep-inspect
        set status enable
        set inspection-mode deep        # deep = MITM giải mã (certificate = chỉ soi SNI)
        set untrusted-server-cert block
    next
end
```

### 1.4. Gắn profile vào policy `accept`

```
config firewall policy
    edit allow-lan-out
        set srcintf lan
        set dstintf wan
        set srcaddr all
        set dstaddr all
        set service all
        set action accept
        set ips-profile default        # gắn IPS → tự bật ips-status
        set ssl-profile deep-inspect   # gắn SSL deep → bật MITM cho policy này
    next
end
```

> **Lưu ý thiết kế (đã chốt):**
> - `set ips-profile <x>` tự bật inspection; `unset ips-profile` tắt. Không có giá trị "none".
> - Policy `deny`/`drop` **không** cho gán `ips-profile`/`ssl-profile` (fail-closed) — CLI báo lỗi, Web ẩn dropdown.
> - SSL deep chỉ thực sự giải mã khi policy có IPS bật — tránh MITM vô ích.

### 1.5. Cài CA của Stargazer lên client

```
# Trên CLI Stargazer: in PEM
execute system ssl-ca-cert
```

Lưu nội dung PEM thành `stargazer-ca.crt` trên client, rồi:

```bash
# Ubuntu (cho curl, hệ thống)
sudo cp stargazer-ca.crt /usr/local/share/ca-certificates/stargazer.crt
sudo update-ca-certificates

# Chrome: Settings → Privacy & security → Security → Manage certificates
#   → Authorities → Import → chọn stargazer-ca.crt → tick "Trust for websites"
```

### 1.6. Xác minh steering trước khi tấn công

```
execute diagnose ssl              # phải thấy: ssld running, CA present, steering rule :8443
execute diagnose ips status       # phải thấy: ipsd running, rules loaded > 0
```

---

## 2. Ma trận test (tổng quan)

| # | Nhóm | Mục tiêu chứng minh | Lớp phòng thủ |
|---|------|---------------------|---------------|
| A | Lành tính / vô ý | **Không false-positive**: traffic thật chạy mượt | Tất cả (baseline) |
| B | Dị thường L3/L4 | Kernel chặn scan/packet dị dạng ngay tại FORWARD | `pkt_forward.ko` |
| C | Signature trên HTTP rõ | IPS bắt payload tấn công cleartext | `ipsd` NFQUEUE |
| D | Signature trên HTTPS | SSL MITM + IPC stateful bắt **cùng** payload qua TLS | `ssld` + IPC |
| E | Machine Learning | ML chấm hành vi bất thường (cleartext + HTTPS) | ML + `ips_fuse` |
| F | Resilience | Fail-mode, hot-reload, detect vs prevent | Vận hành |

**Bộ công cụ quan sát** (chạy sau mỗi test):

| Lệnh | Cho thấy |
|------|----------|
| `execute diagnose ips alerts 50` | Log cảnh báo gần nhất: time, verdict, src→dst, SID, msg, score |
| `execute diagnose ips scores 50` | Điểm ML mỗi flow tại checkpoint: pkts/syn/ack/iwin/score/verdict |
| `execute diagnose ips status` | Trạng thái daemon + số rule + counters |
| `execute diagnose ssl` | ssld, CA, steering, số kết nối bump |
| `execute diagnose session ml` | Đặc trưng `CTA_ML` per-flow từ conntrack |
| `execute diagnose firewall conntrack` | Bảng kết nối sống |
| `cat /proc/stargazer/pkt_forward_stats` | Bộ đếm dị thường L3/L4 của kernel (trên device) |
| `cat /run/stargazer-ipsd-insp.stat` | Telemetry HTTPS-IPC: `sig_hits_https`, `ml_hits_https`, `blocked_https` |

> Reset log giữa các đợt: `execute diagnose ips alerts-clear`.

---

## 3. Nhóm A — Hành vi lành tính / vô ý (baseline không-false-positive)

Mục tiêu: chứng minh firewall **không chặn nhầm** người dùng bình thường. Đây là
phép đo tham chiếu — nếu các test này bị alert/drop thì engine quá nhạy.

```bash
# A1. Duyệt web HTTPS bình thường (deep inspect đang bật)
curl -v https://www.google.com/ -o /dev/null
#  Kỳ vọng: 200 OK; issuer cert = "Stargazer SSL Inspection CA" (chứng minh MITM);
#           KHÔNG có alert; trang hiển thị bình thường trên Chrome.

# A2. Tải file lớn (đẩy nhiều gói/byte qua checkpoint ML)
curl https://speed.hetzner.de/100MB.bin -o /dev/null
#  Kỳ vọng: tải xong; diagnose ips scores → verdict=pass, score < 0.50.

# A3. DNS + ICMP thông thường
dig google.com ; ping -c4 1.1.1.1
#  Kỳ vọng: trả lời bình thường, không xuất hiện trong pkt_forward_stats.

# A4. HTTP rõ hợp lệ
curl http://example.com/ -o /dev/null
#  Kỳ vọng: 200 OK, không alert.
```

**Quan sát:** `execute diagnose ips alerts` → trống/không có dòng mới;
`execute diagnose ips scores` → các flow đều `verdict=pass`.

✅ Tiêu chí đạt: 0 alert, 0 drop cho toàn bộ nhóm A.

---

## 4. Nhóm B — Tấn công cơ bản L3/L4 (kernel anomaly screen)

`pkt_forward.ko` chặn dị thường **không cần state** ngay tại FORWARD. Quan sát bằng
bộ đếm `/proc/stargazer/pkt_forward_stats` (trên device) — mỗi loại có 1 counter.

```bash
# B1. NULL / XMAS / FIN scan (cờ TCP dị dạng)
sudo nmap -sN <target>          # NULL scan
sudo nmap -sX <target>          # XMAS scan
sudo nmap -sF <target>          # FIN scan

# B2. SYN scan (nửa kết nối) — cũng nuôi đặc trưng ML (nhóm E)
sudo nmap -sS -p1-1000 <target>

# B3. Ping of Death (gói ICMP quá khổ)
sudo ping -s 65500 <target>

# B4. Land attack (src=dst) — giả lập bằng hping3
sudo hping3 -S -a <target> -p 80 <target>

# B5. SYN kèm payload (bất thường giao thức)
sudo hping3 -S -p 80 -d 100 -E /etc/hostname <target>
```

**Quan sát (device):**
```
cat /proc/stargazer/pkt_forward_stats
#  Kỳ vọng: counter tương ứng (null_xmas_fin, ping_of_death, land, syn_with_data...)
#           tăng lên. Kernel drop tại FORWARD, không cần ipsd.
```

> Lưu ý: kernel screen **không** sinh alert vào log ipsd (nó vô-state, không block
> theo policy) — bằng chứng nằm ở counter procfs. Các scan này đồng thời tạo flow
> bất thường được ML chấm ở **nhóm E**.

---

## 5. Nhóm C — Tấn công signature trên HTTP rõ (IPS engine)

Gửi payload khớp signature qua **HTTP (không mã hoá)** để xác nhận engine bắt được
trên đường NFQUEUE. Dùng các pattern có trong `emerging-scan.rules`.

```bash
# C1. User-Agent của scanner Nessus
curl -A "Nessus" http://<target>/

# C2. Fingerprint máy chủ web (httprint / DavTest)
curl -A "Mozilla/3.0 (compatible; Indy Library)" http://<target>/   # WebDAV scanner UA
curl http://<target>/davtest_probe_file

# C3. Brute-force FTP root (rule threshold: 5 lần/60s)
for i in $(seq 1 6); do
  printf 'USER root\r\n' | nc <target> 21
done

# C4. testmynids — endpoint chuyên kích hoạt IDS rule
curl http://www.testmynids.org/uid/index.html
```

**Quan sát:**
```
execute diagnose ips alerts 50
#  Kỳ vọng: dòng alert với SID + msg (vd "ET SCAN ... Nessus", "...FTP Root Login"),
#           verdict=DROP (mode prevent) hoặc ALERT (mode detect).
```

> Một lần `curl` có thể sinh **nhiều alert** nếu nội dung khớp nhiều rule — bình
> thường. Mỗi alert là một SID độc lập.

---

## 6. Nhóm D — Tấn công signature trên HTTPS (SSL inspection)

Đây là phép thử **quan trọng nhất** của SSL inspection: lặp lại đúng các payload
nhóm C nhưng **qua HTTPS**. Nếu vẫn bị bắt → MITM giải mã + IPC stateful hoạt động.

```bash
# D1. testmynids qua HTTPS (so trực tiếp với C4)
curl https://www.testmynids.org/uid/index.html
#  Trên client cert phải là "Stargazer SSL Inspection CA" (đã MITM).

# D2. Payload tấn công web qua HTTPS tới target của bạn
curl -A "Nessus" https://<target>/
curl "https://<target>/?id=1' OR '1'='1"          # SQLi-style trong URL

# D3. Pattern VẮT QUA 2 TLS RECORD (chứng minh reassembly có-state > soi từng chunk)
#     Gửi payload bị tách làm đôi qua 2 bản ghi TLS:
python3 - <<'PY'
import ssl, socket
ctx = ssl.create_default_context()
s = ctx.wrap_socket(socket.create_connection(("<target>",443)),
                    server_hostname="<target>")
s.send(b"GET /x HTTP/1.1\r\nUser-Agent: Nes")   # nửa pattern, record 1
import time; time.sleep(0.2)
s.send(b"sus\r\nHost: <target>\r\n\r\n")        # nửa còn lại, record 2
print(s.recv(200))
PY
```

**Khi bị DROP qua HTTPS, client nhận trang chặn** (FortiGate-style, tiếng Anh,
không lộ signature) thay vì nội dung thật.

**Quan sát:**
```
execute diagnose ssl
#  Kỳ vọng: số kết nối bump tăng.

cat /run/stargazer-ipsd-insp.stat
#  Kỳ vọng: conns_total tăng, sig_hits_https tăng, blocked_https tăng (nếu DROP).

execute diagnose ips alerts 50
#  Kỳ vọng: alert có cùng SID như nhóm C — chứng minh nội dung HTTPS đã được soi.
```

✅ Tiêu chí đạt: payload giống hệt nhóm C, đi qua HTTPS, **vẫn** sinh alert/drop.
Đặc biệt D3 chứng minh engine ráp được pattern vắt 2 record — điều mà soi-từng-chunk
không làm được.

> Nếu browser báo `ERR_CERT_AUTHORITY_INVALID` → CA chưa cài đúng (quay lại 1.5).
> Nếu HTTPS treo → kiểm tra steering ở `execute diagnose ssl` và policy có `accept`.

---

## 7. Nhóm E — Machine Learning (chấm điểm hành vi)

ML không dựa vào chuỗi byte mà vào **đặc trưng thống kê của flow** (`CTA_ML`:
số gói/byte mỗi chiều, IAT, kích thước cửa sổ đầu, tỉ lệ SYN/ACK…). Ngưỡng hợp nhất:

| Điểm `score` | Verdict | Lý do |
|--------------|---------|-------|
| `≥ 0.95` | **DROP** | `IPS_R_ML_BLOCK` |
| `≥ 0.50` | **ALERT** | `IPS_R_ML_ALERT` |
| `< 0.50` | pass | — |

Verdict cuối = `MAX(signature, ML)`. Ở `mode detect`, DROP bị hạ xuống ALERT.
Checkpoint chấm điểm: khi flow đạt **≥ 24 gói** hoặc **≥ 14 000 byte**.

### 7.1. ML trên traffic rõ (cleartext)

```bash
# E1. Quét cổng quy mô lớn — hành vi fan-out bất thường (nhiều SYN, ít ACK)
sudo nmap -sS -T4 -p1-65535 <target>

# E2. Flood nửa-mở (giả DoS) — nuôi đặc trưng tốc độ/biến thiên cao
sudo hping3 -S --flood -p 80 <target>     # Ctrl-C sau ~5s

# E3. Kết nối "im lặng" giữ lâu rồi bùng (anomaly về IAT/kích thước)
```

**Quan sát:**
```
execute diagnose ips scores 50
#  Kỳ vọng: flow scan/flood có score cao; verdict=ALERT (≥0.50) hoặc BLOCK (≥0.95).
execute diagnose session ml
#  Kỳ vọng: thấy CTA_ML của flow (pkts_fwd/bwd, bytes, SYN count...) — bằng chứng
#           kernel đã tích lũy đặc trưng để ML chấm.
```

### 7.2. ML trên HTTPS (Pha 2 — `ml-https enable`)

Khi `ml-https=enable`, kernel hook `LOCAL_IN` tích lũy `CTA_ML` trên leg
`client→ssld`; ipsd truy vấn lúc checkpoint và chấm điểm flow HTTPS **dù không khớp
signature nào**.

```bash
# E4. Phiên HTTPS lớn/bất thường (nhiều gói qua ssld leg)
curl https://speed.hetzner.de/1GB.bin -o /dev/null     # Ctrl-C sau vài giây
```

**Quan sát:**
```
cat /run/stargazer-ipsd-insp.stat
#  Kỳ vọng: ml_hits_https tăng khi flow vượt checkpoint VÀ score đủ ngưỡng.

execute diagnose ips alerts 50
#  Nếu ML kết luận bất thường: alert "ML anomaly (score X.XX)".
```

> Pha 2 **opt-in**. Nếu `ml_hits_https` luôn = 0 dù flow lớn → có thể leg-tuple
> kernel chưa khớp với socket ssld trên thiết bị này; hệ thống **degrade an toàn
> về signature-only** (không chặn nhầm). Xác minh hook đã bật:
> `cat /sys/module/pkt_forward/parameters/ml_account_local` phải = `1`.

---

## 8. Nhóm F — Resilience & chế độ vận hành

### 8.1. Detect vs Prevent

```
config security ips
    set mode detect
end
```
Lặp lại một test nhóm C/D → alert vẫn xuất hiện nhưng traffic **không bị chặn**
(DROP hạ thành ALERT). Đổi lại `set mode prevent` để chặn thật.

### 8.2. Fail-mode khi ipsd chết (đường HTTPS)

```bash
# Trên device: kill ipsd, rồi duyệt HTTPS
killall stargazer-ipsd
```
- `ipc-failmode open` (mặc định): ssld **vẫn cho qua** + ghi log → web không sập.
- `ipc-failmode closed`: ssld **chặn** flow HTTPS (fail-closed) → an toàn tối đa.

```
config security ips
    set ipc-failmode closed
end
```
Test lại để thấy khác biệt. (Supervisor sẽ tự khởi động lại ipsd.)

### 8.3. Hot-reload ruleset (không gián đoạn)

```
execute ips reload
```
Trong lúc một `curl https://...` đang chạy → kết nối **không** đứt; ruleset mới
áp dụng cho flow tiếp theo. Chứng minh reload dùng rdlock + rebind virtual-flow.

---

## 9. Bảng đối chiếu "đã chứng minh điều gì"

| Bằng chứng quan sát được | Kết luận |
|--------------------------|----------|
| Nhóm A: 0 alert/drop | Engine không false-positive trên traffic thật |
| `pkt_forward_stats` counter tăng (nhóm B) | Kernel chặn dị thường L3/L4 tại FORWARD |
| `ips alerts` có SID (nhóm C) | IPS signature bắt payload HTTP rõ |
| Cùng SID xuất hiện qua HTTPS (nhóm D) | **SSL deep inspection giải mã + soi thành công** |
| D3 bắt pattern vắt 2 record | IPC stateful > soi-từng-chunk cũ |
| `ips scores` verdict ALERT/BLOCK (nhóm E) | **ML chấm hành vi bất thường** độc lập signature |
| `insp.stat: ml_hits_https > 0` (E4) | ML hoạt động trên HTTPS (Pha 2) |
| Web không sập khi kill ipsd + failmode open | Fail-mode đúng thiết kế |

---

## 10. Dọn dẹp / khôi phục

```
config firewall policy
    edit allow-lan-out
        unset ips-profile         # tắt IPS cho policy
        set ssl-profile no-inspection
    next
end

config security ips
    set status disable
    set ml-https disable          # kernel hook LOCAL_IN trở về no-op
end
```

```
execute diagnose ips alerts-clear        # xoá log alert
```

Gỡ CA khỏi client nếu không dùng nữa:
```bash
sudo rm /usr/local/share/ca-certificates/stargazer.crt
sudo update-ca-certificates --fresh
# Chrome: Manage certificates → Authorities → xoá "Stargazer SSL Inspection CA"
```

---

## Phụ lục — Tham chiếu nhanh

**Lệnh chẩn đoán** (đều dưới `execute`):
`diagnose ips status` · `diagnose ips alerts [n]` · `diagnose ips alerts-clear` ·
`diagnose ips scores [n]` · `diagnose ssl` · `diagnose session ml` ·
`diagnose firewall conntrack` · `diagnose firewall policy` · `ips reload` ·
`ips update-now` · `system ssl-ca-cert`

**File runtime** (trên device):
- `/proc/stargazer/pkt_forward_stats` — counter dị thường kernel
- `/run/stargazer-ipsd.rt` — trạng thái ipsd
- `/run/stargazer-ipsd-insp.stat` — telemetry HTTPS-IPC (`conns_total`, `chunks`,
  `sig_hits_https`, `ml_hits_https`, `blocked_https`)
- `/etc/stargazer/logs/ips-alert.log` — log alert thô
- `/sys/module/pkt_forward/parameters/ml_account_local` — cờ ML-HTTPS (0/1)

**Ngưỡng ML**: ALERT ≥ 0.50 · DROP ≥ 0.95 · checkpoint ≥ 24 gói hoặc ≥ 14 000 byte.

**Công cụ client cần cài**: `curl`, `nmap`, `hping3`, `netcat`, `python3`, Chrome.
```bash
sudo apt install -y nmap hping3 netcat-openbsd curl python3
```
