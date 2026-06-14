# Hướng dẫn Test IPS trên QEMU — Stargazer NGFW

> Môi trường: Ubuntu 24.04 LTS x86_64 (host) + QEMU ARM64 (Stargazer VM + LAN VM)

---

## Phần 1 — Chuẩn bị môi trường (làm 1 lần)

### 1.1. Cài dependencies

```bash
# Bắt buộc
sudo apt install hping3 tcpreplay

# Đã có sẵn trên Ubuntu 24.04 (kiểm tra)
which qemu-system-aarch64      # QEMU 8.2
which aarch64-linux-gnu-gcc    # cross-compiler
which nmap                     # đã cài
```

### 1.2. Build toàn bộ hệ thống (lần đầu ~20–40 phút)

```bash
cd ~/KLTN/Stargazer

# Build kernel + modules + userspace + ipsd + initramfs
make test-build
```

`make test-build` tự động:
- Cross-compile `stargazer-ipsd` cho ARM64 (dùng `aarch64-linux-gnu-gcc`)
- Nhét binary + rules (`emerging-scan.rules`) vào test initramfs
- Tạo `build/test/boot.img` để QEMU boot

**Kiểm tra sau build:**
```bash
ls build/ipsd/stargazer-ipsd          # binary ARM64
ls build/test/initramfs/sbin/stargazer-ipsd   # trong initramfs
ls build/test/initramfs/etc/stargazer/ips/rules/
```

### 1.3. Setup network (mỗi lần reboot host)

```bash
sudo ./scripts/test_net_setup.sh up
```

Tạo topology:
```
Host (internet)
   │
br-wan (10.0.1.0/24)
   │ tap-sg-wan
Stargazer VM
   eth0 = WAN (10.0.1.2)
   eth1 = LAN (192.168.99.99 mgmt)
   │ tap-sg-lan + tap-lan-vm
br-lan (192.168.99.0/24)
   │
LAN VM (192.168.99.100) ← kẻ tấn công
```

---

## Phần 2 — Khởi động VMs

Mở **3 terminal** song song:

### Terminal 1 — Stargazer VM (tường lửa)
```bash
./scripts/run_firewall.sh
# Đợi boot (~30 giây), đăng nhập:
# Username: admin  Password: admin (hoặc theo config mặc định)
```

### Terminal 2 — LAN VM (máy tấn công)
```bash
./scripts/run_lanvm.sh
# Boot tự động, không cần đăng nhập
```

### Terminal 3 — Host monitor
```bash
# Để theo dõi log và kết quả
# Dùng terminal này chạy lệnh trong suốt quá trình test
```

---

## Phần 3 — Bật IPS trên Stargazer VM

Sau khi Stargazer boot xong, chạy trên **Terminal 1**:

```bash
# === Trên Stargazer VM ===

# Bật IPS (prevent mode = chặn thật)
sh /sbin/start-ips.sh prevent

# Hoặc detect mode (chỉ log, không chặn — để quan sát)
sh /sbin/start-ips.sh detect

# Theo dõi log alert real-time
tail -f /etc/stargazer/logs/ipsd.log
```

**Kiểm tra IPS đang chạy:**
```bash
# Xem iptables NFQUEUE rules đã được thêm
iptables -L FORWARD -n --line-numbers

# Xem ipsd process
ps | grep ipsd

# Xem rules đã nạp
cat /etc/stargazer/logs/ipsd.log | head -5
```

Kết quả mong đợi từ iptables:
```
Chain FORWARD (policy DROP)
num  target  prot  ...
1    DROP    all   -- connmark match 0x2/0x2        ← IPS BLOCK
2    NFQUEUE all   -- ctstate NEW ! 0x4/0x4 NFQUEUE #0  ← queue lên ipsd
3    ACCEPT  all   -- ctstate ESTABLISHED,RELATED    ← fast-path
...  (các rule policy bình thường của mgmtd)
```

---

## Phần 4 — Kịch bản test (11 kịch bản)

Mỗi kịch bản: **Chạy từ LAN VM** (Terminal 2) → **Quan sát log trên Stargazer** (Terminal 1).

---

### Kịch bản 1 — Anomaly stateless (pkt_forward.ko)

**Mục đích:** Kiểm layer trước IPS — pkt_forward.ko chặn ngay ở kernel mà không cần ipsd.

```bash
# === Trên LAN VM ===

# NULL scan (không cờ TCP nào)
nmap -sN 10.0.1.1 -p 80

# XMAS scan (FIN+PSH+URG)
nmap -sX 10.0.1.1 -p 80

# FIN scan
nmap -sF 10.0.1.1 -p 80
```

**Kết quả mong đợi:**
```bash
# Trên Stargazer — xem counter
cat /proc/stargazer/pkt_forward_stats
# pkts_anomaly_dropped tăng
```
Gói bị DROP ngay tại kernel hook, **không đi qua ipsd**. Không có alert trong `ipsd.log`.

---

### Kịch bản 2 — SYN Flood (L1 built-in)

**Mục đích:** Trigger rule built-in `syn_count ≥ 10 VÀ syn > 10×ack`.

```bash
# === Trên LAN VM ===
# Flood SYN tới WAN trong 5 giây
hping3 --syn --flood -p 80 10.0.1.1 &
FLOOD_PID=$!
sleep 5
kill $FLOOD_PID
```

**Quan sát trên Stargazer:**
```bash
tail -5 /etc/stargazer/logs/ipsd.log
# Mong đợi: DROP SYN flood: syn=N ack=0 (ratio N:1 > 10:1)

# Xem iptables counter
iptables -L FORWARD -n -v | grep DROP
```

**Kết quả mong đợi:**
- Log: `DROP ... reason=signature msg=SYN flood: syn=50 ack=0`
- Connmark `0x2` (BLOCK) được set → các gói sau của flow cũng bị DROP

---

### Kịch bản 3 — Port Scan (L1 built-in)

**Mục đích:** Trigger rule `pkts_total ≤ 3, syn ≥ 1, ack == 0` (incomplete handshake).

```bash
# === Trên LAN VM ===
nmap -sS --min-rate 50 10.0.1.1 -p 1-1000
```

**Quan sát:**
```bash
tail -10 /etc/stargazer/logs/ipsd.log
# Mong đợi: nhiều dòng "Port scan: N pkts, syn=1 ack=0"
```

> **Lưu ý:** Mỗi port là 1 flow riêng → nhiều alert nhỏ, không phải 1 alert lớn.

---

### Kịch bản 4 — Known-Bad Port (L1 built-in)

**Mục đích:** Trigger ALERT khi kết nối tới port Metasploit/backdoor.

```bash
# === Trên LAN VM ===
# Kết nối tới cổng Metasploit default (4444)
echo "test" | nc -w 2 10.0.1.1 4444

# Kết nối tới cổng Back Orifice (31337)
echo "test" | nc -w 2 10.0.1.1 31337
```

**Quan sát:**
```bash
grep "Known-bad" /etc/stargazer/logs/ipsd.log
# Mong đợi: ALERT ... reason=signature msg=Known-bad port: dport=4444
```

> Hành vi: ALERT (không DROP) vì port có thể dùng hợp lệ.

---

### Kịch bản 5 — FTP Brute-Force (L2 payload, ET OPEN sid:2010642)

**Mục đích:** Trigger rule ET OPEN từ ruleset thật.  
Rule: `content:"USER "; nocase; content:"root"; dport=21`

```bash
# === Trên LAN VM ===
# Gửi 5 lần FTP login "USER root"
for i in $(seq 1 5); do
    printf "USER root\r\nPASS test123\r\n" | nc -w 2 10.0.1.1 21 2>/dev/null || true
    sleep 0.5
done
```

**Quan sát:**
```bash
grep "FTP\|2010642\|brute" /etc/stargazer/logs/ipsd.log
# Mong đợi: ALERT ... sid=2010642 ET SCAN Multiple FTP Root Login...
```

---

### Kịch bản 6 — SQL Injection (L2 payload, ET rule)

**Mục đích:** Trigger rule payload AC với `UNION SELECT`.

```bash
# === Trên LAN VM ===
# HTTP request chứa SQLi payload
curl -s --max-time 3 \
    "http://10.0.1.1/search?q=1+UNION+SELECT+password+FROM+users--" \
    -o /dev/null 2>&1 || echo "(timeout = bị chặn)"

# Thử thêm với lowercase (nocase rule)
curl -s --max-time 3 \
    "http://10.0.1.1/?id=1 union select 0,user(),3--" \
    -o /dev/null 2>&1 || echo "(timeout)"
```

**Quan sát:**
```bash
grep "SQLi\|union\|UNION\|sql" /etc/stargazer/logs/ipsd.log -i | tail -5
```

> **Lưu ý:** Cần có file rule chứa rule SQLi (`emerging-web_client.rules` hoặc `emerging-sql.rules`). Ruleset mặc định (`emerging-scan.rules`) chỉ có scan rules. Xem §5 để nạp thêm rule.

---

### Kịch bản 7 — ML Anomaly Detection (LightGBM)

**Mục đích:** Traffic mà signature KHÔNG bắt nhưng ML phát hiện (score ≥ 0.95).

```bash
# === Trên LAN VM ===
# Tạo DDoS-like traffic: nhiều gói nhỏ, IAT rất lớn, bwd >> fwd
# Mô phỏng đặc trưng của flow DDoS trong CIC dataset
hping3 --udp -p 53 --flood --fast 10.0.1.1 &
sleep 3
kill %1 2>/dev/null
```

Hoặc dùng pcap CIC-IDS2017 nếu có:
```bash
# Copy pcap vào LAN VM trước
scp /path/to/ddos_sample.pcap root@192.168.99.100:/tmp/
# Trên LAN VM:
tcpreplay --intf1=eth0 --multiplier=0.5 /tmp/ddos_sample.pcap
```

**Quan sát:**
```bash
grep "ml-block\|score=" /etc/stargazer/logs/ipsd.log | tail -10
# Mong đợi: DROP ... reason=ml-block score=0.99X
```

**Dùng micro.pcap sẵn có:**
```bash
# micro.pcap trong CICFlowMeter/ — copy vào LAN VM
# Trên host:
scp CICFlowMeter/micro.pcap root@192.168.99.100:/tmp/
# Trên LAN VM:
tcpreplay --intf1=eth0 /tmp/micro.pcap
```

---

### Kịch bản 8 — Auto Rule Generation (rule_gen)

**Mục đích:** Sau khi ML bắt được flow bất thường 3 lần → tự sinh rule mới vào ruleset.

```bash
# === Trên LAN VM ===
# Lặp lại kịch bản 7 ít nhất 3 lần để đủ min_support=3
for i in 1 2 3 4; do
    hping3 --udp -p 5555 --fast 10.0.1.1 -c 20 2>/dev/null
    sleep 2
done
```

**Kiểm tra trên Stargazer:**
```bash
# Xem rule tự sinh
cat /etc/stargazer/ips/auto.rules
# Mong đợi: alert udp any any -> any 5555 (msg:"AUTO:..."; sid:9000001; rev:1;)

# Gửi lại traffic — lần này khớp rule L1-user (không cần ML)
# Log sẽ hiện reason=signature (không phải ml-block)
```

---

### Kịch bản 9 — Hot-Reload Ruleset (sig_reload)

**Mục đích:** Cập nhật rule mà không dừng ipsd, traffic không bị gián đoạn.

```bash
# === Trên Stargazer VM ===

# Thêm rule mới vào file
cat >> /etc/stargazer/ips/rules/local.rules << 'EOF'
alert tcp any any -> any 9999 (msg:"TEST: custom rule port 9999"; content:"TESTPAYLOAD"; sid:8000001; rev:1;)
EOF

# Tải lại ruleset qua SIGUSR1
kill -USR1 $(pidof stargazer-ipsd)

# Xem log reload
tail -5 /etc/stargazer/logs/ipsd.log
# Mong đợi: sig_reload: loaded N rules from ...
```

```bash
# === Trên LAN VM — test rule mới ===
echo "TESTPAYLOAD" | nc -w 2 10.0.1.1 9999
```

```bash
# === Trên Stargazer — kiểm ===
grep "custom rule\|9999\|8000001" /etc/stargazer/logs/ipsd.log
# Mong đợi: ALERT ... msg=TEST: custom rule port 9999
```

---

### Kịch bản 10 — Mode Detect vs Prevent

**Mục đích:** Xác nhận mode detect chỉ log, không chặn.

```bash
# === Trên Stargazer VM ===
# Dừng ipsd hiện tại, chạy lại với detect mode
kill $(pidof stargazer-ipsd) 2>/dev/null
sh /sbin/start-ips.sh detect
```

```bash
# === Trên LAN VM ===
# Thực hiện SYN flood
hping3 --syn --flood -p 80 10.0.1.1 &
sleep 3; kill %1

# Ping bình thường — phải thông suốt
ping -c 5 10.0.1.1
```

```bash
# === Trên Stargazer ===
grep "ALERT\|DROP" /etc/stargazer/logs/ipsd.log | tail -5
# Mong đợi: chỉ thấy ALERT, không DROP
# Ping vẫn trả lời (không bị chặn)
```

---

### Kịch bản 11 — Traffic bình thường không bị ảnh hưởng

**Mục đích:** Xác nhận false positive không có — traffic lành không bị chặn.

```bash
# === Trên LAN VM ===
# HTTP bình thường
curl -s http://10.0.1.1/ -o /dev/null -w "HTTP %{http_code}\n"

# Ping
ping -c 10 10.0.1.1

# SSH handshake
ssh -o ConnectTimeout=3 root@10.0.1.1 exit 2>/dev/null || true

# DNS query bình thường
nslookup google.com 10.0.1.1 2>/dev/null || true
```

```bash
# === Trên Stargazer ===
grep "DROP" /etc/stargazer/logs/ipsd.log | tail -5
# Mong đợi: KHÔNG có DROP cho traffic trên
# Ping thành công từ LAN VM (echo reply nhận được)
```

---

## Phần 5 — Nạp thêm rule cho kịch bản SQLi và web attack

`emerging-scan.rules` chỉ chứa rule scan/recon. Để test L2 payload SQLi/web:

```bash
# === Trên Stargazer VM ===
# Tải thêm rule từ ET OPEN (cần network)
cd /etc/stargazer/ips/rules/

wget -q https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-sql.rules
wget -q https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-web_client.rules
wget -q https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-exploit.rules

# Gộp thành active.rules
cat emerging-scan.rules emerging-sql.rules emerging-web_client.rules \
    emerging-exploit.rules > active.rules

# Reload
kill -USR1 $(pidof stargazer-ipsd)
# Log: "sig_reload: loaded N rules..."
```

Hoặc làm trên host rồi `make test-build` lại với nhiều rule hơn.

---

## Phần 6 — Bảng tóm tắt kết quả kỳ vọng

| # | Kịch bản | Lớp bắt | Mode prevent | Mode detect |
|---|---|---|---|---|
| 1 | NULL/XMAS/FIN scan | `pkt_forward.ko` (trước ipsd) | DROP (kernel) | DROP (kernel) |
| 2 | SYN flood | L1 built-in | DROP + log | ALERT only |
| 3 | Port scan (nmap -sS) | L1 built-in | DROP + log | ALERT only |
| 4 | Known-bad port 4444 | L1 built-in | ALERT + log | ALERT only |
| 5 | FTP `USER root` | L2 ET rule | ALERT/DROP + log | ALERT only |
| 6 | `UNION SELECT` HTTP | L2 ET rule | ALERT/DROP + log | ALERT only |
| 7 | DDoS ML pattern | ML (score≥0.95) | DROP + log | ALERT only |
| 8 | Auto rule (sau 3× ML) | L1-user (rule_gen) | ALERT/DROP | ALERT only |
| 9 | Hot-reload rule mới | L2 ET rule custom | Hiệu lực ngay | Hiệu lực ngay |
| 10 | Mode detect | — | — | Log only, KHÔNG drop |
| 11 | Traffic bình thường | — | PASS | PASS |

---

## Phần 7 — Lệnh debug khi không thấy kết quả mong đợi

```bash
# === Trên Stargazer ===

# 1. ipsd có chạy không?
ps | grep ipsd

# 2. Xem toàn bộ log kể cả stderr
cat /etc/stargazer/logs/ipsd.log

# 3. Iptables rules có đúng không?
iptables -L FORWARD -n --line-numbers -v

# 4. NFQUEUE có nhận gói không?
# (đọc counter packet trên rule NFQUEUE)
iptables -L FORWARD -n -v | grep NFQUEUE

# 5. conntrack có entry không?
conntrack -L 2>/dev/null | head -10

# 6. Chạy ipsd tay với log ra console (debug mode)
kill $(pidof stargazer-ipsd) 2>/dev/null
stargazer-ipsd -d -r /etc/stargazer/ips/rules/active.rules -n

# === Từ LAN VM test kết nối cơ bản ===
ping -c 3 10.0.1.1     # phải thông (nếu policy cho phép)
ping -c 3 10.0.2.1     # ping WAN target

# === Trên host — xem bridge traffic ===
sudo tcpdump -i br-lan -n 'tcp' 2>/dev/null | head -20
```

---

## Phần 8 — Teardown

```bash
# Tắt VMs: Ctrl+A X trong mỗi terminal QEMU

# Dọn network
sudo ./scripts/test_net_setup.sh down
```

---

*Tài liệu này dùng kèm với `docs/ips-master-plan.md` (thiết kế) và `docs/ips-implementation-guide.md` (kỹ thuật).*
