#!/bin/sh
# attack-sim.sh — sinh traffic tấn công từ LAN VM (192.168.99.100)
#
# Chạy trên LAN VM, nhắm vào WAN host (10.0.1.1) hoặc tùy chọn.
# Mỗi test in kết quả và yêu cầu kiểm log ipsd trên Stargazer.
#
# Dùng: ./attack-sim.sh [all|syn-flood|port-scan|web-sqli|ftp-brute|pcap]
# Cần:  nmap, hping3, curl (busybox), tcpreplay (nếu dùng pcap)

TARGET="${TARGET:-10.0.1.1}"   # WAN host hoặc máy đích
SRC_IP=$(ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)

echo "[attack-sim] Source: ${SRC_IP} → Target: ${TARGET}"
echo ""

die() { echo "Lỗi: $*" >&2; exit 1; }

# ---- 1. SYN Flood --------------------------------------------------------
test_syn_flood() {
    echo "=== Test 1: SYN Flood (cần nmap hoặc hping3) ==="
    echo "Mục đích: trigger L1 built-in SYN flood rule (syn_count >> ack_count)"

    if command -v hping3 >/dev/null 2>&1; then
        echo "hping3 --syn --flood -p 80 ${TARGET} (5 giây)..."
        timeout 5 hping3 --syn --flood -p 80 "${TARGET}" 2>/dev/null || true
        echo "→ Kiểm Stargazer: tail -f /etc/stargazer/logs/ipsd.log"
    elif command -v nmap >/dev/null 2>&1; then
        echo "nmap -sS --min-rate 1000 -p 80 ${TARGET}..."
        nmap -sS --min-rate 1000 -p 80 "${TARGET}" 2>/dev/null | tail -3
    else
        echo "SKIP: cần hping3 hoặc nmap"
    fi
    echo ""
}

# ---- 2. Port Scan --------------------------------------------------------
test_port_scan() {
    echo "=== Test 2: Port Scan (nmap SYN scan) ==="
    echo "Mục đích: trigger L1 port-scan rule (≤3 gói, chỉ SYN, không ACK)"

    if command -v nmap >/dev/null 2>&1; then
        echo "nmap -sS -p 1-1000 ${TARGET}..."
        nmap -sS -p 1-1000 "${TARGET}" 2>/dev/null | grep -E 'open|filtered|Nmap done'
    else
        echo "SKIP: cần nmap"
    fi
    echo ""
}

# ---- 3. Web SQLi (payload signature) -------------------------------------
test_web_sqli() {
    echo "=== Test 3: Web SQL Injection (payload AC rule) ==="
    echo "Mục đích: trigger L2 signature (content UNION SELECT) trên port 80"

    echo "Gửi request SQLi tới ${TARGET}:80..."
    curl -s --max-time 3 \
        "http://${TARGET}/index.php?id=1+UNION+SELECT+password+FROM+users" \
        -o /dev/null -w "HTTP %{http_code}\n" 2>/dev/null || echo "(timeout/refused = bị chặn)"
    echo ""
}

# ---- 4. FTP Brute-Force (ET OPEN rule) -----------------------------------
test_ftp_brute() {
    echo "=== Test 4: FTP Brute-Force (ET OPEN rule sid:2010642) ==="
    echo "Mục đích: trigger L2 signature 'USER root' trên port 21"

    if command -v nc >/dev/null 2>&1; then
        for i in 1 2 3; do
            printf "USER root\r\nPASS test\r\n" | \
                timeout 2 nc "${TARGET}" 21 2>/dev/null | head -2 || true
        done
        echo "→ 3 lần gửi USER root. Kiểm log ipsd."
    else
        echo "SKIP: cần nc (netcat)"
    fi
    echo ""
}

# ---- 5. Known-bad port ---------------------------------------------------
test_bad_port() {
    echo "=== Test 5: Known-bad port (4444 Metasploit) ==="
    echo "Mục đích: trigger L1 built-in known-bad-port ALERT"

    if command -v nc >/dev/null 2>&1; then
        echo "kết nối tới ${TARGET}:4444..."
        echo "test" | timeout 2 nc "${TARGET}" 4444 2>/dev/null || true
        echo "→ Kiểm log: dport=4444 Known-bad port"
    else
        echo "SKIP: cần nc"
    fi
    echo ""
}

# ---- 6. Pcap replay (CIC-IDS2017) ----------------------------------------
test_pcap_replay() {
    echo "=== Test 6: Replay pcap tấn công ==="

    PCAP="${1:-/tmp/attack.pcap}"
    if [ ! -f "${PCAP}" ]; then
        echo "SKIP: không có file pcap tại ${PCAP}"
        echo "Để dùng: copy file pcap vào LAN VM rồi chạy:"
        echo "  TARGET=${TARGET} ./attack-sim.sh pcap /path/to/attack.pcap"
        return
    fi

    if command -v tcpreplay >/dev/null 2>&1; then
        echo "Replay ${PCAP} qua eth0 → ${TARGET}..."
        tcpreplay --intf1=eth0 --multiplier=1.0 "${PCAP}" 2>&1 | tail -5
    else
        echo "SKIP: cần tcpreplay"
        echo "Cài: apk add tcpreplay (Alpine) hoặc apt install tcpreplay"
    fi
    echo ""
}

# ---- main ----------------------------------------------------------------
CMD="${1:-all}"
PCAP_FILE="${2:-}"

case "$CMD" in
    all)
        test_syn_flood
        test_port_scan
        test_web_sqli
        test_ftp_brute
        test_bad_port
        ;;
    syn-flood)  test_syn_flood ;;
    port-scan)  test_port_scan ;;
    web-sqli)   test_web_sqli ;;
    ftp-brute)  test_ftp_brute ;;
    bad-port)   test_bad_port ;;
    pcap)       test_pcap_replay "${PCAP_FILE}" ;;
    *)
        echo "Dùng: $0 [all|syn-flood|port-scan|web-sqli|ftp-brute|bad-port|pcap <file>]"
        exit 1
        ;;
esac

echo "=== Xong. Kiểm log trên Stargazer VM: ==="
echo "  tail -f /etc/stargazer/logs/ipsd.log"
echo "  iptables -L FORWARD -n -v | head -10    (xem packet counter)"
