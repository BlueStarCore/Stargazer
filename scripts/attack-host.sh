#!/bin/bash
# =============================================================================
# Stargazer NGFW — Attack simulation from HOST (real nmap / hping3 / nc)
# =============================================================================
#
# Topology (test_net_setup.sh + fake-lanvm.sh):
#   Host (10.0.1.1, br-wan)  ── attacker, real pentest tools
#        │ WAN
#   Stargazer eth1(WAN 10.0.1.2) → FORWARD chain + NFQUEUE (ipsd)
#        │ LAN
#   Stargazer eth0 → br-lan → netns "lanvm" (192.168.99.100)  ── fake target
#
# No separate LAN VM needed: fake-lanvm.sh creates a network namespace on the host,
# connected via br-lan, so traffic still goes through the full FORWARD chain + ipsd.
#
# Prerequisites:
#   1. sudo ./scripts/test_net_setup.sh up
#   2. sudo ./scripts/fake-lanvm.sh up       ← replaces the LAN VM
#   3. Stargazer VM running, IPS policy eth1→eth0 enabled
#
# Usage:  sudo ./scripts/attack-host.sh [all|null-scan|xmas-scan|fin-scan|
#                                        port-scan|syn-flood|udp-flood|
#                                        web-sqli|ftp-brute|shellcode|
#                                        et-loic|et-tsunami|et-ftp-ua]
# =============================================================================

set -uo pipefail

TARGET="${TARGET:-192.168.99.100}"   # LAN VM (through firewall)
GW="${GW:-10.0.1.2}"                 # Stargazer WAN IP
SCEN="${1:-all}"

c_hdr()  { printf "\n\033[1;36m=== %s ===\033[0m\n" "$*"; }
c_note() { printf "  \033[0;33m%s\033[0m\n" "$*"; }
c_run()  { printf "  \033[0;32m$ %s\033[0m\n" "$*"; }

require_root() {
    [ "$(id -u)" -eq 0 ] || { echo "Must run with sudo (raw socket for nmap/hping3)"; exit 1; }
}

preflight() {
    local fail=0
    for t in nmap hping3 nc; do
        command -v "$t" >/dev/null 2>&1 || { echo "MISSING tool: $t (apt install $t)"; fail=1; }
    done
    if ! ip route get "$TARGET" >/dev/null 2>&1; then
        echo "No route to $TARGET — run: sudo ./scripts/test_net_setup.sh up"
        fail=1
    fi
    [ $fail -eq 0 ] || exit 1
    echo "[attack-host] attacker=$(hostname) → target=$TARGET (through firewall $GW)"
    c_note "On Stargazer run: execute diagnose ips alerts  (or tail /etc/stargazer/logs/ipsd.log)"
}

# ── pkt_forward.ko anomaly screen: malformed TCP flag scans ───────────────
null_scan() {
    c_hdr "NULL scan — no TCP flags set (pkt_forward.ko is_tcp_anomaly)"
    c_note "Expected: kernel drop at FORWARD hook + possibly ET SCAN alert"
    c_run "nmap -sN -p 22,80,443 $TARGET"
    nmap -sN -p 22,80,443 "$TARGET" 2>/dev/null | grep -E 'PORT|open|closed|filtered|Nmap done'
}

xmas_scan() {
    c_hdr "XMAS scan — FIN+PSH+URG flags (pkt_forward.ko)"
    c_run "nmap -sX -p 22,80,443 $TARGET"
    nmap -sX -p 22,80,443 "$TARGET" 2>/dev/null | grep -E 'PORT|open|closed|filtered|Nmap done'
}

fin_scan() {
    c_hdr "FIN scan — FIN flag only, no ACK (pkt_forward.ko)"
    c_run "nmap -sF -p 22,80,443 $TARGET"
    nmap -sF -p 22,80,443 "$TARGET" 2>/dev/null | grep -E 'PORT|open|closed|filtered|Nmap done'
}

# ── L1 flow-stat rules ────────────────────────────────────────────────────
port_scan() {
    c_hdr "Port scan SYN — many ports, few packets/flow (L1 port-scan rule)"
    c_note "Expected: L1 rule (proto TCP, SYN only, incomplete handshake)"
    c_run "nmap -sS -p 1-1000 $TARGET"
    nmap -sS -p 1-1000 "$TARGET" 2>/dev/null | grep -E 'open|filtered|Nmap done'
}

syn_flood() {
    c_hdr "SYN flood — hping3 (L1 SYN-flood rule: syn_count >> ack_count)"
    c_note "Running for 5 seconds..."
    c_run "hping3 --syn --flood -p 80 $TARGET"
    timeout 5 hping3 --syn --flood -p 80 "$TARGET" >/dev/null 2>&1 || true
    c_note "→ Done. Check for the SYN flood alert on Stargazer."
}

udp_flood() {
    c_hdr "UDP flood — hping3 (anomaly/ML)"
    c_run "hping3 --udp --flood -p 53 $TARGET"
    timeout 5 hping3 --udp --flood -p 53 "$TARGET" >/dev/null 2>&1 || true
    c_note "→ Done."
}

# ── L2 payload signature (AC engine) ──────────────────────────────────────
web_sqli() {
    c_hdr "Web SQLi — payload contains UNION SELECT (L2 content signature)"
    c_note "Needs a ruleset with web rules; a scan ruleset may not match — demonstrates the mechanism"
    c_run "printf 'GET /?id=1 UNION SELECT ... HTTP/1.0' | nc $TARGET 80"
    printf 'GET /index.php?id=1+UNION+SELECT+password+FROM+users HTTP/1.0\r\nHost: %s\r\n\r\n' \
        "$TARGET" | timeout 3 nc "$TARGET" 80 2>/dev/null | head -3 || \
        c_note "(timeout/refused — no HTTP server on target, packet still inspected by firewall)"
}

ftp_brute() {
    c_hdr "FTP payload — USER/PASS (L2 ET FTP signature)"
    c_run "printf 'USER root\\r\\nPASS test123\\r\\n' | nc $TARGET 21"
    printf 'USER root\r\nPASS test123\r\n' | timeout 3 nc "$TARGET" 21 2>/dev/null | head -2 || \
        c_note "(no FTP server — packet still inspected by firewall)"
}

shellcode() {
    c_hdr "Shellcode-like payload on an unusual port (L2 / ML)"
    c_run "printf '<NOP-sled + payload>' | nc $TARGET 9999"
    printf '\x90\x90\x90\x90\x90\x90\x90\x90/bin/sh\x00TESTPAYLOAD' | \
        timeout 3 nc "$TARGET" 9999 2>/dev/null | head -2 || \
        c_note "(packet already passed through firewall for inspection)"
}

# ── Emerging Threats DOS signatures (need fake-lanvm.sh up) ────────────────

# ET sid:2016031 — LOIC GET /?msg=MSG  (threshold count 1 → 1 request is enough)
et_loic() {
    c_hdr "ET DOS LOIC GET (sid:2016031) — a single request"
    c_note "Rule: GET http_method + '/?msg=MSG' http_uri, threshold count 1/300s"
    c_run "curl -v 'http://$TARGET/?msg=MSG'"
    curl -s --interface br-wan --max-time 5 \
        "http://${TARGET}/?msg=MSG" -o /dev/null -w "HTTP %{http_code}\n" 2>/dev/null || \
        c_note "(connection refused — packet already passed through FORWARD+ipsd)"
}

# ET sid:2022760 — Tsunami User-Agent (no threshold → 1 packet matches)
et_tsunami() {
    c_hdr "ET DOS Tsunami User-Agent (sid:2022760) — no threshold, 1 request"
    c_note "Rule: User-Agent: x00_-gawa.sa.pilipinas.2015"
    c_run "curl -H 'User-Agent: x00_-gawa.sa.pilipinas.2015' http://$TARGET/"
    curl -s --interface br-wan --max-time 5 \
        -H "User-Agent: x00_-gawa.sa.pilipinas.2015" \
        "http://${TARGET}/" -o /dev/null -w "HTTP %{http_code}\n" 2>/dev/null || \
        c_note "(connection refused — packet already passed through FORWARD+ipsd)"
}

# ET sid:2020702 — Bittorrent User-Agent (threshold count 1/60s)
et_ftp_ua() {
    c_hdr "ET DOS Bittorrent User-Agent (sid:2020702)"
    c_note "Rule: User-Agent: Bittorrent, threshold count 1/60s"
    c_run "curl -H 'User-Agent: Bittorrent' http://$TARGET/"
    curl -s --interface br-wan --max-time 5 \
        -H "User-Agent: Bittorrent" \
        "http://${TARGET}/" -o /dev/null -w "HTTP %{http_code}\n" 2>/dev/null || \
        c_note "(connection refused — packet already passed through FORWARD+ipsd)"
}

# ET sid:2019346 — LOIC terse GET 18 bytes (threshold 500 req/60s)
et_loic_terse() {
    c_hdr "ET DOS LOIC terse GET (sid:2019346) — needs 500 req/60s"
    c_note "Rule: dsize=18, 'GET / HTTP/1.1\\r\\n\\r\\n', threshold 500/60s by_dst"
    c_note "Sending 550 raw packets..."
    c_run "python3 -c \"...500 x raw 18-byte GET...\""
    python3 - <<'PYEOF'
import socket, time, threading

TARGET = "192.168.99.100"
PORT   = 80
PAYLOAD = b"GET / HTTP/1.1\r\n\r\n"   # exactly 18 bytes
TOTAL   = 550
THREADS = 20
sent    = 0

def worker(n):
    global sent
    for _ in range(n):
        try:
            s = socket.create_connection((TARGET, PORT), timeout=1)
            s.send(PAYLOAD)
            s.close()
        except Exception:
            pass
        sent += 1

ts = [threading.Thread(target=worker, args=(TOTAL // THREADS,)) for _ in range(THREADS)]
t0 = time.time()
for t in ts: t.start()
for t in ts: t.join()
print(f"  Sent {sent} packets in {time.time()-t0:.1f}s")
PYEOF
}

require_root
preflight

case "$SCEN" in
    null-scan)    null_scan ;;
    xmas-scan)    xmas_scan ;;
    fin-scan)     fin_scan ;;
    port-scan)    port_scan ;;
    syn-flood)    syn_flood ;;
    udp-flood)    udp_flood ;;
    web-sqli)     web_sqli ;;
    ftp-brute)    ftp_brute ;;
    shellcode)    shellcode ;;
    et-loic)      et_loic ;;
    et-tsunami)   et_tsunami ;;
    et-ftp-ua)    et_ftp_ua ;;
    et-loic-terse) et_loic_terse ;;
    all)
        null_scan; xmas_scan; fin_scan
        port_scan; syn_flood; udp_flood
        web_sqli; ftp_brute; shellcode
        et_loic; et_tsunami; et_ftp_ua
        ;;
    *)
        echo "Invalid scenario: $SCEN"
        echo "Usage: $0 [all|null-scan|xmas-scan|fin-scan|port-scan|syn-flood|udp-flood|"
        echo "          web-sqli|ftp-brute|shellcode|et-loic|et-tsunami|et-ftp-ua|et-loic-terse]"
        exit 1
        ;;
esac

c_hdr "Done"
c_note "Verify detection on Stargazer:"
c_note "  execute diagnose ips status     # ipsd_running + alert count"
c_note "  execute diagnose ips alerts 30  # 30 most recent alerts"
