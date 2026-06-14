#!/bin/sh
# start-ips.sh — run on the Stargazer VM to enable IPS testing
#
# Usage: ./start-ips.sh [detect|prevent]
#
# Requires: stargazer-ipsd + rules already present in /sbin/ and /etc/stargazer/ips/

MODE="${1:-prevent}"
QUEUE_NUM=0
RULES="/etc/stargazer/ips/rules/active.rules"
LOG="/etc/stargazer/logs/ipsd.log"

echo "[IPS] Setting up iptables NFQUEUE rules..."

# ---- 1. IPS enforcement rules (insert before the policy chain) ----
# Drop flows marked BLOCK (bit 1 = 0x2)
iptables -I FORWARD 1 -m connmark --mark 0x2/0x2 -j DROP

# Queue NEW flows without an INSPECTED verdict yet (bit 2 = 0x4)
iptables -I FORWARD 2 \
    -m conntrack --ctstate NEW \
    -m connmark ! --mark 0x4/0x4 \
    -j NFQUEUE --queue-num ${QUEUE_NUM}

echo "[IPS] iptables rules:"
iptables -L FORWARD -n --line-numbers | head -10

# ---- 2. Start ipsd ----
echo "[IPS] Starting stargazer-ipsd (mode=${MODE})..."

EXTRA=""
[ "$MODE" = "detect" ] && EXTRA="-d"

stargazer-ipsd \
    -q ${QUEUE_NUM} \
    -r ${RULES} \
    -n \
    ${EXTRA} \
    >> ${LOG} 2>&1 &

echo "[IPS] ipsd PID=$! (log: ${LOG})"
echo "[IPS] Ready. Use 'tail -f ${LOG}' to watch alerts."
