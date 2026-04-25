#!/bin/sh
# test_firewall_behavior.sh — Firewall rule behavior tests for Stargazer NGFW
#
# Tests firewall rule application, chain policy, IPv6 gaps, and address
# object resolution behavior.  Runs both static source checks and live
# iptables checks when available.
#
# Exit 0 = all tests passed (or no live iptables available for live tests)
# Exit 1 = one or more tests FAILED
#
# Run on target: sh tests/test_firewall_behavior.sh
# Run with live server + auth token: BASE_URL=https://192.168.1.1 TOKEN=<tok> sh tests/test_firewall_behavior.sh

set -e
BASE_URL="${BASE_URL:-https://127.0.0.1}"
TOKEN="${TOKEN:-}"
PASS=0
FAIL=0

R='\033[91m'; G='\033[92m'; Y='\033[93m'; C='\033[96m'
N='\033[0m';  B='\033[1m'

pass() { PASS=$((PASS+1)); printf "  ${G}PASS${N} %s\n" "$1"; }
fail() { FAIL=$((FAIL+1)); printf "  ${R}FAIL${N} %s\n" "$1"; [ -n "$2" ] && printf "       ${Y}%s${N}\n" "$2"; }
note() { printf "  ${Y}NOTE${N} %s\n" "$1"; }
skip() { printf "  ${Y}SKIP${N} %s (no live system)\n" "$1"; }

# ─────────────────────────────────────────────────────────────────────────────
printf "\n${B}${C}=== Phase 1: Source-level firewall gap checks ===${N}\n"
# ─────────────────────────────────────────────────────────────────────────────

SRCBASE="$(dirname "$(dirname "$(realpath "$0")")")"
FW_APPLY="$SRCBASE/src/userspace/mgmtd/mgmtd_apply_firewall.c"
MGMTD="$SRCBASE/src/userspace/mgmtd/stargazer-mgmtd.c"
INIT="$SRCBASE/src/userspace/init"

# ATK-J-02: Init does NOT set FORWARD DROP — window before mgmtd starts
if grep -q 'FORWARD.*DROP\|DROP.*FORWARD' "$INIT" 2>/dev/null; then
    pass "ATK-J-02: Init sets FORWARD DROP before mgmtd"
else
    fail "ATK-J-02: Init has NO FORWARD DROP (gap: window before mgmtd starts)" \
         "FORWARD default is ACCEPT between init and mgmtd startup. Packets can flow."
fi

# Check mgmtd DOES set FORWARD DROP
if grep -q '"FORWARD", "DROP"' "$MGMTD" 2>/dev/null; then
    pass "mgmtd_init_firewall sets iptables -P FORWARD DROP"
else
    fail "mgmtd_init_firewall: cannot find FORWARD DROP rule" \
         "If this is missing, FORWARD chain never drops by default"
fi

# Init sets INPUT DROP (good)
if grep -q 'iptables -P INPUT DROP' "$INIT" 2>/dev/null; then
    pass "Init sets iptables -P INPUT DROP before mgmtd"
else
    fail "Init does NOT set INPUT DROP" \
         "Management plane unprotected during boot"
fi

# ATK-J-03: No ip6tables in init (IPv6 forwarding gap)
if grep -q 'ip6tables' "$INIT" 2>/dev/null; then
    pass "ATK-J-03: Init configures ip6tables rules"
else
    fail "ATK-J-03: Init has NO ip6tables rules (IPv6 forwarding not filtered)" \
         "pkt_forward.c only hooks NF_INET_FORWARD (IPv4). IPv6 bypasses the firewall."
fi

# ATK-K-01: Named address objects silently ignored in iptables rules
# When srcaddr is a named object (not CIDR), the -s flag is skipped —
# the iptables rule has no source restriction (matches any source).
if grep -q 'sg_is_cidr(srcaddr)' "$FW_APPLY" 2>/dev/null; then
    note "ATK-K-01: Named address objects skipped in iptables -s/-d (by design)"
    note "         Policy with srcaddr=named-obj generates: iptables -A FORWARD -j TARGET"
    note "         Address object's subnet is NOT enforced at iptables level"
    note "         Severity: HIGH functional gap — policies silently ignore named addrs"
    FAIL=$((FAIL+1))
    printf "  ${R}FAIL${N} ATK-K-01: named address objects have no iptables effect\n"
else
    pass "ATK-K-01: Firewall apply handles named address objects"
fi

# ATK-K-02: Service objects not included in iptables rules
if grep -q '\-\-dport\|--sport\|-p tcp\|-p udp' "$FW_APPLY" 2>/dev/null; then
    pass "ATK-K-02: Service objects included in iptables rules (port filtering)"
else
    note "ATK-K-02: No port/protocol in build_forward_argv"
    note "         Policy with service=my-svc generates iptables rule with NO port filter"
    note "         Service object's port/protocol is NOT enforced at iptables level"
    FAIL=$((FAIL+1))
    printf "  ${R}FAIL${N} ATK-K-02: service objects have no iptables effect (port not filtered)\n"
fi

# ─────────────────────────────────────────────────────────────────────────────
printf "\n${B}${C}=== Phase 2: Live iptables checks ===${N}\n"
# ─────────────────────────────────────────────────────────────────────────────

if ! command -v iptables >/dev/null 2>&1; then
    skip "FORWARD chain default policy (iptables not available)"
    skip "IPv6 forwarding disabled check"
    skip "FORWARD ESTABLISHED/RELATED rule"
else
    # Check FORWARD default policy
    fwd_policy=$(iptables -L FORWARD 2>/dev/null | head -1 | grep -o 'policy [A-Z]*' | awk '{print $2}')
    if [ "$fwd_policy" = "DROP" ]; then
        pass "FORWARD chain default policy is DROP"
    else
        fail "FORWARD chain default policy is $fwd_policy (expected DROP)" \
             "Traffic may be forwarded before firewall policies are loaded"
    fi

    # Check FORWARD ESTABLISHED,RELATED rule exists
    if iptables -L FORWARD 2>/dev/null | grep -q 'ESTABLISHED,RELATED\|RELATED,ESTABLISHED'; then
        pass "FORWARD chain has ESTABLISHED/RELATED ACCEPT rule"
    else
        note "FORWARD chain has no ESTABLISHED/RELATED rule (connections may not work)"
    fi

    # Check INPUT default policy
    in_policy=$(iptables -L INPUT 2>/dev/null | head -1 | grep -o 'policy [A-Z]*' | awk '{print $2}')
    if [ "$in_policy" = "DROP" ]; then
        pass "INPUT chain default policy is DROP"
    else
        fail "INPUT chain default policy is $in_policy (expected DROP)" \
             "Management plane not protected"
    fi

    # Check ip6tables FORWARD policy
    if command -v ip6tables >/dev/null 2>&1; then
        ip6_fwd=$(ip6tables -L FORWARD 2>/dev/null | head -1 | grep -o 'policy [A-Z]*' | awk '{print $2}')
        if [ "$ip6_fwd" = "DROP" ]; then
            pass "ip6tables FORWARD chain default policy is DROP"
        else
            fail "ip6tables FORWARD policy is $ip6_fwd (expected DROP — ATK-J-03)" \
                 "IPv6 traffic bypasses pkt_forward.c and has no FORWARD DROP policy"
        fi
    else
        fail "ip6tables not available — IPv6 forwarding policy cannot be verified" \
             "ATK-J-03: IPv6 traffic may bypass all firewall policies"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
printf "\n${B}${C}=== Phase 3: IPv6 kernel forwarding check ===${N}\n"
# ─────────────────────────────────────────────────────────────────────────────

if [ -f /proc/sys/net/ipv6/conf/all/forwarding ]; then
    ipv6_fwd=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)
    if [ "$ipv6_fwd" = "0" ]; then
        pass "IPv6 forwarding disabled via sysctl (mitigates ATK-J-03)"
    else
        fail "IPv6 forwarding is ENABLED (sysctl net.ipv6.conf.all.forwarding=$ipv6_fwd)" \
             "ATK-J-03: IPv6 traffic forwards without any firewall policy filtering"
    fi
elif [ -f /proc/sys/net ]; then
    fail "IPv6 sysctl forwarding file not found" \
         "Cannot verify IPv6 forwarding state"
else
    skip "IPv6 forwarding check (no /proc/sys)"
fi

# ─────────────────────────────────────────────────────────────────────────────
printf "\n${B}${C}=== Phase 4: Named address object gap (live HTTP) ===${N}\n"
# ─────────────────────────────────────────────────────────────────────────────

if [ -z "$TOKEN" ]; then
    skip "Named address object iptables verification (set TOKEN=<bearer> to enable)"
else
    CURL="curl -sk -H 'Authorization: Bearer $TOKEN'"

    # Create a test address object
    CREATE_ADDR=$(curl -sk -o /dev/null -w "%{http_code}" \
        -X POST "$BASE_URL/api/config/firewall_address" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"name":"test-atk-k01","subnet":"10.99.99.0/24","type":"ipmask"}')
    if [ "$CREATE_ADDR" = "200" ] || [ "$CREATE_ADDR" = "201" ]; then
        pass "Created test address object test-atk-k01 (10.99.99.0/24)"
    else
        skip "Cannot create test address object (HTTP $CREATE_ADDR) — skipping live test"
        TOKEN=""
    fi
fi

if [ -n "$TOKEN" ]; then
    # Create firewall policy using named address object (not CIDR)
    CREATE_POL=$(curl -sk -o /dev/null -w "%{http_code}" \
        -X POST "$BASE_URL/api/config/firewall_policy" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"name":"test-atk-k01","srcintf":"any","dstintf":"any","srcaddr":"test-atk-k01","dstaddr":"all","action":"accept","service":"all","status":"enable"}')
    if [ "$CREATE_POL" = "200" ] || [ "$CREATE_POL" = "201" ]; then
        pass "Created test firewall policy with named srcaddr"
    else
        note "Cannot create test firewall policy (HTTP $CREATE_POL)"
    fi

    # Check what iptables actually got
    if command -v iptables >/dev/null 2>&1; then
        ipt_rules=$(iptables -S FORWARD 2>/dev/null)
        # The rule should have been added — but without -s filter (named object silently ignored)
        if echo "$ipt_rules" | grep -q '\-s 10\.99\.99\.0/24'; then
            pass "ATK-K-01: Named address object resolved to CIDR in iptables rule"
        elif echo "$ipt_rules" | grep -qv '\-s '; then
            note "ATK-K-01: iptables FORWARD rule has no -s filter (named address SILENTLY IGNORED)"
            note "         Policy 'srcaddr=test-atk-k01' created iptables rule without -s 10.99.99.0/24"
            note "         This policy ACCEPTS ALL forwarded traffic regardless of source IP"
            FAIL=$((FAIL+1))
            printf "  ${R}FAIL${N} ATK-K-01: named address object has no effect on iptables rules\n"
        fi
    fi

    # Cleanup
    curl -sk -o /dev/null -X DELETE "$BASE_URL/api/config/firewall_policy/test-atk-k01" \
        -H "Authorization: Bearer $TOKEN" >/dev/null 2>&1
    curl -sk -o /dev/null -X DELETE "$BASE_URL/api/config/firewall_address/test-atk-k01" \
        -H "Authorization: Bearer $TOKEN" >/dev/null 2>&1
fi

# ─────────────────────────────────────────────────────────────────────────────
printf "\n${B}${C}=== Phase 5: Firewall rule ordering and replay ===${N}\n"
# ─────────────────────────────────────────────────────────────────────────────

FW_APPLY2="$SRCBASE/src/userspace/mgmtd/mgmtd_apply_firewall.c"

# Rules are appended (-A FORWARD), not inserted at front
if grep -q '"-A", "FORWARD"' "$FW_APPLY2" 2>/dev/null; then
    pass "Firewall policies use -A FORWARD (append order = policy priority order)"
else
    fail "Cannot verify FORWARD rule append mode"
fi

# No explicit priority/sequence reorder during replay — rules applied in DB ID order
mgmtd_src="$SRCBASE/src/userspace/mgmtd/stargazer-mgmtd.c"
if grep -q 'apply_firewall_policy\|replay.*firewall\|firewall.*replay' "$mgmtd_src" 2>/dev/null; then
    pass "mgmtd replays firewall policies during config reload"
else
    note "Cannot confirm firewall policy replay on config reload"
fi

# ─────────────────────────────────────────────────────────────────────────────
printf "\n${B}${C}=== Summary ===${N}\n"
# ─────────────────────────────────────────────────────────────────────────────

printf "\n  ${Y}Known gaps (require fixes)${N}:\n"
printf "  ATK-J-02: FORWARD chain is ACCEPT before mgmtd starts (init should set DROP)\n"
printf "  ATK-J-03: IPv6 forwarding has no policy filter (ip6tables FORWARD DROP needed)\n"
printf "  ATK-K-01: Named firewall address objects silently ignored in iptables rules\n"
printf "  ATK-K-02: Service objects silently ignored — no port/protocol in iptables rules\n"

printf "\n"
if [ "$FAIL" -eq 0 ]; then
    printf "${G}${B}ALL $((PASS)) FIREWALL BEHAVIOR CHECKS PASSED${N}\n"
else
    printf "${Y}Results: ${G}${PASS} passed${N}, ${R}${FAIL} failed${N} / $((PASS+FAIL)) total\n"
    exit 1
fi
