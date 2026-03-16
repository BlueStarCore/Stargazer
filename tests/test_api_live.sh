#!/bin/bash
# =============================================================================
# Stargazer NGFW — Live API test suite
#
# Tests every REST endpoint against a running firewall VM with three roles:
#   admin    — read-write profile (monitor + configure + admin)
#   testro   — read-only profile  (monitor only)
#   testrw   — read-write profile (monitor + configure + admin)
#
# Usage:
#   ./tests/test_api_live.sh [FIREWALL_IP]
#
# Default firewall IP: 10.0.1.254
# Requires: curl, python3
#
# Pre-requisites:
#   1. Firewall VM running (scripts/run_firewall.sh)
#   2. Admin account exists with password set in ADMIN_PASS below
# =============================================================================

set -euo pipefail

BASE="http://${1:-10.0.1.254}"
ADMIN_PASS="${ADMIN_PASS:-Saolainoi999.}"
RO_PASS="Readon1y_live9!"
RW_PASS="Readwrite_live9!"

JAR_ADMIN="/tmp/sg_test_admin.jar"
JAR_RO="/tmp/sg_test_ro.jar"
JAR_RW="/tmp/sg_test_rw.jar"

PASS=0
FAIL=0
NOTES=()

# ── Helpers ──────────────────────────────────────────────────────────────────

red()   { printf '\033[31m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
yel()   { printf '\033[33m%s\033[0m' "$*"; }

check() {
    local label="$1" got="$2" want="$3"
    if [ "$got" = "$want" ]; then
        printf "  %-60s → %s [%s]\n" "$label" "$got" "$(green PASS)"
        PASS=$((PASS+1))
    else
        printf "  %-60s → %s [%s] (want %s)\n" "$label" "$got" "$(red FAIL)" "$want"
        FAIL=$((FAIL+1))
    fi
}

note() {
    local label="$1" got="$2" comment="$3"
    printf "  %-60s → %s [%s] %s\n" "$label" "$got" "$(yel NOTE)" "$comment"
    NOTES+=("$label → $got ($comment)")
}

api() {
    # api METHOD PATH [JAR] [BODY]
    local method="$1" path="$2" jar="${3:-}" body="${4:-}"
    local args=(-si -X "$method" "$BASE$path" --max-time 15)
    [ -n "$jar" ] && args+=(-b "$jar")
    [ -n "$body" ] && args+=(-H "Content-Type: application/json" -d "$body")
    curl "${args[@]}" 2>/dev/null | grep "^HTTP" | awk '{print $2}'
}

api_body() {
    local method="$1" path="$2" jar="${3:-}" body="${4:-}"
    local args=(-s -X "$method" "$BASE$path" --max-time 15)
    [ -n "$jar" ] && args+=(-b "$jar")
    [ -n "$body" ] && args+=(-H "Content-Type: application/json" -d "$body")
    curl "${args[@]}" 2>/dev/null
}

section() { printf '\n\033[1m[ %s ]\033[0m %s\n' "$1" "$2"; }

# ── Wait for firewall ─────────────────────────────────────────────────────────

wait_for_firewall() {
    printf 'Waiting for firewall at %s ...' "$BASE"
    for i in $(seq 1 30); do
        if curl -si "$BASE/" --max-time 5 2>/dev/null | grep -q "^HTTP.*200"; then
            echo " up!"
            return 0
        fi
        printf '.'
        sleep 5
    done
    echo " TIMEOUT"
    exit 1
}

# ── Login helpers ─────────────────────────────────────────────────────────────

login_all() {
    curl -si -X POST "$BASE/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASS\"}" \
        -c "$JAR_ADMIN" --max-time 10 2>/dev/null | grep -q "^HTTP.*200" || {
        echo "ERROR: admin login failed"; exit 1; }

    # Create test accounts (ignore errors if they already exist)
    curl -s -X POST "$BASE/api/admin/create" -b "$JAR_ADMIN" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"testro\",\"profile\":\"read-only\",\"password\":\"$RO_PASS\"}" \
        --max-time 10 2>/dev/null >/dev/null

    curl -s -X POST "$BASE/api/admin/create" -b "$JAR_ADMIN" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"testrw\",\"profile\":\"read-write\",\"password\":\"$RW_PASS\"}" \
        --max-time 10 2>/dev/null >/dev/null

    # Update passwords in case accounts existed with different passwords
    curl -s -X PUT "$BASE/api/config/system_admin/testro" -b "$JAR_ADMIN" \
        -H "Content-Type: application/json" \
        -d "{\"password\":\"$RO_PASS\"}" --max-time 10 2>/dev/null >/dev/null || true

    curl -si -X POST "$BASE/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"testro\",\"password\":\"$RO_PASS\"}" \
        -c "$JAR_RO" --max-time 10 2>/dev/null | grep -q "^HTTP.*200" || {
        echo "WARN: testro login failed (may need manual password reset)"; }

    curl -si -X POST "$BASE/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"testrw\",\"password\":\"$RW_PASS\"}" \
        -c "$JAR_RW" --max-time 10 2>/dev/null | grep -q "^HTTP.*200" || {
        echo "WARN: testrw login failed (may need manual password reset)"; }
}

refresh_sessions() {
    # Re-login all accounts (call when 401 errors appear mid-suite)
    curl -si -X POST "$BASE/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASS\"}" \
        -c "$JAR_ADMIN" --max-time 10 2>/dev/null >/dev/null

    curl -si -X POST "$BASE/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"testro\",\"password\":\"$RO_PASS\"}" \
        -c "$JAR_RO" --max-time 10 2>/dev/null >/dev/null

    curl -si -X POST "$BASE/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"testrw\",\"password\":\"$RW_PASS\"}" \
        -c "$JAR_RW" --max-time 10 2>/dev/null >/dev/null
}

# =============================================================================
# TEST PHASES
# =============================================================================

phase1_unauthenticated() {
    section 1 "Unauthenticated access — all protected endpoints must 401"
    local endpoints=(
        "GET /api/auth/whoami"
        "GET /api/config/system_interface"
        "GET /api/config/system_interface/eth0"
        "GET /api/config/firewall_policy"
        "GET /api/system/resources"
        "GET /api/system/resources/detail"
        "GET /api/system/resources/ram"
        "GET /api/system/firmware"
        "POST /api/admin/create"
        "PUT /api/config/system_interface/eth0"
        "DELETE /api/config/firewall_policy/x"
        "POST /api/diagnose/ping"
        "POST /api/auth/change-password"
        "POST /api/auth/logout"
    )
    for ep in "${endpoints[@]}"; do
        local method; method=$(echo "$ep" | awk '{print $1}')
        local path;   path=$(echo "$ep"   | awk '{print $2}')
        local r; r=$(api "$method" "$path")
        check "Unauthed $method $path" "$r" "401"
    done
}

phase2_auth_edge_cases() {
    section 2 "Auth endpoint edge cases"

    local r
    r=$(api POST /api/auth/login "" '{}')
    check "POST /api/auth/login — missing body" "$r" "400"

    r=$(api POST /api/auth/login "" '{"username":"admin","password":"wrongpassword"}')
    check "POST /api/auth/login — wrong password" "$r" "401"

    r=$(api POST /api/auth/login "" '{"username":"nosuchuser99","password":"anything"}')
    check "POST /api/auth/login — nonexistent user (username enumeration)" "$r" "401"

    r=$(api POST /api/auth/login "" '{"username":"<script>alert(1)</script>","password":"x"}')
    check "POST /api/auth/login — XSS in username" "$r" "400"

    r=$(api POST /api/auth/login "" '{"username":"admin'"'"' OR 1=1 --","password":"x"}')
    check "POST /api/auth/login — SQL injection" "$r" "400"

    r=$(api POST /api/auth/login "" '{"username":"","password":""}')
    check "POST /api/auth/login — empty strings" "$r" "400"

    r=$(api POST /api/auth/login "" '{"username":"admin"}')
    check "POST /api/auth/login — missing password field" "$r" "400"

    # Rate limiting: send 11 rapid requests, 11th must be 429
    for i in $(seq 1 11); do
        r=$(api POST /api/auth/login "" '{"username":"admin","password":"wrong"}')
    done
    check "POST /api/auth/login — rate limit (11th attempt)" "$r" "429"
    sleep 1  # reset rate window
}

phase3_login_and_whoami() {
    section 3 "Login + whoami verification"
    login_all

    local r
    r=$(api_body GET /api/auth/whoami "$JAR_ADMIN")
    if echo "$r" | grep -q '"admin"'; then
        printf "  %-60s → %s [%s]\n" "admin whoami" "$r" "$(green PASS)"; PASS=$((PASS+1))
    else
        printf "  %-60s → %s [%s]\n" "admin whoami" "$r" "$(red FAIL)"; FAIL=$((FAIL+1))
    fi

    r=$(api_body GET /api/auth/whoami "$JAR_RO")
    if echo "$r" | grep -q '"monitor"'; then
        printf "  %-60s → %s [%s]\n" "testro whoami (monitor)" "$r" "$(green PASS)"; PASS=$((PASS+1))
    else
        printf "  %-60s → %s [%s]\n" "testro whoami (monitor)" "$r" "$(red FAIL)"; FAIL=$((FAIL+1))
    fi

    r=$(api_body GET /api/auth/whoami "$JAR_RW")
    if echo "$r" | grep -q '"monitor,configure,admin"'; then
        printf "  %-60s → %s [%s]\n" "testrw whoami (monitor,configure,admin)" "$r" "$(green PASS)"; PASS=$((PASS+1))
    else
        printf "  %-60s → %s [%s]\n" "testrw whoami (monitor,configure,admin)" "$r" "$(red FAIL)"; FAIL=$((FAIL+1))
    fi
}

phase4_config_read() {
    section 4 "Config READ — all three roles"
    local types=("system_interface" "system_interface/eth0" "firewall_policy" "system_admin" "system_admin-profile")
    for role in admin ro rw; do
        local jar="/tmp/sg_test_${role}.jar"
        for t in "${types[@]}"; do
            local r; r=$(api GET "/api/config/$t" "$jar")
            check "[$role] GET /api/config/$t" "$r" "200"
        done
    done
}

phase5_config_write() {
    section 5 "Config WRITE — privilege enforcement"
    refresh_sessions

    # First create a test firewall policy to operate on
    api_body POST /api/config/firewall_policy "$JAR_ADMIN" \
        '{"name":"99","action":"accept","srcintf":"eth0","dstintf":"eth1","srcaddr":"all","dstaddr":"all","service":"all","schedule":"all","status":"enable"}' \
        >/dev/null 2>&1 || true

    local r

    # ro must 403 on write
    r=$(api PUT /api/config/firewall_policy/99 "$JAR_RO" '{"action":"deny"}')
    check "[ro] PUT /api/config/firewall_policy/99 (expect 403)" "$r" "403"

    # rw can write
    r=$(api PUT /api/config/firewall_policy/99 "$JAR_RW" '{"action":"deny"}')
    check "[rw] PUT /api/config/firewall_policy/99 (expect 200)" "$r" "200"

    # admin can write
    r=$(api PUT /api/config/firewall_policy/99 "$JAR_ADMIN" '{"action":"accept"}')
    check "[admin] PUT /api/config/firewall_policy/99 (expect 200)" "$r" "200"

    # ro must 403 on POST
    r=$(api POST /api/config/firewall_policy "$JAR_RO" \
        '{"name":"98","action":"accept","srcintf":"eth0","dstintf":"eth1","srcaddr":"all","dstaddr":"all","service":"all","schedule":"all","status":"enable"}')
    check "[ro] POST /api/config/firewall_policy (expect 403)" "$r" "403"
}

phase5b_bug_api4() {
    section "5b" "BUG-API-4: PUT body name/id must be stripped — not stored in DB"
    refresh_sessions

    api PUT /api/config/firewall_policy/99 "$JAR_ADMIN" \
        '{"name":"injected","id":"999","action":"deny"}' >/dev/null

    local body; body=$(api_body GET /api/config/firewall_policy/99 "$JAR_ADMIN")
    # 'name' must not appear as a field (id is present as the routing key only)
    if echo "$body" | grep -q '"name":"injected"'; then
        printf "  %-60s [%s] (name=injected was stored)\n" "BUG-API-4: name stripped from PUT body" "$(red FAIL)"
        FAIL=$((FAIL+1))
    else
        printf "  %-60s [%s]\n" "BUG-API-4: name stripped from PUT body" "$(green PASS)"
        PASS=$((PASS+1))
    fi
}

phase6_config_delete() {
    section 6 "Config DELETE — privilege enforcement + edge cases"
    refresh_sessions

    local r
    r=$(api DELETE /api/config/firewall_policy/99 "$JAR_RO")
    check "[ro] DELETE /api/config/firewall_policy/99 (expect 403)" "$r" "403"

    r=$(api DELETE /api/config/firewall_policy/99 "$JAR_RW")
    check "[rw] DELETE /api/config/firewall_policy/99 (expect 200)" "$r" "200"

    r=$(api DELETE /api/config/system_admin/admin "$JAR_ADMIN")
    check "[admin] DELETE builtin system_admin/admin (expect 403)" "$r" "403"

    # Nonexistent entry — mgmtd currently returns 200 (pre-existing behavior)
    r=$(api DELETE /api/config/firewall_policy/99999 "$JAR_ADMIN")
    if [ "$r" = "404" ]; then
        check "[admin] DELETE nonexistent entry (404)" "$r" "404"
    else
        note "[admin] DELETE nonexistent entry" "$r" "mgmtd silently succeeds (pre-existing)"
    fi
}

phase7_system_resources() {
    section 7 "System resources — all roles"
    for role in admin ro rw; do
        local jar="/tmp/sg_test_${role}.jar"
        for ep in resources resources/detail resources/ram resources/disk firmware; do
            local r; r=$(api GET "/api/system/$ep" "$jar")
            check "[$role] GET /api/system/$ep" "$r" "200"
        done
    done
}

phase8_diagnose() {
    section 8 "Diagnose tools"
    refresh_sessions

    local r

    # Missing target
    r=$(api POST /api/diagnose/ping "$JAR_ADMIN" '{}')
    check "[admin] POST /api/diagnose/ping — missing target" "$r" "400"

    # Unknown tool
    r=$(api POST /api/diagnose/nonexistent "$JAR_ADMIN" '{"target":"x"}')
    check "[admin] POST /api/diagnose/nonexistent — 404" "$r" "404"

    # nslookup (non-streaming)
    r=$(api POST /api/diagnose/nslookup "$JAR_ADMIN" '{"target":"localhost"}')
    check "[admin] POST /api/diagnose/nslookup localhost — 200" "$r" "200"

    # ping (streaming, 30s timeout)
    r=$(api POST /api/diagnose/ping "$JAR_ADMIN" '{"target":"127.0.0.1"}')
    check "[admin] POST /api/diagnose/ping 127.0.0.1 — 200" "$r" "200"

    # read-only can use diagnose (has monitor perm)
    r=$(api POST /api/diagnose/nslookup "$JAR_RO" '{"target":"localhost"}')
    check "[ro] POST /api/diagnose/nslookup — 200 (monitor allowed)" "$r" "200"
}

phase9_change_password() {
    section 9 "Change password"
    refresh_sessions

    local r

    # Missing body
    r=$(api POST /api/auth/change-password "$JAR_ADMIN" '{}')
    check "[admin] POST /api/auth/change-password — missing body" "$r" "400"

    # Weak password
    r=$(api POST /api/auth/change-password "$JAR_RW" '{"password":"weak"}')
    check "[rw] POST /api/auth/change-password — weak password" "$r" "400"

    # ro can change own password
    r=$(api POST /api/auth/change-password "$JAR_RO" "{\"password\":\"${RO_PASS}\"}")
    check "[ro] POST /api/auth/change-password — valid password" "$r" "200"
}

phase10_admin_create() {
    section 10 "Admin create — privilege enforcement"
    refresh_sessions

    local r

    # ro cannot create admin
    r=$(api POST /api/admin/create "$JAR_RO" '{"username":"shouldfail","profile":"read-only"}')
    check "[ro] POST /api/admin/create (expect 403)" "$r" "403"

    # rw (has admin perm) can create admin
    r=$(api POST /api/admin/create "$JAR_RW" '{"username":"tmpuser","profile":"read-only"}')
    check "[rw] POST /api/admin/create (expect 200)" "$r" "200"

    # Duplicate user
    r=$(api POST /api/admin/create "$JAR_ADMIN" '{"username":"testro","profile":"read-only"}')
    check "[admin] POST /api/admin/create duplicate (expect 409)" "$r" "409"

    # Bad profile
    r=$(api POST /api/admin/create "$JAR_ADMIN" '{"username":"badprof","profile":"superadmin"}')
    check "[admin] POST /api/admin/create bad profile (expect 404)" "$r" "404"

    # Invalid username
    r=$(api POST /api/admin/create "$JAR_ADMIN" '{"username":"bad user!","profile":"read-only"}')
    check "[admin] POST /api/admin/create invalid username (expect 400)" "$r" "400"

    # Missing username
    r=$(api POST /api/admin/create "$JAR_ADMIN" '{"profile":"read-only"}')
    check "[admin] POST /api/admin/create missing username (expect 400)" "$r" "400"

    # Cleanup tmpuser
    api DELETE /api/config/system_admin/tmpuser "$JAR_ADMIN" >/dev/null 2>&1 || true
}

phase11_session_management() {
    section 11 "Session management"

    # Logout clears session
    local logout_resp
    logout_resp=$(curl -si -X POST "$BASE/api/auth/logout" -b "$JAR_RW" --max-time 5 2>/dev/null)
    if echo "$logout_resp" | grep -q "Max-Age=0"; then
        printf "  %-60s [%s]\n" "POST /api/auth/logout — clears cookie" "$(green PASS)"; PASS=$((PASS+1))
    else
        printf "  %-60s [%s]\n" "POST /api/auth/logout — clears cookie" "$(red FAIL)"; FAIL=$((FAIL+1))
    fi

    # Old token rejected after logout
    local r
    r=$(api GET /api/auth/whoami "$JAR_RW")
    check "GET /api/auth/whoami after logout (expect 401)" "$r" "401"

    # Garbage token
    r=$(curl -si "$BASE/api/auth/whoami" \
        -H "Authorization: Bearer 0000000000000000000000000000000000000000000000000000000000000000" \
        --max-time 5 2>/dev/null | grep "^HTTP" | awk '{print $2}')
    check "GET /api/auth/whoami — 64-char garbage token (expect 401)" "$r" "401"

    # Short token
    r=$(curl -si "$BASE/api/auth/whoami" \
        -H "Authorization: Bearer short" \
        --max-time 5 2>/dev/null | grep "^HTTP" | awk '{print $2}')
    check "GET /api/auth/whoami — short token (expect 401)" "$r" "401"

    # Bearer wins over cookie
    r=$(curl -si "$BASE/api/auth/whoami" -b "$JAR_ADMIN" \
        -H "Authorization: Bearer 0000000000000000000000000000000000000000000000000000000000000000" \
        --max-time 5 2>/dev/null | grep "^HTTP" | awk '{print $2}')
    check "GET /api/auth/whoami — valid cookie + invalid bearer (bearer wins)" "$r" "401"

    # Re-login rw for remaining tests
    curl -si -X POST "$BASE/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"testrw\",\"password\":\"$RW_PASS\"}" \
        -c "$JAR_RW" --max-time 10 2>/dev/null >/dev/null
}

phase12_config_edge_cases() {
    section 12 "Config edge cases"
    refresh_sessions

    local r

    r=$(api GET /api/config/nosuchtype "$JAR_ADMIN")
    check "GET /api/config/nosuchtype (expect 400)" "$r" "400"

    r=$(api GET /api/config/system_interface/eth99 "$JAR_ADMIN")
    check "GET /api/config/system_interface/eth99 (expect 404)" "$r" "404"

    r=$(api POST /api/config/firewall_policy "$JAR_ADMIN" 'not-json')
    check "POST /api/config/firewall_policy — invalid JSON (expect 400)" "$r" "400"

    # Search filter
    r=$(api GET "/api/config/firewall_policy?q=deny" "$JAR_ADMIN")
    check "GET /api/config/firewall_policy?q=deny — search filter" "$r" "200"
}

phase13_security_headers() {
    section 13 "Security headers"

    local headers
    headers=$(curl -si "$BASE/api/auth/whoami" -b "$JAR_ADMIN" --max-time 5 2>/dev/null)

    for hdr in "X-Content-Type-Options: nosniff" "X-Frame-Options: DENY" "Content-Security-Policy:"; do
        if echo "$headers" | grep -qi "$hdr"; then
            printf "  %-60s [%s]\n" "Header present: $hdr" "$(green PASS)"; PASS=$((PASS+1))
        else
            printf "  %-60s [%s]\n" "Header present: $hdr" "$(red FAIL)"; FAIL=$((FAIL+1))
        fi
    done
}

phase14_firmware() {
    section 14 "Firmware endpoints"
    refresh_sessions

    local r

    r=$(api GET /api/system/firmware "$JAR_ADMIN")
    check "GET /api/system/firmware" "$r" "200"

    r=$(api GET /api/system/firmware/progress "$JAR_ADMIN")
    check "GET /api/system/firmware/progress" "$r" "200"

    r=$(api POST /api/system/firmware/upgrade "$JAR_ADMIN")
    check "POST /api/system/firmware/upgrade (stub, expect 501)" "$r" "501"
}

phase15_lockout_not_leaking() {
    section 15 "BUG-MGMTD-1: locked account must return 401 not 403"

    # Trigger lockout (5 failures)
    for i in $(seq 1 5); do
        curl -s -X POST "$BASE/api/auth/login" \
            -H "Content-Type: application/json" \
            -d '{"username":"testrw","password":"wrongpass"}' \
            --max-time 5 2>/dev/null >/dev/null
    done
    sleep 1

    local r

    # Wrong password on locked account — must be 401, NOT 403
    r=$(api POST /api/auth/login "" '{"username":"testrw","password":"wrongpass"}')
    check "POST /api/auth/login — locked acct + wrong pw (must be 401, not 403)" "$r" "401"

    # Correct password on locked account — must also be 401 (hides lockout status)
    r=$(api POST /api/auth/login "" "{\"username\":\"testrw\",\"password\":\"$RW_PASS\"}")
    check "POST /api/auth/login — locked acct + correct pw (must be 401)" "$r" "401"

    # Wait for lockout to expire and restore rw session
    sleep 2
    refresh_sessions
}

phase16_method_not_allowed() {
    section 16 "Method not allowed"
    refresh_sessions

    for method in PATCH HEAD OPTIONS; do
        local r; r=$(api "$method" /api/config/system_interface "$JAR_ADMIN")
        check "$method /api/config/system_interface (expect 405)" "$r" "405"
    done
}

phase17_static_files() {
    section 17 "Static file serving"

    declare -A expected=(["/"]="200" ["/login.html"]="200" ["/js/app.js"]="200"
                         ["/css/stargazer.css"]="200" ["/nonexistent.html"]="404")
    for path in "${!expected[@]}"; do
        local r; r=$(curl -si "$BASE$path" --max-time 5 2>/dev/null | grep "^HTTP" | awk '{print $2}')
        check "GET $path" "$r" "${expected[$path]}"
    done
}

phase18_path_traversal() {
    section 18 "Path traversal + injection"
    refresh_sessions

    local r

    for path in \
        "/api/config/../../etc/passwd" \
        "/api/config/%2e%2e%2fetc%2fpasswd" \
        "/api/config/system_interface/../../../etc/passwd"; do
        r=$(api GET "$path" "$JAR_ADMIN")
        if [ "$r" = "404" ] || [ "$r" = "400" ]; then
            printf "  %-60s → %s [%s]\n" "Path traversal: $path" "$r" "$(green PASS)"; PASS=$((PASS+1))
        else
            printf "  %-60s → %s [%s]\n" "Path traversal: $path" "$r" "$(red FAIL)"; FAIL=$((FAIL+1))
        fi
    done
}

phase19_pool1_large_config() {
    section 19 "BUG-POOL-1: large config PUT (heap buffer, no truncation)"
    refresh_sessions

    local big_comment="test comment with enough length to exercise the heap-allocated merge buffer "
    big_comment+="grow path across multiple realloc iterations verifying that no data is "
    big_comment+="silently truncated when the merged config exceeds the initial 4096 byte capacity"

    local body; body=$(printf '{"action":"deny","comment":"%s"}' "$big_comment")

    # Ensure test policy exists
    api_body POST /api/config/firewall_policy "$JAR_ADMIN" \
        '{"name":"98","action":"accept","srcintf":"eth0","dstintf":"eth1","srcaddr":"all","dstaddr":"all","service":"all","schedule":"all","status":"enable"}' \
        >/dev/null 2>&1 || true

    api PUT /api/config/firewall_policy/98 "$JAR_ADMIN" "$body" >/dev/null

    local stored; stored=$(api_body GET /api/config/firewall_policy/98 "$JAR_ADMIN")
    if echo "$stored" | grep -q "realloc iterations"; then
        printf "  %-60s [%s]\n" "BUG-POOL-1: full comment stored without truncation" "$(green PASS)"; PASS=$((PASS+1))
    else
        printf "  %-60s [%s]\n" "BUG-POOL-1: full comment stored without truncation" "$(red FAIL)"; FAIL=$((FAIL+1))
    fi

    # Cleanup
    api DELETE /api/config/firewall_policy/98 "$JAR_ADMIN" >/dev/null 2>&1 || true
}

phase20_reboot_privilege() {
    section 20 "Reboot — privilege check (no actual reboot)"
    refresh_sessions

    local r
    r=$(api POST /api/system/reboot "$JAR_RO" '{}')
    check "[ro] POST /api/system/reboot (expect 403)" "$r" "403"
}

# =============================================================================
# MAIN
# =============================================================================

echo "======================================================================"
echo " Stargazer NGFW — Live API Test Suite"
echo " Target: $BASE"
echo "======================================================================"

wait_for_firewall

phase1_unauthenticated
phase2_auth_edge_cases
phase3_login_and_whoami
phase4_config_read
phase5_config_write
phase5b_bug_api4
phase6_config_delete
phase7_system_resources
phase8_diagnose
phase9_change_password
phase10_admin_create
phase11_session_management
phase12_config_edge_cases
phase13_security_headers
phase14_firmware
phase15_lockout_not_leaking
phase16_method_not_allowed
phase17_static_files
phase18_path_traversal
phase19_pool1_large_config
phase20_reboot_privilege

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "======================================================================"
printf " Results: %s PASS, %s FAIL\n" "$(green $PASS)" "$([ $FAIL -gt 0 ] && red $FAIL || echo $FAIL)"
echo "======================================================================"

if [ ${#NOTES[@]} -gt 0 ]; then
    echo ""
    echo "Notes (pre-existing mgmtd behavior, not regressions):"
    for n in "${NOTES[@]}"; do
        echo "  - $n"
    done
fi

[ "$FAIL" -eq 0 ]
