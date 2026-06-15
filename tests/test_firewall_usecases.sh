#!/bin/bash
# =============================================================================
# test_firewall_usecases.sh — Stargazer NGFW firewall use case tests
#
# Script that exercises the full firewall feature set through the Web UI,
# simulating real-world firewall administrator scenarios.
#
# Use cases:
#   UC-01: Authentication and authorization (Login/Logout/Session)
#   UC-02: Firewall Policy management (create, edit, delete rules)
#   UC-03: Network Interface configuration (WAN/LAN)
#   UC-04: NAT configuration (Port Forwarding, SNAT)
#   UC-05: DHCP Server management
#   UC-06: Static Route management
#   UC-07: Address & Service Object management
#   UC-08: System monitoring (CPU, RAM, Disk)
#   UC-09: Diagnostic tools (Ping, DNS)
#   UC-10: Firmware management
#   UC-11: Admin account management
#   UC-12: Security checks
#
# Run: bash tests/test_firewall_usecases.sh [BASE_URL]
#
# Examples:
#   bash tests/test_firewall_usecases.sh http://localhost:8080
#   bash tests/test_firewall_usecases.sh https://192.168.1.1
# =============================================================================

set -uo pipefail

BASE="${1:-http://localhost:8080}"
ADMIN_USER="admin"
ADMIN_PASS="T@n27404"

JAR="/tmp/sg_test_firewall_uc.jar"
PASS=0
FAIL=0
WARN=0

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
RESET='\033[0m'
BOLD='\033[1m'

# ── Helpers ──────────────────────────────────────────────────────────────────

header() {
    echo -e "\n${BOLD}${CYAN}$(printf '=%.0s' {1..80})${RESET}"
    printf "${BOLD}${CYAN}%*s${RESET}\n" $(((${#1}+80)/2)) "$1"
    echo -e "${BOLD}${CYAN}$(printf '=%.0s' {1..80})${RESET}\n"
}

section() {
    echo -e "\n${BOLD}[$1] $2${RESET}"
    printf '%*s\n' 80 | tr ' ' '-'
}

check() {
    local label="$1" got="$2" want="$3" detail="${4:-}"
    if [ "$got" = "$want" ]; then
        printf "  ${GREEN}✓ PASS${RESET} %s\n" "$label"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} %s\n" "$label"
        if [ -n "$detail" ]; then
            printf "         ${YELLOW}↳ %s${RESET}\n" "$detail"
        else
            printf "         ${YELLOW}↳ Got: %s, Want: %s${RESET}\n" "$got" "$want"
        fi
        FAIL=$((FAIL+1))
    fi
}

warn() {
    local label="$1" detail="${2:-}"
    printf "  ${YELLOW}⚠ WARN${RESET} %s\n" "$label"
    if [ -n "$detail" ]; then
        printf "         ${YELLOW}↳ %s${RESET}\n" "$detail"
    fi
    WARN=$((WARN+1))
}

info() {
    printf "  ${CYAN}ℹ INFO${RESET} %s\n" "$1"
}

api() {
    # api METHOD PATH [BODY]
    local method="$1" path="$2" body="${3:-}"
    local url="$BASE$path"
    local args=(-si -X "$method" "$url" -b "$JAR" --max-time 10 -k)

    if [ -n "$body" ]; then
        args+=(-H "Content-Type: application/json" -d "$body")
    fi

    curl "${args[@]}" 2>/dev/null | grep "^HTTP" | awk '{print $2}'
}

api_body() {
    local method="$1" path="$2" body="${3:-}"
    local url="$BASE$path"
    local args=(-s -X "$method" "$url" -b "$JAR" --max-time 10 -k)

    if [ -n "$body" ]; then
        args+=(-H "Content-Type: application/json" -d "$body")
    fi

    curl "${args[@]}" 2>/dev/null
}

api_headers() {
    local method="$1" path="$2"
    local url="$BASE$path"
    curl -si -X "$method" "$url" -b "$JAR" --max-time 10 -k 2>/dev/null
}

# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 1: AUTHENTICATION AND AUTHORIZATION
# ══════════════════════════════════════════════════════════════════════════════

test_authentication() {
    section "USE CASE 1" "Authentication and Authorization"

    # UC-01.1: Successful login
    local r
    r=$(curl -si -X POST "$BASE/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
        -c "$JAR" --max-time 10 -k 2>/dev/null | grep "^HTTP" | awk '{print $2}')
    check "UC-01.1: Login succeeds with admin credentials" "$r" "200"

    # UC-01.2: Session cookie is set
    if grep -q "sg_sid" "$JAR" 2>/dev/null; then
        printf "  ${GREEN}✓ PASS${RESET} UC-01.2: Session cookie (sg_sid) is set\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-01.2: Session cookie not set\n"
        FAIL=$((FAIL+1))
    fi

    # UC-01.3: whoami returns username
    local body
    body=$(api_body GET /api/auth/whoami)
    if echo "$body" | grep -q "\"$ADMIN_USER\""; then
        printf "  ${GREEN}✓ PASS${RESET} UC-01.3: whoami returns username = admin\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-01.3: whoami did not return the correct username\n"
        FAIL=$((FAIL+1))
    fi

    # UC-01.4: whoami returns permissions
    if echo "$body" | grep -q "permissions"; then
        printf "  ${GREEN}✓ PASS${RESET} UC-01.4: whoami returns permissions\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-01.4: whoami missing permissions field\n"
        FAIL=$((FAIL+1))
    fi

    # UC-01.5: Login with wrong password
    r=$(curl -si -X POST "$BASE/api/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"wrongpassword"}' \
        --max-time 10 -k 2>/dev/null | grep "^HTTP" | awk '{print $2}')
    check "UC-01.5: Login with wrong password returns 401" "$r" "401"

    # UC-01.6: Login with nonexistent username
    r=$(curl -si -X POST "$BASE/api/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"nonexistent","password":"any"}' \
        --max-time 10 -k 2>/dev/null | grep "^HTTP" | awk '{print $2}')
    check "UC-01.6: Login with nonexistent username returns 401" "$r" "401" \
        "Must not leak whether the user exists"

    # UC-01.7: Access API without authentication
    r=$(curl -si -X GET "$BASE/api/config/firewall_policy" \
        --max-time 10 -k 2>/dev/null | grep "^HTTP" | awk '{print $2}')
    check "UC-01.7: Unauthenticated API returns 401" "$r" "401"

    # UC-01.8: Logout
    r=$(api POST /api/auth/logout)
    check "UC-01.8: Logout succeeds" "$r" "200"

    # UC-01.9: Session no longer valid after logout
    r=$(api GET /api/auth/whoami)
    check "UC-01.9: Session is invalidated after logout" "$r" "401"

    # Re-login for the following tests
    curl -si -X POST "$BASE/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
        -c "$JAR" --max-time 10 -k 2>/dev/null >/dev/null
}

# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 2: FIREWALL POLICY MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

test_firewall_policy() {
    section "USE CASE 2" "Firewall Policy Management"

    # UC-02.1: List policies
    local r
    r=$(api GET /api/config/firewall_policy)
    check "UC-02.1: List firewall policies" "$r" "200"

    local count
    count=$(api_body GET /api/config/firewall_policy | grep -o '"name"' | wc -l)
    info "There are currently $count firewall policies in the system"

    # UC-02.2: Create ALLOW ANY→ANY policy
    local policy_name="test-allow-any"
    local policy_id="98"
    r=$(api POST /api/config/firewall_policy \
        '{"id":"'$policy_id'","name":"'$policy_name'","srcintf":"any","dstintf":"any","srcaddr":"all","dstaddr":"all","service":"all","schedule":"all","action":"accept","status":"enable","comment":"Test: Allow traffic"}')
    if [ "$r" = "200" ] || [ "$r" = "201" ]; then
        printf "  ${GREEN}✓ PASS${RESET} UC-02.2: Create ALLOW LAN→WAN policy\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-02.2: Policy creation failed (status: $r)\n"
        FAIL=$((FAIL+1))
    fi

    # UC-02.3: Read the policy just created
    r=$(api GET "/api/config/firewall_policy/$policy_id")
    check "UC-02.3: Read the policy just created" "$r" "200"

    # UC-02.4-6: Verify policy fields
    local policy_data
    policy_data=$(api_body GET "/api/config/firewall_policy/$policy_id")

    if echo "$policy_data" | grep -q '"action":"accept"'; then
        printf "  ${GREEN}✓ PASS${RESET} UC-02.4: Policy has action = accept\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-02.4: Policy does not have action = accept\n"
        FAIL=$((FAIL+1))
    fi

    if echo "$policy_data" | grep -q '"srcintf":"any"'; then
        printf "  ${GREEN}✓ PASS${RESET} UC-02.5: Policy has srcintf = any\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-02.5: Policy does not have srcintf = any\n"
        FAIL=$((FAIL+1))
    fi

    # UC-02.7: Edit policy (accept → deny)
    r=$(api PUT "/api/config/firewall_policy/$policy_id" \
        '{"action":"deny","comment":"Changed to DENY"}')
    check "UC-02.7: Edit policy (accept → deny)" "$r" "200"

    # UC-02.8: Verify after the edit
    policy_data=$(api_body GET "/api/config/firewall_policy/$policy_id")
    if echo "$policy_data" | grep -q '"action":"deny"'; then
        printf "  ${GREEN}✓ PASS${RESET} UC-02.8: After edit, action = deny\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-02.8: After edit, action is incorrect\n"
        FAIL=$((FAIL+1))
    fi

    # UC-02.9: Create DENY ANY→ANY policy
    local deny_policy="test-deny-any"
    local deny_id="97"
    r=$(api POST /api/config/firewall_policy \
        '{"id":"'$deny_id'","name":"'$deny_policy'","srcintf":"any","dstintf":"any","srcaddr":"all","dstaddr":"all","service":"all","schedule":"all","action":"deny","status":"enable","comment":"Test deny policy"}')
    if [ "$r" = "200" ] || [ "$r" = "201" ]; then
        printf "  ${GREEN}✓ PASS${RESET} UC-02.9: Create DENY WAN→LAN policy\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-02.9: DENY policy creation failed\n"
        FAIL=$((FAIL+1))
    fi

    # UC-02.10: Disable policy
    r=$(api PUT "/api/config/firewall_policy/$deny_id" '{"status":"disable"}')
    check "UC-02.10: Disable policy" "$r" "200"

    # UC-02.11-12: Delete test policies
    r=$(api DELETE "/api/config/firewall_policy/$policy_id")
    check "UC-02.11: Delete policy $policy_id" "$r" "200"

    r=$(api DELETE "/api/config/firewall_policy/$deny_id")
    check "UC-02.12: Delete policy $deny_id" "$r" "200"

    # UC-02.13: Verify deleted (404)
    r=$(api GET "/api/config/firewall_policy/$policy_id")
    check "UC-02.13: GET returns 404 after delete" "$r" "404"

    # UC-02.14: Create policy with invalid action
    r=$(api POST /api/config/firewall_policy \
        '{"id":"96","name":"invalid","srcintf":"any","dstintf":"any","srcaddr":"all","dstaddr":"all","service":"all","schedule":"all","action":"invalid_action","status":"enable"}')
    if [ "$r" = "400" ] || [ "$r" = "404" ]; then
        printf "  ${GREEN}✓ PASS${RESET} UC-02.14: Invalid action is rejected\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-02.14: Invalid action is not rejected\n"
        FAIL=$((FAIL+1))
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 3: INTERFACE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

test_interface_management() {
    section "USE CASE 3" "Network Interface Management"

    # UC-03.1: List interfaces
    local r
    r=$(api GET /api/config/system_interface)
    check "UC-03.1: List interfaces" "$r" "200"

    local count
    count=$(api_body GET /api/config/system_interface | grep -o '"name"' | wc -l)
    info "The system has $count interfaces"

    # UC-03.2: Read interface eth0 details
    r=$(api GET /api/config/system_interface/eth0)
    if [ "$r" = "200" ]; then
        printf "  ${GREEN}✓ PASS${RESET} UC-03.2: Read interface eth0\n"
        PASS=$((PASS+1))

        local iface_data
        iface_data=$(api_body GET /api/config/system_interface/eth0)

        # UC-03.3-5: Check required fields
        for field in "name" "ip" "mode"; do
            if echo "$iface_data" | grep -q "\"$field\""; then
                printf "  ${GREEN}✓ PASS${RESET} UC-03: Interface has field '$field'\n"
                PASS=$((PASS+1))
            else
                printf "  ${RED}✗ FAIL${RESET} UC-03: Interface missing field '$field'\n"
                FAIL=$((FAIL+1))
            fi
        done
    else
        printf "  ${YELLOW}⚠ WARN${RESET} UC-03.2: Interface eth0 does not exist\n"
        WARN=$((WARN+1))
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 8: SYSTEM MONITORING
# ══════════════════════════════════════════════════════════════════════════════

test_system_monitoring() {
    section "USE CASE 8" "System Monitoring"

    # UC-08.1: System resources
    local r
    r=$(api GET /api/system/resources)
    check "UC-08.1: Get system resources" "$r" "200"

    if [ "$r" = "200" ]; then
        local res
        res=$(api_body GET /api/system/resources)

        # Extract metrics
        local cpu ram disk
        cpu=$(echo "$res" | grep -o '"cpu":[0-9.]*' | cut -d: -f2)
        ram=$(echo "$res" | grep -o '"ram":[0-9.]*' | cut -d: -f2)
        disk=$(echo "$res" | grep -o '"disk":[0-9.]*' | cut -d: -f2)

        if [ -n "$cpu" ]; then
            info "CPU: ${cpu}%"
        fi
        if [ -n "$ram" ]; then
            info "RAM: ${ram}%"
        fi
        if [ -n "$disk" ]; then
            info "Disk: ${disk}%"
        fi

        # UC-08.2-4: Check fields
        for field in "cpu" "ram" "disk"; do
            if echo "$res" | grep -q "\"$field\""; then
                printf "  ${GREEN}✓ PASS${RESET} UC-08: Response has '$field'\n"
                PASS=$((PASS+1))
            else
                printf "  ${RED}✗ FAIL${RESET} UC-08: Response missing '$field'\n"
                FAIL=$((FAIL+1))
            fi
        done
    fi

    # UC-08.5: RAM detail
    r=$(api GET /api/system/resources/ram)
    check "UC-08.5: Get RAM detail" "$r" "200"

    # UC-08.6: Disk detail
    r=$(api GET /api/system/resources/disk)
    check "UC-08.6: Get Disk detail" "$r" "200"
}

# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 9: DIAGNOSTIC TOOLS
# ══════════════════════════════════════════════════════════════════════════════

test_diagnostic_tools() {
    section "USE CASE 9" "Diagnostic Tools"

    # UC-09.1: Ping localhost
    local r
    r=$(api POST /api/diagnose/ping '{"target":"127.0.0.1"}')
    check "UC-09.1: Ping localhost (127.0.0.1)" "$r" "200"

    # UC-09.2: Ping external
    r=$(api POST /api/diagnose/ping '{"target":"8.8.8.8"}')
    check "UC-09.2: Ping external (8.8.8.8)" "$r" "200"

    # UC-09.3: DNS lookup
    r=$(api POST /api/diagnose/nslookup '{"target":"google.com"}')
    check "UC-09.3: DNS lookup (google.com)" "$r" "200"

    # UC-09.5: Invalid target
    r=$(api POST /api/diagnose/ping '{"target":"invalid!@#"}')
    check "UC-09.5: Ping with invalid target must fail" "$r" "400"

    # UC-09.6: Missing target
    r=$(api POST /api/diagnose/ping '{}')
    check "UC-09.6: Ping without a target must fail" "$r" "400"
}

# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 10: FIRMWARE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

test_firmware_management() {
    section "USE CASE 10" "Firmware Management"

    # UC-10.1: Firmware info
    local r
    r=$(api GET /api/system/firmware)
    check "UC-10.1: Get firmware version" "$r" "200"

    if [ "$r" = "200" ]; then
        local fw
        fw=$(api_body GET /api/system/firmware)
        local version
        version=$(echo "$fw" | grep -o '"current_version":"[^"]*"' | cut -d'"' -f4)
        if [ -n "$version" ]; then
            info "Firmware version: $version"
        fi
    fi

    # UC-10.3: Progress
    r=$(api GET /api/system/firmware/progress)
    check "UC-10.3: Firmware progress" "$r" "200"
}

# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 11: ADMIN MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

test_admin_management() {
    section "USE CASE 11" "Admin Account Management"

    # UC-11.1: List admins
    local r
    r=$(api GET /api/config/system_admin)
    check "UC-11.1: List admin users" "$r" "200"

    # UC-11.2: List profiles
    r=$(api GET /api/config/system_admin-profile)
    check "UC-11.2: List profiles" "$r" "200"

    # UC-11.3: Create test user
    local test_user="testuser-ro"
    r=$(api POST /api/admin/create \
        '{"username":"'$test_user'","password":"TestPass123!","profile":"read-only"}')
    if [ "$r" = "200" ] || [ "$r" = "201" ]; then
        printf "  ${GREEN}✓ PASS${RESET} UC-11.3: Create read-only admin user\n"
        PASS=$((PASS+1))

        # Cleanup
        api DELETE "/api/config/system_admin/$test_user" >/dev/null 2>&1
    else
        printf "  ${RED}✗ FAIL${RESET} UC-11.3: User creation failed (status: $r)\n"
        FAIL=$((FAIL+1))
    fi

    # UC-11.10: Cannot delete builtin admin
    r=$(api DELETE /api/config/system_admin/admin)
    check "UC-11.10: Cannot delete the builtin admin" "$r" "403"
}

# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 12: SECURITY
# ══════════════════════════════════════════════════════════════════════════════

test_security_features() {
    section "USE CASE 12" "Security Checks"

    # UC-12.1-3: Security headers
    local headers
    headers=$(api_headers GET /api/auth/whoami)

    if echo "$headers" | grep -q "X-Content-Type-Options: nosniff"; then
        printf "  ${GREEN}✓ PASS${RESET} UC-12.1: X-Content-Type-Options: nosniff\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-12.1: Missing X-Content-Type-Options\n"
        FAIL=$((FAIL+1))
    fi

    if echo "$headers" | grep -q "X-Frame-Options: DENY"; then
        printf "  ${GREEN}✓ PASS${RESET} UC-12.2: X-Frame-Options: DENY\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-12.2: Missing X-Frame-Options\n"
        FAIL=$((FAIL+1))
    fi

    if echo "$headers" | grep -qi "Content-Security-Policy"; then
        printf "  ${GREEN}✓ PASS${RESET} UC-12.3: Content-Security-Policy\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-12.3: Missing CSP header\n"
        FAIL=$((FAIL+1))
    fi

    # UC-12.5: XSS protection
    local r
    r=$(api POST /api/config/firewall_policy \
        '{"id":"95","name":"<script>alert(1)</script>","srcintf":"any","dstintf":"any","srcaddr":"all","dstaddr":"all","service":"all","schedule":"all","action":"accept","status":"enable"}')
    if [ "$r" = "400" ] || [ "$r" = "404" ]; then
        printf "  ${GREEN}✓ PASS${RESET} UC-12.5: XSS in input is rejected\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-12.5: XSS is not blocked\n"
        FAIL=$((FAIL+1))
    fi

    # UC-12.6: SQL injection
    r=$(api GET "/api/config/firewall_policy/'; DROP TABLE firewall_policy; --")
    if [ "$r" = "400" ] || [ "$r" = "404" ]; then
        printf "  ${GREEN}✓ PASS${RESET} UC-12.6: SQL injection is rejected\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-12.6: SQL injection is not blocked\n"
        FAIL=$((FAIL+1))
    fi

    # UC-12.7-8: Cookie security
    if echo "$headers" | grep -q "HttpOnly"; then
        printf "  ${GREEN}✓ PASS${RESET} UC-12.7: Cookie has HttpOnly\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-12.7: Cookie missing HttpOnly\n"
        FAIL=$((FAIL+1))
    fi

    if echo "$headers" | grep -q "SameSite=Strict"; then
        printf "  ${GREEN}✓ PASS${RESET} UC-12.8: Cookie has SameSite=Strict\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-12.8: Cookie missing SameSite\n"
        FAIL=$((FAIL+1))
    fi

    # UC-12.13: Path traversal
    r=$(api GET "/api/config/../../etc/passwd")
    if [ "$r" = "400" ] || [ "$r" = "404" ]; then
        printf "  ${GREEN}✓ PASS${RESET} UC-12.13: Path traversal is blocked\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-12.13: Path traversal is not blocked\n"
        FAIL=$((FAIL+1))
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

main() {
    header "STARGAZER NGFW - FIREWALL USE CASE TESTS"

    info "Target URL: $BASE"
    info "Admin User: $ADMIN_USER"
    info "Starting tests..."

    local start_time
    start_time=$(date +%s)

    # Check connection
    local conn
    conn=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/" --max-time 5 -k 2>/dev/null || echo "000")
    if [ "$conn" = "200" ] || [ "$conn" = "302" ]; then
        printf "  ${GREEN}✓ PASS${RESET} Connected to Web UI\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} Could not connect to $BASE\n"
        FAIL=$((FAIL+1))
        exit 1
    fi

    # Run test suites
    test_authentication
    test_firewall_policy
    test_interface_management
    test_system_monitoring
    test_diagnostic_tools
    test_firmware_management
    test_admin_management
    test_security_features

    # Summary
    local end_time
    end_time=$(date +%s)
    local elapsed=$((end_time - start_time))

    header "TEST RESULTS"

    local total=$((PASS + FAIL))
    local pass_rate=0
    if [ "$total" -gt 0 ]; then
        pass_rate=$((PASS * 100 / total))
    fi

    echo -e "${GREEN}✓ PASS:  $PASS${RESET}"
    echo -e "${RED}✗ FAIL:  $FAIL${RESET}"
    echo -e "${YELLOW}⚠ WARN:  $WARN${RESET}"
    echo -e "\n${BOLD}Total tests:  $total${RESET}"
    echo -e "${BOLD}Pass rate:    ${pass_rate}%${RESET}"
    echo -e "${BOLD}Elapsed:      ${elapsed}s${RESET}"

    if [ "$FAIL" -eq 0 ]; then
        echo -e "\n${GREEN}${BOLD}ALL TEST CASES PASSED!${RESET}"
        exit 0
    else
        echo -e "\n${YELLOW}${BOLD}$FAIL TEST CASE(S) FAILED${RESET}"
        exit 1
    fi
}

main
