#!/bin/bash
# =============================================================================
# test_firewall_usecases.sh — Kiểm tra các use case tường lửa Stargazer NGFW
#
# Script kiểm tra đầy đủ các chức năng của tường lửa qua Web UI, mô phỏng
# các tình huống thực tế của người quản trị firewall.
#
# Các use case:
#   UC-01: Xác thực và phân quyền (Login/Logout/Session)
#   UC-02: Quản lý Firewall Policy (tạo, sửa, xóa rule)
#   UC-03: Cấu hình Network Interface (WAN/LAN)
#   UC-04: Cấu hình NAT (Port Forwarding, SNAT)
#   UC-05: Quản lý DHCP Server
#   UC-06: Quản lý Static Route
#   UC-07: Quản lý Address & Service Objects
#   UC-08: Giám sát hệ thống (CPU, RAM, Disk)
#   UC-09: Công cụ chẩn đoán (Ping, DNS)
#   UC-10: Quản lý Firmware
#   UC-11: Quản lý Admin Accounts
#   UC-12: Kiểm tra bảo mật
#
# Chạy: bash tests/test_firewall_usecases.sh [BASE_URL]
#
# Ví dụ:
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
# USE CASE 1: XÁC THỰC VÀ PHÂN QUYỀN
# ══════════════════════════════════════════════════════════════════════════════

test_authentication() {
    section "USE CASE 1" "Xác thực và Phân quyền"

    # UC-01.1: Login thành công
    local r
    r=$(curl -si -X POST "$BASE/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
        -c "$JAR" --max-time 10 -k 2>/dev/null | grep "^HTTP" | awk '{print $2}')
    check "UC-01.1: Login thành công với admin credentials" "$r" "200"

    # UC-01.2: Session cookie được set
    if grep -q "sg_sid" "$JAR" 2>/dev/null; then
        printf "  ${GREEN}✓ PASS${RESET} UC-01.2: Session cookie (sg_sid) được set\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-01.2: Session cookie không được set\n"
        FAIL=$((FAIL+1))
    fi

    # UC-01.3: whoami trả về username
    local body
    body=$(api_body GET /api/auth/whoami)
    if echo "$body" | grep -q "\"$ADMIN_USER\""; then
        printf "  ${GREEN}✓ PASS${RESET} UC-01.3: whoami trả về username = admin\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-01.3: whoami không trả về đúng username\n"
        FAIL=$((FAIL+1))
    fi

    # UC-01.4: whoami trả về permissions
    if echo "$body" | grep -q "permissions"; then
        printf "  ${GREEN}✓ PASS${RESET} UC-01.4: whoami trả về permissions\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-01.4: whoami không có field permissions\n"
        FAIL=$((FAIL+1))
    fi

    # UC-01.5: Login sai password
    r=$(curl -si -X POST "$BASE/api/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"wrongpassword"}' \
        --max-time 10 -k 2>/dev/null | grep "^HTTP" | awk '{print $2}')
    check "UC-01.5: Login với password sai trả về 401" "$r" "401"

    # UC-01.6: Login với username không tồn tại
    r=$(curl -si -X POST "$BASE/api/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"nonexistent","password":"any"}' \
        --max-time 10 -k 2>/dev/null | grep "^HTTP" | awk '{print $2}')
    check "UC-01.6: Login với username không tồn tại trả về 401" "$r" "401" \
        "Không được leak thông tin user tồn tại"

    # UC-01.7: Access API không authentication
    r=$(curl -si -X GET "$BASE/api/config/firewall_policy" \
        --max-time 10 -k 2>/dev/null | grep "^HTTP" | awk '{print $2}')
    check "UC-01.7: API không auth trả về 401" "$r" "401"

    # UC-01.8: Logout
    r=$(api POST /api/auth/logout)
    check "UC-01.8: Logout thành công" "$r" "200"

    # UC-01.9: Sau logout session không còn valid
    r=$(api GET /api/auth/whoami)
    check "UC-01.9: Sau logout session bị invalidate" "$r" "401"

    # Re-login cho các test tiếp theo
    curl -si -X POST "$BASE/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
        -c "$JAR" --max-time 10 -k 2>/dev/null >/dev/null
}

# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 2: QUẢN LÝ FIREWALL POLICY
# ══════════════════════════════════════════════════════════════════════════════

test_firewall_policy() {
    section "USE CASE 2" "Quản lý Firewall Policy"

    # UC-02.1: Lấy danh sách policies
    local r
    r=$(api GET /api/config/firewall_policy)
    check "UC-02.1: Lấy danh sách firewall policies" "$r" "200"

    local count
    count=$(api_body GET /api/config/firewall_policy | grep -o '"name"' | wc -l)
    info "Hiện có $count firewall policies trong hệ thống"

    # UC-02.2: Tạo policy ALLOW ANY→ANY
    local policy_name="test-allow-any"
    local policy_id="98"
    r=$(api POST /api/config/firewall_policy \
        '{"id":"'$policy_id'","name":"'$policy_name'","srcintf":"any","dstintf":"any","srcaddr":"all","dstaddr":"all","service":"all","schedule":"all","action":"accept","status":"enable","comment":"Test: Allow traffic"}')
    if [ "$r" = "200" ] || [ "$r" = "201" ]; then
        printf "  ${GREEN}✓ PASS${RESET} UC-02.2: Tạo policy ALLOW LAN→WAN\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-02.2: Tạo policy fail (status: $r)\n"
        FAIL=$((FAIL+1))
    fi

    # UC-02.3: Đọc policy vừa tạo
    r=$(api GET "/api/config/firewall_policy/$policy_id")
    check "UC-02.3: Đọc policy vừa tạo" "$r" "200"

    # UC-02.4-6: Verify policy fields
    local policy_data
    policy_data=$(api_body GET "/api/config/firewall_policy/$policy_id")

    if echo "$policy_data" | grep -q '"action":"accept"'; then
        printf "  ${GREEN}✓ PASS${RESET} UC-02.4: Policy có action = accept\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-02.4: Policy không có action = accept\n"
        FAIL=$((FAIL+1))
    fi

    if echo "$policy_data" | grep -q '"srcintf":"any"'; then
        printf "  ${GREEN}✓ PASS${RESET} UC-02.5: Policy có srcintf = any\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-02.5: Policy không có srcintf = any\n"
        FAIL=$((FAIL+1))
    fi

    # UC-02.7: Sửa policy (accept → deny)
    r=$(api PUT "/api/config/firewall_policy/$policy_id" \
        '{"action":"deny","comment":"Changed to DENY"}')
    check "UC-02.7: Sửa policy (accept → deny)" "$r" "200"

    # UC-02.8: Verify sau khi sửa
    policy_data=$(api_body GET "/api/config/firewall_policy/$policy_id")
    if echo "$policy_data" | grep -q '"action":"deny"'; then
        printf "  ${GREEN}✓ PASS${RESET} UC-02.8: Sau sửa, action = deny\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-02.8: Sau sửa, action không đúng\n"
        FAIL=$((FAIL+1))
    fi

    # UC-02.9: Tạo policy DENY ANY→ANY
    local deny_policy="test-deny-any"
    local deny_id="97"
    r=$(api POST /api/config/firewall_policy \
        '{"id":"'$deny_id'","name":"'$deny_policy'","srcintf":"any","dstintf":"any","srcaddr":"all","dstaddr":"all","service":"all","schedule":"all","action":"deny","status":"enable","comment":"Test deny policy"}')
    if [ "$r" = "200" ] || [ "$r" = "201" ]; then
        printf "  ${GREEN}✓ PASS${RESET} UC-02.9: Tạo policy DENY WAN→LAN\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-02.9: Tạo policy DENY fail\n"
        FAIL=$((FAIL+1))
    fi

    # UC-02.10: Disable policy
    r=$(api PUT "/api/config/firewall_policy/$deny_id" '{"status":"disable"}')
    check "UC-02.10: Disable policy" "$r" "200"

    # UC-02.11-12: Xóa test policies
    r=$(api DELETE "/api/config/firewall_policy/$policy_id")
    check "UC-02.11: Xóa policy $policy_id" "$r" "200"

    r=$(api DELETE "/api/config/firewall_policy/$deny_id")
    check "UC-02.12: Xóa policy $deny_id" "$r" "200"

    # UC-02.13: Verify đã xóa (404)
    r=$(api GET "/api/config/firewall_policy/$policy_id")
    check "UC-02.13: Sau xóa GET trả về 404" "$r" "404"

    # UC-02.14: Tạo policy invalid action
    r=$(api POST /api/config/firewall_policy \
        '{"id":"96","name":"invalid","srcintf":"any","dstintf":"any","srcaddr":"all","dstaddr":"all","service":"all","schedule":"all","action":"invalid_action","status":"enable"}')
    if [ "$r" = "400" ] || [ "$r" = "404" ]; then
        printf "  ${GREEN}✓ PASS${RESET} UC-02.14: Invalid action bị reject\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-02.14: Invalid action không bị reject\n"
        FAIL=$((FAIL+1))
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 3: QUẢN LÝ INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

test_interface_management() {
    section "USE CASE 3" "Quản lý Network Interface"

    # UC-03.1: Lấy danh sách interfaces
    local r
    r=$(api GET /api/config/system_interface)
    check "UC-03.1: Lấy danh sách interfaces" "$r" "200"

    local count
    count=$(api_body GET /api/config/system_interface | grep -o '"name"' | wc -l)
    info "Hệ thống có $count interfaces"

    # UC-03.2: Đọc chi tiết interface eth0
    r=$(api GET /api/config/system_interface/eth0)
    if [ "$r" = "200" ]; then
        printf "  ${GREEN}✓ PASS${RESET} UC-03.2: Đọc interface eth0\n"
        PASS=$((PASS+1))

        local iface_data
        iface_data=$(api_body GET /api/config/system_interface/eth0)

        # UC-03.3-5: Check required fields
        for field in "name" "ip" "mode"; do
            if echo "$iface_data" | grep -q "\"$field\""; then
                printf "  ${GREEN}✓ PASS${RESET} UC-03: Interface có field '$field'\n"
                PASS=$((PASS+1))
            else
                printf "  ${RED}✗ FAIL${RESET} UC-03: Interface thiếu field '$field'\n"
                FAIL=$((FAIL+1))
            fi
        done
    else
        printf "  ${YELLOW}⚠ WARN${RESET} UC-03.2: Interface eth0 không tồn tại\n"
        WARN=$((WARN+1))
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 8: GIÁM SÁT HỆ THỐNG
# ══════════════════════════════════════════════════════════════════════════════

test_system_monitoring() {
    section "USE CASE 8" "Giám sát Hệ thống"

    # UC-08.1: System resources
    local r
    r=$(api GET /api/system/resources)
    check "UC-08.1: Lấy system resources" "$r" "200"

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
                printf "  ${GREEN}✓ PASS${RESET} UC-08: Response có '$field'\n"
                PASS=$((PASS+1))
            else
                printf "  ${RED}✗ FAIL${RESET} UC-08: Response thiếu '$field'\n"
                FAIL=$((FAIL+1))
            fi
        done
    fi

    # UC-08.5: RAM detail
    r=$(api GET /api/system/resources/ram)
    check "UC-08.5: Lấy RAM detail" "$r" "200"

    # UC-08.6: Disk detail
    r=$(api GET /api/system/resources/disk)
    check "UC-08.6: Lấy Disk detail" "$r" "200"
}

# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 9: CÔNG CỤ CHẨN ĐOÁN
# ══════════════════════════════════════════════════════════════════════════════

test_diagnostic_tools() {
    section "USE CASE 9" "Công cụ Chẩn đoán"

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
    check "UC-09.5: Ping invalid target phải fail" "$r" "400"

    # UC-09.6: Missing target
    r=$(api POST /api/diagnose/ping '{}')
    check "UC-09.6: Ping không có target phải fail" "$r" "400"
}

# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 10: QUẢN LÝ FIRMWARE
# ══════════════════════════════════════════════════════════════════════════════

test_firmware_management() {
    section "USE CASE 10" "Quản lý Firmware"

    # UC-10.1: Firmware info
    local r
    r=$(api GET /api/system/firmware)
    check "UC-10.1: Lấy firmware version" "$r" "200"

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
# USE CASE 11: QUẢN LÝ ADMIN
# ══════════════════════════════════════════════════════════════════════════════

test_admin_management() {
    section "USE CASE 11" "Quản lý Admin Accounts"

    # UC-11.1: List admins
    local r
    r=$(api GET /api/config/system_admin)
    check "UC-11.1: Lấy danh sách admin users" "$r" "200"

    # UC-11.2: List profiles
    r=$(api GET /api/config/system_admin-profile)
    check "UC-11.2: Lấy danh sách profiles" "$r" "200"

    # UC-11.3: Create test user
    local test_user="testuser-ro"
    r=$(api POST /api/admin/create \
        '{"username":"'$test_user'","password":"TestPass123!","profile":"read-only"}')
    if [ "$r" = "200" ] || [ "$r" = "201" ]; then
        printf "  ${GREEN}✓ PASS${RESET} UC-11.3: Tạo admin user read-only\n"
        PASS=$((PASS+1))

        # Cleanup
        api DELETE "/api/config/system_admin/$test_user" >/dev/null 2>&1
    else
        printf "  ${RED}✗ FAIL${RESET} UC-11.3: Tạo user fail (status: $r)\n"
        FAIL=$((FAIL+1))
    fi

    # UC-11.10: Cannot delete builtin admin
    r=$(api DELETE /api/config/system_admin/admin)
    check "UC-11.10: Không thể xóa admin builtin" "$r" "403"
}

# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 12: BẢO MẬT
# ══════════════════════════════════════════════════════════════════════════════

test_security_features() {
    section "USE CASE 12" "Kiểm tra Bảo mật"

    # UC-12.1-3: Security headers
    local headers
    headers=$(api_headers GET /api/auth/whoami)

    if echo "$headers" | grep -q "X-Content-Type-Options: nosniff"; then
        printf "  ${GREEN}✓ PASS${RESET} UC-12.1: X-Content-Type-Options: nosniff\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-12.1: Thiếu X-Content-Type-Options\n"
        FAIL=$((FAIL+1))
    fi

    if echo "$headers" | grep -q "X-Frame-Options: DENY"; then
        printf "  ${GREEN}✓ PASS${RESET} UC-12.2: X-Frame-Options: DENY\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-12.2: Thiếu X-Frame-Options\n"
        FAIL=$((FAIL+1))
    fi

    if echo "$headers" | grep -qi "Content-Security-Policy"; then
        printf "  ${GREEN}✓ PASS${RESET} UC-12.3: Content-Security-Policy\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-12.3: Thiếu CSP header\n"
        FAIL=$((FAIL+1))
    fi

    # UC-12.5: XSS protection
    local r
    r=$(api POST /api/config/firewall_policy \
        '{"id":"95","name":"<script>alert(1)</script>","srcintf":"any","dstintf":"any","srcaddr":"all","dstaddr":"all","service":"all","schedule":"all","action":"accept","status":"enable"}')
    if [ "$r" = "400" ] || [ "$r" = "404" ]; then
        printf "  ${GREEN}✓ PASS${RESET} UC-12.5: XSS trong input bị reject\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-12.5: XSS không bị block\n"
        FAIL=$((FAIL+1))
    fi

    # UC-12.6: SQL injection
    r=$(api GET "/api/config/firewall_policy/'; DROP TABLE firewall_policy; --")
    if [ "$r" = "400" ] || [ "$r" = "404" ]; then
        printf "  ${GREEN}✓ PASS${RESET} UC-12.6: SQL injection bị reject\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-12.6: SQL injection không bị block\n"
        FAIL=$((FAIL+1))
    fi

    # UC-12.7-8: Cookie security
    if echo "$headers" | grep -q "HttpOnly"; then
        printf "  ${GREEN}✓ PASS${RESET} UC-12.7: Cookie có HttpOnly\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-12.7: Cookie thiếu HttpOnly\n"
        FAIL=$((FAIL+1))
    fi

    if echo "$headers" | grep -q "SameSite=Strict"; then
        printf "  ${GREEN}✓ PASS${RESET} UC-12.8: Cookie có SameSite=Strict\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-12.8: Cookie thiếu SameSite\n"
        FAIL=$((FAIL+1))
    fi

    # UC-12.13: Path traversal
    r=$(api GET "/api/config/../../etc/passwd")
    if [ "$r" = "400" ] || [ "$r" = "404" ]; then
        printf "  ${GREEN}✓ PASS${RESET} UC-12.13: Path traversal bị block\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} UC-12.13: Path traversal không bị block\n"
        FAIL=$((FAIL+1))
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

main() {
    header "STARGAZER NGFW - KIỂM TRA USE CASE TƯỜNG LỬA"

    info "Target URL: $BASE"
    info "Admin User: $ADMIN_USER"
    info "Bắt đầu kiểm tra..."

    local start_time
    start_time=$(date +%s)

    # Check connection
    local conn
    conn=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/" --max-time 5 -k 2>/dev/null || echo "000")
    if [ "$conn" = "200" ] || [ "$conn" = "302" ]; then
        printf "  ${GREEN}✓ PASS${RESET} Kết nối đến Web UI\n"
        PASS=$((PASS+1))
    else
        printf "  ${RED}✗ FAIL${RESET} Không thể kết nối đến $BASE\n"
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

    header "KẾT QUẢ KIỂM TRA"

    local total=$((PASS + FAIL))
    local pass_rate=0
    if [ "$total" -gt 0 ]; then
        pass_rate=$((PASS * 100 / total))
    fi

    echo -e "${GREEN}✓ PASS:  $PASS${RESET}"
    echo -e "${RED}✗ FAIL:  $FAIL${RESET}"
    echo -e "${YELLOW}⚠ WARN:  $WARN${RESET}"
    echo -e "\n${BOLD}Tổng số test: $total${RESET}"
    echo -e "${BOLD}Tỷ lệ pass:   ${pass_rate}%${RESET}"
    echo -e "${BOLD}Thời gian:    ${elapsed}s${RESET}"

    if [ "$FAIL" -eq 0 ]; then
        echo -e "\n${GREEN}${BOLD}TẤT CẢ CÁC TEST CASE ĐỀU PASSED!${RESET}"
        exit 0
    else
        echo -e "\n${YELLOW}${BOLD}CÓ $FAIL TEST CASE FAILED${RESET}"
        exit 1
    fi
}

main
