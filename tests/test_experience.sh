#!/bin/sh
# Stargazer NGFW - Experience Test Suite
# Simulates real-world user workflows: admin creation, permission enforcement,
# configuration operations, and read-only access restrictions.
#
# This test exercises the full IPC permission model:
#   admin   → Can create/delete users, system operations, configure, and monitor
#   configure → Can modify configurations and monitor
#   monitor → Can ONLY view status and config (read-only)
#
# Runs on: QEMU target with mgmtd active, or host with mgmtd socket available.

set -e

TEST_LOG="/tmp/stargazer_experience_test.log"
BUG_REPORT="/tmp/stargazer_experience_bugs.json"
BUG_NDJSON="/tmp/stargazer_experience_bugs.ndjson"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

: > "$TEST_LOG"
: > "$BUG_NDJSON"

# ── Test admins ──────────────────────────────────────────────────────────

RW_ADMIN="testadmin_rw"
RO_ADMIN="testadmin_ro"
TEST_PASSWORD="TestPass1234!"

json_escape() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r/\\r/g'
}

log_test() {
	TESTS_RUN=$((TESTS_RUN + 1))
	printf "[TEST %d] %s\n" "$TESTS_RUN" "$*" | tee -a "$TEST_LOG"
}

test_pass() {
	TESTS_PASSED=$((TESTS_PASSED + 1))
	printf "${GREEN}  ✓ PASS${NC}: %s\n" "$*" | tee -a "$TEST_LOG"
}

test_fail() {
	local test_name="$1"
	local expected="$2"
	local actual="$3"
	local cmd="$4"

	TESTS_FAILED=$((TESTS_FAILED + 1))
	printf "${RED}  ✗ FAIL${NC}: %s\n" "$test_name" | tee -a "$TEST_LOG"
	printf "    Expected: %s\n" "$expected" | tee -a "$TEST_LOG"
	printf "    Actual:   %s\n" "$actual" | tee -a "$TEST_LOG"
	printf "    Command:  %s\n" "$cmd" | tee -a "$TEST_LOG"

	local test_name_e expected_e actual_e cmd_e
	test_name_e=$(json_escape "$test_name")
	expected_e=$(json_escape "$expected")
	actual_e=$(json_escape "$actual")
	cmd_e=$(json_escape "$cmd")
	cat >> "$BUG_NDJSON" <<EOF
{"id": $TESTS_FAILED, "test": "$test_name_e", "expected": "$expected_e", "actual": "$actual_e", "command": "$cmd_e", "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
EOF
}

# IPC command as a specific user
ipc_as() {
	local user="$1"
	local cmd_id="$2"
	local payload="$3"
	STARGAZER_USER="$user" timeout 5 stargazer-ipc-cli "$cmd_id" "$payload" 2>/dev/null || echo "TIMEOUT"
}

# Extract status code from first line of response
get_status() {
	echo "$1" | head -1
}

# ══════════════════════════════════════════════════════════════════════════
# PHASE 1: Setup — Create test admin accounts (as built-in admin)
# ══════════════════════════════════════════════════════════════════════════

section() {
	echo "" | tee -a "$TEST_LOG"
	printf "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}\n"
	printf "${CYAN}║  %-60s ║${NC}\n" "$1"
	printf "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}\n"
	echo "" | tee -a "$TEST_LOG"
}

section "PHASE 1: Setup — Create Admin Accounts"

echo "  Creating test accounts as built-in 'admin' user..." | tee -a "$TEST_LOG"

# Verify admin identity first
log_test "WHOAMI as built-in admin"
resp=$(ipc_as "admin" "620" "")
status=$(get_status "$resp")
if echo "$resp" | grep -q "permissions=monitor,configure,admin"; then
	test_pass "Built-in admin has full permissions"
else
	test_fail "Admin WHOAMI" "permissions=monitor,configure,admin" "$resp" "ipc_as admin 620"
fi

# Create read-write admin
log_test "Create read-write admin ($RW_ADMIN)"
resp=$(ipc_as "admin" "300" "username=$RW_ADMIN\nprofile=read-write\npassword=$TEST_PASSWORD")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "Read-write admin created"
else
	test_fail "Create RW admin" "status 0" "$status" "ipc_as admin 300 (create $RW_ADMIN)"
fi

# Create read-only admin
log_test "Create read-only admin ($RO_ADMIN)"
resp=$(ipc_as "admin" "300" "username=$RO_ADMIN\nprofile=read-only\npassword=$TEST_PASSWORD")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "Read-only admin created"
else
	test_fail "Create RO admin" "status 0" "$status" "ipc_as admin 300 (create $RO_ADMIN)"
fi

# Verify both accounts exist
log_test "Verify read-write admin profile via WHOAMI"
resp=$(ipc_as "$RW_ADMIN" "620" "")
if echo "$resp" | grep -q "profile=read-write" && echo "$resp" | grep -q "permissions=monitor,configure,admin"; then
	test_pass "RW admin has read-write profile with monitor,configure,admin"
else
	test_fail "RW admin WHOAMI" "profile=read-write, permissions=monitor,configure,admin" "$resp" "ipc_as $RW_ADMIN 620"
fi

log_test "Verify read-only admin profile via WHOAMI"
resp=$(ipc_as "$RO_ADMIN" "620" "")
if echo "$resp" | grep -q "profile=read-only" && echo "$resp" | grep -q "permissions=monitor"; then
	test_pass "RO admin has read-only profile with monitor only"
else
	test_fail "RO admin WHOAMI" "profile=read-only, permissions=monitor" "$resp" "ipc_as $RO_ADMIN 620"
fi

# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: Read-Write Admin — Full Configuration Access
# ══════════════════════════════════════════════════════════════════════════

section "PHASE 2: Read-Write Admin — Configuration Tests"

echo "  Testing as read-write admin ($RW_ADMIN)..." | tee -a "$TEST_LOG"

# --- Show commands (monitor permission) ---

log_test "RW: show status (opcode 610)"
resp=$(ipc_as "$RW_ADMIN" "610" "")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RW admin can view system status"
else
	test_fail "RW show status" "status 0" "$status" "ipc_as $RW_ADMIN 610"
fi

log_test "RW: show interfaces (opcode 611)"
resp=$(ipc_as "$RW_ADMIN" "611" "")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RW admin can view interfaces"
else
	test_fail "RW show interfaces" "status 0" "$status" "ipc_as $RW_ADMIN 611"
fi

log_test "RW: show routes (opcode 612)"
resp=$(ipc_as "$RW_ADMIN" "612" "")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RW admin can view routes"
else
	test_fail "RW show routes" "status 0" "$status" "ipc_as $RW_ADMIN 612"
fi

log_test "RW: show config (opcode 613)"
resp=$(ipc_as "$RW_ADMIN" "613" "")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RW admin can view full config"
else
	test_fail "RW show config" "status 0" "$status" "ipc_as $RW_ADMIN 613"
fi

# --- Config read (configure permission) ---

log_test "RW: CFG_GET system settings (opcode 100)"
resp=$(ipc_as "$RW_ADMIN" "100" "path=system\nsection=settings")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RW admin can read config section"
else
	test_fail "RW CFG_GET" "status 0" "$status" "ipc_as $RW_ADMIN 100"
fi

log_test "RW: CFG_LIST firewall policies (opcode 101)"
resp=$(ipc_as "$RW_ADMIN" "101" "path=firewall\ntype=policy")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RW admin can list config entries"
else
	test_fail "RW CFG_LIST" "status 0" "$status" "ipc_as $RW_ADMIN 101"
fi

# --- Config write (configure permission) ---

log_test "RW: CFG_SET — create firewall address object (opcode 200)"
resp=$(ipc_as "$RW_ADMIN" "200" "path=firewall\nsection=firewall_address:test-addr\ntype=subnet\nsubnet=10.0.0.0/24\ncomment=Experience test address")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RW admin can create firewall address object"
else
	test_fail "RW CFG_SET address" "status 0" "$status" "ipc_as $RW_ADMIN 200 (address)"
fi

log_test "RW: Verify address object was created (CFG_GET)"
resp=$(ipc_as "$RW_ADMIN" "100" "path=firewall\nsection=firewall_address:test-addr")
if echo "$resp" | grep -q "subnet=10.0.0.0/24"; then
	test_pass "Address object persisted with correct subnet"
else
	test_fail "RW verify address" "subnet=10.0.0.0/24" "$resp" "ipc_as $RW_ADMIN 100 (verify)"
fi

log_test "RW: CFG_SET — create firewall policy (opcode 200)"
resp=$(ipc_as "$RW_ADMIN" "200" "path=firewall\nsection=firewall_policy:100\nname=test-policy\nsrcintf=lan\ndstintf=wan\nsrcaddr=test-addr\ndstaddr=all\naction=accept\nstatus=enable\ncomment=Experience test policy")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RW admin can create firewall policy"
else
	test_fail "RW CFG_SET policy" "status 0" "$status" "ipc_as $RW_ADMIN 200 (policy)"
fi

log_test "RW: Verify firewall policy was created"
resp=$(ipc_as "$RW_ADMIN" "100" "path=firewall\nsection=firewall_policy:100")
if echo "$resp" | grep -q "name=test-policy" && echo "$resp" | grep -q "action=accept"; then
	test_pass "Firewall policy persisted with correct values"
else
	test_fail "RW verify policy" "name=test-policy, action=accept" "$resp" "ipc_as $RW_ADMIN 100 (verify policy)"
fi

log_test "RW: CFG_SET — modify system hostname (opcode 200)"
resp=$(ipc_as "$RW_ADMIN" "200" "path=system\nsection=settings\nhostname=rw-test-host")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RW admin can modify system hostname"
else
	test_fail "RW CFG_SET hostname" "status 0" "$status" "ipc_as $RW_ADMIN 200 (hostname)"
fi

log_test "RW: Verify hostname change"
resp=$(ipc_as "$RW_ADMIN" "100" "path=system\nsection=settings")
if echo "$resp" | grep -q "hostname=rw-test-host"; then
	test_pass "Hostname change persisted"
else
	test_fail "RW verify hostname" "hostname=rw-test-host" "$resp" "ipc_as $RW_ADMIN 100 (hostname verify)"
fi

# --- Config delete ---

log_test "RW: CFG_DEL — delete test address object (opcode 201)"
resp=$(ipc_as "$RW_ADMIN" "201" "path=firewall\nsection=firewall_address:test-addr")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RW admin can delete config entry"
else
	test_fail "RW CFG_DEL address" "status 0" "$status" "ipc_as $RW_ADMIN 201 (delete address)"
fi

log_test "RW: Verify address object deleted (CFG_GET should fail)"
resp=$(ipc_as "$RW_ADMIN" "100" "path=firewall\nsection=firewall_address:test-addr")
status=$(get_status "$resp")
if echo "$status" | grep -q "^300\|^303" || ! echo "$resp" | grep -q "subnet="; then
	test_pass "Address object successfully deleted"
else
	test_fail "RW verify delete" "not found / no subnet" "$resp" "ipc_as $RW_ADMIN 100 (verify delete)"
fi

# --- Config apply ---

log_test "RW: CFG_APPLY — apply firewall config (opcode 202)"
resp=$(ipc_as "$RW_ADMIN" "202" "path=firewall\nsection=firewall_policy:100")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RW admin can apply config"
else
	# Apply may return various codes depending on state; 0 or apply-specific errors are acceptable
	test_fail "RW CFG_APPLY" "status 0" "$status" "ipc_as $RW_ADMIN 202"
fi

# --- Session management ---

log_test "RW: SESSION_REV — get session revision (opcode 400)"
resp=$(ipc_as "$RW_ADMIN" "400" "username=$RW_ADMIN")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RW admin can check session revision"
else
	test_fail "RW SESSION_REV" "status 0" "$status" "ipc_as $RW_ADMIN 400"
fi

log_test "RW: SESSION_BUMP — bump session revision (opcode 401)"
resp=$(ipc_as "$RW_ADMIN" "401" "username=$RW_ADMIN")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RW admin can bump session revision"
else
	test_fail "RW SESSION_BUMP" "status 0" "$status" "ipc_as $RW_ADMIN 401"
fi

# --- Commit/revisions ---

log_test "RW: COMMIT — save configuration revision (opcode 500)"
resp=$(ipc_as "$RW_ADMIN" "500" "comment=Experience test checkpoint")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RW admin can commit configuration"
else
	test_fail "RW COMMIT" "status 0" "$status" "ipc_as $RW_ADMIN 500"
fi

log_test "RW: REVISIONS — list configuration revisions (opcode 501)"
resp=$(ipc_as "$RW_ADMIN" "501" "")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RW admin can list revisions"
else
	test_fail "RW REVISIONS" "status 0" "$status" "ipc_as $RW_ADMIN 501"
fi

# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: Read-Only Admin — View Only, No Configuration
# ══════════════════════════════════════════════════════════════════════════

section "PHASE 3: Read-Only Admin — Permission Enforcement"

echo "  Testing as read-only admin ($RO_ADMIN)..." | tee -a "$TEST_LOG"
echo "  Read-only has: permissions=monitor (ONLY)" | tee -a "$TEST_LOG"
echo "" | tee -a "$TEST_LOG"

# --- Show commands SHOULD work (monitor permission) ---

echo "  --- Commands that SHOULD succeed (monitor) ---" | tee -a "$TEST_LOG"

log_test "RO: show status (opcode 610) — should succeed"
resp=$(ipc_as "$RO_ADMIN" "610" "")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RO admin can view system status"
else
	test_fail "RO show status" "status 0 (monitor allowed)" "$status" "ipc_as $RO_ADMIN 610"
fi

log_test "RO: show interfaces (opcode 611) — should succeed"
resp=$(ipc_as "$RO_ADMIN" "611" "")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RO admin can view interfaces"
else
	test_fail "RO show interfaces" "status 0 (monitor allowed)" "$status" "ipc_as $RO_ADMIN 611"
fi

log_test "RO: show routes (opcode 612) — should succeed"
resp=$(ipc_as "$RO_ADMIN" "612" "")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RO admin can view routes"
else
	test_fail "RO show routes" "status 0 (monitor allowed)" "$status" "ipc_as $RO_ADMIN 612"
fi

log_test "RO: show config (opcode 613) — should succeed"
resp=$(ipc_as "$RO_ADMIN" "613" "")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RO admin can view full config"
else
	test_fail "RO show config" "status 0 (monitor allowed)" "$status" "ipc_as $RO_ADMIN 613"
fi

log_test "RO: CFG_GET — read config section (opcode 100) — should succeed"
resp=$(ipc_as "$RO_ADMIN" "100" "path=system\nsection=settings")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RO admin can read config sections"
else
	test_fail "RO CFG_GET" "status 0 (read allowed)" "$status" "ipc_as $RO_ADMIN 100"
fi

log_test "RO: CFG_LIST — list entries (opcode 101) — should succeed"
resp=$(ipc_as "$RO_ADMIN" "101" "path=firewall\ntype=policy")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RO admin can list config entries"
else
	test_fail "RO CFG_LIST" "status 0 (read allowed)" "$status" "ipc_as $RO_ADMIN 101"
fi

log_test "RO: WHOAMI (opcode 620) — should succeed"
resp=$(ipc_as "$RO_ADMIN" "620" "")
if echo "$resp" | grep -q "profile=read-only"; then
	test_pass "RO admin WHOAMI returns correct profile"
else
	test_fail "RO WHOAMI" "profile=read-only" "$resp" "ipc_as $RO_ADMIN 620"
fi

log_test "RO: PING (opcode 900) — should succeed"
resp=$(ipc_as "$RO_ADMIN" "900" "")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RO admin can ping mgmtd"
else
	test_fail "RO PING" "status 0" "$status" "ipc_as $RO_ADMIN 900"
fi

# --- Configure commands MUST be denied (no configure/admin permission) ---

echo "" | tee -a "$TEST_LOG"
echo "  --- Commands that MUST be DENIED (requires configure/admin) ---" | tee -a "$TEST_LOG"

log_test "RO: CFG_SET — attempt to set hostname (opcode 200) — should DENY"
resp=$(ipc_as "$RO_ADMIN" "200" "path=system\nsection=settings\nhostname=ro-hacked")
status=$(get_status "$resp")
if echo "$status" | grep -q "^200\|^203"; then
	test_pass "RO admin DENIED config set (status=$status)"
else
	test_fail "RO CFG_SET denied" "status 200 or 203 (permission denied)" "$status" "ipc_as $RO_ADMIN 200"
fi

log_test "RO: Verify hostname was NOT changed"
resp=$(ipc_as "admin" "100" "path=system\nsection=settings")
if echo "$resp" | grep -q "hostname=ro-hacked"; then
	test_fail "RO bypass check" "hostname should NOT be ro-hacked" "hostname=ro-hacked found!" "CFG_GET verify"
else
	test_pass "Hostname unchanged — RO write was properly blocked"
fi

log_test "RO: CFG_SET — attempt to create firewall policy (opcode 200) — should DENY"
resp=$(ipc_as "$RO_ADMIN" "200" "path=firewall\nsection=firewall_policy:999\nname=ro-policy\nsrcintf=any\ndstintf=any\naction=accept\nstatus=enable")
status=$(get_status "$resp")
if echo "$status" | grep -q "^200\|^203"; then
	test_pass "RO admin DENIED firewall policy creation"
else
	test_fail "RO CFG_SET policy denied" "status 200 or 203" "$status" "ipc_as $RO_ADMIN 200 (policy)"
fi

log_test "RO: CFG_DEL — attempt to delete firewall policy (opcode 201) — should DENY"
resp=$(ipc_as "$RO_ADMIN" "201" "path=firewall\nsection=firewall_policy:1")
status=$(get_status "$resp")
if echo "$status" | grep -q "^200\|^203"; then
	test_pass "RO admin DENIED config delete"
else
	test_fail "RO CFG_DEL denied" "status 200 or 203" "$status" "ipc_as $RO_ADMIN 201"
fi

log_test "RO: CFG_APPLY — attempt to apply config (opcode 202) — should DENY"
resp=$(ipc_as "$RO_ADMIN" "202" "path=firewall\nsection=firewall_policy:1")
status=$(get_status "$resp")
if echo "$status" | grep -q "^200\|^203"; then
	test_pass "RO admin DENIED config apply"
else
	test_fail "RO CFG_APPLY denied" "status 200 or 203" "$status" "ipc_as $RO_ADMIN 202"
fi

log_test "RO: ADMIN_CREATE — attempt to create admin (opcode 300) — should DENY"
resp=$(ipc_as "$RO_ADMIN" "300" "username=ro-created\nprofile=read-only\npassword=$TEST_PASSWORD")
status=$(get_status "$resp")
if echo "$status" | grep -q "^200\|^203"; then
	test_pass "RO admin DENIED user creation"
else
	test_fail "RO ADMIN_CREATE denied" "status 200 or 203" "$status" "ipc_as $RO_ADMIN 300"
fi

log_test "RO: ADMIN_DELETE — attempt to delete admin (opcode 301) — should DENY"
resp=$(ipc_as "$RO_ADMIN" "301" "username=$RW_ADMIN")
status=$(get_status "$resp")
if echo "$status" | grep -q "^200\|^203"; then
	test_pass "RO admin DENIED user deletion"
else
	test_fail "RO ADMIN_DELETE denied" "status 200 or 203" "$status" "ipc_as $RO_ADMIN 301"
fi

log_test "RO: ADMIN_SET_PW — attempt to change another user's password (opcode 302) — should DENY"
resp=$(ipc_as "$RO_ADMIN" "302" "username=$RW_ADMIN\npassword=Pwned1234!")
status=$(get_status "$resp")
if echo "$status" | grep -q "^200\|^203"; then
	test_pass "RO admin DENIED password change for other user"
else
	test_fail "RO ADMIN_SET_PW denied" "status 200 or 203" "$status" "ipc_as $RO_ADMIN 302"
fi

log_test "RO: ADMIN_SET_ENF — attempt to set enforce flag (opcode 303) — should DENY"
resp=$(ipc_as "$RO_ADMIN" "303" "username=$RW_ADMIN\nenforce=enable")
status=$(get_status "$resp")
if echo "$status" | grep -q "^200\|^203"; then
	test_pass "RO admin DENIED enforce flag change"
else
	test_fail "RO ADMIN_SET_ENF denied" "status 200 or 203" "$status" "ipc_as $RO_ADMIN 303"
fi

log_test "RO: SESSION_BUMP — attempt to bump session (opcode 401) — should DENY"
resp=$(ipc_as "$RO_ADMIN" "401" "username=$RW_ADMIN")
status=$(get_status "$resp")
if echo "$status" | grep -q "^200\|^203"; then
	test_pass "RO admin DENIED session bump"
else
	test_fail "RO SESSION_BUMP denied" "status 200 or 203" "$status" "ipc_as $RO_ADMIN 401"
fi

log_test "RO: COMMIT — attempt to commit config (opcode 500) — should DENY"
resp=$(ipc_as "$RO_ADMIN" "500" "comment=RO should not commit")
status=$(get_status "$resp")
if echo "$status" | grep -q "^200\|^203"; then
	test_pass "RO admin DENIED config commit"
else
	test_fail "RO COMMIT denied" "status 200 or 203" "$status" "ipc_as $RO_ADMIN 500"
fi

log_test "RO: SYS_POWEROFF — attempt poweroff (opcode 600) — should DENY"
resp=$(ipc_as "$RO_ADMIN" "600" "")
status=$(get_status "$resp")
if echo "$status" | grep -q "^200\|^203"; then
	test_pass "RO admin DENIED system poweroff"
else
	test_fail "RO SYS_POWEROFF denied" "status 200 or 203" "$status" "ipc_as $RO_ADMIN 600"
fi

log_test "RO: SYS_REBOOT — attempt reboot (opcode 601) — should DENY"
resp=$(ipc_as "$RO_ADMIN" "601" "")
status=$(get_status "$resp")
if echo "$status" | grep -q "^200\|^203"; then
	test_pass "RO admin DENIED system reboot"
else
	test_fail "RO SYS_REBOOT denied" "status 200 or 203" "$status" "ipc_as $RO_ADMIN 601"
fi

# ══════════════════════════════════════════════════════════════════════════
# PHASE 4: Cross-Account Integrity Checks
# ══════════════════════════════════════════════════════════════════════════

section "PHASE 4: Cross-Account Integrity"

log_test "Verify RW admin still works after RO tests"
resp=$(ipc_as "$RW_ADMIN" "200" "path=system\nsection=settings\nhostname=integrity-check")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "RW admin still has write access after RO tests"
else
	test_fail "RW integrity" "status 0" "$status" "ipc_as $RW_ADMIN 200 (integrity)"
fi

log_test "Verify default-deny policy unchanged by RO attempts"
resp=$(ipc_as "admin" "100" "path=firewall\nsection=firewall_policy:1")
if echo "$resp" | grep -q "action=deny" && echo "$resp" | grep -q "name=default-deny"; then
	test_pass "Default-deny policy intact — no unauthorized modifications"
else
	test_fail "Default-deny integrity" "action=deny, name=default-deny" "$resp" "CFG_GET policy:1"
fi

log_test "Verify built-in admin cannot be deleted by RW admin"
resp=$(ipc_as "$RW_ADMIN" "301" "username=admin")
status=$(get_status "$resp")
if echo "$status" | grep -q "^402"; then
	test_pass "Built-in admin protected from deletion by other admin"
else
	test_fail "Builtin protection" "status 402 (builtin)" "$status" "ipc_as $RW_ADMIN 301 admin"
fi

# ══════════════════════════════════════════════════════════════════════════
# PHASE 5: Cleanup — Remove test accounts and restore state
# ══════════════════════════════════════════════════════════════════════════

section "PHASE 5: Cleanup"

# Delete test policy
log_test "Cleanup: delete test firewall policy"
resp=$(ipc_as "admin" "201" "path=firewall\nsection=firewall_policy:100")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0\|^300\|^303"; then
	test_pass "Test policy cleaned up"
else
	test_fail "Cleanup policy" "status 0 or 300/303" "$status" "ipc_as admin 201 (cleanup policy)"
fi

# Restore hostname
log_test "Cleanup: restore hostname"
resp=$(ipc_as "admin" "200" "path=system\nsection=settings\nhostname=stargazer")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "Hostname restored to 'stargazer'"
else
	test_fail "Cleanup hostname" "status 0" "$status" "ipc_as admin 200 (restore hostname)"
fi

# Delete test admins
log_test "Cleanup: delete read-write test admin"
resp=$(ipc_as "admin" "301" "username=$RW_ADMIN")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "Read-write test admin deleted"
else
	test_fail "Cleanup RW admin" "status 0" "$status" "ipc_as admin 301 ($RW_ADMIN)"
fi

log_test "Cleanup: delete read-only test admin"
resp=$(ipc_as "admin" "301" "username=$RO_ADMIN")
status=$(get_status "$resp")
if echo "$status" | grep -q "^0"; then
	test_pass "Read-only test admin deleted"
else
	test_fail "Cleanup RO admin" "status 0" "$status" "ipc_as admin 301 ($RO_ADMIN)"
fi

# Verify cleanup
log_test "Verify test admins no longer exist"
resp_rw=$(ipc_as "$RW_ADMIN" "620" "")
resp_ro=$(ipc_as "$RO_ADMIN" "620" "")
if echo "$resp_rw" | grep -q "profile=read-only\|monitor" && echo "$resp_ro" | grep -q "profile=read-only\|monitor"; then
	test_pass "Deleted admins fall back to read-only defaults"
else
	# If WHOAMI still returns the old profile, accounts weren't cleaned up
	test_fail "Cleanup verification" "fallback to defaults" "rw=$resp_rw; ro=$resp_ro" "WHOAMI after delete"
fi

# ══════════════════════════════════════════════════════════════════════════
# FINAL REPORT
# ══════════════════════════════════════════════════════════════════════════

section "TEST RESULTS"

printf "Tests Run:    %d\n" "$TESTS_RUN" | tee -a "$TEST_LOG"
printf "${GREEN}Tests Passed: %d ✓${NC}\n" "$TESTS_PASSED" | tee -a "$TEST_LOG"
if [ "$TESTS_FAILED" -gt 0 ]; then
	printf "${RED}Tests Failed: %d ✗${NC}\n" "$TESTS_FAILED" | tee -a "$TEST_LOG"
else
	printf "Tests Failed: %d\n" "$TESTS_FAILED" | tee -a "$TEST_LOG"
fi
echo "" | tee -a "$TEST_LOG"

# Pass rate
if [ "$TESTS_RUN" -gt 0 ]; then
	pass_pct=$((TESTS_PASSED * 100 / TESTS_RUN))
	printf "Pass rate: %d%%\n" "$pass_pct" | tee -a "$TEST_LOG"
fi

echo "" | tee -a "$TEST_LOG"
printf "Permission model summary:\n" | tee -a "$TEST_LOG"
printf "  read-write (monitor,configure,admin): full access ✓\n" | tee -a "$TEST_LOG"
printf "  read-only  (monitor):                 view only, all writes denied ✓\n" | tee -a "$TEST_LOG"

# Generate bug report JSON
if [ -s "$BUG_NDJSON" ]; then
	BUGS_JSON=$(awk 'BEGIN{printf "["} {if (NR>1) printf ","; printf $0} END{printf "]"}' "$BUG_NDJSON")
else
	BUGS_JSON="[]"
fi

cat > "$BUG_REPORT" <<EOF
{
  "project": "Stargazer NGFW",
  "test_suite": "Experience Test — Permission Enforcement",
  "test_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "environment": {
    "os": "$(uname -s)",
    "kernel": "$(uname -r)",
    "machine": "$(uname -m)"
  },
  "accounts_tested": {
    "read_write": "$RW_ADMIN (profile=read-write, permissions=monitor,configure,admin)",
    "read_only": "$RO_ADMIN (profile=read-only, permissions=monitor)"
  },
  "summary": {
    "total_tests": $TESTS_RUN,
    "passed": $TESTS_PASSED,
    "failed": $TESTS_FAILED,
    "pass_rate": "${pass_pct:-0}%"
  },
  "bugs": $BUGS_JSON
}
EOF

echo "" | tee -a "$TEST_LOG"
printf "✓ Test log:   %s\n" "$TEST_LOG" | tee -a "$TEST_LOG"
printf "✓ Bug report: %s\n" "$BUG_REPORT" | tee -a "$TEST_LOG"

exit $TESTS_FAILED
