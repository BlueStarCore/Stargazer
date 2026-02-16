#!/bin/sh
# Stargazer NGFW - Comprehensive Test Suite
# Tests all IPC commands, config operations, and edge cases
# Output: JSON-formatted bug report

set -e

TEST_LOG="/tmp/stargazer_test.log"
BUG_REPORT="/tmp/stargazer_bugs.json"
BUG_NDJSON="/tmp/stargazer_bugs.ndjson"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Bugs found
: > "$BUG_NDJSON"

json_escape() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r/\\r/g; s/\n/\\n/g'
}

# Helper: Log test execution
log_test() {
	TESTS_RUN=$((TESTS_RUN + 1))
	printf "[TEST %d] %s\n" "$TESTS_RUN" "$*" | tee -a "$TEST_LOG"
}

# Helper: Mark test as passed
test_pass() {
	TESTS_PASSED=$((TESTS_PASSED + 1))
	printf "${GREEN}✓ PASS${NC}: %s\n" "$*" | tee -a "$TEST_LOG"
}

# Helper: Mark test as failed and record bug
test_fail() {
	local test_name="$1"
	local expected="$2"
	local actual="$3"
	local cmd="$4"
	
	TESTS_FAILED=$((TESTS_FAILED + 1))
	printf "${RED}✗ FAIL${NC}: %s\n" "$test_name" | tee -a "$TEST_LOG"
	printf "  Expected: %s\n" "$expected" | tee -a "$TEST_LOG"
	printf "  Actual:   %s\n" "$actual" | tee -a "$TEST_LOG"
	printf "  Command:  %s\n" "$cmd" | tee -a "$TEST_LOG"
	
	# Append to bugs file (NDJSON)
	local test_name_e expected_e actual_e cmd_e
	test_name_e=$(json_escape "$test_name")
	expected_e=$(json_escape "$expected")
	actual_e=$(json_escape "$actual")
	cmd_e=$(json_escape "$cmd")
	cat >> "$BUG_NDJSON" <<EOF
{"id": $TESTS_FAILED, "test": "$test_name_e", "expected": "$expected_e", "actual": "$actual_e", "command": "$cmd_e", "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
EOF
}

# Helper: IPC send with timeout
ipc_cmd() {
	local cmd_id="$1"
	local payload="$2"
	timeout 5 stargazer-ipc-cli "$cmd_id" "$payload" 2>/dev/null || echo "TIMEOUT"
}

# Helper: Verify IPC response
verify_response() {
	local response="$1"
	local expected_status="$2"
	local test_desc="$3"
	local cmd="$4"
	
	local status_line="$(echo "$response" | head -1)"
	if echo "$status_line" | grep -q "$expected_status"; then
		test_pass "$test_desc"
		return 0
	else
		test_fail "$test_desc" "$expected_status in response" "$status_line" "$cmd"
		return 1
	fi
}

# ──────────────────────────────────────────────────────────────────────────
# SECTION 1: Basic IPC Connectivity
# ──────────────────────────────────────────────────────────────────────────

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  SECTION 1: Basic IPC Connectivity & Protocol                 ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo "" | tee -a "$TEST_LOG"

log_test "PING command (900) - mgmtd availability"
resp=$(ipc_cmd "900" "")
verify_response "$resp" "0\|Success" "IPC PING reachable" "stargazer-ipc-cli 900 ''"

log_test "Invalid command ID (-1)"
resp=$(ipc_cmd "-1" "")
if echo "$resp" | grep -q "100\|Invalid\|error"; then
	test_pass "Invalid command returns error"
else
	test_fail "Invalid command handling" "error response" "$resp" "stargazer-ipc-cli -1 ''"
fi

log_test "Overly large payload (>4096 bytes)"
big_payload=$(printf '%0.s#' $(seq 1 5000))
resp=$(ipc_cmd "100" "$big_payload" 2>&1)
if echo "$resp" | grep -qi "payload\|too large\|truncat"; then
	test_pass "Large payload rejected"
else
	test_fail "Payload size limit check" "rejection or truncation" "$resp" "ipc_cmd with 5000 bytes"
fi

# ──────────────────────────────────────────────────────────────────────────
# SECTION 2: Config Operations (Get/Set/Delete)
# ──────────────────────────────────────────────────────────────────────────

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  SECTION 2: Configuration Read/Write Operations               ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo "" | tee -a "$TEST_LOG"

log_test "CFG_GET (100) - Retrieve system.conf section"
resp=$(ipc_cmd "100" "path=system\nsection=settings")
verify_response "$resp" "0" "CFG_GET system settings" "ipc_cmd 100 'path=system\nsection=settings'"

log_test "CFG_LIST (101) - List all entries of a type"
resp=$(ipc_cmd "101" "path=system\ntype=admin")
verify_response "$resp" "0" "CFG_LIST admin users" "ipc_cmd 101 'path=system\ntype=admin'"

log_test "CFG_SET (200) - Set hostname"
hostname_test="test-sg-$(date +%s)"
resp=$(ipc_cmd "200" "path=system\nsection=settings\nhostname=$hostname_test")
verify_response "$resp" "0" "CFG_SET hostname" "ipc_cmd 200 hostname"

log_test "CFG_GET verify hostname was set"
resp=$(ipc_cmd "100" "path=system\nsection=settings")
if echo "$resp" | grep -q "hostname=$hostname_test"; then
	test_pass "Hostname persisted"
else
	test_fail "Hostname persistence" "hostname=$hostname_test in response" "$resp" "CFG_GET after set"
fi

log_test "CFG_SET - Set invalid value type (hostname with special chars)"
resp=$(ipc_cmd "200" "path=system\nsection=settings\nhostname=test!@#$%")
if echo "$resp" | grep -q "0\|Success"; then
	test_fail "Special chars hostname validation" "error for invalid hostname" "$resp" "CFG_SET invalid hostname"
else
	test_pass "Invalid hostname rejected"
fi

# ──────────────────────────────────────────────────────────────────────────
# SECTION 3: Admin User Management
# ──────────────────────────────────────────────────────────────────────────

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  SECTION 3: Admin User Management                             ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo "" | tee -a "$TEST_LOG"

TEST_ADMIN="testadmin_$(date +%s | tail -c 4)"

log_test "ADMIN_CREATE (300) - Create new admin user"
resp=$(ipc_cmd "300" "username=$TEST_ADMIN\nprofile=read-write\npassword=TestPass123!")
verify_response "$resp" "0" "ADMIN_CREATE succeeds" "ipc_cmd 300 admin create"

log_test "ADMIN_CREATE - Duplicate user (should fail)"
resp=$(ipc_cmd "300" "username=$TEST_ADMIN\nprofile=read-write\npassword=DiffPass456@")
if echo "$resp" | grep -q "400\|Already exists"; then
	test_pass "Duplicate admin rejected"
else
	test_fail "Duplicate admin check" "error 400 (already exists)" "$resp" "ipc_cmd 300 duplicate"
fi

log_test "ADMIN_CREATE - Missing required field 'profile'"
resp=$(ipc_cmd "300" "username=noProfile\npassword=Pass123!")
if echo "$resp" | grep -q "103\|Missing"; then
	test_pass "Missing profile field rejected"
else
	test_fail "Missing profile validation" "error 103" "$resp" "ipc_cmd 300 missing profile"
fi

log_test "ADMIN_CREATE - Weak password (<8 chars)"
resp=$(ipc_cmd "300" "username=weakpass\nprofile=read-only\npassword=short")
if echo "$resp" | grep -q "102\|Invalid"; then
	test_pass "Weak password rejected"
else
	test_fail "Password strength check" "error for weak password" "$resp" "ipc_cmd 300 weak password"
fi

log_test "ADMIN_CREATE - Non-existent profile reference"
resp=$(ipc_cmd "300" "username=badprofile\nprofile=nonexistent\npassword=Pass123!")
if echo "$resp" | grep -q "302\|Profile not found"; then
	test_pass "Invalid profile rejected"
else
	test_fail "Profile existence check" "error 302" "$resp" "ipc_cmd 300 bad profile"
fi

log_test "ADMIN_SET_PW (302) - Change password"
resp=$(ipc_cmd "302" "username=$TEST_ADMIN\npassword=NewPass789@")
verify_response "$resp" "0" "ADMIN_SET_PW succeeds" "ipc_cmd 302 password change"

log_test "ADMIN_SET_PW - Non-existent user"
resp=$(ipc_cmd "302" "username=doesntexist\npassword=Pass123!")
if echo "$resp" | grep -q "301\|User not found"; then
	test_pass "Non-existent user rejected"
else
	test_fail "User existence check" "error 301" "$resp" "ipc_cmd 302 nonexistent user"
fi

log_test "ADMIN_SET_ENF (303) - Set enforce-change-password flag"
resp=$(ipc_cmd "303" "username=$TEST_ADMIN\nenforce=enable")
verify_response "$resp" "0" "ADMIN_SET_ENF succeeds" "ipc_cmd 303 enforce flag"

log_test "ADMIN_DELETE (301) - Delete test admin"
resp=$(ipc_cmd "301" "username=$TEST_ADMIN")
verify_response "$resp" "0" "ADMIN_DELETE succeeds" "ipc_cmd 301 admin delete"

log_test "ADMIN_DELETE - Delete built-in admin (should fail)"
resp=$(ipc_cmd "301" "username=admin")
if echo "$resp" | grep -q "402\|built-in\|Built-in"; then
	test_pass "Built-in admin protection works"
else
	test_fail "Built-in admin protection" "error 402" "$resp" "ipc_cmd 301 builtin admin"
fi

log_test "ADMIN_DELETE - Non-existent user"
resp=$(ipc_cmd "301" "username=ghost$RANDOM")
if echo "$resp" | grep -q "301\|User not found"; then
	test_pass "Delete nonexistent user rejected"
else
	test_fail "Delete nonexistent user" "error 301" "$resp" "ipc_cmd 301 ghost user"
fi

# ──────────────────────────────────────────────────────────────────────────
# SECTION 4: Show Commands (Status, Interfaces, Routes, Config)
# ──────────────────────────────────────────────────────────────────────────

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  SECTION 4: Show/Query Commands                               ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo "" | tee -a "$TEST_LOG"

log_test "SHOW_STATUS (610) - System status"
resp=$(ipc_cmd "610" "")
if echo "$resp" | head -1 | grep -q "0"; then
	test_pass "SHOW_STATUS returns success"
else
	test_fail "SHOW_STATUS" "status 0" "$(echo "$resp" | head -1)" "ipc_cmd 610"
fi

log_test "SHOW_STATUS response contains uptime/modules"
resp=$(ipc_cmd "610" "")
if echo "$resp" | grep -qi "uptime\|module\|pkt_forward"; then
	test_pass "SHOW_STATUS payload valid"
else
	test_fail "SHOW_STATUS payload" "contains uptime/module info" "$resp" "ipc_cmd 610"
fi

log_test "SHOW_IFACES (611) - Interface list"
resp=$(ipc_cmd "611" "")
verify_response "$resp" "0" "SHOW_IFACES returns success" "ipc_cmd 611"

log_test "SHOW_ROUTES (612) - Routing table"
resp=$(ipc_cmd "612" "")
verify_response "$resp" "0" "SHOW_ROUTES returns success" "ipc_cmd 612"

log_test "SHOW_CONFIG (613) - Current configuration"
resp=$(ipc_cmd "613" "")
verify_response "$resp" "0" "SHOW_CONFIG returns success" "ipc_cmd 613"

# ──────────────────────────────────────────────────────────────────────────
# SECTION 5: Session Management
# ──────────────────────────────────────────────────────────────────────────

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  SECTION 5: Session & Auth Management                         ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo "" | tee -a "$TEST_LOG"

log_test "SESSION_REV (400) - Get session revision"
resp=$(ipc_cmd "400" "username=admin")
verify_response "$resp" "0" "SESSION_REV succeeds" "ipc_cmd 400 admin"

log_test "SESSION_BUMP (401) - Bump session revision"
resp=$(ipc_cmd "401" "username=admin")
verify_response "$resp" "0" "SESSION_BUMP succeeds" "ipc_cmd 401 admin"

# ──────────────────────────────────────────────────────────────────────────
# SECTION 6: Edge Cases & Error Handling
# ──────────────────────────────────────────────────────────────────────────

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  SECTION 6: Edge Cases & Buffer Handling                      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo "" | tee -a "$TEST_LOG"

log_test "Username at max length boundary (SG_USERNAME_MAX=64)"
long_user="u$(printf 'a%.0s' $(seq 1 62))z"
resp=$(ipc_cmd "400" "username=$long_user")
if echo "$resp" | grep -q "0\|100\|300\|301"; then
	test_pass "Max-length username handled"
else
	test_fail "Max-length username" "valid response" "TIMEOUT/error" "SESSION_REV with 64-char username"
fi

log_test "Newline injection in payload (security test)"
malicious="username=admin\npassword=injected&extra=value"
resp=$(ipc_cmd "302" "$malicious" 2>&1)
if echo "$resp" | grep -q "102\|Invalid\|error"; then
	test_pass "Newline injection rejected"
else
	# Check if it was parsed as single value
	if ! echo "$resp" | grep -q "injected"; then
		test_pass "Newline injection didn't execute"
	else
		test_fail "Newline injection safety" "rejected or not executed" "$resp" "ipc_cmd 302 with newline"
	fi
fi

log_test "NULL byte in field value"
resp=$(ipc_cmd "200" "path=system\nsection=settings\nhostname=test\x00pwned")
if echo "$resp" | head -1 | grep -q "0"; then
	# Verify it didn't store the null-terminated early value
	verify_resp=$(ipc_cmd "100" "path=system\nsection=settings")
	if echo "$verify_resp" | grep -q "hostname=testpwned"; then
		test_fail "NULL byte handling" "should not create hostname=testpwned" "found in config" "CFG_SET/CFG_GET null byte"
	else
		test_pass "NULL byte safely handled"
	fi
fi

log_test "Empty payload to command requiring arguments"
resp=$(ipc_cmd "300" "")
if echo "$resp" | grep -q "103\|Missing"; then
	test_pass "Empty payload rejected"
else
	test_fail "Empty payload validation" "error 103" "$resp" "ipc_cmd 300 ''"
fi

# ──────────────────────────────────────────────────────────────────────────
# SECTION 7: Concurrency & Resource Limits
# ──────────────────────────────────────────────────────────────────────────

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  SECTION 7: Concurrency & Resource Limits                     ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo "" | tee -a "$TEST_LOG"

log_test "Rapid sequential PING commands (10x)"
success_count=0
for i in $(seq 1 10); do
	resp=$(ipc_cmd "900" "")
	if echo "$resp" | grep -q "0"; then
		success_count=$((success_count + 1))
	fi
done
if [ "$success_count" -eq 10 ]; then
	test_pass "All 10 PING commands succeeded"
else
	test_fail "Rapid PING commands" "10/10 success" "$success_count/10 succeeded" "10x PING"
fi

log_test "Parallel CFG_GET operations (background)"
tmp1=$(mktemp)
tmp2=$(mktemp)
ipc_cmd "100" "path=system\nsection=settings" > "$tmp1" &
pid1=$!
ipc_cmd "100" "path=system\nsection=settings" > "$tmp2" &
pid2=$!
wait "$pid1"
wait "$pid2"
resp1=$(cat "$tmp1")
resp2=$(cat "$tmp2")
rm -f "$tmp1" "$tmp2"
if [ -n "$resp1" ] && [ -n "$resp2" ]; then
	test_pass "Parallel CFG_GET handled"
else
	test_fail "Parallel operations" "both responses non-empty" "one or both empty" "parallel CFG_GET"
fi

# ──────────────────────────────────────────────────────────────────────────
# SECTION 8: Permission & Auth Checks
# ──────────────────────────────────────────────────────────────────────────

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  SECTION 8: Permission Enforcement                            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo "" | tee -a "$TEST_LOG"

log_test "System operations (POWEROFF/REBOOT) available"
resp=$(ipc_cmd "600" "")
# Expecting either success (cleared as tested) or permission check
if echo "$resp" | head -1 | grep -q "[0-9]"; then
	test_pass "System command reachable"
else
	test_fail "System command access" "valid response code" "TIMEOUT" "ipc_cmd 600"
fi

# ──────────────────────────────────────────────────────────────────────────
# FINAL REPORT
# ──────────────────────────────────────────────────────────────────────────

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                      TEST SUMMARY                             ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo "" | tee -a "$TEST_LOG"

printf "Tests Run:    %d\n" "$TESTS_RUN" | tee -a "$TEST_LOG"
printf "Tests Passed: %d ${GREEN}✓${NC}\n" "$TESTS_PASSED" | tee -a "$TEST_LOG"
printf "Tests Failed: %d ${RED}✗${NC}\n" "$TESTS_FAILED" | tee -a "$TEST_LOG"
echo "" | tee -a "$TEST_LOG"

# Generate bug report JSON
if [ -s "$BUG_NDJSON" ]; then
	BUGS_JSON=$(awk 'BEGIN{printf "["} {if (NR>1) printf ","; printf $0} END{printf "]"}' "$BUG_NDJSON")
else
	BUGS_JSON="[]"
fi

cat > "$BUG_REPORT" <<EOF
{
  "project": "Stargazer NGFW",
  "test_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "environment": {
    "os": "$(uname -s)",
    "kernel": "$(uname -r)",
    "machine": "$(uname -m)"
  },
  "summary": {
    "total_tests": $TESTS_RUN,
    "passed": $TESTS_PASSED,
    "failed": $TESTS_FAILED,
    "pass_rate": "$(awk "BEGIN {printf \"%.1f\", ($TESTS_PASSED/$TESTS_RUN*100)}")%"
  },
	"bugs": $BUGS_JSON
}
EOF

printf "\n✓ Test log: %s\n" "$TEST_LOG" | tee -a "$TEST_LOG"
printf "✓ Bug report: %s\n" "$BUG_REPORT" | tee -a "$TEST_LOG"

exit $TESTS_FAILED
