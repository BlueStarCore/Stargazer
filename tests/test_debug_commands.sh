#!/bin/sh
# Test execute debug command suite

set -e

PROJECT_ROOT="/home/rusted/projects/Stargazer"
CMD_DIR="$PROJECT_ROOT/src/userspace/usr/libexec/stargazer"
STATE_FILE="/tmp/stargazer-debug.conf"

pass() {
	echo "PASS: $1"
}

fail() {
	echo "FAIL: $1"
	exit 1
}

assert_kv() {
	key="$1"
	expected="$2"
	actual=$(grep "^${key}=" "$STATE_FILE" 2>/dev/null | tail -1 | cut -d= -f2-)
	[ "$actual" = "$expected" ] || fail "${key} expected '${expected}', got '${actual}'"
}

run_exec() {
	STARGAZER_PERMISSIONS="admin,configure,monitor" \
	CMD_DIR="$CMD_DIR" \
	sh "$CMD_DIR/cmd_execute" "$@"
}

rm -f "$STATE_FILE"

run_exec debug reset >/dev/null
assert_kv enabled 0
assert_kv flow_trace 0
assert_kv flow_limit 0
assert_kv cli_debug 0
assert_kv mgmtd_debug 0
pass "reset initializes defaults"

run_exec debug enable >/dev/null
assert_kv enabled 1
pass "global debug enable"

run_exec debug cli enable >/dev/null
assert_kv cli_debug 1
pass "cli debug enable"

run_exec debug mgmtd enable >/dev/null
assert_kv mgmtd_debug 1
pass "mgmtd debug enable"

run_exec debug auth admin enable >/dev/null
assert_kv auth_admin 1
pass "auth admin debug enable"

run_exec debug flow trace enable limit 5 >/dev/null
assert_kv flow_trace 1
assert_kv flow_limit 5
pass "flow trace with limit"

out_top=$(run_exec debug top 2>/dev/null || true)
echo "$out_top" | grep -qi "process snapshot\|debug top\|top" || fail "debug top output"
pass "debug top output"

out_res=$(run_exec debug resources cpu 2>/dev/null || true)
echo "$out_res" | grep -qi "cpu resources\|cpu cores" || fail "debug resources cpu output"
pass "debug resources cpu output"

run_exec debug disable >/dev/null
assert_kv enabled 0
assert_kv flow_trace 1
assert_kv flow_limit 5
pass "disable keeps feature options"

run_exec debug reset >/dev/null
assert_kv enabled 0
assert_kv flow_trace 0
assert_kv flow_limit 0
assert_kv cli_debug 0
assert_kv auth_admin 0
assert_kv mgmtd_debug 0
pass "reset clears all features"

echo "ALL PASSED"
