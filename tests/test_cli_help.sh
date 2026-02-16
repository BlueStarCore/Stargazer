#!/bin/sh
# Test CLI '?' help behavior: <Enter> for exact leaf and argument hints for edit.

set -e

PROJECT_ROOT="/home/rusted/projects/Stargazer"
CLI_INPUT="$PROJECT_ROOT/src/userspace/usr/libexec/stargazer/cli_input.sh"

# shellcheck source=/dev/null
. "$CLI_INPUT"

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }

# Case 1: leaf command with trailing space should show <Enter>
_CLI_CMDS=""
_CLI_PATHS=""
cli_register "execute debug top" "Show process snapshot like top"
cli_register "execute debug flow trace" "Enable flow trace debug"
cli_register "execute debug flow trace limit" "Enable flow trace debug and limit captured flows"
cli_register "execute debug flow trace unlimited" "Enable flow trace debug and capture all flows"

_cli_build_help "execute debug top "
echo "$_HELP_RESULT" | grep -q "<Enter>" || fail "leaf command should show <Enter>"
pass "leaf command shows <Enter>"

# Case 2: command that allows enter and has children should show both
_cli_build_help "execute debug flow trace "
echo "$_HELP_RESULT" | grep -q "<Enter>" || fail "flow trace should show <Enter>"
echo "$_HELP_RESULT" | grep -q "limit" || fail "flow trace should show limit"
echo "$_HELP_RESULT" | grep -q "unlimited" || fail "flow trace should show unlimited"
pass "flow trace shows <Enter> and sub-commands"

# Case 3: edit context should show allowed input rule
_CLI_CMDS=""
_CLI_PATHS=""
cli_register "edit <id>" "Allow: string [A-Za-z0-9_.-]"
cli_register "delete <id>" "Allow: string [A-Za-z0-9_.-]"
cli_register "show" "Show all entries"

_cli_build_help "edit "
echo "$_HELP_RESULT" | grep -q "<id>" || fail "edit should show <id> placeholder"
echo "$_HELP_RESULT" | grep -q "Allow:" || fail "edit should show allow rule"
pass "edit help shows allowed ID type"

echo "ALL PASSED"
