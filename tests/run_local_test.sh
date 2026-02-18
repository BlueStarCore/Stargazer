#!/bin/bash
# Stargazer NGFW - Local Test Runner
# Builds native x86_64 mgmtd + ipc-cli, starts mgmtd, runs tests, cleans up.
# Must be run with sudo (mgmtd needs /run socket + /etc/shadow access).
#
# Usage: sudo ./tests/run_local_test.sh [test_script]
#   Default test_script: tests/test_experience.sh

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build/native"
MGMTD_BIN="$BUILD_DIR/stargazer-mgmtd"
IPC_BIN="$BUILD_DIR/stargazer-ipc-cli"
CONFIG_DIR="/etc/stargazer"
DEFAULT_CONF="$PROJECT_ROOT/src/userspace/etc/stargazer/default.conf"
TEST_SCRIPT="${1:-$PROJECT_ROOT/tests/test_experience.sh}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

cleanup() {
	echo ""
	printf "${YELLOW}Cleaning up...${NC}\n"

	# Stop mgmtd
	if [ -n "$MGMTD_PID" ] && kill -0 "$MGMTD_PID" 2>/dev/null; then
		kill "$MGMTD_PID" 2>/dev/null
		wait "$MGMTD_PID" 2>/dev/null || true
		printf "  Stopped mgmtd (PID %d)\n" "$MGMTD_PID"
	fi

	# Remove socket
	rm -f /run/stargazer-mgmtd.sock

	# Remove config dir only if we created it
	if [ "$CREATED_CONFIG_DIR" = "1" ]; then
		rm -rf "$CONFIG_DIR"
		printf "  Removed %s\n" "$CONFIG_DIR"
	fi

	printf "${GREEN}Cleanup complete.${NC}\n"
}

trap cleanup EXIT

# ── Checks ───────────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
	echo "ERROR: This script must be run as root (sudo)."
	echo "Usage: sudo $0 [test_script]"
	exit 1
fi

if [ ! -f "$TEST_SCRIPT" ]; then
	echo "ERROR: Test script not found: $TEST_SCRIPT"
	exit 1
fi

printf "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}\n"
printf "${CYAN}║  Stargazer NGFW - Local Test Environment                       ║${NC}\n"
printf "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}\n"
echo ""

# ── Build native binaries ────────────────────────────────────────────────

printf "${CYAN}[1/4] Building native x86_64 binaries...${NC}\n"

mkdir -p "$BUILD_DIR"

# Build ipc-cli
gcc -Wall -Wextra -Os \
	-I"$PROJECT_ROOT/src/userspace/mgmtd" \
	-o "$IPC_BIN" \
	"$PROJECT_ROOT/src/userspace/mgmtd/stargazer-ipc-cli.c" 2>&1

printf "  ✓ stargazer-ipc-cli\n"

# Build mgmtd
gcc -Wall -Wextra -Wno-unused-result -Os \
	-I"$PROJECT_ROOT/src/userspace/mgmtd" \
	-I"$PROJECT_ROOT/src/userspace/common" \
	-o "$MGMTD_BIN" \
	"$PROJECT_ROOT/src/userspace/mgmtd/stargazer-mgmtd.c" \
	"$PROJECT_ROOT/src/userspace/common/password_policy.c" \
	-lcrypt 2>&1

printf "  ✓ stargazer-mgmtd\n"

# ── Setup config directory ───────────────────────────────────────────────

printf "\n${CYAN}[2/4] Setting up config directory...${NC}\n"

CREATED_CONFIG_DIR=0
if [ ! -d "$CONFIG_DIR" ]; then
	mkdir -p "$CONFIG_DIR"
	CREATED_CONFIG_DIR=1
	printf "  Created %s\n" "$CONFIG_DIR"
fi

# Seed config from default.conf (split by ### DOMAIN: markers)
if [ -f "$DEFAULT_CONF" ]; then
	# Parse default.conf into domain-specific files
	current_domain=""
	while IFS= read -r line; do
		case "$line" in
			"### DOMAIN:"*)
				current_domain="${line#*DOMAIN:}"
				current_domain="${current_domain%% *}"
				current_domain="${current_domain% ###}"
				# Only create if file doesn't exist (don't overwrite)
				if [ ! -f "$CONFIG_DIR/$current_domain.conf" ]; then
					: > "$CONFIG_DIR/$current_domain.conf"
				fi
				;;
			*)
				if [ -n "$current_domain" ] && [ ! -s "$CONFIG_DIR/$current_domain.conf" ]; then
					echo "$line" >> "$CONFIG_DIR/$current_domain.conf"
				fi
				;;
		esac
	done < "$DEFAULT_CONF"
	printf "  ✓ Seeded config from default.conf\n"
else
	printf "  ${YELLOW}WARNING: default.conf not found, mgmtd will start with empty config${NC}\n"
fi

# Show what we have
for f in "$CONFIG_DIR"/*.conf; do
	[ -f "$f" ] && printf "    %s (%d lines)\n" "$f" "$(wc -l < "$f")"
done

# ── Start mgmtd ─────────────────────────────────────────────────────────

printf "\n${CYAN}[3/4] Starting mgmtd daemon...${NC}\n"

# Kill any existing mgmtd
if pgrep -f "stargazer-mgmtd" >/dev/null 2>&1; then
	pkill -f "stargazer-mgmtd" 2>/dev/null
	sleep 1
	printf "  Stopped existing mgmtd\n"
fi

rm -f /run/stargazer-mgmtd.sock

# Start mgmtd in background
"$MGMTD_BIN" &
MGMTD_PID=$!

# Wait for socket to appear
MAX_WAIT=10
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
	if [ -S /run/stargazer-mgmtd.sock ]; then
		break
	fi
	sleep 0.5
	WAITED=$((WAITED + 1))
done

if [ -S /run/stargazer-mgmtd.sock ]; then
	printf "  ✓ mgmtd started (PID %d), socket ready\n" "$MGMTD_PID"
else
	printf "  ${RED}✗ mgmtd failed to create socket after %d attempts${NC}\n" "$MAX_WAIT"
	# Check if process is still alive
	if kill -0 "$MGMTD_PID" 2>/dev/null; then
		printf "  Process is running but socket not created\n"
	else
		printf "  Process exited prematurely\n"
		wait "$MGMTD_PID" 2>/dev/null
	fi
	exit 1
fi

# Quick smoke test
printf "  PING test: "
STARGAZER_USER=admin "$IPC_BIN" 900 2>/dev/null
if [ $? -eq 0 ]; then
	printf "  ${GREEN}✓ mgmtd responding${NC}\n"
else
	printf "  ${RED}✗ mgmtd not responding${NC}\n"
	exit 1
fi

# ── Run test suite ───────────────────────────────────────────────────────

printf "\n${CYAN}[4/4] Running test suite: %s${NC}\n" "$(basename "$TEST_SCRIPT")"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Make ipc-cli available in PATH
export PATH="$BUILD_DIR:$PATH"

# Run the test
chmod +x "$TEST_SCRIPT"
"$TEST_SCRIPT"
TEST_EXIT=$?

echo ""
echo "════════════════════════════════════════════════════════════════"
printf "Test suite exited with code: %d\n" "$TEST_EXIT"

exit $TEST_EXIT
