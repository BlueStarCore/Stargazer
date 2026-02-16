#!/bin/bash
# Stargazer NGFW - Automated Test Runner for QEMU
# This script copies test files to the running QEMU instance and executes them

set -e

STARGAZER_DIR="/home/rusted/projects/Stargazer"
QEMU_SSH_PORT=2222
QEMU_USER="root"

# Check if QEMU is running
if ! pgrep -f "qemu-system-aarch64.*virt" >/dev/null 2>&1; then
	echo "ERROR: QEMU is not running. Start with: make test"
	exit 1
fi

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  Stargazer NGFW - Automated Test Suite                         ║"
echo "║  Running tests on QEMU instance...                             ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Wait for QEMU to fully boot and mgmtd to start
echo "Waiting for QEMU to boot and mgmtd socket to be ready..."
MAX_WAIT=60
WAITED=0

while [ $WAITED -lt $MAX_WAIT ]; do
	if [ -S "/run/stargazer-mgmtd.sock" ] 2>/dev/null; then
		echo "✓ mgmtd socket is ready"
		break
	fi
	WAITED=$((WAITED + 1))
	echo "  Waiting... ($WAITED/$MAX_WAIT seconds)"
	sleep 1
done

if [ $WAITED -ge $MAX_WAIT ]; then
	echo "✗ TIMEOUT: mgmtd socket not ready after $MAX_WAIT seconds"
	exit 1
fi

# Run the test suite
echo ""
echo "Starting comprehensive test suite..."
echo "================================================================"
echo ""

cd "$STARGAZER_DIR"
"$STARGAZER_DIR/tests/test_suite.sh"
EXIT_CODE=$?

echo ""
echo "================================================================"
echo "Test suite completed with exit code: $EXIT_CODE"
echo ""

# Show bug report
if [ -f "/tmp/stargazer_bugs.json" ]; then
	echo ""
	echo "╔════════════════════════════════════════════════════════════════╗"
	echo "║                   BUG REPORT SUMMARY                           ║"
	echo "╚════════════════════════════════════════════════════════════════╝"
	cat "/tmp/stargazer_bugs.json" | jq '.' 2>/dev/null || cat "/tmp/stargazer_bugs.json"
fi

exit $EXIT_CODE
