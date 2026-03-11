#!/usr/bin/env python3
"""QEMU selftest runner for Stargazer NGFW.

Boots QEMU, logs in, runs 'diagnose selftest', and reports results.
Uses non-blocking I/O to handle the interactive serial console.
"""

import subprocess
import sys
import os
import time
import select
import re
import signal

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOOT_IMG = os.path.join(PROJECT, "build/test/boot.img")
DATA_IMG = os.path.join(PROJECT, "build/test/data.img")
UBOOT_BIN = os.path.join(PROJECT, "build/u-boot/u-boot.bin")
TIMEOUT = 300  # 5 minutes max


def read_until(proc, pattern, timeout=60):
    """Read from QEMU stdout until pattern is found or timeout."""
    buf = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        ready, _, _ = select.select([proc.stdout], [], [], min(1.0, remaining))
        if ready:
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk:
                break
            text = chunk.decode("utf-8", errors="replace")
            buf += text
            sys.stdout.write(text)
            sys.stdout.flush()
            if re.search(pattern, buf):
                return buf
    return buf


def send(proc, text, delay=0.3):
    """Send text to QEMU stdin."""
    proc.stdin.write(text.encode())
    proc.stdin.flush()
    time.sleep(delay)


def main():
    if not os.path.exists(BOOT_IMG):
        print(f"ERROR: {BOOT_IMG} not found. Run 'make test-build' first.")
        sys.exit(1)

    # Create fresh data image
    subprocess.run(
        ["dd", "if=/dev/zero", f"of={DATA_IMG}", "bs=1M", "count=32"],
        capture_output=True,
    )

    qemu_cmd = [
        "qemu-system-aarch64",
        "-M", "virt", "-cpu", "cortex-a57", "-m", "2G", "-nographic",
        "-bios", UBOOT_BIN,
        "-drive", f"file={BOOT_IMG},format=raw,if=virtio,snapshot=on",
        "-drive", f"file={DATA_IMG},format=raw,if=virtio",
        "-net", "none",
    ]

    print(f"Starting QEMU...")
    proc = subprocess.Popen(
        qemu_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )

    try:
        # Wait for login prompt
        buf = read_until(proc, r"login:", timeout=120)
        if "login:" not in buf:
            print("\nERROR: Never got login prompt")
            sys.exit(1)

        # Login as admin (empty password on first boot)
        send(proc, "admin\n")
        buf = read_until(proc, r"[Pp]assword:", timeout=10)
        send(proc, "\n")  # empty password

        # Check if forced password change
        buf = read_until(proc, r"([$#>]|[Nn]ew [Pp]assword|change)", timeout=10)
        if "new" in buf.lower() or "change" in buf.lower():
            # Set new password
            send(proc, "Admin@1234\n")
            read_until(proc, r"[Cc]onfirm|[Rr]etype|[Nn]ew", timeout=5)
            send(proc, "Admin@1234\n")
            read_until(proc, r"[$#>]", timeout=10)

            # Re-login with new password
            buf = read_until(proc, r"login:|[$#>]", timeout=10)
            if "login:" in buf:
                send(proc, "admin\n")
                read_until(proc, r"[Pp]assword:", timeout=10)
                send(proc, "Admin@1234\n")
                read_until(proc, r"[$#>]", timeout=10)

        # Run selftest
        print("\n\n=== Running selftest ===\n")
        send(proc, "execute diagnose selftest\n", delay=1)

        # Collect selftest output (takes a while)
        buf = read_until(proc, r"tests passed|tests failed|SUMMARY", timeout=180)

        # Look for remaining output
        extra = read_until(proc, r"[$#>]", timeout=10)
        buf += extra

        # Parse results
        passed = len(re.findall(r"PASS", buf))
        failed = len(re.findall(r"FAIL", buf))
        total = passed + failed

        print(f"\n\n{'='*50}")
        print(f"SELFTEST RESULTS: {passed}/{total} passed, {failed} failed")
        print(f"{'='*50}")

        if failed > 0:
            # Show failed tests
            for line in buf.split("\n"):
                if "FAIL" in line:
                    print(f"  FAILED: {line.strip()}")

        # Cleanup
        send(proc, "exit\n")
        time.sleep(1)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
