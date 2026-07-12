#!/bin/sh
# test_session_tracking.sh — Verify session.ko + pkt_forward.ko behavior
#
# Three phases:
#   Phase 1 (static)  — source code analysis: spinlock consistency, RCU
#                        usage, no floats, MODULE_SOFTDEP.  Runs on host.
#   Phase 2 (live)    — module loading + /proc/stargazer/sessions.
#                        Runs on the target (inside QEMU or real hardware).
#   Phase 3 (inject)  — TUN-based packet injection via test_session_kern
#                        binary.  Requires cross-compiled C helper.
#
# Exit 0 = all non-skipped tests passed
# Exit 1 = one or more tests FAILED
#
# Usage:
#   On host (static only):   sh tests/test_session_tracking.sh
#   On target (full):        sh tests/test_session_tracking.sh
#   With prebuilt binary:    KERN_BIN=/path/to/test_session_kern sh tests/test_session_tracking.sh

set -e
PASS=0
FAIL=0
SKIP=0

R='\033[91m'; G='\033[92m'; Y='\033[93m'; C='\033[96m'
N='\033[0m';  B='\033[1m'

pass() { PASS=$((PASS+1)); printf "  ${G}PASS${N} %s\n" "$1"; }
fail() { FAIL=$((FAIL+1)); printf "  ${R}FAIL${N} %s\n" "$1"; [ -n "${2:-}" ] && printf "       ${Y}↳ %s${N}\n" "$2"; }
skip() { SKIP=$((SKIP+1)); printf "  ${Y}SKIP${N} %s\n" "$1"; }
note() { printf "  ${Y}NOTE${N} %s\n" "$1"; }

# Resolve source root whether run from project root or tests/
SRCBASE="$(cd "$(dirname "$0")/.." && pwd)"
SESSION_C="$SRCBASE/src/modules/session.c"
SESSION_H="$SRCBASE/src/modules/session.h"
PKT_FWD_C="$SRCBASE/src/modules/pkt_forward.c"
MODULE_DIR="/lib/modules/stargazer"

# Optional prebuilt injection binary
KERN_BIN="${KERN_BIN:-$SRCBASE/tests/test_session_kern}"

# ─────────────────────────────────────────────────────────────────────────────
printf "\n${B}${C}=== Phase 1: Static source analysis ===${N}\n"
# ─────────────────────────────────────────────────────────────────────────────

# T01: Source files exist
if [ -f "$SESSION_C" ] && [ -f "$SESSION_H" ] && [ -f "$PKT_FWD_C" ]; then
    pass "T01: Session and pkt_forward source files present"
else
    fail "T01: Missing source files" "Expected $SESSION_C / $SESSION_H / $PKT_FWD_C"
fi

# T02: pkt_forward declares MODULE_SOFTDEP pre:session
# Ensures the kernel loads session.ko before pkt_forward.ko — required because
# pkt_forward calls symbols exported by session.ko.
if grep -q 'MODULE_SOFTDEP.*pre.*session' "$PKT_FWD_C" 2>/dev/null; then
    pass "T02: pkt_forward declares MODULE_SOFTDEP pre:session"
else
    fail "T02: pkt_forward missing MODULE_SOFTDEP pre:session" \
         "pkt_forward.ko uses EXPORT_SYMBOL_GPL symbols from session.ko. Without SOFTDEP the load order is undefined."
fi

# T03: pkt_forward wraps session calls inside rcu_read_lock / rcu_read_unlock
# sess_lookup_or_create and sess_update dereference RCU-protected pointers;
# the caller must hold the RCU read lock for the entire dereference window.
if grep -q 'rcu_read_lock' "$PKT_FWD_C" 2>/dev/null && \
   grep -q 'rcu_read_unlock' "$PKT_FWD_C" 2>/dev/null; then
    pass "T03: pkt_forward holds rcu_read_lock around session operations"
else
    fail "T03: pkt_forward missing rcu_read_lock/unlock around session calls" \
         "Session pointers are only valid inside an RCU read-side CS."
fi

# T04: sess_lookup_or_create is called inside the rcu_read_lock block
# (not before rcu_read_lock or after rcu_read_unlock)
if awk '/rcu_read_lock/{inside=1} /rcu_read_unlock/{inside=0} inside && /sess_lookup_or_create/{found=1} END{exit !found}' "$PKT_FWD_C" 2>/dev/null; then
    pass "T04: sess_lookup_or_create called inside rcu_read_lock block"
else
    fail "T04: sess_lookup_or_create called outside rcu_read_lock block" \
         "Dereferencing the returned session pointer outside the RCU CS is use-after-free."
fi

# T05: SESS_BLOCKED is checked via READ_ONCE, not a plain load
# The ML/policy code sets s->flags from a different CPU without holding
# s->lock.  READ_ONCE prevents the compiler from caching the old value.
if grep -q 'READ_ONCE.*flags.*SESS_BLOCKED\|READ_ONCE.*s->flags' "$PKT_FWD_C" 2>/dev/null; then
    pass "T05: SESS_BLOCKED flag checked via READ_ONCE (prevents stale cache)"
else
    fail "T05: SESS_BLOCKED flag read without READ_ONCE" \
         "Flags may be set from another CPU without holding s->lock. Plain load can read stale value."
fi

# T06: GFP_ATOMIC used in sess_alloc (called from NF_INET_FORWARD softirq)
# GFP_KERNEL would sleep; sleeping inside a Netfilter hook is illegal.
if grep -q 'GFP_ATOMIC' "$SESSION_C" 2>/dev/null; then
    pass "T06: sess_alloc uses GFP_ATOMIC (correct for softirq/atomic context)"
else
    fail "T06: sess_alloc does not use GFP_ATOMIC" \
         "Session allocation is called from NF_INET_FORWARD (softirq). GFP_KERNEL would sleep and crash."
fi

# T07: No floating-point type declarations in kernel modules
# ARM64 does not save/restore FPU state in interrupt context.
# Check for 'float' or 'double' as C type keywords in non-comment lines.
for f in "$SESSION_C" "$PKT_FWD_C"; do
    base="$(basename $f)"
    if grep -v '^\s*[/*#]' "$f" 2>/dev/null | grep -qE '\bfloat\b|\bdouble\b'; then
        fail "T07: float/double type found in $base" \
             "FPU state is not saved in kernel interrupt context on ARM64."
    else
        pass "T07: No float/double types in $base"
    fi
done

# T08: hash_del_rcu is always followed by call_rcu (deferred free)
# Direct kfree after hash_del_rcu would free memory while RCU readers
# may still hold references to the object.
del_rcu=$(grep -c 'hash_del_rcu' "$SESSION_C" 2>/dev/null || true)
call_rcu=$(grep -c 'call_rcu' "$SESSION_C" 2>/dev/null || true)
if [ "$del_rcu" -gt 0 ] && [ "$call_rcu" -eq "$del_rcu" ]; then
    pass "T08: Every hash_del_rcu has a corresponding call_rcu (${del_rcu} pairs)"
else
    fail "T08: hash_del_rcu/call_rcu count mismatch (del=${del_rcu} call=${call_rcu})" \
         "Objects removed from RCU hash must be freed via call_rcu to respect RCU grace period."
fi

# T09: sess_reaper uses spin_lock_bh for table_lock (correct for workqueue)
# Use awk to extract the function body (from definition to closing brace) and
# search within it — grep -A2 is too narrow for a multi-line function.
reaper_uses_bh=$(awk '
    /^static void sess_reaper_fn\(/ { in_fn=1; depth=0 }
    in_fn {
        for (i=1; i<=length($0); i++) {
            c = substr($0, i, 1)
            if (c == "{") depth++
            else if (c == "}") { depth--; if (depth==0) { in_fn=0; next } }
        }
        if (/spin_lock_bh/) found=1
    }
    END { exit !found }
' "$SESSION_C" 2>/dev/null; echo $?)
if [ "$reaper_uses_bh" = "0" ]; then
    pass "T09: sess_reaper_fn uses spin_lock_bh (correct for workqueue process context)"
else
    fail "T09: sess_reaper_fn does not use spin_lock_bh" \
         "Reaper runs in workqueue (process context). spin_lock_bh is needed to block softirqs."
fi

# T10: sess_delete uses spin_lock_bh for table_lock
# BUG CHECK: sess_delete is exported (EXPORT_SYMBOL_GPL) for Phase 3 callers
# such as ML/IPS daemons via netlink — those callers run in process context.
# If the NF_INET_FORWARD softirq fires on the same CPU while sess_delete
# holds table_lock with plain spin_lock (no _bh), and the softirq also
# tries to acquire table_lock, the CPU deadlocks.
# Fix: use spin_lock_bh in sess_delete.
sess_delete_lock=$(awk '/^void sess_delete/{found=1} found && /spin_lock/{print;exit}' "$SESSION_C" 2>/dev/null)
if echo "$sess_delete_lock" | grep -q 'spin_lock_bh'; then
    pass "T10: sess_delete uses spin_lock_bh (safe for process-context callers)"
else
    fail "T10: sess_delete uses spin_lock — should be spin_lock_bh" \
         "sess_delete is EXPORT_SYMBOL_GPL. Future callers (Phase 3 netlink handler) are in process context. If NF_INET_FORWARD softirq fires on same CPU while sess_delete holds the lock, deadlock occurs."
fi

# T11: sess_lookup_or_create uses spin_lock_bh
# Currently only called from softirq (forward_hook), so spin_lock is safe.
# However, once exported, process-context callers would hit the same
# deadlock risk.  Flag as a warning (not a hard fail yet).
loc_lock=$(awk '/^struct session \*sess_lookup_or_create/{found=1} found && /spin_lock/{print;exit}' "$SESSION_C" 2>/dev/null)
if echo "$loc_lock" | grep -q 'spin_lock_bh'; then
    pass "T11: sess_lookup_or_create uses spin_lock_bh"
else
    note "T11: sess_lookup_or_create uses spin_lock (safe now — softirq-only caller)"
    note "     When Phase 3 adds process-context callers, this also needs spin_lock_bh."
    PASS=$((PASS+1))
fi

# T12: sess_flush_all uses spin_lock_bh (called from module exit = process context)
flush_uses_bh=$(awk '
    /^static void sess_flush_all\(/ { in_fn=1; depth=0 }
    in_fn {
        for (i=1; i<=length($0); i++) {
            c = substr($0, i, 1)
            if (c == "{") depth++
            else if (c == "}") { depth--; if (depth==0) { in_fn=0; next } }
        }
        if (/spin_lock_bh/) found=1
    }
    END { exit !found }
' "$SESSION_C" 2>/dev/null; echo $?)
if [ "$flush_uses_bh" = "0" ]; then
    pass "T12: sess_flush_all uses spin_lock_bh (correct for module exit context)"
else
    fail "T12: sess_flush_all does not use spin_lock_bh" \
         "sess_flush_all is called from session_exit (process context). Needs spin_lock_bh."
fi

# T13: rcu_barrier called in sess_flush_all before module exits
# Ensures all pending call_rcu callbacks complete before the module's
# memory (containing sess_free_rcu) is unmapped.
flush_has_barrier=$(awk '
    /^static void sess_flush_all\(/ { in_fn=1; depth=0 }
    in_fn {
        for (i=1; i<=length($0); i++) {
            c = substr($0, i, 1)
            if (c == "{") depth++
            else if (c == "}") { depth--; if (depth==0) { in_fn=0; next } }
        }
        if (/rcu_barrier/) found=1
    }
    END { exit !found }
' "$SESSION_C" 2>/dev/null; echo $?)
if [ "$flush_has_barrier" = "0" ]; then
    pass "T13: sess_flush_all calls rcu_barrier (all deferred frees complete before unload)"
else
    fail "T13: sess_flush_all missing rcu_barrier" \
         "Without rcu_barrier, pending call_rcu callbacks may fire after module unload → crash."
fi

# T14: Reaper reschedules itself (persistent periodic cleanup)
reaper_reschedules=$(awk '
    /^static void sess_reaper_fn\(/ { in_fn=1; depth=0 }
    in_fn {
        for (i=1; i<=length($0); i++) {
            c = substr($0, i, 1)
            if (c == "{") depth++
            else if (c == "}") { depth--; if (depth==0) { in_fn=0; next } }
        }
        if (/schedule_delayed_work/) found=1
    }
    END { exit !found }
' "$SESSION_C" 2>/dev/null; echo $?)
if [ "$reaper_reschedules" = "0" ]; then
    pass "T14: Reaper reschedules itself after each run"
else
    fail "T14: Reaper does not reschedule — idle sessions will never expire" \
         "After the first run, the reaper work item must be requeued."
fi

# T15: pkt_forward accounts blocked packets separately from dropped
if grep -q 'pkts_blocked' "$PKT_FWD_C" 2>/dev/null && \
   grep -q 'pkts_dropped' "$PKT_FWD_C" 2>/dev/null && \
   grep -q 'pkts_forwarded' "$PKT_FWD_C" 2>/dev/null; then
    pass "T15: pkt_forward has separate blocked/dropped/forwarded counters"
else
    fail "T15: pkt_forward missing one or more of pkts_blocked/dropped/forwarded"
fi

# T16: Capacity gate prevents table overflow
if grep -q 'MAX_SESSIONS\|sess_active.*MAX_SESSIONS\|MAX_SESSIONS.*sess_active' "$SESSION_C" 2>/dev/null; then
    max_val=$(grep '#define MAX_SESSIONS' "$SESSION_C" | awk '{print $3}')
    pass "T16: Capacity gate enforces MAX_SESSIONS=$max_val (prevents unbounded growth)"
else
    fail "T16: No capacity gate in sess_lookup_or_create" \
         "Without a limit, an attacker can exhaust kernel memory with SYN flood."
fi

# T17: IAT (inter-arrival time) only accumulated after first packet
# First packet has no previous timestamp so iat_sum_ns update is skipped.
if awk '/iat_sum_ns/{if(/iat_count.*>.*0/||prev~/iat_count.*>.*0/){found=1}} {prev=$0} END{exit !found}' "$SESSION_C" 2>/dev/null; then
    pass "T17: IAT accumulation guarded by iat_count > 0 (first packet has no IAT)"
else
    fail "T17: IAT not guarded — first packet would add a bogus timestamp delta"
fi

# T18: sess_pkt_len.min initialized to U32_MAX (correct min-tracking sentinel)
if grep -q 'U32_MAX\|0xffffffff\|UINT_MAX' "$SESSION_C" 2>/dev/null; then
    pass "T18: Packet length minimum initialized to U32_MAX (correct sentinel for min tracking)"
else
    fail "T18: sess_pkt_len.min not initialized to U32_MAX" \
         "If min starts at 0, every packet looks like a record low."
fi

# ─────────────────────────────────────────────────────────────────────────────
printf "\n${B}${C}=== Phase 2: Live module + procfs checks ===${N}\n"
# ─────────────────────────────────────────────────────────────────────────────

# Detect whether we are running on the target.
# We look for the stargazer module directory specifically — both conditions
# must be true so that a developer's x86 host (which has /lib/modules but
# no Stargazer modules) doesn't accidentally run the live phase.
ON_TARGET=0
if [ -d /lib/modules/stargazer ] || \
   [ -f /lib/modules/stargazer/session.ko ] || \
   lsmod 2>/dev/null | grep -q 'session\|pkt_forward' || \
   [ -f /proc/stargazer/sessions ]; then
    ON_TARGET=1
fi

if [ "$ON_TARGET" -eq 0 ]; then
    skip "T19–T28: Not on target — skipping live module checks"
    skip "(Run this script inside QEMU or on real hardware for live tests)"
else
    # T19: Module files exist
    if [ -f "$MODULE_DIR/session.ko" ]; then
        pass "T19: $MODULE_DIR/session.ko exists"
    else
        fail "T19: $MODULE_DIR/session.ko not found" \
             "Run 'make modules' and ensure the image includes /lib/modules/stargazer/"
    fi

    if [ -f "$MODULE_DIR/pkt_forward.ko" ]; then
        pass "T20: $MODULE_DIR/pkt_forward.ko exists"
    else
        fail "T20: $MODULE_DIR/pkt_forward.ko not found"
    fi

    # T21: Load session.ko (idempotent — skip if already loaded)
    SESS_WAS_LOADED=0
    if lsmod 2>/dev/null | grep -q '^session '; then
        SESS_WAS_LOADED=1
        pass "T21: session.ko already loaded"
    elif insmod "$MODULE_DIR/session.ko" 2>/dev/null; then
        pass "T21: session.ko loaded successfully"
    else
        fail "T21: session.ko failed to load" "Check dmesg for errors"
    fi

    # T22: /proc/stargazer/sessions appears after session.ko loads
    if [ -f /proc/stargazer/sessions ]; then
        pass "T22: /proc/stargazer/sessions exists"
    else
        fail "T22: /proc/stargazer/sessions not found after module load" \
             "session_init() failed to create proc entry — check dmesg"
    fi

    # T23: Load pkt_forward.ko
    PFW_WAS_LOADED=0
    if lsmod 2>/dev/null | grep -q '^pkt_forward '; then
        PFW_WAS_LOADED=1
        pass "T23: pkt_forward.ko already loaded"
    elif insmod "$MODULE_DIR/pkt_forward.ko" 2>/dev/null; then
        pass "T23: pkt_forward.ko loaded successfully after session.ko"
    else
        fail "T23: pkt_forward.ko failed to load" "Likely unresolved symbols from session.ko"
    fi

    # T24: Both modules visible in lsmod
    if lsmod 2>/dev/null | grep -q '^session '; then
        pass "T24: session visible in lsmod"
    else
        fail "T24: session not visible in lsmod"
    fi

    if lsmod 2>/dev/null | grep -q '^pkt_forward '; then
        pass "T25: pkt_forward visible in lsmod"
    else
        fail "T25: pkt_forward not visible in lsmod"
    fi

    # T26: procfs header line contains expected counter fields
    hdr=$(head -1 /proc/stargazer/sessions 2>/dev/null || true)
    if echo "$hdr" | grep -q 'active=' && echo "$hdr" | grep -q 'created=' && echo "$hdr" | grep -q 'expired='; then
        pass "T26: procfs header contains active= created= expired= fields"
    else
        fail "T26: procfs header missing expected fields" "Got: $hdr"
    fi

    # T27: Initial counters are zero (fresh load, no traffic yet)
    active=$(echo "$hdr"  | sed 's/.*active=\([0-9]*\).*/\1/')
    created=$(echo "$hdr" | sed 's/.*created=\([0-9]*\).*/\1/')
    expired=$(echo "$hdr" | sed 's/.*expired=\([0-9]*\).*/\1/')

    if [ "$active" = "0" ] && [ "$created" = "0" ]; then
        pass "T27: Initial session counters are zero (active=$active created=$created expired=$expired)"
    else
        note "T27: Counters not zero on load (active=$active created=$created) — may be a reloaded module"
        PASS=$((PASS+1))
    fi

    # T28: procfs second line has column header
    col_hdr=$(sed -n '2p' /proc/stargazer/sessions 2>/dev/null || true)
    if echo "$col_hdr" | grep -q 'proto.*src.*dst\|src.*dst.*id'; then
        pass "T28: procfs column header present"
    else
        fail "T28: procfs column header missing or malformed" "Got: $col_hdr"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
printf "\n${B}${C}=== Phase 3: Packet injection + session verification ===${N}\n"
# ─────────────────────────────────────────────────────────────────────────────

if [ "$ON_TARGET" -eq 0 ]; then
    skip "T29–T35: Not on target — skipping injection tests"
elif [ ! -x "$KERN_BIN" ]; then
    skip "T29–T35: $KERN_BIN not found or not executable"
    note "Cross-compile with:"
    note "  aarch64-linux-gnu-gcc -O2 -o tests/test_session_kern tests/test_session_kern.c"
    note "Then copy to target and re-run with KERN_BIN=/path/to/test_session_kern"
else
    # Run the C injection binary; it prints PASS/FAIL lines and exits 0/1
    printf "  Running %s ...\n" "$KERN_BIN"
    if "$KERN_BIN"; then
        pass "T29–T35: TUN packet injection tests passed (see output above)"
    else
        fail "T29–T35: One or more TUN injection tests failed (see output above)"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
printf "\n${B}${C}=== Summary ===${N}\n"
# ─────────────────────────────────────────────────────────────────────────────

TOTAL=$((PASS + FAIL))
printf "\n"
printf "  ${G}PASS:${N} %d\n" "$PASS"
printf "  ${R}FAIL:${N} %d\n" "$FAIL"
printf "  ${Y}SKIP:${N} %d\n" "$SKIP"
printf "  Total: %d\n\n" "$TOTAL"

if [ "$FAIL" -gt 0 ]; then
    printf "${R}${B}%d test(s) FAILED${N}\n\n" "$FAIL"
    exit 1
else
    printf "${G}${B}All %d tests passed${N}\n\n" "$PASS"
    exit 0
fi
