#!/bin/bash
# security-scan.sh — Static analysis vulnerability scanner for Stargazer
#
# Runs independently (no API, no Claude session dependency).
# Emails findings via notify.sh as they're discovered.
#
# Usage: nohup ./scripts/security-scan.sh &
#
# Each finding is categorized by severity:
#   CRITICAL  — likely exploitable (injection, overflow, auth bypass)
#   HIGH      — dangerous pattern (race condition, missing bounds)
#   MEDIUM    — code smell that may lead to bugs
#   LOW       — informational / hardening suggestion

set -u

PROJECT="/home/rusted/projects/Stargazer"
SRC="$PROJECT/src"
NOTIFY="$HOME/.config/stargazer/notify.sh"
LOGFILE="$PROJECT/scripts/security-scan.log"
BATCH_INTERVAL=5   # seconds between file scans (be gentle on disk)

# Skip embedded third-party code
SKIP_PATTERNS="sqlite3\\.c|sqlite3\\.h|pkt_forward\\.mod\\.c"

# ── Helpers ──────────────────────────────────────────────────────────────

timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

log() { echo "[$(timestamp)] $*" | tee -a "$LOGFILE"; }

# Accumulate findings per file, send one email per file
FINDINGS=""
FINDING_COUNT=0

add_finding() {
    local severity="$1"
    local file="$2"
    local line="$3"
    local rule="$4"
    local detail="$5"

    FINDINGS="${FINDINGS}[$severity] Line $line: $rule
  $detail

"
    FINDING_COUNT=$((FINDING_COUNT + 1))
}

flush_findings() {
    local file="$1"
    if [ "$FINDING_COUNT" -gt 0 ]; then
        local relpath="${file#$PROJECT/}"
        local subject="[SecurityScan] $FINDING_COUNT finding(s) in $relpath"
        local body="Stargazer Security Scanner Report
File: $relpath
Date: $(timestamp)
Findings: $FINDING_COUNT

$FINDINGS
---
Automated scan — verify each finding manually."

        log "  -> Sending email: $FINDING_COUNT findings in $relpath"
        "$NOTIFY" "$subject" "$body" 2>/dev/null || \
            log "  !! Email send failed for $relpath"
    fi
    FINDINGS=""
    FINDING_COUNT=0
}

# grep helper: search file, report matches
# scan_pattern <severity> <rule_name> <grep_pattern> <description> <file>
scan_pattern() {
    local sev="$1" rule="$2" pattern="$3" desc="$4" file="$5"

    while IFS=: read -r lineno content; do
        [ -z "$lineno" ] && continue
        # Trim content for readability
        content="$(echo "$content" | sed 's/^[[:space:]]*//' | head -c 120)"
        add_finding "$sev" "$file" "$lineno" "$rule" "$desc: $content"
    done < <(grep -n -E "$pattern" "$file" 2>/dev/null || true)
}

# ── Vulnerability Rules ──────────────────────────────────────────────────

scan_c_file() {
    local f="$1"

    # ── CRITICAL: Buffer overflow ────────────────────────────────────
    scan_pattern "CRITICAL" "BOF-SPRINTF" \
        '\bsprintf\s*\(' \
        "sprintf without bounds — use snprintf" "$f"

    scan_pattern "CRITICAL" "BOF-STRCPY" \
        '\bstrcpy\s*\(' \
        "strcpy without bounds — use strncpy or snprintf" "$f"

    scan_pattern "CRITICAL" "BOF-STRCAT" \
        '\bstrcat\s*\(' \
        "strcat without bounds — use strncat or snprintf" "$f"

    scan_pattern "CRITICAL" "BOF-GETS" \
        '\bgets\s*\(' \
        "gets is always unsafe — use fgets" "$f"

    # ── CRITICAL: Command injection ──────────────────────────────────
    scan_pattern "CRITICAL" "INJ-SYSTEM" \
        '\bsystem\s*\(' \
        "system() call — check for user-controlled input" "$f"

    scan_pattern "CRITICAL" "INJ-POPEN" \
        '\bpopen\s*\(' \
        "popen() call — check for user-controlled input" "$f"

    # ── CRITICAL: Format string ──────────────────────────────────────
    # printf/fprintf/snprintf with variable as format (no string literal)
    scan_pattern "CRITICAL" "FMT-STRING" \
        '\b(printf|fprintf|syslog)\s*\([^"]*\b[a-z_][a-z0-9_]*\s*\)' \
        "Possible format string vulnerability — variable as format arg" "$f"

    # ── HIGH: Integer issues ─────────────────────────────────────────
    scan_pattern "HIGH" "INT-ATOI" \
        '\batoi\s*\(' \
        "atoi has no error detection — use strtol with errno check" "$f"

    scan_pattern "HIGH" "INT-ATOL" \
        '\batol\s*\(' \
        "atol has no error detection — use strtol with errno check" "$f"

    # ── HIGH: Race conditions ────────────────────────────────────────
    scan_pattern "HIGH" "RACE-ACCESS" \
        '\baccess\s*\(' \
        "access() is TOCTOU-prone — use open() and fstat() instead" "$f"

    scan_pattern "HIGH" "RACE-MKTEMP" \
        '\bmktemp\s*\(' \
        "mktemp is race-prone — use mkstemp" "$f"

    # ── HIGH: Memory safety ──────────────────────────────────────────
    # malloc/calloc/realloc without null check on next line
    scan_pattern "HIGH" "MEM-UNCHECKED" \
        '\b(malloc|calloc|realloc)\s*\(.*\)\s*;' \
        "Memory allocation — verify NULL check exists" "$f"

    # ── HIGH: Crypto / randomness ────────────────────────────────────
    scan_pattern "HIGH" "CRYPTO-RAND" \
        '\brand\s*\(\s*\)' \
        "rand() is not cryptographically secure — use /dev/urandom" "$f"

    scan_pattern "HIGH" "CRYPTO-SRAND" \
        '\bsrand\s*\(' \
        "srand+rand is predictable — use /dev/urandom for security" "$f"

    # ── MEDIUM: Dangerous functions ──────────────────────────────────
    scan_pattern "MEDIUM" "FUNC-STRTOK" \
        '\bstrtok\s*\(' \
        "strtok is not reentrant — use strtok_r in multi-threaded code" "$f"

    scan_pattern "MEDIUM" "FUNC-TMPNAM" \
        '\btmpnam\s*\(' \
        "tmpnam is race-prone — use mkstemp" "$f"

    scan_pattern "MEDIUM" "FUNC-REALPATH" \
        '\brealpath\s*\(' \
        "realpath may overflow — ensure buffer is PATH_MAX" "$f"

    # ── MEDIUM: File permission issues ───────────────────────────────
    scan_pattern "MEDIUM" "PERM-CHMOD-777" \
        '\bchmod\s*\([^,]*,\s*0?777\b' \
        "chmod 777 — world-writable file" "$f"

    scan_pattern "MEDIUM" "PERM-OPEN-WORLD" \
        '\bopen\s*\([^,]*,.*0666\b' \
        "open with 0666 — world-writable" "$f"

    # ── MEDIUM: Credential / secret patterns ─────────────────────────
    scan_pattern "MEDIUM" "CRED-HARDCODED" \
        '(password|passwd|secret|api_key|token)\s*=\s*"[^"]+' \
        "Possible hardcoded credential" "$f"

    # ── MEDIUM: Signal handler safety ────────────────────────────────
    scan_pattern "MEDIUM" "SIG-UNSAFE" \
        'signal\s*\(' \
        "signal() is not portable — use sigaction()" "$f"

    # ── LOW: Informational ───────────────────────────────────────────
    scan_pattern "LOW" "INFO-TODO-FIXME" \
        '(TODO|FIXME|HACK|XXX|VULN|BUG)' \
        "Developer annotation found" "$f"

    scan_pattern "LOW" "INFO-SETUID" \
        '\b(setuid|setgid|seteuid|setegid)\s*\(' \
        "Privilege change — verify proper ordering and error checks" "$f"

    scan_pattern "LOW" "INFO-EXEC" \
        '\b(execl|execle|execlp|execv|execve|execvp)\s*\(' \
        "exec call — verify arguments are not user-controlled" "$f"
}

scan_shell_file() {
    local f="$1"

    # ── CRITICAL: Shell injection ────────────────────────────────────
    scan_pattern "CRITICAL" "SH-EVAL" \
        '\beval\b' \
        "eval in shell script — high injection risk" "$f"

    scan_pattern "CRITICAL" "SH-BACKTICK-VAR" \
        '`.*\$' \
        "Backtick expansion with variable — injection risk" "$f"

    # ── HIGH: Unquoted variables ─────────────────────────────────────
    scan_pattern "HIGH" "SH-UNQUOTED" \
        '\$\{?[A-Za-z_][A-Za-z0-9_]*\}?[^"'\'')}]' \
        "Possibly unquoted variable — word splitting / glob risk" "$f"

    # ── MEDIUM: Dangerous shell patterns ─────────────────────────────
    scan_pattern "MEDIUM" "SH-CHMOD-777" \
        'chmod.*777' \
        "chmod 777 in script — world-writable" "$f"

    scan_pattern "MEDIUM" "SH-CURL-PIPE" \
        'curl.*\|\s*(bash|sh)' \
        "curl piped to shell — integrity risk" "$f"

    scan_pattern "MEDIUM" "SH-HARDCODED-CRED" \
        '(password|passwd|secret|token)\s*=' \
        "Possible hardcoded credential in shell" "$f"

    # ── LOW: Informational ───────────────────────────────────────────
    scan_pattern "LOW" "SH-TODO" \
        '(TODO|FIXME|HACK|XXX)' \
        "Developer annotation" "$f"
}

# ── Main ─────────────────────────────────────────────────────────────────

main() {
    log "=== Stargazer Security Scan Started ==="
    log "Project: $PROJECT"
    log "Scanning: $SRC"

    # Collect files
    local c_files sh_files
    c_files=$(find "$SRC" -name '*.c' -o -name '*.h' | \
              grep -v -E "$SKIP_PATTERNS" | sort)
    sh_files=$(find "$SRC" -name '*.sh' -o -name 'init' -o \
               -name 'stargazer-login' | sort)

    local total_c total_sh
    total_c=$(echo "$c_files" | wc -l)
    total_sh=$(echo "$sh_files" | wc -l)
    log "Files: $total_c C/H, $total_sh shell"

    # Scan C/H files
    local i=0
    for f in $c_files; do
        i=$((i + 1))
        local rel="${f#$PROJECT/}"
        log "[$i/$total_c] Scanning $rel"
        scan_c_file "$f"
        flush_findings "$f"
        sleep "$BATCH_INTERVAL"
    done

    # Scan shell files
    i=0
    for f in $sh_files; do
        i=$((i + 1))
        local rel="${f#$PROJECT/}"
        log "[$((total_c + i))/$((total_c + total_sh))] Scanning $rel"
        scan_shell_file "$f"
        flush_findings "$f"
        sleep "$BATCH_INTERVAL"
    done

    # Send summary email
    local summary="Stargazer Security Scan Complete
Date: $(timestamp)
Files scanned: $((total_c + total_sh)) ($total_c C/H, $total_sh shell)

Check individual emails for per-file findings.
Full log: $LOGFILE"

    "$NOTIFY" "[SecurityScan] Scan complete — $((total_c + total_sh)) files" \
              "$summary" 2>/dev/null

    log "=== Scan Complete ==="
}

main "$@"
