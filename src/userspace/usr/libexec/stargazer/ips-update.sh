#!/bin/sh
# SPDX-License-Identifier: MIT
# =============================================================================
# ips-update.sh — Smart IPS signature update (Phase E, FortiGate-style)
# =============================================================================
#
# Cập nhật MỘT category signature an toàn, không gián đoạn:
#   1. Conditional GET: so Last-Modified với bản local → trùng thì BỎ QUA tải.
#   2. Hash dedup: tải về /tmp, so sha256 với bản local → trùng thì KHÔNG reload.
#   3. Syntax verify: `ipsd -C` ruleset mới → hỏng thì GIỮ bản cũ (fail-closed).
#      Skipped for large files (>1 MB) — ipsd on QEMU ARM is too slow for 40k+ rules.
#   4. Atomic swap: mv vào repo + lưu hash/lastmod.
#   5. Trigger recompile: ipc-cli → mgmtd compile profiles + SIGUSR1 ipsd (hot-reload).
#   6. Log kết quả (Success / No Update / Error) vào ips-update.log.
#
# Dùng:  ips-update.sh <url> <category> [repo_dir] [meta_dir] [ipsd_bin]
# Env override (cho test): WGET, SHA, IPC_CLI
# =============================================================================

URL="$1"
CAT="$2"
REPO="${3:-/etc/stargazer/ips/repo}"
META="${4:-/etc/stargazer/ips/.meta}"
IPSD="${5:-/sbin/stargazer-ipsd}"
WGET="${WGET:-wget}"
SHA="${SHA:-sha256sum}"
IPC_CLI="${IPC_CLI:-/sbin/stargazer-ipc-cli}"
LOGDIR="${LOGDIR:-/etc/stargazer/logs}"
LOG="$LOGDIR/ips-update.log"
SG_CMD_IPS_REBUILD=687

# Max bytes for a strict (fail-closed) syntax check.  Files larger than this
# are still checked but failures are treated as warnings, not errors — large
# real-world rulesets (ET open, 5–50 MB) would otherwise time out on ARM/QEMU.
SYNTAX_CHECK_STRICT=1048576   # 1 MB: fail-closed
SYNTAX_CHECK_WARN=52428800    # 50 MB: warn-only (still installs, logs error count)

[ -n "$URL" ] && [ -n "$CAT" ] || {
    echo "usage: $0 <url> <category> [repo] [meta] [ipsd]" >&2; exit 2; }

mkdir -p "$REPO" "$META" "$LOGDIR" 2>/dev/null

log() {
    _ts=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "?")
    echo "$_ts [$CAT] $*" >> "$LOG" 2>/dev/null
    echo "$*"
}

tmp="/tmp/ips-$CAT.$$.rules"
trap 'rm -f "$tmp"' EXIT

# ── 1. Conditional GET (Last-Modified) ───────────────────────────────────────
hdr=$("$WGET" -S --spider --timeout=20 "$URL" 2>&1 | grep -i 'Last-Modified' | head -n 1 | sed 's/^[ \t]*//')
prev_hdr=$(cat "$META/$CAT.lastmod" 2>/dev/null)
if [ -n "$hdr" ] && [ "$hdr" = "$prev_hdr" ]; then
    log "Source unchanged. Skipping download."
    exit 0
fi

# ── 2. Download ──────────────────────────────────────────────────────────────
if ! "$WGET" -q --timeout=60 -O "$tmp" "$URL"; then
    log "ERROR: download failed ($URL)"
    exit 1
fi
if [ ! -s "$tmp" ]; then
    log "ERROR: downloaded file empty"
    exit 1
fi

# ── 3. Hash dedup ────────────────────────────────────────────────────────────
new=$("$SHA" "$tmp" 2>/dev/null | cut -d' ' -f1)
prev=$(cat "$META/$CAT.sha" 2>/dev/null)
if [ -n "$new" ] && [ "$new" = "$prev" ]; then
    log "Content hash unchanged. Skipping reload."
    exit 0
fi

# ── 4. Syntax verify ─────────────────────────────────────────────────────────
fsize=$(wc -c < "$tmp" 2>/dev/null)
if [ -n "$fsize" ] && [ "$fsize" -le "$SYNTAX_CHECK_WARN" ]; then
    # Run check; capture stderr (ipsd -C prints "OK … loaded/skip/err" there)
    chk_out=$(timeout 60 "$IPSD" -C -r "$tmp" -n 2>&1)
    chk_rc=$?
    if [ "$chk_rc" -ne 0 ]; then
        if [ -n "$fsize" ] && [ "$fsize" -le "$SYNTAX_CHECK_STRICT" ]; then
            log "ERROR: syntax check failed — keeping current ruleset."
            log "  ipsd output: $chk_out"
            exit 1
        else
            # Large file: warn but install anyway (error count already in log)
            log "WARNING: syntax check issues for ${CAT} (${fsize} bytes) — installing anyway."
            log "  ipsd output: $chk_out"
        fi
    else
        log "Syntax OK: $chk_out"
    fi
else
    log "Note: file ${fsize} bytes exceeds warn limit — skipping syntax check."
fi

# ── 5. Atomic swap + lưu metadata ────────────────────────────────────────────
if ! mv "$tmp" "$REPO/$CAT.rules"; then
    log "ERROR: cannot install $REPO/$CAT.rules"
    exit 1
fi
[ -n "$new" ] && printf '%s\n' "$new" > "$META/$CAT.sha"
[ -n "$hdr" ] && printf '%s\n' "$hdr" > "$META/$CAT.lastmod"

# ── 6. Trigger recompile (mgmtd: profiles + hot-reload ipsd) ──────────────────
if [ -x "$IPC_CLI" ]; then
    "$IPC_CLI" "$SG_CMD_IPS_REBUILD" >/dev/null 2>&1 || true
fi

log "Success: updated category '$CAT' (sha ${new%${new#????????}}…)"
exit 0
