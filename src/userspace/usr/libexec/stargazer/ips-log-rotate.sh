#!/bin/sh
# SPDX-License-Identifier: MIT
# ips-log-rotate.sh — rotate /etc/stargazer/logs/ips-alert.log by size,
# then send SIGHUP to ipsd so it closes+reopens its fd (same mechanism as
# Suricata's logrotate). The busybox target has NO logrotate, so we do a
# minimal version here.
#
# Flow:
#   1. File exceeds MAXSZ → rename .log → .log.1 (.1→.2 … up to KEEP, oldest deleted).
#      ipsd still holds an fd to the old .log.1 inode → no alert in progress is lost.
#   2. Send SIGHUP to the pid in PIDFILE → ipsd closes the old fd, reopens "ips-alert.log".
#      Since the original was renamed, open() creates a NEW empty file → next alerts go there.
#   3. SIGHUP fails (ipsd not running) → skip; ipsd recreates it on its next write.
#
# Usage:  ips-log-rotate.sh            (default 5 MB, keep 5 copies)
#         ips-log-rotate.sh <maxbytes> <keep>
set -u

LOG=/etc/stargazer/logs/ips-alert.log
PIDFILE=/run/stargazer-ipsd.pid
MAXSZ=${1:-5242880}     # 5 MB
KEEP=${2:-5}

[ -f "$LOG" ] || exit 0

# Current size (busybox stat -c%s). Error → treat as no rotation needed yet.
sz=$(stat -c%s "$LOG" 2>/dev/null) || exit 0
[ "$sz" -ge "$MAXSZ" ] 2>/dev/null || exit 0

# Shift old copies: .(KEEP-1) -> .KEEP, ..., .1 -> .2; the oldest .KEEP is overwritten.
i=$((KEEP - 1))
while [ "$i" -ge 1 ]; do
    [ -f "$LOG.$i" ] && mv -f "$LOG.$i" "$LOG.$((i + 1))"
    i=$((i - 1))
done
mv -f "$LOG" "$LOG.1"

# Tell ipsd to reopen. No pid / kill fails → ipsd reopens on its next write
# (log_alert: g_alert_fd<0 → log_open), so this isn't required, just for an immediate switch.
if [ -r "$PIDFILE" ]; then
    pid=$(cat "$PIDFILE" 2>/dev/null)
    [ -n "$pid" ] && kill -HUP "$pid" 2>/dev/null || true
fi

exit 0
