#!/bin/sh
# SPDX-License-Identifier: MIT
# ips-report-cron.sh — wrapper run every minute by crond. Reads .schedule.conf
# written by mgmtd (mode=off|daily|weekly, hour, minute, day) and asks mgmtd to
# generate a scheduled IPS/IDS report when the current time (HH:MM, and for
# weekly the day) matches.
#
#   ips-report-cron.sh          → normal scheduled run (checks the time gate)
#   ips-report-cron.sh now      → force a generate right now, skipping the gate
#                                 (manual test of the scheduled-generate path)

# crond (and the CLI exec sandbox) may run us with an empty PATH, so external
# applets like `date`/`cat` are not found and silently produce nothing. Set it.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

CONF=/etc/stargazer/reports/.schedule.conf
STAMP=/run/stargazer-report.lastrun
IPC=/sbin/stargazer-ipc-cli
LOG=/etc/stargazer/logs/ips-report.log
SG_CMD_REPORT_GENERATE=696

FORCE=0
[ "$1" = "now" ] && FORCE=1

# Config is required for a scheduled run; a forced run tolerates its absence.
if [ ! -f "$CONF" ] && [ "$FORCE" != 1 ]; then
    exit 0
fi

mode=""; conf_hour=""; conf_min=""; conf_day=""
if [ -f "$CONF" ]; then
    while IFS='=' read -r k v; do
        case "$k" in
            mode)   mode=$v ;;
            hour)   conf_hour=$v ;;
            minute) conf_min=$v ;;
            day)    conf_day=$v ;;
        esac
    done < "$CONF"
fi
[ -z "$conf_min" ] && conf_min=0

if [ "$FORCE" != 1 ]; then
    # off / unset → nothing to do.
    [ "$mode" = "off" ] || [ -z "$mode" ] && exit 0

    # Match the configured HH:MM. Strip a single leading zero the POSIX way
    # ("09"→"9", "00"→"0") — busybox ash has NO bash-style $((10#..)) notation.
    now_h=$(date +%H 2>/dev/null); now_h=${now_h#0}
    now_m=$(date +%M 2>/dev/null); now_m=${now_m#0}
    [ "$now_h" = "$conf_hour" ] || exit 0
    [ "$now_m" = "$conf_min" ]  || exit 0

    # Weekly → only on the configured day-of-week (1=Mon .. 7=Sun).
    if [ "$mode" = "weekly" ]; then
        now_d=$(date +%u 2>/dev/null)
        [ "$now_d" = "$conf_day" ] || exit 0
    fi

    # De-duplicate within the same minute (crond may fire us more than once).
    stamp_now=$(date +%Y%m%d%H%M 2>/dev/null)
    [ "$(cat "$STAMP" 2>/dev/null)" = "$stamp_now" ] && exit 0
    echo "$stamp_now" > "$STAMP"
fi

# daily → last 1 day; weekly → last 7 days; forced run defaults to 1 day.
range=1
[ "$mode" = "weekly" ] && range=7

ts=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
if [ -x "$IPC" ]; then
    # Payload is newline-separated key=value (extract_val parses up to newline).
    out=$("$IPC" "$SG_CMD_REPORT_GENERATE" "range=$range
type=scheduled" 2>&1)
    echo "$ts $([ "$FORCE" = 1 ] && echo forced || echo scheduled) generate (mode=$mode range=$range): $out" >> "$LOG" 2>/dev/null
    echo "generate result: $out"
else
    echo "$ts generate SKIPPED: $IPC missing" >> "$LOG" 2>/dev/null
    echo "SKIPPED: $IPC missing"
fi
