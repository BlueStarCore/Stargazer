#!/bin/sh
# SPDX-License-Identifier: MIT
# ips-update-cron.sh — run every minute by crond. Reads the scheduled-update
# spec from .update.conf (written by mgmtd from the WebUI Schedule tab / the
# security_ips cron-* keys) and, when the current time matches the five cron
# fields, asks mgmtd to update every enabled ruleset via SG_CMD_IPS_UPDATE_NOW —
# the SAME path the WebUI "Update Now" button uses, so a scheduled run stamps
# last-downloaded and hot-reloads ipsd identically to a manual update.
#
# The crontab entry is a fixed "* * * * *" — the schedule the user configures
# lives here, matched against the wall clock, because the root filesystem is
# read-only and mgmtd cannot rewrite the crontab at runtime.
#
#   ips-update-cron.sh        → scheduled run (checks the cron time gate)
#   ips-update-cron.sh now    → force a run right now, skipping the gate

# crond (and the CLI exec sandbox) may hand us an empty PATH, so date/grep/cut
# would not be found and the gate would silently misfire. Set it.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

CONF=/etc/stargazer/ips/.update.conf
STAMP=/run/stargazer-ips-update.lastrun
IPC=/sbin/stargazer-ipc-cli
LOG=/etc/stargazer/logs/ips-update.log
SG_CMD_IPS_UPDATE_NOW=688

[ -f "$CONF" ] || exit 0

FORCE=0
[ "$1" = "now" ] && FORCE=1

cron_enabled=disable
cron_min=0; cron_hour=0; cron_dom='*'; cron_mon='*'; cron_dow='*'
ids=""
while IFS='=' read -r k v; do
    case "$k" in
        cron_enabled) cron_enabled=$v ;;
        cron_min)     cron_min=$v ;;
        cron_hour)    cron_hour=$v ;;
        cron_dom)     cron_dom=$v ;;
        cron_mon)     cron_mon=$v ;;
        cron_dow)     cron_dow=$v ;;
        ids)          ids=$v ;;
    esac
done < "$CONF"

# Match ONE cron field. Supports the same syntax the WebUI validates:
#   *  |  N  |  a,b,c  |  a-b  |  */n  |  a-b/n
#   $1 current value  $2 spec  $3 field min  $4 field max
cron_field_match() {
    _cur=$1; _spec=$2; _fmin=$3; _fmax=$4
    [ "$_spec" = '*' ] && return 0
    _oldifs=$IFS; IFS=','
    for _part in $_spec; do
        IFS=$_oldifs
        _step=1; _range=$_part
        case "$_part" in */*) _range=${_part%/*}; _step=${_part#*/} ;; esac
        [ "$_step" -ge 1 ] 2>/dev/null || _step=1     # guard against /0
        case "$_range" in
            '*') _lo=$_fmin; _hi=$_fmax ;;
            *-*) _lo=${_range%-*}; _hi=${_range#*-} ;;
            *)   _lo=$_range; _hi=$_range ;;
        esac
        # numeric guard — skip a malformed segment rather than misfire
        case "$_lo$_hi" in ''|*[!0-9]*) IFS=','; continue ;; esac
        _i=$_lo
        while [ "$_i" -le "$_hi" ]; do
            [ "$_i" -eq "$_cur" ] && { IFS=$_oldifs; return 0; }
            _i=$((_i + _step))
        done
        IFS=','
    done
    IFS=$_oldifs
    return 1
}

if [ "$FORCE" != 1 ]; then
    [ "$cron_enabled" = "enable" ] || exit 0

    # Strip a single leading zero the POSIX way ("09"->"9"); busybox ash has no
    # $((10#..)) so "08"/"09" would otherwise be read as invalid octal.
    now_min=$(date +%M 2>/dev/null);  now_min=${now_min#0};  [ -n "$now_min" ] || exit 0
    now_hour=$(date +%H 2>/dev/null); now_hour=${now_hour#0}
    now_dom=$(date +%d 2>/dev/null);  now_dom=${now_dom#0}
    now_mon=$(date +%m 2>/dev/null);  now_mon=${now_mon#0}
    now_dow=$(date +%w 2>/dev/null)   # 0=Sun..6=Sat — matches cron/GUI

    cron_field_match "${now_min:-0}"  "$cron_min"  0 59 || exit 0
    cron_field_match "${now_hour:-0}" "$cron_hour" 0 23 || exit 0
    cron_field_match "${now_mon:-1}"  "$cron_mon"  1 12 || exit 0

    # Standard cron day rule: if BOTH day-of-month and day-of-week are
    # restricted, the job runs when EITHER matches; otherwise both must match
    # (a '*' field always matches).
    _dom_ok=1; _dow_ok=1
    [ "$cron_dom" != '*' ] && { cron_field_match "${now_dom:-1}" "$cron_dom" 1 31 || _dom_ok=0; }
    [ "$cron_dow" != '*' ] && { cron_field_match "${now_dow:-0}" "$cron_dow" 0 6  || _dow_ok=0; }
    if [ "$cron_dom" != '*' ] && [ "$cron_dow" != '*' ]; then
        [ "$_dom_ok" = 1 ] || [ "$_dow_ok" = 1 ] || exit 0
    else
        { [ "$_dom_ok" = 1 ] && [ "$_dow_ok" = 1 ]; } || exit 0
    fi

    # De-duplicate within the same minute (crond may fire us more than once).
    stamp_now=$(date +%Y%m%d%H%M 2>/dev/null)
    [ "$(cat "$STAMP" 2>/dev/null)" = "$stamp_now" ] && exit 0
    echo "$stamp_now" > "$STAMP"
fi

[ -n "$ids" ] || exit 0

# Hand the enabled ruleset IDs to mgmtd's Update-Now path (downloads + stamps
# last-downloaded + rebuilds + hot-reloads). SG_CMD_IPS_UPDATE_NOW ignores the
# caller identity, so this works from crond without a login session.
ts=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
if [ -x "$IPC" ]; then
    out=$("$IPC" "$SG_CMD_IPS_UPDATE_NOW" "$ids" 2>&1)
    echo "$ts $([ "$FORCE" = 1 ] && echo forced || echo scheduled) update (ids=$ids): $out" >> "$LOG" 2>/dev/null
    echo "$out"
else
    echo "$ts scheduled update SKIPPED: $IPC missing" >> "$LOG" 2>/dev/null
    echo "SKIPPED: $IPC missing"
fi
