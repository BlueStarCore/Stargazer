#!/bin/sh
# SPDX-License-Identifier: MIT
# ips-log-rotate.sh — xoay /etc/stargazer/logs/ips-alert.log theo kích thước,
# rồi gửi SIGHUP cho ipsd để nó đóng+mở lại fd (giống cơ chế logrotate của
# Suricata). Target busybox KHÔNG có logrotate nên tự làm tối giản ở đây.
#
# Luồng:
#   1. File vượt MAXSZ → rename .log → .log.1 (.1→.2 … tới KEEP, cũ nhất bị xoá).
#      ipsd vẫn đang giữ fd vào inode .log.1 cũ → không mất alert đang ghi.
#   2. Gửi SIGHUP tới pid trong PIDFILE → ipsd close fd cũ, open lại "ips-alert.log".
#      Vì file gốc đã đổi tên, open() tạo file MỚI rỗng → alert tiếp theo vào đó.
#   3. Không SIGHUP được (ipsd không chạy) → bỏ qua, lần ghi sau ipsd tự tạo lại.
#
# Dùng:  ips-log-rotate.sh            (mặc định 5 MB, giữ 5 bản)
#        ips-log-rotate.sh <maxbytes> <keep>
set -u

LOG=/etc/stargazer/logs/ips-alert.log
PIDFILE=/run/stargazer-ipsd.pid
MAXSZ=${1:-5242880}     # 5 MB
KEEP=${2:-5}

[ -f "$LOG" ] || exit 0

# Kích thước hiện tại (busybox stat -c%s). Lỗi → coi như chưa cần xoay.
sz=$(stat -c%s "$LOG" 2>/dev/null) || exit 0
[ "$sz" -ge "$MAXSZ" ] 2>/dev/null || exit 0

# Dịch các bản cũ: .(KEEP-1) -> .KEEP, ..., .1 -> .2; bản .KEEP cũ nhất bị ghi đè.
i=$((KEEP - 1))
while [ "$i" -ge 1 ]; do
    [ -f "$LOG.$i" ] && mv -f "$LOG.$i" "$LOG.$((i + 1))"
    i=$((i - 1))
done
mv -f "$LOG" "$LOG.1"

# Báo ipsd reopen. Không có pid / kill fail → ipsd sẽ tự mở lại ở lần write kế
# (log_alert: g_alert_fd<0 → log_open) nên không bắt buộc, chỉ để chuyển ngay.
if [ -r "$PIDFILE" ]; then
    pid=$(cat "$PIDFILE" 2>/dev/null)
    [ -n "$pid" ] && kill -HUP "$pid" 2>/dev/null || true
fi

exit 0
