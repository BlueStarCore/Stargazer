#!/bin/sh
# SPDX-License-Identifier: MIT
# ips-update-cron.sh — wrapper chạy bởi crond (daily). Đọc .update.conf do
# mgmtd ghi (auto-update + url_count + url_N); nếu bật thì gọi ips-update.sh
# cho từng URL. weekly → chỉ chạy Chủ nhật.
CONF=/etc/stargazer/ips/.update.conf
UPD=/usr/libexec/stargazer/ips-update.sh
[ -f "$CONF" ] || exit 0

enabled=""; url_count=0
while IFS='=' read -r k v; do
    case "$k" in
        enabled)   enabled=$v ;;
        url_count) url_count=$v ;;
    esac
done < "$CONF"

[ "$enabled" = "disable" ] || [ -z "$enabled" ] && exit 0
if [ "$enabled" = "weekly" ] && [ "$(date +%u 2>/dev/null)" != "7" ]; then
    exit 0
fi

[ "$url_count" -gt 0 ] 2>/dev/null || exit 0

i=0
while [ "$i" -lt "$url_count" ]; do
    url=$(grep "^url_${i}=" "$CONF" | cut -d= -f2-)
    if [ -n "$url" ]; then
        base=$(basename "$url")
        cat=$(echo "$base" | sed 's/^emerging-//; s/\.rules$//')
        [ -n "$cat" ] || cat=custom
        "$UPD" "$url" "$cat" || true
    fi
    i=$((i + 1))
done
