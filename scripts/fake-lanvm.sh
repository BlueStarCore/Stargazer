#!/bin/bash
# =============================================================================
# fake-lanvm.sh — Giả lập LAN VM bằng network namespace (không cần QEMU VM)
#
# Topology sau khi chạy:
#   Host (10.0.1.1, br-wan) → Stargazer FORWARD+NFQUEUE → br-lan → veth-fw
#                                                                      │
#                                                              netns "lanvm"
#                                                          (192.168.99.100)
#                                                           nc listeners trên
#                                                           port 21,22,80,443
#
# Traffic từ 10.0.1.1 → 192.168.99.100 đi qua FORWARD chain + ipsd đầy đủ.
# Dùng: sudo ./scripts/fake-lanvm.sh up
#        sudo ./scripts/fake-lanvm.sh down
#        sudo ./scripts/fake-lanvm.sh status
# =============================================================================

set -euo pipefail

NS="lanvm"
VETH_FW="veth-fw"
VETH_VM="veth-vm"
BRIDGE="br-lan"
VM_IP="192.168.99.100"
VM_GW="192.168.99.99"   # Stargazer LAN IP
VM_MASK="24"

die() { echo "ERROR: $*" >&2; exit 1; }

ns_exists()     { ip netns list 2>/dev/null | grep -q "^${NS}"; }
link_exists()   { ip link show "$1" &>/dev/null 2>&1; }
bridge_exists() { ip link show "$BRIDGE" &>/dev/null 2>&1; }

# ── up ───────────────────────────────────────────────────────────────────────
do_up() {
    [[ $EUID -eq 0 ]] || die "cần chạy bằng sudo"
    bridge_exists || die "Bridge $BRIDGE chưa có — chạy: sudo ./scripts/test_net_setup.sh up"

    echo "[fake-lanvm] Tạo network namespace '$NS'..."

    if ns_exists; then
        echo "  netns $NS đã tồn tại, bỏ qua"
    else
        ip netns add "$NS"
    fi

    if ! link_exists "$VETH_FW"; then
        ip link add "$VETH_FW" type veth peer name "$VETH_VM"
        echo "  tạo veth pair: $VETH_FW <-> $VETH_VM"
    fi

    # Gán veth-vm vào namespace
    if ! ip netns exec "$NS" ip link show "$VETH_VM" &>/dev/null 2>&1; then
        ip link set "$VETH_VM" netns "$NS"
        echo "  chuyển $VETH_VM vào netns $NS"
    fi

    # Gắn veth-fw vào br-lan
    if ! bridge link show | grep -q "$VETH_FW"; then
        ip link set "$VETH_FW" master "$BRIDGE"
        echo "  gắn $VETH_FW vào $BRIDGE"
    fi
    ip link set "$VETH_FW" up

    # Cấu hình interface trong namespace
    ip netns exec "$NS" ip link set lo up
    ip netns exec "$NS" ip link set "$VETH_VM" up

    if ! ip netns exec "$NS" ip addr show "$VETH_VM" | grep -q "$VM_IP"; then
        ip netns exec "$NS" ip addr add "${VM_IP}/${VM_MASK}" dev "$VETH_VM"
        echo "  gán IP $VM_IP/$VM_MASK cho $VETH_VM"
    fi

    if ! ip netns exec "$NS" ip route show | grep -q "default"; then
        ip netns exec "$NS" ip route add default via "$VM_GW"
        echo "  default route: $VM_GW (qua Stargazer)"
    fi

    # Khởi động listeners
    echo "[fake-lanvm] Khởi động nc listeners trong netns..."
    for port in 21 22 80 443 8080; do
        if ! ip netns exec "$NS" ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            ip netns exec "$NS" bash -c \
                "while true; do nc -lp ${port} -q 1 < /dev/null > /dev/null 2>&1; done" &
            echo "  listener trên port $port (PID $!)"
        fi
    done

    echo ""
    echo "[fake-lanvm] Sẵn sàng. Fake LAN VM: $VM_IP"
    echo "  Kiểm tra: ping -I br-wan $VM_IP (phải đi qua Stargazer)"
    echo "  Tấn công: sudo ./scripts/attack-host.sh all"
    echo "  Chặn:     sudo ./scripts/fake-lanvm.sh down"
}

# ── down ─────────────────────────────────────────────────────────────────────
do_down() {
    [[ $EUID -eq 0 ]] || die "cần chạy bằng sudo"

    echo "[fake-lanvm] Dọn dẹp..."

    # Kill tất cả process trong namespace
    if ns_exists; then
        ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns delete "$NS" 2>/dev/null && echo "  xóa netns $NS" || true
    fi

    # Xóa veth (xóa một đầu là xóa cả pair)
    if link_exists "$VETH_FW"; then
        ip link delete "$VETH_FW" 2>/dev/null && echo "  xóa veth pair" || true
    fi

    echo "  xong."
}

# ── status ───────────────────────────────────────────────────────────────────
do_status() {
    echo "=== fake-lanvm status ==="
    if ns_exists; then
        echo "netns '$NS': UP"
        ip netns exec "$NS" ip addr show "$VETH_VM" 2>/dev/null | grep -E 'inet |state'
        echo "listeners:"
        ip netns exec "$NS" ss -tlnp 2>/dev/null | grep -E 'LISTEN' || echo "  (không có)"
    else
        echo "netns '$NS': DOWN"
    fi
}

case "${1:-}" in
    up)     do_up ;;
    down)   do_down ;;
    status) do_status ;;
    *) echo "Dùng: sudo $0 {up|down|status}"; exit 1 ;;
esac
