#!/bin/bash
# =============================================================================
# fake-lanvm.sh — Simulate a LAN VM with a network namespace (no QEMU VM needed)
#
# Topology after running:
#   Host (10.0.1.1, br-wan) → Stargazer FORWARD+NFQUEUE → br-lan → veth-fw
#                                                                      │
#                                                              netns "lanvm"
#                                                          (192.168.99.100)
#                                                           nc listeners on
#                                                           port 21,22,80,443
#
# Traffic from 10.0.1.1 → 192.168.99.100 goes through the full FORWARD chain + ipsd.
# Usage: sudo ./scripts/fake-lanvm.sh up
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
    [[ $EUID -eq 0 ]] || die "must run with sudo"
    bridge_exists || die "Bridge $BRIDGE does not exist — run: sudo ./scripts/test_net_setup.sh up"

    echo "[fake-lanvm] Creating network namespace '$NS'..."

    if ns_exists; then
        echo "  netns $NS already exists, skipping"
    else
        ip netns add "$NS"
    fi

    if ! link_exists "$VETH_FW"; then
        ip link add "$VETH_FW" type veth peer name "$VETH_VM"
        echo "  create veth pair: $VETH_FW <-> $VETH_VM"
    fi

    # Move veth-vm into the namespace
    if ! ip netns exec "$NS" ip link show "$VETH_VM" &>/dev/null 2>&1; then
        ip link set "$VETH_VM" netns "$NS"
        echo "  move $VETH_VM into netns $NS"
    fi

    # Attach veth-fw to br-lan
    if ! bridge link show | grep -q "$VETH_FW"; then
        ip link set "$VETH_FW" master "$BRIDGE"
        echo "  attach $VETH_FW to $BRIDGE"
    fi
    ip link set "$VETH_FW" up

    # Configure interface inside the namespace
    ip netns exec "$NS" ip link set lo up
    ip netns exec "$NS" ip link set "$VETH_VM" up

    if ! ip netns exec "$NS" ip addr show "$VETH_VM" | grep -q "$VM_IP"; then
        ip netns exec "$NS" ip addr add "${VM_IP}/${VM_MASK}" dev "$VETH_VM"
        echo "  assign IP $VM_IP/$VM_MASK to $VETH_VM"
    fi

    if ! ip netns exec "$NS" ip route show | grep -q "default"; then
        ip netns exec "$NS" ip route add default via "$VM_GW"
        echo "  default route: $VM_GW (via Stargazer)"
    fi

    # Start listeners
    echo "[fake-lanvm] Starting nc listeners in netns..."
    for port in 21 22 80 443 8080; do
        if ! ip netns exec "$NS" ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            ip netns exec "$NS" bash -c \
                "while true; do nc -lp ${port} -q 1 < /dev/null > /dev/null 2>&1; done" &
            echo "  listener on port $port (PID $!)"
        fi
    done

    echo ""
    echo "[fake-lanvm] Ready. Fake LAN VM: $VM_IP"
    echo "  Check:  ping -I br-wan $VM_IP (must go through Stargazer)"
    echo "  Attack: sudo ./scripts/attack-host.sh all"
    echo "  Stop:   sudo ./scripts/fake-lanvm.sh down"
}

# ── down ─────────────────────────────────────────────────────────────────────
do_down() {
    [[ $EUID -eq 0 ]] || die "must run with sudo"

    echo "[fake-lanvm] Cleaning up..."

    # Kill all processes in the namespace
    if ns_exists; then
        ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns delete "$NS" 2>/dev/null && echo "  delete netns $NS" || true
    fi

    # Delete veth (deleting one end deletes the whole pair)
    if link_exists "$VETH_FW"; then
        ip link delete "$VETH_FW" 2>/dev/null && echo "  delete veth pair" || true
    fi

    echo "  done."
}

# ── status ───────────────────────────────────────────────────────────────────
do_status() {
    echo "=== fake-lanvm status ==="
    if ns_exists; then
        echo "netns '$NS': UP"
        ip netns exec "$NS" ip addr show "$VETH_VM" 2>/dev/null | grep -E 'inet |state'
        echo "listeners:"
        ip netns exec "$NS" ss -tlnp 2>/dev/null | grep -E 'LISTEN' || echo "  (none)"
    else
        echo "netns '$NS': DOWN"
    fi
}

case "${1:-}" in
    up)     do_up ;;
    down)   do_down ;;
    status) do_status ;;
    *) echo "Usage: sudo $0 {up|down|status}"; exit 1 ;;
esac
