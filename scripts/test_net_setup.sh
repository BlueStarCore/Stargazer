#!/bin/bash
# =============================================================================
# Stargazer NGFW — Host network setup for QEMU test environment
# =============================================================================
#
# Creates bridges, TAP interfaces, and NAT rules for the three-node test
# topology:
#
#   Internet <-> Host (masquerade) <-> br-wan (10.0.1.0/24) <-> Stargazer VM
#                                      10.0.1.1                  eth0 (WAN)
#                                                                eth1 (LAN)
#                                                         br-lan (192.168.99.0/24)
#                                                           192.168.99.99 (mgmt)
#                                                                192.168.99.100
#                                                                LAN VM
#
# Usage:  sudo ./scripts/test_net_setup.sh up
#         sudo ./scripts/test_net_setup.sh down
# =============================================================================

set -euo pipefail

BR_WAN="br-wan"
BR_LAN="br-lan"
TAP_SG_WAN="tap-sg-wan"
TAP_SG_LAN="tap-sg-lan"
TAP_LAN_VM="tap-lan-vm"

WAN_IP="10.0.1.1/24"
TAPS=("$TAP_SG_WAN" "$TAP_SG_LAN" "$TAP_LAN_VM")

# Resolve the real user (works under sudo)
TAP_USER="${SUDO_USER:-$(whoami)}"

die() { echo "ERROR: $*" >&2; exit 1; }

# Auto-detect the host's internet-facing interface
detect_wan_iface() {
    ip route get 8.8.8.8 2>/dev/null | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -n 1
}

# ── helpers ──────────────────────────────────────────────────────────────────

bridge_exists()  { ip link show "$1" &>/dev/null; }
tap_exists()     { ip link show "$1" &>/dev/null; }

create_bridge() {
    local name="$1"
    if bridge_exists "$name"; then
        echo "  bridge $name already exists"
    else
        ip link add name "$name" type bridge
        ip link set "$name" up
        echo "  created bridge $name"
    fi
}

create_tap() {
    local name="$1" bridge="$2"
    if tap_exists "$name"; then
        echo "  tap $name already exists"
    else
        ip tuntap add dev "$name" mode tap user "$TAP_USER"
        ip link set "$name" up
        ip link set "$name" master "$bridge"
        echo "  created tap $name -> $bridge (owner $TAP_USER)"
    fi
}

# ── up ───────────────────────────────────────────────────────────────────────

do_up() {
    [[ $EUID -eq 0 ]] || die "must run as root (use sudo)"

    local wan_iface
    wan_iface=$(detect_wan_iface)
    [[ -n "$wan_iface" ]] || die "cannot detect internet interface"
    echo "Host internet interface: $wan_iface"

    echo "Creating bridges..."
    create_bridge "$BR_WAN"
    create_bridge "$BR_LAN"

    # Assign IP to br-wan (host side of the WAN subnet)
    if ! ip addr show "$BR_WAN" | grep -q "${WAN_IP%/*}"; then
        ip addr add "$WAN_IP" dev "$BR_WAN"
        echo "  assigned $WAN_IP to $BR_WAN"
    fi

    echo "Creating TAP interfaces..."
    create_tap "$TAP_SG_WAN" "$BR_WAN"
    create_tap "$TAP_SG_LAN" "$BR_LAN"
    create_tap "$TAP_LAN_VM" "$BR_LAN"

    echo "Setting up routes..."
    # Host needs a route to the LAN subnet via Stargazer's WAN IP.
    # Use "via $gw dev $br" so the kernel installs the route even while
    # br-wan is still linkdown (no QEMU connected yet).
    if ! ip route show 192.168.99.0/24 2>/dev/null | grep -q "192.168.99.0/24"; then
        ip route add 192.168.99.0/24 via 10.0.1.2 dev "$BR_WAN"
        echo "  added route 192.168.99.0/24 via 10.0.1.2 dev $BR_WAN"
    fi

    echo "Setting up NAT (masquerade)..."
    # Masquerade WAN subnet to the internet
    if ! iptables -t nat -C POSTROUTING -s 10.0.1.0/24 -o "$wan_iface" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o "$wan_iface" -j MASQUERADE
        echo "  added MASQUERADE rule (10.0.1.0/24)"
    fi
    # Masquerade LAN subnet to the internet (packets forwarded by Stargazer
    # arrive at the host with their original 192.168.99.x source since
    # Stargazer has no iptables — the host must NAT them)
    if ! iptables -t nat -C POSTROUTING -s 192.168.99.0/24 -o "$wan_iface" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s 192.168.99.0/24 -o "$wan_iface" -j MASQUERADE
        echo "  added MASQUERADE rule (192.168.99.0/24)"
    fi

    # Allow forwarding for br-wan traffic
    if ! iptables -C FORWARD -i "$BR_WAN" -o "$wan_iface" -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i "$BR_WAN" -o "$wan_iface" -j ACCEPT
        echo "  added FORWARD rule (br-wan -> $wan_iface)"
    fi
    if ! iptables -C FORWARD -i "$wan_iface" -o "$BR_WAN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        iptables -A FORWARD -i "$wan_iface" -o "$BR_WAN" -m state --state RELATED,ESTABLISHED -j ACCEPT
        echo "  added FORWARD rule ($wan_iface -> br-wan, established)"
    fi

    # Enable IP forwarding on host
    sysctl -q net.ipv4.ip_forward=1

    echo ""
    echo "Network ready. Launch VMs in separate terminals:"
    echo "  Terminal 2: ./scripts/run_firewall.sh"
    echo "  Terminal 3: ./scripts/run_lanvm.sh"
}

# ── down ─────────────────────────────────────────────────────────────────────

do_down() {
    [[ $EUID -eq 0 ]] || die "must run as root (use sudo)"

    local wan_iface
    wan_iface=$(detect_wan_iface) || true

    echo "Removing routes..."
    ip route del 192.168.99.0/24 2>/dev/null && echo "  removed route 192.168.99.0/24" || true

    echo "Removing iptables rules..."
    if [[ -n "$wan_iface" ]]; then
        iptables -t nat -D POSTROUTING -s 10.0.1.0/24 -o "$wan_iface" -j MASQUERADE 2>/dev/null && echo "  removed MASQUERADE (10.0.1.0/24)" || true
        iptables -t nat -D POSTROUTING -s 192.168.99.0/24 -o "$wan_iface" -j MASQUERADE 2>/dev/null && echo "  removed MASQUERADE (192.168.99.0/24)" || true
        iptables -D FORWARD -i "$BR_WAN" -o "$wan_iface" -j ACCEPT 2>/dev/null && echo "  removed FORWARD (out)" || true
        iptables -D FORWARD -i "$wan_iface" -o "$BR_WAN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null && echo "  removed FORWARD (in)" || true
    fi

    echo "Removing TAP interfaces..."
    for tap in "${TAPS[@]}"; do
        if tap_exists "$tap"; then
            ip link set "$tap" down 2>/dev/null || true
            ip link delete "$tap" 2>/dev/null || true
            echo "  deleted $tap"
        fi
    done

    echo "Removing bridges..."
    for br in "$BR_WAN" "$BR_LAN"; do
        if bridge_exists "$br"; then
            ip link set "$br" down 2>/dev/null || true
            ip link delete "$br" type bridge 2>/dev/null || true
            echo "  deleted $br"
        fi
    done

    echo "Teardown complete."
}

# ── main ─────────────────────────────────────────────────────────────────────

case "${1:-}" in
    up)   do_up   ;;
    down) do_down ;;
    *)    echo "Usage: sudo $0 {up|down}"; exit 1 ;;
esac
