# Stargazer Routing & Forwarding Guide

## Overview
Stargazer NGFW implements packet forwarding and routing functionality for the BPI-R4 router platform.

## Features Enabled

### 1. IP Forwarding (Kernel Level)
```bash
# Automatically enabled by init script
echo 1 > /proc/sys/net/ipv4/ip_forward
```

This allows the kernel to forward packets between network interfaces.

### 2. Netfilter Hook (Module Level)
The `pkt_forward.ko` module registers a Netfilter hook at `NF_INET_FORWARD` priority `NF_IP_PRI_FIRST`.

**Hook Flow:**
```
Packet arrives -> PREROUTING -> ROUTING DECISION -> FORWARD -> POSTROUTING -> Packet leaves
                                                        ↑
                                                 pkt_forward.ko hook
```

### 3. Reverse Path Filter Disabled
```bash
# Allow asymmetric routing (packets can take different paths)
echo 0 > /proc/sys/net/ipv4/conf/*/rp_filter
```

## Routing Example

### Basic LAN-to-WAN Routing
```bash
# BPI-R4 interface setup example:
# eth0 = WAN (10.0.0.1/24)
# eth1 = LAN (192.168.1.1/24)

# Configure interfaces
ip addr add 10.0.0.1/24 dev eth0
ip addr add 192.168.1.1/24 dev eth1
ip link set eth0 up
ip link set eth1 up

# Set default route via WAN gateway
ip route add default via 10.0.0.254 dev eth0

# LAN clients use 192.168.1.1 as gateway
# Packets from 192.168.1.0/24 -> Internet will be forwarded
```

### NAT/Masquerading (Optional)
For internet sharing, add iptables NAT:
```bash
# Masquerade LAN traffic going to WAN
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Or specific source NAT
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE
```

## Packet Flow Through Module

1. **Packet arrives** at interface
2. **Kernel routing** determines if packet should be forwarded
3. **NF_INET_FORWARD hook** triggers `pkt_forward.ko`
4. **Module validates** packet (IP version, header integrity)
5. **Module logs** packet details (rate-limited)
6. **Module returns NF_ACCEPT** - allows forwarding
7. **Kernel forwards** packet to output interface

## Monitoring

### View Forwarding Stats
```bash
# Unload module to see statistics
rmmod pkt_forward

# Check kernel logs
dmesg | grep pkt_forward
# Example output:
# pkt_forward: unloaded (fwd=12345 drop=67)
```

### Real-time Packet Logging
```bash
# Watch kernel messages for forwarded packets
dmesg -w | grep pkt_forward

# Example output:
# pkt_forward: [eth1->eth0] 192.168.1.100:0 -> 8.8.8.8:0 proto=1 len=84
```

### View Routing Table
```bash
ip route show
# Example:
# default via 10.0.0.254 dev eth0
# 10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.1
# 192.168.1.0/24 dev eth1 proto kernel scope link src 192.168.1.1
```

## Performance Considerations

### Atomic Counters
Module uses `atomic64_t` for packet counters - safe for multi-core ARM64 (Cortex-A73).

### Rate Limiting
Packet logging uses `net_ratelimit()` to prevent log flooding:
- Default: 10 messages/sec burst, 5 sec cooldown
- Prevents kernel log saturation on high traffic

### Hook Priority
`NF_IP_PRI_FIRST` (-2147483648) ensures our module sees packets before other Netfilter rules.

## Testing

### Test 1: Ping Between Interfaces
```bash
# From LAN client (192.168.1.100)
ping 8.8.8.8

# On BPI-R4, watch logs
dmesg -w | grep pkt_forward
# Should see forwarded ICMP packets
```

### Test 2: Check Counters
```bash
# Generate some traffic, then unload
rmmod pkt_forward
dmesg | tail -1
# Output: pkt_forward: unloaded (fwd=100 drop=0)
```

### Test 3: Validate Routing
```bash
# Trace route from LAN to Internet
traceroute -n 8.8.8.8
# First hop should be 192.168.1.1 (BPI-R4)
```

## Troubleshooting

### Packets Not Forwarding
```bash
# 1. Check IP forwarding is enabled
cat /proc/sys/net/ipv4/ip_forward
# Should output: 1

# 2. Check module is loaded
lsmod | grep pkt_forward

# 3. Check routing table
ip route show

# 4. Check interfaces are UP
ip link show
```

### High Drop Count
```bash
# Check dmesg for invalid packets
dmesg | grep pkt_forward

# Common reasons:
# - Malformed IP headers (ihl < 5)
# - Non-IPv4 packets (version != 4)
# - Truncated packets (pskb_may_pull fails)
```

## Future Enhancements (Roadmap)

### Phase 2: Session Tracking
```c
// Add session table lookup
struct session *sess = sess_lookup(skb);
if (!sess) {
    sess = sess_create(skb);
}
sess_update(sess, skb);
```

### Phase 3: IPS Integration
```c
// Signature matching
if (ips_check(skb) == IPS_BLOCK) {
    atomic64_inc(&pkts_blocked_ips);
    return NF_DROP;
}
```

### Phase 4: ML Threat Detection
```c
// ML-based classification
int threat_score = ml_classify(sess);
if (threat_score > THRESHOLD) {
    log_threat(sess, threat_score);
    return NF_DROP;
}
```

## References
- Linux Kernel Netfilter Documentation: https://www.netfilter.org/documentation/
- BPI-R4 Wiki: https://wiki.banana-pi.org/Banana_Pi_BPI-R4
- Frank-w BPI-Router-Linux: https://github.com/frank-w/BPI-Router-Linux
