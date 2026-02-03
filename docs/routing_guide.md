# Routing & Forwarding

Packet forwarding implementation for BPI-R4.

## Architecture

```
Packet → PREROUTING → ROUTING → FORWARD → POSTROUTING → Out
                                    ↑
                              pkt_forward.ko
```

## Kernel Parameters

Applied automatically via `/etc/sysctl.d/10-stargazer.conf`:

| Parameter | Value | Purpose |
|-----------|-------|--------|
| `net.ipv4.ip_forward` | 1 | Enable routing |
| `net.ipv4.conf.*.rp_filter` | 0 | Allow asymmetric routing |
| `net.ipv4.tcp_syncookies` | 1 | SYN flood protection |

## Quick Setup

```bash
# Interface configuration
ip addr add 10.0.0.1/24 dev eth0    # WAN
ip addr add 192.168.1.1/24 dev eth1  # LAN
ip link set eth0 up && ip link set eth1 up

# Default route
ip route add default via 10.0.0.254 dev eth0

# NAT (optional)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

## Monitoring

```bash
# Check forwarding status
cat /proc/sys/net/ipv4/ip_forward

# View module stats (on unload)
rmmod pkt_forward && dmesg | tail -1

# Watch packets in real-time
dmesg -w | grep pkt_forward
```

## Troubleshooting

| Issue | Check |
|-------|-------|
| No forwarding | `cat /proc/sys/net/ipv4/ip_forward` = 1? |
| Module not loaded | `lsmod \| grep pkt_forward` |
| High drop count | `dmesg \| grep pkt_forward` for malformed packets |

## Roadmap

- **Phase 2**: Session tracking (`sess_lookup`, `sess_create`)
- **Phase 3**: IPS signature matching
- **Phase 4**: ML threat detection

## References

- [Netfilter Documentation](https://www.netfilter.org/documentation/)
- [BPI-R4 Wiki](https://wiki.banana-pi.org/Banana_Pi_BPI-R4)
- [BPI-Router-Linux](https://github.com/frank-w/BPI-Router-Linux)
