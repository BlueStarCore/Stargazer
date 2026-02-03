# Stargazer NGFW

**Next-Generation Firewall with Machine Learning for Banana Pi BPI-R4**

[![License](https://img.shields.io/badge/license-GPL-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-BPI--R4-orange.svg)](https://wiki.banana-pi.org/Banana_Pi_BPI-R4)

## Project Overview

Stargazer is a custom Linux-based firewall (StargazerOS) that combines traditional stateful packet inspection with machine learning-based anomaly detection. Designed for the Banana Pi BPI-R4 router platform (MediaTek MT7988A, 4-8GB RAM, 6x Ethernet ports).

### Key Features

- **Stateful Firewall**: Session tracking with flags (active, benign, suspicious, dirty, FIN-wait, URG priority)
- **IPS Engine**: Signature-based intrusion prevention (Emerging Threats ruleset)
- **ML Threat Detection**: LightGBM-based anomaly detection trained on CIC-IDS2018 dataset
- **NetFlow Export**: Feature extraction for ML (IAT, packet length variance, flag counts, etc.)
- **Multi-tier Logging**: Disk (rsyslog), RAM (tmpfs), optional cloud integration
- **Performance Target**: >500Mbps throughput, 5k-8k concurrent sessions, <8W power

### Architecture

```
[Ingress] → TCP/IP Stack → DoS Policy → Session Lookup → IPS/ML Rating → Shaping → [Egress]
                                              ↓
                                        Session Table
                                      (nf_conntrack hash)
                                              ↓
                                      NetFlow Features → ML Daemon (userspace)
```

Inspired by FortiGate's parallel path processing architecture.

## Hardware Requirements

- **Platform**: Banana Pi BPI-R4
- **CPU**: MediaTek MT7988A (quad Cortex-A73 @ 1.8GHz)
- **RAM**: 4-8GB
- **Network**: 6x Ethernet ports (HW NAT/DSA support)

## Development Timeline

15-week project cycle (started Feb 1, 2026):

| Phase | Weeks | Focus |
|-------|-------|-------|
| Phase 0 | 1 | System design & architecture |
| Phase 1 | 2-3 | OS base + routing/NAT/DHCP |
| Phase 2 | 4-5 | Session management + NetFlow |
| Phase 3 | 6-7 | IPS signature-based + AV |
| Phase 4 | 8-9 | ML integration (LightGBM) |
| Phase 5 | 10 | Logging infrastructure |
| Phase 6 | 11-13 | Testing & optimization |
| Phase 7 | 14-15 | Documentation & presentation |

## Repository Structure

```
Stargazer/
├── VERSION                    # Single source of truth for version
├── Makefile                   # Unified build system
├── docs/                      # Documentation
│   ├── coding_standards.md
│   └── routing_guide.md
├── src/
│   ├── modules/               # Kernel modules (Netfilter)
│   │   ├── pkt_forward.c      # Packet forwarding hook
│   │   ├── session.c          # Session tracking (Phase 2)
│   │   └── Makefile
│   ├── userspace/             # Init system & configs
│   │   ├── init               # PID 1 init script
│   │   └── etc/
│   │       ├── init.d/stargazer
│   │       ├── modules-load.d/stargazer.conf
│   │       └── sysctl.d/10-stargazer.conf
│   └── ml/                    # ML training scripts (Phase 4)
├── kernel/                    # BPI-R4 kernel source (git clone)
├── build/                     # Build artifacts
└── tests/                     # Test scripts
```

## Quick Start

### Prerequisites (Host System)

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    git make gcc-aarch64-linux-gnu \
    bc bison flex libssl-dev libncurses5-dev \
    qemu-system-arm xorriso wget cpio
```

### Build Everything

```bash
cd Stargazer

# Build kernel + modules + rootfs + ISO (first run: ~70 min)
make all

# Output: build/stargazer-bpi-r4.iso
```

### Test in QEMU

```bash
make test
# Boots ARM64 QEMU with auto-loaded pkt_forward module
```

### Deploy to BPI-R4

```bash
# Write to SD card
sudo dd if=build/stargazer-bpi-r4.iso of=/dev/sdX bs=4M status=progress
```

## Code Quality Standards

This project follows **"The Art of Readable Code"** principles:

1. **Clear Naming**: `stargazer_forward_hook()` instead of `fwd_hk()`
2. **Self-Documenting**: Functions explain "why", not just "what"
3. **Minimal Scope**: Small, focused functions with single responsibilities
4. **Consistent Style**: Linux kernel coding standards
5. **Explicit Error Handling**: Check all return values, log failures
6. **Performance Awareness**: Atomic counters, rate-limited logging

See [docs/coding_standards.md](docs/coding_standards.md) for details.

## Testing Strategy

- **Unit Tests**: Phase 2+ (session table operations)
- **QEMU Testing**: ARM64 emulation before hardware deployment
- **Stress Tests**: iperf3 throughput, hping3 DDoS simulation
- **Penetration Testing**: Nmap scans, EICAR test files, CIC-IDS2018 attack replays
- **Power Measurement**: USB power meter, target <8W under load

## Contributing

This is an academic project (3-person team). External contributions not accepted during development phase (Feb-May 2026).

### Team Roles

- **Member A**: System architecture, integration testing (limited availability Tue-Thu 8am-5pm)
- **Member B**: Build automation, documentation, diagrams
- **Member C**: ML training, session coding, kernel modules

## License

GPL v3.0 - See [LICENSE](LICENSE) for details.

## References

- [Banana Pi BPI-R4 Wiki](https://wiki.banana-pi.org/Banana_Pi_BPI-R4)
- [FortiGate Session Table](https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-FortiGate-session-table-information/ta-p/196988)
- [BPI-R4 Kernel (frank-w)](https://github.com/frank-w/BPI-Router-Linux)
- [LightGBM Documentation](https://lightgbm.readthedocs.io/)
- [CIC-IDS2018 Dataset](https://www.unb.ca/cic/datasets/ids-2018.html)

## Acknowledgments

Inspired by FortiGate's parallel processing architecture and built on frank-w's excellent BPI-R4 kernel work.

---

**Status**: Phase 1 Complete - Packet Forwarding  
**Last Updated**: February 3, 2026
