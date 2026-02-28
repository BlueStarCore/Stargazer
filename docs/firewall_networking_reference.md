# Firewall, Networking & OS Reference

A ground-up reference for understanding how firewalls, networking, and operating
systems fit together — written for the Stargazer NGFW project.

---

# PART I: Operating System Fundamentals

## 1.1 What is an Operating System

An operating system (OS) is the software layer between hardware and applications.
It manages:

- **CPU** — scheduling which programs run and when
- **Memory** — allocating RAM to processes, preventing them from stepping on each other
- **Storage** — file systems, reading/writing to disk
- **Devices** — drivers for network cards, USB, display, etc.
- **Processes** — creating, stopping, and isolating running programs

```
┌──────────────────────────────────────┐
│           Applications               │
│    (CLI, web server, mgmtd, etc.)    │
├──────────────────────────────────────┤
│           Operating System           │
│   (Linux kernel + system daemons)    │
├──────────────────────────────────────┤
│             Hardware                 │
│  (CPU, RAM, NIC, disk, etc.)         │
└──────────────────────────────────────┘
```

## 1.2 Kernel vs. Userspace

The OS is split into two worlds:

**Kernel space** — the core of the OS. Runs with full hardware access. Handles:
- Memory management
- Process scheduling
- Device drivers
- Network stack (TCP/IP)
- Packet filtering (Netfilter — the engine behind iptables)

**User space** — where applications run. Each process is isolated and must ask the
kernel for anything privileged (opening files, sending packets, etc.) through
**system calls** (syscalls).

```
┌─────────────────────────────────────────────┐
│  User space                                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐ │
│  │   CLI    │ │  mgmtd   │ │   logind     │ │
│  └────┬─────┘ └────┬─────┘ └──────┬───────┘ │
│       │ syscalls    │              │         │
├───────┴─────────────┴──────────────┴─────────┤
│  Kernel space                                │
│  ┌──────────┐ ┌───────────┐ ┌─────────────┐  │
│  │ scheduler│ │ net stack │ │ Netfilter   │  │
│  └──────────┘ └───────────┘ └─────────────┘  │
└──────────────────────────────────────────────┘
```

In Stargazer:
- **Kernel space**: `pkt_forward.ko` (Netfilter hook for forwarded traffic)
- **User space**: `stargazer-cli`, `stargazer-mgmtd`, `stargazer-logind`

## 1.3 Processes and Daemons

A **process** is a running program. It has its own memory, open files, and a
process ID (PID).

A **daemon** is a background process that runs continuously, waiting for work.
Convention: daemon names end in `d`.

Stargazer daemons:
- `stargazer-mgmtd` — management daemon (config, iptables, routing)
- `stargazer-logind` — login/authentication daemon

Daemons typically start at boot via init scripts (`/etc/init.d/stargazer`).

## 1.4 File Systems and Key Directories

Linux organizes everything as files:

| Path | Purpose |
|------|---------|
| `/sbin/` | System binaries (stargazer-cli, mgmtd) |
| `/etc/` | Configuration files (stargazer.db, network configs) |
| `/run/` | Runtime data (sockets like `stargazer-mgmtd.sock`) |
| `/sys/` | Virtual filesystem exposing kernel info (NIC status, etc.) |
| `/proc/` | Virtual filesystem for process and kernel info |
| `/dev/` | Device files (disks, terminals, random) |

To check if a network interface exists, you look at `/sys/class/net/<name>`:
```c
// from stargazer-mgmtd.c
int iface_exists(const char *name) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s", name);
    return access(path, F_OK) == 0;
}
```

## 1.5 Permissions and Privilege

Linux has a permission model:
- **root** (UID 0) — full access to everything (kernel, hardware, all files)
- **regular users** — restricted, must use root-owned daemons for privileged ops

Stargazer's design:
- `stargazer-cli` runs as the logged-in user (unprivileged)
- `stargazer-mgmtd` runs as root (can modify iptables, routes, interfaces)
- CLI sends requests to mgmtd over a Unix socket — mgmtd performs the privileged
  operation and returns the result

This is the **principle of least privilege** — the user-facing tool has no direct
power. Only the trusted daemon does.

---

# PART II: Networking Fundamentals

## 2.1 The OSI Model (Simplified)

Network communication is layered. Each layer handles one concern:

```
Layer 7  Application    HTTP, DNS, SSH         ← what apps speak
Layer 4  Transport      TCP, UDP               ← reliable vs. fast delivery
Layer 3  Network        IP (IPv4, IPv6)        ← addressing and routing
Layer 2  Data Link      Ethernet, Wi-Fi        ← local network frames
Layer 1  Physical       Cables, radio waves    ← raw bits on the wire
```

Firewalls primarily work at **Layers 3 and 4** (IP addresses and ports),
though next-gen firewalls (like Stargazer aims to be) also inspect Layer 7.

## 2.2 IP Addresses

Every device on a network has an **IP address** — its identity.

**IPv4**: 32-bit, written as four octets: `192.168.1.1`
- Each octet is 0-255
- Total: ~4.3 billion addresses (not enough for everyone)

**IPv6**: 128-bit, written in hex: `2001:db8::1`
- Practically unlimited addresses

**Special addresses**:
| Address | Meaning |
|---------|---------|
| `127.0.0.1` | Loopback — the machine talking to itself |
| `0.0.0.0` | "Any address" (used in rules to mean "all") |
| `192.168.x.x` | Private network (not routed on the internet) |
| `10.x.x.x` | Private network |
| `172.16-31.x.x` | Private network |

## 2.3 CIDR Notation

CIDR (Classless Inter-Domain Routing) combines an IP address with a subnet mask
to define a range of addresses:

```
192.168.1.0/24
│              │
│              └── 24 bits are the network part
└── base address

This means: 192.168.1.0 through 192.168.1.255 (256 addresses)
```

Common masks:
| CIDR | Subnet Mask | Addresses | Use |
|------|-------------|-----------|-----|
| `/32` | 255.255.255.255 | 1 | Single host |
| `/24` | 255.255.255.0 | 256 | Typical LAN |
| `/16` | 255.255.0.0 | 65,536 | Large network |
| `/0` | 0.0.0.0 | All | Default route (everywhere) |

## 2.4 Ports

A port is a number (0-65535) that identifies a specific service on a machine.
Think of the IP address as the building address and the port as the room number.

| Port | Service | Protocol |
|------|---------|----------|
| 22 | SSH | TCP |
| 23 | Telnet | TCP |
| 53 | DNS | TCP/UDP |
| 80 | HTTP | TCP |
| 161 | SNMP | UDP |
| 443 | HTTPS | TCP |

When you SSH to `192.168.1.1`, you're connecting to `192.168.1.1:22`.

## 2.5 TCP vs. UDP

**TCP** (Transmission Control Protocol):
- Connection-oriented — establishes a connection before sending data (3-way handshake)
- Reliable — guarantees delivery, in order
- Used for: SSH, HTTP/S, Telnet

The 3-way handshake:
```
Client              Server
  │── SYN ──────────►│     "I want to connect"
  │◄── SYN-ACK ─────│     "OK, I acknowledge"
  │── ACK ──────────►│     "Connection established"
  │                   │
  │◄──── data ──────►│     (bidirectional communication)
```

**UDP** (User Datagram Protocol):
- Connectionless — just sends packets, no handshake
- Unreliable — no delivery guarantee
- Faster, less overhead
- Used for: DNS, SNMP, NTP, syslog

## 2.6 ICMP

ICMP (Internet Control Message Protocol) is used for diagnostics, not data transfer.

| Type | Name | Purpose |
|------|------|---------|
| 8 | Echo Request | Ping: "are you there?" |
| 0 | Echo Reply | Pong: "yes I'm here" |
| 3 | Destination Unreachable | "Can't reach that" |
| 11 | Time Exceeded | Traceroute uses this |

ICMP doesn't use ports. Firewall rules match on ICMP **type** instead.

```
iptables -A SG_IN_eth0 -p icmp --icmp-type echo-request -j ACCEPT
```
This allows incoming pings but not other ICMP types.

## 2.7 Network Interfaces

A **network interface** is the OS's representation of a network connection:

| Interface | What it is |
|-----------|-----------|
| `eth0`, `eth1` | Physical Ethernet ports |
| `lo` | Loopback — virtual, always exists, for internal communication |
| `wlan0` | Wi-Fi |
| `br0` | Bridge — combines multiple interfaces |
| `tun0`, `wg0` | VPN tunnels |

The loopback interface (`lo`) is special:
- IP: `127.0.0.1`
- Traffic on `lo` never leaves the machine
- Used for: processes talking to each other, self-ping
- When you ping your own IP (e.g., `ping 192.168.1.1` from the machine that
  *has* 192.168.1.1), Linux routes it through `lo`, not the physical interface

This is why `mgmtd_init_firewall()` adds `-i lo -j ACCEPT` — without it,
the firewall can't even talk to itself.

## 2.8 Routing

Routing is how the OS decides where to send a packet. The **routing table** maps
destination networks to interfaces and gateways:

```
$ ip route
default via 192.168.1.1 dev eth0          ← everything else goes here
192.168.1.0/24 dev eth0 scope link        ← local network, direct
127.0.0.0/8 dev lo scope host             ← loopback
```

When a packet is sent:
1. Kernel checks destination IP against routing table
2. Most specific match wins (longest prefix)
3. Packet is sent out the matching interface

A firewall sits at the routing decision point and can intercept packets before
they're forwarded.

---

# PART III: Firewalls

## 3.1 What is a Firewall

A firewall controls which network traffic is allowed in, out, or through a system.
It enforces security policy by inspecting packets and deciding: allow, block, or log.

**Analogy**: A bouncer at a club door. They check each person (packet) against
a list of rules. If you're on the guest list (matching rule), you get in. If not,
you're turned away (dropped).

## 3.2 Types of Firewalls

**Packet filter** (stateless):
- Looks at each packet individually: source IP, destination IP, port, protocol
- No memory of previous packets
- Fast but limited: can't tell if a packet is part of an existing conversation

**Stateful firewall**:
- Tracks connections (connection tracking / conntrack)
- Knows that an incoming packet is a *reply* to something we sent
- Can allow "ESTABLISHED" traffic without per-port rules
- This is what Stargazer uses with `-m conntrack --ctstate ESTABLISHED,RELATED`

**Next-Generation Firewall (NGFW)**:
- Everything above, plus:
- Application awareness (Layer 7 inspection)
- Intrusion Prevention System (IPS)
- Deep packet inspection (DPI)
- Stargazer's goal: IPS + ML scoring via a userspace daemon

## 3.3 Firewall Placement

```
                 Internet
                    │
              ┌─────┴─────┐
              │  Firewall │    ← controls what gets in/out
              └─────┬─────┘
                    │
         ┌──────────┼──────────┐
         │          │          │
     ┌───┴───┐  ┌───┴───┐  ┌───┴───┐
     │ LAN 1 │  │ LAN 2 │  │  DMZ  │
     └───────┘  └───────┘  └───────┘
```

The firewall inspects traffic at every boundary:
- **INPUT**: traffic destined for the firewall itself (management access)
- **FORWARD**: traffic passing through (LAN-to-Internet, LAN-to-LAN)
- **OUTPUT**: traffic originating from the firewall

## 3.4 Default Deny vs. Default Allow

Two philosophies:

**Default Allow** (bad for firewalls):
- Everything is permitted unless explicitly blocked
- You must anticipate every threat and write a rule for it
- Miss one? You're exposed
- This was Stargazer's state before our fix (INPUT policy ACCEPT)

**Default Deny** (what we implement):
- Everything is blocked unless explicitly allowed
- You only open what you need
- Miss a rule? That service is unreachable, but not exploitable
- This is the **least-privilege principle**

```
Default Allow:          Default Deny:
  "Block bad stuff"       "Allow only good stuff"
  (infinite list)         (finite list)
```

Always use default deny for firewalls. It's the only sane approach.

## 3.5 Self-Protection: Why INPUT Matters

A firewall doesn't just protect the network behind it — it must protect **itself**.

If an attacker compromises the firewall itself (via an exposed service, a management
port, etc.), they own everything behind it. The INPUT chain controls what can reach
the firewall's own processes.

```
                  Attacker
                     │
              ┌──────┴──────┐
              │  INPUT chain│ ← must be locked down
              ├─────────────┤
              │   Firewall  │
              │  processes  │
              │ (ssh, mgmtd,│
              │  web UI)    │
              └──────┬──────┘
                     │
              Protected network
```

Stargazer's INPUT chain structure:
1. Allow loopback (the firewall must talk to itself)
2. Allow return traffic (replies to connections we initiated)
3. Per-interface rules (only explicitly configured services)
4. Everything else: DROP (policy)

---

# PART IV: iptables

## 4.1 What is iptables

`iptables` is the userspace tool for configuring the Linux kernel's packet
filtering framework (**Netfilter**). It doesn't filter packets itself — it tells
the kernel how to filter.

```
iptables (userspace tool)
    │
    │  configures
    ▼
Netfilter (kernel framework)
    │
    │  inspects/filters
    ▼
network packets
```

## 4.2 Tables

iptables has multiple tables, each serving a different purpose:

| Table | Purpose | Chains |
|-------|---------|--------|
| `filter` | Allow/block packets (default) | INPUT, FORWARD, OUTPUT |
| `nat` | Rewrite addresses/ports | PREROUTING, POSTROUTING, OUTPUT |
| `mangle` | Modify packet headers | All five |
| `raw` | Bypass connection tracking | PREROUTING, OUTPUT |

If you don't specify `-t <table>`, iptables uses `filter`. So:
```
iptables -A INPUT ...
```
is the same as:
```
iptables -t filter -A INPUT ...
```

## 4.3 Chains — Built-in vs. User-Defined

**Built-in chains** are hardwired to packet flow points in the kernel:

```
packet arrives
    │
    ▼
PREROUTING (nat/mangle)     ← before routing decision
    │
    ├── destined for this machine? ──► INPUT (filter) ──► local process
    │
    └── destined elsewhere? ──► FORWARD (filter) ──► POSTROUTING (nat) ──► out
```

Built-in chains have:
- A **policy** (ACCEPT or DROP) — the default verdict
- Packets are forced through them by the kernel

**User-defined chains** are custom rule groups you create:
```
iptables -N SG_IN_eth0      ← create
iptables -X SG_IN_eth0      ← delete (must be empty and unreferenced)
```

User-defined chains:
- Have NO policy
- Are only reached via `-j <chain>` jump from another chain
- If a packet reaches the end without matching, it **returns** to the caller
- Act like subroutines / function calls

Stargazer uses user-defined chains `SG_IN_<iface>` to organize per-interface
rules, keeping INPUT clean:

```
INPUT:
  → SG_IN_eth0  (jump)
  → SG_IN_eth1  (jump)

SG_IN_eth0:
  allow ping
  allow ssh
  drop rest

SG_IN_eth1:
  allow https
  drop rest
```

## 4.4 Rules

A rule consists of **match criteria** and a **target** (action).

```
iptables -A INPUT -i eth0 -p tcp --dport 22 -j ACCEPT
         │        │        │       │          │
         │        │        │       │          └── target: ACCEPT
         │        │        │       └── match: destination port 22
         │        │        └── match: TCP protocol
         │        └── match: arriving on eth0
         └── append to INPUT chain
```

Common match options:
| Option | Meaning | Example |
|--------|---------|---------|
| `-i eth0` | Input interface | `-i lo` |
| `-o eth0` | Output interface | `-o eth1` |
| `-s 10.0.0.0/8` | Source IP/network | `-s 192.168.1.0/24` |
| `-d 10.0.0.1` | Destination IP | `-d 0.0.0.0/0` (any) |
| `-p tcp` | Protocol | `-p udp`, `-p icmp` |
| `--dport 22` | Destination port | `--dport 443` |
| `--sport 1024` | Source port | `--sport 53` |
| `-m conntrack` | Use conntrack module | `--ctstate ESTABLISHED` |

## 4.5 Targets

| Target | Behavior |
|--------|----------|
| `ACCEPT` | Allow the packet. Stop processing this chain. |
| `DROP` | Silently discard. No response to sender. Sender times out. |
| `REJECT` | Discard but send ICMP error back. Sender knows immediately. |
| `LOG` | Log to syslog, then continue processing (non-terminating). |
| `RETURN` | Stop processing current chain, go back to caller chain. |
| `<user-chain>` | Jump into user-defined chain (like a function call). |

**DROP vs. REJECT**: DROP is generally preferred for firewalls because:
- It reveals less information (attacker doesn't know if the port exists)
- It's cheaper (no reply packet generated)
- REJECT is friendlier (fail fast) but tells attackers what's filtered

Stargazer uses DROP everywhere.

## 4.6 Command Reference

### Chain operations
```
iptables -N MYCHAIN              # Create user-defined chain
iptables -X MYCHAIN              # Delete user-defined chain (must be empty)
iptables -F INPUT                # Flush (remove all rules from chain)
iptables -F                      # Flush all chains in filter table
iptables -P INPUT DROP           # Set policy for built-in chain
iptables -L INPUT -n --line-numbers   # List rules with numbers
```

### Rule operations
```
iptables -A INPUT <matches> -j <target>    # Append rule at end
iptables -I INPUT 1 <matches> -j <target>  # Insert rule at position 1
iptables -D INPUT <matches>                # Delete rule by match
iptables -D INPUT 3                        # Delete rule by number
iptables -C INPUT <matches>                # Check if rule exists (exit code)
```

### Key flags
| Flag | Long form | Meaning |
|------|-----------|---------|
| `-A` | `--append` | Add rule at end of chain |
| `-I` | `--insert` | Add rule at position (default: 1 = top) |
| `-D` | `--delete` | Remove a rule |
| `-C` | `--check` | Test if rule exists (no output, just exit code) |
| `-F` | `--flush` | Remove all rules from a chain |
| `-N` | `--new-chain` | Create user-defined chain |
| `-X` | `--delete-chain` | Delete user-defined chain |
| `-P` | `--policy` | Set default policy for built-in chain |
| `-L` | `--list` | List rules |
| `-n` | `--numeric` | Show IPs/ports as numbers (don't resolve DNS) |

## 4.7 Policy vs. Rules

This is a critical distinction:

**Policy** — a property of the chain, set with `-P`:
```
Chain INPUT (policy DROP)     ← this is the policy
```
- Only built-in chains have policies
- Only two values: ACCEPT or DROP
- Applied when a packet reaches the end of the chain without matching any rule
- NOT affected by `-F` (flush) — flush removes rules, not the policy
- Only changed by another `-P` command

**Rules** — entries in the chain, managed with `-A`, `-I`, `-D`, `-F`:
```
Chain INPUT (policy DROP)
 1    ACCEPT    all   lo           ← this is a rule
 2    ACCEPT    all   ctstate...   ← this is a rule
```
- `-F` removes all rules
- Each rule has match criteria and a target

Think of it as: the policy is the chain's "else" clause. Rules are "if" statements.

```
for each packet in chain:
    if matches rule 1 → do rule 1's target
    if matches rule 2 → do rule 2's target
    ...
    else → do policy (ACCEPT or DROP)
```

## 4.8 Rule Processing Order

Rules are processed **top to bottom, first match wins**:

```
Chain INPUT (policy DROP)
 1    ACCEPT    -i lo                ← checked first
 2    ACCEPT    ctstate EST,REL      ← checked second
 3    SG_IN_eth0  -i eth0            ← checked third
 4    SG_IN_eth1  -i eth1            ← checked fourth
 (policy DROP)                       ← reached only if nothing matched
```

A packet hitting rule 1 is immediately ACCEPTed. It never sees rules 2-4.

**This means order matters**:
- Put the most frequent matches first (performance)
- Put broad allows (lo, ESTABLISHED) before specific ones (per-interface)
- More specific rules should come before less specific ones within a group

## 4.9 How Stargazer Uses iptables

Stargazer calls iptables through `safe_exec()` — a fork+exec wrapper that avoids
shell interpretation (no command injection):

```c
const char *argv[] = {"iptables", "-A", "INPUT", "-i", "lo",
                      "-j", "ACCEPT", NULL};
free(safe_exec(argv));
```

Why not `system("iptables -A INPUT -i lo -j ACCEPT")`?
- `system()` invokes a shell (`/bin/sh -c "..."`)
- Shell interpretation allows command injection if any argument contains
  shell metacharacters (`;`, `|`, `$()`, etc.)
- `safe_exec()` passes arguments directly to `execvp()` — no shell, no injection

---

# PART V: Netfilter — The Kernel Framework

## 5.1 What is Netfilter

Netfilter is the **kernel-side** framework. iptables is just the userspace
configuration tool. Netfilter provides:

- **Hooks** — points in the network stack where code can inspect/modify packets
- **Connection tracking** (conntrack) — stateful packet inspection
- **NAT** — address/port translation
- **Packet mangling** — header modification

```
User space:     iptables (configure rules)
                    │
                    ▼
Kernel space:   Netfilter (enforce rules on live traffic)
```

## 5.2 Netfilter Hooks

Netfilter defines 5 hook points in the IPv4 packet path:

```
                        packet in
                            │
                 ┌──────────┴──────────┐
                 │  NF_INET_PRE_ROUTING│  ← hook 1
                 └──────────┬──────────┘
                            │
                     routing decision
                       ┌────┴────┐
                       │         │
               for this host  for another host
                       │         │
              ┌────────┴───┐   ┌─┴──────────────┐
              │NF_INET_    │   │NF_INET_FORWARD │  ← hook 3
              │LOCAL_IN    │   └─┬──────────────┘
              │(= INPUT)   │     │
              │  ← hook 2  │   ┌─┴───────────────┐
              └────────┬───┘   │NF_INET_POST_    │  ← hook 4
                       │       │ROUTING          │
                local process  └─┬───────────────┘
                       │         │
              ┌────────┴───┐     ▼
              │NF_INET_    │  packet out
              │LOCAL_OUT   │
              │  ← hook 5  │
              └────────┬───┘
                       │
              ┌────────┴──────────┐
              │NF_INET_POST_      │  ← hook 4
              │ROUTING            │
              └────────┬──────────┘
                       │
                    packet out
```

iptables chains map to these hooks:
| Hook | iptables chain | When |
|------|---------------|------|
| NF_INET_PRE_ROUTING | PREROUTING | Before routing decision |
| NF_INET_LOCAL_IN | INPUT | Packet destined for this machine |
| NF_INET_FORWARD | FORWARD | Packet being routed through |
| NF_INET_LOCAL_OUT | OUTPUT | Packet from local process |
| NF_INET_POST_ROUTING | POSTROUTING | After routing, before leaving |

Stargazer's `pkt_forward.ko` registers at `NF_INET_FORWARD` — it inspects
packets being routed through the firewall (the data plane).

## 5.3 Hook Verdicts

When a Netfilter hook function inspects a packet, it returns a verdict:

| Verdict | Meaning |
|---------|---------|
| `NF_ACCEPT` | Let the packet continue to the next hook |
| `NF_DROP` | Silently discard the packet |
| `NF_QUEUE` | Pass to userspace for inspection (used by IPS) |
| `NF_REPEAT` | Process this hook again |
| `NF_STOLEN` | Hook took ownership (don't touch the packet anymore) |

## 5.4 Hook Priorities

Multiple modules can register at the same hook. Priority determines order:

```
NF_INET_FORWARD:
  priority -300  → conntrack (connection tracking)
  priority -150  → mangle
  priority  0    → filter (iptables FORWARD rules)
  priority  1    → pkt_forward.ko (Stargazer's module)
  priority  100  → NAT
```

Lower number = higher priority = runs first.

---

# PART VI: Connection Tracking (conntrack)

## 6.1 What is Connection Tracking

Connection tracking (conntrack) is the kernel subsystem that remembers active
network connections. It turns a stateless packet filter into a **stateful firewall**.

Without conntrack, the firewall sees each packet in isolation:
```
packet: src=8.8.8.8 dst=192.168.1.1 ICMP echo-reply
Question: should I allow this?
Answer: I don't know — is this a reply to our ping, or an unsolicited packet?
```

With conntrack, the firewall knows:
```
packet: src=8.8.8.8 dst=192.168.1.1 ICMP echo-reply
Conntrack: this matches an existing connection (we sent echo-request 50ms ago)
State: ESTABLISHED
Answer: allow it (if we have an ESTABLISHED rule)
```

## 6.2 Connection States

Conntrack assigns a state to every packet:

| State | Meaning |
|-------|---------|
| `NEW` | First packet of a connection (SYN for TCP, first UDP packet) |
| `ESTABLISHED` | Part of an already-seen bidirectional connection |
| `RELATED` | New connection related to an existing one (e.g., FTP data channel, ICMP error about an existing connection) |
| `INVALID` | Doesn't belong to any known connection, or is malformed |
| `UNTRACKED` | Explicitly bypassed conntrack (via raw table) |

## 6.3 The ESTABLISHED,RELATED Rule

```
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

This single rule allows **all return traffic** for connections the firewall
initiated. Without it, using a DROP policy would break everything the firewall
does outbound:

| Scenario | What breaks without ESTABLISHED |
|----------|-------------------------------|
| `ping 8.8.8.8` | Echo-reply dropped |
| `nslookup google.com` | DNS reply (UDP 53) dropped |
| NTP sync | Time reply dropped, clock drifts |
| Firmware upgrade (HTTPS) | All response data dropped |
| Syslog forwarding | Acknowledgment dropped |
| Package manager updates | HTTPS response dropped |

Why it's safe:
- It does NOT allow new inbound connections
- It only allows packets that are part of conversations **we started**
- An attacker can't spoof an ESTABLISHED packet without knowing the exact
  connection tuple (src IP, dst IP, src port, dst port, protocol, sequence number)

## 6.4 How Conntrack Works Internally

The kernel maintains a hash table of connections:

```
conntrack table:
┌─────────────────────────────────────────────────────────────────┐
│ proto  src IP        src port  dst IP      dst port  state     │
├─────────────────────────────────────────────────────────────────┤
│ tcp    192.168.1.1   45823     8.8.8.8     443       ESTABLISHED│
│ udp    192.168.1.1   38291     8.8.8.8     53        ESTABLISHED│
│ icmp   192.168.1.1   (id=7)   8.8.8.8     (type=8)  ESTABLISHED│
└─────────────────────────────────────────────────────────────────┘
```

When a packet arrives, conntrack looks it up:
1. Compute hash from packet's 5-tuple (proto, src IP, src port, dst IP, dst port)
2. Look up in the hash table
3. If found → mark packet as ESTABLISHED (or RELATED)
4. If not found → mark as NEW (or INVALID if malformed)

The conntrack module (`nf_conntrack`) is auto-loaded by the kernel the first time
iptables uses `-m conntrack`. You don't need to manually load it.

## 6.5 Conntrack and Protocol Details

**TCP**: conntrack tracks the full TCP state machine (SYN, SYN-ACK, ACK,
FIN, RST). A connection is ESTABLISHED after the SYN-ACK is seen.

**UDP**: no real "connection," but conntrack creates an entry when the first
packet is seen. If a reply comes from the same IP:port, it's ESTABLISHED.
Entry times out after ~30 seconds of inactivity.

**ICMP**: echo-request creates an entry. The matching echo-reply (same ID and
sequence) is marked ESTABLISHED. Error messages (unreachable, time-exceeded)
are RELATED to the connection that triggered them.

---

# PART VII: Network Address Translation (NAT)

## 7.1 What is NAT

NAT rewrites IP addresses (and sometimes ports) in packets as they pass through.
Most commonly used to let many private IPs share one public IP.

## 7.2 Types of NAT

**SNAT (Source NAT) / Masquerade**:
```
Internal: 192.168.1.100 ──► Firewall ──► Internet
  src: 192.168.1.100          rewrites src to public IP
  dst: 8.8.8.8                src: 203.0.113.1
                               dst: 8.8.8.8
```
- Used in POSTROUTING
- `iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE`
- Allows internal machines to reach the internet

**DNAT (Destination NAT) / Port Forwarding**:
```
Internet: ──► Firewall (public IP:8080) ──► Internal: 192.168.1.100:80
  src: attacker                rewrites dst
  dst: 203.0.113.1:8080        dst: 192.168.1.100:80
```
- Used in PREROUTING
- `iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to 192.168.1.100:80`
- Exposes internal services to the internet

## 7.3 NAT and Conntrack

NAT depends entirely on conntrack. When the first packet of a connection is
NATted, conntrack records the translation. All subsequent packets in that
connection are translated automatically — no additional NAT rules are consulted.

This is why NAT rules are only applied to NEW connections:
```
Packet 1 (SYN):     hits NAT rule → translated → conntrack records mapping
Packets 2-N:        conntrack handles translation automatically
```

---

# PART VIII: Firewall Design Principles

## 8.1 Defense in Depth

Never rely on a single layer of defense. Stack multiple:

```
Layer 1:  INPUT policy DROP                     ← base safety net
Layer 2:  Per-interface chains (SG_IN_*)        ← granular control
Layer 3:  Per-service rules (port + protocol)   ← specific allows
Layer 4:  Application-level auth (SSH keys)     ← even if port is open
Layer 5:  IPS / deep inspection (future)        ← detect bad content
```

If any single layer fails, others still protect. This is why we have:
- Policy DROP **and** per-chain DROP rules
- Loopback allow **and** conntrack ESTABLISHED
- Multiple layers are redundant by design

## 8.2 Least Privilege

Only allow exactly what is needed, nothing more:

- Default policy: DROP (not ACCEPT)
- Only open ports that are configured via `allowaccess`
- Only allow protocols that match the service (TCP for SSH, not UDP)
- Only allow on specific interfaces (SSH on mgmt port, not WAN)

## 8.3 Fail Closed

When something goes wrong, the system should become **more** restrictive, not less:

- Policy DROP before flush (not after) — if flush somehow breaks rules, DROP
  catches everything
- If mgmtd crashes, INPUT policy remains DROP — the firewall is locked down
  rather than wide open
- If a rule fails to apply, no traffic gets through (safe default)

This is the opposite of "fail open," where errors result in allowing everything.

## 8.4 Rule Ordering Strategy

```
Chain INPUT (policy DROP)
 ┌── High-frequency, low-cost checks first ──────────┐
 │ 1. Loopback (ACCEPT)        ← very fast, no state │
 │ 2. ESTABLISHED,RELATED      ← fast conntrack lookup│
 ├── Per-interface jumps ────────────────────────────┤
 │ 3. -i eth0 -j SG_IN_eth0    ← interface match     │
 │ 4. -i eth1 -j SG_IN_eth1                          │
 ├── Implicit default ──────────────────────────────┤
 │ (policy DROP)               ← everything else     │
 └────────────────────────────────────────────────────┘
```

Why this order:
1. **Loopback first** — lots of local traffic (daemon IPC), dirt cheap to match
2. **ESTABLISHED second** — most packets belong to existing connections; conntrack
   lookup is O(1) hash table. This handles 90%+ of legitimate traffic.
3. **Per-interface rules** — only NEW inbound connections reach here
4. **Policy DROP** — anything not explicitly allowed

## 8.5 Idempotency

Firewall init must be safe to run multiple times (daemon restart, config reload):

```c
// mgmtd_init_firewall():
iptables -P INPUT DROP     ← safe to repeat (already DROP? no-op)
iptables -F INPUT          ← safe to repeat (already empty? no-op)
iptables -A INPUT ...      ← adds fresh rules to clean chain

// apply_allowaccess():
iptables -N SG_IN_eth0     ← ignore error if exists
iptables -F SG_IN_eth0     ← flush old rules
iptables -D INPUT ... SG_IN_eth0   ← remove old jump (ignore if absent)
iptables -A INPUT ... SG_IN_eth0   ← add fresh jump
```

Without idempotency, restarting mgmtd would duplicate rules:
```
BAD (no flush):
 1. -i lo -j ACCEPT
 2. -m conntrack ...
 3. -i lo -j ACCEPT          ← duplicate after restart
 4. -m conntrack ...          ← duplicate after restart
```

## 8.6 Atomicity Concerns

iptables commands are **not atomic**. Each command is a separate kernel call.
Between commands, there's a brief window where the state is incomplete.

```
                     Time →
iptables -P DROP     ──┐
                       │  ← window: DROP + old stale rules (safe: too strict)
iptables -F INPUT    ──┤
                       │  ← window: DROP + no rules (safe: too strict)
iptables -A lo       ──┤
                       │  ← window: DROP + lo only (safe: too strict)
iptables -A EST      ──┘
                          ← final state: correct
```

The principle: during setup, it's acceptable to be temporarily **too strict**
(dropping legitimate traffic briefly). It's never acceptable to be temporarily
**too permissive** (allowing illegitimate traffic). This is why we set policy
DROP before flushing, not after.

For truly atomic updates, Linux offers `iptables-restore` which loads an entire
ruleset in one kernel call. This is a future improvement if the brief strictness
window during restart becomes problematic.

---

# PART IX: Stargazer Firewall Architecture

## 9.1 Boot Sequence

```
init script (/etc/init.d/stargazer)
    │
    ├── load kernel modules (pkt_forward.ko)
    ├── sysctl (enable IP forwarding, etc.)
    └── start stargazer-mgmtd
            │
            ├── sg_db_open()              open config database
            ├── mgmtd_seed_defaults()     seed factory defaults
            ├── mgmtd_sync_interfaces()   discover NICs
            ├── mgmtd_init_firewall()     INPUT: DROP + lo + ESTABLISHED
            └── mgmtd_replay_config()     apply saved config
                    │
                    ├── system_settings    (hostname, timezone)
                    ├── network_dns        (resolv.conf)
                    ├── system_interface   → apply_allowaccess() per NIC
                    ├── network_route      (static routes)
                    ├── network_nat        (SNAT/DNAT rules)
                    └── network_dhcp       (DHCP server)
```

## 9.2 Runtime Config Change

When a user changes `allowaccess` on an interface at runtime:

```
CLI: set allowaccess ping ssh
  │
  └── IPC request to mgmtd
        │
        └── apply_interface()
              │
              └── apply_allowaccess("eth0", "ping ssh")
                    │
                    ├── flush SG_IN_eth0 chain
                    ├── remove old INPUT jump
                    ├── add new INPUT jump (appended at end)
                    ├── add ICMP echo-request ACCEPT
                    ├── add TCP/22 ACCEPT
                    └── add DROP (end of chain)
```

The base rules (lo, ESTABLISHED, policy DROP) are untouched. Only the
per-interface chain is rebuilt.

## 9.3 Data Plane vs. Control Plane

```
┌─────────────────────────────────────────────────────┐
│ Control Plane (managing the firewall itself)        │
│                                                     │
│  INPUT chain → mgmtd, CLI, SSH, web UI              │
│  Only accessible via allowaccess config              │
│  Protected by: policy DROP + SG_IN_* chains          │
├─────────────────────────────────────────────────────┤
│ Data Plane (traffic passing through)                │
│                                                     │
│  FORWARD chain → pkt_forward.ko                      │
│  Traffic between networks (LAN↔WAN, LAN↔LAN)        │
│  Protected by: Netfilter hook + firewall policies    │
│  Future: IPS + ML scoring                            │
└─────────────────────────────────────────────────────┘
```

---

# Appendix A: Quick Reference — Packet Flow Through Stargazer

```
packet arrives on eth0
    │
    ▼
PREROUTING (nat)
    │ DNAT if port forwarding configured
    ▼
routing decision ─────────────────────────────┐
    │                                          │
    │ for this machine                         │ for another host
    ▼                                          ▼
INPUT (filter)                             FORWARD (filter)
    │                                          │
    ├─ rule 1: -i lo? ──► ACCEPT               ├─ pkt_forward.ko
    ├─ rule 2: ESTABLISHED? ──► ACCEPT          │   (inspect, count,
    ├─ rule 3: -i eth0? ──► SG_IN_eth0          │    future: IPS/ML)
    │   ├─ ping? ACCEPT                         │
    │   ├─ ssh? ACCEPT                          ▼
    │   └─ DROP                             POSTROUTING (nat)
    ├─ rule 4: -i eth1? ──► SG_IN_eth1          │ SNAT/masquerade
    │   └─ ...                                  ▼
    └─ policy DROP                          packet leaves
    │
    ▼
local process (mgmtd, sshd, etc.)
```

---

# Appendix B: Common Debugging Commands

```bash
# Show INPUT chain with rule numbers
iptables -L INPUT -n --line-numbers -v

# Show all chains in filter table
iptables -L -n -v

# Show NAT rules
iptables -t nat -L -n -v

# Show conntrack entries (active connections)
conntrack -L
# or
cat /proc/net/nf_conntrack

# Count conntrack entries
conntrack -C

# Show conntrack for specific IP
conntrack -L -s 192.168.1.100

# Watch packets hit rules in real-time (counters)
watch -n 1 'iptables -L INPUT -n -v'

# Check if a specific rule exists (exit code 0 = yes)
iptables -C INPUT -i lo -j ACCEPT

# Show interface status
ip link show
ip addr show

# Show routing table
ip route show

# Check if conntrack module is loaded
lsmod | grep nf_conntrack
```
