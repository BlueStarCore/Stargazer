# Stargazer NGFW — Architecture Overview

**Version 0.1.3** | **Target: BPI-R4 (MT7988A, ARM64)** | **License: MIT (kernel modules: GPL-2.0-only)**

---

## 1. System Flow — The Big Picture

```
                        +------------------------------------------+
                        |            BPI-R4 Hardware                |
                        |  MT7988A SoC, ARM64, eMMC + SPI-NAND     |
                        +----------------------+-------------------+
                                               |
                    +----------------------------------------------+
                    |              BOOT CHAIN                       |
                    |                                               |
                    |  +-----+   +-----+   +-------+   +-------+  |
                    |  | BL2 |-->| ATF |-->|U-Boot |-->|  FIT  |  |
                    |  |boot0|   |BL31 |   | BL33  |   |kernel |  |
                    |  +-----+   +-----+   +-------+   |+initrd|  |
                    |                                   | +dtb  |  |
                    |                                   +---+---+  |
                    +---------------------------------------+------+
                                                           |
             +-------------------------------------------------------------+
             |                    KERNEL SPACE                             |
             |                                                             |
             |  +------------------------------------------------------+   |
             |  | Netfilter Framework                                  |   |
             |  |                                                      |   |
             |  |   NF_INET_FORWARD                                    |   |
             |  |   +--------------+                                   |   |
             |  |   | pkt_forward  | -- validate IPv4 -- NF_ACCEPT --> |   |
             |  |   |   .ko        |         |                         |   |
             |  |   | (active)     |     invalid -- NF_DROP            |   |
             |  |   +--------------+                                   |   |
             |  |                                                      |   |
             |  |   +--------------+                                   |   |
             |  |   |  session.ko  |  (disabled — Phase 2)             |   |
             |  |   |  RCU hash    |  5-tuple tracking, ML stats       |   |
             |  |   +--------------+                                   |   |
             |  |                                                      |   |
             |  |   iptables: INPUT DROP (mgmtd-managed)               |   |
             |  |   iptables: NAT PREROUTING/POSTROUTING (mgmtd)       |   |
             |  |   nf_conntrack (connection tracking, TFTP helper)    |   |
             |  +------------------------------------------------------+   |
             |                                                             |
             |  sysctl: ip_forward=1, rp_filter=1, syncookies=1            |
             |          conntrack_max=131072, tcp_fin_timeout=30           |
             +-------------------------------------------------------------+
                                           |
             +-------------------------------------------------------------+
             |                    USER SPACE                               |
             |                                                             |
             |  +------+     +------------+     +-----------------------+  |
             |  | init |---->| mgmtd      |<IPC>| CLI / logind / webui  |  |
             |  |PID 1 |     | (root)     |     | (unprivileged)        |  |
             |  +------+     +------------+     +-----------------------+  |
             |                     |                                       |
             |              +------+------+                                |
             |              |   SQLite    |                                |
             |              | stargazer.db|                                |
             |              +-------------+                                |
             +-------------------------------------------------------------+
                                           |
             +-------------------------------------------------------------+
             |                 PERSISTENT STORAGE (eMMC)                   |
             |                                                             |
             |  P3: fip       P4: firmware    P5: sgdata      P6: sglogs   |
             |  (BL31+UBoot)  (FIT image)     (/etc/stargazer) (logs)      |
             +-------------------------------------------------------------+
```

---

## 2. Boot Flow

What happens from power-on to login prompt.

```
Power On
  |
  v
MT7988A Boot ROM
  |  Reads BL2 from eMMC boot0 HW partition
  v
BL2 (ARM Trusted Firmware preloader)
  |  Inits DRAM, finds FIP by GPT label "fip" in partition P3
  v
BL31 (Secure Monitor) + U-Boot (BL33)
  |  Parses GPT, loads FIT image from partition P4 ("firmware")
  |  Decompresses: kernel (LZMA), initramfs (gzip), DTB
  v
Linux Kernel 6.12 (ARM64)
  |  ip_forward=1, loads initramfs into RAM
  v
/init (PID 1 — shell script)
  |
  +-- Mount /proc, /sys, /dev, /tmp, /run
  |
  +-- Detect & mount persistent storage
  |   +-- P5 (sgdata) → /etc/stargazer     (config database)
  |   +-- P6 (sglogs) → /etc/stargazer/logs (audit logs)
  |   +-- First boot: auto-format ext2, create P6 via sg-partinit
  |
  +-- Restore /etc/shadow, /etc/passwd, /etc/group from sgdata
  |
  +-- iptables -P INPUT DROP   (lock down before any interface up)
  |
  +-- /etc/init.d/stargazer
  |   +-- insmod pkt_forward.ko
  |   +-- sysctl -p (ip_forward, syncookies, conntrack_max, ...)
  |
  +-- Start stargazer-mgmtd (root daemon)
  |   |  Waits for readiness via /run/mgmtd-ready FIFO
  |   |
  |   |  Inside mgmtd:
  |   +-- Open /etc/stargazer/stargazer.db (SQLite)
  |   +-- Boot integrity check:
  |   |   +-- BOOT_FIRST:      empty DB → seed defaults (admin, profiles, policies)
  |   |   +-- BOOT_NORMAL:     seeded flag + data present → continue
  |   |   +-- BOOT_CORRUPTED:  flag but missing data → REFUSE TO START
  |   |   +-- BOOT_COMPROMISED: data but no flag (tampering) → REFUSE TO START
  |   +-- Sync interfaces (discover NICs, create DB entries)
  |   +-- Init firewall (INPUT DROP, loopback ACCEPT, conntrack ACCEPT)
  |   +-- Replay saved config (routes, interfaces, NAT, DHCP)
  |   +-- Listen on /run/stargazer-mgmtd.sock (signal ready)
  |
  +-- Login loop
      +-- Spawn stargazer-logind → authenticate → exec shell → CLI
```

---

## 3. Packet Flow — Data Plane

How a network packet traverses the system.

### 3.1 Forwarded Traffic (LAN ↔ WAN)

```
                Ingress NIC                              Egress NIC
                    |                                        ^
                    v                                        |
            +---------------+                        +------+------+
            |  PREROUTING   |                        | POSTROUTING |
            |  (nat table)  |                        | (nat table) |
            |               |                        |             |
            |  DNAT rules   |                        |  SNAT/MASQ  |
            |  (port fwd)   |                        |  rules      |
            +-------+-------+                        +------^------+
                    |                                        |
                    v                                        |
            +---------------+                                |
            |   ROUTING     |                                |
            |   DECISION    |                                |
            |  (ip route)   |                                |
            +-------+-------+                                |
                    |                                        |
                    v                                        |
            +------------------------------------------------+
            |              NF_INET_FORWARD                   |
            |                                                |
            |  pkt_forward.ko (priority: NF_IP_PRI_FIRST)    |
            |  +------------------------------------------+  |
            |  | 1. pskb_may_pull(skb, 20)                |  |
            |  | 2. Check IP version == 4                 |  |
            |  | 3. Check IHL >= 5                        |  |
            |  |                                          |  |
            |  | Valid:   pkts_forwarded++  → NF_ACCEPT --+--+
            |  | Invalid: pkts_dropped++   → NF_DROP      |  |
            |  +------------------------------------------+  |
            |                                                |
            |  +------------------------------------------+  |
            |  | [Phase 2: session.ko integration here]   |  |
            |  | extract 5-tuple → sess_get_or_create()   |  |
            |  | sess_update(skb, direction)              |  |
            |  | ML score check → accept/drop             |  |
            |  +------------------------------------------+  |
            |                                                |
            |  nf_conntrack (ESTABLISHED state tracking)     |
            +------------------------------------------------+
```

### 3.2 Management Traffic (to the firewall itself)

```
            Ingress NIC
                |
                v
        +----------------------------------------------------------+
        |  INPUT chain                (iptables, managed by mgmtd) |
        |                                                          |
        |  Default: DROP                                           |
        |                                                          |
        |  Rules:                                                  |
        |  +- lo: ACCEPT (loopback)                                |
        |  +- ESTABLISHED,RELATED: ACCEPT (return traffic)         |
        |  |                                                       |
        |  +- Per-interface chains (SG_IN_<iface>):                |
        |  |   +- allowaccess=ping  → ICMP ACCEPT                  |
        |  |   +- allowaccess=ssh   → TCP/22 ACCEPT                |
        |  |   +- allowaccess=https → TCP/443 ACCEPT               |
        |  |   +- allowaccess=http  → TCP/80 ACCEPT                |
        |  |   +- allowaccess=snmp  → UDP/161 ACCEPT               |
        |  |   +- (final) DROP                                     |
        |  |                                                       |
        |  +- DHCP server: UDP/67 ACCEPT (per-pool interface)      |
        |                                                          |
        +-------+--------------------------------------------------+
                | (if accepted)
                v
        Local processes (mgmtd, logind, webui, sshd, ...)
```

---

## 4. User Interaction Flow

How a human interacts with the system.

```
Serial Console / SSH
        |
        v
+---------------------------------------------------------------+
|  stargazer-logind  (per-login process, starts as root)        |
|                                                               |
|  Phase 1: Cache user data (getpwnam), open /dev/console       |
|  Phase 1.5: Install seccomp-bpf sandbox                       |
|     +-- Block: openat, fork, execve, network sockets          |
|     +-- Block: mmap/mprotect with PROT_EXEC (no shellcode)    |
|     +-- Allow: read/write/AF_UNIX/ioctl (terminal only)       |
|                                                               |
|  Phase 2: Prompt password (echo disabled)                     |
|     +-- IPC → mgmtd AUTH_LOGIN (validates against /etc/shadow)|
|     +-- Constant-time crypt() (no timing attacks)             |
|     +-- Account lockout after N failures (auth_lockouts table)|
|     +-- Forced password change if admin-flag or policy-mismatch|
|                                                                |
|  Phase 3: Drop privileges + exec                              |
|     +-- setsid() + set controlling terminal                   |
|     +-- setgid(gid) + setuid(uid) — permanent drop            |
|     +-- exec /sbin/stargazer-cli                              |
+---------------------------------------------------------------+
        |
        v
+---------------------------------------------------------------+
|  stargazer-cli  (unprivileged, statically linked C binary)    |
|                                                                |
|  Startup:                                                      |
|  +-- Install sandbox (seccomp-bpf + Landlock + drop caps)     |
|  |   +-- Landlock: deny ALL filesystem access                 |
|  |   +-- Capabilities: drop ALL                               |
|  |   +-- seccomp: ~40 syscalls allowed (AF_UNIX, terminal)    |
|  +-- IPC: WHOAMI → get profile + permissions                  |
|  +-- Register commands (filtered by permissions)              |
|  +-- IPC: HISTORY_LOAD → restore readline history             |
|  +-- IPC: SESSION_TAG_NEW → acquire 64-bit session tag        |
|                                                                |
|  Main Loop:                                                    |
|  +-----------------------------------------------------+      |
|  |  stargazer> _                                        |      |
|  |                                                      |      |
|  |  +- User types command                               |      |
|  |  |  (e.g. "exe sys shut" or "conf sys int")          |      |
|  |  |                                                    |      |
|  |  +- Resolve abbreviations (FortiOS-style)             |      |
|  |  |  "exe sys shut" → "execute system shutdown"        |      |
|  |  |                                                    |      |
|  |  +- Permission check (CLI-side, first gate)           |      |
|  |  |                                                    |      |
|  |  +- Dispatch to handler                               |      |
|  |  |  +- show/execute → IPC to mgmtd → print result    |      |
|  |  |  +- configure → enter config context (see §5)      |      |
|  |  |  +- diagnose → IPC to mgmtd → print diagnostics   |      |
|  |  |                                                    |      |
|  |  +- Fetch debug traces from mgmtd (if debug enabled)  |      |
|  |  +- Check session expiry (tag validation)             |      |
|  +-----------------------------------------------------+      |
|                                                                |
|  Idle: polls WHOAMI every ~5s → detects profile changes       |
|  Exit: SESSION_TAG_DEL + HISTORY_SAVE                         |
+---------------------------------------------------------------+
```

---

## 5. Configuration Flow

How configuration changes propagate through the system.

```
Admin types:
  stargazer> configure system interface
  stargazer(interface)> edit port1
  stargazer(port1)> set mode static
  stargazer(port1)> set ip 192.168.1.1/24
  stargazer(port1)> set allowaccess ping ssh https
  stargazer(port1)> set status up
  stargazer(port1)> end                     ← triggers save + apply

  +------------------------------------------------------------------+
  |                      CLI (in-process)                            |
  |                                                                  |
  |  cli_configure.c:                                                |
  |  +-- "set" → buffer key=value in memory (kv_buf, max 64 pairs)   |
  |  +-- "show" → display buffered changes                           |
  |  +-- "abort" → discard buffer, exit context                      |
  |  +-- "end"  → send buffered data via IPC                         |
  |              |                                                   |
  |              v                                                   |
  |  IPC: SG_CMD_CFG_SET  payload="mode=static\nip=192.168.1.1/24\n  |
  |                                allowaccess=ping ssh https\n..."  |
  +------------------------------------------------------------------+
              | Unix Domain Socket
              v
  +------------------------------------------------------------------+
  |                      mgmtd (root daemon)                         |
  |                                                                  |
  |  1. Permission check (server-side, second gate)                  |
  |     +-- "configure" or "admin" permission required               |
  |                                                                  |
  |  2. Validate every field against type registry (sg_validate.c)   |
  |     +-- "mode" → enum:static,dhcp ✓                              |
  |     +-- "ip" → cidr (A.B.C.D/N) ✓                               |
  |     +-- "allowaccess" → access-services (ping ssh https) ✓       |
  |     +-- Unknown key → reject                                     |
  |                                                                  |
  |  3. Check referential integrity                                  |
  |     +-- e.g. can't delete address object referenced by a policy  |
  |                                                                  |
  |  4. Save to SQLite (atomic transaction)                          |
  |     INSERT OR REPLACE INTO config(type,id,key,value)             |
  |                                                                  |
  |  5. Apply to running system (apply_interface):                   |
  |     +-- ip link set port1 up                                     |
  |     +-- ip addr flush dev port1                                  |
  |     +-- ip addr add 192.168.1.1/24 dev port1                    |
  |     +-- iptables: create chain SG_IN_port1                       |
  |     |   +-- -A SG_IN_port1 -p icmp --icmp echo-request -j ACCEPT  |
  |     |   +-- -A SG_IN_port1 -p tcp --dport 22 -j ACCEPT          |
  |     |   +-- -A SG_IN_port1 -p tcp --dport 443 -j ACCEPT         |
  |     |   +-- -A SG_IN_port1 -j DROP                              |
  |     +-- -A INPUT -i port1 -j SG_IN_port1                        |
  |                                                                  |
  |  6. Audit log: "200 OK type=system_interface id=port1 ..."       |
  |                                                                  |
  |  7. Send response → CLI displays result                          |
  +------------------------------------------------------------------+
```

---

## 6. IPC Protocol — CLI ↔ mgmtd

All privileged operations flow through a single Unix domain socket.

```
  CLI Process                                    mgmtd Daemon
  (unprivileged)                                 (root)
       |                                              |
       |  +------------------------------------+      |
       |  | Request (CLI → mgmtd)              |      |
       |  |                                    |      |
       |  | magic:    0x5347 ("SG")            |      |
       |  | version:  2                        |      |
       |  | debug:    flags (mgmtd/auth)       |      |
       |  | cmd:      sg_cmd_t (e.g. 200)      |      |
       |  | username: "admin" (64 bytes)       |------>|
       |  | payload_len: N                     |      |
       |  | session_tag: 0xABCD1234...         |      |
       |  | payload: "key=val\nkey=val\n"      |      |
       |  +------------------------------------+      |
       |                                              |
       |                                     +--------+
       |                                     | Verify |
       |                                     | SO_PEERCRED (UID match)
       |                                     | Session tag valid?
       |                                     | Permission check
       |                                     | Process command
       |                                     | Audit log
       |                                     +--------+
       |                                              |
       |  +------------------------------------+      |
       |  | Response (mgmtd → CLI)             |      |
       |  |                                    |      |
       |  | magic:    0x5347                   |      |
       |  | version:  2                        |<------|
       |  | status:   sg_status_t (0=OK)       |      |
       |  | extra:    "hint text" (256 bytes)  |      |
       |  | payload_len: M                     |      |
       |  | payload: "result data..."          |      |
       |  +------------------------------------+      |
       |                                              |
  (close)                                        (close)
  fresh connection per request
```

### Command Map

```
 Config Reads  (1xx)           Config Writes (2xx)
 +- 100 CFG_GET                +- 200 CFG_SET
 +- 101 CFG_LIST               +- 201 CFG_DEL
 +- 102 CFG_LIST_TYPES         +- 202 CFG_APPLY

 Admin Mgmt    (3xx)           Session       (4xx)
 +- 300 ADMIN_CREATE           +- 400 SESSION_TAG_NEW
 +- 301 ADMIN_DELETE           +- 401 SESSION_TAG_DEL
 +- 302 ADMIN_SET_PW
 +- 303 ADMIN_SET_ENF          Revisions     (5xx) [stubs]
 +- 304 ADMIN_CHECK_PW         +- 500 COMMIT
 +- 305 ADMIN_LOCK_PW          +- 501 REVISIONS
 +- 310 AUTH_LOGIN              +- 502 ROLLBACK
 +- 311 AUTH_CHANGE_PW
 +- 312 AUTH_LOGIN_OK

 System Ops    (6xx)           Diagnostics   (63x-65x)
 +- 600 SYS_POWEROFF           +- 630 DIAG_FW_IPTABLES
 +- 601 SYS_REBOOT             +- 631 DIAG_FW_POLICY
 +- 602 UPGRADE_START           +- 632 DIAG_FW_CONNTRACK
 +- 603 UPGRADE_STATUS          +- 633 DIAG_ROUTES
 +- 604 UPGRADE_PROGRESS        +- 640 DIAG_CPU
 +- 605 NET_PING                +- 641 DIAG_RAM
 +- 606 NET_TRACEROUTE          +- 642 DIAG_DISK
 +- 607 NET_NSLOOKUP            +- 643 DIAG_IFACE_STATS
 +- 608 NET_ARPING              +- 644 DIAG_PROCTOP
 +- 609 UPGRADE_CANCEL          +- 645 DIAG_THERMAL
 +- 610 SHOW_STATUS             +- 646 DIAG_DISK_HEALTH
 +- 611 SHOW_IFACES             +- 650 SHOW_SESSIONS
 +- 612 SHOW_ROUTES             +- 651 SHOW_BOOT_CONFIG
 +- 613 SHOW_CONFIG
 +- 614 SHOW_STATS             Debug/History (66x)
 +- 620 WHOAMI                  +- 660 DEBUG_STATE_GET
                                +- 661 DEBUG_STATE_SET
 Log Mgmt     (67x)            +- 662 DEBUG_STATE_RESET
 +- 670 LOG_AUDIT               +- 663 HISTORY_SAVE
 +- 671 LOG_SYSTEM              +- 664 HISTORY_LOAD
 +- 672 LOG_CLEAR_AUDIT
                                Internal      (9xx)
                                +- 900 PING (keepalive)
                                +- 901 DEBUG_FETCH
```

---

## 7. Security Architecture

### 7.1 Privilege Separation

```
                    +-----------------------------+
                    |         ROOT (UID 0)         |
                    |                              |
                    |  stargazer-mgmtd             |
                    |  +-- All file I/O            |
                    |  +-- /etc/shadow access       |
                    |  +-- iptables / ip commands   |
                    |  +-- SQLite database          |
                    |  +-- Module loading           |
                    |  +-- System power control     |
                    |                              |
                    +--------------+---------------+
                         AF_UNIX socket
                    +--------------+---------------+
                    |      UNPRIVILEGED (UID>0)     |
                    |                               |
                    |  stargazer-logind              |
                    |  +-- Password prompting        |
                    |  +-- Exec CLI after auth       |
                    |                               |
                    |  stargazer-cli                 |
                    |  +-- Readline + display        |
                    |  +-- Command parsing           |
                    |  +-- IPC requests to mgmtd     |
                    |                               |
                    |  Both sandboxed:               |
                    |  +-- seccomp-bpf (~40 syscalls)|
                    |  +-- Landlock (no FS access)   |
                    |  +-- Capabilities dropped      |
                    |  +-- PR_SET_NO_NEW_PRIVS       |
                    +-------------------------------+
```

### 7.2 Authentication Flow

```
User connects
  |
  v
logind: prompt "Login: " → read username
logind: prompt "Password: " → read (echo off)
  |
  v
IPC: AUTH_LOGIN → mgmtd
  |
  v
mgmtd:
  +-- Check auth_lockouts table (locked? too many fails?)
  +-- getspnam(user) → read /etc/shadow
  +-- crypt(password, hash) → constant-time compare
  |
  +-- FAIL → increment fail_count, lock if threshold reached
  |          return SG_ERR_AUTH_FAIL
  |
  +-- OK → clear fail_count
  |        check enforce-change-password flag
  |        check password against current policy
  |        return SG_OK + enforce/mismatch flags
  |
  v
logind:
  +-- If enforce_change=1 → force password change dialog
  +-- If policy_mismatch=1 → force password change dialog
  +-- IPC: AUTH_LOGIN_OK → mgmtd (audit: successful login)
  |
  v
Drop privileges → exec stargazer-cli
```

### 7.3 Session Tag Lifecycle

```
CLI Login:
  CLI --SESSION_TAG_NEW--> mgmtd generates 64-bit random tag
  CLI <-- tag=0xABCD... -- mgmtd stores (user, tag, expiry)

Every IPC Request:
  CLI sends tag in header → mgmtd validates against stored tags
  Invalid/expired → SG_ERR_SESSION_EXPIRED → CLI kicks user

Admin Changes User Profile:
  mgmtd -- session_tag_purge_user(username) → all tags invalidated
  Next CLI request → SESSION_EXPIRED → forced re-login

CLI Logout:
  CLI --SESSION_TAG_DEL--> mgmtd removes tag
```

---

## 8. Storage Layout

### 8.1 eMMC Partitions (GPT)

```
+----------------------------------------------------------------------+
| eMMC Device (mmcblk0)                                                |
|                                                                      |
|  HW Partition: boot0                                                 |
|  +-- BL2 preloader (EMMC_BOOT header, ~256KB)                       |
|                                                                      |
|  User Partition (GPT):                                               |
|  +--------+----------+--------+----------+----------+----------+    |
|  |  P1    |   P2     |  P3    |   P4     |   P5     |   P6     |    |
|  |u-boot  | factory  |  fip   | firmware | sgdata   | sglogs   |    |
|  |-env    |          |        |          |          |          |    |
|  |512KB   |  4MB     |  2MB   |  64MB    |  512MB   |  512MB   |    |
|  |        |          |BL31+   | FIT:     |/etc/     |/etc/     |    |
|  |        |          |U-Boot  | kernel   |stargazer |stargazer |    |
|  |        |          |        | +initrd  |          |/logs     |    |
|  |        |          |        | +dtb     | DB +     | audit    |    |
|  |        |          |        |          | shadow   | +system  |    |
|  +--------+----------+--------+----------+----------+----------+    |
+----------------------------------------------------------------------+
```

### 8.2 Filesystem Layout (initramfs)

```
/
+-- bin/            busybox symlinks, dash
+-- sbin/
|   +-- stargazer-cli
|   +-- stargazer-mgmtd
|   +-- stargazer-logind
|   +-- iptables, ip
|   +-- sg-partinit
+-- etc/
|   +-- stargazer/           ← sgdata (P5) mounted here
|   |   +-- stargazer.db     SQLite config database
|   |   +-- logs/            ← sglogs (P6) mounted here
|   |       +-- audit.log    persistent audit trail
|   +-- init.d/stargazer     module/sysctl loader
|   +-- modules-load.d/      kernel modules to load
|   +-- sysctl.d/            kernel parameters
|   +-- shadow, passwd, group (restored from sgdata)
|   +-- hostname
+-- lib/modules/stargazer/
|   +-- pkt_forward.ko
|   +-- nf_conntrack_tftp.ko
|   +-- nf_nat_tftp.ko
+-- run/
|   +-- stargazer-mgmtd.sock Unix domain socket
|   +-- mgmtd-ready          FIFO for boot sync
+-- var/log/                  fallback log location (tmpfs)
+-- proc/, sys/, dev/, tmp/   virtual filesystems
+-- init                      PID 1 script
```

---

## 9. Config Object Model

The database stores all configuration as typed key-value entries.

```
+----------------------------------------------------------+
|                    Config Types                           |
|                                                          |
|  TABLE types (multiple entries, each with unique ID):    |
|  +--------------------+------------------------------+   |
|  | system_interface   | NIC config (ip, mode, mtu)   |   |
|  | system_admin       | Admin users + profiles       |   |
|  | system_admin-profile| Permission profiles          |   |
|  | network_route_static| Static routes               |   |
|  | network_route_policy| Policy-based routing        |   |
|  | network_nat        | SNAT/DNAT rules              |   |
|  | network_dhcp-server| DHCP pools per-interface     |   |
|  | firewall_policy    | Firewall rules               |   |
|  | firewall_address   | Address objects              |   |
|  | firewall_service   | Service objects              |   |
|  +--------------------+------------------------------+   |
|                                                          |
|  SINGLE types (one global entry, ID = "0"):              |
|  +--------------------+------------------------------+   |
|  | system_settings    | Hostname, ip_forward, tz     |   |
|  | system_ntp         | NTP server                   |   |
|  | system_password-pol| Password requirements        |   |
|  | network_dns        | DNS forwarder settings       |   |
|  | network_ospf/rip/bgp| Dynamic routing (stubs)    |   |
|  +--------------------+------------------------------+   |
|                                                          |
|  Storage in SQLite:                                      |
|  +------------------+-----+------+-------------------+   |
|  | type             | id  | key  | value             |   |
|  +------------------+-----+------+-------------------+   |
|  | system_interface |port1| mode | static            |   |
|  | system_interface |port1| ip   | 192.168.1.1/24    |   |
|  | system_interface |port1|status| up                |   |
|  | network_nat      | 1   | type | snat              |   |
|  | network_nat      | 1   |srcintf| wan              |   |
|  | firewall_policy  | 1   |action| deny              |   |
|  +------------------+-----+------+-------------------+   |
+----------------------------------------------------------+
```

---

## 10. Apply Handlers — Config to Running System

When a config entry is saved, mgmtd applies it to the live system:

```
Config Type             Apply Handler           System Effect
--------------------    ------------------      -------------------------
system_settings         apply_settings()        sethostname(), ip_forward
system_interface        apply_interface()       ip link/addr, iptables INPUT
network_route_static    apply_route_static()    ip route replace/del
network_nat             apply_nat()             iptables -t nat SNAT/DNAT
network_dhcp-server     apply_dhcp()            udhcpd start/stop, iptables
network_dns             apply_dns()             [stub — not yet implemented]
firewall_policy         [none yet]              [stub — policies stored only]
network_ospf/rip/bgp    [none yet]              [stub — stored only]
```

### Replay on Boot

```
mgmtd_replay_config() — called during daemon startup:
  |
  +-- Flush NAT tables (clean slate)
  +-- For each config type with an apply handler:
  |   +-- List all entries from database
  |   +-- Call apply handler for each entry
  |       +-- Routes applied via ip route
  |       +-- Interfaces configured via ip link/addr
  |       +-- NAT rules inserted via iptables
  |       +-- DHCP servers started via udhcpd
  |       +-- Allowaccess rules applied per-interface
  +-- Log any failures (non-fatal, continues)
```

---

## 11. Diagnostic & Monitoring Commands

```
CLI Command                      IPC Cmd    Source of Data
----------------------------     -------    -------------------------
show status                      610        lsmod + modinfo
show interfaces                  611        ip addr show
show routes                      612        ip route
show stats                       614        dmesg | grep pkt_forward
show sessions                    650        /proc/stargazer/sessions
show firmware                    603        /etc/stargazer/fw_state

execute log audit [N]            670        /etc/stargazer/logs/audit.log
execute log system               671        dmesg
execute log clear audit          672        truncate audit.log

execute ping <host>              605        ping (streaming)
execute traceroute <host>        606        traceroute (streaming)
execute nslookup <host>          607        nslookup
execute arping <ip> [iface]      608        arping (streaming)

execute diagnose top [int] [n]   644        /proc/stat + /proc/*/stat
execute diagnose resources       640-645    /proc/stat, meminfo, statvfs
execute diagnose selftest        local      715 built-in tests
execute diagnose firewall policy 630        iptables -L -n -v
execute diagnose firewall conntrack 632     /proc/net/nf_conntrack
execute diagnose routes          633        ip route (v4+v6)
```

---

## 12. Module Architecture — Source Files

```
src/
+-- modules/                            KERNEL SPACE
|   +-- pkt_forward.c                   NF_INET_FORWARD hook (active)
|   +-- session.c                       RCU session table (disabled, Phase 2)
|   +-- Makefile
|
+-- userspace/                          USER SPACE
    +-- init                            PID 1 boot script
    +-- boot/
    |   +-- extlinux.conf               Boot config
    |   +-- stargazer.its               FIT image description
    |
    +-- cli/                            CLI (unprivileged)
    |   +-- stargazer-cli.c             Entry point, main loop
    |   +-- cli_readline.c              Zero-fork readline engine
    |   +-- cli_ipc.c                   IPC client (AF_UNIX)
    |   +-- cli_cmd_table.c             Command handlers (show/execute/diag)
    |   +-- cli_configure.c             FortiOS-style config contexts
    |   +-- cli_dispatch.c              Command routing + abbreviation
    |   +-- cli_sandbox.c               seccomp + Landlock + caps
    |   +-- cli_show.c                  Show command formatters
    |   +-- cli_debug.c                 Debug state management
    |   +-- cli_diagnose*.c             Diagnostic + selftest suites
    |   +-- Makefile
    |
    +-- mgmtd/                          mgmtd (root daemon)
    |   +-- stargazer-mgmtd.c           Main daemon, request dispatch
    |   +-- stargazer_ipc.h             IPC protocol (shared with CLI)
    |   +-- mgmtd_internal.h            Internal API declarations
    |   +-- sg_db.c / sg_db.h           SQLite database layer
    |   +-- mgmtd_user.c               Admin/user/auth management
    |   +-- mgmtd_firmware.c            Firmware upgrade handler
    |   +-- mgmtd_network.c             ping/traceroute/nslookup
    |   +-- mgmtd_diag.c               System diagnostics (CPU/RAM/disk)
    |   +-- mgmtd_apply_iface.c         Interface + allowaccess
    |   +-- mgmtd_apply_route.c         Static route management
    |   +-- mgmtd_apply_nat.c           NAT rule management
    |   +-- mgmtd_apply_dns.c           DNS config (stub)
    |   +-- mgmtd_apply_dhcp.c          DHCP server management
    |   +-- Makefile
    |
    +-- logind/                         Login daemon
    |   +-- stargazer-logind.c          Auth, sandbox, privilege drop
    |
    +-- common/                         Shared code (CLI + mgmtd)
    |   +-- sg_validate.c              Type registry + field validation
    |   +-- sg_cmd_defs.h              X-macro command table (CLI)
    |   +-- password_policy.c           Password strength rules
    |
    +-- tools/
    |   +-- sg-partinit.c              First-boot partition creator
    |
    +-- webui/www/                      Web UI frontend (in progress)
    |   +-- index.html, login.html
    |   +-- js/app.js, js/login.js
    |   +-- css/stargazer.css
    |
    +-- etc/                            Config templates
    |   +-- init.d/stargazer            Service script
    |   +-- modules-load.d/             Module list
    |   +-- sysctl.d/                   Kernel parameters
    |
    +-- usr/libexec/stargazer/
        +-- db_schema.sql               SQLite schema
```

---

## 13. What Works Today (v0.1.3)

| Feature | Status |
|---------|--------|
| eMMC boot chain (BL2 → ATF → U-Boot → FIT) | Working |
| Kernel data-plane (pkt_forward, IPv4 validation) | Working |
| Persistent config (SQLite on sgdata partition) | Working |
| Persistent audit logs (sglogs partition) | Working |
| CLI with FortiOS-style abbreviation | Working |
| Admin users + profiles + permissions | Working |
| Password auth + policy enforcement + lockout | Working |
| Session tags (idle kick, profile change detection) | Working |
| seccomp-bpf + Landlock sandbox (CLI + logind) | Working |
| Interface config (static/DHCP, allowaccess) | Working |
| Static routes | Working |
| NAT (SNAT masquerade + DNAT port forwarding) | Working |
| DHCP server (per-interface pools) | Working |
| Firmware upgrade (download + verify + install) | Working |
| Network diagnostics (ping, traceroute, nslookup, arping) | Working |
| System diagnostics (CPU, RAM, disk, thermal, top) | Working |
| Log viewing (audit + system) and clearing | Working |
| QEMU test environment + 715 self-tests | Working |

## 14. What's Next

| Feature | Status | Notes |
|---------|--------|-------|
| Session tracking (session.ko → pkt_forward) | Phase 2 | Code exists, not wired |
| /proc/stargazer/sessions procfs export | Phase 2 | mgmtd already expects it |
| Firewall policy → iptables translation | Phase 2 | Schema + objects defined |
| DNS forwarder (dnsmasq or built-in) | Phase 2 | Schema defined, apply stub |
| IPS module + ML scoring daemon | Phase 3 | Architecture planned |
| Netlink interface (ML score feedback) | Phase 3 | Not started |
| Dynamic routing (OSPF/RIP/BGP) | Future | Schema defined |
| Web UI backend | In progress | Frontend exists |
| DHCP selftest | In progress | Agent working on it |
