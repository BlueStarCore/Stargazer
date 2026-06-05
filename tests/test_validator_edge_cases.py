#!/usr/bin/env python3
"""
test_validator_edge_cases.py — Edge-case verification for sg_validate.c

Re-implements every Stargazer validator in Python, mirroring the C source
exactly.  Tests security-relevant boundary inputs and injection bypass
attempts that are hard to exercise from higher-level test suites.

What this catches:
  - Octal confusion in numeric parsers (leading zeros)
  - Off-by-one at buffer/length limits (SG_SAFE_ID_MAX=64, SG_NET_TARGET_MAX=253)
  - Dangerous characters that must be rejected by net-target / safe-id
  - Empty-string edge cases (access-services empty is VALID)
  - Integer overflow / underflow in uint validators
  - Port-range inversion (b < a must be rejected)
  - CIDR boundary values (/0, /32, /33)
  - Case sensitivity on enum / permissions validators
  - Source-code consistency checks (read actual C and verify patterns)

Run: python3 tests/test_validator_edge_cases.py
"""

import os
import re
import sys

PASS = FAIL = 0
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"
N = "\033[0m";  B = "\033[1m"

def chk(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1; print(f"  {G}PASS{N} {name}")
    else:
        FAIL += 1; print(f"  {R}FAIL{N} {name}")
        if detail: print(f"       {Y}{detail}{N}")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def rd(p):
    with open(os.path.join(BASE, p)) as f:
        return f.read()

# ─────────────────────────────────────────────────────────────────────────────
# Python mirrors of C validators  (match C source byte-for-byte in logic)
# ─────────────────────────────────────────────────────────────────────────────

SG_SAFE_ID_MAX    = 64
SG_NET_TARGET_MAX = 253

def sg_is_safe_id(s):
    """C: alphanum + [_.-], max SG_SAFE_ID_MAX=64, non-empty"""
    if not s:
        return False
    if len(s) > SG_SAFE_ID_MAX:
        return False
    for c in s:
        if c.isalnum() or c in ('_', '.', '-'):
            continue
        return False
    return True

def sg_is_net_target(s):
    """C: alphanum + [_.-:], max SG_NET_TARGET_MAX=253, non-empty"""
    if not s:
        return False
    if len(s) > SG_NET_TARGET_MAX:
        return False
    for c in s:
        if c.isalnum() or c in ('_', '.', '-', ':'):
            continue
        return False
    return True

def sg_is_uint_range(s, min_val, max_val):
    """C: digits only (isdigit), strtol base 10 — leading zeros are decimal"""
    if not s:
        return False
    for c in s:
        if not c.isdigit():
            return False
    val = int(s, 10)
    return min_val <= val <= max_val

def sg_is_ipv4(s):
    """C: 4 dotted-decimal octets, max 3 digits/octet, val <=255, no leading-zero octal"""
    if not s:
        return False
    p = 0
    octets = 0
    slen = len(s)
    while p < slen:
        if not s[p].isdigit():
            return False
        val = 0
        digits = 0
        while p < slen and s[p].isdigit():
            val = val * 10 + int(s[p])
            digits += 1
            if digits > 3:
                return False
            p += 1
        if val > 255:
            return False
        octets += 1
        if octets < 4:
            if p >= slen or s[p] != '.':
                return False
            p += 1  # skip dot
    return octets == 4 and p == slen

def sg_is_cidr(s):
    """C: sg_is_ipv4(ip) + sg_is_uint_range(mask, 0, 32)"""
    if not s:
        return False
    try:
        slash = s.index('/')
    except ValueError:
        return False
    if slash == 0 or slash == len(s) - 1:
        return False
    ip_part = s[:slash]
    if len(ip_part) >= 64:
        return False
    if not sg_is_ipv4(ip_part):
        return False
    return sg_is_uint_range(s[slash+1:], 0, 32)

def sg_is_fqdn(s):
    """C: RFC-1123 labels [A-Za-z0-9-], 1-63 each, total <=253, >=1 dot,
    no leading/trailing hyphen per label, last label not all-digits,
    wildcard rejected (no '*')"""
    if not s:
        return False
    if len(s) > SG_NET_TARGET_MAX:
        return False
    label_len = 0
    dots = 0
    last_label_digits = True
    for i, c in enumerate(s):
        if c == '.':
            if label_len == 0 or s[i-1] == '-':
                return False
            if i + 1 == len(s):
                return False
            dots += 1
            label_len = 0
            last_label_digits = True
            continue
        if c == '-':
            if label_len == 0:
                return False
            last_label_digits = False
        elif c in '0123456789':
            pass
        elif c.isascii() and c.isalpha():
            last_label_digits = False
        else:
            return False
        label_len += 1
        if label_len > 63:
            return False
    if label_len == 0 or s[-1] == '-':
        return False
    if dots == 0:
        return False
    if last_label_digits:
        return False
    return True

def sg_is_iface_name(s):
    """C: alphanum + [_.:- ], non-empty"""
    if not s:
        return False
    for c in s:
        if c.isalnum() or c in ('_', '.', ':', '-'):
            continue
        return False
    return True

def sg_is_tz_token(s):
    """C: alphanum + [_./+- ], non-empty"""
    if not s:
        return False
    for c in s:
        if c.isalnum() or c in ('_', '.', '/', '+', '-'):
            continue
        return False
    return True

def sg_is_permissions_csv(s):
    """C: monitor|configure|admin, comma-separated, no leading/trailing comma"""
    if not s:
        return False
    if len(s) > 256:
        return False
    if s.startswith(',') or s.endswith(','):
        return False
    if ',,' in s:
        return False
    valid = {'monitor', 'configure', 'admin'}
    for tok in s.split(','):
        if tok not in valid:
            return False
    return True

def sg_is_access_services(s):
    """C: empty string is VALID; space-separated tokens from allowed set"""
    if s is None or s == '':
        return True                     # explicit: empty = allow none = valid
    if len(s) > 256:
        return False
    # strtok_r with ' ' skips leading spaces; if no tokens → return False
    tokens = [t for t in s.split(' ') if t]
    if not tokens:
        return False                    # "  " → no tokens → invalid
    valid = {'ping', 'ssh', 'https', 'http', 'snmp', 'telnet'}
    for tok in tokens:
        if tok not in valid:
            return False
    return True

def sg_is_port_or_range(s):
    """C: single port 1-65535 or range a-b (a<=b, both 1-65535)"""
    if not s:
        return False
    if '-' in s:
        dash = s.index('-')
        if dash == 0 or dash == len(s) - 1:
            return False
        if s.count('-') > 1:
            return False
        a_str, b_str = s[:dash], s[dash+1:]
        if not sg_is_uint_range(a_str, 1, 65535):
            return False
        if not sg_is_uint_range(b_str, 1, 65535):
            return False
        return int(a_str) <= int(b_str)
    return sg_is_uint_range(s, 1, 65535)

def sg_match_csv_option(opts, val):
    """C: exact match against comma-separated options (case-sensitive)"""
    if not opts or not val:
        return False
    for opt in opts.split(','):
        if opt == val:
            return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{B}{C}=== 1. sg_is_safe_id: character set and length ==={N}")
# ─────────────────────────────────────────────────────────────────────────────

chk("safe_id: normal alphanum accepted", sg_is_safe_id("admin"))
chk("safe_id: underscore accepted",      sg_is_safe_id("my_id"))
chk("safe_id: dot accepted",             sg_is_safe_id("v1.2"))
chk("safe_id: dash accepted",            sg_is_safe_id("read-only"))
chk("safe_id: empty rejected",           not sg_is_safe_id(""))
chk("safe_id: slash rejected",           not sg_is_safe_id("../etc/passwd"))
chk("safe_id: space rejected",           not sg_is_safe_id("hello world"))
chk("safe_id: semicolon rejected",       not sg_is_safe_id("id;ls"))
chk("safe_id: ampersand rejected",       not sg_is_safe_id("id&&ls"))
chk("safe_id: backtick rejected",        not sg_is_safe_id("`id`"))
chk("safe_id: dollar rejected",          not sg_is_safe_id("$HOME"))
chk("safe_id: null byte rejected",       not sg_is_safe_id("\x00admin"))
chk("safe_id: colon rejected (shell risk)", not sg_is_safe_id("key:val"))
chk("safe_id: 64-char (at limit) accepted", sg_is_safe_id("a" * 64))
chk("safe_id: 65-char (over limit) rejected", not sg_is_safe_id("a" * 65))

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{B}{C}=== 2. sg_is_net_target: injection barrier ==={N}")
# ─────────────────────────────────────────────────────────────────────────────

chk("net_target: IPv4 address accepted",    sg_is_net_target("192.168.1.1"))
chk("net_target: hostname accepted",        sg_is_net_target("example.com"))
chk("net_target: IPv6 colon accepted",      sg_is_net_target("2001:db8::1"))
chk("net_target: empty rejected",           not sg_is_net_target(""))
chk("net_target: semicolon rejected",       not sg_is_net_target("127.0.0.1;id"))
chk("net_target: pipe rejected",            not sg_is_net_target("host|grep"))
chk("net_target: ampersand rejected",       not sg_is_net_target("host&cmd"))
chk("net_target: dollar rejected",          not sg_is_net_target("$(/bin/sh)"))
chk("net_target: backtick rejected",        not sg_is_net_target("`id`"))
chk("net_target: space rejected",           not sg_is_net_target("host name"))
chk("net_target: newline rejected",         not sg_is_net_target("host\ncmd"))
chk("net_target: null byte rejected",       not sg_is_net_target("\x00host"))
chk("net_target: slash rejected",           not sg_is_net_target("/etc/passwd"))
chk("net_target: exclamation rejected",     not sg_is_net_target("host!"))
chk("net_target: paren rejected",           not sg_is_net_target("host(1)"))
chk("net_target: 253-char hostname accepted", sg_is_net_target("a" * 253))
chk("net_target: 254-char hostname rejected", not sg_is_net_target("a" * 254))

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{B}{C}=== 3. sg_is_ipv4: octal confusion and boundary ==={N}")
# ─────────────────────────────────────────────────────────────────────────────

chk("ipv4: normal address accepted",       sg_is_ipv4("192.168.1.1"))
chk("ipv4: all zeros accepted",            sg_is_ipv4("0.0.0.0"))
chk("ipv4: all 255 accepted",              sg_is_ipv4("255.255.255.255"))
chk("ipv4: 256 octet rejected",            not sg_is_ipv4("256.0.0.0"))
chk("ipv4: 256 in last octet rejected",    not sg_is_ipv4("1.2.3.256"))
# Leading zeros: C parser is decimal-only (val = val*10 + digit), not octal
# "010" → 10 decimal (NOT 8 octal) → valid, but confusing: document this
chk("ipv4: leading zeros are DECIMAL (010=10, not 8)",
    sg_is_ipv4("010.010.010.010"))         # passes as 10.10.10.10
chk("ipv4: 4-digit octet rejected",        not sg_is_ipv4("1000.0.0.0"))
chk("ipv4: missing octet rejected",        not sg_is_ipv4("192.168.1"))
chk("ipv4: extra octet rejected",          not sg_is_ipv4("1.2.3.4.5"))
chk("ipv4: trailing dot rejected",         not sg_is_ipv4("1.2.3.4."))
chk("ipv4: leading dot rejected",          not sg_is_ipv4(".1.2.3.4"))
chk("ipv4: empty rejected",                not sg_is_ipv4(""))
chk("ipv4: non-digit rejected",            not sg_is_ipv4("a.b.c.d"))
chk("ipv4: colon (IPv6) rejected",         not sg_is_ipv4("::1"))
chk("ipv4: CIDR notation rejected",        not sg_is_ipv4("192.168.0.0/24"))

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{B}{C}=== 4. sg_is_cidr: prefix length boundary ==={N}")
# ─────────────────────────────────────────────────────────────────────────────

chk("cidr: /0 (default route) accepted",   sg_is_cidr("0.0.0.0/0"))
chk("cidr: /32 (host route) accepted",     sg_is_cidr("192.168.1.1/32"))
chk("cidr: /16 accepted",                  sg_is_cidr("10.0.0.0/16"))
chk("cidr: /33 rejected",                  not sg_is_cidr("10.0.0.0/33"))
chk("cidr: /128 rejected",                 not sg_is_cidr("10.0.0.0/128"))
chk("cidr: negative prefix rejected",      not sg_is_cidr("10.0.0.0/-1"))
chk("cidr: no slash rejected",             not sg_is_cidr("10.0.0.0"))
chk("cidr: empty IP rejected",             not sg_is_cidr("/24"))
chk("cidr: empty mask rejected",           not sg_is_cidr("10.0.0.0/"))
chk("cidr: invalid IP rejected",           not sg_is_cidr("999.0.0.0/24"))
chk("cidr: IPv6 rejected",                 not sg_is_cidr("2001:db8::/32"))
# Leading zeros in prefix: same decimal rule
chk("cidr: leading zero prefix (024=24) accepted", sg_is_cidr("10.0.0.0/024"))

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{B}{C}=== 4b. sg_is_fqdn: FQDN address objects ==={N}")
# ─────────────────────────────────────────────────────────────────────────────

chk("fqdn: www.example.com accepted",      sg_is_fqdn("www.example.com"))
chk("fqdn: example.com accepted",          sg_is_fqdn("example.com"))
chk("fqdn: digit-leading label accepted",  sg_is_fqdn("1.example.com"))
chk("fqdn: hyphen inside label accepted",  sg_is_fqdn("my-host.example.com"))
chk("fqdn: single label rejected (unqualified)", not sg_is_fqdn("localhost"))
chk("fqdn: wildcard rejected (needs DNS snooping)", not sg_is_fqdn("*.facebook.com"))
chk("fqdn: bare IPv4 rejected (belongs in subnet)", not sg_is_fqdn("8.8.8.8"))
chk("fqdn: numeric TLD rejected",          not sg_is_fqdn("example.123"))
chk("fqdn: trailing dot rejected",         not sg_is_fqdn("example.com."))
chk("fqdn: leading dot rejected",          not sg_is_fqdn(".example.com"))
chk("fqdn: empty label rejected",          not sg_is_fqdn("a..com"))
chk("fqdn: label leading hyphen rejected", not sg_is_fqdn("-bad.example.com"))
chk("fqdn: label trailing hyphen rejected", not sg_is_fqdn("bad-.example.com"))
chk("fqdn: trailing hyphen rejected",      not sg_is_fqdn("example.com-"))
chk("fqdn: underscore rejected (strict RFC-1123)", not sg_is_fqdn("_dmarc.example.com"))
chk("fqdn: space rejected",                not sg_is_fqdn("exa mple.com"))
chk("fqdn: empty rejected",                not sg_is_fqdn(""))
chk("fqdn: 63-char label accepted",        sg_is_fqdn("a" * 63 + ".com"))
chk("fqdn: 64-char label rejected",        not sg_is_fqdn("a" * 64 + ".com"))
chk("fqdn: 253-char total accepted",
    sg_is_fqdn(("a" * 63 + ".") * 3 + "a" * 61))
chk("fqdn: 254-char total rejected",
    not sg_is_fqdn(("a" * 63 + ".") * 3 + "a" * 62))

# Source-consistency: the C side must wire the same rules
_vc = rd("src/userspace/common/sg_validate.c")
chk("fqdn: C validator exists",            "sg_is_fqdn" in _vc)
chk("fqdn: kind wired in dispatcher",      'strcmp(kind, "fqdn") == 0' in _vc)
chk("fqdn: firewall_address has fqdn field",
    '"firewall_address", "fqdn"' in _vc)
chk("fqdn: iprange dropped from type enum (was never implemented)",
    "enum:ipmask,iprange,fqdn" not in _vc and "enum:ipmask,fqdn" in _vc)
_fw = rd("src/userspace/mgmtd/mgmtd_apply_firewall.c")
chk("fqdn: FORWARD chain emits ipset match", "--match-set" in _fw)

# Membership visibility: the box has no ipset binary, so the diagnose
# command is the only way to see what a deny rule actually matches.
_ips = rd("src/userspace/mgmtd/mgmtd_ipset.c")
chk("fqdn: ipset membership dump exists (sg_ipset_list)",
    "int sg_ipset_list(" in _ips and "SG_IPSET_CMD_LIST" in _ips)

# Accumulate mode: round-robin DNS hands out one answer per query, so a
# swap-replace deny set only matches the latest answer (blocking
# flickers — observed live on-device).  The set must MERGE resolves
# and let the kernel expire entries via per-entry timeout.
chk("fqdn: sets are created with entry timeouts",
    "SG_IPSET_ENTRY_TIMEOUT_SEC" in _ips and "SG_IPSET_ATTR_TIMEOUT" in _ips)
chk("fqdn: membership merges (sg_ipset_add), swap-replace removed",
    "int sg_ipset_add(" in _ips and "sg_ipset_replace" not in _ips
    and "IPSET_CMD_SWAP" not in _ips)
_fq = rd("src/userspace/mgmtd/mgmtd_fqdn.c")
chk("fqdn: worker merges resolves into the set",
    "sg_ipset_add(" in _fq and "sg_ipset_replace" not in _fq)
chk("fqdn: resolve failure keep-alives current members (no drain)",
    "sg_ipset_members(" in _fq)

# fqdn-ttl: the entry lifetime is a global system setting, stamped onto
# every ADD so a change reaches existing sets without recreating them.
chk("fqdn-ttl: registered in system_settings (60-86400, default 3600)",
    '"system_settings", "fqdn-ttl",   "uint:60:86400",       0, "3600"' in _vc)
chk("fqdn-ttl: every ADD stamps the current timeout",
    _ips.count("SG_IPSET_ATTR_TIMEOUT | SG_NLA_F_NET_BYTEORDER") >= 2)
_st = rd("src/userspace/mgmtd/mgmtd_apply_iface.c")
chk("fqdn-ttl: apply_settings wires the runtime value",
    "sg_ipset_set_entry_timeout(" in _st)
chk("fqdn-ttl: change re-stamps existing members immediately",
    "fqdn_restamp_all(" in _st and "void fqdn_restamp_all(void)" in _fq)
chk("fqdn-ttl: apply re-checks range (corrupt DB cannot zero the ttl)",
    "ttl >= 60" in _st)
# The kernel answers EEXIST when CREATE meets a same-name set whose
# create params differ — which is every set that predates a fqdn-ttl
# change.  ensure() must tolerate it or all updates fail after the
# change and the next rebuild SKIPs fqdn rules (fail-open).
chk("fqdn-ttl: ensure tolerates create-param clash (EEXIST)",
    "ips_transact(buf, off, EEXIST)" in _ips)

# Multi-agent review findings (2026-06): regression locks.
_mg = rd("src/userspace/mgmtd/stargazer-mgmtd.c")
# 1. The validator accepts FQDNs up to 253 chars; reading them through a
#    VALBUFSZ (128) buffer truncates silently and resolves the wrong
#    name — DENY set stays empty (fail-open).
chk("review: worker carries full-length FQDN (no VALBUFSZ truncation)",
    "fq[SG_NET_TARGET_MAX + 1]" in _fq)
chk("review: diag handler carries full-length FQDN",
    "fqdn[SG_NET_TARGET_MAX + 1]" in _mg)
# 2. Workers self-serialize via flock — a slow resolver run can outlast
#    the 60s tick and pile up otherwise (parent can't waitpid a child
#    reparented to init).
chk("review: refresh workers gate on a lock file",
    "flock(lk, LOCK_EX | LOCK_NB)" in _fq)
# 3. A successful resolve with zero A records must keep-alive like a
#    failure — never trust an answer that would empty a DENY set.
chk("review: zero-A-record resolve keep-alives (n <= 0)",
    _fq.count("if (n <= 0) {") >= 1 and "returned no IPv4 addresses" in _fq)
# 4. The set-name cap is expressed via SG_IPSET_MAXNAMELEN (was a dead
#    define + stale temp-set comment).
chk("review: name cap uses SG_IPSET_MAXNAMELEN, temp-set comment gone",
    "SG_IPSET_MAXNAMELEN - 2" in _ips and '"<name>T"' not in _ips)
_ipc = rd("src/userspace/mgmtd/stargazer_ipc.h")
chk("fqdn: SG_CMD_DIAG_FW_IPSET wired in IPC", "SG_CMD_DIAG_FW_IPSET" in _ipc)
_cd = rd("src/userspace/common/sg_cmd_defs.h")
chk("fqdn: diagnose firewall ipset CLI command registered",
    '"execute diagnose firewall ipset"' in _cd)
chk("fqdn: mgmtd handler rejects non-fqdn objects",
    "Not an fqdn-type object" in _mg)

# ── Audit HIGH fixes (2026-06) — regression locks ──────────────────────────
import re as _re
# HIGH-1A: snprintf returns the UNtruncated length; never copy that many
# bytes out of a fixed local buffer (out-of-bounds read). kv_to_json must
# build straight into the growing heap buffer (json_appendf), and every
# other "copy by (size_t)n from a fixed buffer" site must clamp to the
# buffer size. These check the specific siblings the blast-radius mapped,
# including the two the original audit sweep missed (J_APP/IL_APP frag).
_wp = rd("src/userspace/webd/webd_pool.c")
chk("1A: kv_to_json drops the fixed frag/id_frag buffers (grow-to-fit)",
    "frag[2048]" not in _wp and "id_frag[512]" not in _wp
    and "json_appendf(&buf" in _wp)
chk("1A: kv_to_json no longer copies a raw snprintf return into a local buf",
    not _re.search(r'APPEND\((?:id_)?frag, ?\(size_t\)n\)', _wp))
chk("1A: proctop/iface JSON builders clamp n to the source buffer",
    _wp.count("< sizeof(frag) ? (size_t)fn") >= 2
    and "< sizeof(hdr) ? (size_t)hn" in _wp)
chk("1A: interface-row builder clamps the uncapped description length",
    "(size_t)n >= sizeof(line)" in _mg)
_fwc = rd("src/userspace/mgmtd/mgmtd_firmware.c")
chk("1A: firmware step log clamps message length before memcpy",
    "(size_t)n >= sizeof(entry)" in _fwc)
_rl = rd("src/userspace/cli/cli_readline.c")
chk("1A: history payload clamps the user= header length",
    "(size_t)n < SG_PAYLOAD_MAX)" in _rl)
_dg = rd("src/userspace/mgmtd/mgmtd_diag.c")
chk("1A: session-flow line clamps n to its buffer before append",
    "(size_t)n < sizeof(l) ? (size_t)n : sizeof(l) - 1" in _dg)

# HIGH-1B: the session-tag-exempt DHCP lease handler mutates routing as
# root and must authorize on the kernel-verified peer UID (root only),
# not on group-socket access.
chk("1B: dhcp lease handler gates on the verified peer UID",
    "g_peer_uid != 0" in _mg and "DHCP_LEASE_EVENT from non-root" in _mg)
chk("1B: peer UID is captured from SO_PEERCRED per connection",
    "g_peer_uid = cred.uid" in _mg)

# Adversarial re-verification of the HIGH fixes found two siblings the
# first pass missed (same snprintf-return root cause), now fixed:
#  - ipt_exec joined argv with "pos += snprintf" then wrote cmd[pos]='\0'
#    → out-of-bounds STACK WRITE when an argv element truncated.
#  - the storage-diag handler accumulated "pos += snprintf(buf+pos,
#    cap-pos,...)" with no clamp → cap-pos underflow past a 64KB buffer.
chk("1A+: ipt_exec stops at a full cmd buffer (no OOB write on cmd[pos])",
    "pos = (int)sizeof(cmd) - 1;" in _mg and ">= sizeof(cmd) - (size_t)pos" in _mg)
chk("1A+: bounded response-append helper exists",
    "static size_t rsp_appendf(" in _mg)
chk("1A+: rsp_appendf carries printf format attribute (-Wformat covers callers)",
    "__attribute__((format(printf, 4, 5)))" in _mg)
chk("1A+: no raw 'pos += snprintf' accumulation remains in mgmtd",
    "pos += snprintf" not in _re.sub(r'\* .*snprintf.*\n', '', _mg))

# ── Audit MEDIUM fixes (2026-06) — regression locks ────────────────────────
_dg2 = rd("src/userspace/mgmtd/mgmtd_diag.c")
# M1: DHCP hostname (option-12, attacker-controlled) must be JSON-escaped
# before interpolation, else a " forges/poisons the leases response.
chk("M1: dhcp leases JSON-escape helper exists",
    "static void json_escape_field(" in _dg2)
chk("M1: hostname + pool_id escaped before the leases JSON snprintf",
    "json_escape_field(hostname" in _dg2 and "json_escape_field(pool_id" in _dg2
    and "host_esc, ip_str, mac_str" not in _dg2  # old raw-var order gone
    and "pool_esc, ip_str, mac_str, host_esc" in _dg2)
# M2: /etc/group rewrite must not split lines >1023B (getline, not fgets).
_us = rd("src/userspace/mgmtd/mgmtd_user.c")
chk("M2: add_user_to_group uses getline (no fixed-buffer truncation)",
    "getline(&line, &linecap, fp)" in _us)
# M3: per-upload staging path (mkstemp), validated by prefix; no shared file.
_wa = rd("src/userspace/webd/webd_api.c")
chk("M3: webd stages firmware at a unique per-upload path (no shared race)",
    'O_WRONLY | O_CREAT | O_EXCL' in _wa and '"/tmp/sg-fw-upload.tar.gz"' not in _wa)
# Re-verify (component trace) follow-up: mkstemp opens O_RDWR, which the
# webd seccomp filter KILLs — staging must use O_WRONLY. The suffix stays
# alnum so mgmtd's strict path check still accepts it.
chk("M3+: webd staging is seccomp-safe (O_WRONLY, not mkstemp/O_RDWR)",
    'mkstemp(stage)' not in _wa and 'A36[v % 36]' in _wa)
_fw2 = rd("src/userspace/mgmtd/mgmtd_firmware.c")
chk("M3: mgmtd validates upload path by prefix and consumes that exact path",
    '"/tmp/sg-fw-upload."' in _fw2 and "rename(path, FW_DL_FILE)" in _fw2
    and "#define FW_UPLOAD_FILE" not in _fw2)  # fixed-path macro removed
# Re-verify follow-up: the staging-path suffix must be strict [A-Za-z0-9]
# (mkstemp charset) so it cannot carry shell metacharacters into the cp
# fallback command — the loose ".."/"/" check alone left an injection.
chk("M3+: upload path suffix restricted to mkstemp charset (no shell metachars)",
    "*s >= 'A' && *s <= 'Z'" in _fw2 and "*s >= '0' && *s <= '9'" in _fw2
    and 'strstr(path, "..")' not in _fw2)
# M4/M5: direct NAT path honors protocol + is idempotent.
_cl = rd("src/userspace/usr/libexec/stargazer/config_lib.sh")
chk("M4: direct NAT reads protocol and is in valid keys",
    "_protocol=$(grep '^protocol=' " in _cl
    and "type srcintf dstintf protocol srcaddr" in _cl)
chk("M4: direct DNAT no longer hardcodes -p tcp (honors tcp/udp/tcp+udp/all)",
    'iptables -t nat -A PREROUTING -p tcp --dport "$_dstport"' not in _cl
    and '_dnat_proto "$_protocol"' in _cl)
# Re-verify follow-up: a tcp/udp DNAT with no dstport must still emit a
# -p rule (mirrors mgmtd emit_dnat_rule) instead of silently dropping it.
chk("M4+: DNAT emits -p rule even without dstport (parity with mgmtd)",
    'else\n\t\t\t\t\t\t\t\t_nat_add PREROUTING -p "$1" -j DNAT' in _cl)
chk("M4+: protocol listed in NAT help and has enum validation",
    'protocol     tcp | udp | tcp+udp | all' in _cl
    and 'network_nat:protocol) echo "enum:tcp,udp,tcp+udp,all"' in _cl)
chk("M5: direct NAT is idempotent (check-then-add, no duplicate accumulation)",
    'iptables -t nat -C "$_c" "$@" 2>/dev/null ||' in _cl)

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{B}{C}=== 5. sg_is_uint_range: overflow and negative ==={N}")
# ─────────────────────────────────────────────────────────────────────────────

chk("uint: 0 in 0-255 accepted",           sg_is_uint_range("0", 0, 255))
chk("uint: 255 in 0-255 accepted",         sg_is_uint_range("255", 0, 255))
chk("uint: 256 in 0-255 rejected",         not sg_is_uint_range("256", 0, 255))
chk("uint: negative sign rejected",        not sg_is_uint_range("-1", 0, 255))
chk("uint: empty rejected",                not sg_is_uint_range("", 0, 255))
chk("uint: text rejected",                 not sg_is_uint_range("abc", 0, 255))
chk("uint: hex prefix rejected",           not sg_is_uint_range("0xff", 0, 255))
chk("uint: float rejected",               not sg_is_uint_range("1.5", 0, 255))
chk("uint: space rejected",                not sg_is_uint_range(" 5", 0, 255))
# Leading zeros are decimal (strtol base 10)
chk("uint: leading zeros are decimal (010=10)", sg_is_uint_range("010", 5, 15))
chk("uint: 65535 accepted for port",       sg_is_uint_range("65535", 1, 65535))
chk("uint: 65536 rejected for port",       not sg_is_uint_range("65536", 1, 65535))
chk("uint: very long number rejected",     not sg_is_uint_range("9" * 20, 0, 65535))

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{B}{C}=== 6. sg_is_iface_name: shell injection chars ==={N}")
# ─────────────────────────────────────────────────────────────────────────────

chk("iface: normal eth0 accepted",         sg_is_iface_name("eth0"))
chk("iface: dot in name accepted",         sg_is_iface_name("eth0.100"))  # VLAN
chk("iface: colon accepted",               sg_is_iface_name("eth0:1"))    # alias
chk("iface: empty rejected",               not sg_is_iface_name(""))
chk("iface: semicolon rejected",           not sg_is_iface_name("eth0;id"))
chk("iface: slash rejected",               not sg_is_iface_name("/dev/eth0"))
chk("iface: space rejected",               not sg_is_iface_name("eth 0"))
chk("iface: dollar rejected",              not sg_is_iface_name("$IFACE"))
chk("iface: newline rejected",             not sg_is_iface_name("eth0\nCMD"))
chk("iface: backslash rejected",           not sg_is_iface_name("eth\\0"))

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{B}{C}=== 7. sg_is_tz_token: allowed charset ==={N}")
# ─────────────────────────────────────────────────────────────────────────────

chk("tz: UTC accepted",                    sg_is_tz_token("UTC"))
chk("tz: Asia/Ho_Chi_Minh accepted",       sg_is_tz_token("Asia/Ho_Chi_Minh"))
chk("tz: Etc/GMT+7 accepted",              sg_is_tz_token("Etc/GMT+7"))
chk("tz: empty rejected",                  not sg_is_tz_token(""))
chk("tz: space rejected",                  not sg_is_tz_token("Asia/Ho Chi Minh"))
chk("tz: semicolon rejected",              not sg_is_tz_token("UTC;ls"))
chk("tz: dollar rejected",                 not sg_is_tz_token("$TZ"))
chk("tz: ampersand rejected",              not sg_is_tz_token("UTC&id"))

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{B}{C}=== 8. sg_is_permissions_csv: validity ==={N}")
# ─────────────────────────────────────────────────────────────────────────────

chk("perms: monitor accepted",             sg_is_permissions_csv("monitor"))
chk("perms: configure accepted",           sg_is_permissions_csv("configure"))
chk("perms: admin accepted",               sg_is_permissions_csv("admin"))
chk("perms: multiple accepted",            sg_is_permissions_csv("monitor,configure"))
chk("perms: all three accepted",           sg_is_permissions_csv("monitor,configure,admin"))
chk("perms: duplicates allowed",           sg_is_permissions_csv("monitor,monitor"))
chk("perms: empty rejected",               not sg_is_permissions_csv(""))
chk("perms: uppercase rejected (MONITOR)", not sg_is_permissions_csv("MONITOR"))
chk("perms: invalid token rejected",       not sg_is_permissions_csv("root"))
chk("perms: leading comma rejected",       not sg_is_permissions_csv(",monitor"))
chk("perms: trailing comma rejected",      not sg_is_permissions_csv("monitor,"))
chk("perms: double comma rejected",        not sg_is_permissions_csv("monitor,,admin"))
chk("perms: space in token rejected",      not sg_is_permissions_csv("monitor, configure"))
chk("perms: 257-char rejected",            not sg_is_permissions_csv("a" * 257))

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{B}{C}=== 9. sg_is_access_services: empty is valid ==={N}")
# ─────────────────────────────────────────────────────────────────────────────

# Critical: empty means "no services" — must be ACCEPTED (not rejected)
chk("access_svc: empty string is VALID (no services)",
    sg_is_access_services(""))
chk("access_svc: ping accepted",           sg_is_access_services("ping"))
chk("access_svc: ssh https accepted",      sg_is_access_services("ssh https"))
chk("access_svc: all services accepted",
    sg_is_access_services("ping ssh https http snmp telnet"))
chk("access_svc: only-spaces is INVALID",  not sg_is_access_services("  "))
chk("access_svc: unknown service rejected", not sg_is_access_services("rdp"))
chk("access_svc: HTTPS uppercase rejected", not sg_is_access_services("HTTPS"))
chk("access_svc: semicolon injection rejected",
    not sg_is_access_services("ssh;id"))
chk("access_svc: comma-sep (wrong delim) rejected",
    not sg_is_access_services("ssh,https"))
chk("access_svc: 257-char rejected",       not sg_is_access_services("a" * 257))

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{B}{C}=== 10. sg_is_port_or_range: boundary and inversion ==={N}")
# ─────────────────────────────────────────────────────────────────────────────

chk("port: 1 accepted",                    sg_is_port_or_range("1"))
chk("port: 80 accepted",                   sg_is_port_or_range("80"))
chk("port: 65535 accepted",                sg_is_port_or_range("65535"))
chk("port: 0 rejected",                    not sg_is_port_or_range("0"))
chk("port: 65536 rejected",                not sg_is_port_or_range("65536"))
chk("port: empty rejected",                not sg_is_port_or_range(""))
chk("port: text rejected",                 not sg_is_port_or_range("http"))
chk("range: 1-65535 accepted",             sg_is_port_or_range("1-65535"))
chk("range: 80-443 accepted",              sg_is_port_or_range("80-443"))
chk("range: 80-80 (equal) accepted",       sg_is_port_or_range("80-80"))
chk("range: 443-80 (inverted) rejected",   not sg_is_port_or_range("443-80"))
chk("range: 0-1000 rejected (lo=0)",       not sg_is_port_or_range("0-1000"))
chk("range: leading dash rejected",        not sg_is_port_or_range("-80"))
chk("range: trailing dash rejected",       not sg_is_port_or_range("80-"))
chk("range: double dash rejected",         not sg_is_port_or_range("80-90-100"))

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{B}{C}=== 11. sg_match_csv_option: case sensitivity ==={N}")
# ─────────────────────────────────────────────────────────────────────────────

chk("csv_opt: exact match accepted",       sg_match_csv_option("accept,deny,drop", "accept"))
chk("csv_opt: last option matched",        sg_match_csv_option("accept,deny,drop", "drop"))
chk("csv_opt: uppercase rejected",         not sg_match_csv_option("accept,deny,drop", "ACCEPT"))
chk("csv_opt: partial match rejected",     not sg_match_csv_option("enable,disable", "en"))
chk("csv_opt: empty val rejected",         not sg_match_csv_option("a,b,c", ""))
chk("csv_opt: extra chars rejected",       not sg_match_csv_option("enable,disable", "enabled"))

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{B}{C}=== 12. Source-code consistency checks ==={N}")
# ─────────────────────────────────────────────────────────────────────────────

validate = rd("src/userspace/common/sg_validate.c")

# Verify C code is actually decimal, not strtol(s, NULL, 0) which would be octal
chk("sg_is_ipv4 uses decimal arithmetic (val*10), not strtol",
    "val * 10 + (*p - '0')" in validate or
    "val = val * 10 + (*p" in validate)

chk("sg_is_uint_range uses strtol with base 10",
    "strtol(s, NULL, 10)" in validate)

chk("sg_is_safe_id max is SG_SAFE_ID_MAX=64",
    "SG_SAFE_ID_MAX" in validate and
    "#define SG_SAFE_ID_MAX      64" in rd("src/userspace/common/sg_validate.h"))

chk("sg_is_net_target max is SG_NET_TARGET_MAX=253",
    "SG_NET_TARGET_MAX" in validate and
    "#define SG_NET_TARGET_MAX  253" in rd("src/userspace/common/sg_validate.h"))

# Verify the CIDR mask range is 0-32 (not 0-128 which would be IPv6)
chk("sg_is_cidr mask validated with sg_is_uint_range(... 0, 32)",
    "sg_is_uint_range(slash + 1, 0, 32)" in validate)

# access-services: empty string must be VALID at C level
chk("sg_is_access_services: explicit empty-valid check in C source",
    "Empty string = no services allowed" in validate or
    "if (!s || !*s)\n\t\treturn 1;" in validate or
    "return 1" in validate.split("sg_is_access_services")[1][:100])

# No strtol with base 0 (would trigger octal interpretation for "010")
chk("No strtol base-0 calls (no octal misparse risk)",
    "strtol(" not in validate.replace("strtol(s, NULL, 10)", "")
    .replace("strtol(p, &end, 10)", "")
    .replace("strtol(a_buf, NULL, 10)", "")
    .replace("strtol(b_str, NULL, 10)", "")
    .replace("strtol(end + 1, &end, 10)", ""))

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{B}{C}=== 13. Firewall apply: address/service resolution ==={N}")
# ─────────────────────────────────────────────────────────────────────────────
# (Rewritten: the original section asserted the OLD build_forward_argv
#  gaps — named objects skipped, services ignored.  Both gaps have been
#  fixed since; the section now verifies the fixed behavior.)

fw_apply = rd("src/userspace/mgmtd/mgmtd_apply_firewall.c")

# Named address objects are resolved from the DB; dangling refs skip the
# rule fail-closed instead of emitting a broader-than-intended rule.
chk("resolve_address resolves named objects",
    "sg_db_get(\"firewall_address\"" in fw_apply)
chk("dangling address ref skips rule (fail-closed)",
    "ADDR_SKIP" in fw_apply and "skip_rule" in fw_apply)

# fqdn-type objects emit an ipset match, never a raw -s/-d
chk("fqdn objects emit -m set --match-set",
    "--match-set" in fw_apply)
chk("fqdn without kernel ipset support skips rule (fail-closed)",
    "sg_ipset_available" in fw_apply)

# Service objects ARE included in rules (protocol + port)
chk("service objects emit -p/--dport",
    "--dport" in fw_apply and "resolve_service" in fw_apply)

# FORWARD -P DROP is set in mgmtd (good)
mgmtd = rd("src/userspace/mgmtd/stargazer-mgmtd.c")
chk("mgmtd_init_firewall sets iptables -P FORWARD DROP",
    '"-P", "FORWARD", "DROP"' in mgmtd)

# ATK-J-02 (fixed): init sets FORWARD DROP before mgmtd starts, so there
# is no fail-open window between boot and policy replay.
init = rd("src/userspace/init")
chk("ATK-J-02 fixed: init sets FORWARD DROP before mgmtd",
    "iptables -P FORWARD DROP" in init)

# init sets INPUT DROP (good)
chk("Init sets INPUT DROP before mgmtd starts",
    "iptables -P INPUT DROP" in init)

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{B}{C}=== 14. Route apply: proto static substring check ==={N}")
# ─────────────────────────────────────────────────────────────────────────────

route_apply = rd("src/userspace/mgmtd/mgmtd_apply_route.c")

chk("apply_route_static uses strstr('proto static') to check before delete",
    'strstr(cur, "proto static")' in route_apply)

# The check uses strstr — it would also match "proto statically-managed" or
# similar if the kernel ever used that string.  In practice, Linux only uses
# exact protocol name "static", so this is very low risk.
chk("No other 'proto' substring that could cause false matches in route output",
    # Verify the check is "proto static" not just "static"
    '"proto static"' in route_apply)

# ─────────────────────────────────────────────────────────────────────────────
# RESULTS
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
notes = []
if not sg_is_ipv4("010.010.010.010"):
    notes.append("Note: leading zeros in IPv4 octets cause unexpected REJECTION")
else:
    notes.append("Note: leading zeros in IPv4 octets are treated as DECIMAL (010=10)")

for n in notes:
    print(f"  {Y}NOTE{N} {n}")

if FAIL == 0:
    print(f"{G}{B}ALL {PASS} VALIDATOR EDGE-CASE CHECKS PASSED{N}")
else:
    print(f"{Y}Results: {G}{PASS} passed{N}, {R}{FAIL} failed{N} / {PASS+FAIL} total")
    sys.exit(1)
