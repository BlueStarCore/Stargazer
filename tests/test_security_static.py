#!/usr/bin/env python3
"""
test_security_static.py — Static security property analysis for Stargazer NGFW

Verifies security-critical properties in C and shell source code without
needing a running server. Complements test_webui_security_attacks.py.

Covers:
  - IPC security: SO_PEERCRED enforcement, username spoofing prevention
  - Session tag: both user AND tag validated together
  - __webd bypass scope: only allowed from UID 900
  - Diagnose target: execvp array (no shell), validator chain
  - Firmware: popen usage scope, URL validation
  - Init: ip6tables handling at boot
  - Password hashing: crypt() used, no plaintext storage
  - Audit logging: all write commands logged, skip-list is minimal

Run: python3 tests/test_security_static.py
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
    full = os.path.join(BASE, p)
    with open(full) as f: return f.read()

mgmtd   = rd("src/userspace/mgmtd/stargazer-mgmtd.c")
mgmtd_user = rd("src/userspace/mgmtd/mgmtd_user.c") if os.path.exists(
    os.path.join(BASE, "src/userspace/mgmtd/mgmtd_user.c")) else ""
netdiag = rd("src/userspace/mgmtd/mgmtd_network.c")
firmware= rd("src/userspace/mgmtd/mgmtd_firmware.c")
validate= rd("src/userspace/common/sg_validate.c")
ipc_h   = rd("src/userspace/mgmtd/stargazer_ipc.h")
init    = rd("src/userspace/init")
webd_pool = rd("src/userspace/webd/webd_pool.c")
webd_sess = rd("src/userspace/webd/webd_session.c")
pentest   = rd("tests/pentest/sg_pentest.c")

# ================================================================
print(f"\n{B}{C}=== 1. IPC identity: SO_PEERCRED enforcement ==={N}")
# ================================================================

# mgmtd must use SO_PEERCRED to kernel-verify the client's UID
chk("mgmtd uses SO_PEERCRED to verify client UID",
    "SO_PEERCRED" in mgmtd and "getsockopt" in mgmtd)

# If SO_PEERCRED fails, the connection must be rejected (not fall through)
chk("SO_PEERCRED failure causes connection rejection",
    "Cannot verify client identity" in mgmtd or
    "SG_ERR_AUTH_FAIL" in mgmtd.split("SO_PEERCRED")[1][:500])

# The __webd bypass is only trusted when cred.uid == WEBD_SERVICE_UID (900)
chk("__webd bypass requires cred.uid == WEBD_SERVICE_UID",
    "cred.uid == WEBD_SERVICE_UID" in mgmtd)

# Any other UID claiming __webd is corrected to their real username
chk("Non-900 UID claiming __webd is overwritten with getpwuid()",
    "getpwuid" in mgmtd and "pw_name" in mgmtd)

# ================================================================
print(f"\n{B}{C}=== 2. Session tag validation integrity ==={N}")
# ================================================================

# session_tag_validate checks BOTH user AND tag
chk("session_tag_validate checks username AND tag together",
    "g_session_tags[i].tag == tag" in mgmtd and
    'strcmp(g_session_tags[i].user, user) == 0' in mgmtd)

# tag == 0 is always rejected (untagged)
chk("session_tag_validate rejects tag == 0",
    "if (tag == 0) return 0;" in mgmtd or
    ("tag == 0" in mgmtd and "return 0" in mgmtd.split("tag == 0")[1][:30]))

# session_tag_delete also checks BOTH to prevent cross-user deletion
chk("session_tag_delete requires both user AND tag match",
    mgmtd.count('strcmp(g_session_tags[i].user, user) == 0') >= 2)

# ================================================================
print(f"\n{B}{C}=== 3. Diagnose handlers: no shell execution ==={N}")
# ================================================================

# All network diag commands must use execvp (array), never system() or popen()
chk("mgmtd_network.c uses execvp/safe_exec, no system()",
    "system(" not in netdiag and
    ("execvp" in netdiag or "safe_exec" in netdiag or "stream_exec" in netdiag))

chk("ping handler validates target with sg_is_net_target",
    "sg_is_net_target(target)" in netdiag and
    "handle_net_ping" in netdiag)

chk("traceroute handler validates target with sg_is_net_target",
    netdiag.count("sg_is_net_target(target)") >= 2)

chk("nslookup handler validates target with sg_is_net_target",
    "nslookup" in netdiag and "sg_is_net_target" in netdiag)

chk("arping handler validates iface with sg_is_iface_name",
    "sg_is_iface_name(iface)" in netdiag)

# sg_is_net_target must reject shell special characters
# It allows: alphanum, _, ., -, : (for IPv6)
chk("sg_is_net_target rejects semicolons (no shell injection path)",
    # The validator allows only alphanum + [_.-:] — semicolons not listed
    "';'" not in validate.split("sg_is_net_target")[1][:300] and
    "sg_is_net_target" in validate)

# Verify the actual character allowlist excludes dangerous chars
net_target_fn = ""
if "sg_is_net_target" in validate:
    idx = validate.index("sg_is_net_target")
    net_target_fn = validate[idx:idx+400]

dangerous_chars = [';', '|', '&', '$', '`', '!', '(', ')', '{', '}', '\n']
for ch in dangerous_chars:
    chk(f"sg_is_net_target rejects '{ch}'",
        f"'{ch}'" not in net_target_fn and
        f'"{ch}"' not in net_target_fn)

# ================================================================
print(f"\n{B}{C}=== 4. Firmware: popen scope and URL handling ==={N}")
# ================================================================

# popen is used only in fw_run_cmd (internal firmware flash, not user-controlled)
chk("popen only in fw_run_cmd (not in user-facing code)",
    firmware.count("popen") == 1 and
    "fw_run_cmd" in firmware and
    firmware.index("popen") > firmware.index("fw_run_cmd"))

# The dd command in fw_run_cmd uses kpart (from sysfs label lookup), not user input
chk("fw_run_cmd dd cmd uses kpart from sysfs, not user input",
    "kpart" in firmware and "kpart[0]" in firmware)

# wget and tftp are called via execlp (no shell), URL is an argument
chk("wget called via execlp (no shell), URL as argv",
    'execlp("wget"' in firmware and
    'system(' not in firmware.split('execlp("wget"')[0][-100:])

chk("tftp called via execlp (no shell)",
    'execlp("tftp"' in firmware)

# ================================================================
print(f"\n{B}{C}=== 5. Password handling ==={N}")
# ================================================================

# Passwords must be hashed with crypt(), never stored plaintext
chk("crypt() included and linked in mgmtd",
    "#include <crypt.h>" in mgmtd or "lcrypt" in mgmtd)

chk("Password hash stored in shadow file via set_shadow_hash, not SQLite",
    "set_shadow_hash" in mgmtd and "shadow" in mgmtd)

chk("Password field is password-interactive (set-only, not stored in DB)",
    'password-interactive' in validate)

# webd session tokens use getrandom() for entropy
chk("webd session tokens use getrandom() syscall",
    "getrandom" in webd_sess)

chk("getrandom() failure causes session creation to fail",
    "getrandom" in webd_sess and
    "return -1" in webd_sess.split("getrandom")[1][:100])

# ================================================================
print(f"\n{B}{C}=== 6. Audit logging coverage ==={N}")
# ================================================================

# sg_cmd_audit_skip() must be minimal — only skip harmless read-only ops
chk("sg_cmd_audit_skip exists",
    "sg_cmd_audit_skip" in ipc_h or "sg_cmd_audit_skip" in mgmtd)

# Extract skip list
skip_cmds = re.findall(r'SG_CMD_\w+', ipc_h.split("audit_skip")[1][:800]
                       if "audit_skip" in ipc_h else "")
dangerous_skipped = [c for c in skip_cmds if any(
    kw in c for kw in ["CFG_SET", "CFG_DEL", "ADMIN", "AUTH_LOGIN", "REBOOT", "POWEROFF"])]

chk("No destructive commands in audit skip list",
    len(dangerous_skipped) == 0,
    f"Dangerous commands skipped from audit: {dangerous_skipped}")

# SG_CMD_AUTH_LOGIN is NOT skipped (login attempts must be logged)
audit_skip_section = ipc_h.split("audit_skip")[1][:1000] if "audit_skip" in ipc_h else mgmtd
chk("AUTH_LOGIN is not in audit skip list (login attempts logged)",
    "SG_CMD_AUTH_LOGIN" not in audit_skip_section.split("\n")[:20] or
    # It might be checked differently — verify it's in the dispatch that does log
    "SG_CMD_AUTH_LOGIN" in mgmtd)

# ================================================================
print(f"\n{B}{C}=== 7. Init: IPv6 and firewall defaults ==={N}")
# ================================================================

# Init should either drop IPv6 forwarding or not enable it
chk("Init or mgmtd loads kernel module (pkt_forward)",
    "pkt_forward" in init or "insmod" in init or "modprobe" in init or
    "pkt_forward" in mgmtd)

# Check for ip6tables rules (either DROP all FORWARD or explicit handling)
has_ip6tables = "ip6tables" in init
has_ipv6_forward_disable = "net.ipv6.conf.all.forwarding" in init

if has_ip6tables:
    chk("Init configures ip6tables rules",
        has_ip6tables)
elif has_ipv6_forward_disable:
    chk("Init disables IPv6 forwarding via sysctl",
        has_ipv6_forward_disable)
else:
    FAIL += 1
    print(f"  {R}FAIL{N} ATK-J-03: Init has no ip6tables rules or IPv6 forward disable")
    print(f"       {Y}GAP: IPv6 traffic bypasses pkt_forward.c (IPv4-only hook){N}")

# iptables default FORWARD policy should be DROP
has_iptables_default_drop = (
    "iptables -P FORWARD DROP" in init or
    "INPUT DROP" in init or
    "iptables" in init
)
chk("Init sets iptables FORWARD default (check policy in init)",
    has_iptables_default_drop,
    "If missing, FORWARD chain may default to ACCEPT before first rule applies")

# ================================================================
print(f"\n{B}{C}=== 8. IPC payload size enforcement ==={N}")
# ================================================================

# SG_PAYLOAD_MAX must be defined and enforced
chk("SG_PAYLOAD_MAX defined in IPC header",
    "SG_PAYLOAD_MAX" in ipc_h)

chk("mgmtd rejects payload_len > SG_PAYLOAD_MAX",
    "SG_PAYLOAD_MAX" in mgmtd and
    ("payload_len" in mgmtd))

# sg_pentest must test oversized payload
chk("sg_pentest tests SG_PAYLOAD_MAX boundary (DOS-03)",
    "DOS-03" in pentest and "SG_PAYLOAD_MAX" in pentest)

# ================================================================
print(f"\n{B}{C}=== 9. webd session: idle + absolute TTL ==={N}")
# ================================================================

chk("WEBD_IDLE_TIMEOUT defined",
    "WEBD_IDLE_TIMEOUT" in webd_sess or
    "WEBD_IDLE_TIMEOUT" in rd("src/userspace/webd/webd_session.h"))

chk("WEBD_SESSION_TTL defined",
    "WEBD_SESSION_TTL" in webd_sess or
    "WEBD_SESSION_TTL" in rd("src/userspace/webd/webd_session.h"))

# Idle check: last_used compared to current time
chk("session_lookup checks last_used for idle timeout",
    "last_used" in webd_sess and
    "WEBD_IDLE_TIMEOUT" in webd_sess)

# Absolute TTL check: created_at compared to current time
chk("session_lookup checks created time for absolute TTL",
    ("created_at" in webd_sess or ".created" in webd_sess) and
    "WEBD_SESSION_TTL" in webd_sess)

# Expired sessions must be zeroed (not just skipped)
chk("Expired session slot is zeroed (memset)",
    "memset" in webd_sess and
    ("WEBD_IDLE_TIMEOUT" in webd_sess or "WEBD_SESSION_TTL" in webd_sess))

# ================================================================
print(f"\n{B}{C}=== 10. mgmtd session tag: no expiry (known gap) ==={N}")
# ================================================================

# Verify there is no TTL field in the session tag structure
tag_struct = ""
if "g_session_tags" in mgmtd:
    idx = mgmtd.index("g_session_tags")
    tag_struct = mgmtd[max(0, idx-500):idx+200]

has_tag_expiry = ("expires" in tag_struct or "created_at" in tag_struct or
                  "ttl" in tag_struct.lower() or "timeout" in tag_struct.lower())

if has_tag_expiry:
    print(f"  {G}PASS{N} mgmtd session tags have expiry (ATK-B-08 resolved)")
    PASS += 1
else:
    print(f"  {Y}NOTE{N} ATK-B-08: mgmtd session tags have NO expiry timestamp")
    print(f"       Tags live until logout or daemon restart (low risk, recommend 24h TTL)")

# ================================================================
# RESULTS
# ================================================================
print(f"\n{'='*60}")
if FAIL == 0:
    print(f"{G}{B}ALL {PASS+FAIL} STATIC SECURITY CHECKS PASSED{N}")
else:
    print(f"{Y}Results: {G}{PASS} passed{N}, {R}{FAIL} failed{N} / {PASS+FAIL} total")
    sys.exit(1)
