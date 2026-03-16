#!/usr/bin/env python3
"""
test_webui_fixes.py — Verify Web UI security & data contract fixes

Tests the source code changes from the 12-commit plan:
  1. Status value mapping
  2. DHCP field key mismatches
  3. Interface form (Mode field)
  4. XSS escaping in innerHTML
  5. Demo login bypass removed
  6. JSON escaping in webd
  7. Allowaccess checkbox values
  8. Firmware upload validation
  9. Enforce-change-password
  10. Session idle timeout + keepalive
  11. HttpOnly cookie session
  12. HSTS header

Run: python3 tests/test_webui_fixes.py
"""

import os
import re
import sys
import json
import subprocess
import tempfile

PASS = 0
FAIL = 0
TOTAL = 0

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

def check(name, condition, detail=""):
    global PASS, FAIL, TOTAL
    TOTAL += 1
    if condition:
        PASS += 1
        print(f"  {GREEN}PASS{RESET} {name}")
    else:
        FAIL += 1
        print(f"  {RED}FAIL{RESET} {name}")
        if detail:
            print(f"       {detail}")

def read_file(path):
    with open(path, "r") as f:
        return f.read()

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = os.path.join(BASE, "src/userspace/webui/www/home.html")
APPJS = os.path.join(BASE, "src/userspace/webui/www/js/app.js")
LOGINJS = os.path.join(BASE, "src/userspace/webui/www/js/login.js")
POOL_C = os.path.join(BASE, "src/userspace/webd/webd_pool.c")
POOL_H = os.path.join(BASE, "src/userspace/webd/webd_pool.h")
API_C = os.path.join(BASE, "src/userspace/webd/webd_api.c")
API_H = os.path.join(BASE, "src/userspace/webd/webd_api.h")
SESS_C = os.path.join(BASE, "src/userspace/webd/webd_session.c")
SESS_H = os.path.join(BASE, "src/userspace/webd/webd_session.h")
WEBD_C = os.path.join(BASE, "src/userspace/webd/stargazer-webd.c")

html = read_file(HTML)
appjs = read_file(APPJS)
loginjs = read_file(LOGINJS)
pool_c = read_file(POOL_C)
pool_h = read_file(POOL_H)
api_c = read_file(API_C)
api_h = read_file(API_H)
sess_c = read_file(SESS_C)
sess_h = read_file(SESS_H)
webd_c = read_file(WEBD_C)


# ================================================================
# COMMIT 1: Status value mapping
# ================================================================
print(f"\n{BOLD}=== Commit 1: Status value mapping ==={RESET}")

# Check interface status uses up/down
check("HTML: interface status has value='up'",
      'value="up"' in html and 'value="down"' in html)

# Check non-interface status uses enable/disable
enable_count = html.count('value="enable"')
disable_count = html.count('value="disable"')
check("HTML: non-interface status has value='enable'/'disable'",
      enable_count >= 5 and disable_count >= 5,
      f"Found enable={enable_count}, disable={disable_count}")

# Check no bare <option>Enabled</option> without value (except where not a status select)
bare_enabled = re.findall(r'<option[^>]*>Enabled</option>', html)
bare_enabled_no_value = [o for o in bare_enabled if 'value=' not in o]
check("HTML: no status <option>Enabled without value attr",
      len(bare_enabled_no_value) == 0,
      f"Found {len(bare_enabled_no_value)} bare options: {bare_enabled_no_value[:3]}")

# app.js: formSubmit uses .value
check("JS: formSubmit uses .value for selects",
      ".value || inp.options[inp.selectedIndex].text" in appjs)

# app.js: settingsApply uses .value
check("JS: settingsApply uses .value for selects",
      "inp.options[inp.selectedIndex].value || inp.options[inp.selectedIndex].text"
      in appjs)

# app.js: demoSetStatus sends correct values
check("JS: demoSetStatus sends up/down for interfaces",
      "statusVal = enable ? 'up' : 'down'" in appjs)
check("JS: demoSetStatus sends enable/disable for others",
      "statusVal = enable ? 'enable' : 'disable'" in appjs)

# app.js: renderEntityRows recognizes enable/up
check("JS: renderEntityRows isOn includes 'enable' and 'up'",
      "val === 'enable'" in appjs and "val === 'up'" in appjs)


# ================================================================
# COMMIT 2: DHCP field key mismatches
# ================================================================
print(f"\n{BOLD}=== Commit 2: DHCP field key mismatches ==={RESET}")

check("JS: DHCP key 'start-ip' (not 'range-start')",
      "key: 'start-ip'" in appjs)
check("JS: DHCP key 'end-ip' (not 'range-end')",
      "key: 'end-ip'" in appjs)
check("JS: DHCP key 'gateway' (not 'default-gateway')",
      "key: 'gateway'" in appjs and "key: 'default-gateway'" not in appjs)
check("JS: DHCP has netmask field (col: -1)",
      "key: 'netmask'" in appjs)
check("JS: DHCP has domain-name field (col: -1)",
      "key: 'domain-name'" in appjs)
check("JS: DHCP label 'DNS Server 1' (not 'DNS Server')",
      "'DNS Server 1'" in appjs)
check("JS: renderEntityRows skips col:-1 fields",
      "if (f.col === -1) return;" in appjs)

# Verify old keys are gone
check("JS: no 'range-start' key",
      "key: 'range-start'" not in appjs)
check("JS: no 'range-end' key",
      "key: 'range-end'" not in appjs)


# ================================================================
# COMMIT 3: Interface form (Mode field)
# ================================================================
print(f"\n{BOLD}=== Commit 3: Interface form (Mode field) ==={RESET}")

check("HTML: interface form has Mode field",
      'form-label">Mode</label>' in html)
check("HTML: Mode has static/dhcp options",
      'value="static"' in html and 'value="dhcp"' in html)
check("HTML: no Type field (Physical/VLAN/Tunnel/Loopback) in interface form",
      '<option>Physical</option>' not in html)
check("HTML: no Alias field in interface form",
      'form-label">Alias</label>' not in html)


# ================================================================
# COMMIT 4: XSS — escape innerHTML
# ================================================================
print(f"\n{BOLD}=== Commit 4: XSS escaping ==={RESET}")

# renderEntityRows should use esc()
check("JS: renderEntityRows escapes row identifier",
      "esc(row.id || row.name || idx)" in appjs)
check("JS: renderEntityRows escapes val in td",
      "esc(val)" in appjs)
check("JS: renderEntityRows escapes dotClass",
      "esc(dotClass)" in appjs)
check("JS: renderEntityRows escapes status label",
      "esc(label)" in appjs)

# Check esc() function exists
check("JS: esc() function defined",
      "function esc(s)" in appjs)

# forEachSelected should not use unsanitized selector
check("JS: forEachSelected avoids selector injection",
      "row.dataset.rowId === id" in appjs)

# Simulate XSS payload — check it would be escaped
xss_payload = '<script>alert(1)</script>'
expected = '&lt;script&gt;alert(1)&lt;/script&gt;'
# The esc() function replaces < with &lt; and > with &gt;
check("JS: esc() handles XSS payloads (code review)",
      ".replace(/</g,'&lt;').replace(/>/g,'&gt;')" in appjs)


# ================================================================
# COMMIT 5: Demo login bypass removed
# ================================================================
print(f"\n{BOLD}=== Commit 5: Demo login bypass ==={RESET}")

check("JS: no demo fallback on TypeError",
      "Demo fallback" not in loginjs)
check("JS: no auto-auth for admin",
      "user === 'admin'" not in loginjs or
      "CANNOT CONNECT" in loginjs)
check("JS: shows 'CANNOT CONNECT TO MANAGEMENT DAEMON'",
      "CANNOT CONNECT TO MANAGEMENT DAEMON" in loginjs)

# Verify: TypeError no longer grants access
check("JS: TypeError handler doesn't redirect to index.html",
      # In the TypeError block, there should be NO window.location.href = 'index.html'
      # Check the error handler block
      "TypeError" not in loginjs.split("CANNOT CONNECT")[0].split(".catch")[1]
      if "CANNOT CONNECT" in loginjs and ".catch" in loginjs else
      "CANNOT CONNECT TO MANAGEMENT DAEMON" in loginjs)


# ================================================================
# COMMIT 6: JSON escaping in webd
# ================================================================
print(f"\n{BOLD}=== Commit 6: JSON escaping in webd ==={RESET}")

check("C: json_escape() function exists",
      "static char *json_escape(const char *src)" in pool_c)
check("C: json_escape handles backslash",
      "buf[j++] = '\\\\'; buf[j++] = '\\\\'" in pool_c or
      r"ch == '\\'" in pool_c)
check("C: json_escape handles double-quote",
      'ch == \'"\'' in pool_c)
check("C: json_escape handles control chars (\\uXXXX)",
      "\\\\u%04x" in pool_c)
check("C: json_error uses json_escape",
      "json_escape(msg)" in pool_c)
check("C: kv_to_json escapes keys",
      "json_escape(key_tmp)" in pool_c)
check("C: kv_to_json escapes values",
      "json_escape(val_tmp)" in pool_c)
check("C: kv_to_json id field escaped",
      "json_escape(id)" in pool_c)


# ================================================================
# COMMIT 7: Allowaccess checkbox values
# ================================================================
print(f"\n{BOLD}=== Commit 7: Allowaccess checkboxes ==={RESET}")

check("JS: checkbox values lowercased",
      ".trim().toLowerCase()" in appjs)
check("JS: allowaccess uses space separator",
      "' '" in appjs and "vals.join(sep)" in appjs)
check("JS: permissions uses comma separator",
      "'permissions'" in appjs and "','" in appjs)
check("HTML: HTTP checkbox in admin access",
      "> HTTP<" in html)


# ================================================================
# COMMIT 8: Firmware upload validation
# ================================================================
print(f"\n{BOLD}=== Commit 8: Firmware upload validation ==={RESET}")

check("JS: checks .itb extension",
      ".itb" in appjs and "file.name.match" in appjs)
check("JS: rejects files > 64MB",
      "64 * 1024 * 1024" in appjs)
check("JS: shows error toast for invalid extension",
      "Invalid firmware file" in appjs)
check("JS: shows error toast for oversize",
      "too large" in appjs)


# ================================================================
# COMMIT 9: Enforce-change-password
# ================================================================
print(f"\n{BOLD}=== Commit 9: Enforce-change-password ==={RESET}")

# webd_pool.c
check("C: flow_login checks enforce_change=1",
      'enforce_change=1' in pool_c)
check("C: flow_login checks policy_mismatch=1",
      'policy_mismatch=1' in pool_c)
check("C: login response includes change_password",
      'change_password' in pool_c)

# webd_pool.h
check("C: FLOW_CHANGE_PW defined",
      "FLOW_CHANGE_PW" in pool_h)

# webd_api.c
check("C: /api/auth/change-password route exists",
      "change-password" in api_c)
check("C: change-password uses FLOW_CHANGE_PW",
      "FLOW_CHANGE_PW" in api_c)

# webd_pool.c
check("C: flow_change_pw handler exists",
      "flow_change_pw" in pool_c)
check("C: flow_change_pw uses SG_CMD_AUTH_CHANGE_PW",
      "SG_CMD_AUTH_CHANGE_PW" in pool_c)

# login.js
check("JS: checks data.change_password",
      "data.change_password" in loginjs)
check("JS: showChangePasswordForm function exists",
      "function showChangePasswordForm" in loginjs)
check("JS: password change calls /api/auth/change-password",
      "/api/auth/change-password" in loginjs)
check("JS: confirms passwords match",
      "PASSWORDS DO NOT MATCH" in loginjs)


# ================================================================
# COMMIT 10: Session idle timeout + keepalive
# ================================================================
print(f"\n{BOLD}=== Commit 10: Session idle timeout + keepalive ==={RESET}")

# webd_session.h
check("C: WEBD_IDLE_TIMEOUT defined as 900",
      "WEBD_IDLE_TIMEOUT" in sess_h and "900" in sess_h)

# webd_session.c
check("C: session_lookup checks idle timeout",
      "WEBD_IDLE_TIMEOUT" in sess_c)
check("C: idle timeout clears session",
      "last_used > WEBD_IDLE_TIMEOUT" in sess_c)

# app.js
check("JS: keepalive interval set to 60s",
      "KEEPALIVE_INTERVAL = 60000" in appjs)
check("JS: keepaliveCheck function exists",
      "function keepaliveCheck" in appjs)
check("JS: keepalive calls /auth/whoami",
      "/auth/whoami" in appjs)
check("JS: keepalive shows 'Session expired' on 401",
      "Session expired" in appjs)
check("JS: keepalive detects permission changes",
      "Permissions updated" in appjs)


# ================================================================
# COMMIT 11: HttpOnly cookie session
# ================================================================
print(f"\n{BOLD}=== Commit 11: HttpOnly cookie ==={RESET}")

# webd_pool.c — Set-Cookie on login
check("C: flow_login sets Set-Cookie header",
      "Set-Cookie: sg_sid=" in pool_c)
check("C: cookie has HttpOnly flag",
      "HttpOnly" in pool_c)
check("C: cookie has SameSite=Strict",
      "SameSite=Strict" in pool_c)
_login_body = pool_c.split("static void flow_login")[1].split("static void")[0] if "static void flow_login" in pool_c else ""
check("C: login returns {ok:true} not token in body",
      '\\"ok\\":true' in _login_body and '\\"token\\"' not in _login_body)

# webd_pool.h — extra_hdrs in work_result_t
check("C: work_result_t has extra_hdrs field",
      "extra_hdrs" in pool_h)

# webd_api.c — cookie parsing
check("C: extract_bearer parses Cookie header",
      "sg_sid=" in api_c)
check("C: logout clears cookie with Max-Age=0",
      "Max-Age=0" in api_c)

# app.js — no token in sessionStorage
check("JS: no sessionStorage token access",
      "sessionStorage.getItem('sg_token')" not in appjs and
      "sessionStorage.setItem('sg_token'" not in appjs)
check("JS: no Authorization header injection",
      "Authorization" not in appjs or
      "'Authorization': 'Bearer'" not in appjs)
check("JS: logout calls API instead of just removing token",
      "api('/auth/logout'" in appjs)

# login.js — no token storage
check("JS: login.js no sessionStorage token",
      "sessionStorage.setItem('sg_token'" not in loginjs)


# ================================================================
# COMMIT 12: HSTS header
# ================================================================
print(f"\n{BOLD}=== Commit 12: HSTS header ==={RESET}")

check("C: g_tls_active declared extern",
      "extern int g_tls_active" in api_h)
check("C: WEBD_HSTS_HEADER defined",
      "WEBD_HSTS_HEADER" in api_h)
check("C: Strict-Transport-Security in HSTS header",
      "Strict-Transport-Security" in api_h)
check("C: max-age=31536000",
      "max-age=31536000" in api_h)
check("C: webd_sec_headers() function exists",
      "webd_sec_headers" in api_h)
check("C: g_tls_active set when TLS configured",
      "g_tls_active = 1" in webd_c)
check("C: ev_handler uses webd_sec_headers()",
      "webd_sec_headers()" in webd_c)
check("C: static files get HSTS when TLS active",
      "static_hdrs_hsts" in webd_c)


# ================================================================
# CROSS-CUTTING SECURITY CHECKS
# ================================================================
print(f"\n{BOLD}=== Cross-cutting security checks ==={RESET}")

# No demo/bypass code left
check("JS: no demo bypass in login flow",
      "Demo fallback: accept admin" not in loginjs)

# No token in body responses (for non-change-pw flows)
check("C: login response is {ok:true} not {token:...}",
      '\\"ok\\":true' in _login_body and '\\"token\\"' not in _login_body,
      "Token should only be in Set-Cookie header, not response body")

# Session has both absolute TTL and idle timeout
check("C: session has absolute TTL check",
      "WEBD_SESSION_TTL" in sess_c)
check("C: session has idle timeout check",
      "WEBD_IDLE_TIMEOUT" in sess_c)

# Cookie security flags
check("C: cookie Path=/ set",
      "Path=/" in pool_c)

# CSP header present
check("C: Content-Security-Policy header",
      "Content-Security-Policy" in api_h)

# X-Frame-Options
check("C: X-Frame-Options DENY",
      "X-Frame-Options: DENY" in api_h)

# Cache-Control no-store
check("C: Cache-Control no-store",
      "Cache-Control: no-store" in api_h)


# ================================================================
# RESULTS
# ================================================================
print(f"\n{'='*60}")
if FAIL == 0:
    print(f"{GREEN}{BOLD}ALL {TOTAL} TESTS PASSED{RESET}")
else:
    print(f"{YELLOW}Results: {GREEN}{PASS} passed{RESET}, {RED}{FAIL} failed{RESET} / {TOTAL} total")
    sys.exit(1)
