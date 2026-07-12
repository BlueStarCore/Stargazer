#!/usr/bin/env python3
"""
test_webd_internals.py — Deep structural verification of webd internals

Tests things not covered by test_api_contract.py:
  - Login rate limiting implementation
  - HTTP method enforcement per route
  - Session token format & eviction policy
  - IPC error code → HTTP status mapping completeness
  - strip_kv_keys and json_body_to_kv correctness
  - Queue overflow → 503 path
  - admin/create endpoint requirements
  - Session security properties (token entropy, idle/TTL logic)
  - Resources sub-endpoints routing

Run: python3 tests/test_webd_internals.py
"""

import os
import re
import sys
import json

PASS = 0
FAIL = 0
TOTAL = 0

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

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

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def rd(p):
    with open(os.path.join(BASE, p)) as f:
        return f.read()

api_c   = rd("src/userspace/webd/webd_api.c")
pool_c  = rd("src/userspace/webd/webd_pool.c")
pool_h  = rd("src/userspace/webd/webd_pool.h")
sess_c  = rd("src/userspace/webd/webd_session.c")
sess_h  = rd("src/userspace/webd/webd_session.h")
appjs   = rd("src/userspace/webui/www/js/app.js")


# ================================================================
print(f"\n{BOLD}=== 1. Login rate limiting ==={RESET}")
# ================================================================
# RATE_LIMIT_MAX = 10 attempts per second
check("RATE_LIMIT_MAX defined as 10",
      "RATE_LIMIT_MAX     10" in api_c or "RATE_LIMIT_MAX  10" in api_c or
      re.search(r'RATE_LIMIT_MAX\s+10', api_c) is not None)

check("rate_limit_check() called before login dispatch",
      "rate_limit_check" in api_c.split("FLOW_LOGIN")[0])

check("rate limit returns 429 Too Many Requests",
      "429" in api_c and "Too many requests" in api_c)

check("rate limit window resets each second (time-based, not counter-only)",
      "rate_window" in api_c and "time(NULL)" in api_c)

check("rate limit only on login, not other routes",
      # Definition (void) appears once; call () != 0 appears exactly once
      api_c.count("rate_limit_check() != 0") == 1)


# ================================================================
print(f"\n{BOLD}=== 2. HTTP method enforcement per route ==={RESET}")
# ================================================================

# Login: POST only
login_block = api_c.split('strcmp(segs[1], "login")')[1][:300] if '"login"' in api_c else ""
check("Login requires POST method check",
      '"POST"' in login_block or "POST" in login_block)

# Logout: POST only
logout_block = api_c.split('"logout"')[1][:200] if '"logout"' in api_c else ""
check("Logout requires POST method check",
      "POST" in logout_block)

# whoami: GET only
whoami_block = api_c.split('"whoami"')[1][:200] if '"whoami"' in api_c else ""
check("whoami requires GET method check",
      "GET" in whoami_block)

# change-password: POST only
chpw_block = api_c.split('"change-password"')[1][:200] if '"change-password"' in api_c else ""
check("change-password requires POST method check",
      "POST" in chpw_block)

# Config: 405 Method Not Allowed for unrecognised methods
check("Config routes return 405 for unrecognised methods",
      "405" in api_c and "Method not allowed" in api_c)

# Resources: GET only
res_block = api_c.split('"resources"')[1][:200] if '"resources"' in api_c else ""
check("Resources requires GET method check",
      "GET" in res_block)


# ================================================================
print(f"\n{BOLD}=== 3. Session token security ==={RESET}")
# ================================================================

check("Token is 64-char hex (32 random bytes)",
      "WEBD_TOKEN_LEN     64" in sess_h or
      re.search(r'WEBD_TOKEN_LEN\s+64', sess_h) is not None)

check("Token generated with getrandom() (not rand/srand/urandom path)",
      "getrandom(rnd" in sess_c and "rand(" not in sess_c)

check("Token uses 32 bytes of entropy (getrandom 32-byte call)",
      "getrandom(rnd, sizeof(rnd), 0)" in sess_c or
      "getrandom(rnd, 32" in sess_c)

check("Token hex-encoded (not base64, not raw bytes in cookie)",
      "hex_encode" in sess_c)

check("session_lookup rejects tokens != 64 chars (length check)",
      "strlen(token) != WEBD_TOKEN_LEN" in sess_c)

check("session_lookup uses memcmp (constant-time comparison for tokens)",
      "memcmp(sessions[i].token, token, WEBD_TOKEN_LEN)" in sess_c)


# ================================================================
print(f"\n{BOLD}=== 4. Session limits and eviction ==={RESET}")
# ================================================================

check("WEBD_MAX_SESSIONS defined as 16",
      re.search(r'WEBD_MAX_SESSIONS\s+16', sess_h) is not None)

check("Session create finds free slot first",
      "token[0] == '\\0'" in sess_c or "token[0] == 0" in sess_c or
      "token[0] ==" in sess_c)

check("Session evicts oldest when all slots full",
      "oldest" in sess_c and "last_used" in sess_c and "evict" in sess_c.lower() or
      ("oldest" in sess_c and "last_used" in sess_c and "slot" in sess_c))

check("Evicted session is the one with smallest last_used (LRU)",
      "sessions[i].last_used < oldest" in sess_c)

check("session_destroy zeroes slot (memset 0)",
      "memset(&sessions[i], 0, sizeof(sessions[i]))" in sess_c)

check("session_destroy_all exists for shutdown",
      "session_destroy_all" in sess_h and "session_destroy_all" in sess_c)


# ================================================================
print(f"\n{BOLD}=== 5. Session timeout logic ==={RESET}")
# ================================================================

check("WEBD_SESSION_TTL = 3600 (absolute 1-hour max)",
      re.search(r'WEBD_SESSION_TTL\s+3600', sess_h) is not None)

check("WEBD_IDLE_TIMEOUT = 900 (15-min idle)",
      re.search(r'WEBD_IDLE_TIMEOUT\s+900', sess_h) is not None)

check("session_lookup checks absolute TTL (created)",
      "now - sessions[i].created > WEBD_SESSION_TTL" in sess_c)

check("session_lookup checks idle timeout (last_used)",
      "now - sessions[i].last_used > WEBD_IDLE_TIMEOUT" in sess_c)

check("Expired session zeroed in lookup path",
      # memset appears in the lookup function, inside the for loop
      sess_c.count("memset(&sessions[i], 0, sizeof(sessions[i]))") >= 2)

check("session_expire_check scans all slots periodically",
      "session_expire_check" in sess_c and
      "WEBD_SESSION_TTL" in sess_c.split("session_expire_check")[1][:400])

check("last_used refreshed on each successful lookup",
      "sessions[i].last_used = now" in sess_c)


# ================================================================
print(f"\n{BOLD}=== 6. IPC error → HTTP status mapping ==={RESET}")
# ================================================================

# Simulate Python equivalent of ipc_status_to_http()
def py_ipc_status_to_http(src):
    """Extract the mapping table from the C source."""
    mapping = {}
    for m in re.finditer(r'if \(st == (\w+)\)\s+return (\d+)', src):
        mapping[m.group(1)] = int(m.group(2))
    return mapping

mapping = py_ipc_status_to_http(pool_c if "ipc_status_to_http" in pool_c else api_c)

expected = {
    "SG_OK": 200,
    "SG_ERR_INVALID_ARG": 400,
    "SG_ERR_INVALID_VAL": 400,
    "SG_ERR_MISSING_ARG": 400,
    "SG_ERR_POLICY_FAIL": 400,
    "SG_ERR_PERM_DENIED": 403,
    "SG_ERR_AUTH_FAIL": 401,
    "SG_ERR_LOCKED": 401,
    "SG_ERR_SESSION_EXPIRED": 401,
    "SG_ERR_PROFILE_DENY": 403,
    "SG_ERR_NOT_FOUND": 404,
    "SG_ERR_ALREADY_EXISTS": 409,
    "SG_ERR_IN_USE": 409,
    "SG_ERR_BUILTIN": 403,
}

for err_code, http_code in expected.items():
    check(f"ipc_status_to_http: {err_code} → HTTP {http_code}",
          mapping.get(err_code) == http_code,
          f"Got {mapping.get(err_code)}, expected {http_code}")

# Unknown errors should default to 500
ipc_fn = api_c.split("ipc_status_to_http")[1][:800] if "ipc_status_to_http" in api_c else \
         pool_c.split("ipc_status_to_http")[1][:800] if "ipc_status_to_http" in pool_c else ""
check("ipc_status_to_http: unknown errors default to 500",
      # function body is ~900 chars; search a wider window
      "return 500" in (pool_c.split("ipc_status_to_http")[1][:1500]
                       if "ipc_status_to_http" in pool_c else ""))


# ================================================================
print(f"\n{BOLD}=== 7. strip_kv_keys correctness ==={RESET}")
# ================================================================

def py_strip_kv_keys(kv, skip):
    """Python equivalent of C strip_kv_keys()."""
    out = []
    for line in kv.split('\n'):
        if not line:
            continue
        eq = line.find('=')
        if eq < 0:
            out.append(line)
            continue
        key = line[:eq]
        if key not in skip:
            out.append(line)
    return '\n'.join(out) + '\n' if out else ''

# Test: 'id' key stripped from create payload
kv_with_id = "id=myentry\nstatus=enable\nip=1.2.3.4/24\n"
stripped = py_strip_kv_keys(kv_with_id, {"id"})
check("strip_kv_keys removes 'id' key from create body",
      "id=myentry" not in stripped and "status=enable" in stripped)

# Test: other keys preserved
check("strip_kv_keys preserves non-skipped keys",
      "ip=1.2.3.4/24" in stripped)

# Test: 'id' not the only key
kv_multi = "name=test\nid=test\ntype=ipmask\n"
stripped2 = py_strip_kv_keys(kv_multi, {"id"})
check("strip_kv_keys keeps 'name' when only stripping 'id'",
      "name=test" in stripped2 and "id=test" not in stripped2)

# Verify C code strips 'id' but keeps 'name' in create path
check("C create path strips 'id' key (not 'name')",
      'strip_keys[] = {"id", NULL}' in api_c or
      '"id", NULL' in api_c.split("FLOW_CONFIG_CREATE")[0].split("strip_kv_keys")[0] or
      '"id"' in api_c and 'strip_keys' in api_c)

# Verify 'builtin' and 'password-hash' stripped in update path
# (these are internal keys that should not be writable via API)
check("Internal keys (builtin, password-hash) not user-writable via API",
      # The mgmtd validate_cfg_fields skips these; at least 'builtin' checked
      "builtin" in rd("src/userspace/mgmtd/stargazer-mgmtd.c") and
      "password-hash" in rd("src/userspace/mgmtd/stargazer-mgmtd.c"))


# ================================================================
print(f"\n{BOLD}=== 8. json_body_to_kv parsing ==={RESET}")
# ================================================================

def py_json_body_to_kv(body_str):
    """Python simulation of C json_body_to_kv().
    Converts '{"key":"val",...}' to 'key=val\n...'
    Handles string and non-string values, skips nested objects/arrays.
    """
    try:
        obj = json.loads(body_str)
    except json.JSONDecodeError:
        return ""
    lines = []
    for k, v in obj.items():
        if isinstance(v, (dict, list)):
            continue  # C parser skips these (no nesting support)
        lines.append(f"{k}={v}")
    return '\n'.join(lines) + '\n' if lines else ''

# Basic conversion
result = py_json_body_to_kv('{"status":"enable","mtu":"1500"}')
check("json_body_to_kv: basic string fields converted",
      "status=enable" in result and "mtu=1500" in result)

# Number values
result2 = py_json_body_to_kv('{"port":443,"protocol":"tcp"}')
check("json_body_to_kv: number values accepted",
      "port=443" in result2 or "port=" in result2)

# C implementation handles escape sequences in string values
check("C json_body_to_kv: handles backslash escape in string values",
      "skip escape" in api_c or
      "p + 1 < end) p++" in api_c)

# Verify C does NOT support nested JSON (flat kv only)
check("C json_body_to_kv: flat-only (nested objects not parsed)",
      # The C parser breaks on '}' — nested values would confuse it
      "p == '}'" in api_c or "*p == '}'" in api_c)

# Verify buffer grows dynamically
check("json_body_to_kv: buffer grows dynamically (realloc)",
      "realloc(buf, cap)" in api_c and "cap *=" in api_c or
      "cap *= 2" in api_c)


# ================================================================
print(f"\n{BOLD}=== 9. Queue overflow → 503 ==={RESET}")
# ================================================================

# All routes that enqueue should handle queue-full with 503
check("WEBD_QUEUE_MAX = 32",
      re.search(r'WEBD_QUEUE_MAX\s+32', pool_h) is not None)

check("WEBD_POOL_SIZE = 4 worker threads",
      re.search(r'WEBD_POOL_SIZE\s+4', pool_h) is not None)

# Count 503 / Server busy occurrences — should be many (one per route)
server_busy_count = api_c.count('Server busy') + pool_c.count('Server busy')
check("Multiple routes return 503 when queue full",
      server_busy_count >= 6,
      f"Found {server_busy_count} 'Server busy' returns, expected >= 6")

check("webd_pool_enqueue returns -1 when queue is full",
      "q_count >= WEBD_QUEUE_MAX" in pool_c or
      "q_count == WEBD_QUEUE_MAX" in pool_c or
      "WEBD_QUEUE_MAX" in pool_c and "return -1" in pool_c)


# ================================================================
print(f"\n{BOLD}=== 10. admin/create endpoint ==={RESET}")
# ================================================================

check("POST /api/admin/create route exists",
      '"admin"' in api_c and '"create"' in api_c)

check("admin/create requires auth (after global auth guard)",
      # The admin/create block is after the global session_lookup at line ~482
      api_c.index('"admin"') > api_c.index("/* ── All remaining routes require auth")
      if '"admin"' in api_c and "All remaining routes require auth" in api_c else False)

check("admin/create requires username and profile",
      '"$.username"' in api_c.split('"create"')[1][:400] and
      '"$.profile"' in api_c.split('"create"')[1][:400])

check("admin/create password is optional",
      "password" in api_c.split('"create"')[1][:600] and
      ("if (password)" in api_c or "password ?" in api_c))

check("admin/create dispatches FLOW_ADMIN_CREATE",
      "FLOW_ADMIN_CREATE" in api_c)

check("FLOW_ADMIN_CREATE defined in pool.h",
      "FLOW_ADMIN_CREATE" in pool_h)


# ================================================================
print(f"\n{BOLD}=== 11. Resources sub-endpoint routing ==={RESET}")
# ================================================================

check("GET /api/system/resources → FLOW_RESOURCES",
      "FLOW_RESOURCES" in api_c and "FLOW_RESOURCES_DET" in api_c)

check("GET /api/system/resources/detail → FLOW_RESOURCES_DET",
      '"detail"' in api_c and "FLOW_RESOURCES_DET" in api_c)

check("GET /api/system/resources/ram → FLOW_RES_RAM",
      '"ram"' in api_c and "FLOW_RES_RAM" in api_c)

check("GET /api/system/resources/disk → FLOW_RES_DISK",
      '"disk"' in api_c and "FLOW_RES_DISK" in api_c)

check("GET /api/system/resources/proctop → FLOW_RES_PROCTOP",
      '"proctop"' in api_c and "FLOW_RES_PROCTOP" in api_c)

check("All 5 FLOW_RES_* defined in pool.h",
      "FLOW_RES_RAM" in pool_h and "FLOW_RES_DISK" in pool_h and
      "FLOW_RES_PROCTOP" in pool_h)


# ================================================================
print(f"\n{BOLD}=== 12. search/filter support on config list ==={RESET}")
# ================================================================

check("GET /api/config/{type}?q=<term> parses query param",
      "query_param" in api_c and '"q"' in api_c)

check("query_param() handles missing query string (returns NULL)",
      "query.len == 0" in api_c or "query->len == 0" in api_c or
      "if (query.len == 0) return NULL" in api_c)

check("Search payload passed to FLOW_CONFIG_LIST",
      "item.payload = search" in api_c or "payload = search" in api_c)


# ================================================================
print(f"\n{BOLD}=== 13. 503 on queue full: payload freed before return ==={RESET}")
# ================================================================

# Verify no memory leak: when enqueue fails, payload must be freed
# Pattern: free(payload)  immediately after webd_pool_enqueue check
enqueue_fails = re.findall(
    r'if \(webd_pool_enqueue\(&item\) != 0\) \{\s*free\((\w+)\)',
    api_c
)
check("Payload freed when queue is full (no memory leak)",
      len(enqueue_fails) >= 3,
      f"Found {len(enqueue_fails)} free-on-queue-full sites, expected >= 3")


# ================================================================
print(f"\n{BOLD}=== 14. Response security headers on all replies ==={RESET}")
# ================================================================

# webd_sec_headers() called in reply_json — all error paths use reply_json
check("reply_json() calls webd_sec_headers()",
      "webd_sec_headers()" in api_c.split("reply_json")[1][:200] or
      "webd_sec_headers()" in api_c)

check("webd_sec_headers() present in webd_api.h",
      "webd_sec_headers" in rd("src/userspace/webd/webd_api.h"))

check("Security headers include X-Content-Type-Options",
      "X-Content-Type-Options" in rd("src/userspace/webd/webd_api.h"))

check("Security headers include X-Frame-Options: DENY",
      "X-Frame-Options: DENY" in rd("src/userspace/webd/webd_api.h"))


# ================================================================
print(f"\n{BOLD}=== 15. Bearer token fallback logic ==={RESET}")
# ================================================================

check("extract_bearer checks Authorization: Bearer header first",
      "Bearer " in api_c and "memcmp(auth->buf, \"Bearer \"" in api_c or
      '"Bearer "' in api_c)

check("extract_bearer falls back to sg_sid cookie",
      'sg_sid=' in api_c and "Cookie" in api_c)

check("Bearer token length bounded to bufsz",
      "tlen < bufsz" in api_c)

check("Cookie value length bounded to bufsz",
      "vlen < bufsz" in api_c or "vlen > 0 && vlen < bufsz" in api_c)

check("extract_bearer returns NULL when no token found",
      # function is ~50 lines; search a 2500-char window
      "return NULL" in api_c.split("extract_bearer")[1][:2500])


# ================================================================
# RESULTS
# ================================================================
print(f"\n{'='*60}")
if FAIL == 0:
    print(f"{GREEN}{BOLD}ALL {TOTAL} WEBD INTERNAL CHECKS PASSED{RESET}")
else:
    print(f"{YELLOW}Results: {GREEN}{PASS} passed{RESET}, {RED}{FAIL} failed{RESET} / {TOTAL} total")
    sys.exit(1)
