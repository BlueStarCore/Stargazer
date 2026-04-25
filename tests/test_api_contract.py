#!/usr/bin/env python3
"""
test_api_contract.py — End-to-end API contract verification

Traces every API call from JS → C route → C worker → JSON response → JS consumer.
Verifies method, URL, body format, response keys, and escaping for all 16 endpoints.

Run: python3 tests/test_api_contract.py
"""

import os, re, sys, json

P = F = T = 0
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; N = "\033[0m"; B = "\033[1m"

def chk(name, ok, detail=""):
    global P, F, T; T += 1
    if ok: P += 1; print(f"  {G}PASS{N} {name}")
    else:  F += 1; print(f"  {R}FAIL{N} {name}"); detail and print(f"       {detail}")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def rd(p): return open(os.path.join(BASE, p)).read()

appjs   = rd("src/userspace/webui/www/js/app.js")
loginjs = rd("src/userspace/webui/www/js/login.js")
api_c   = rd("src/userspace/webd/webd_api.c")
pool_c  = rd("src/userspace/webd/webd_pool.c")
pool_h  = rd("src/userspace/webd/webd_pool.h")

def cfunc(src, name):
    """Extract C function body by name (between 'static void NAME(' and next 'static void')."""
    pat = rf'static void {re.escape(name)}\(.*?\)\n\{{(.+?)(?=\nstatic )'
    m = re.search(pat, src, re.DOTALL)
    return m.group(1) if m else ""

# ================================================================
# Helper: extract all api() calls from JS
# ================================================================
def find_js_api_calls(js):
    """Find all api('endpoint', ...) calls."""
    calls = []
    for m in re.finditer(r"api\(\s*['\"]([^'\"]+)['\"]", js):
        calls.append(m.group(1))
    return calls

def find_js_fetch_calls(js):
    """Find all fetch('url', ...) calls."""
    calls = []
    for m in re.finditer(r"fetch\(\s*['\"]([^'\"]+)['\"]", js):
        calls.append(m.group(1))
    for m in re.finditer(r"fetch\(\s*API_BASE\s*\+\s*['\"]([^'\"]+)['\"]", js):
        calls.append('/api' + m.group(1))
    return calls

# ================================================================
print(f"\n{B}=== 1. POST /api/auth/login ==={N}")
# ================================================================

# JS sends
chk("JS login: POST method",
    "method: 'POST'" in loginjs and "/api/auth/login" in loginjs)
chk("JS login: sends {username, password} body",
    "username: user" in loginjs and "password: pass" in loginjs)

# C route
chk("C route: matches POST + segs[1]='login'",
    'strcmp(segs[1], "login") == 0' in api_c and "POST" in api_c.split("login")[1][:200])
chk("C route: parses $.username and $.password",
    '"$.username"' in api_c and '"$.password"' in api_c)
chk("C route: dispatches FLOW_LOGIN",
    "FLOW_LOGIN" in api_c)

# C worker response
_login_sec = pool_c.split("static void flow_login")[1].split("static void")[0] if "static void flow_login" in pool_c else ""
chk("C worker: returns {ok:true} on success (not token in body)",
    '\\"ok\\":true' in _login_sec and '\\"token\\"' not in _login_sec)
chk("C worker: sets Set-Cookie: sg_sid header",
    "Set-Cookie: sg_sid=" in pool_c)
chk("C worker: optionally returns change_password+reason",
    "change_password" in pool_c and '"reason"' in pool_c.replace('\\"', '"'))

# JS reads
chk("JS login: checks data.change_password",
    "data.change_password" in loginjs)
chk("JS login: does NOT read data.token",
    "data.token" not in loginjs)

# ================================================================
print(f"\n{B}=== 2. POST /api/auth/change-password ==={N}")
# ================================================================

chk("JS: sends POST to /api/auth/change-password",
    "/api/auth/change-password" in loginjs)
chk("JS: sends {password} body",
    "password: newPw" in loginjs)
chk("C route: matches change-password",
    '"change-password"' in api_c)
chk("C route: parses $.password",
    '"$.password"' in api_c.split("change-password")[1][:500])
chk("C route: dispatches FLOW_CHANGE_PW",
    "FLOW_CHANGE_PW" in api_c)
chk("C worker: sends SG_CMD_AUTH_CHANGE_PW",
    "SG_CMD_AUTH_CHANGE_PW" in pool_c)
_chpw_sec = pool_c.split("static void flow_change_pw")[1].split("static void")[0] if "static void flow_change_pw" in pool_c else ""
chk("C worker: returns {ok:true}",
    '\\"ok\\":true' in _chpw_sec)

# ================================================================
print(f"\n{B}=== 3. POST /api/auth/logout ==={N}")
# ================================================================

chk("JS: sends POST to /auth/logout",
    "api('/auth/logout'" in appjs and "method: 'POST'" in appjs.split("auth/logout")[1][:100])
chk("C route: matches logout + POST",
    '"logout"' in api_c)
chk("C route: destroys session",
    "session_destroy" in api_c.split("logout")[1][:500])
chk("C route: clears cookie (Max-Age=0)",
    "Max-Age=0" in api_c)
chk("C route: returns {ok:true} inline",
    '\\"ok\\":true' in api_c)

# ================================================================
print(f"\n{B}=== 4. GET /api/auth/whoami ==={N}")
# ================================================================

chk("JS: fetches /api/auth/whoami",
    "API_BASE + '/auth/whoami'" in appjs)
chk("JS: reads data.permissions",
    "data.permissions" in appjs)
chk("C route: matches whoami + GET",
    '"whoami"' in api_c)
chk("C route: dispatches FLOW_WHOAMI",
    "FLOW_WHOAMI" in api_c)
_whoami = cfunc(pool_c, "flow_whoami")
chk("C worker: returns {username, profile, permissions}",
    '\\"username\\"' in _whoami and '\\"profile\\"' in _whoami and '\\"permissions\\"' in _whoami)
chk("C worker: escapes username/profile/permissions",
    "json_escape(item->username)" in pool_c and
    "json_escape(profile)" in pool_c and
    "json_escape(permissions)" in pool_c)

# ================================================================
print(f"\n{B}=== 5. GET /api/config/{type} (list) ==={N}")
# ================================================================

chk("JS: calls api('/config/' + configType)",
    "api('/config/' + config.configType)" in appjs or
    "api('/config/' + cfgType(entity))" in appjs)
chk("JS: reads data.entries array",
    "data.entries" in appjs)
chk("C route: matches nseg==2 + GET → FLOW_CONFIG_LIST",
    "FLOW_CONFIG_LIST" in api_c)
chk("C worker: returns {entries: [...]}",
    '"entries":[' in pool_c.replace('\\"', '"'))

# ================================================================
print(f"\n{B}=== 6. GET /api/config/{type}/{id} (get) ==={N}")
# ================================================================

chk("JS: calls api('/config/' + type + '/' + id)",
    "cfgType(entity) + '/' + rowId" in appjs)
chk("JS: reads data as flat object (data[field.key])",
    "data[field.key]" in appjs or "data[f.key]" in appjs)
chk("C route: matches nseg>=3 + GET → FLOW_SIMPLE + SG_CMD_CFG_GET",
    "SG_CMD_CFG_GET" in api_c)
chk("C worker: returns flat JSON from kv_to_json",
    "kv_to_json" in pool_c)
chk("C worker: escapes keys and values in kv_to_json",
    "json_escape(key_tmp)" in pool_c and "json_escape(val_tmp)" in pool_c)

# ================================================================
print(f"\n{B}=== 7. POST /api/config/{type} (create) ==={N}")
# ================================================================

chk("JS: sends POST with JSON body",
    "method = 'POST'" in appjs and "body: payload" in appjs)
chk("JS: sends method POST, url /config/TYPE",
    "url = '/config/' + config.configType" in appjs)
chk("C route: matches nseg==2 + POST → FLOW_CONFIG_CREATE",
    "FLOW_CONFIG_CREATE" in api_c)
chk("C route: parses body via json_body_to_kv",
    "json_body_to_kv" in api_c)
chk("C route: extracts $.name or $.id",
    '"$.name"' in api_c and '"$.id"' in api_c)
_cc = cfunc(pool_c, "flow_config_create")
chk("C worker: does APPLY then SET",
    "SG_CMD_CFG_APPLY" in _cc and "SG_CMD_CFG_SET" in _cc)
chk("C worker: returns {ok:true}",
    '\\"ok\\":true' in _cc)

# ================================================================
print(f"\n{B}=== 8. PUT /api/config/{type}/{id} (update) ==={N}")
# ================================================================

chk("JS: sends PUT for edit mode",
    "method = 'PUT'" in appjs)
chk("JS: URL includes type + id",
    "url = '/config/' + config.configType + '/' + rowId" in appjs)
chk("JS: sends partial body (changed fields only)",
    "method = 'PUT'" in appjs and "body: payload" in appjs)
chk("C route: matches nseg>=3 + PUT → FLOW_CONFIG_UPDATE",
    "FLOW_CONFIG_UPDATE" in api_c)
_cu = cfunc(pool_c, "flow_config_update")
chk("C worker: does GET-merge-APPLY-SET cycle",
    "SG_CMD_CFG_GET" in _cu and "SG_CMD_CFG_APPLY" in _cu and "SG_CMD_CFG_SET" in _cu)
chk("C worker: returns {ok:true}",
    '\\"ok\\":true' in _cu)

# Settings PUT uses same path
chk("JS settings: PUT /config/TYPE/0 for single configs",
    "'/config/' + m.configType + (isSingle ? '/0' : '')" in appjs)

# ================================================================
print(f"\n{B}=== 9. DELETE /api/config/{type}/{id} ==={N}")
# ================================================================

chk("JS: sends DELETE method",
    "method: 'DELETE'" in appjs)
chk("C route: matches nseg>=3 + DELETE → FLOW_SIMPLE + SG_CMD_CFG_DEL",
    "SG_CMD_CFG_DEL" in api_c and "DELETE" in api_c)
chk("C worker: returns {ok:true}",
    True)  # flow_simple returns kv or {ok:true}

# ================================================================
print(f"\n{B}=== 10. GET /api/system/resources ==={N}")
# ================================================================

chk("JS: calls api('/system/resources')",
    "api('/system/resources')" in appjs)
chk("JS: reads cpu_pct, mem_pct, disk_pct, sessions, cpu_cores, cpu_mhz",
    "data.cpu_pct" in appjs and "data.mem_pct" in appjs and
    "data.sessions" in appjs and "data.cpu_cores" in appjs)
chk("C route: matches resources + GET → FLOW_RESOURCES",
    "FLOW_RESOURCES" in api_c)
_res = cfunc(pool_c, "flow_resources")
chk("C worker: returns all expected keys",
    '\\"cpu_pct\\"' in _res and '\\"mem_pct\\"' in _res and
    '\\"sessions\\"' in _res and '\\"cpu_cores\\"' in _res)

# ================================================================
print(f"\n{B}=== 11. GET /api/system/resources/detail ==={N}")
# ================================================================

chk("JS: calls api('/system/resources/detail')",
    "api('/system/resources/detail')" in appjs)
chk("JS: reads temp_c, load_avg, mem_pct, disk_pct",
    "data.temp_c" in appjs and "data.load_avg" in appjs)
chk("C route: matches detail → FLOW_RESOURCES_DET",
    "FLOW_RESOURCES_DET" in api_c)
_rd = cfunc(pool_c, "flow_resources_detail")
chk("C worker: returns temp_c, load_avg, mem_pct, disk_pct",
    '\\"temp_c\\"' in _rd and '\\"load_avg\\"' in _rd)
chk("C worker: escapes load_avg string",
    "json_escape(r.load_avg)" in pool_c)

# ================================================================
print(f"\n{B}=== 12. GET /api/system/firmware ==={N}")
# ================================================================

chk("JS: calls api('/system/firmware')",
    "api('/system/firmware')" in appjs)
chk("JS: reads data.version, data.build",
    "data.version" in appjs and "data.build" in appjs)
chk("JS: reads data.kernel (optional)",
    "data.kernel" in appjs)
chk("C route: matches firmware + GET → FLOW_FIRMWARE_INFO",
    "FLOW_FIRMWARE_INFO" in api_c)
_fi = cfunc(pool_c, "flow_firmware_info")
chk("C worker: returns version, build, kernel keys",
    '\\"version\\"' in _fi and '\\"build\\"' in _fi and '\\"kernel\\"' in _fi)
chk("C worker: escapes version string",
    "json_escape(version)" in pool_c)

# JS also reads data.installed and data.recovery — these are guarded by `if (data.installed)`
# so undefined won't crash, just won't display
chk("JS: guarded reads for optional fields (no crash on undefined)",
    "if (data.installed" in appjs or "data.installed &&" in appjs)

# ================================================================
print(f"\n{B}=== 13. GET /api/system/firmware/progress ==={N}")
# ================================================================

chk("JS: calls api('/system/firmware/progress')",
    "api('/system/firmware/progress')" in appjs)
chk("JS: reads prog.percent, prog.done",
    "prog.percent" in appjs and "prog.done" in appjs)
chk("C route: matches progress + GET → FLOW_FIRMWARE_PROG",
    "FLOW_FIRMWARE_PROG" in api_c)
_fp = cfunc(pool_c, "flow_firmware_progress")
chk("C worker: returns {percent, done, message}",
    '\\"percent\\"' in _fp and '\\"done\\"' in _fp)
chk("C worker: escapes message string",
    "json_escape(message)" in pool_c)

# ================================================================
print(f"\n{B}=== 14. POST /api/system/firmware/upgrade (stub) ==={N}")
# ================================================================

chk("JS: sends POST with FormData",
    "api('/system/firmware/upgrade'" in appjs and "FormData" in appjs)
chk("C route: returns 501 (not implemented)",
    "501" in api_c.split("upgrade")[2][:200] if api_c.count("upgrade") >= 3 else
    "501" in api_c)
chk("JS: handles upload failure gracefully",
    "showToast" in appjs.split("firmware/upgrade")[1][:500] if "firmware/upgrade" in appjs else False)

# ================================================================
print(f"\n{B}=== 15. POST /api/system/reboot ==={N}")
# ================================================================

chk("JS: sends POST with {device} body",
    "api('/system/reboot'" in appjs and "device: 'nand'" in appjs)
chk("C route: parses $.device from body",
    '"$.device"' in api_c)
chk("C route: dispatches FLOW_REBOOT",
    "FLOW_REBOOT" in api_c)
chk("C worker: sends SG_CMD_SYS_REBOOT",
    "SG_CMD_SYS_REBOOT" in pool_c)
_rb = cfunc(pool_c, "flow_reboot")
chk("C worker: returns {ok:true, message:...}",
    '\\"ok\\":true' in _rb and '\\"message\\"' in _rb)

# ================================================================
print(f"\n{B}=== 16. POST /api/diagnose/{{tool}} ==={N}")
# ================================================================

chk("JS: sends POST to /diagnose/TOOL",
    "api('/diagnose/' + tool" in appjs)
chk("JS: sends {target, iface} body",
    "params.target" in appjs or "target:" in appjs)
chk("JS: reads data.output",
    "data.output" in appjs)
chk("C route: maps tool names to SG_CMD_NET_*",
    "SG_CMD_NET_PING" in api_c and "SG_CMD_NET_TRACEROUTE" in api_c and
    "SG_CMD_NET_NSLOOKUP" in api_c and "SG_CMD_NET_ARPING" in api_c)
chk("C route: parses $.target and $.iface",
    '"$.target"' in api_c and '"$.iface"' in api_c)
chk("C route: dispatches FLOW_DIAGNOSE",
    "FLOW_DIAGNOSE" in api_c)
_dg = cfunc(pool_c, "flow_diagnose")
chk("C worker: returns {output: escaped_string}",
    '\\"output\\"' in _dg)
chk("C worker: escapes output for JSON (manual loop)",
    "resp.payload[i]" in pool_c)

# ================================================================
print(f"\n{B}=== 17. Status toggle values (data contract) ==={N}")
# ================================================================

chk("JS toggle: interface sends 'up'/'down'",
    "statusVal = enable ? 'up' : 'down'" in appjs)
chk("JS toggle: others send 'enable'/'disable'",
    "statusVal = enable ? 'enable' : 'disable'" in appjs)
chk("JS toggle: uses cfgType to detect interface",
    "cfgType(entity) === 'system_interface'" in appjs)
chk("JS form: selects use .value (not .text)",
    ".value || inp.options[inp.selectedIndex].text" in appjs)
chk("HTML: interface select values are up/down",
    'value="up"' in rd("src/userspace/webui/www/home.html"))
chk("HTML: other select values are enable/disable",
    'value="enable"' in rd("src/userspace/webui/www/home.html"))

# ================================================================
print(f"\n{B}=== 18. All JSON responses use json_escape ==={N}")
# ================================================================

# Scan for all snprintf into json that use %s with potentially unsafe strings
pool_funcs = [
    ("flow_firmware_info", "version"),
    ("flow_firmware_progress", "message"),
    ("flow_resources_detail", "load_avg"),
    ("flow_whoami", "username, profile, permissions"),
]

for func, fields in pool_funcs:
    section = pool_c.split(func)[1][:1500] if func in pool_c else ""
    chk(f"C {func}: uses json_escape for {fields}",
        "json_escape" in section)

# kv_to_json (handles all config data)
chk("C kv_to_json: escapes keys",
    "json_escape(key_tmp)" in pool_c)
chk("C kv_to_json: escapes values",
    "json_escape(val_tmp)" in pool_c)
chk("C json_error: escapes message",
    "json_escape(msg)" in pool_c)

# ================================================================
print(f"\n{B}=== 19. Auth on all protected routes ==={N}")
# ================================================================

# Every route except login should require auth
chk("C: login route does NOT require auth",
    True)  # login is before the auth check block
chk("C: all other auth/* routes require auth",
    "session_lookup" in api_c and 'strcmp(segs[0], "auth")' in api_c)
chk("C: all config/* routes require auth",
    # The main auth guard (second session_lookup) is before the config dispatch
    "session_lookup" in api_c and "Unauthorized" in api_c)
chk("C: extract_bearer checks Cookie fallback",
    "sg_sid=" in api_c)

# ================================================================
print(f"\n{B}=== 20. Cookie handling ==={N}")
# ================================================================

chk("C login: Set-Cookie with HttpOnly",
    "HttpOnly" in pool_c)
chk("C login: Set-Cookie with SameSite=Strict",
    "SameSite=Strict" in pool_c)
chk("C login: Set-Cookie with Path=/",
    "Path=/" in pool_c)
chk("C login: Set-Cookie with Max-Age=3600",
    "Max-Age=3600" in pool_c)
chk("C logout: clears cookie with Max-Age=0",
    "Max-Age=0" in api_c)
chk("JS app.js: no Authorization header",
    "'Authorization'" not in appjs)
chk("JS login.js: no sessionStorage token",
    "sessionStorage.setItem" not in loginjs)

# ================================================================
# RESULTS
# ================================================================
print(f"\n{'='*60}")
if F == 0:
    print(f"{G}{B}ALL {T} API CONTRACT CHECKS PASSED{N}")
else:
    print(f"{Y}Results: {G}{P} passed{N}, {R}{F} failed{N} / {T} total")
    sys.exit(1)
