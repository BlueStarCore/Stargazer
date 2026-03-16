# Stargazer NGFW — Attacker's Perspective & Security Plan

## Threat Model

The firewall sits at the network edge. Attackers range from:
- **External attacker** with no credentials, only HTTP access to port 443
- **Low-privilege insider** with a monitor-only account (can read, not write config)
- **Partial insider** with configure permissions but not admin
- **Compromised process** running as `__webd` (sandboxed, UID 900)
- **Physical attacker** with SSH or console access, trying to escalate from a non-root shell

The firewall's job is to be the last line of defence. Every daemon, config path, and API
endpoint must assume the caller is hostile.

---

## Attack Surface Map

| Entry point | Protocol | Exposed to | Trust level |
|------------|----------|------------|-------------|
| HTTPS :443 | TLS/HTTP | LAN / WAN | Zero trust |
| Unix socket `/run/stargazer-mgmtd.sock` | Binary IPC | Local processes | UID-verified |
| CLI (`/sbin/stargazer-cli`) | stdin/readline | Console / SSH | Authenticated user |
| Kernel module hook | Netfilter FORWARD | Network packets | N/A |
| Init + shell scripts | Shell | Boot / root | Root only |

---

## Category A — Authentication Attacks

### ATK-A-01: Brute-force login
- **Method**: Send repeated POST /api/auth/login with wrong passwords
- **Target**: webd rate limiter
- **Status**: PROTECTED — rate limiter fires at 10 req/s (429)
- **Test**: `test_api_live.sh` phase2

### ATK-A-02: Username enumeration via timing
- **Method**: Login with valid vs. non-existent username, measure response time
- **Target**: auth handler in mgmtd
- **Status**: PROTECTED — mgmtd runs crypt() even for missing users to equalize timing
- **Test**: `test_api_live.sh` phase2 (status code parity, timing not measured)
- **Gap**: No automated timing comparison test

### ATK-A-03: Login with injected username (XSS, SQL, shell)
- **Method**: `{"username":"<script>alert(1)</script>","password":"x"}`
- **Target**: webd JSON parser → IPC → mgmtd safe-id validation
- **Status**: PROTECTED — `sg_is_safe_id()` rejects non-alphanum chars; webd returns 400
- **Test**: `test_api_live.sh` phase2

### ATK-A-04: Login with null-byte username
- **Method**: `{"username":"admin\u0000evil","password":"..."}`
- **Target**: username field (64-byte fixed buffer in IPC header)
- **Status**: PROTECTED — JSON parser yields C string (null-terminated), safe-id rejects
- **Test**: `test_security_pentest.sh` ATK-A-04

### ATK-A-05: Claim `__webd` service account via HTTP
- **Method**: Forge a session cookie/token claiming to be `__webd`
- **Target**: Identity bypass — `__webd` skips session tag validation in mgmtd
- **Status**: PROTECTED — mgmtd uses `SO_PEERCRED` to kernel-verify UID; UID 900 is
  only reachable by the actual webd process. A normal user claiming `__webd` gets
  their real UID looked up instead.
- **Test**: `test_security_pentest.sh` ATK-A-05 (static verify + live attempt)

### ATK-A-06: Login with maximum-length username (63 chars)
- **Method**: Send 63-char username (IPC header limit is 64 incl. null)
- **Target**: Buffer handling in IPC header copy
- **Status**: NEEDS TEST — boundary not explicitly tested
- **Test**: `test_security_pentest.sh` ATK-A-06

### ATK-A-07: Login with empty Content-Type
- **Method**: POST /api/auth/login with no Content-Type header
- **Target**: webd JSON body parser
- **Status**: NEEDS TEST
- **Test**: `test_security_pentest.sh` ATK-A-07

---

## Category B — Session Management Attacks

### ATK-B-01: Session replay after logout
- **Method**: Copy cookie before logout, send it after logout
- **Target**: webd session store (memset on destroy)
- **Status**: PROTECTED — token is zeroed from slot; subsequent lookup returns 401
- **Test**: `test_api_live.sh` phase11

### ATK-B-02: Garbage/short token
- **Method**: Send `Authorization: Bearer 0000...` (64 chars) or `Bearer short`
- **Target**: `session_lookup()` length check + constant-time compare
- **Status**: PROTECTED
- **Test**: `test_api_live.sh` phase11

### ATK-B-03: Bearer header takes priority over cookie
- **Method**: Send valid cookie + invalid bearer simultaneously
- **Target**: `extract_bearer()` priority logic
- **Status**: PROTECTED — bearer wins, invalid bearer → 401 even with valid cookie
- **Test**: `test_api_live.sh` phase11

### ATK-B-04: Session idle timeout bypass
- **Method**: Steal a cookie, wait 15 min idle, try to use it
- **Target**: `WEBD_IDLE_TIMEOUT = 900s` check in `session_lookup()`
- **Status**: PROTECTED
- **Test**: `test_webui_security_attacks.py` ATTACK-6 (static)

### ATK-B-05: Session slot exhaustion — webd (128 sessions)
- **Method**: Create 130+ simultaneous sessions; verify LRU eviction fires
- **Target**: `sessions[WEBD_MAX_SESSIONS=128]` pool
- **Expected**: 130th login succeeds (evicts oldest), oldest session gets 401
- **Status**: NEEDS TEST — LRU eviction is implemented but not live-tested
- **Test**: `test_security_pentest.sh` ATK-B-05

### ATK-B-06: Session slot exhaustion — mgmtd (16 tags)
- **Method**: Fill all 16 mgmtd session tag slots via rapid CLI logins
- **Target**: `g_session_tags[MAX_SESSION_TAGS=16]`
- **Expected**: 17th `SG_CMD_SESSION_TAG_NEW` returns error (table full)
- **Status**: NEEDS TEST
- **Test**: `test_security_pentest.sh` ATK-B-06 (needs pentest/sg_pentest)

### ATK-B-07: Session fixation
- **Method**: Obtain a session token before login, try to force the server to use it
- **Target**: `session_create_with_tag()` — always generates new token with `getrandom()`
- **Status**: PROTECTED — token is generated server-side, client cannot force a value
- **Test**: `test_webui_security_attacks.py` ATTACK-4 (HttpOnly verification)

### ATK-B-08: Session tag with no TTL (long-lived admin session)
- **Method**: Login, never log out, come back days later
- **Target**: mgmtd session tags have no expiry timestamp
- **Status**: GAP — tags live until explicit logout or mgmtd restart. A forgotten admin
  session stays valid indefinitely.
- **Recommendation**: Add `created_at` field to `session_tag_entry`, expire after 24h
- **Test**: `test_security_pentest.sh` ATK-B-08 (documents the gap)

---

## Category C — Authorization / Privilege Escalation

### ATK-C-01: Read-only user writes config
- **Method**: testro (monitor) sends PUT /api/config/firewall_policy/1
- **Target**: mgmtd permission check on SG_CMD_CFG_SET
- **Status**: PROTECTED — returns 403
- **Test**: `test_api_live.sh` phase5

### ATK-C-02: Read-only user creates admin
- **Method**: testro sends POST /api/admin/create
- **Status**: PROTECTED — returns 403
- **Test**: `test_api_live.sh` phase10

### ATK-C-03: Self-escalation — change own profile
- **Method**: testro sends PUT /api/config/system_admin/testro `{"profile":"read-write"}`
- **Target**: `system_admin` type requires `admin` permission; configure-level should not suffice
- **Status**: NEEDS TEST — the permission for `system_admin` is `admin`, so even
  configure-only users cannot modify it
- **Test**: `test_security_pentest.sh` ATK-C-03

### ATK-C-04: Self-escalation — modify own profile permissions
- **Method**: testro sends PUT /api/config/system_admin-profile/read-only `{"permissions":"monitor,configure,admin"}`
- **Target**: `system_admin-profile` type requires `admin` permission
- **Status**: NEEDS TEST (should return 403 for non-admin)
- **Test**: `test_security_pentest.sh` ATK-C-04

### ATK-C-05: Configure user accesses admin-only config types
- **Method**: A user with `configure` perm (not `admin`) tries to GET/PUT system_admin,
  system_admin-profile, system_password-policy
- **Target**: type-level permission enforcement in mgmtd
- **Status**: NEEDS TEST — type_table has `"admin"` access level for these types
- **Test**: `test_security_pentest.sh` ATK-C-05

### ATK-C-06: IDOR — access other user's admin config
- **Method**: testro reads GET /api/config/system_admin/admin — should this be allowed?
  Monitor users can read system config; admin's record includes profile but NOT password.
- **Target**: Does mgmtd ever return password hash via the config API?
- **Status**: NEEDS TEST — password hash is in Linux shadow, not in SQLite config.
  The `password` field in system_admin is `password-interactive` (set-only), not stored
  in DB. But worth confirming the API doesn't leak it.
- **Test**: `test_security_pentest.sh` ATK-C-06

### ATK-C-07: Delete admin account being used in active session
- **Method**: Admin A deletes Admin B while B is logged in → B's next request should 401
- **Target**: `admin_notify_change()` → `session_tag_purge_user()` invalidates tags
- **Status**: PROTECTED — mgmtd purges session tags on account deletion
- **Test**: `test_security_pentest.sh` ATK-C-07

### ATK-C-08: Delete builtin admin account
- **Method**: DELETE /api/config/system_admin/admin
- **Status**: PROTECTED — returns 403 (builtin flag)
- **Test**: `test_api_live.sh` phase6

### ATK-C-09: Delete profile while still in use
- **Method**: Create user with "read-only" profile, then try to delete "read-only" profile
- **Target**: `SG_ERR_IN_USE` guard in mgmtd before profile deletion
- **Status**: NEEDS TEST at HTTP level
- **Test**: `test_security_pentest.sh` ATK-C-09

### ATK-C-10: Horizontal escalation — reboot without admin perm
- **Method**: testro sends POST /api/system/reboot
- **Status**: PROTECTED — returns 403
- **Test**: `test_api_live.sh` phase20

---

## Category D — Input Validation

### ATK-D-01: Oversized string field value
- **Method**: PUT comment = 50,000-char string; PUT hostname = 300-char string
- **Target**: field validators — `string` kind has no explicit max in field_table
- **Status**: PARTIALLY — IPC payload is capped at 4096 bytes (SG_PAYLOAD_MAX).
  Any single config set exceeding 4096 bytes will be rejected at the IPC layer before
  reaching SQLite. But worth confirming graceful rejection.
- **Test**: `test_security_pentest.sh` ATK-D-01

### ATK-D-02: Null byte in field value
- **Method**: PUT `{"comment":"value\u0000injected"}` (JSON unicode escape for null)
- **Target**: C string handling — does mgmtd treat null as end-of-string safely?
- **Status**: NEEDS TEST — JSON parsers may or may not pass null bytes
- **Test**: `test_security_pentest.sh` ATK-D-02

### ATK-D-03: Unicode / multibyte characters in string field
- **Method**: PUT `{"comment":"你好世界"}` — multibyte UTF-8
- **Target**: kv storage and JSON response escaping
- **Status**: NEEDS TEST — C code uses byte-level operations, should be safe,
  but JSON escape of multibyte chars should be verified
- **Test**: `test_security_pentest.sh` ATK-D-03

### ATK-D-04: Integer boundary values for uint fields
- **Method**: PUT `{"mtu":"0"}`, `{"mtu":"-1"}`, `{"mtu":"99999"}`, `{"mtu":"4294967295"}`
- **Target**: `sg_is_uint_range()` with configured min/max
- **Status**: PARTIALLY tested in sg_pentest.c — needs HTTP-level confirmation
- **Test**: `test_security_pentest.sh` ATK-D-04

### ATK-D-05: CIDR boundary values
- **Method**: PUT `{"ip":"0.0.0.0/0"}`, `{"ip":"255.255.255.255/32"}`, `{"ip":"192.168.1.1/33"}`
- **Target**: `sg_is_cidr()` validator
- **Status**: NEEDS TEST at HTTP level (valid CIDRs should be accepted, /33 rejected)
- **Test**: `test_security_pentest.sh` ATK-D-05

### ATK-D-06: Enum field with wrong case
- **Method**: PUT `{"status":"Enable"}` (capital E) — enum expects lowercase
- **Target**: `sg_reg_validate_value()` enum comparison
- **Status**: NEEDS TEST — comparison is `strcmp` (case-sensitive)
- **Test**: `test_security_pentest.sh` ATK-D-06

### ATK-D-07: Extra unknown fields in PUT body
- **Method**: PUT `{"action":"accept","unknown_field":"evil","__proto__":"hack"}`
- **Target**: `json_body_to_kv()` → mgmtd ignores unknown keys, only stores known ones
- **Status**: PROTECTED — mgmtd validates each key against field_table registry
- **Test**: `test_security_pentest.sh` ATK-D-07

### ATK-D-08: Required field missing in POST (create)
- **Method**: POST firewall_policy without required `srcintf`
- **Target**: `check_required_fields()` in mgmtd
- **Status**: PROTECTED — returns error listing missing fields
- **Test**: `test_api_live.sh` phase10 (admin create missing username)
- **Gap**: Not tested for non-admin config types

---

## Category E — Injection Attacks

### ATK-E-01: Command injection in diagnose target
- **Method**: POST /api/diagnose/ping `{"target":"127.0.0.1; id"}`
- **Target**: `sg_is_net_target()` → `stream_exec()` with argv array (no shell)
- **Status**: PROTECTED — `sg_is_net_target()` rejects `;`, `$`, spaces, `|`, etc.
  Even if it slipped through, `execvp()` passes args as array (no shell interpolation).
- **Test**: `test_security_pentest.sh` ATK-E-01

### ATK-E-02: Command injection in diagnose iface
- **Method**: POST /api/diagnose/arping `{"target":"1.2.3.4","iface":"eth0; id"}`
- **Target**: `sg_is_iface_name()` checks `/sys/class/net/` existence
- **Status**: PROTECTED — `sg_is_iface_name()` validates via sysfs; no shell
- **Test**: `test_security_pentest.sh` ATK-E-02

### ATK-E-03: SQL injection in config set
- **Method**: PUT `{"name":"' OR 1=1 --","action":"accept"}`
- **Target**: `sg_db_set()` / `sg_db_get()` — all SQL uses `sqlite3_bind_text()`
- **Status**: PROTECTED — parameterized queries throughout
- **Test**: `tests/pentest/sg_pentest.c` test_sql_injection

### ATK-E-04: SQL injection in search filter (config list)
- **Method**: GET /api/config/firewall_policy?q=' OR 1=1 --
- **Target**: webd query param → IPC → mgmtd search handler
- **Status**: NEEDS TEST — search filter path not tested for injection
- **Test**: `test_security_pentest.sh` ATK-E-04

### ATK-E-05: JSON structure injection in config value
- **Method**: PUT `{"comment":"value\",\"injected\":\"true"}`
- **Target**: `json_escape()` in `kv_to_json()` before sending to client
- **Status**: PROTECTED — `json_escape()` escapes `"`, `\`, control chars
- **Test**: `test_webui_security_attacks.py` ATTACK-2

### ATK-E-06: Newline injection in IPC kv payload
- **Method**: Via IPC, send `key=value\nmalicious_key=evil` in payload
- **Target**: `kv_parse()` in mgmtd — is the key sanitized against newlines?
- **Status**: NEEDS TEST (IPC-level) — the HTTP API goes through `json_body_to_kv()`
  which produces the kv string, and key names are validated against field registry
- **Test**: `tests/pentest/sg_pentest.c` (add to test_config_validation)

### ATK-E-07: Path traversal in URL segments
- **Method**: GET /api/config/../../etc/passwd
- **Target**: URL segment parser in webd
- **Status**: PROTECTED — returns 404/400
- **Test**: `test_api_live.sh` phase18

### ATK-E-08: Stored XSS via config field
- **Method**: CLI sets interface description to `<script>alert(1)</script>`, then admin
  opens web UI
- **Target**: `esc()` in JS `renderEntityRows()` escapes all displayed values
- **Status**: PROTECTED
- **Test**: `test_webui_security_attacks.py` ATTACK-1

---

## Category F — Web Security

### ATK-F-01: CSRF via cross-origin request
- **Method**: evil.com sends POST to /api/config/... with cookie
- **Target**: `SameSite=Strict` on sg_sid cookie prevents cross-origin attachment
- **Status**: PROTECTED
- **Test**: `test_webui_security_attacks.py` ATTACK-5

### ATK-F-02: Clickjacking via iframe embed
- **Method**: evil.com embeds firewall in an iframe
- **Target**: `X-Frame-Options: DENY` header
- **Status**: PROTECTED
- **Test**: `test_api_live.sh` phase13

### ATK-F-03: HTTPS downgrade / SSL stripping
- **Method**: MitM strips HTTPS on first connection
- **Target**: HSTS header `max-age=31536000; includeSubDomains`
- **Status**: PROTECTED once first HTTPS visit occurs
- **Test**: `test_webui_security_attacks.py` ATTACK-11

### ATK-F-04: Malicious firmware upload
- **Method**: Upload a .exe or 500MB file as firmware update
- **Target**: JS validation: .itb extension only, max 64MB, before FormData
- **Status**: PROTECTED at JS level
- **Note**: Server-side stub returns 501 (not implemented), so no server-side upload
  test is possible yet
- **Test**: `test_webui_security_attacks.py` ATTACK-7

### ATK-F-05: Large HTTP body DoS (memory pressure)
- **Method**: POST 10MB body to /api/auth/login
- **Target**: mongoose HTTP body buffer limits in webd
- **Status**: NEEDS TEST — mongoose may buffer entire body before dispatch
- **Test**: `test_security_pentest.sh` ATK-F-05

### ATK-F-06: HTTP method abuse (PATCH, HEAD, OPTIONS)
- **Method**: PATCH /api/config/system_interface
- **Status**: PROTECTED — returns 405
- **Test**: `test_api_live.sh` phase16

### ATK-F-07: Wrong Content-Type on JSON endpoint
- **Method**: POST /api/auth/login with `Content-Type: text/plain` and JSON body
- **Target**: webd JSON parser — does it require Content-Type?
- **Status**: NEEDS TEST
- **Test**: `test_security_pentest.sh` ATK-F-07

---

## Category G — Denial of Service

### ATK-G-01: Login rate limit flood
- **Method**: 11 rapid login attempts → 429 on 11th
- **Status**: PROTECTED
- **Test**: `test_api_live.sh` phase2

### ATK-G-02: Connection flood (100 rapid connects)
- **Method**: 100 rapid TCP connects to mgmtd Unix socket
- **Status**: PROTECTED — mgmtd survives, still responsive
- **Test**: `tests/pentest/sg_pentest.c` DOS-01/DOS-02

### ATK-G-03: Max IPC payload
- **Method**: 4096-byte payload to mgmtd
- **Status**: PROTECTED — SG_PAYLOAD_MAX enforced, rejected without crash
- **Test**: `tests/pentest/sg_pentest.c` DOS-03

### ATK-G-04: Slowloris-style slow send
- **Method**: Connect to mgmtd, send 1 byte/second
- **Status**: PROTECTED — mgmtd handles it, remains responsive
- **Test**: `tests/pentest/sg_pentest.c` DOS-05

### ATK-G-05: Session pool exhaustion
- **Method**: Create 130 webd sessions → LRU eviction kicks in; oldest session logged out
- **Status**: NEEDS TEST — LRU eviction may kick out legitimate sessions silently
- **Test**: `test_security_pentest.sh` ATK-G-05

### ATK-G-06: Rapid config create/delete loop
- **Method**: Create + delete 500 firewall policies in rapid succession
- **Target**: mgmtd single-threaded handler, SQLite write throughput
- **Status**: NEEDS TEST
- **Test**: `test_security_pentest.sh` ATK-G-06

---

## Category H — Config Data Integrity

### ATK-H-01: Delete address object referenced by firewall policy (orphan)
- **Method**: Create address "testaddr", create policy with srcaddr="testaddr",
  delete "testaddr"
- **Target**: No referential integrity check in mgmtd before deletion
- **Status**: GAP — deletion succeeds; policy now has a dangling reference.
  When policy is evaluated, behavior depends on apply logic (may silently use stale value).
- **Recommendation**: Add pre-delete reference check for address, service objects.
- **Test**: `test_security_pentest.sh` ATK-H-01 (documents the gap)

### ATK-H-02: Delete admin profile referenced by admin account
- **Method**: Create admin with "read-only" profile, delete "read-only" profile
- **Target**: `SG_ERR_IN_USE` check in mgmtd
- **Status**: PROTECTED — mgmtd checks if profile is in use before deletion
- **Test**: `test_security_pentest.sh` ATK-H-02

### ATK-H-03: Create circular config reference
- **Method**: Create a firewall_policy where srcintf == dstintf (same interface)
- **Target**: No such validation exists; logically nonsensical but not invalid
- **Status**: ALLOWED — mgmtd does not check interface equality
- **Note**: Functionally harmless for firewall logic; traffic simply won't match

### ATK-H-04: Inject `builtin=yes` via config set
- **Method**: IPC: CFG_SET for system_admin with `builtin=yes\n` in payload
- **Status**: PROTECTED — mgmtd strips builtin flag on set
- **Test**: `tests/pentest/sg_pentest.c` PRIV-01

### ATK-H-05: Replay old config (config rollback attack)
- **Method**: Export current config, make destructive changes, re-import old config via
  PUT on each entry — no version or CSRF-per-op token
- **Target**: No operation-level CSRF protection beyond SameSite cookie
- **Status**: PARTIALLY PROTECTED — SameSite=Strict blocks cross-origin replay;
  within-session replay is allowed by design (that's how edit works)
- **Test**: Not applicable as standalone attack

---

## Category I — IPC Protocol Attacks

### ATK-I-01: Bad magic number
- **Method**: Send 0xDEAD in place of 0x5347
- **Status**: PROTECTED — connection dropped
- **Test**: `tests/pentest/sg_pentest.c` test_proto_fuzz

### ATK-I-02: Bad version number
- **Method**: Send version 99 instead of 2
- **Status**: PROTECTED — connection dropped
- **Test**: `tests/pentest/sg_pentest.c` test_proto_fuzz

### ATK-I-03: Payload length > SG_PAYLOAD_MAX
- **Method**: Claim payload_len = UINT32_MAX in header
- **Status**: PROTECTED — header checked before payload read
- **Test**: `tests/pentest/sg_pentest.c` test_proto_fuzz

### ATK-I-04: Privileged command with session_tag = 0
- **Method**: Send SG_CMD_CFG_SET with tag = 0 (untagged)
- **Status**: PROTECTED — `session_tag_validate()` rejects tag == 0
- **Test**: `tests/pentest/sg_pentest.c` test_privesc

### ATK-I-05: Spoof `__webd` username from non-UID-900 process
- **Method**: From shell (UID 1000), send IPC with username="__webd"
- **Target**: `SO_PEERCRED` + UID check in mgmtd connection handler
- **Status**: PROTECTED — mgmtd overwrites claimed username with `getpwuid(cred.uid)`
  when UID does not match 900
- **Test**: `tests/pentest/sg_pentest.c` (PRIV-04 / PRIV-05 cover spoofed non-admin user)

### ATK-I-06: Valid session tag used with wrong username
- **Method**: Login as "admin", get tag T. Send IPC with username="testro" and tag T.
- **Target**: `session_tag_validate(user, tag)` checks BOTH user AND tag match
- **Status**: PROTECTED — tag is only valid for the user it was issued to
- **Test**: Implicitly covered by PRIV-04/05 in sg_pentest.c

---

## Category J — Network / Firewall Logic

### ATK-J-01: `any/any/any` accept policy allows all traffic
- **Method**: Create policy: srcintf=any, dstintf=any, srcaddr=all, dstaddr=all,
  service=all, action=accept
- **Target**: pkt_forward.c applies iptables ACCEPT
- **Status**: BY DESIGN — admin explicitly chose to allow all; this is expected behavior
- **Test**: Not a security test — document as admin responsibility

### ATK-J-02: FORWARD chain not set to DROP by default
- **Method**: Before any firewall_policy is applied, check default FORWARD chain policy
- **Target**: `mgmtd_apply_firewall.c` default chain behavior
- **Status**: NEEDS TEST — if default FORWARD policy is ACCEPT before first rule,
  window exists between boot and rule application
- **Test**: `test_security_pentest.sh` ATK-J-02 (check iptables default at startup)

### ATK-J-03: Firewall bypass via IPv6 (no IPv6 policy enforced)
- **Method**: Send IPv6 traffic — if firewall only filters IPv4 FORWARD, IPv6 goes through
- **Target**: pkt_forward.c only hooks NF_INET_FORWARD (IPv4)
- **Status**: GAP — IPv6 is not filtered by pkt_forward.c
- **Recommendation**: Either explicitly block all IPv6 forwarding via ip6tables rule,
  or extend pkt_forward.c to hook NF_INET6_FORWARD
- **Test**: `test_security_pentest.sh` ATK-J-03 (static verify — check ip6tables rules)

---

## Category K — Firewall Policy Enforcement Gaps

### ATK-K-01: Named address object silently ignored in iptables rules
- **Method**: Create firewall policy with `srcaddr="trusted-net"` (a named address object),
  then check the actual iptables FORWARD rule generated
- **Target**: `build_forward_argv()` in `mgmtd_apply_firewall.c`
- **Root cause**: `-s/-d` flags only added when `sg_is_cidr(srcaddr)` returns true.
  Named address objects are `safe-id` format (not CIDR), so `sg_is_cidr()` fails
  and the `-s` flag is silently skipped.
- **Impact**: Policy `srcaddr="trusted-subnet" action=accept` generates
  `iptables -A FORWARD -j ACCEPT` — accepts **all** forwarded traffic, not just
  from the named address object's subnet. Policy `srcaddr="evil-host" action=deny`
  generates `iptables -A FORWARD -j DROP` — drops **all** forwarded traffic.
- **Status**: GAP — named address objects are silently not enforced at iptables level.
  Comment in code says "skip address object references" (intentional design, incomplete).
- **Severity**: HIGH functional gap — admin configures address-based policy, but
  the address restriction has zero effect.
- **Recommendation**: Resolve named address object to its `subnet` CIDR before
  calling `build_forward_argv()`. Use `sg_db_get()` to look up the address entry.
- **Test**: `test_firewall_behavior.sh` Phase 4

### ATK-K-02: Service object silently ignored in iptables rules
- **Method**: Create firewall policy with `service="web-service"` (a named service object),
  then verify the iptables rule — no `--dport` or `-p tcp` present.
- **Target**: `build_forward_argv()` in `mgmtd_apply_firewall.c`
- **Root cause**: `build_forward_argv()` takes only srcintf/dstintf/srcaddr/dstaddr/target.
  Protocol and port are not passed in, so service objects have no iptables effect.
- **Impact**: Policy `service="https-only" action=accept` generates
  `iptables -A FORWARD -j ACCEPT` — allows traffic on ALL ports, not just 443.
- **Status**: GAP — service objects are completely ignored in iptables rules.
  pkt_forward.ko may handle L4 filtering, but this is not confirmed.
- **Severity**: HIGH functional gap — port/protocol-based access control not enforced.
- **Recommendation**: Pass service protocol and port range to `build_forward_argv()`,
  add `-p tcp --dport PORT` / `-p udp --dport PORT` to generated iptables rule.
- **Test**: `test_firewall_behavior.sh` Phase 1

### ATK-K-03: Init does not set FORWARD DROP before mgmtd starts
- **Method**: Boot system; watch FORWARD chain policy between init and mgmtd startup.
- **Target**: `src/userspace/init` — sets `iptables -P INPUT DROP` but not `FORWARD DROP`.
  `mgmtd_init_firewall()` sets `iptables -P FORWARD DROP` but only when mgmtd starts.
- **Impact**: Small window (typically 1-3 seconds at boot) where FORWARD chain is ACCEPT.
  An attacker at the LAN port during this boot window could forward traffic through
  the firewall before rules are in place.
- **Status**: GAP (low practical risk; window is brief and requires physical presence/LAN access)
- **Recommendation**: Add `iptables -P FORWARD DROP` to init before starting mgmtd.
- **Test**: `test_firewall_behavior.sh` Phase 1 (source check), Phase 2 (live check)

### ATK-K-04: Route proto-static substring match (very low risk)
- **Method**: Manually add a route via `ip route add 10.0.0.0/8 proto statically-set`;
  then try to disable the Stargazer static route — check if `strstr("proto static")`
  incorrectly matches.
- **Target**: `mgmtd_apply_route.c` line 56: `strstr(cur, "proto static")`
- **Impact**: `strstr` would match "proto statically-set" if kernel route output ever
  contained that string. In practice, Linux only uses exact protocol names from
  `rt_protos`, and "statically" is not a valid proto name — so risk is near zero.
- **Status**: NEGLIGIBLE — theoretical only. Linux kernel outputs exactly "proto static".
- **Test**: `test_validator_edge_cases.py` Section 14 (source pattern check)

---

## Summary: Security Posture

### Confirmed Strong (no action needed)
| ID | Finding |
|----|---------|
| ATK-A-03 | Username injection blocked by safe-id validator |
| ATK-A-05 | `__webd` claim requires kernel-verified UID 900 |
| ATK-B-01/02/03 | Session replay, garbage token, bearer priority: all handled |
| ATK-C-01/02/08/10 | RBAC enforced on all write operations |
| ATK-E-01/02 | Diagnose commands use `execvp()` array + input validator — no shell injection |
| ATK-E-03 | SQL injection blocked by parameterized queries throughout |
| ATK-E-05/08 | JSON + XSS escaping in both C (json_escape) and JS (esc()) |
| ATK-F-01/02/03 | CSRF, clickjacking, HTTPS downgrade: SameSite, X-Frame-Options, HSTS |
| ATK-G-01/02/03/04 | Rate limiting, flood resistance, slowloris survival |
| ATK-H-04 | builtin=yes injection stripped |
| ATK-I-01–06 | IPC protocol: bad magic/version/size/tag all rejected; username verified by kernel |

### Gaps — Known, Accepted
| ID | Gap | Severity | Recommendation |
|----|-----|----------|----------------|
| ATK-B-08 | mgmtd session tags have no expiry TTL | Low | Add 24h expiry per tag |
| ATK-H-01 | Deleting address referenced by firewall policy is allowed (orphan) | Medium | Add pre-delete ref check |
| ATK-J-03 | IPv6 forwarding not filtered by pkt_forward.c | High | Add ip6tables DROP-all or extend kernel hook |
| ATK-J-02 | Init does not set FORWARD DROP; window before mgmtd starts | Medium | Add `iptables -P FORWARD DROP` in init |
| ATK-K-01 | Named address objects silently ignored in iptables rules | High | Resolve address name to CIDR before applying |
| ATK-K-02 | Service objects silently ignored — no port/protocol in iptables | High | Pass protocol+port to build_forward_argv() |
| ATK-K-03 | Boot window: FORWARD ACCEPT before mgmtd sets DROP | Low | Set FORWARD DROP in init (same fix as ATK-J-02) |

### Needs Live Test Coverage
| ID | Description | Script |
|----|-------------|--------|
| ATK-A-04/06/07 | Null byte username, max-length username, wrong Content-Type | test_security_pentest.sh |
| ATK-B-05/06 | Session pool exhaustion (webd 128, mgmtd 16) | test_security_pentest.sh |
| ATK-C-03/04/05/06/09 | Self-escalation, admin-type access, IDOR, profile-in-use | test_security_pentest.sh |
| ATK-D-01–08 | Input boundary: oversized, null, unicode, integer, CIDR, enum case | test_security_pentest.sh |
| ATK-E-01/02/04 | Diagnose injection (live), search filter injection | test_security_pentest.sh |
| ATK-F-05/07 | Large HTTP body, wrong Content-Type | test_security_pentest.sh |
| ATK-G-05/06 | Session exhaustion, rapid create/delete | test_security_pentest.sh |
| ATK-H-02 | Profile in-use protection at HTTP level | test_security_pentest.sh |

---

## Test Scripts

| Script | Type | Requires live server |
|--------|------|---------------------|
| `tests/test_api_live.sh` | HTTP live | Yes |
| `tests/test_security_pentest.sh` | HTTP live (new gaps) | Yes |
| `tests/test_firewall_behavior.sh` | Source + iptables live | Partial (live checks need root) |
| `tests/pentest/sg_pentest` (binary) | IPC live | Yes (root) |
| `tests/test_api_contract.py` | Static source analysis | No |
| `tests/test_security_static.py` | Static security properties | No |
| `tests/test_validator_edge_cases.py` | Validator edge cases | No |
| `tests/test_webui_security_attacks.py` | Static + JS simulation | No |
| `tests/test_webui_fixes.py` | Static regression | No |
