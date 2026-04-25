# Admin Account & Session Lifecycle Flowcharts

## 0. Boot — Auth File Restore & Admin Replay

```
BOOT (init PID 1)
        │
        ├─ Mount /etc/stargazer (persistent partition)
        │
        ├─ Restore auth files from persistent storage:
        │   ├─ /etc/stargazer/shadow → /etc/shadow  (password hashes)
        │   ├─ /etc/stargazer/passwd → /etc/passwd  (user entries)
        │   └─ /etc/stargazer/group  → /etc/group   (group memberships)
        │
        ├─ Ensure stargazer group exists
        │   └─ Restored? → no-op.  First boot? → create stargazer:x:900:
        │
        ├─ Start mgmtd (background)
        │   ├─ sg_db_open()
        │   ├─ mgmtd_seed_defaults()        (first boot: create admin + profiles)
        │   ├─ mgmtd_sync_interfaces()
        │   ├─ mgmtd_init_firewall()
        │   ├─ mgmtd_replay_config()
        │   │   │
        │   │   ├─ For each system_admin in DB:
        │   │   │   │
        │   │   │   ▼
        │   │   │  ┌──────────────────────────┐
        │   │   │  │ apply_config(            │
        │   │   │  │   "system_admin", id)    │
        │   │   │  └────────────┬─────────────┘
        │   │   │               │
        │   │   │               ▼
        │   │   │  ┌──────────────────────────┐
        │   │   │  │ create_system_user(id)   │
        │   │   │  │  ├─ User in /etc/passwd? │
        │   │   │  │  │   YES → add_user_to   │
        │   │   │  │  │         _group(id,     │
        │   │   │  │  │         "stargazer")   │
        │   │   │  │  │         (idempotent)   │
        │   │   │  │  │   NO  → create user   │
        │   │   │  │  │         + group entry  │
        │   │   │  └──┴────────────────────────┘
        │   │   │               │
        │   │   │               ▼
        │   │   │  ┌──────────────────────────┐
        │   │   │  │ user_has_password(id)?   │
        │   │   │  │  YES → SG_OK (logged)    │
        │   │   │  │  NO  → WARN (non-fatal)  │
        │   │   │  │        (first boot, user  │
        │   │   │  │         sets pw at login) │
        │   │   │  └──────────────────────────┘
        │   │   │
        │   │   ├─ system_interface, network_route_static, ...
        │   │   └─ (remaining table types replayed)
        │   │
        │   ├─ socket() + bind() + listen()  ← socket appears = truly ready
        │   ├─ write("ready") → /run/mgmtd-ready FIFO
        │   └─ accept() loop
        │
        ├─ read < /run/mgmtd-ready   (blocks until "ready" or timeout)
        ├─ "Management daemon ready."
        │
        └─ Login loop: setsid -c /sbin/stargazer-login
                │
                ▼
        ┌──────────────────────────┐
        │ login: admin1            │
        │  → auth OK (shadow       │
        │    restored)             │
        │  → exec stargazer-cli   │
        │  → connect mgmtd socket │
        │    (admin1 in stargazer  │
        │     group → OK)         │
        │  → WHOAMI: read-write   │
        └──────────────────────────┘


SHUTDOWN (poweroff / reboot)
        │
        ├─ killall stargazer-mgmtd
        ├─ Save auth files to persistent storage:
        │   ├─ /etc/shadow → /etc/stargazer/shadow
        │   ├─ /etc/passwd → /etc/stargazer/passwd
        │   └─ /etc/group  → /etc/stargazer/group
        ├─ sync
        └─ umount /etc/stargazer
```

---

## 1. Account Creation

```
admin types: configure system admin → edit admin1 → set profile → set password → next
                │
                ▼
        ┌───────────────┐
        │  CFG_APPLY    │
        │  system_admin │
        └───────┬───────┘
                │
                ▼
        ┌───────────────────┐
        │ Profile exists?   │
        │ sg_db_get(        │
        │  system_admin-    │
        │  profile,         │
        │  "read-write")    │
        └───────┬───────────┘
                │
           YES  │  NO → return SG_ERR_PROFILE_NOT_FOUND
                ▼
        ┌───────────────────┐
        │ create_system_user│
        │ ("admin1")        │
        └───────┬───────────┘
                │
                ▼
        ┌───────────────────┐     ┌──────────────────────────┐
        │ User exists in    │ YES │ add_user_to_group(       │
        │ /etc/passwd?      ├────►│   "admin1", "stargazer") │
        └───────┬───────────┘     │ return 0                 │
                │ NO              └──────────────────────────┘
                ▼
        ┌───────────────────┐
        │ Create:           │
        │  /etc/passwd      │
        │  /etc/shadow      │
        │  /etc/group       │
        │  /home/admin1     │
        │ add_user_to_group │
        │  ("stargazer")    │
        └───────┬───────────┘
                │
                ▼
        ┌───────────────────┐
        │ set_password()    │
        │ → /etc/shadow     │
        └───────┬───────────┘
                │
                ▼
        ┌───────────────────┐     NO
        │ user_has_password?├──────────► return SG_ERR_MISSING_ARG
        └───────┬───────────┘            "has no password"
                │ YES
                ▼
        ┌───────────────────┐
        │ session_rev_bump  │
        │ ("admin1")        │
        │ rev: 0 → 1       │
        └───────┬───────────┘
                │
                ▼
          return SG_OK
                │
                ▼
        ┌───────────────┐
        │  CFG_SET       │
        │  system_admin  │
        │  :admin1       │
        └───────┬────────┘
                │
                ▼
        ┌────────────────────┐
        │ sg_db_set:         │
        │  BEGIN             │
        │  DELETE old rows   │
        │  INSERT profile=   │
        │    read-write      │
        │  INSERT enforce-*  │
        │  COMMIT            │
        └───────┬────────────┘
                │
                ▼
        ┌───────────────────┐
        │ type==system_admin│
        │ session_rev_bump  │
        │ ("admin1")        │
        │ rev: 1 → 2       │
        └───────┬───────────┘
                │
                ▼
              DONE
```

---

## 2. Login

```
        ┌──────────────┐
        │ login: admin1│  (stargazer-login shell script)
        └──────┬───────┘
               │
               ▼
        ┌──────────────────┐
        │ normalize to     │
        │ lowercase        │
        │ admin_exists_in  │
        │ _config?         │
        └──────┬───────────┘
               │
          YES  │  NO → "Invalid credentials"
               ▼
        ┌──────────────────┐
        │ auth_is_locked?  │
        └──────┬───────────┘
               │
           NO  │  YES → "Account temporarily locked"
               ▼
        ┌──────────────────┐
        │ stargazer-logind │  (C binary, runs as root)
        │ argv[1]="admin1" │
        └──────┬───────────┘
               │
               ▼
        ┌──────────────────┐
        │ sg_db_open()     │  ← own DB connection
        │ read_password()  │
        │ authenticate()   │
        │  → getspnam()    │
        │  → crypt+compare │
        └──────┬───────────┘
               │
          OK   │  FAIL → "Invalid credentials"
               ▼                    + auth_note_fail()
        ┌──────────────────┐
        │ enforce_password │
        │ _change?         │
        │ (DB: enforce-    │
        │  change-password)│
        └──────┬───────────┘
               │
        ┌──────┴──────┐
        │"enable"     │"disable"
        ▼             ▼
   ┌──────────┐   (skip)
   │ Force pw │       │
   │ change   │       │
   │ prompt   │       │
   └────┬─────┘       │
        │             │
        ▼             ▼
        ┌──────────────────┐
        │ sg_db_close()    │  ← close DB before privilege drop
        └──────┬───────────┘
               │
               ▼
        ┌──────────────────┐
        │ setgid(1001)     │
        │ setuid(1001)     │  ← drop to admin1
        │ setenv(          │
        │  STARGAZER_USER, │
        │  "admin1")       │
        └──────┬───────────┘
               │
               ▼
        ┌──────────────────┐
        │ execl(           │  ← replaces logind process
        │  /sbin/stargazer │
        │  -cli)           │
        └──────┬───────────┘
               │
               ▼
        ┌──────────────────────────────────────────────┐
        │              stargazer-cli                    │
        │  (runs as admin1 uid=1001)                   │
        └──────┬───────────────────────────────────────┘
               │
               ▼
        ┌──────────────────┐
        │ ipc_init("admin1")
        │ cli_term_init()  │
        │ cli_sandbox_     │
        │   install()      │
        └──────┬───────────┘
               │
               ▼
        ┌──────────────────┐
        │ WHOAMI (5 tries) │
        │ connect to       │
        │ mgmtd socket     │
        └──────┬───────────┘
               │
               ▼
        ┌──────────────────────┐
        │ Socket access check: │
        │ /run/stargazer-      │
        │   mgmtd.sock         │
        │ owner: root:stargazer│
        │ perms: srw-rw----    │
        └──────┬───────────────┘
               │
        ┌──────┴───────────────────┐
        │                          │
        ▼                          ▼
  admin1 IN                  admin1 NOT IN
  stargazer group            stargazer group
        │                          │
        ▼                          ▼
  connect() OK             connect() EACCES
        │                    5 retries fail
        ▼                          │
  mgmtd WHOAMI:                    ▼
  sg_db_get(               ┌──────────────┐
   "system_admin",         │ Keep defaults│
   "admin1")               │ profile=     │
        │                  │  read-only   │
        ▼                  │ perms=       │
  extract profile          │  monitor     │
  → "read-write"           └──────┬───────┘
        │                         │
        ▼                         │
  sg_db_get(                      │
   "system_admin-profile",        │
   "read-write")                  │
        │                         │
        ▼                         │
  extract permissions             │
  → "monitor,configure,           │
     admin"                       │
        │                         │
        ▼                         ▼
        ┌──────────────────────────┐
        │ session_rev_start =      │
        │   get_session_rev(user)  │
        │ g_session_rev_start =    │
        │   &session_rev_start     │
        │ cli_set_idle_cb(         │
        │   check_permissions_cb)  │
        └──────────┬───────────────┘
                   │
                   ▼
            ┌─────────────┐
            │ Main loop   │
            │ (readline)  │
            └─────────────┘
```

---

## 3. Main Loop — Command Dispatch + Session Check

```
        ┌─────────────────────┐
        │ cli_readline(       │◄──────────────────────────┐
        │   "stargazer> ")    │                           │
        └────────┬────────────┘                           │
                 │                                        │
                 ▼                                        │
        ┌────────────────────┐                            │
        │ cli_resolve_cmd()  │                            │
        │ (abbreviation      │                            │
        │  expansion)        │                            │
        └────────┬───────────┘                            │
                 │                                        │
                 ▼                                        │
        ┌────────────────────┐                            │
        │ get_session_rev    │                            │
        │ (user)             │                            │
        └────────┬───────────┘                            │
                 │                                        │
                 ▼                                        │
        ┌────────────────────┐     ┌───────────────────┐  │
        │ rev !=             │ YES │ "Session expired"  │  │
        │ session_rev_start? ├────►│  break (exit CLI)  │  │
        └────────┬───────────┘     └───────────────────┘  │
                 │ NO (same rev)                          │
                 ▼                                        │
        ┌────────────────────┐                            │
        │ cmd_dispatch(      │                            │
        │   resolved,        │                            │
        │   permissions)     │                            │
        └────────┬───────────┘                            │
                 │                                        │
                 ▼                                        │
        ┌────────────────────┐                            │
        │ ipc_fetch_debug()  │                            │
        │ (only prints if    │                            │
        │  status==SG_OK)    │                            │
        └────────┬───────────┘                            │
                 │                                        │
                 ▼                                        │
           rc == 0? ──NO──► break (exit CLI)              │
                 │                                        │
                YES                                       │
                 │                                        │
                 └────────────────────────────────────────┘
```

---

## 4. Idle Permission Polling (inside cli_readline)

```
        ┌──────────────────────┐
        │ cli_readline()       │
        │ waiting for keypress │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ ppoll(tty_fd, 5s)    │◄─────────────────┐
        └──────────┬───────────┘                   │
                   │                               │
            ┌──────┴──────┐                        │
            │             │                        │
         TIMEOUT       KEYPRESS                    │
            │             │                        │
            ▼             ▼                        │
   ┌────────────────┐  return to                   │
   │ check_         │  main loop                   │
   │ permissions_cb │  (process                    │
   │ ()             │   input)                     │
   └───────┬────────┘                              │
           │                                       │
           ▼                                       │
   ┌────────────────┐                              │
   │ ipc_send       │                              │
   │ (WHOAMI)       │                              │
   └───────┬────────┘                              │
           │                                       │
           ▼                                       │
   ┌────────────────┐                              │
   │ parse response │                              │
   │ new_perms =    │                              │
   │  "monitor,..." │                              │
   └───────┬────────┘                              │
           │                                       │
           ▼                                       │
   ┌────────────────────┐     ┌──────────────────┐ │
   │ new_perms !=       │ YES │ printf("\r\n     │ │
   │ g_permissions?     ├────►│  Permissions     │ │
   └───────┬────────────┘     │  changed...")    │ │
           │ NO               │ return -1        │ │
           │                  │  → readline      │ │
           ▼                  │    returns NULL   │ │
      return 0                │  → main loop     │ │
           │                  │    exits (kicked) │ │
           │                  └──────────────────┘ │
           └───────────────────────────────────────┘
```

---

## 5. Session Rev Bump Sources (mgmtd)

```
                    ┌───────────────────────────────┐
                    │     IPC request from CLI       │
                    └───────────────┬───────────────┘
                                    │
               ┌────────────────────┼────────────────────┐
               │                    │                    │
               ▼                    ▼                    ▼
        ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
        │  CFG_SET     │     │  CFG_DEL    │     │  CFG_APPLY  │
        └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
               │                    │                    │
               ▼                    ▼                    ▼
        ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
        │ What type?  │     │ What type?  │     │ What type?  │
        └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
               │                    │                    │
     ┌─────────┼─────────┐         │           ┌────────┴────────┐
     │         │         │         │           │                 │
     ▼         ▼         ▼         ▼           ▼                 ▼
  system_  system_   system_   system_     system_           system_
  admin    admin-    password  admin       admin             admin-
           profile   -policy                                 profile
     │         │         │         │           │                 │
     ▼         ▼         ▼         ▼           ▼                 ▼
  bump(X)  bump all  bump all  bump(X)     bump(X)           bump(X)
  target   admins    admins    target      target            (profile
  admin    using     (every    admin       admin              name,
  only     profile X admin)   only        only               not user)
     │         │         │         │           │                 │
     ▼         ▼         ▼         ▼           ▼                 ▼
     └─────────┴─────────┴─────────┴───────────┴─────────────────┘
                                    │
                                    ▼
                         ┌──────────────────┐
                         │                  │
                    ┌────┴────┐        ┌────┴────────┐
                    │ firewall│        │ system_     │
                    │ network │        │ settings    │
                    │ etc.    │        │ etc.        │
                    └────┬────┘        └────┬────────┘
                         │                  │
                         ▼                  ▼
                    NO BUMP            NO BUMP
                    (not permission-   (not permission-
                     related)           related)
```

---

## 6. Selftest Session Rev Handling

```
     admin1: execute diagnose selftest full
                    │
                    ▼
        ┌───────────────────────┐
        │ cmd_dispatch()        │
        │ → cli_diagnose_test   │
        │   _permissions()      │
        └───────────┬───────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │ diag_self_test()      │
        │  • permission checks  │
        │  • SESSION_BUMP       │
        │    "__diag_nobody"    │
        │    (not self, no      │
        │     rev issue)        │
        │  • DEBUG_FETCH check  │
        └───────────┬───────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │ diag_full_test()      │
        └───────────┬───────────┘
                    │
        ┌───────────┴───────────────────────┐
        │                                   │
        ▼                                   ▼
  ┌─────────────────┐            ┌──────────────────────┐
  │ Create temp     │            │ SEC-8: SESSION_BUMP  │
  │ accounts:       │            │ on diag_username()   │
  │ __diag_rw       │            │ (self-bump)          │
  │ __diag_ro       │            │                      │
  │ __diag_upg      │            │ admin1 rev: 2 → 3   │
  │                 │            └──────────────────────┘
  │ CFG_SET on      │
  │ system_admin:   │
  │ __diag_upg      │
  │ (bumps __diag   │
  │  _upg's rev,    │
  │  NOT admin1's)  │
  └─────────────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │ cleanup: delete temp  │
        │ accounts              │
        └───────────┬───────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │ cli_refresh_session() │  ← absorbs self-bump
        │                       │
        │ session_rev_start =   │
        │   get_session_rev     │
        │   ("admin1") → 3     │
        └───────────┬───────────┘
                    │
                    ▼
          return to main loop
                    │
                    ▼
        ┌───────────────────────┐
        │ admin1 types next cmd │
        │ get_session_rev → 3   │
        │ 3 == session_rev      │
        │   _start(3)           │
        │ → OK, no kick ✓      │
        └───────────────────────┘
```

---

## 7. External Change During Interactive Command

```
     admin1: execute diagnose top
                    │
                    ▼
        ┌───────────────────────┐
        │ cmd_dispatch()        │
        │ → enters interactive  │
        │   poll loop           │
        │                       │
        │ (no session rev check │
        │  — only at main loop  │
        │  top)                 │
        │                       │
        │ (no idle poll — only  │
        │  inside cli_readline) │
        └───────────┬───────────┘
                    │
                    │  ◄── admin2 changes admin1's
                    │      profile here
                    │      mgmtd bumps admin1's
                    │      rev: 2 → 4
                    │
                    ▼
        ┌───────────────────────┐
        │ admin1 presses 'q'   │
        │ → cmd_dispatch()     │
        │   returns            │
        └───────────┬──────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │ ipc_fetch_debug()    │
        │ (no rev refresh —    │
        │  selftest-only)      │
        └───────────┬──────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │ Main loop continues  │
        │                      │
        │ admin1 types next cmd│
        │ get_session_rev → 4  │
        │ 4 != session_rev     │
        │   _start(2)          │
        │ → MISMATCH           │
        │ → "Session expired"  │
        │ → kicked ✓           │
        └──────────────────────┘
```

---

## 8. Detection Summary

```
        ┌─────────────────────────────────────────────────────────┐
        │              Permission change occurs                    │
        │         (mgmtd bumps target admin's rev)                │
        └────────────────────────┬────────────────────────────────┘
                                 │
                ┌────────────────┼────────────────┐
                │                │                │
                ▼                ▼                ▼
        ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐
        │ Admin is     │ │ Admin is     │ │ Admin is in      │
        │ idle at      │ │ about to     │ │ interactive cmd   │
        │ prompt       │ │ type command │ │ (diagnose top)   │
        └──────┬───────┘ └──────┬───────┘ └──────┬───────────┘
               │                │                │
               ▼                ▼                ▼
        ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐
        │ Idle poll    │ │ Session rev  │ │ No detection     │
        │ fires ≤5s    │ │ check before │ │ until command    │
        │              │ │ dispatch     │ │ exits            │
        │ WHOAMI →     │ │              │ │                  │
        │ perms differ │ │ rev mismatch │ │ Then: session    │
        │              │ │              │ │ rev check on     │
        │ KICKED       │ │ KICKED       │ │ next command     │
        │ (≤5s delay)  │ │ (immediate)  │ │                  │
        └──────────────┘ └──────────────┘ │ KICKED           │
                                          │ (after exit+cmd) │
                                          └──────────────────┘

        ┌─────────────────────────────────────────────────────────┐
        │              Exception: Selftest                         │
        │                                                          │
        │  SEC-8 bumps own rev → cli_refresh_session() absorbs    │
        │  → no false kick ✓                                       │
        └─────────────────────────────────────────────────────────┘

        ┌─────────────────────────────────────────────────────────┐
        │              Non-permission config change                │
        │                                                          │
        │  firewall/network/settings → mgmtd does NOT bump rev   │
        │  → no kick (correct) ✓                                   │
        └─────────────────────────────────────────────────────────┘
```
