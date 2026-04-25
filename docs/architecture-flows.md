# Stargazer NGFW — Architecture Flows

Complete system flows traced from codebase. All diagrams in Mermaid format.

---

## 1. Boot Flow

```mermaid
flowchart TD
    KERNEL[Kernel boot] --> INIT["/sbin/init (PID 1)<br/>src/userspace/init"]

    subgraph INIT_PHASE["Init Phase"]
        INIT --> MOUNT["Mount filesystems<br/>proc, sysfs, devtmpfs, tmpfs"]
        MOUNT --> STORAGE{"Detect persistent<br/>storage?"}
        STORAGE -->|"eMMC p5 or<br/>QEMU vdb"| FSCK["e2fsck / format<br/>if blank"]
        STORAGE -->|"Not found"| TMPFS_FALLBACK["tmpfs fallback<br/>/etc/stargazer"]
        FSCK --> MOUNT_DATA["Mount /etc/stargazer<br/>(config + DB)"]
        TMPFS_FALLBACK --> MOUNT_DATA
        MOUNT_DATA --> LOGS_PART{"Detect logs<br/>partition?"}
        LOGS_PART -->|"eMMC p6 or<br/>QEMU vdc"| MOUNT_LOGS["Mount /etc/stargazer/logs"]
        LOGS_PART -->|"Not found"| SKIP_LOGS["Skip logs partition"]
        MOUNT_LOGS --> AUTH_RESTORE
        SKIP_LOGS --> AUTH_RESTORE
        AUTH_RESTORE["Restore /etc/shadow,<br/>/etc/passwd, /etc/group<br/>from persistent storage"]
        AUTH_RESTORE --> CONSOLE["Detect console device<br/>from kernel cmdline"]
        CONSOLE --> SYSACCTS["Create stargazer group<br/>Create __webd account"]
        SYSACCTS --> INPUT_DROP["iptables -P INPUT DROP<br/>(before any iface up)"]
        INPUT_DROP --> INITD["/etc/init.d/stargazer start<br/>Load kernel modules<br/>Apply sysctl"]
    end

    subgraph MGMTD_START["mgmtd Startup"]
        INITD --> FIFO["Create FIFO<br/>/run/mgmtd-ready"]
        FIFO --> FORK_MGMTD["Fork restart loop<br/>spawn stargazer-mgmtd"]
        FORK_MGMTD --> WAIT_FIFO["Init blocks on FIFO<br/>(30s timeout)"]
        FORK_MGMTD --> MGMTD_MAIN["mgmtd main()"]
        MGMTD_MAIN --> SIGNALS["Setup signal handlers<br/>SIGPIPE=IGN, SIGCHLD"]
        SIGNALS --> DB_OPEN["sg_db_open()<br/>/etc/stargazer/stargazer.db"]
        DB_OPEN --> INTEGRITY{"Boot integrity<br/>check?"}
        INTEGRITY -->|BOOT_FIRST| SEED["mgmtd_seed_defaults()<br/>Admin, profiles, policies,<br/>default-deny, DNS, NTP"]
        INTEGRITY -->|BOOT_NORMAL| RECONCILE
        INTEGRITY -->|CORRUPTED<br/>COMPROMISED| ABORT["Refuse to boot<br/>Log critical error"]
        SEED --> RECONCILE["mgmtd_reconcile_config()<br/>Backfill missing keys,<br/>purge stale types"]
        RECONCILE --> SYNC_IFACE["mgmtd_sync_interfaces()<br/>Scan /sys/class/net<br/>Create/protect NIC entries"]
        SYNC_IFACE --> FW_INIT["mgmtd_init_firewall()"]
    end

    subgraph FW_INIT_DETAIL["Firewall Init"]
        FW_INIT --> INPUT_POLICY["INPUT: policy DROP<br/>+ lo ACCEPT<br/>+ ESTABLISHED,RELATED"]
        INPUT_POLICY --> FWD_POLICY["FORWARD: policy DROP<br/>+ ESTABLISHED,RELATED"]
        FWD_POLICY --> TFTP_CT["Load nf_conntrack_tftp<br/>CT helper on OUTPUT udp/69"]
    end

    subgraph CONFIG_REPLAY["Config Replay"]
        TFTP_CT --> BACKFILL_SEQ["Backfill sequence numbers<br/>for firewall/NAT"]
        BACKFILL_SEQ --> REPLAY_SINGLE["Replay single types:<br/>settings, password-policy,<br/>DNS, NTP"]
        REPLAY_SINGLE --> REPLAY_TABLE["Replay table types:<br/>admin-profile, admin,<br/>interface, routes"]
        REPLAY_TABLE --> REPLAY_FW["rebuild_forward_chain()<br/>Atomic iptables-restore"]
        REPLAY_FW --> REPLAY_NAT["rebuild_nat_chains()<br/>Atomic iptables-restore"]
        REPLAY_NAT --> REPLAY_DHCP["Replay DHCP servers<br/>Start udhcpd instances"]
    end

    subgraph SERVICES_UP["Services Ready"]
        REPLAY_DHCP --> SOCKET["Create listen socket<br/>/run/stargazer-mgmtd.sock"]
        SOCKET --> START_WEBD["supervisor_start(webd)<br/>spawn stargazer-webd"]
        START_WEBD --> SIGNAL_READY["Write 'ready' to FIFO"]
        SIGNAL_READY --> ACCEPT_LOOP["Enter accept loop<br/>(poll 5s timeout)"]
    end

    WAIT_FIFO -->|"ready signal"| LOGIN_LOOP

    subgraph WEBD_BOOT["webd Startup"]
        START_WEBD --> WEBD_PRIV["Drop privileges<br/>UID __webd (900)"]
        WEBD_PRIV --> WEBD_BIND["Bind HTTP/HTTPS<br/>per interface allowaccess"]
        WEBD_BIND --> WEBD_POOL["Spawn thread pool"]
        WEBD_POOL --> WEBD_SANDBOX["Install seccomp sandbox"]
        WEBD_SANDBOX --> WEBD_POLL["Enter Mongoose poll loop"]
    end

    subgraph LOGIN_PHASE["Login Phase"]
        LOGIN_LOOP["Init: infinite login loop<br/>setsid -c stargazer-logind"]
        LOGIN_LOOP --> LOGIND["logind: cache user data<br/>Install seccomp sandbox"]
        LOGIND --> PROMPT["Prompt username/password"]
        PROMPT --> AUTH_IPC["IPC: SG_CMD_AUTH_LOGIN<br/>to mgmtd"]
        AUTH_IPC --> AUTH_OK{"Auth<br/>success?"}
        AUTH_OK -->|No| PROMPT
        AUTH_OK -->|Yes| FORCE_PW{"Force password<br/>change?"}
        FORCE_PW -->|Yes| CHANGE_PW["Prompt new password<br/>IPC: AUTH_CHANGE_PW"]
        CHANGE_PW --> DROP_PRIV
        FORCE_PW -->|No| DROP_PRIV["Drop to user UID/GID"]
        DROP_PRIV --> EXEC_CLI["exec /sbin/stargazer-cli"]
        EXEC_CLI --> CLI_INIT["CLI: sandbox, session tag,<br/>register commands, REPL"]
    end
```

---

## 2. Config Change Flow (CLI)

```mermaid
flowchart TD
    subgraph CLI_SIDE["CLI (stargazer-cli)"]
        USER_CMD["User: configure system interface"]
        USER_CMD --> ENTER_CTX["cli_configure.c: context_entry()<br/>IPC: CFG_GET system_interface:lan0"]
        ENTER_CTX --> LOAD_KV["Parse response into<br/>key=value buffer"]
        LOAD_KV --> SET_CMD["User: set ip 10.0.0.1/24"]
        SET_CMD --> CLIENT_VALIDATE["sg_reg_validate_value()<br/>Client-side format check"]
        CLIENT_VALIDATE -->|Invalid| SHOW_ERR["Print error, stay in context"]
        CLIENT_VALIDATE -->|Valid| BUFFER["kv_set(): buffer change<br/>in-memory"]
        BUFFER --> MORE_SETS{"More set<br/>commands?"}
        MORE_SETS -->|Yes| SET_CMD
        MORE_SETS -->|No| END_CMD["User: end"]
        END_CMD --> APPLY_TEST["IPC: CFG_APPLY<br/>payload: type\\nid\\nkey=val..."]
        APPLY_TEST --> APPLY_RESP{"Apply<br/>response?"}
        APPLY_RESP -->|Error| STAY_CTX["Print error<br/>Stay in context"]
        APPLY_RESP -->|OK| PERSIST["IPC: CFG_SET<br/>payload: type:id\\nkey=val..."]
        PERSIST --> SET_RESP{"SET<br/>response?"}
        SET_RESP -->|Error| STAY_CTX2["Print error"]
        SET_RESP -->|OK| EXIT_CTX["Exit context<br/>Print success"]
    end
```

---

## 3. Config Change Flow (Web UI)

```mermaid
flowchart TD
    subgraph WEBUI["Browser"]
        FORM["User fills form<br/>clicks Save"]
        FORM --> HTTP["POST /api/config/system_interface<br/>JSON body"]
    end

    subgraph WEBD["webd (stargazer-webd)"]
        HTTP --> DISPATCH["webd_api_dispatch()<br/>Parse URL segments"]
        DISPATCH --> SESSION_CHECK["Validate session cookie"]
        SESSION_CHECK --> JSON_TO_KV["json_body_to_kv()<br/>JSON → key=value"]
        JSON_TO_KV --> ENQUEUE["webd_pool_enqueue()<br/>Queue work item"]

        subgraph WORKER["Worker Thread"]
            ENQUEUE --> FLOW_TYPE{"Flow type?"}
            FLOW_TYPE -->|CREATE| DUP_CHECK["CFG_GET: entry exists?"]
            DUP_CHECK -->|Yes| HTTP_409["409 Conflict"]
            DUP_CHECK -->|No| APPLY_IPC
            FLOW_TYPE -->|UPDATE| GET_CURRENT["CFG_GET: fetch current"]
            GET_CURRENT --> MERGE["Merge old + new values"]
            MERGE --> APPLY_IPC
            FLOW_TYPE -->|DELETE| DEL_IPC["IPC: CFG_DEL"]
            FLOW_TYPE -->|MOVE| INSERT_IPC["IPC: CFG_INSERT"]
            APPLY_IPC["IPC: CFG_APPLY<br/>(validate/test)"]
            APPLY_IPC --> APPLY_OK{"Apply OK?"}
            APPLY_OK -->|No| HTTP_ERR["Return error JSON"]
            APPLY_OK -->|Yes| SET_IPC["IPC: CFG_SET<br/>(persist + apply)"]
            SET_IPC --> SET_OK{"SET OK?"}
            SET_OK -->|No| HTTP_ERR
            SET_OK -->|Yes| HTTP_200["200 OK + JSON"]
        end
    end

    subgraph MGMTD_SIDE["mgmtd"]
        SET_IPC --> MGMTD_HANDLER["handle_request_dispatch()"]
    end
```

---

## 4. mgmtd CFG_SET Handler (Central)

```mermaid
flowchart TD
    REQ["CFG_SET request<br/>payload: type:id\\nkey=val..."] --> PARSE["Parse section → type, id"]
    PARSE --> PERM{"User has<br/>permission?"}
    PERM -->|No| DENY["SG_ERR_PERM_DENIED"]
    PERM -->|Yes| VALIDATE_FIELDS["validate_cfg_data()<br/>Check required fields,<br/>value formats"]
    VALIDATE_FIELDS -->|Invalid| ERR_VAL["Return validation error"]
    VALIDATE_FIELDS -->|Valid| GET_EXISTING["sg_db_get(type, id)<br/>Fetch old entry"]
    GET_EXISTING --> BUILTIN{"Old entry is<br/>builtin FW/NAT?"}
    BUILTIN -->|Yes| ERR_BUILTIN["SG_ERR_BUILTIN<br/>Cannot modify"]
    BUILTIN -->|No| STRIP["Strip builtin=, password=,<br/>password-hash= from payload"]
    STRIP --> BACKFILL["Backfill default values<br/>for missing keys"]
    BACKFILL --> IS_FW_NAT{"Type is<br/>firewall_policy<br/>or network_nat?"}

    subgraph FW_NAT_PATH["Firewall/NAT: Persist-First"]
        IS_FW_NAT -->|Yes| FN_VALIDATE["validate_firewall_policy()<br/>or validate_nat()"]
        FN_VALIDATE -->|Error| FN_ERR["Return error"]
        FN_VALIDATE -->|OK| SEQ_ASSIGN{"New entry?"}
        SEQ_ASSIGN -->|Yes| AUTO_SEQ["seq_auto_assign()<br/>sequence = max+1"]
        SEQ_ASSIGN -->|No| DB_WRITE
        AUTO_SEQ --> DB_WRITE["sg_db_set()<br/>Write to DB FIRST"]
        DB_WRITE -->|Error| DB_ERR["Return IO error"]
        DB_WRITE -->|OK| REBUILD["rebuild_forward_chain()<br/>or rebuild_nat_chains()"]
        REBUILD -->|Error| ROLLBACK["Rollback DB:<br/>delete if new,<br/>restore if update"]
        ROLLBACK --> REBUILD_ERR["Return error"]
        REBUILD -->|OK| FN_OK["Send 'Config saved'"]
    end

    subgraph OTHER_PATH["Other Types: Apply-First"]
        IS_FW_NAT -->|No| APPLY["apply_config()<br/>→ type-specific handler<br/>(route, iface, dns, dhcp...)"]
        APPLY -->|Error| APPLY_ERR["Return error<br/>(DB unchanged)"]
        APPLY -->|OK| DB_PERSIST["sg_db_set()<br/>Persist to DB"]
        DB_PERSIST --> RESTORE_PW["Restore password-hash<br/>(if system_admin)"]
        RESTORE_PW --> OTHER_OK["Send 'Config saved'"]
    end
```

---

## 5. CFG_DEL Handler

```mermaid
flowchart TD
    DEL_REQ["CFG_DEL request<br/>payload: type:id"] --> DEL_PARSE["Parse type, id"]
    DEL_PARSE --> DEL_PERM{"Permission?"}
    DEL_PERM -->|No| DEL_DENY["PERM_DENIED"]
    DEL_PERM -->|Yes| DEL_EXISTS{"Entry<br/>exists?"}
    DEL_EXISTS -->|No| DEL_NOT_FOUND["ENTRY_NOT_FOUND"]
    DEL_EXISTS -->|Yes| DEL_BUILTIN{"Builtin?"}
    DEL_BUILTIN -->|Yes| DEL_BUILTIN_ERR["Cannot delete builtin"]
    DEL_BUILTIN -->|No| DEL_REFCHECK{"Referenced by<br/>other config?"}
    DEL_REFCHECK -->|Yes| DEL_IN_USE["SG_ERR_IN_USE"]
    DEL_REFCHECK -->|No| DEL_UNAPPLY{"Type-specific<br/>cleanup?"}
    DEL_UNAPPLY -->|route| DEL_ROUTE["ip route del"]
    DEL_UNAPPLY -->|dhcp| DEL_DHCP["unapply_dhcp()<br/>Stop udhcpd, rm firewall rule"]
    DEL_UNAPPLY -->|fw/nat| DEL_SKIP["No per-rule unapply<br/>(rebuild handles)"]
    DEL_UNAPPLY -->|other| DEL_SKIP
    DEL_ROUTE --> DEL_DB
    DEL_DHCP --> DEL_DB
    DEL_SKIP --> DEL_DB["sg_db_del()"]
    DEL_DB --> DEL_IS_FW{"firewall_policy<br/>or network_nat?"}
    DEL_IS_FW -->|Yes| DEL_REBUILD["rebuild_forward_chain()<br/>or rebuild_nat_chains()"]
    DEL_IS_FW -->|No| DEL_DONE
    DEL_REBUILD --> DEL_DONE["Send 'Deleted'"]
```

---

## 6. Packet Processing Flow

```mermaid
flowchart TD
    PKT_IN["Packet arrives<br/>on interface"]

    subgraph PREROUTING["PREROUTING (nat table)"]
        PKT_IN --> DNAT_CHECK{"DNAT rules<br/>match?"}
        DNAT_CHECK -->|Yes| DNAT_APPLY["Rewrite dest IP/port<br/>-j DNAT --to-destination"]
        DNAT_CHECK -->|No| NO_DNAT["Pass through"]
        DNAT_APPLY --> ROUTING
        NO_DNAT --> ROUTING
    end

    ROUTING{"Routing decision:<br/>dest = local IP?"}
    ROUTING -->|"Yes (to firewall)"| INPUT_CHAIN
    ROUTING -->|"No (forward)"| FORWARD_CHAIN

    subgraph INPUT_CHAIN["INPUT chain (filter)"]
        INPUT_POLICY["Policy: DROP"]
        INPUT_POLICY --> IN_LO{"Loopback?"}
        IN_LO -->|Yes| IN_ACCEPT_LO["ACCEPT"]
        IN_LO -->|No| IN_EST{"ESTABLISHED<br/>RELATED?"}
        IN_EST -->|Yes| IN_ACCEPT_EST["ACCEPT"]
        IN_EST -->|No| IN_ALLOW{"Interface<br/>allowaccess<br/>chain?"}
        IN_ALLOW -->|Match| IN_ACCEPT_SVC["ACCEPT<br/>(ping/ssh/http/https)"]
        IN_ALLOW -->|No match| IN_DHCP{"DHCP server<br/>rule? (udp/67)"}
        IN_DHCP -->|Yes| IN_ACCEPT_DHCP["ACCEPT"]
        IN_DHCP -->|No| IN_DROP["DROP<br/>(policy)"]
    end

    subgraph FORWARD_CHAIN["FORWARD chain (filter)"]
        FWD_POLICY["Policy: DROP"]
        FWD_POLICY --> FWD_EST{"ESTABLISHED<br/>RELATED?"}
        FWD_EST -->|Yes| FWD_ACCEPT_EST["ACCEPT"]
        FWD_EST -->|No| FWD_RULES{"Firewall policy<br/>rules (by sequence)"}
        FWD_RULES -->|Match ACCEPT| FWD_ACCEPT["ACCEPT"]
        FWD_RULES -->|Match DROP/DENY| FWD_DROP_RULE["DROP"]
        FWD_RULES -->|No match| FWD_DROP["DROP<br/>(policy)"]
    end

    subgraph PKT_FWD_MOD["pkt_forward.ko<br/>(NF_INET_FORWARD)"]
        FWD_ACCEPT --> MOD_CHECK{"Valid IPv4<br/>header?"}
        MOD_CHECK -->|Yes| MOD_ACCEPT["NF_ACCEPT<br/>pkts_forwarded++"]
        MOD_CHECK -->|No| MOD_DROP["NF_DROP<br/>pkts_dropped++"]
    end

    subgraph POSTROUTING["POSTROUTING (nat table)"]
        MOD_ACCEPT --> SNAT_CHECK{"SNAT rules<br/>match?"}
        SNAT_CHECK -->|Yes| SNAT_APPLY["Rewrite src IP<br/>-j MASQUERADE"]
        SNAT_CHECK -->|No| NO_SNAT["Pass through"]
        SNAT_APPLY --> PKT_OUT
        NO_SNAT --> PKT_OUT
    end

    PKT_OUT["Packet sent out<br/>on interface"]
```

---

## 7. Firewall Policy Rebuild Flow

```mermaid
flowchart TD
    TRIGGER["Trigger: CFG_SET, CFG_DEL,<br/>CFG_INSERT, or boot replay"]
    TRIGGER --> INIT_BUF["dbuf_init(4096)<br/>Append: *filter\\n"]
    INIT_BUF --> EST_RULE["Append: -A FORWARD<br/>-m conntrack --ctstate<br/>ESTABLISHED,RELATED -j ACCEPT"]
    EST_RULE --> READ_DB["sg_db_list_ordered()<br/>All entries by sequence DESC"]
    READ_DB --> LOOP{"Next<br/>entry?"}
    LOOP -->|None left| COMMIT["Append: COMMIT\\n"]
    LOOP -->|Entry| GET_DATA["sg_db_get() → extract fields:<br/>srcintf, dstintf, srcaddr,<br/>dstaddr, action, status"]
    GET_DATA --> DISABLED{"status =<br/>disable?"}
    DISABLED -->|Yes| LOOP
    DISABLED -->|No| BUILD_RULE["Build: -A FORWARD<br/>[-i srcintf] [-o dstintf]<br/>[-s srcaddr] [-d dstaddr]<br/>-j ACCEPT|DROP"]
    BUILD_RULE --> LOOP

    COMMIT --> FLUSH["iptables -F FORWARD<br/>(chain policy DROP<br/>catches all traffic)"]
    FLUSH --> RESTORE["pipe buf → iptables-restore<br/>--noflush"]
    RESTORE --> RESULT{"exit code?"}
    RESULT -->|0| SUCCESS["Return OK<br/>N rules loaded"]
    RESULT -->|!=0| RECOVERY["flush_forward_chain()<br/>Restore ESTABLISHED,RELATED<br/>Return error"]
```

---

## 8. NAT Rebuild Flow

```mermaid
flowchart TD
    NAT_TRIGGER["Trigger: CFG_SET, CFG_DEL,<br/>CFG_INSERT, or boot replay"]
    NAT_TRIGGER --> NAT_INIT["dbuf_init(4096)<br/>Append: *nat\\n"]
    NAT_INIT --> NAT_READ["sg_db_list_ordered()<br/>All entries by sequence DESC"]
    NAT_READ --> NAT_LOOP{"Next<br/>entry?"}
    NAT_LOOP -->|None left| NAT_COMMIT["Append: COMMIT\\n"]
    NAT_LOOP -->|Entry| NAT_GET["sg_db_get() → extract all fields"]
    NAT_GET --> NAT_DISABLED{"status =<br/>disable?"}
    NAT_DISABLED -->|Yes| NAT_LOOP
    NAT_DISABLED -->|No| NAT_TYPE{"type?"}

    subgraph SNAT_GEN["SNAT Generation"]
        NAT_TYPE -->|snat| SNAT_CHECK{"dstintf is<br/>real iface?"}
        SNAT_CHECK -->|No| NAT_LOOP
        SNAT_CHECK -->|Yes| SNAT_BUILD["-A POSTROUTING<br/>[-s srcaddr] [-d dstaddr]<br/>-o dstintf -j MASQUERADE"]
        SNAT_BUILD --> NAT_LOOP
    end

    subgraph DNAT_GEN["DNAT Generation"]
        NAT_TYPE -->|dnat| DNAT_CHECK{"mapped-ip<br/>set?"}
        DNAT_CHECK -->|No| NAT_LOOP
        DNAT_CHECK -->|Yes| DNAT_PROTO{"protocol?"}
        DNAT_PROTO -->|"tcp or udp"| DNAT_SINGLE["emit_dnat_rule(proto)<br/>1 rule"]
        DNAT_PROTO -->|"tcp+udp"| DNAT_DUAL["emit_dnat_rule(tcp)<br/>emit_dnat_rule(udp)<br/>2 rules"]
        DNAT_PROTO -->|"all"| DNAT_ALL["emit_dnat_rule(NULL)<br/>No -p flag, 1 rule"]
        DNAT_SINGLE --> NAT_LOOP
        DNAT_DUAL --> NAT_LOOP
        DNAT_ALL --> NAT_LOOP
    end

    NAT_COMMIT --> NAT_FLUSH["flush_nat_rules()<br/>-F PREROUTING<br/>-F POSTROUTING"]
    NAT_FLUSH --> NAT_RESTORE["pipe buf → iptables-restore<br/>--noflush"]
    NAT_RESTORE --> NAT_RESULT{"exit code?"}
    NAT_RESULT -->|0| NAT_OK["Return OK"]
    NAT_RESULT -->|!=0| NAT_FAIL["Return error<br/>(no recovery)"]
```

---

## 9. Login & Authentication Flow

```mermaid
flowchart TD
    subgraph LOGIND["stargazer-logind"]
        INIT_L["Cache user data (getpwnam)<br/>Open /dev/console"]
        INIT_L --> SANDBOX_L["Install seccomp sandbox<br/>(block open, fork, exec)"]
        SANDBOX_L --> PROMPT_USER["Prompt: Login:"]
        PROMPT_USER --> PROMPT_PASS["Prompt: Password:<br/>(echo disabled)"]
        PROMPT_PASS --> IPC_LOGIN["IPC: SG_CMD_AUTH_LOGIN<br/>payload: username\\npassword"]
    end

    subgraph MGMTD_AUTH["mgmtd: handle_auth_login()"]
        IPC_LOGIN --> CALLER_CHECK{"Caller is<br/>root or __webd?"}
        CALLER_CHECK -->|No| AUTH_DENY["SG_ERR_PERM_DENIED"]
        CALLER_CHECK -->|Yes| PARSE_CREDS["Parse username, password"]
        PARSE_CREDS --> LOCKOUT_CHECK{"Account<br/>locked out?"}
        LOCKOUT_CHECK -->|"Yes (time<br/>not expired)"| DUMMY_CRYPT["crypt() on dummy hash<br/>(timing defense)"]
        DUMMY_CRYPT --> AUTH_FAIL_GENERIC["'Invalid credentials'"]
        LOCKOUT_CHECK -->|"No or<br/>expired"| GET_SHADOW["getspnam(username)"]
        GET_SHADOW --> DO_CRYPT["crypt(password, hash)"]
        DO_CRYPT --> COMPARE{"Hash<br/>matches?"}
        COMPARE -->|No| INC_FAIL["Increment fail counter"]
        INC_FAIL --> THRESHOLD{"Fails >=<br/>5?"}
        THRESHOLD -->|Yes| SET_LOCKOUT["Set lockout<br/>duration = 2^rounds * 120s<br/>(max 3600s)"]
        SET_LOCKOUT --> AUTH_FAIL_GENERIC
        THRESHOLD -->|No| AUTH_FAIL_GENERIC
        COMPARE -->|Yes| ACCT_LOCKED{"Shadow has<br/>! or * prefix?"}
        ACCT_LOCKED -->|Yes| AUTH_LOCKED["'Account is locked'"]
        ACCT_LOCKED -->|No| GHOST_CHECK{"Admin exists<br/>in DB?"}
        GHOST_CHECK -->|No| AUTH_GHOST["Reject ghost account"]
        GHOST_CHECK -->|Yes| CLEAR_LOCKOUT["Clear lockout state"]
        CLEAR_LOCKOUT --> CHECK_ENFORCE{"enforce-change<br/>-password?"}
        CHECK_ENFORCE --> CHECK_POLICY{"Password meets<br/>current policy?"}
        CHECK_POLICY --> AUTH_OK["SG_OK<br/>enforce_change=0|1<br/>policy_mismatch=0|1"]
    end

    subgraph POST_AUTH["Post-Authentication"]
        AUTH_OK --> FORCE{"enforce_change=1<br/>or policy_mismatch=1?"}
        FORCE -->|Yes| NEW_PW["Prompt new password"]
        NEW_PW --> IPC_CHANGE["IPC: AUTH_CHANGE_PW"]
        IPC_CHANGE --> POLICY_VAL{"Meets<br/>policy?"}
        POLICY_VAL -->|No| NEW_PW
        POLICY_VAL -->|Yes| LOGIN_OK
        FORCE -->|No| LOGIN_OK["IPC: AUTH_LOGIN_OK<br/>(audit log)"]
        LOGIN_OK --> DROP_PRIV["setgid() + setuid()<br/>Set HOME, SHELL, TMOUT"]
        DROP_PRIV --> EXEC["exec /sbin/stargazer-cli"]
    end

    subgraph CLI_INIT["CLI Initialization"]
        EXEC --> CLI_SANDBOX["Install seccomp sandbox"]
        CLI_SANDBOX --> SESSION_TAG["IPC: SESSION_TAG_NEW<br/>Get 64-bit random tag"]
        SESSION_TAG --> WHOAMI["IPC: WHOAMI<br/>Get profile + permissions"]
        WHOAMI --> REGISTER["Register commands<br/>(filtered by permissions)"]
        REGISTER --> REPL["Enter REPL loop<br/>stargazer> "]
    end
```

---

## 10. DHCP Server Lifecycle

```mermaid
flowchart TD
    CREATE["CFG_SET network_dhcp-server:pool1<br/>interface, start-ip, end-ip,<br/>netmask, gateway, dns, lease"]
    CREATE --> APPLY_DHCP["apply_dhcp()"]
    APPLY_DHCP --> VALIDATE_DHCP["Validate fields:<br/>IPs, interface exists,<br/>no DHCP client conflict"]
    VALIDATE_DHCP -->|Error| DHCP_ERR["Return error"]
    VALIDATE_DHCP -->|OK| WRITE_CONF["Write /var/run/<br/>udhcpd-pool1.conf"]
    WRITE_CONF --> FW_RULE["iptables -I INPUT<br/>-i iface -p udp<br/>--dport 67 -j ACCEPT"]
    FW_RULE --> START_DAEMON["supervisor_start()<br/>udhcpd -f conf"]
    START_DAEMON --> RUNNING["udhcpd running<br/>(supervised, auto-restart)"]

    DELETE["CFG_DEL network_dhcp-server:pool1"]
    DELETE --> UNAPPLY["unapply_dhcp()"]
    UNAPPLY --> STOP_DAEMON["supervisor_stop()<br/>SIGTERM → 3s → SIGKILL"]
    STOP_DAEMON --> RM_FW["iptables -D INPUT<br/>-i iface -p udp --dport 67"]
    RM_FW --> RM_FILES["Delete conf + leases files"]
```

---

## 11. Interface Apply Flow

```mermaid
flowchart TD
    IFACE_SET["CFG_SET system_interface:lan0<br/>mode, ip, status, mtu, allowaccess"]
    IFACE_SET --> IFACE_VALIDATE["Validate: mode, IP format,<br/>MTU range, iface exists,<br/>DHCP conflict check"]
    IFACE_VALIDATE -->|Error| IFACE_ERR["Return error"]
    IFACE_VALIDATE -->|OK| STOP_DHCPC["dhcpc_stop()<br/>(always, clean slate)"]
    STOP_DHCPC --> LINK_STATE{"status?"}
    LINK_STATE -->|up| LINK_UP["ip link set iface up"]
    LINK_STATE -->|down| LINK_DOWN["ip link set iface down"]
    LINK_UP --> MODE_CHECK{"mode?"}
    LINK_DOWN --> MODE_CHECK
    MODE_CHECK -->|static| FLUSH_IP["ip addr flush dev iface"]
    FLUSH_IP --> HAS_IP{"IP set and<br/>not sentinel?"}
    HAS_IP -->|Yes| ADD_IP["ip addr add IP dev iface"]
    HAS_IP -->|No| SET_MTU
    ADD_IP --> SET_MTU
    MODE_CHECK -->|dhcp| START_DHCPC["dhcpc_start()<br/>supervisor: udhcpc -f -i iface"]
    START_DHCPC --> SET_MTU{"MTU set?"}
    SET_MTU -->|Yes| APPLY_MTU["ip link set iface mtu N"]
    SET_MTU -->|No| ALLOWACCESS
    APPLY_MTU --> ALLOWACCESS{"allowaccess<br/>set?"}
    ALLOWACCESS -->|Yes| APPLY_ACCESS["Create chain SG_IN_iface<br/>Per-service rules:<br/>ping/ssh/https/http/snmp<br/>Default: DROP"]
    ALLOWACCESS -->|No| IFACE_DONE["Done"]
    APPLY_ACCESS --> IFACE_DONE
```

---

## 12. Codebase Review — Issues & Recommendations

### Critical (Fix before release)

| # | Issue | File:Line | Description |
|---|-------|-----------|-------------|
| 1 | DHCP race condition | `mgmtd_apply_iface.c:288` + `mgmtd_apply_dhcp.c:299` | `dhcpc_stop()` is async — if interface transitions DHCP server → client, udhcpd may still hold the port |
| 2 | Allowaccess chain leak | `mgmtd_apply_iface.c:60-150` | `SG_IN_<iface>` chain created but never deleted with `iptables -X` on CFG_DEL |
| 3 | DHCP FW rule orphan on crash | `mgmtd_apply_dhcp.c:145-147` | If udhcpd crashes and conf file is missing, `iptables -D INPUT -p udp --dport 67` never runs |

### High

| # | Issue | File:Line | Description |
|---|-------|-----------|-------------|
| 4 | Route gateway not validated | `mgmtd_apply_route.c:54-62` | `ip route replace` succeeds even if gateway is unreachable |
| 5 | webd trusted for all users | `stargazer-mgmtd.c:4878` | Compromised webd can inject any username in IPC requests |
| 6 | Chain name truncation | `mgmtd_apply_iface.c:65` | `SG_IN_<iface>` can exceed 31-char iptables limit |

### Medium

| # | Issue | File:Line | Description |
|---|-------|-----------|-------------|
| 7 | No CSRF tokens on POST | `webd_api.c:43` | SameSite=Strict not set on all responses |
| 8 | getrandom() unchecked | `webd_session.c:35` | Return -1 → uninitialized token |
| 9 | query_param unbounded malloc | `webd_api.c:138` | DoS via large query params |
| 10 | Supervisor restart race | `stargazer-mgmtd.c:895` | DB condition can change between SIGCHLD reap and restart check |
| 11 | Config rollback not implemented | `stargazer_ipc.h:500` | COMMIT/REVISIONS/ROLLBACK are stubs |
| 12 | extract_val truncation silent | `stargazer-mgmtd.c:2454` | Truncated values used without error |
| 13 | flush_* uses fprintf not mgmt_log | `stargazer-mgmtd.c:392,403,415` | Inconsistent logging |
| 14 | DEBUG_STATE_FILE in /tmp | `stargazer-mgmtd.c:67` | World-writable path for debug flags |

### Medium (cont.)

| # | Issue | File:Line | Description |
|---|-------|-----------|-------------|
| 15 | Server-side ref existence check missing | `stargazer-mgmtd.c` CFG_SET | `ref-or:` and `ref-iface:` fields only validate **format** server-side, not that the referenced object exists in DB. CLI checks via IPC (`cli_configure.c:617`), but Web API / raw IPC can create entries referencing nonexistent objects (e.g. `srcaddr=nonexistent_address`) |
| 16 | NAT srcaddr/dstaddr not using address objects | `sg_validate.c:66-67` | NAT uses `cidr-or:any,all` (raw CIDR) while firewall_policy uses `ref-or:firewall_address` (address objects). Inconsistent — cannot reuse address objects in NAT rules |

### Low (v2.0 / document)

| # | Issue | Description |
|---|-------|-------------|
| 17 | No IPv6 support | IPv4 only throughout |
| 18 | No VLAN/PPPoE/Tunnel | Physical interfaces only |
| 19 | No QoS/traffic shaping | No bandwidth/priority rules |
| 20 | Password change doesn't invalidate sessions | Old tokens remain valid |
| 21 | Unused IPC commands | OSPF/RIP/BGP enums defined but not implemented |
| 22 | session.c not wired into pkt_forward.ko | Session tracking infrastructure exists but unused |

### Recommended Priority for Next Sprint

1. Fix #1 (DHCP race) + #3 (DHCP FW orphan) — reliability
2. Fix #2 (chain leak on delete) — resource leak
3. Fix #15 (server-side ref existence check) — data integrity
4. Fix #7 (CSRF) + #8 (getrandom) — web security
5. Implement #11 (config rollback) — operational safety
6. Wire session.c into pkt_forward.ko (#22) — data plane advancement
