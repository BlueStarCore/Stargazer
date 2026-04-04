/* SPDX-License-Identifier: MIT */
/*
 * sg_cmd_defs.h — Single source of truth for CLI command definitions.
 *
 * X-macro pattern: each consumer #defines X before #include.
 * CLI expands all fields. mgmtd can ignore the handler field.
 *
 * X(path, desc, perm, max_args, handler)
 *   path      — command path ("execute ping")
 *   desc      — help text
 *   perm      — required permission, or NULL
 *   max_args  — 0=none, N=at most N, -1=variadic
 *   handler   — CLI handler function name, or NULL (completion-only)
 */

X("help",                                   "Show available commands",                 NULL,              0,  cmd_help)
X("exit",                                   "Logout from CLI",                         NULL,              0,  cmd_exit)
X("logout",                                 "Logout from CLI",                         NULL,              0,  cmd_exit)

X("show",                                   "Show system information",                 "monitor",         0,  NULL)
X("show status",                            "Module and system status",                "monitor",         0,  cmd_show_status)
X("show sessions",                          "Active session table",                    "monitor",         0,  cmd_show_sessions)
X("show stats",                             "Packet statistics",                       "monitor",         0,  cmd_show_stats)
X("show interfaces",                        "Network interfaces",                      "monitor",         0,  cmd_show_interfaces)
X("show routes",                            "Routing table",                           "monitor",         0,  cmd_show_routes)
X("show configure",                         "Running configuration (FortiGate-style)", "monitor",         0,  cmd_show_configure)
X("show config",                            "Current configuration",                   "monitor",         0,  cmd_show_config)
X("show firmware",                          "Firmware version and status",             "monitor",         0,  cmd_show_firmware)

X("configure",                              "Configure firewall",                      "configure,admin", -1, cmd_configure)
X("configure commit",                       "Save a configuration revision",           "configure",       0,  NULL)
X("configure revisions",                    "List configuration revisions",            "configure",       0,  NULL)
X("configure rollback",                     "Rollback configuration to revision",      "configure",       0,  NULL)

X("execute",                                "Execute commands and operations",          NULL,              0,  NULL)

X("execute system",                         "System management commands",              "admin",           0,  NULL)
X("execute system shutdown",                "Shut down the system",                    "admin",           0,  cmd_sys_shutdown)
X("execute system reboot",                  "Reboot the system",                       "admin",           0,  cmd_sys_reboot)
X("execute system factory-reboot",         "Factory reset and reboot",                "admin",           0,  cmd_sys_factory_reboot)
X("execute system factory-shutdown",       "Factory reset and shutdown",              "admin",           0,  cmd_sys_factory_shutdown)

X("execute firmware",                       "Firmware management",                     "admin",           0,  NULL)
X("execute firmware upgrade",               "Upgrade firmware from URL",               "admin",           1,  cmd_fw_upgrade)

X("execute ping",                           "Ping a host (ICMP echo request)",         "monitor",         1,  cmd_ping)
X("execute traceroute",                     "Trace route to a host",                   "monitor",         1,  cmd_traceroute)
X("execute nslookup",                       "DNS lookup for a host or IP",             "monitor",         1,  cmd_nslookup)
X("execute arping",                         "ARP ping a host on local network",        "monitor",         2,  cmd_arping)

X("execute debug",                          "Runtime debug control",                   "admin",           0,  cmd_debug_status)
X("execute debug enable",                   "Enable debug output",                     "admin",           0,  cmd_debug_enable)
X("execute debug disable",                  "Disable debug output",                    "admin",           0,  cmd_debug_disable)
X("execute debug reset",                    "Reset all debug options",                 "admin",           0,  cmd_debug_reset)
X("execute debug status",                   "Show debug status",                       "admin",           0,  cmd_debug_status)
X("execute debug option",                   "Set debug output options",                "admin",           2,  cmd_debug_option)
X("execute debug option timestamp",         "Print timestamp in debug logs",           "admin",           0,  NULL)
X("execute debug option actor",             "Print actor (user/system) in debug logs", "admin",           0,  NULL)
X("execute debug option function",          "Print function name in debug logs",       "admin",           0,  NULL)
X("execute debug option hierarchy",         "Print call hierarchy in debug logs",      "admin",           0,  NULL)
X("execute debug flow trace",               "Enable packet flow tracing",              "admin",           4,  cmd_debug_flow)
X("execute debug flow trace limit",         "Limit number of flow records",            "admin",           0,  NULL)
X("execute debug flow trace unlimited",     "No flow record limit",                    "admin",           0,  NULL)
X("execute debug cli",                      "Enable/disable CLI debug tracing",        "admin",           1,  cmd_debug_cli)
X("execute debug mgmtd",                    "Enable/disable mgmtd daemon debug tracing", "admin",        1,  cmd_debug_mgmtd)
X("execute debug auth",                     "Enable/disable auth debug tracing",       "admin",           2,  cmd_debug_auth)
X("execute debug auth admin",               "Debug admin authentication",              "admin",           0,  NULL)
X("execute debug auth user",                "Debug user authentication",               "admin",           0,  NULL)

X("execute log",                             "Log management",                          "monitor",         0,  NULL)
X("execute log audit",                      "Show audit log entries",                  "monitor",         1,  cmd_log_audit)
X("execute log system",                     "Show system/kernel log",                  "monitor",         1,  cmd_log_system)
X("execute log clear",                      "Clear log files",                         "admin",           0,  NULL)
X("execute log clear audit",                "Clear audit log",                         "admin",           0,  cmd_log_clear_audit)

X("execute diagnose",                       "Run diagnostic tools",                    "admin",           0,  NULL)
X("execute diagnose top",                   "Show live process monitor (q to quit)",   "admin",           2,  cmd_diag_top)
X("execute diagnose resources",             "Show system resource usage",              "admin",           1,  cmd_diag_resources)
X("execute diagnose resources cpu",         "Show CPU usage and temperature",          "admin",           0,  NULL)
X("execute diagnose resources ram",         "Show RAM usage",                          "admin",           0,  NULL)
X("execute diagnose resources disk",        "Show disk usage",                         "admin",           0,  NULL)
X("execute diagnose resources interface",   "Show interface throughput",               "admin",           0,  NULL)
X("execute diagnose resources all",         "Show all resource metrics",               "admin",           0,  NULL)
X("execute diagnose disk",                  "Disk diagnostics",                        "admin",           0,  NULL)
X("execute diagnose disk list",             "List available disks",                    "admin",           0,  cmd_diag_disk_list)
X("execute diagnose disk info",             "Show disk/partition details",             "admin",           1,  cmd_diag_disk_info)
X("execute diagnose disk smart",            "Show eMMC wear/health",                   "admin",           0,  cmd_diag_disk_smart)

X("execute diagnose ntp",                   "Show NTP status and system time",         "monitor",         0,  cmd_diag_ntp)

X("execute diagnose selftest",              "Run built-in self-tests",                 "admin",           1,  cmd_diag_selftest)
X("execute diagnose selftest full",         "All suites, full mode (with IPC)",        "admin",           0,  NULL)
X("execute diagnose selftest permissions",  "Permission model tests (full)",           "admin",           0,  NULL)
X("execute diagnose selftest configure",    "Configuration validation tests (full)",   "admin",           0,  NULL)
X("execute diagnose selftest firewall",     "Firewall & network tests (full)",         "admin",           0,  NULL)
X("execute diagnose selftest upgrade",      "Firmware upgrade tests (full)",           "admin",           0,  NULL)
X("execute diagnose selftest sandbox",      "Seccomp/Landlock sandbox tests (full)",   "admin",           0,  NULL)
X("execute diagnose selftest database",     "Database health tests (full)",            "admin",           0,  NULL)
X("execute diagnose selftest disk",         "Disk partition health tests (full)",      "admin",           0,  NULL)
X("execute diagnose selftest dhcp",         "DHCP client/server cross-validation",     "admin",           0,  NULL)
X("execute diagnose selftest supervisor",  "Supervisor process management tests",      "admin",           0,  NULL)
X("execute diagnose pentest",              "Run security penetration tests",          "admin",           1,  cmd_diag_pentest)
X("execute diagnose pentest full",         "Full pentest with SEC-1..18",             "admin",           0,  NULL)

X("execute diagnose firewall",              "Firewall diagnostics",                    "admin",           0,  NULL)
X("execute diagnose firewall policy",       "Show firewall policy and rules",          "admin",           1,  cmd_diag_fw_policy)
X("execute diagnose firewall policy nat",   "Show NAT rules",                          "admin",           0,  NULL)
X("execute diagnose firewall conntrack",    "Show connection tracking entries",         "admin",           0,  cmd_diag_fw_conntrack)

X("execute diagnose nat",                  "NAT diagnostics",                         "admin",           0,  NULL)
X("execute diagnose nat policy",           "Show kernel NAT table rules",             "admin",           0,  cmd_diag_nat_policy)

X("execute diagnose routes",               "Show routing table",                       "admin",           0,  cmd_diag_routes)
