/* SPDX-License-Identifier: MIT */
/*
 * stargazer_ipc.h — Shared IPC protocol for Stargazer NGFW
 *
 * Defines the wire protocol between CLI (unprivileged) and mgmtd (root).
 * Used by: stargazer-mgmtd, stargazer-ipc-cli, stargazer-logind
 *
 * Architecture:
 *   CLI (user-level)  ──Unix Domain Socket──►  mgmtd (root daemon)
 *   CLI only parses text and displays results.
 *   mgmtd performs all privileged operations (file I/O, shadow, iptables).
 */

#ifndef STARGAZER_IPC_H
#define STARGAZER_IPC_H

#include <stdint.h>

/* ── Socket path ────────────────────────────────────────────────────────── */
#ifndef SG_MGMTD_SOCK
#define SG_MGMTD_SOCK   "/run/stargazer-mgmtd.sock"
#endif

/* ── Status codes ───────────────────────────────────────────────────────── */
typedef enum {
	SG_OK                = 0,

	/* Client/validation errors (100-199) */
	SG_ERR_INVALID_CMD   = 100,
	SG_ERR_INVALID_ARG   = 101,
	SG_ERR_INVALID_VAL   = 102,
	SG_ERR_MISSING_ARG   = 103,
	SG_ERR_POLICY_FAIL   = 104,

	/* Permission/auth errors (200-299) */
	SG_ERR_PERM_DENIED   = 200,
	SG_ERR_AUTH_FAIL     = 201,
	SG_ERR_LOCKED        = 202,
	SG_ERR_PROFILE_DENY  = 203,
	SG_ERR_SESSION_EXPIRED = 204, /* Session tag no longer valid  */

	/* Not found errors (300-399) */
	SG_ERR_NOT_FOUND     = 300,
	SG_ERR_USER_NOT_FOUND = 301,
	SG_ERR_PROFILE_NOT_FOUND = 302,
	SG_ERR_ENTRY_NOT_FOUND = 303,

	/* Conflict errors (400-499) */
	SG_ERR_ALREADY_EXISTS = 400,
	SG_ERR_IN_USE        = 401,
	SG_ERR_BUILTIN       = 402,

	/* System errors (500-599) */
	SG_ERR_SYSTEM_FAIL   = 500,
	SG_ERR_IO_FAIL       = 501,
	SG_ERR_DISK_FULL     = 502,
	SG_ERR_INTERNAL      = 503,
} sg_status_t;

/* ── Command IDs ────────────────────────────────────────────────────────── */
typedef enum {
	/* Config read operations (1xx) */
	SG_CMD_CFG_GET       = 100,   /* Get section data               */
	SG_CMD_CFG_LIST      = 101,   /* List entries of a type          */
	SG_CMD_CFG_LIST_TYPES = 102,  /* List all config types in DB     */

	/* Config write operations (2xx) */
	SG_CMD_CFG_SET       = 200,   /* Set/update section data         */
	SG_CMD_CFG_DEL       = 201,   /* Delete a section                */
	SG_CMD_CFG_APPLY     = 202,   /* Apply config to running system  */
	SG_CMD_CFG_INSERT    = 203,   /* Move entry to new sequence pos  */

	/* Admin management (3xx) */
	SG_CMD_ADMIN_CREATE  = 300,   /* Create admin user               */
	SG_CMD_ADMIN_DELETE  = 301,   /* Delete admin user               */
	SG_CMD_ADMIN_SET_PW  = 302,   /* Set admin password              */
	SG_CMD_ADMIN_SET_ENF = 303,   /* Set enforce-change-password     */
	SG_CMD_ADMIN_CHECK_PW = 304,  /* Validate password against policy */
	SG_CMD_ADMIN_LOCK_PW  = 305,  /* Lock (invalidate) admin password */

	/* Auth login flow (31x) — used by stargazer-logind */
	SG_CMD_AUTH_LOGIN      = 310,  /* Authenticate user via shadow     */
	SG_CMD_AUTH_CHANGE_PW  = 311,  /* Change password (logind forced)  */
	SG_CMD_AUTH_LOGIN_OK   = 312,  /* Confirm login success (audit)    */

	/* Session/auth (4xx) */
	SG_CMD_SESSION_TAG_NEW = 400, /* Acquire a new session tag       */
	SG_CMD_SESSION_TAG_DEL = 401, /* Release session tag (logout)    */

	/* Config revision management (5xx) — CLI sends these, mgmtd not yet implemented */
	SG_CMD_COMMIT        = 500,   /* Record config revision (stub)   */
	SG_CMD_REVISIONS     = 501,   /* List revisions (stub)           */
	SG_CMD_ROLLBACK      = 502,   /* Rollback to revision (stub)     */

	/* System operations (6xx) */
	SG_CMD_SYS_POWEROFF  = 600,
	SG_CMD_SYS_REBOOT    = 601,
	SG_CMD_UPGRADE_START    = 602, /* Download + install firmware    */
	SG_CMD_UPGRADE_STATUS   = 603, /* Show firmware version/status   */
	SG_CMD_UPGRADE_PROGRESS = 604, /* Poll firmware upgrade progress */
	SG_CMD_NET_PING      = 605,   /* Network ping (ICMP echo)       */
	SG_CMD_NET_TRACEROUTE = 606,  /* Network traceroute             */
	SG_CMD_NET_NSLOOKUP  = 607,   /* DNS lookup                     */
	SG_CMD_NET_ARPING    = 608,   /* ARP ping (L2 reachability)     */
	SG_CMD_UPGRADE_CANCEL  = 609, /* Cancel in-progress upgrade     */
	SG_CMD_SHOW_STATUS   = 610,
	SG_CMD_SHOW_IFACES   = 611,
	SG_CMD_SHOW_ROUTES   = 612,
	SG_CMD_SHOW_CONFIG   = 613,   /* Reserved: not yet implemented   */
	SG_CMD_SHOW_STATS    = 614,
	SG_CMD_SYS_FACTORY_RESET = 615, /* Factory reset to defaults         */
	SG_CMD_WHOAMI        = 620,   /* Get caller's profile+permissions */

	/* Firewall/routing diagnostics (63x) */
	SG_CMD_DIAG_FW_IPTABLES  = 630,  /* Show iptables rules (filter/nat) */
	SG_CMD_DIAG_FW_POLICY    = 631,  /* Show INPUT chain policy+rules    */
	SG_CMD_DIAG_FW_CONNTRACK = 632,  /* Show conntrack entries            */
	SG_CMD_DIAG_ROUTES       = 633,  /* Show IPv4+IPv6 routing tables     */

	/* System diagnostics (64x) — served by mgmtd_diag.c */
	SG_CMD_DIAG_CPU          = 640,  /* CPU jiffies + thermal readings     */
	SG_CMD_DIAG_RAM          = 641,  /* MemTotal, MemAvailable             */
	SG_CMD_DIAG_DISK         = 642,  /* statvfs("/") results               */
	SG_CMD_DIAG_IFACE_STATS  = 643,  /* Per-iface rx/tx + link speed       */
	SG_CMD_DIAG_PROCTOP      = 644,  /* CPU agg + mem + uptime + proc list */
	SG_CMD_DIAG_THERMAL      = 645,  /* Thermal zone temperatures          */
	SG_CMD_DIAG_DISK_HEALTH  = 646,  /* Disk health: mount/fs/write/usage  */
	SG_CMD_DISK_LIST         = 647,  /* List block devices + sizes/mounts  */
	SG_CMD_DISK_INFO         = 648,  /* Detail for one disk or partition   */
	SG_CMD_DISK_SMART        = 649,  /* eMMC wear/health (life_time etc)   */

	/* Show data (65x) */
	SG_CMD_SHOW_SESSIONS     = 650,  /* /proc/stargazer/sessions contents  */
	SG_CMD_SHOW_BOOT_CONFIG  = 651,  /* modules + sysctl config files      */
	SG_CMD_DIAG_NTP          = 652,  /* NTP status: server, pid, time      */
	SG_CMD_DIAG_BUSYBOX_LIST = 653,  /* Enumerate busybox applet symlinks  */
	SG_CMD_DIAG_SESSION      = 654,  /* Session table status + inject test */
	SG_CMD_SESSION_CLEAR     = 655,  /* Flush all active sessions          */
	SG_CMD_SESSION_STATS     = 656,  /* Parsed session counters + status   */
	SG_CMD_NETFLOW_STATUS    = 657,  /* NetFlow exporter stats + status    */
	SG_CMD_NETFLOW_SET       = 658,  /* Set collector IP:port, enable flag */

	/* Debug state (66x) */
	SG_CMD_DEBUG_STATE_GET   = 660,  /* Read debug conf key=value pairs    */
	SG_CMD_DEBUG_STATE_SET   = 661,  /* Atomic write debug conf            */
	SG_CMD_DEBUG_STATE_RESET = 662,  /* Unlink debug conf                  */
	SG_CMD_HISTORY_SAVE      = 663,  /* Save CLI history lines             */
	SG_CMD_HISTORY_LOAD      = 664,  /* Load CLI history lines             */

	/* Log viewing/management (67x) */
	SG_CMD_LOG_AUDIT         = 670,  /* Read audit log (tail N lines)      */
	SG_CMD_LOG_SYSTEM        = 671,  /* Read dmesg output                  */
	SG_CMD_LOG_CLEAR_AUDIT   = 672,  /* Truncate audit log                 */
	SG_CMD_LOG_MGMTD        = 673,  /* Read mgmtd daemon log              */
	SG_CMD_DIAG_STARGAZER_LOG = 674, /* Filtered stargazer init messages   */
	SG_CMD_DIAG_STORAGE      = 675,  /* Storage mount status and health    */

	/* DNS/DHCP — Member A (7xx): SG_CMD_DNS_* 700-749, SG_CMD_DHCP_* 750-799 */
	/* NAT — Member B (8xx): SG_CMD_NAT_* 800-849 */

	/* Firmware upload via IPC (webd → mgmtd) */
	SG_CMD_UPGRADE_UPLOAD    = 680,  /* Receive firmware data via IPC   */

	/* Keepalive / ping (9xx) */
	SG_CMD_PING          = 900,
	SG_CMD_DEBUG_FETCH   = 901,   /* Fetch buffered debug traces    */
	SG_CMD_UPGRADE_TEST_SETUP = 902, /* Test: write/clean/query fw state */
	SG_CMD_SUPERVISOR_TEST = 903, /* Test: start/stop/query supervised children */
} sg_cmd_t;

/* ── Message header ─────────────────────────────────────────────────────── */

#define SG_MSG_MAGIC     0x5347    /* "SG" */
#define SG_MSG_VERSION   2
#define SG_PAYLOAD_MAX   4096
#define SG_RESPONSE_MAX  65536    /* Max response payload (diagnostics etc) */
#define SG_USERNAME_MAX  64
#define SG_EXTRA_MAX     256

/* Debug flag bits in sg_request_hdr_t.debug_flags */
#define SG_DBG_FLAG_MGMTD  0x01  /* Enable mgmtd request/response tracing */
#define SG_DBG_FLAG_AUTH    0x02  /* Enable auth operation tracing         */

/*
 * Request: CLI → mgmtd
 *
 * Wire format (fixed header + variable payload):
 *   [ magic:2 | version:1 | debug_flags:1 | cmd:4 | user[64] |
 *     payload_len:4 | session_tag:8 | payload[...] ]
 */
typedef struct {
	uint16_t  magic;                     /* SG_MSG_MAGIC               */
	uint8_t   version;                   /* SG_MSG_VERSION             */
	uint8_t   debug_flags;               /* SG_DBG_FLAG_* bits         */
	uint32_t  cmd;                       /* sg_cmd_t                   */
	char      username[SG_USERNAME_MAX]; /* authenticated user         */
	uint32_t  payload_len;               /* length of payload data     */
	uint64_t  session_tag;               /* session tag (0 = untagged) */
	/* followed by payload_len bytes of payload (key=value lines, etc) */
} __attribute__((packed)) sg_request_hdr_t;

/*
 * Response: mgmtd → CLI
 *
 * Wire format (fixed header + variable payload):
 *   [ magic:2 | version:1 | _pad:1 | status:4 | extra[256] | payload_len:4 | payload[...] ]
 */
typedef struct {
	uint16_t   magic;                    /* SG_MSG_MAGIC               */
	uint8_t    version;                  /* SG_MSG_VERSION             */
	uint8_t    _pad;
	uint32_t   status;                   /* sg_status_t                */
	char       extra[SG_EXTRA_MAX];      /* human hint (for CLI)       */
	uint32_t   payload_len;              /* length of response payload */
	/* followed by payload_len bytes of payload data                   */
} __attribute__((packed)) sg_response_hdr_t;

/* ── Error message lookup ───────────────────────────────────────────────── */

static inline const char *sg_status_str(sg_status_t s)
{
	switch (s) {
	case SG_OK:                    return "Success";
	case SG_ERR_INVALID_CMD:       return "Invalid command";
	case SG_ERR_INVALID_ARG:       return "Invalid argument";
	case SG_ERR_INVALID_VAL:       return "Invalid value";
	case SG_ERR_MISSING_ARG:       return "Missing required argument";
	case SG_ERR_POLICY_FAIL:       return "Password policy violation";
	case SG_ERR_PERM_DENIED:       return "Permission denied";
	case SG_ERR_AUTH_FAIL:         return "Authentication failed";
	case SG_ERR_LOCKED:            return "Account is locked";
	case SG_ERR_PROFILE_DENY:      return "Profile does not allow this operation";
	case SG_ERR_SESSION_EXPIRED:   return "Session expired";
	case SG_ERR_NOT_FOUND:         return "Not found";
	case SG_ERR_USER_NOT_FOUND:    return "User not found";
	case SG_ERR_PROFILE_NOT_FOUND: return "Profile not found";
	case SG_ERR_ENTRY_NOT_FOUND:   return "Entry not found";
	case SG_ERR_ALREADY_EXISTS:    return "Already exists";
	case SG_ERR_IN_USE:            return "Resource is in use";
	case SG_ERR_BUILTIN:           return "Cannot modify built-in object";
	case SG_ERR_SYSTEM_FAIL:       return "System error";
	case SG_ERR_IO_FAIL:           return "I/O error";
	case SG_ERR_DISK_FULL:         return "Disk full";
	case SG_ERR_INTERNAL:          return "Internal error";
	default:                       return "Unknown error";
	}
}

/*
 * Commands excluded from central audit logging.
 *
 * These fire at high frequency during normal CLI operation and
 * carry no meaningful security or operational information:
 *   PING          — idle keepalive, every 30 seconds
 *   DEBUG_FETCH   — pulls debug buffer, after every CLI command
 *   WHOAMI        — permission check, on login + idle polling
 *   HISTORY_SAVE  — persists readline history on logout
 *   HISTORY_LOAD  — loads readline history on login
 *   LOG_AUDIT     — read-only log viewer, no security significance
 *   LOG_SYSTEM    — read-only dmesg viewer, no security significance
 *
 * All other commands (reads, writes, diagnostics, session tags)
 * are audited automatically by the central dispatch hook.
 */
static inline int sg_cmd_audit_skip(sg_cmd_t cmd)
{
	switch (cmd) {
	case SG_CMD_PING:
	case SG_CMD_DEBUG_FETCH:
	case SG_CMD_WHOAMI:
	case SG_CMD_HISTORY_SAVE:
	case SG_CMD_HISTORY_LOAD:
	case SG_CMD_LOG_AUDIT:
	case SG_CMD_LOG_SYSTEM:
	case SG_CMD_LOG_MGMTD:
	case SG_CMD_DIAG_STARGAZER_LOG:
	case SG_CMD_DIAG_STORAGE:
	case SG_CMD_DISK_LIST:
	case SG_CMD_DISK_INFO:
	case SG_CMD_DISK_SMART:
	case SG_CMD_SUPERVISOR_TEST:
	case SG_CMD_DIAG_NTP:
		return 1;
	default:
		return 0;
	}
}

#endif /* STARGAZER_IPC_H */
