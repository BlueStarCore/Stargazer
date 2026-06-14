/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply.h — Shared declarations for per-feature apply handlers
 *
 * Each apply handler lives in its own file (mgmtd_apply_*.c) to allow
 * parallel development without merge conflicts in the monolith.
 *
 * Helpers defined in stargazer-mgmtd.c (no longer static):
 *   extract_val, safe_exec, iface_exists, read_iface_mtu_limits, mgmt_log
 */

#ifndef MGMTD_APPLY_H
#define MGMTD_APPLY_H

#include "stargazer_ipc.h"
#include "sg_validate.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct dynbuf;   /* mgmtd_dynbuf.h — fwd decl for emit_ssl_steering() */

/* ── Shared constants ───────────────────────────────────────────────────── */

#define VALBUFSZ 128

/* ── Supervisor API ────────────────────────────────────────────────────── */

/*
 * Child source: why this process was started.
 * SRC_ALWAYS — unconditional (e.g. webd), always restart on crash.
 * SRC_CONFIG — config-driven (e.g. udhcpc.wan), only restart if the
 *              relevant DB key still matches the expected value.
 */
typedef enum { SRC_ALWAYS, SRC_CONFIG } child_source_t;

/*
 * Start a supervised child process. If an entry with the same name
 * already exists and is running, it is stopped first.
 *
 * argv is deep-copied into internal storage (survives caller stack).
 * For SRC_CONFIG children, cfg_type/cfg_id/cfg_key/cfg_val define
 * the DB condition checked before auto-restart.
 */
int  supervisor_start(const char *name, const char *const argv[],
		      child_source_t source,
		      const char *cfg_type, const char *cfg_id,
		      const char *cfg_key, const char *cfg_val);

/*
 * Stop a supervised child. Sets restart_max=0 (prevents auto-restart),
 * sends SIGTERM, waits up to 3s, then SIGKILL. Unregisters entry.
 */
void supervisor_stop(const char *name);

/*
 * Return the PID of a supervised child, or 0 if not found / not running.
 */
pid_t supervisor_get_pid(const char *name);

/* ── Helpers (defined in stargazer-mgmtd.c) ─────────────────────────────── */

void extract_val(const char *data, const char *key,
		 char *out, size_t outsz);

char *safe_exec(const char *const argv[]);

int ipt_exec(const char *const argv[]);

int iface_exists(const char *name);

void read_iface_mtu_limits(const char *name, int *out_min, int *out_max);

void mgmt_log(const char *level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

/* ── Pre-replay flush functions ─────────────────────────────────────────── *
 *
 * Called once before replaying each config type.  Each function cleans
 * the runtime state so replay starts from a known baseline.
 *
 * Rules:
 *   - Only remove state owned by this config type.
 *   - Never destroy state owned by other types (e.g. connected routes
 *     belong to interfaces, not static routes).
 *   - BusyBox caveats: "ip route flush proto X" ignores the proto
 *     filter — must delete individually.
 */
void flush_static_routes(void);
void flush_nat_rules(void);
void flush_forward_chain(void);

/* ── Pipe data to child stdin, read stdout ─────────────────────────────── */
char *pipe_exec_stdin(const char *const argv[],
		      const char *input, size_t input_len,
		      int *exit_code);

/* ── Address resolution (shared by firewall + NAT) ─────────────────────── */

/* Resolve address field value → CIDR.  Returns NULL (match-all),
 * pointer to out (resolved CIDR), or "SKIP" (fail-closed).
 * fqdn-type objects resolve to SKIP here — only resolve_address_ex()
 * callers (FORWARD chain) can match them, via ipset. */
const char *resolve_address(const char *val, char *out, size_t outsz);

/* Extended resolver for the FORWARD chain.  Return values:
 *   ADDR_MATCH_ALL  — no -s/-d flag (any/all/0.0.0.0/0)
 *   ADDR_CIDR       — out = CIDR for -s/-d
 *   ADDR_IPSET      — out = ipset name for -m set --match-set
 *   ADDR_SKIP       — dangling/unenforceable → skip rule (fail-closed) */
enum addr_kind { ADDR_MATCH_ALL, ADDR_CIDR, ADDR_IPSET, ADDR_SKIP };
enum addr_kind resolve_address_ex(const char *val, char *out, size_t outsz);

/* ── ipset management (mgmtd_ipset.c — in-process netlink) ─────────────── */

int  sg_ipset_available(void);                /* kernel hash:ip support?   */
void sg_fqdn_set_name(const char *obj, char *out, size_t outsz);
int  sg_ipset_ensure(const char *set);        /* create hash:ip (timeout
					       * support) if missing       */
int  sg_ipset_add(const char *set, const uint32_t *addrs_be, int n);
					      /* merge members; re-add
					       * refreshes entry timeout    */
int  sg_ipset_destroy(const char *set);       /* ENOENT tolerated          */
int  sg_ipset_list(const char *set, char *out, size_t outsz);
					      /* dump members + expiry, one
					       * per line; returns member
					       * count or -errno            */
int  sg_ipset_members(const char *set, uint32_t *addrs_be, int max);
					      /* raw be32 members; returns
					       * member count or -errno     */
void     sg_ipset_set_entry_timeout(uint32_t sec);  /* system settings
						     * fqdn-ttl            */
uint32_t sg_ipset_entry_timeout(void);

/* ── FQDN refresh engine (mgmtd_fqdn.c) ────────────────────────────────── */

void fqdn_refresh_tick(void);                 /* main-loop periodic check  */
void fqdn_refresh_kick(void);                 /* immediate worker run      */
void fqdn_restamp_all(void);                  /* re-stamp members with the
					       * current entry timeout     */
void fqdn_object_removed(const char *obj_name);  /* destroy object's set   */

/* ── Atomic chain rebuild (firewall + NAT) ─────────────────────────────── */
sg_status_t rebuild_forward_chain(char *result, size_t rsize);
sg_status_t rebuild_nat_chains(char *result, size_t rsize);

/* ── IPS ruleset compile + hot-reload (mgmtd_apply_ips.c, Phase B) ───────── */
/* Compile per-profile rulesets + union active.rules từ repo theo categories,
 * verify bằng ipsd -C, atomic swap, SIGUSR1 ipsd. Gọi sau khi đổi
 * security_ips / security_ips-profile / firewall_policy. */
sg_status_t rebuild_ips_active(char *result, size_t rsize);
/* Bit index ổn định (0..30) cho IPS profile enable, theo thứ tự sg_db_list. Dùng
 * CHUNG bởi firewall (skb MARK = bit+1) và ips compile (sgprof:bit; → mask) để hai
 * bên khớp số. -1 nếu profile không tồn tại / disable / vượt 31 profile. */
int ips_profile_bit(const char *name);
sg_status_t run_ips_update_now(const char *ids_csv, char *result, size_t rsize);
sg_status_t ips_rulesets_reload_custom(char *result, size_t rsize);

/* Validation-only for CFG_APPLY (no kernel changes) */
sg_status_t validate_firewall_policy(const char *id, const char *data,
				     char *result, size_t rsize);
sg_status_t validate_nat(const char *id, const char *data,
			 char *result, size_t rsize);
/* IPS bật trên policy theo toggle ips-status (tương thích ngược với policy cũ
 * chưa có ips-status). Dùng cho cả forward chain lẫn SSL steering coupling. */
int ips_policy_on(const char *status, const char *profile);

sg_status_t validate_ips(const char *id, const char *data,
			 char *result, size_t rsize);

/* ── SSL-inspection steering (mgmtd_apply_ssl.c) ────────────────────────── */
/*
 * Append the TLS REDIRECT rule(s) into a *nat restore buffer (PREROUTING),
 * steering forwarded HTTPS into stargazer-ssld. Called from rebuild_nat_chains
 * so the whole *nat table stays one atomic restore. No-op (returns 0) when no
 * accept policy binds an enabled security_ssl-inspection-profile. Returns the
 * number of rules emitted, or -1 on a sanitization failure (caller still
 * proceeds — fail-safe = no steering, normal traffic). */
int emit_ssl_steering(struct dynbuf *buf);

/* Start/stop/restart stargazer-ssld theo security_ssl-inspection-profile.
 * Gọi sau khi rebuild_nat_chains apply steering. off-by-default → no-op. */
void ssld_sync(void);

/* ── Per-feature apply handlers ─────────────────────────────────────────── */

sg_status_t apply_route_static(const char *id, const char *data,
			       char *result, size_t rsize);

sg_status_t apply_settings(const char *id, const char *data,
			   char *result, size_t rsize);

sg_status_t apply_interface(const char *id, const char *data,
			    char *result, size_t rsize);

sg_status_t apply_dns(const char *id, const char *data,
		      char *result, size_t rsize);

sg_status_t apply_dhcp(const char *id, const char *data,
		       char *result, size_t rsize);

void unapply_dhcp(const char *id);

sg_status_t apply_ntp(const char *id, const char *data,
		      char *result, size_t rsize);

sg_status_t apply_session_ttl(const char *id, const char *data,
			      char *result, size_t rsize);

/* Flush the whole conntrack table via NFNETLINK (in-process, no shelling).
 * Defined in mgmtd_diag.c. Returns 0 on success, negative on failure. */
int conntrack_flush_all(void);

/* Set the connmark DIRTY bit on live flows so they re-traverse the FORWARD
 * chain on their next packet. pid==0 = all flows; pid==cmkid = only flows that
 * policy stamped. In-process NFNETLINK dump + per-flow update. Defined in
 * mgmtd_diag.c. Returns 0 on success, negative on failure. */
int conntrack_mark_dirty_by_policy(unsigned int pid);

/* Re-evaluate live flows after a FORWARD policy rebuild (connmark dirty, or
 * flush fallback). Defined in mgmtd_apply_firewall.c. */
void conntrack_reeval_after_policy_change(unsigned int pid);

#endif /* MGMTD_APPLY_H */
