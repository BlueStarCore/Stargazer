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
#include <sys/types.h>

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

/* ── Per-feature apply handlers ─────────────────────────────────────────── */

sg_status_t apply_route_static(const char *id, const char *data,
			       char *result, size_t rsize);

sg_status_t apply_settings(const char *id, const char *data,
			   char *result, size_t rsize);

sg_status_t apply_interface(const char *id, const char *data,
			    char *result, size_t rsize);

sg_status_t apply_nat(const char *id, const char *data,
		      char *result, size_t rsize);

sg_status_t apply_dns(const char *id, const char *data,
		      char *result, size_t rsize);

sg_status_t apply_dhcp(const char *id, const char *data,
		       char *result, size_t rsize);

void unapply_dhcp(const char *id);

sg_status_t apply_firewall_policy(const char *id, const char *data,
				   char *result, size_t rsize);

void unapply_firewall_policy(const char *id, const char *data);

sg_status_t apply_ntp(const char *id, const char *data,
		      char *result, size_t rsize);

#endif /* MGMTD_APPLY_H */
