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

/* ── Shared constants ───────────────────────────────────────────────────── */

#define VALBUFSZ 128

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

#endif /* MGMTD_APPLY_H */
