/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_internal.h — Shared internal declarations for mgmtd modules
 *
 * Functions defined in stargazer-mgmtd.c that sub-modules
 * (mgmtd_user.c, mgmtd_firmware.c, mgmtd_network.c) need to call.
 *
 * Follows the same pattern as mgmtd_apply.h.
 */

#ifndef MGMTD_INTERNAL_H
#define MGMTD_INTERNAL_H

#include "stargazer_ipc.h"
#include "sg_db.h"
#include "sg_validate.h"
#include "password_policy.h"

#include <stddef.h>
#include <stdint.h>

/* ── Constants ───────────────────────────────────────────────────────────── */

#define CMD_BUF_SIZE     512
#define MAX_LINE         1024
#define MAX_SALT_LEN     32
#define SHADOW_LOCK_MODE  0600
#define SHADOW_FILE_MODE  0640
#define SHADOW_LAST_CHANGED  "19700"
#define SHADOW_MAX_DAYS      "99999"
#define SHADOW_WARN_DAYS     "7"

/* ── Per-request debug flags (defined in stargazer-mgmtd.c) ─────────────── */

extern uint8_t g_debug_flags;

/* ── I/O helpers (defined in stargazer-mgmtd.c) ─────────────────────────── */

void send_ok(int fd, const char *extra, const char *payload);
void send_error(int fd, sg_status_t status, const char *extra);
int  send_stream_chunk(int fd, const char *data, size_t len);
int  stream_exec(int client_fd, const char *const argv[]);

/* ── Logging (defined in stargazer-mgmtd.c) ──────────────────────────────── */

void mgmt_log(const char *level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
int  audit_log(const char *user, const char *event, const char *msg);

/* ── Debug (defined in stargazer-mgmtd.c) ────────────────────────────────── */

void debug_buf_push(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

/* ── Session tags (defined in stargazer-mgmtd.c) ─────────────────────────── */

void session_tag_purge_user(const char *user);
void admin_notify_change(const char *user);

/* ── Auth / permissions (defined in stargazer-mgmtd.c) ───────────────────── */

const char *get_user_permissions(const char *username);
int  has_permission(const char *perms_csv, const char *perm);
const char *get_type_permission(const char *type_name);

/* ── Config validation (defined in stargazer-mgmtd.c) ────────────────────── */

sg_status_t validate_cfg_data(const char *type, const char *data,
			      char *errbuf, size_t errsz);
int  check_references(const char *type, const char *id,
		      char *errbuf, size_t errsz);

/* ── User/password helpers (defined in mgmtd_user.c) ─────────────────────── */

int  set_password(const char *username, const char *password);
int  set_shadow_hash(const char *username, const char *hash);
int  create_system_user(const char *username, const char *shell,
			int allow_empty_pw);
int  delete_system_user(const char *username);
int  user_has_password(const char *username);
int  mgmtd_validate_password(const char *username, const char *password,
			     const char *enforce_override,
			     const char **reason);

/* ── User management handlers (defined in mgmtd_user.c) ─────────────────── */

int handle_admin_create(int client_fd, const char *user,
			const char *payload, const sg_request_hdr_t *hdr);
int handle_admin_delete(int client_fd, const char *user,
			const char *payload, const sg_request_hdr_t *hdr);
int handle_admin_set_pw(int client_fd, const char *user,
			const char *payload, const sg_request_hdr_t *hdr);
int handle_admin_set_enf(int client_fd, const char *user,
			 const char *payload, const sg_request_hdr_t *hdr);
int handle_admin_check_pw(int client_fd, const char *user,
			  const char *payload, const sg_request_hdr_t *hdr);
int handle_admin_lock_pw(int client_fd, const char *user,
			 const char *payload, const sg_request_hdr_t *hdr);

/* ── Auth login handlers (defined in mgmtd_user.c) ────────────────────────── */

int handle_auth_login(int client_fd, const char *user,
		      const char *payload, const sg_request_hdr_t *hdr);
int handle_auth_change_pw(int client_fd, const char *user,
			  const char *payload, const sg_request_hdr_t *hdr);
int handle_auth_login_ok(int client_fd, const char *user,
			 const char *payload, const sg_request_hdr_t *hdr);

/* ── Firmware upgrade handlers (defined in mgmtd_firmware.c) ──────────────── */

int handle_upgrade_status(int client_fd, const char *user,
			  const char *payload, const sg_request_hdr_t *hdr);
int handle_upgrade_start(int client_fd, const char *user,
			 const char *payload, const sg_request_hdr_t *hdr);
int handle_upgrade_progress(int client_fd, const char *user,
			    const char *payload, const sg_request_hdr_t *hdr);
int handle_upgrade_cancel(int client_fd, const char *user,
			  const char *payload, const sg_request_hdr_t *hdr);
int handle_upgrade_test_setup(int client_fd, const char *user,
			      const char *payload, const sg_request_hdr_t *hdr);

/* ── Network diagnostic handlers (defined in mgmtd_network.c) ────────────── */

int handle_net_ping(int client_fd, const char *user,
		    const char *payload, const sg_request_hdr_t *hdr);
int handle_net_traceroute(int client_fd, const char *user,
			  const char *payload, const sg_request_hdr_t *hdr);
int handle_net_nslookup(int client_fd, const char *user,
			const char *payload, const sg_request_hdr_t *hdr);
int handle_net_arping(int client_fd, const char *user,
		      const char *payload, const sg_request_hdr_t *hdr);

/* ── System diagnostics handlers (defined in mgmtd_diag.c) ───────────────── */

int handle_diag_cpu(int client_fd, const char *user,
		    const char *payload, const sg_request_hdr_t *hdr);
int handle_diag_ram(int client_fd, const char *user,
		    const char *payload, const sg_request_hdr_t *hdr);
int handle_diag_disk(int client_fd, const char *user,
		     const char *payload, const sg_request_hdr_t *hdr);
int handle_diag_iface_stats(int client_fd, const char *user,
			    const char *payload, const sg_request_hdr_t *hdr);
int handle_diag_proctop(int client_fd, const char *user,
			const char *payload, const sg_request_hdr_t *hdr);
int handle_diag_thermal(int client_fd, const char *user,
			const char *payload, const sg_request_hdr_t *hdr);
int handle_diag_disk_health(int client_fd, const char *user,
			    const char *payload, const sg_request_hdr_t *hdr);
int handle_disk_list(int client_fd, const char *user,
		     const char *payload, const sg_request_hdr_t *hdr);
int handle_disk_info(int client_fd, const char *user,
		     const char *payload, const sg_request_hdr_t *hdr);
int handle_disk_smart(int client_fd, const char *user,
		      const char *payload, const sg_request_hdr_t *hdr);
int handle_show_sessions(int client_fd, const char *user,
			 const char *payload, const sg_request_hdr_t *hdr);
int handle_show_boot_config(int client_fd, const char *user,
			    const char *payload, const sg_request_hdr_t *hdr);
int handle_debug_state_get(int client_fd, const char *user,
			   const char *payload, const sg_request_hdr_t *hdr);
int handle_debug_state_set(int client_fd, const char *user,
			   const char *payload, const sg_request_hdr_t *hdr);
int handle_debug_state_reset(int client_fd, const char *user,
			     const char *payload, const sg_request_hdr_t *hdr);
int handle_history_save(int client_fd, const char *user,
			const char *payload, const sg_request_hdr_t *hdr);
int handle_history_load(int client_fd, const char *user,
			const char *payload, const sg_request_hdr_t *hdr);

/* ── Log handlers (defined in stargazer-mgmtd.c) ─────────────────────────── */

int handle_log_audit(int client_fd, const char *user,
		     const char *payload, const sg_request_hdr_t *hdr);
int handle_log_system(int client_fd, const char *user,
		      const char *payload, const sg_request_hdr_t *hdr);
int handle_log_clear_audit(int client_fd, const char *user,
			   const char *payload, const sg_request_hdr_t *hdr);

#endif /* MGMTD_INTERNAL_H */
