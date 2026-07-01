/* SPDX-License-Identifier: MIT */
/*
 * webd_pool.c — Thread pool for async IPC dispatch
 *
 * Fixed-size circular queue protected by mutex + condvar.
 * Workers dequeue items, perform blocking IPC, then wake the main
 * Mongoose thread via mg_wakeup() with the result.
 */

#define _GNU_SOURCE
#include "webd_pool.h"
#include "webd_ipc.h"
#include "webd_session.h"
#include "webd_api.h"
#include "stargazer_ipc.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Internal state ──────────────────────────────────────────────────── */

static struct mg_mgr    *g_mgr;
static pthread_t         workers[WEBD_POOL_SIZE];
static pthread_mutex_t   q_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t    q_cond = PTHREAD_COND_INITIALIZER;
static volatile int      q_shutdown = 0;

/* Circular queue */
static work_item_t       q_items[WEBD_QUEUE_MAX];
static int               q_head = 0;
static int               q_tail = 0;
static int               q_count = 0;

/* ── Helper: JSON-escape a string ────────────────────────────────────── */

/*
 * Escape a raw string for safe inclusion in a JSON string value.
 * Returns heap-allocated escaped string, caller frees.
 * Escapes: \ → \\, " → \", control chars → \uXXXX
 */
static char *json_escape(const char *src)
{
	if (!src) return strdup("");
	size_t slen = strlen(src);
	size_t cap = slen * 2 + 1;
	char *buf = malloc(cap);
	if (!buf) return NULL;

	size_t j = 0;
	for (size_t i = 0; i < slen; i++) {
		if (j + 8 >= cap) {
			cap *= 2;
			char *tmp = realloc(buf, cap);
			if (!tmp) { free(buf); return NULL; }
			buf = tmp;
		}
		unsigned char ch = (unsigned char)src[i];
		if (ch == '\\')     { buf[j++] = '\\'; buf[j++] = '\\'; }
		else if (ch == '"') { buf[j++] = '\\'; buf[j++] = '"'; }
		else if (ch == '\n') { buf[j++] = '\\'; buf[j++] = 'n'; }
		else if (ch == '\r') { buf[j++] = '\\'; buf[j++] = 'r'; }
		else if (ch == '\t') { buf[j++] = '\\'; buf[j++] = 't'; }
		else if (ch < 0x20) {
			j += (size_t)snprintf(buf + j, cap - j, "\\u%04x", ch);
		}
		else { buf[j++] = (char)ch; }
	}
	buf[j] = '\0';
	return buf;
}

/* ── Helper: build JSON error string ─────────────────────────────────── */

static char *json_error(const char *msg, int *http_status)
{
	char *esc_msg = json_escape(msg);
	if (!esc_msg) return NULL;
	size_t len = strlen(esc_msg) + 32;
	char *buf = malloc(len);
	if (buf)
		snprintf(buf, len, "{\"error\":\"%s\"}", esc_msg);
	free(esc_msg);
	(void)http_status;
	return buf;
}

/* ── Helper: map IPC status to HTTP status ───────────────────────────── */

static int ipc_status_to_http(uint32_t st)
{
	if (st == SG_OK)                  return 200;
	if (st == SG_ERR_INVALID_ARG)     return 400;
	if (st == SG_ERR_INVALID_VAL)     return 400;
	if (st == SG_ERR_MISSING_ARG)     return 400;
	if (st == SG_ERR_POLICY_FAIL)     return 400;
	if (st == SG_ERR_PERM_DENIED)     return 403;
	if (st == SG_ERR_AUTH_FAIL)       return 401;
	if (st == SG_ERR_LOCKED)          return 401;
	if (st == SG_ERR_SESSION_EXPIRED) return 401;
	if (st == SG_ERR_PROFILE_DENY)    return 403;
	if (st == SG_ERR_NOT_FOUND)       return 404;
	if (st == SG_ERR_USER_NOT_FOUND)  return 404;
	if (st == SG_ERR_PROFILE_NOT_FOUND) return 404;
	if (st == SG_ERR_ENTRY_NOT_FOUND) return 404;
	if (st == SG_ERR_ALREADY_EXISTS)  return 409;
	if (st == SG_ERR_IN_USE)          return 409;
	if (st == SG_ERR_BUILTIN)         return 403;
	return 500;
}

static void send_result(unsigned long conn_id, int http_status,
			char *json_data, size_t json_len)
{
	work_result_t result;
	memset(&result, 0, sizeof(result));
	result.data = json_data;
	result.data_len = json_len;
	result.http_status = http_status;
	mg_wakeup(g_mgr, conn_id, &result, sizeof(result));
	/* Note: main thread will free result.data after sending response */
}

/* Send result with extra HTTP headers (e.g. Set-Cookie) */
static void send_result_hdrs(unsigned long conn_id, int http_status,
			     char *json_data, size_t json_len,
			     const char *extra_hdrs)
{
	work_result_t result;
	memset(&result, 0, sizeof(result));
	result.data = json_data;
	result.data_len = json_len;
	result.http_status = http_status;
	if (extra_hdrs)
		snprintf(result.extra_hdrs, sizeof(result.extra_hdrs),
			 "%s", extra_hdrs);
	mg_wakeup(g_mgr, conn_id, &result, sizeof(result));
}

static void send_ipc_error(unsigned long conn_id, uint32_t status,
			   const char *extra)
{
	int http = ipc_status_to_http(status);
	/* json_error() already escapes msg via json_escape() */
	const char *msg = (extra && extra[0]) ? extra
					      : sg_status_str((sg_status_t)status);
	char *json = json_error(msg, &http);
	if (!json) json = strdup("{\"error\":\"Internal error\"}");
	size_t len = json ? strlen(json) : 0;
	send_result(conn_id, http, json, len);
}

/* ── Helper: parse key=value payload into JSON object ────────────────── */

/*
 * json_appendf — grow-to-fit formatted append into a heap buffer.
 *
 * Measures the formatted length first, grows *buf so the whole result
 * fits, then writes it. This avoids the over-read class where a fixed
 * local buffer is filled by a truncating snprintf and then copied using
 * snprintf's (un-truncated) return value as the length; it also never
 * truncates a value mid-byte, so the emitted JSON stays well-formed even
 * for arbitrarily long config values.
 *
 * Returns 0 on success, -1 on OOM (the caller still owns *buf and must
 * free it).
 */
static int json_appendf(char **buf, size_t *cap, size_t *len,
			const char *fmt, ...)
{
	va_list ap;
	int need;

	va_start(ap, fmt);
	need = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (need < 0)
		return -1;

	while (*len + (size_t)need + 1 > *cap) {
		size_t ncap = *cap * 2;
		char *tmp = realloc(*buf, ncap);
		if (!tmp)
			return -1;
		*buf = tmp;
		*cap = ncap;
	}

	va_start(ap, fmt);
	vsnprintf(*buf + *len, *cap - *len, fmt, ap);
	va_end(ap);
	*len += (size_t)need;
	return 0;
}

/*
 * Convert "key=val\nkey2=val2\n" to JSON object string.
 * If id is provided, prepends "id" field.
 * Returns heap-allocated string, caller frees.
 */
static char *kv_to_json(const char *kv, const char *id)
{
	/* Estimate size: each kv line becomes "key":"val", */
	size_t cap = 256;
	size_t len = 0;
	char *buf = malloc(cap);
	if (!buf) return NULL;

#define APPEND(s, n) do { \
	while (len + (n) >= cap) { \
		cap *= 2; \
		char *tmp = realloc(buf, cap); \
		if (!tmp) { free(buf); return NULL; } \
		buf = tmp; \
	} \
	memcpy(buf + len, (s), (n)); \
	len += (n); \
} while (0)

	APPEND("{", 1);

	if (id && id[0]) {
		char *esc_id = json_escape(id);
		if (esc_id) {
			int rc = json_appendf(&buf, &cap, &len,
					      "\"id\":\"%s\"", esc_id);
			free(esc_id);
			if (rc != 0) { free(buf); return NULL; }
		}
	}

	if (kv) {
		const char *p = kv;
		while (*p) {
			const char *nl = strchr(p, '\n');
			size_t line_len = nl ? (size_t)(nl - p) : strlen(p);
			if (line_len == 0) { p = nl ? nl + 1 : p + line_len; continue; }

			const char *eq = memchr(p, '=', line_len);
			if (!eq) { p = nl ? nl + 1 : p + line_len; continue; }

			size_t klen = (size_t)(eq - p);
			size_t vlen = line_len - klen - 1;
			const char *key = p;
			const char *val = eq + 1;

			if (len > 1) APPEND(",", 1);

			/* Escape key and value for safe JSON */
			char key_tmp[256], val_tmp[1024];
			if (klen < sizeof(key_tmp)) {
				memcpy(key_tmp, key, klen);
				key_tmp[klen] = '\0';
			} else {
				memcpy(key_tmp, key, sizeof(key_tmp) - 1);
				key_tmp[sizeof(key_tmp) - 1] = '\0';
			}
			if (vlen < sizeof(val_tmp)) {
				memcpy(val_tmp, val, vlen);
				val_tmp[vlen] = '\0';
			} else {
				memcpy(val_tmp, val, sizeof(val_tmp) - 1);
				val_tmp[sizeof(val_tmp) - 1] = '\0';
			}
			char *esc_key = json_escape(key_tmp);
			char *esc_val = json_escape(val_tmp);
			if (!esc_key || !esc_val) {
				free(esc_key);
				free(esc_val);
				p = nl ? nl + 1 : p + line_len;
				continue;
			}
			int rc = json_appendf(&buf, &cap, &len,
					      "\"%s\":\"%s\"",
					      esc_key, esc_val);
			free(esc_key);
			free(esc_val);
			if (rc != 0) { free(buf); return NULL; }

			p = nl ? nl + 1 : p + line_len;
		}
	}

	APPEND("}", 1);
	APPEND("\0", 1);
#undef APPEND

	return buf;
}

/* ── Flow handlers (called from worker threads) ──────────────────────── */

static void flow_login(work_item_t *item)
{
	/* item->payload = "username\npassword\n"
	 * item->username = target user (e.g. "admin")
	 *
	 * AUTH_LOGIN is a privileged IPC: must go as __webd (service
	 * account, trusted proxy).  The target credentials are in
	 * the payload.  SESSION_TAG_NEW goes as the target user so
	 * mgmtd creates the tag under the right identity. */

	/* Step 1: Authenticate (as __webd — privileged auth proxy) */
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_AUTH_LOGIN, "__webd",
			  0, item->payload, &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}

	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}

	/* Check for enforce-change-password / policy-mismatch flags */
	int need_change_pw = 0;
	const char *change_reason = NULL;
	if (resp.payload) {
		if (strstr(resp.payload, "enforce_change=1"))
			{ need_change_pw = 1; change_reason = "admin"; }
		if (strstr(resp.payload, "policy_mismatch=1"))
			{ need_change_pw = 1; change_reason = "policy"; }
	}
	webd_ipc_resp_free(&resp);

	/* Step 2: Acquire session tag (as target user — tag belongs
	 * to the web user, not the service account) */
	webd_ipc_response_t resp2;
	if (webd_ipc_send(SG_CMD_SESSION_TAG_NEW, item->username,
			  0, "", &resp2) != 0) {
		char *json = json_error("Session creation failed", NULL);
		send_result(item->conn_id, 500, json, json ? strlen(json) : 0);
		return;
	}

	if (resp2.status != SG_OK) {
		/* Surface mgmtd's reason rather than a generic string. */
		send_ipc_error(item->conn_id, resp2.status, resp2.extra);
		webd_ipc_resp_free(&resp2);
		return;
	}

	uint64_t tag = 0;
	if (resp2.payload)
		tag = strtoull(resp2.payload, NULL, 10);
	webd_ipc_resp_free(&resp2);

	/* Step 3: Create local session */
	char token[WEBD_TOKEN_LEN + 1];
	if (session_create_with_tag(item->username, tag, token) != 0) {
		char *json = json_error("Session creation failed", NULL);
		send_result(item->conn_id, 500, json, json ? strlen(json) : 0);
		return;
	}

	/* Set session token as HttpOnly cookie */
	char cookie_hdr[256];
	snprintf(cookie_hdr, sizeof(cookie_hdr),
		 "Set-Cookie: sg_sid=%s; HttpOnly; SameSite=Strict; "
		 "Path=/; Max-Age=3600\r\n", token);

	char *json = malloc(256);
	if (json) {
		if (need_change_pw && change_reason)
			snprintf(json, 256,
				 "{\"ok\":true,\"change_password\":true,"
				 "\"reason\":\"%s\"}",
				 change_reason);
		else
			snprintf(json, 256, "{\"ok\":true}");
	}
	send_result_hdrs(item->conn_id, 200, json, json ? strlen(json) : 0,
			 cookie_hdr);
}

static void flow_change_pw(work_item_t *item)
{
	/* item->payload = "username\nnew_password\nadmin-flag\n" */
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_AUTH_CHANGE_PW, "__webd",
			  item->session_tag, item->payload, &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}

	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}
	webd_ipc_resp_free(&resp);

	char *json = strdup("{\"ok\":true}");
	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
}

static void flow_admin_create(work_item_t *item)
{
	/* item->payload = "username\nprofile\npassword\n"
	 * Step 1: ADMIN_CREATE (username\nprofile\n)
	 * Step 2: ADMIN_SET_PW (username\nnew_password\n) */

	/* Parse fields */
	const char *p = item->payload;
	if (!p) {
		char *json = json_error("Missing payload", NULL);
		send_result(item->conn_id, 400, json, json ? strlen(json) : 0);
		return;
	}
	const char *nl1 = strchr(p, '\n');
	if (!nl1) {
		char *json = json_error("Bad format", NULL);
		send_result(item->conn_id, 400, json, json ? strlen(json) : 0);
		return;
	}
	char username[128] = {0};
	size_t ulen = (size_t)(nl1 - p);
	if (ulen >= sizeof(username)) ulen = sizeof(username) - 1;
	memcpy(username, p, ulen);

	const char *p2 = nl1 + 1;
	const char *nl2 = strchr(p2, '\n');
	char profile[128] = {0};
	size_t plen = nl2 ? (size_t)(nl2 - p2) : strlen(p2);
	if (plen >= sizeof(profile)) plen = sizeof(profile) - 1;
	memcpy(profile, p2, plen);

	char password[256] = {0};
	if (nl2) {
		const char *p3 = nl2 + 1;
		const char *nl3 = strchr(p3, '\n');
		size_t pwlen = nl3 ? (size_t)(nl3 - p3) : strlen(p3);
		if (pwlen >= sizeof(password)) pwlen = sizeof(password) - 1;
		memcpy(password, p3, pwlen);
	}

	/* Step 1: Create admin (as __webd — privileged proxy) */
	char create_payload[512];
	snprintf(create_payload, sizeof(create_payload),
		 "%s\n%s\n", username, profile);

	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_ADMIN_CREATE, item->username,
			  item->session_tag, create_payload, &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}
	webd_ipc_resp_free(&resp);

	/* Step 2: Set password if provided */
	if (password[0]) {
		char pw_payload[512];
		snprintf(pw_payload, sizeof(pw_payload),
			 "%s\n%s\n", username, password);

		webd_ipc_response_t resp2;
		if (webd_ipc_send(SG_CMD_ADMIN_SET_PW, item->username,
				  item->session_tag, pw_payload,
				  &resp2) != 0) {
			/* Admin created but password not set — still report success
			 * since the admin exists (enforce-change-password is on) */
			char *json = strdup("{\"ok\":true}");
			send_result(item->conn_id, 200, json,
				    json ? strlen(json) : 0);
			return;
		}
		if (resp2.status != SG_OK) {
			/* Admin created but password failed policy — report the
			 * policy error so the user knows */
			send_ipc_error(item->conn_id, resp2.status, resp2.extra);
			webd_ipc_resp_free(&resp2);
			return;
		}
		webd_ipc_resp_free(&resp2);
	}

	char *json = strdup("{\"ok\":true}");
	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
}

static void flow_simple(work_item_t *item)
{
	/* Simple single-IPC flow: send command, return result */
	webd_ipc_response_t resp;
	int streaming = (item->ipc_cmd == SG_CMD_NET_PING ||
			 item->ipc_cmd == SG_CMD_NET_TRACEROUTE ||
			 item->ipc_cmd == SG_CMD_NET_ARPING);

	int ret;
	if (streaming)
		ret = webd_ipc_send_stream(item->ipc_cmd, item->username,
					   item->session_tag, item->payload,
					   30, &resp);
	else
		ret = webd_ipc_send(item->ipc_cmd, item->username,
				    item->session_tag, item->payload, &resp);

	if (ret != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}

	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}

	/* If response has kv payload, convert to JSON; else just {"ok":true} */
	char *json = NULL;
	if (resp.payload && resp.payload_len > 0) {
		/* Extract entry ID from payload section (e.g. "type:id\n") */
		const char *id = NULL;
		if (item->payload) {
			const char *colon = strchr(item->payload, ':');
			if (colon) {
				id = colon + 1;
				/* Strip trailing \n for kv_to_json */
			}
		}
		/* Strip trailing \n from id if present */
		char id_buf[128] = "";
		if (id) {
			snprintf(id_buf, sizeof(id_buf), "%s", id);
			size_t il = strlen(id_buf);
			if (il > 0 && id_buf[il - 1] == '\n')
				id_buf[il - 1] = '\0';
		}
		json = kv_to_json(resp.payload, id_buf[0] ? id_buf : NULL);
	} else {
		json = strdup("{\"ok\":true}");
	}
	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
	webd_ipc_resp_free(&resp);
}

static void flow_config_list(work_item_t *item)
{
	/* item->extra = config type (e.g. "firewall_policy") */
	/* item->payload has optional search query in extra[128..] area */
	const char *type = item->extra;

	/* Step 1: List entry IDs */
	char list_payload[512];
	snprintf(list_payload, sizeof(list_payload), "%s\n", type);

	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_CFG_LIST, item->username,
			  item->session_tag, list_payload, &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}

	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}

	/* Parse list of IDs */
	char *ids[256];
	int nids = 0;
	if (resp.payload) {
		char *save = NULL;
		char *copy = strdup(resp.payload);
		if (copy) {
			for (char *tok = strtok_r(copy, "\n", &save);
			     tok && nids < 256;
			     tok = strtok_r(NULL, "\n", &save)) {
				if (tok[0])
					ids[nids++] = strdup(tok);
			}
			free(copy);
		}
	}
	webd_ipc_resp_free(&resp);

	/* Step 2: Fetch each entry */
	size_t buf_cap = 256;
	size_t buf_len = 0;
	char *buf = malloc(buf_cap);
	if (!buf) {
		for (int i = 0; i < nids; i++) free(ids[i]);
		char *json = json_error("Out of memory", NULL);
		send_result(item->conn_id, 500, json, json ? strlen(json) : 0);
		return;
	}

#define BUF_APPEND(s, n) do { \
	while (buf_len + (n) >= buf_cap) { \
		buf_cap *= 2; \
		char *tmp = realloc(buf, buf_cap); \
		if (!tmp) { free(buf); buf = NULL; goto list_done; } \
		buf = tmp; \
	} \
	memcpy(buf + buf_len, (s), (n)); \
	buf_len += (n); \
} while (0)

	BUF_APPEND("{\"entries\":[", 12);

	/* Optional search filter from payload */
	const char *search = item->payload;
	int first = 1;
	/* Hoisted so the BUF_APPEND OOM goto (which jumps to list_done) does
	 * not leak the current entry_json — list_done frees it (NULL-safe). */
	char *entry_json = NULL;

	for (int i = 0; i < nids; i++) {
		char get_payload[512];
		snprintf(get_payload, sizeof(get_payload), "%s:%s\n", type, ids[i]);

		webd_ipc_response_t entry_resp;
		if (webd_ipc_send(SG_CMD_CFG_GET, item->username,
				  item->session_tag, get_payload,
				  &entry_resp) != 0)
			continue;

		if (entry_resp.status != SG_OK) {
			webd_ipc_resp_free(&entry_resp);
			continue;
		}

		/* For system_interface, skip system-managed entries (DSA master).
		 * These have system=yes in the DB and must never appear in
		 * user-facing config lists or dropdown selects. */
		if (strcmp(type, "system_interface") == 0 &&
		    entry_resp.payload) {
			const char *kv = entry_resp.payload;
			if (strncmp(kv, "system=yes", 10) == 0 ||
			    strstr(kv, "\nsystem=yes")) {
				webd_ipc_resp_free(&entry_resp);
				continue;
			}
		}

		/* Apply search filter — check both entry ID and kv data */
		if (search && search[0]) {
			int match = 0;
			if (strcasestr(ids[i], search))
				match = 1;
			if (entry_resp.payload &&
			    strcasestr(entry_resp.payload, search))
				match = 1;
			if (!match) {
				webd_ipc_resp_free(&entry_resp);
				continue;
			}
		}

		entry_json = kv_to_json(entry_resp.payload, ids[i]);
		webd_ipc_resp_free(&entry_resp);

		if (entry_json) {
			if (!first) BUF_APPEND(",", 1);
			size_t elen = strlen(entry_json);
			BUF_APPEND(entry_json, elen);
			free(entry_json);
			entry_json = NULL;
			first = 0;
		}
	}

	BUF_APPEND("]}", 2);
	BUF_APPEND("\0", 1);

list_done:
	free(entry_json);	/* NULL unless a BUF_APPEND OOM jumped here */
	for (int i = 0; i < nids; i++) free(ids[i]);
#undef BUF_APPEND

	if (buf)
		send_result(item->conn_id, 200, buf, buf_len - 1);
	else {
		char *json = json_error("Out of memory", NULL);
		send_result(item->conn_id, 500, json, json ? strlen(json) : 0);
	}
}

static void flow_config_create(work_item_t *item)
{
	/* item->extra = config type
	 * item->payload = "type\nid\nkey=val\nkey=val\n" for APPLY
	 *   followed by \x00 then "type:id\nkey=val\n..." for SET */

	const char *apply_payload = item->payload;
	/* Find SET payload after NUL separator */
	const char *set_payload = NULL;
	if (item->payload) {
		size_t alen = strlen(item->payload);
		if (alen + 1 < item->payload_len)
			set_payload = item->payload + alen + 1;
	}

	/* Step 0: Check if entry already exists — reject duplicate create.
	 * Extract "type:id" from the SET payload (first line). */
	if (set_payload) {
		char section[512];
		const char *nl = strchr(set_payload, '\n');
		size_t slen = nl ? (size_t)(nl - set_payload) : strlen(set_payload);
		if (slen >= sizeof(section)) slen = sizeof(section) - 1;
		memcpy(section, set_payload, slen);
		section[slen] = '\0';

		char get_buf[520];
		snprintf(get_buf, sizeof(get_buf), "%s\n", section);

		webd_ipc_response_t chk;
		if (webd_ipc_send(SG_CMD_CFG_GET, item->username,
				  item->session_tag, get_buf, &chk) == 0) {
			if (chk.status == SG_OK && chk.payload_len > 0) {
				/* Entry exists — reject create */
				webd_ipc_resp_free(&chk);
				char *json = json_error(
					"Entry already exists", NULL);
				send_result(item->conn_id, 409, json,
					    json ? strlen(json) : 0);
				return;
			}
			webd_ipc_resp_free(&chk);
		}
	}

	/* Step 1: APPLY first (test run) */
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_CFG_APPLY, item->username,
			  item->session_tag, apply_payload, &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}

	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}
	webd_ipc_resp_free(&resp);

	/* Step 2: SET to persist (validates + applies + persists) */
	if (set_payload) {
		webd_ipc_response_t resp2;
		if (webd_ipc_send(SG_CMD_CFG_SET, item->username,
				  item->session_tag, set_payload,
				  &resp2) != 0) {
			char *json = json_error("Applied but save failed", NULL);
			send_result(item->conn_id, 500, json,
				    json ? strlen(json) : 0);
			return;
		}
		if (resp2.status != SG_OK) {
			/* Surface mgmtd's reason rather than a generic string. */
			send_ipc_error(item->conn_id, resp2.status, resp2.extra);
			webd_ipc_resp_free(&resp2);
			return;
		}
		webd_ipc_resp_free(&resp2);
	}

	char *json = strdup("{\"ok\":true}");
	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
}

static void flow_config_update(work_item_t *item)
{
	/* item->extra = "type:id"
	 * item->payload = JSON body key=val pairs to merge */
	const char *section = item->extra;

	/* Step 1: GET current config */
	char get_payload[512];
	snprintf(get_payload, sizeof(get_payload), "%s\n", section);

	webd_ipc_response_t get_resp;
	if (webd_ipc_send(SG_CMD_CFG_GET, item->username,
			  item->session_tag, get_payload, &get_resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (get_resp.status != SG_OK) {
		send_ipc_error(item->conn_id, get_resp.status, get_resp.extra);
		webd_ipc_resp_free(&get_resp);
		return;
	}

	/* Step 2: Merge — existing kv + new kv (new overrides existing) */
	size_t merge_cap = 4096;
	char *merged = malloc(merge_cap);
	if (!merged) {
		webd_ipc_resp_free(&get_resp);
		char *j = json_error("Out of memory", NULL);
		if (!j) j = strdup("{\"error\":\"Internal error\"}");
		send_result(item->conn_id, 500, j, j ? strlen(j) : 0);
		return;
	}
	size_t mlen = 0;

	/* Collect new keys from item->payload */
	char new_keys[64][64];
	int nk = 0;
	if (item->payload) {
		const char *p = item->payload;
		while (*p && nk < 64) {
			const char *nl = strchr(p, '\n');
			size_t ll = nl ? (size_t)(nl - p) : strlen(p);
			if (ll > 0) {
				const char *eq = memchr(p, '=', ll);
				if (eq) {
					size_t kl = (size_t)(eq - p);
					if (kl < 64) {
						memcpy(new_keys[nk], p, kl);
						new_keys[nk][kl] = '\0';
						nk++;
					}
				}
			}
			p = nl ? nl + 1 : p + ll;
		}
	}

	/* Copy existing kv, skipping keys that are in the new set */
	if (get_resp.payload) {
		const char *p = get_resp.payload;
		while (*p) {
			const char *nl = strchr(p, '\n');
			size_t ll = nl ? (size_t)(nl - p) : strlen(p);
			if (ll > 0) {
				const char *eq = memchr(p, '=', ll);
				int skip = 0;
				if (eq) {
					size_t kl = (size_t)(eq - p);
					for (int i = 0; i < nk; i++) {
						if (strlen(new_keys[i]) == kl &&
						    memcmp(new_keys[i], p, kl) == 0) {
							skip = 1;
							break;
						}
					}
				}
				if (!skip) {
					while (mlen + ll + 1 >= merge_cap) {
						merge_cap *= 2;
						char *tmp = realloc(merged, merge_cap);
						if (!tmp) {
							free(merged);
							webd_ipc_resp_free(&get_resp);
							char *j = json_error("Out of memory", NULL);
							if (!j) j = strdup("{\"error\":\"Internal error\"}");
							send_result(item->conn_id, 500, j, j ? strlen(j) : 0);
							return;
						}
						merged = tmp;
					}
					memcpy(merged + mlen, p, ll);
					mlen += ll;
					merged[mlen++] = '\n';
				}
			}
			p = nl ? nl + 1 : p + ll;
		}
	}
	webd_ipc_resp_free(&get_resp);

	/* Append new kv, skipping id= (routing key — section identifier,
	 * not a config field).  name= is a real schema field for all types
	 * (required for firewall_policy, firewall_address, firewall_service)
	 * and must NOT be stripped here. */
	if (item->payload) {
		const char *p = item->payload;
		while (*p) {
			const char *nl = strchr(p, '\n');
			size_t ll = nl ? (size_t)(nl - p) : strlen(p);
			if (ll > 0) {
				int is_routing =
					(ll > 3 && strncmp(p, "id=", 3) == 0);
				if (!is_routing) {
					while (mlen + ll + 1 >= merge_cap) {
						merge_cap *= 2;
						char *tmp = realloc(merged, merge_cap);
						if (!tmp) {
							free(merged);
							char *j = json_error("Out of memory", NULL);
							if (!j) j = strdup("{\"error\":\"Internal error\"}");
							send_result(item->conn_id, 500, j, j ? strlen(j) : 0);
							return;
						}
						merged = tmp;
					}
					memcpy(merged + mlen, p, ll);
					mlen += ll;
					merged[mlen++] = '\n';
				}
			}
			p = nl ? nl + 1 : p + ll;
		}
	}
	merged[mlen] = '\0';

	/* Extract type and id from section */
	char type[128], id[128];
	type[0] = id[0] = '\0';
	const char *colon = strchr(section, ':');
	if (colon) {
		size_t tlen = (size_t)(colon - section);
		if (tlen < sizeof(type)) {
			memcpy(type, section, tlen);
			type[tlen] = '\0';
		}
		snprintf(id, sizeof(id), "%s", colon + 1);
	}

	/* Step 3: APPLY merged config */
	size_t ap_sz = strlen(type) + 1 + strlen(id) + 1 + mlen + 1;
	char *apply_payload = malloc(ap_sz);
	if (!apply_payload) {
		free(merged);
		char *j = json_error("Out of memory", NULL);
		if (!j) j = strdup("{\"error\":\"Internal error\"}");
		send_result(item->conn_id, 500, j, j ? strlen(j) : 0);
		return;
	}
	snprintf(apply_payload, ap_sz, "%s\n%s\n%s", type, id, merged);

	webd_ipc_response_t apply_resp;
	if (webd_ipc_send(SG_CMD_CFG_APPLY, item->username,
			  item->session_tag, apply_payload,
			  &apply_resp) != 0) {
		free(apply_payload);
		free(merged);
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (apply_resp.status != SG_OK) {
		free(apply_payload);
		free(merged);
		send_ipc_error(item->conn_id, apply_resp.status,
			       apply_resp.extra);
		webd_ipc_resp_free(&apply_resp);
		return;
	}
	free(apply_payload);
	webd_ipc_resp_free(&apply_resp);

	/* Step 4: SET full merged config */
	size_t sp_sz = strlen(section) + 1 + mlen + 1;
	char *set_payload = malloc(sp_sz);
	if (!set_payload) {
		free(merged);
		char *j = json_error("Out of memory", NULL);
		if (!j) j = strdup("{\"error\":\"Internal error\"}");
		send_result(item->conn_id, 500, j, j ? strlen(j) : 0);
		return;
	}
	snprintf(set_payload, sp_sz, "%s\n%s", section, merged);
	free(merged);

	webd_ipc_response_t set_resp;
	if (webd_ipc_send(SG_CMD_CFG_SET, item->username,
			  item->session_tag, set_payload, &set_resp) != 0) {
		free(set_payload);
		char *json = json_error("Applied but save failed", NULL);
		send_result(item->conn_id, 500, json, json ? strlen(json) : 0);
		return;
	}
	free(set_payload);
	if (set_resp.status != SG_OK) {
		/* Surface mgmtd's reason rather than a generic string. */
		send_ipc_error(item->conn_id, set_resp.status, set_resp.extra);
		webd_ipc_resp_free(&set_resp);
		return;
	}
	webd_ipc_resp_free(&set_resp);

	char *json = strdup("{\"ok\":true}");
	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
}

/* ── Shared resource data collector ───────────────────────────────── */

typedef struct {
	int  cpu_pct;
	int  mem_pct;
	unsigned long mem_used_mb, mem_total_mb;
	int  disk_pct;
	unsigned long disk_used_mb, disk_total_mb;
	int  cpu_cores, cpu_mhz, temp_c;
	char load_avg[64];
} sys_resources_t;

static void fetch_resources(work_item_t *item, sys_resources_t *r)
{
	memset(r, 0, sizeof(*r));
	snprintf(r->load_avg, sizeof(r->load_avg), "0 0 0");

	webd_ipc_response_t cpu_resp, ram_resp, disk_resp;
	int cpu_ok = 0, ram_ok = 0, disk_ok = 0;

	if (webd_ipc_send(SG_CMD_DIAG_CPU, item->username,
			  item->session_tag, "", &cpu_resp) == 0 &&
	    cpu_resp.status == SG_OK)
		cpu_ok = 1;
	if (webd_ipc_send(SG_CMD_DIAG_RAM, item->username,
			  item->session_tag, "", &ram_resp) == 0 &&
	    ram_resp.status == SG_OK)
		ram_ok = 1;
	if (webd_ipc_send(SG_CMD_DIAG_DISK, item->username,
			  item->session_tag, "", &disk_resp) == 0 &&
	    disk_resp.status == SG_OK)
		disk_ok = 1;

	/* Parse RAM */
	unsigned long mem_total = 0, mem_avail = 0;
	if (ram_ok && ram_resp.payload) {
		const char *p;
		if ((p = strstr(ram_resp.payload, "MemTotal=")) != NULL)
			mem_total = strtoul(p + 9, NULL, 10);
		if ((p = strstr(ram_resp.payload, "MemAvailable=")) != NULL)
			mem_avail = strtoul(p + 13, NULL, 10);
	}
	r->mem_total_mb = mem_total / 1024;
	r->mem_used_mb = (mem_total - mem_avail) / 1024;
	r->mem_pct = mem_total ? (int)((mem_total - mem_avail) * 100 / mem_total) : 0;

	/* Parse disk */
	unsigned long disk_blocks = 0, disk_bavail = 0, disk_frsize = 0;
	if (disk_ok && disk_resp.payload) {
		const char *p;
		if ((p = strstr(disk_resp.payload, "sgdata_blocks=")) != NULL)
			disk_blocks = strtoul(p + 14, NULL, 10);
		if ((p = strstr(disk_resp.payload, "sgdata_bavail=")) != NULL)
			disk_bavail = strtoul(p + 14, NULL, 10);
		if ((p = strstr(disk_resp.payload, "sgdata_frsize=")) != NULL)
			disk_frsize = strtoul(p + 14, NULL, 10);
	}
	r->disk_total_mb = disk_blocks * disk_frsize / (1024 * 1024);
	unsigned long disk_free_mb = disk_bavail * disk_frsize / (1024 * 1024);
	r->disk_used_mb = r->disk_total_mb - disk_free_mb;
	r->disk_pct = r->disk_total_mb ? (int)(r->disk_used_mb * 100 / r->disk_total_mb) : 0;

	/* Parse CPU */
	if (cpu_ok && cpu_resp.payload) {
		const char *p;
		if ((p = strstr(cpu_resp.payload, "cpu_cores=")) != NULL)
			r->cpu_cores = atoi(p + 10);
		if ((p = strstr(cpu_resp.payload, "cpu_mhz=")) != NULL)
			r->cpu_mhz = atoi(p + 8);
		if ((p = strstr(cpu_resp.payload, "thermal_zone0=")) != NULL)
			r->temp_c = atoi(p + 14) / 1000;
		if ((p = strstr(cpu_resp.payload, "loadavg=")) != NULL) {
			snprintf(r->load_avg, sizeof(r->load_avg), "%.60s", p + 8);
			char *nl = strchr(r->load_avg, '\n');
			if (nl) *nl = '\0';
		}

		/* Compute cpu_pct from aggregate "cpu " jiffie line.
		 * Format: cpu  user nice system idle iowait irq softirq steal
		 * Since-boot average — not per-interval, but non-zero and
		 * directionally correct for a dashboard overview. */
		const char *cpuline = cpu_resp.payload;
		if (strncmp(cpuline, "cpu ", 4) == 0 ||
		    (cpuline = strstr(cpu_resp.payload, "\ncpu ")) != NULL) {
			if (*cpuline == '\n') cpuline++;
			unsigned long cu = 0, cn = 0, cs = 0, ci = 0,
				     cw = 0, cq = 0, csi = 0, cst = 0;
			sscanf(cpuline + 4, "%lu %lu %lu %lu %lu %lu %lu %lu",
			       &cu, &cn, &cs, &ci, &cw, &cq, &csi, &cst);
			unsigned long total = cu+cn+cs+ci+cw+cq+csi+cst;
			unsigned long busy = total - ci - cw;
			r->cpu_pct = total > 0
				? (int)(busy * 100 / total) : 0;
		}
	}

	if (cpu_ok) webd_ipc_resp_free(&cpu_resp);
	if (ram_ok) webd_ipc_resp_free(&ram_resp);
	if (disk_ok) webd_ipc_resp_free(&disk_resp);
}

static void flow_resources(work_item_t *item)
{
	sys_resources_t r;
	fetch_resources(item, &r);

	/* Read the active conntrack flow count from mgmtd (SG_CMD_SESSION_STATS).
	 * session_count() counts web UI logins, not network flows. */
	long long net_sessions = 0;
	webd_ipc_response_t sr = {0};   /* zero-init: webd_ipc_resp_free is always called */
	if (webd_ipc_send(SG_CMD_SESSION_STATS, item->username,
			  item->session_tag, "", &sr) == 0 &&
	    sr.status == SG_OK && sr.payload) {
		const char *kv = strstr(sr.payload, "active=");
		if (kv)
			net_sessions = strtoll(kv + 7, NULL, 10);
	}
	webd_ipc_resp_free(&sr);   /* safe: free(NULL) is a no-op when IPC failed */

	char *json = malloc(512);
	if (json)
		snprintf(json, 512,
			 "{\"cpu_pct\":%d,"
			 "\"mem_pct\":%d,"
			 "\"mem_used_mb\":%lu,"
			 "\"mem_total_mb\":%lu,"
			 "\"disk_pct\":%d,"
			 "\"disk_used_mb\":%lu,"
			 "\"disk_total_mb\":%lu,"
			 "\"sessions\":%lld,"
			 "\"sessions_max\":65536,"
			 "\"cpu_cores\":%d,"
			 "\"cpu_mhz\":%d}",
			 r.cpu_pct,
			 r.mem_pct, r.mem_used_mb, r.mem_total_mb,
			 r.disk_pct, r.disk_used_mb, r.disk_total_mb,
			 net_sessions,
			 r.cpu_cores, r.cpu_mhz);

	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
}

static void flow_resources_detail(work_item_t *item)
{
	sys_resources_t r;
	fetch_resources(item, &r);

	char *ela = json_escape(r.load_avg);
	char *json = malloc(512);
	if (json)
		snprintf(json, 512,
			 "{\"temp_c\":%d,"
			 "\"cpu_pct\":%d,"
			 "\"load_avg\":\"%s\","
			 "\"mem_pct\":%d,"
			 "\"mem_used_mb\":%lu,"
			 "\"mem_total_mb\":%lu,"
			 "\"disk_pct\":%d,"
			 "\"disk_used_mb\":%lu,"
			 "\"disk_total_mb\":%lu}",
			 r.temp_c, r.cpu_pct,
			 ela ? ela : "0 0 0",
			 r.mem_pct, r.mem_used_mb, r.mem_total_mb,
			 r.disk_pct, r.disk_used_mb, r.disk_total_mb);
	free(ela);
	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
}

static void flow_res_ram(work_item_t *item)
{
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_DIAG_RAM, item->username,
			  item->session_tag, "", &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}
	/* Parse all /proc/meminfo fields from kv response */
	long mt = 0, mf = 0, ma = 0, buf = 0, cached = 0, slab = 0;
	long st = 0, sf = 0;
	if (resp.payload) {
		const char *p;
		if ((p = strstr(resp.payload, "MemTotal=")) != NULL)     mt = atol(p + 9);
		if ((p = strstr(resp.payload, "MemFree=")) != NULL)      mf = atol(p + 8);
		if ((p = strstr(resp.payload, "MemAvailable=")) != NULL) ma = atol(p + 13);
		if ((p = strstr(resp.payload, "Buffers=")) != NULL)      buf = atol(p + 8);
		if ((p = strstr(resp.payload, "Cached=")) != NULL)       cached = atol(p + 7);
		if ((p = strstr(resp.payload, "Slab=")) != NULL)         slab = atol(p + 5);
		if ((p = strstr(resp.payload, "SwapTotal=")) != NULL)    st = atol(p + 10);
		if ((p = strstr(resp.payload, "SwapFree=")) != NULL)     sf = atol(p + 9);
	}
	webd_ipc_resp_free(&resp);

	long used = mt - ma;
	char *json = malloc(512);
	if (json)
		snprintf(json, 512,
			 "{\"total\":%ld,\"free\":%ld,\"available\":%ld,"
			 "\"used\":%ld,\"buffers\":%ld,\"cached\":%ld,"
			 "\"slab\":%ld,\"swap_total\":%ld,\"swap_used\":%ld}",
			 mt, mf, ma, used, buf, cached, slab, st, st - sf);
	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
}

static void flow_res_disk(work_item_t *item)
{
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_DIAG_DISK, item->username,
			  item->session_tag, "", &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}

	unsigned long blocks = 0, bavail = 0, frsize = 0;
	unsigned long lblocks = 0, lbavail = 0, lfrsize = 0;
	int logs_present = 0;
	unsigned long long emmc_bytes = 0;
	if (resp.payload) {
		const char *p;
		if ((p = strstr(resp.payload, "sgdata_blocks=")) != NULL) blocks = strtoul(p + 14, NULL, 10);
		if ((p = strstr(resp.payload, "sgdata_bavail=")) != NULL) bavail = strtoul(p + 14, NULL, 10);
		if ((p = strstr(resp.payload, "sgdata_frsize=")) != NULL) frsize = strtoul(p + 14, NULL, 10);
		/* sglogs_* is only emitted when /etc/stargazer/logs is a distinct
		 * mount (the large eMMC partition sg-partinit grows on first boot);
		 * absent on dev hosts / before partinit. */
		if ((p = strstr(resp.payload, "sglogs_blocks=")) != NULL) { lblocks = strtoul(p + 14, NULL, 10); logs_present = 1; }
		if ((p = strstr(resp.payload, "sglogs_bavail=")) != NULL) lbavail = strtoul(p + 14, NULL, 10);
		if ((p = strstr(resp.payload, "sglogs_frsize=")) != NULL) lfrsize = strtoul(p + 14, NULL, 10);
		if ((p = strstr(resp.payload, "emmc_bytes=")) != NULL)    emmc_bytes = strtoull(p + 11, NULL, 10);
	}
	webd_ipc_resp_free(&resp);

	unsigned long total_mb = blocks * frsize / (1024 * 1024);
	unsigned long free_mb = bavail * frsize / (1024 * 1024);
	unsigned long used_mb = total_mb - free_mb;
	unsigned long logs_total_mb = lblocks * lfrsize / (1024 * 1024);
	unsigned long logs_free_mb = lbavail * lfrsize / (1024 * 1024);
	unsigned long logs_used_mb = logs_total_mb - logs_free_mb;
	unsigned long emmc_mb = (unsigned long)(emmc_bytes / (1024 * 1024));

	char *json = malloc(320);
	if (json)
		snprintf(json, 320,
			 "{\"total_mb\":%lu,\"used_mb\":%lu,\"free_mb\":%lu,"
			 "\"emmc_mb\":%lu,\"logs_present\":%d,"
			 "\"logs_total_mb\":%lu,\"logs_used_mb\":%lu,"
			 "\"logs_free_mb\":%lu}",
			 total_mb, used_mb, free_mb, emmc_mb, logs_present,
			 logs_total_mb, logs_used_mb, logs_free_mb);
	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
}

static void flow_res_proctop(work_item_t *item)
{
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_DIAG_PROCTOP, item->username,
			  item->session_tag, "", &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}

	/* Parse uptime and process list from kv response.
	 * Format: uptime=X\nloadavg=X\nmem_total_kb=X\nmem_avail_kb=X\n
	 *         proc=PID COMM STATE UTIME STIME VSIZE RSS_KB\n...
	 * (process rows use the kv "proc=" prefix, matching mgmtd's
	 *  handle_diag_proctop emitter — see mgmtd_diag.c). */
	char uptime[64] = "0";
	long mem_total_kb = 0, mem_avail_kb = 0;

	/* Build JSON array of processes */
	size_t cap = 4096, len = 0;
	char *json = malloc(cap);
	if (!json) {
		webd_ipc_resp_free(&resp);
		char *j = json_error("Out of memory", NULL);
		send_result(item->conn_id, 500, j, j ? strlen(j) : 0);
		return;
	}

#define J_APP(s, n) do { \
	while (len + (n) >= cap) { \
		cap *= 2; \
		char *tmp = realloc(json, cap); \
		if (!tmp) { free(json); json = NULL; goto pt_done; } \
		json = tmp; \
	} \
	memcpy(json + len, (s), (n)); \
	len += (n); \
} while (0)

	if (resp.payload) {
		const char *p;
		if ((p = strstr(resp.payload, "uptime=")) != NULL) {
			const char *nl = strchr(p + 7, '\n');
			size_t l = nl ? (size_t)(nl - p - 7) : strlen(p + 7);
			if (l < sizeof(uptime)) { memcpy(uptime, p + 7, l); uptime[l] = '\0'; }
		}
		if ((p = strstr(resp.payload, "mem_total_kb=")) != NULL) mem_total_kb = atol(p + 13);
		if ((p = strstr(resp.payload, "mem_avail_kb=")) != NULL) mem_avail_kb = atol(p + 13);
	}

	char hdr[256];
	int hn = snprintf(hdr, sizeof(hdr),
			  "{\"uptime\":\"%s\",\"mem_total_kb\":%ld,"
			  "\"mem_avail_kb\":%ld,\"procs\":[",
			  uptime, mem_total_kb, mem_avail_kb);
	/* clamp to the source buffer: snprintf returns the untruncated
	 * length, copying that many bytes would over-read hdr */
	if (hn > 0) J_APP(hdr, (size_t)hn < sizeof(hdr) ? (size_t)hn : sizeof(hdr) - 1);

	/* Parse proc lines */
	int first = 1;
	if (resp.payload) {
		const char *line = resp.payload;
		while (*line) {
			const char *nl = strchr(line, '\n');
			size_t llen = nl ? (size_t)(nl - line) : strlen(line);

			if (llen > 5 && strncmp(line, "proc=", 5) == 0) {
				/* proc=PID COMM STATE UTIME STIME VSIZE RSS_KB */
				int pid = 0;
				char comm[64] = "", st = '?';
				unsigned long ut = 0, stm = 0, vsz = 0;
				long rss = 0;
				sscanf(line + 5, "%d %63s %c %lu %lu %lu %ld",
				       &pid, comm, &st, &ut, &stm, &vsz, &rss);

				char *ec = json_escape(comm);
				char frag[256];
				int fn = snprintf(frag, sizeof(frag),
					"%s{\"pid\":%d,\"name\":\"%s\","
					"\"state\":\"%c\","
					"\"cpu_ticks\":%lu,\"rss_kb\":%ld}",
					first ? "" : ",",
					pid, ec ? ec : comm, st,
					ut + stm, rss);
				free(ec);
				if (fn > 0) J_APP(frag, (size_t)fn < sizeof(frag) ? (size_t)fn : sizeof(frag) - 1);
				first = 0;
			}

			line = nl ? nl + 1 : line + llen;
		}
	}

	J_APP("]}", 2);
	J_APP("\0", 1);

pt_done:
	webd_ipc_resp_free(&resp);
#undef J_APP

	if (json)
		send_result(item->conn_id, 200, json, len > 0 ? len - 1 : 0);
	else {
		char *j = json_error("Out of memory", NULL);
		send_result(item->conn_id, 500, j, j ? strlen(j) : 0);
	}
}

/* GET /api/system/resources/percore — per-core jiffies, frequency, die temp.
 *
 * The mgmtd DIAG_CPU reply already carries the per-cpu /proc/stat lines
 * (cpu0..cpuN) plus per-core cpufreq<N>= and thermal_zone0=. We forward
 * the raw busy/total jiffie counters so the browser can compute an
 * instantaneous per-core utilisation from the delta between polls, rather
 * than a flat since-boot average. */
static void flow_res_percore(work_item_t *item)
{
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_DIAG_CPU, item->username,
			  item->session_tag, "", &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}

	/* Per-core current frequency (kHz), indexed by core number. */
	long freq_khz[64];
	for (int i = 0; i < 64; i++)
		freq_khz[i] = 0;
	/* SoC die temperature (m°C → °C); the A73 cluster shares one sensor. */
	int temp_c = 0;

	if (resp.payload) {
		const char *p;
		for (int i = 0; i < 64; i++) {
			char key[16];
			int kn = snprintf(key, sizeof(key), "cpufreq%d=", i);
			if (kn > 0 && (p = strstr(resp.payload, key)) != NULL)
				freq_khz[i] = atol(p + kn);
		}
		if ((p = strstr(resp.payload, "thermal_zone0=")) != NULL)
			temp_c = atoi(p + 14) / 1000;
	}

	size_t cap = 4096, len = 0;
	char *json = malloc(cap);
	if (!json) {
		webd_ipc_resp_free(&resp);
		char *j = json_error("Out of memory", NULL);
		send_result(item->conn_id, 500, j, j ? strlen(j) : 0);
		return;
	}

#define J_APP(s, n) do { \
	while (len + (n) >= cap) { \
		cap *= 2; \
		char *tmp = realloc(json, cap); \
		if (!tmp) { free(json); json = NULL; goto pc_done; } \
		json = tmp; \
	} \
	memcpy(json + len, (s), (n)); \
	len += (n); \
} while (0)

	char hdr[64];
	int hn = snprintf(hdr, sizeof(hdr),
			  "{\"temp_c\":%d,\"cores\":[", temp_c);
	if (hn > 0) J_APP(hdr, (size_t)hn < sizeof(hdr) ? (size_t)hn : sizeof(hdr) - 1);

	int first = 1;
	if (resp.payload) {
		const char *line = resp.payload;
		while (*line) {
			const char *nl = strchr(line, '\n');
			size_t llen = nl ? (size_t)(nl - line) : strlen(line);

			/* Per-core line: "cpu<N> user nice system idle ..."
			 * (skip the aggregate "cpu " line — no digit). */
			if (llen > 3 && strncmp(line, "cpu", 3) == 0 &&
			    isdigit((unsigned char)line[3])) {
				int core = atoi(line + 3);
				const char *f = line + 3;
				while (*f && *f != ' ') f++;   /* past cpuN */
				unsigned long u=0, n=0, s=0, idle=0, w=0,
					      irq=0, sirq=0, steal=0;
				sscanf(f, "%lu %lu %lu %lu %lu %lu %lu %lu",
				       &u, &n, &s, &idle, &w, &irq, &sirq, &steal);
				unsigned long total = u+n+s+idle+w+irq+sirq+steal;
				unsigned long busy  = total - idle - w;

				long fk = (core >= 0 && core < 64)
					? freq_khz[core] : 0;
				char frag[160];
				int fn = snprintf(frag, sizeof(frag),
					"%s{\"core\":%d,\"busy\":%lu,"
					"\"total\":%lu,\"freq_mhz\":%ld,"
					"\"temp_c\":%d}",
					first ? "" : ",",
					core, busy, total,
					fk / 1000, temp_c);
				if (fn > 0) J_APP(frag, (size_t)fn < sizeof(frag) ? (size_t)fn : sizeof(frag) - 1);
				first = 0;
			}

			line = nl ? nl + 1 : line + llen;
		}
	}

	J_APP("]}", 2);
	J_APP("\0", 1);

pc_done:
	webd_ipc_resp_free(&resp);
#undef J_APP

	if (json)
		send_result(item->conn_id, 200, json, len > 0 ? len - 1 : 0);
	else {
		char *j = json_error("Out of memory", NULL);
		send_result(item->conn_id, 500, j, j ? strlen(j) : 0);
	}
}

static void flow_diagnose(work_item_t *item)
{
	/* item->ipc_cmd is the diag command (PING, TRACEROUTE, etc.)
	 * item->payload = "target=X\n" or "target=X\niface=Y\n" */

	int streaming = (item->ipc_cmd == SG_CMD_NET_PING ||
			 item->ipc_cmd == SG_CMD_NET_TRACEROUTE ||
			 item->ipc_cmd == SG_CMD_NET_ARPING);

	webd_ipc_response_t resp;
	int ret;
	if (streaming)
		ret = webd_ipc_send_stream(item->ipc_cmd, item->username,
					   item->session_tag, item->payload,
					   30, &resp);
	else
		ret = webd_ipc_send(item->ipc_cmd, item->username,
				    item->session_tag, item->payload, &resp);

	if (ret != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}

	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}

	/* Escape output for JSON */
	size_t raw_len = resp.payload ? resp.payload_len : 0;
	size_t esc_cap = raw_len * 2 + 64;
	char *json = malloc(esc_cap);
	if (json) {
		size_t pos = 0;
		pos += (size_t)snprintf(json + pos, esc_cap - pos,
					"{\"output\":\"");
		if (resp.payload) {
			for (size_t i = 0; i < raw_len && pos + 8 < esc_cap; i++) {
				char ch = resp.payload[i];
				if (ch == '"') { json[pos++] = '\\'; json[pos++] = '"'; }
				else if (ch == '\\') { json[pos++] = '\\'; json[pos++] = '\\'; }
				else if (ch == '\n') { json[pos++] = '\\'; json[pos++] = 'n'; }
				else if (ch == '\r') { json[pos++] = '\\'; json[pos++] = 'r'; }
				else if (ch == '\t') { json[pos++] = '\\'; json[pos++] = 't'; }
				else if ((unsigned char)ch >= 0x20) { json[pos++] = ch; }
			}
		}
		pos += (size_t)snprintf(json + pos, esc_cap - pos, "\"}");
		send_result(item->conn_id, 200, json, pos);
	} else {
		char *j = json_error("Out of memory", NULL);
		send_result(item->conn_id, 500, j, j ? strlen(j) : 0);
	}
	webd_ipc_resp_free(&resp);
}

static void flow_firmware_info(work_item_t *item)
{
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_UPGRADE_STATUS, item->username,
			  item->session_tag, "", &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}

	/* Parse version from response */
	char version[64] = "unknown";
	if (resp.payload) {
		const char *p = strstr(resp.payload, "Running version: ");
		if (p) {
			p += 17;
			const char *nl = strchr(p, '\n');
			size_t vlen = nl ? (size_t)(nl - p) : strlen(p);
			if (vlen < sizeof(version)) {
				memcpy(version, p, vlen);
				version[vlen] = '\0';
			}
		}
	}

	/* Parse additional fields from response if available */
	char kernel[64] = "";
	if (resp.payload) {
		const char *kp = strstr(resp.payload, "Kernel version: ");
		if (kp) {
			kp += 16;
			const char *nl = strchr(kp, '\n');
			size_t klen = nl ? (size_t)(nl - kp) : strlen(kp);
			if (klen < sizeof(kernel)) {
				memcpy(kernel, kp, klen);
				kernel[klen] = '\0';
			}
		}
	}

	char *esc_ver = json_escape(version);
	char *esc_ker = json_escape(kernel);
	char *json = malloc(512);
	if (json)
		snprintf(json, 512,
			 "{\"version\":\"%s\",\"build\":\"arm64\","
			 "\"kernel\":\"%s\",\"installed\":\"N/A\"}",
			 esc_ver ? esc_ver : version,
			 esc_ker ? esc_ker : "");
	free(esc_ver);
	free(esc_ker);
	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
	webd_ipc_resp_free(&resp);
}

static void flow_firmware_progress(work_item_t *item)
{
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_UPGRADE_PROGRESS, item->username,
			  item->session_tag, "", &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}

	/* Parse step/total/message */
	int step = 0, total = 1;
	char message[256] = "";
	char status_str[32] = "running";
	if (resp.payload) {
		const char *p;
		if ((p = strstr(resp.payload, "step=")) != NULL)
			step = atoi(p + 5);
		if ((p = strstr(resp.payload, "total=")) != NULL)
			total = atoi(p + 6);
		if ((p = strstr(resp.payload, "message=")) != NULL) {
			const char *nl = strchr(p + 8, '\n');
			size_t mlen = nl ? (size_t)(nl - p - 8) : strlen(p + 8);
			if (mlen < sizeof(message)) {
				memcpy(message, p + 8, mlen);
				message[mlen] = '\0';
			}
		}
		if ((p = strstr(resp.payload, "status=")) != NULL) {
			const char *nl = strchr(p + 7, '\n');
			size_t slen = nl ? (size_t)(nl - p - 7) : strlen(p + 7);
			if (slen < sizeof(status_str)) {
				memcpy(status_str, p + 7, slen);
				status_str[slen] = '\0';
			}
		}
	}

	if (total < 1) total = 1;
	int percent = step * 100 / total;
	int done    = (strcmp(status_str, "done") == 0 ||
		       strcmp(status_str, "error") == 0);
	int is_err  = (strcmp(status_str, "error") == 0);

	char *esc_msg = json_escape(message);
	char *esc_sts = json_escape(status_str);
	char *json = malloc(512);
	if (json)
		snprintf(json, 512,
			 "{\"percent\":%d,\"done\":%s,\"error\":%s,"
			 "\"status\":\"%s\",\"message\":\"%s\"}",
			 percent, done ? "true" : "false",
			 is_err ? "true" : "false",
			 esc_sts ? esc_sts : "",
			 esc_msg ? esc_msg : "");
	free(esc_msg);
	free(esc_sts);
	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
	webd_ipc_resp_free(&resp);
}

static void flow_iface_live(work_item_t *item)
{
	/* Call SG_CMD_SHOW_IFACES and parse the fixed-width text table into
	 * a JSON array so the web UI can overlay live operstate on the
	 * config-DB interface list. */
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_SHOW_IFACES, item->username,
			  item->session_tag, "", &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}

	/* Parse "Name             Status   IP                    Description"
	 * table — skip header line, then split each row on whitespace. */
	size_t cap = 512, len = 0;
	char *json = malloc(cap);
	if (!json) {
		webd_ipc_resp_free(&resp);
		char *j = json_error("Out of memory", NULL);
		send_result(item->conn_id, 500, j, j ? strlen(j) : 0);
		return;
	}

#define IL_APP(s, n) do { \
	while (len + (n) >= cap) { \
		cap *= 2; \
		char *tmp = realloc(json, cap); \
		if (!tmp) { free(json); json = NULL; goto il_done; } \
		json = tmp; \
	} \
	memcpy(json + len, (s), (n)); \
	len += (n); \
} while (0)

	IL_APP("{\"interfaces\":[", 15);

	int first = 1;
	int header_skipped = 0;
	const char *p = resp.payload ? resp.payload : "";
	while (*p) {
		const char *nl = strchr(p, '\n');
		size_t llen = nl ? (size_t)(nl - p) : strlen(p);

		/* Skip the header row (starts with "Name") */
		if (!header_skipped) {
			header_skipped = 1;
			p = nl ? nl + 1 : p + llen;
			continue;
		}
		if (llen == 0) { p = nl ? nl + 1 : p + llen; continue; }

		/* Parse: name(16) status(8) ip(21) ... — split on spaces */
		char row[256];
		if (llen >= sizeof(row)) llen = sizeof(row) - 1;
		memcpy(row, p, llen);
		row[llen] = '\0';

		char name[32] = "", status[16] = "", ip[32] = "-";
		sscanf(row, "%31s %15s %31s", name, status, ip);

		if (!name[0]) { p = nl ? nl + 1 : p + llen; continue; }

		/* Normalise lowerlayerdown → down */
		if (strcmp(status, "lowerlayerdown") == 0)
			snprintf(status, sizeof(status), "down");

		char *en = json_escape(name);
		char *es = json_escape(status);
		char *ei = json_escape(ip);
		if (!en || !es || !ei) { free(en); free(es); free(ei); goto il_done; }

		char frag[256];
		int fn = snprintf(frag, sizeof(frag),
				  "%s{\"name\":\"%s\",\"status\":\"%s\",\"ip\":\"%s\"}",
				  first ? "" : ",", en, es, ei);
		free(en); free(es); free(ei);
		if (fn > 0) IL_APP(frag, (size_t)fn < sizeof(frag) ? (size_t)fn : sizeof(frag) - 1);
		first = 0;

		p = nl ? nl + 1 : p + llen;
	}

	IL_APP("]}", 2);
	IL_APP("\0", 1);

il_done:
	webd_ipc_resp_free(&resp);
#undef IL_APP

	if (json)
		send_result(item->conn_id, 200, json, len > 0 ? len - 1 : 0);
	else {
		char *j = json_error("Out of memory", NULL);
		send_result(item->conn_id, 500, j, j ? strlen(j) : 0);
	}
}

static void flow_firmware_upload(work_item_t *item)
{
	/* item->payload = "path=/tmp/sg-fw-upload.<rand>\n" (per-upload file).
	 * On the success path mgmtd consumes and removes the staged file; on a
	 * failure path it may never have received or finished it, so remove it
	 * here. Parse the path out for the failure cleanup. */
	char stage[96] = {0};
	if (item->payload && strncmp(item->payload, "path=", 5) == 0) {
		snprintf(stage, sizeof(stage), "%s", item->payload + 5);
		char *nl = strchr(stage, '\n');
		if (nl) *nl = '\0';
	}

	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_UPGRADE_FROM_FILE, item->username,
			  item->session_tag,
			  item->payload ? item->payload : "", &resp) != 0) {
		if (stage[0]) unlink(stage);	/* mgmtd never got the file */
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		if (stage[0]) unlink(stage);	/* upgrade rejected/failed */
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}
	webd_ipc_resp_free(&resp);
	char *json = strdup("{\"ok\":true}");
	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
}

static void flow_cert_import(work_item_t *item)
{
	/* item->payload = "name=<n>\ncert=/tmp/sg-cert.<r>\nkey=/tmp/sg-key.<r>\n..."
	 * On success mgmtd consumes + removes the staged files; on any failure path
	 * remove them here so /tmp does not accumulate uploads. */
	char cstage[96] = {0}, kstage[96] = {0};
	if (item->payload) {
		const char *p;
		if ((p = strstr(item->payload, "cert=")) != NULL) {
			snprintf(cstage, sizeof(cstage), "%s", p + 5);
			char *nl = strchr(cstage, '\n'); if (nl) *nl = '\0';
		}
		if ((p = strstr(item->payload, "\nkey=")) != NULL) {
			snprintf(kstage, sizeof(kstage), "%s", p + 5);
			char *nl = strchr(kstage, '\n'); if (nl) *nl = '\0';
		}
	}

	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_CERT_IMPORT, item->username,
			  item->session_tag,
			  item->payload ? item->payload : "", &resp) != 0) {
		if (cstage[0]) unlink(cstage);
		if (kstage[0]) unlink(kstage);
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		if (cstage[0]) unlink(cstage);
		if (kstage[0]) unlink(kstage);
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}
	/* Success: mgmtd copied the PEM into the store but does NOT remove our
	 * staged /tmp uploads (the CLI path reuses the same handler with the user's
	 * own files) — so clean them up here. */
	if (cstage[0]) unlink(cstage);
	if (kstage[0]) unlink(kstage);
	webd_ipc_resp_free(&resp);
	char *json = strdup("{\"ok\":true}");
	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
}

static void flow_reboot(work_item_t *item)
{
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_SYS_REBOOT, item->username,
			  item->session_tag, item->payload ? item->payload : "",
			  &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}
	webd_ipc_resp_free(&resp);

	char *json = strdup("{\"ok\":true,\"message\":\"Rebooting...\"}");
	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
}

static void flow_whoami(work_item_t *item)
{
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_WHOAMI, item->username,
			  item->session_tag, "", &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}

	/* Parse profile and permissions from response */
	char profile[64] = "", permissions[256] = "";
	if (resp.payload) {
		const char *p;
		if ((p = strstr(resp.payload, "profile=")) != NULL) {
			const char *nl = strchr(p + 8, '\n');
			size_t l = nl ? (size_t)(nl - p - 8) : strlen(p + 8);
			if (l < sizeof(profile)) { memcpy(profile, p + 8, l); profile[l] = '\0'; }
		}
		if ((p = strstr(resp.payload, "permissions=")) != NULL) {
			const char *nl = strchr(p + 12, '\n');
			size_t l = nl ? (size_t)(nl - p - 12) : strlen(p + 12);
			if (l < sizeof(permissions)) { memcpy(permissions, p + 12, l); permissions[l] = '\0'; }
		}
	}

	char *eu = json_escape(item->username);
	char *ep = json_escape(profile);
	char *epm = json_escape(permissions);
	char *json = malloc(512);
	if (json)
		snprintf(json, 512,
			 "{\"username\":\"%s\",\"profile\":\"%s\","
			 "\"permissions\":\"%s\"}",
			 eu ? eu : "", ep ? ep : "", epm ? epm : "");
	free(eu); free(ep); free(epm);
	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
	webd_ipc_resp_free(&resp);
}

/* Helper: extract value of "key=value" from a space-delimited line.
 * Copies into dst (len bytes), returns dst or "" if not found. */
static const char *kv_extract(const char *line, const char *key,
			       char *dst, size_t len)
{
	dst[0] = '\0';
	size_t klen = strlen(key);
	const char *p = line;
	while (*p) {
		if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
			p += klen + 1;
			size_t i = 0;
			while (*p && *p != ' ' && *p != '\n' && i + 1 < len)
				dst[i++] = *p++;
			dst[i] = '\0';
			return dst;
		}
		/* advance to next word */
		while (*p && *p != ' ' && *p != '\n') p++;
		while (*p == ' ') p++;
	}
	return dst;
}

/* GET /api/monitor/ips — IPS daemon status (key=value → JSON object). */
static void flow_ips_status(work_item_t *item)
{
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_IPS_STATUS, item->username,
			  item->session_tag, "", &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}
	/* resp.payload is "status=...\nmode=...\n..." → kv_to_json gives a flat object. */
	char *json = kv_to_json(resp.payload ? resp.payload : "", NULL);
	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
	webd_ipc_resp_free(&resp);
}

/* GET /api/monitor/ips-alerts — recent IPS alert log lines (raw → {"output":...}). */
static void flow_ips_alerts(work_item_t *item)
{
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_IPS_ALERTS, item->username,
			  item->session_tag,
			  item->payload ? item->payload : "", &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}
	/* Wrap raw log text as {"output":"..."} (same shape as flow_diagnose). */
	size_t raw_len = resp.payload ? resp.payload_len : 0;
	size_t esc_cap = raw_len * 2 + 64;
	char *json = malloc(esc_cap);
	if (json) {
		size_t pos = 0;
		pos += (size_t)snprintf(json + pos, esc_cap - pos, "{\"output\":\"");
		if (resp.payload) {
			for (size_t i = 0; i < raw_len && pos + 8 < esc_cap; i++) {
				char ch = resp.payload[i];
				if (ch == '"')       { json[pos++] = '\\'; json[pos++] = '"'; }
				else if (ch == '\\') { json[pos++] = '\\'; json[pos++] = '\\'; }
				else if (ch == '\n') { json[pos++] = '\\'; json[pos++] = 'n'; }
				else if (ch == '\r') { json[pos++] = '\\'; json[pos++] = 'r'; }
				else if (ch == '\t') { json[pos++] = '\\'; json[pos++] = 't'; }
				else if ((unsigned char)ch >= 0x20) { json[pos++] = ch; }
			}
		}
		pos += (size_t)snprintf(json + pos, esc_cap - pos, "\"}");
		send_result(item->conn_id, 200, json, pos);
	} else {
		char *j = json_error("Out of memory", NULL);
		send_result(item->conn_id, 500, j, j ? strlen(j) : 0);
	}
	webd_ipc_resp_free(&resp);
}

/* GET /api/ips/alerts-json — mgmtd returns a READY JSON array [{...}]. Send it
 * verbatim, NOT through flow_simple/kv_to_json (which assumes payload is
 * key=value → would mangle it). */
static void flow_ips_alerts_json(work_item_t *item)
{
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_IPS_ALERTS_JSON, item->username,
			  item->session_tag,
			  item->payload ? item->payload : "", &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}
	if (resp.payload && resp.payload_len > 0) {
		char *body = malloc(resp.payload_len + 1);
		if (body) {
			memcpy(body, resp.payload, resp.payload_len);
			body[resp.payload_len] = '\0';
			send_result(item->conn_id, 200, body, resp.payload_len);
		} else {
			char *j = json_error("Out of memory", NULL);
			send_result(item->conn_id, 500, j, j ? strlen(j) : 0);
		}
	} else {
		send_result(item->conn_id, 200, strdup("[]"), 2);
	}
	webd_ipc_resp_free(&resp);
}

/* GET /api/ips/signatures — signature catalog (mgmtd returns a ready JSON object
 * {items,truncated}). payload carries "q=<keyword>" for server-side filtering. */
static void flow_ips_signatures(work_item_t *item)
{
	webd_ipc_response_t resp;
	const char *q = item->payload ? item->payload : "";
	if (webd_ipc_send(SG_CMD_IPS_SIGNATURES, item->username,
			  item->session_tag, q, &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}
	/* payload is already a JSON object → send verbatim (item->payload freed by dispatcher) */
	const char *body = resp.payload ? resp.payload : "{\"items\":[],\"truncated\":0}";
	char *out = strdup(body);
	send_result(item->conn_id, 200, out, out ? strlen(out) : 0);
	webd_ipc_resp_free(&resp);
}

static void flow_session_clear(work_item_t *item)
{
	/* SG_CMD_SESSION_CLEAR with a filter or tuples= batch payload. A
	 * dedicated handler (not flow_simple): flow_simple sniffs an entry id
	 * from the first ':' in the payload, which would mangle the ':' inside
	 * a src/dst ip:port. The mgmtd reply is flat key=value
	 * (mode/matched/deleted/failed/dump_complete) → kv_to_json verbatim. */
	webd_ipc_response_t resp;
	if (webd_ipc_send(item->ipc_cmd, item->username,
			  item->session_tag, item->payload, &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		/* 403 admin / 400 bad filter — surface mgmtd's reason verbatim. */
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}
	char *json = kv_to_json(resp.payload ? resp.payload : "", NULL);
	send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
	webd_ipc_resp_free(&resp);
}

static void flow_monitor_sessions(work_item_t *item)
{
	/* Call SG_CMD_SHOW_SESSIONS; parse the procfs text into JSON. */
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_SHOW_SESSIONS, item->username,
			  item->session_tag, "", &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK ||
	    strcmp(resp.extra, "not_available") == 0) {
		/* conntrack unavailable → empty result, not an error */
		char *j = strdup("{\"active\":0,\"loaded\":false,\"sessions\":[]}");
		send_result(item->conn_id, 200, j, j ? strlen(j) : 0);
		webd_ipc_resp_free(&resp);
		return;
	}

	const char *text = resp.payload ? resp.payload : "";

	/* Header line: "active=N" (conntrack flow count). */
	long long active = 0;
	const char *hdr = strstr(text, "active=");
	if (hdr) {
		char tmp[32];
		kv_extract(hdr, "active", tmp, sizeof(tmp));
		active = strtoll(tmp, NULL, 10);
	}

	/* Build JSON output */
	size_t cap = 8192, pos = 0;
	char *json = malloc(cap);
	if (!json) {
		webd_ipc_resp_free(&resp);
		char *j = json_error("Out of memory", NULL);
		send_result(item->conn_id, 500, j, j ? strlen(j) : 0);
		return;
	}

#define SJ_APP(s, n) do { \
	while (pos + (n) + 1 >= cap) { \
		cap *= 2; char *_t = realloc(json, cap); \
		if (!_t) { free(json); webd_ipc_resp_free(&resp); \
			char *_j = json_error("Out of memory", NULL); \
			send_result(item->conn_id, 500, _j, _j ? strlen(_j) : 0); \
			return; } \
		json = _t; } \
	memcpy(json + pos, (s), (n)); pos += (n); \
} while (0)

	char hbuf[96];
	int hlen = snprintf(hbuf, sizeof(hbuf),
		"{\"active\":%lld,\"loaded\":true,\"sessions\":[", active);
	if (hlen > 0) SJ_APP(hbuf, (size_t)hlen);

	/* Parse session rows — skip lines starting with '#' */
	int first = 1;
	const char *p = text;
	while (*p) {
		const char *nl = strchr(p, '\n');
		size_t ll = nl ? (size_t)(nl - p) : strlen(p);

		if (ll == 0 || p[0] == '#') {
			p = nl ? nl + 1 : p + ll;
			continue;
		}

		/* Copy line for kv_extract */
		char line[512];
		size_t cp = ll < sizeof(line) - 1 ? ll : sizeof(line) - 1;
		memcpy(line, p, cp);
		line[cp] = '\0';

		char proto[12], state[24], src[64], dst[64], pkts[32], bytes[32];
		char policy[64], iif[24], oif[24];

		kv_extract(line, "proto",  proto,  sizeof(proto));
		kv_extract(line, "state",  state,  sizeof(state));
		kv_extract(line, "src",    src,    sizeof(src));
		kv_extract(line, "dst",    dst,    sizeof(dst));
		kv_extract(line, "pkts",   pkts,   sizeof(pkts));
		kv_extract(line, "bytes",  bytes,  sizeof(bytes));
		kv_extract(line, "policy", policy, sizeof(policy));
		kv_extract(line, "iif",    iif,    sizeof(iif));
		kv_extract(line, "oif",    oif,    sizeof(oif));

		if (!proto[0]) {
			p = nl ? nl + 1 : p + ll;
			continue;
		}
		if (!policy[0]) { policy[0] = '-'; policy[1] = '\0'; }
		if (!iif[0])    { iif[0]    = '-'; iif[1]    = '\0'; }
		if (!oif[0])    { oif[0]    = '-'; oif[1]    = '\0'; }

		if (!first) SJ_APP(",", 1);
		first = 0;

		char entry[448];
		int elen = snprintf(entry, sizeof(entry),
			"{\"proto\":\"%s\",\"state\":\"%s\",\"src\":\"%s\","
			"\"dst\":\"%s\",\"pkts\":\"%s\",\"bytes\":\"%s\","
			"\"policy\":\"%s\",\"iif\":\"%s\",\"oif\":\"%s\"}",
			proto, state, src, dst, pkts, bytes, policy, iif, oif);
		if (elen > 0 && (size_t)elen < sizeof(entry))
			SJ_APP(entry, (size_t)elen);

		p = nl ? nl + 1 : p + ll;
	}

	SJ_APP("]}", 2);
	json[pos] = '\0';

	send_result(item->conn_id, 200, json, pos);
	webd_ipc_resp_free(&resp);
}

static void flow_monitor_dhcp(work_item_t *item)
{
	/* Call SG_CMD_DIAG_DHCP_LEASES; mgmtd returns JSON directly. */
	webd_ipc_response_t resp;
	if (webd_ipc_send(SG_CMD_DIAG_DHCP_LEASES, item->username,
			  item->session_tag, "", &resp) != 0) {
		char *json = json_error("Backend unavailable", NULL);
		send_result(item->conn_id, 502, json, json ? strlen(json) : 0);
		return;
	}
	if (resp.status != SG_OK) {
		send_ipc_error(item->conn_id, resp.status, resp.extra);
		webd_ipc_resp_free(&resp);
		return;
	}

	if (resp.payload && resp.payload_len > 0) {
		char *json = malloc(resp.payload_len + 1);
		if (json) {
			memcpy(json, resp.payload, resp.payload_len);
			json[resp.payload_len] = '\0';
			send_result(item->conn_id, 200, json, resp.payload_len);
		} else {
			char *j = json_error("Out of memory", NULL);
			send_result(item->conn_id, 500, j, j ? strlen(j) : 0);
		}
	} else {
		char *json = strdup("{\"leases\":[]}");
		send_result(item->conn_id, 200, json, json ? strlen(json) : 0);
	}
	webd_ipc_resp_free(&resp);
}

/* ── Worker thread entry point ───────────────────────────────────────── */

static void *worker_fn(void *arg)
{
	(void)arg;

	for (;;) {
		pthread_mutex_lock(&q_lock);

		while (q_count == 0 && !q_shutdown)
			pthread_cond_wait(&q_cond, &q_lock);

		if (q_shutdown && q_count == 0) {
			pthread_mutex_unlock(&q_lock);
			break;
		}

		/* Dequeue */
		work_item_t item = q_items[q_head];
		q_head = (q_head + 1) % WEBD_QUEUE_MAX;
		q_count--;

		pthread_mutex_unlock(&q_lock);

		/* Dispatch by flow type */
		switch (item.flow_type) {
		case FLOW_MONITOR_DHCP:     flow_monitor_dhcp(&item);     break;
		case FLOW_MONITOR_SESSIONS: flow_monitor_sessions(&item); break;
		case FLOW_SESSION_CLEAR:    flow_session_clear(&item);    break;
		case FLOW_CERT_IMPORT:      flow_cert_import(&item);      break;
		case FLOW_IPS_STATUS:       flow_ips_status(&item);       break;
		case FLOW_IPS_ALERTS:       flow_ips_alerts(&item);       break;
		case FLOW_IPS_SIGS:         flow_ips_signatures(&item);   break;
		case FLOW_IPS_UPDATE:       flow_diagnose(&item);         break;
		case FLOW_IPS_ALERTS_JSON:  flow_ips_alerts_json(&item);   break;
		case FLOW_IPS_UPDATE_LOG:   flow_diagnose(&item);         break;
		case FLOW_LOGIN:         flow_login(&item);           break;
		case FLOW_CONFIG_LIST:   flow_config_list(&item);     break;
		case FLOW_CONFIG_CREATE: flow_config_create(&item);   break;
		case FLOW_CONFIG_UPDATE: flow_config_update(&item);   break;
		case FLOW_RESOURCES:     flow_resources(&item);       break;
		case FLOW_RESOURCES_DET: flow_resources_detail(&item);break;
		case FLOW_DIAGNOSE:      flow_diagnose(&item);        break;
		case FLOW_FIRMWARE_INFO: flow_firmware_info(&item);    break;
		case FLOW_FIRMWARE_PROG: flow_firmware_progress(&item);break;
		case FLOW_REBOOT:        flow_reboot(&item);          break;
		case FLOW_WHOAMI:        flow_whoami(&item);          break;
		case FLOW_CHANGE_PW:    flow_change_pw(&item);       break;
		case FLOW_RES_RAM:      flow_res_ram(&item);         break;
		case FLOW_RES_DISK:     flow_res_disk(&item);        break;
		case FLOW_RES_PROCTOP:  flow_res_proctop(&item);     break;
		case FLOW_RES_PERCORE:  flow_res_percore(&item);     break;
		case FLOW_ADMIN_CREATE: flow_admin_create(&item);    break;
		case FLOW_CONFIG_MOVE:    flow_simple(&item);           break;
		case FLOW_IFACE_LIVE:     flow_iface_live(&item);      break;
		case FLOW_FIRMWARE_UPLOAD: flow_firmware_upload(&item); break;
		default:                  flow_simple(&item);           break;
		}

		free(item.payload);
	}

	return NULL;
}

/* ── Public API ──────────────────────────────────────────────────────── */

void webd_pool_init(struct mg_mgr *mgr)
{
	g_mgr = mgr;

	for (int i = 0; i < WEBD_POOL_SIZE; i++) {
		if (pthread_create(&workers[i], NULL, worker_fn, NULL) != 0) {
			fprintf(stderr, "webd: failed to create worker %d\n", i);
		}
	}
}

int webd_pool_enqueue(work_item_t *item)
{
	pthread_mutex_lock(&q_lock);

	if (q_count >= WEBD_QUEUE_MAX) {
		pthread_mutex_unlock(&q_lock);
		return -1;
	}

	q_items[q_tail] = *item;
	q_tail = (q_tail + 1) % WEBD_QUEUE_MAX;
	q_count++;

	pthread_cond_signal(&q_cond);
	pthread_mutex_unlock(&q_lock);

	return 0;
}

void webd_pool_shutdown(void)
{
	pthread_mutex_lock(&q_lock);
	q_shutdown = 1;
	pthread_cond_broadcast(&q_cond);
	pthread_mutex_unlock(&q_lock);

	for (int i = 0; i < WEBD_POOL_SIZE; i++)
		pthread_join(workers[i], NULL);
}
