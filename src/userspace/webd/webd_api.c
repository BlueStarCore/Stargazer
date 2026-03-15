/* SPDX-License-Identifier: MIT */
/*
 * webd_api.c — REST API route dispatch for stargazer-webd
 *
 * Routes API requests to the thread pool as work items.
 * Login rate limiting is checked in the main thread before dispatch.
 */

#define _GNU_SOURCE
#include "webd_api.h"
#include "webd_pool.h"
#include "webd_session.h"
#include "webd_ipc.h"
#include "stargazer_ipc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Login rate limiter ──────────────────────────────────────────────── */

#define RATE_LIMIT_MAX     10   /* max attempts per second */
static int    rate_count = 0;
static time_t rate_window = 0;

static int rate_limit_check(void)
{
	time_t now = time(NULL);
	if (now != rate_window) {
		rate_window = now;
		rate_count = 0;
	}
	rate_count++;
	return (rate_count > RATE_LIMIT_MAX) ? -1 : 0;
}

/* ── Helpers ─────────────────────────────────────────────────────────── */

static void reply_json(struct mg_connection *c, int status, const char *json)
{
	mg_http_reply(c, status, webd_sec_headers(), "%s", json);
}

static int mg_str_eq(struct mg_str a, const char *b)
{
	size_t blen = strlen(b);
	return (a.len == blen && memcmp(a.buf, b, blen) == 0);
}

/*
 * Extract session token from Authorization header or sg_sid cookie.
 * Checks Bearer header first, then falls back to HttpOnly cookie.
 * Returns pointer to buf (NUL-terminated token), or NULL.
 */
static const char *extract_bearer(struct mg_http_message *hm,
				  char *buf, size_t bufsz)
{
	/* Try Authorization: Bearer header first */
	struct mg_str *auth = mg_http_get_header(hm, "Authorization");
	if (auth && auth->len >= 8 &&
	    memcmp(auth->buf, "Bearer ", 7) == 0) {
		size_t tlen = auth->len - 7;
		if (tlen < bufsz) {
			memcpy(buf, auth->buf + 7, tlen);
			buf[tlen] = '\0';
			return buf;
		}
	}

	/* Fallback: parse sg_sid from Cookie header */
	struct mg_str *cookie = mg_http_get_header(hm, "Cookie");
	if (cookie && cookie->len > 0) {
		const char *p = cookie->buf;
		const char *end = cookie->buf + cookie->len;
		const char *needle = "sg_sid=";
		size_t nlen = 7;

		while (p < end) {
			/* Skip whitespace */
			while (p < end && (*p == ' ' || *p == ';')) p++;
			if (p >= end) break;

			if ((size_t)(end - p) >= nlen &&
			    memcmp(p, needle, nlen) == 0) {
				p += nlen;
				const char *ve = memchr(p, ';',
							(size_t)(end - p));
				size_t vlen = ve ? (size_t)(ve - p)
					        : (size_t)(end - p);
				if (vlen > 0 && vlen < bufsz) {
					memcpy(buf, p, vlen);
					buf[vlen] = '\0';
					return buf;
				}
				break;
			}

			/* Skip to next cookie */
			const char *sc = memchr(p, ';', (size_t)(end - p));
			p = sc ? sc + 1 : end;
		}
	}

	return NULL;
}

/*
 * Extract JSON string field using mg_json_get_str.
 * Returns heap-allocated string, caller frees.
 */
static char *json_str(struct mg_str body, const char *path)
{
	return mg_json_get_str(body, path);
}

/*
 * Extract query parameter from URI.
 * Returns heap-allocated string, caller frees, or NULL.
 */
static char *query_param(struct mg_str query, const char *name)
{
	if (query.len == 0) return NULL;

	char needle[64];
	int n = snprintf(needle, sizeof(needle), "%s=", name);
	if (n <= 0) return NULL;

	const char *p = query.buf;
	const char *end = query.buf + query.len;

	while (p < end) {
		if ((size_t)(end - p) >= (size_t)n && memcmp(p, needle, (size_t)n) == 0) {
			p += n;
			const char *ve = memchr(p, '&', (size_t)(end - p));
			size_t vlen = ve ? (size_t)(ve - p) : (size_t)(end - p);
			char *val = malloc(vlen + 1);
			if (val) {
				memcpy(val, p, vlen);
				val[vlen] = '\0';
			}
			return val;
		}
		const char *amp = memchr(p, '&', (size_t)(end - p));
		p = amp ? amp + 1 : end;
	}
	return NULL;
}

/*
 * Parse URL path segments after /api/.
 * E.g. "/api/config/firewall_policy/1" → seg[0]="config",
 *        seg[1]="firewall_policy", seg[2]="1"
 * Returns number of segments parsed.
 */
static int parse_segments(struct mg_str uri, char segs[][128], int max)
{
	/* Skip "/api/" prefix */
	const char *p = uri.buf;
	const char *end = uri.buf + uri.len;

	if (uri.len > 5 && memcmp(p, "/api/", 5) == 0)
		p += 5;
	else
		return 0;

	/* Strip query string */
	const char *q = memchr(p, '?', (size_t)(end - p));
	if (q) end = q;

	int n = 0;
	while (p < end && n < max) {
		const char *slash = memchr(p, '/', (size_t)(end - p));
		size_t slen = slash ? (size_t)(slash - p) : (size_t)(end - p);
		if (slen > 0 && slen < 128) {
			memcpy(segs[n], p, slen);
			segs[n][slen] = '\0';
			n++;
		}
		p = slash ? slash + 1 : end;
	}
	return n;
}

/*
 * Convert JSON body to key=value\n format for IPC.
 * Returns heap-allocated string, caller frees.
 */
static char *json_body_to_kv(struct mg_str body)
{
	size_t cap = 512;
	size_t len = 0;
	char *buf = malloc(cap);
	if (!buf) return NULL;
	buf[0] = '\0';

	/* Scan JSON for "key":"value" or "key":number pairs */
	const char *p = body.buf;
	const char *end = body.buf + body.len;

	/* Find opening { */
	while (p < end && *p != '{') p++;
	if (p >= end) return buf;
	p++; /* skip { */

	while (p < end) {
		/* Skip whitespace and commas */
		while (p < end && (*p == ' ' || *p == ',' || *p == '\n' ||
				   *p == '\r' || *p == '\t'))
			p++;

		if (p >= end || *p == '}') break;

		/* Expect "key" */
		if (*p != '"') break;
		p++; /* skip opening quote */
		const char *ks = p;
		while (p < end && *p != '"') p++;
		if (p >= end) break;
		size_t kl = (size_t)(p - ks);
		p++; /* skip closing quote */

		/* Skip : */
		while (p < end && (*p == ' ' || *p == ':')) p++;

		/* Read value */
		const char *vs;
		size_t vl;
		if (*p == '"') {
			/* String value */
			p++; /* skip opening quote */
			vs = p;
			while (p < end && *p != '"') {
				if (*p == '\\' && p + 1 < end) p++; /* skip escape */
				p++;
			}
			vl = (size_t)(p - vs);
			if (p < end) p++; /* skip closing quote */
		} else {
			/* Number, bool, null */
			vs = p;
			while (p < end && *p != ',' && *p != '}' &&
			       *p != ' ' && *p != '\n')
				p++;
			vl = (size_t)(p - vs);
		}

		/* Append key=value\n to buffer */
		size_t needed = kl + 1 + vl + 1;
		while (len + needed >= cap) {
			cap *= 2;
			char *tmp = realloc(buf, cap);
			if (!tmp) { free(buf); return NULL; }
			buf = tmp;
		}
		memcpy(buf + len, ks, kl);
		len += kl;
		buf[len++] = '=';
		memcpy(buf + len, vs, vl);
		len += vl;
		buf[len++] = '\n';
	}

	buf[len] = '\0';
	return buf;
}

/*
 * Remove lines whose key matches any entry in the null-terminated skip list.
 * Returns a new malloc'd string with those lines removed.
 * Caller must free the result.
 */
static char *strip_kv_keys(const char *kv, const char *const skip[])
{
	if (!kv || !skip) return NULL;
	size_t len = strlen(kv);
	char *out = malloc(len + 1);
	if (!out) return NULL;
	size_t opos = 0;

	const char *p = kv;
	while (*p) {
		const char *eol = strchr(p, '\n');
		size_t llen = eol ? (size_t)(eol - p) : strlen(p);
		int skip_line = 0;
		for (int i = 0; skip[i]; i++) {
			size_t klen = strlen(skip[i]);
			if (llen > klen && memcmp(p, skip[i], klen) == 0 &&
			    p[klen] == '=') {
				skip_line = 1;
				break;
			}
		}
		if (!skip_line) {
			memcpy(out + opos, p, llen);
			opos += llen;
			out[opos++] = '\n';
		}
		p += llen;
		if (eol) p++;
	}
	out[opos] = '\0';
	return out;
}

/* ── Route dispatch ──────────────────────────────────────────────────── */

int webd_api_dispatch(struct mg_http_message *hm, struct mg_connection *c)
{
	char segs[6][128];
	memset(segs, 0, sizeof(segs));
	int nseg = parse_segments(hm->uri, segs, 6);

	if (nseg < 1) {
		reply_json(c, 404, "{\"error\":\"Not found\"}");
		return -1;
	}

	/* ── /api/auth/... ───────────────────────────────────────────── */
	if (strcmp(segs[0], "auth") == 0) {
		if (nseg >= 2 && strcmp(segs[1], "login") == 0 &&
		    mg_str_eq(hm->method, "POST")) {
			/* Rate limit */
			if (rate_limit_check() != 0) {
				reply_json(c, 429,
					   "{\"error\":\"Too many requests\"}");
				return -1;
			}

			/* Parse credentials from JSON body */
			char *username = json_str(hm->body, "$.username");
			char *password = json_str(hm->body, "$.password");
			if (!username || !password) {
				free(username);
				free(password);
				reply_json(c, 400,
					   "{\"error\":\"Missing username or password\"}");
				return -1;
			}

			/* Build IPC payload: "username\npassword\n" */
			size_t plen = strlen(username) + strlen(password) + 3;
			char *payload = malloc(plen);
			if (payload)
				snprintf(payload, plen, "%s\n%s\n",
					 username, password);

			work_item_t item;
			memset(&item, 0, sizeof(item));
			item.conn_id = c->id;
			item.flow_type = FLOW_LOGIN;
			snprintf(item.username, sizeof(item.username),
				 "%s", username);
			item.payload = payload;
			item.payload_len = payload ? strlen(payload) : 0;

			free(username);
			free(password);

			if (webd_pool_enqueue(&item) != 0) {
				free(payload);
				reply_json(c, 503,
					   "{\"error\":\"Server busy\"}");
				return -1;
			}
			return 0;
		}

		/* All other /api/auth/... routes require auth */
		char token_buf[WEBD_TOKEN_LEN + 1];
		const char *token = extract_bearer(hm, token_buf,
						   sizeof(token_buf));
		webd_session_t sess;
		if (!token || session_lookup(token, &sess) != 0) {
			reply_json(c, 401, "{\"error\":\"Unauthorized\"}");
			return -1;
		}

		if (nseg >= 2 && strcmp(segs[1], "logout") == 0 &&
		    mg_str_eq(hm->method, "POST")) {
			/* Destroy local session + clear cookie */
			session_destroy(token_buf);

			/* Best-effort release mgmtd session tag (fire-and-forget) */
			work_item_t item;
			memset(&item, 0, sizeof(item));
			item.conn_id = 0; /* no response needed */
			item.ipc_cmd = SG_CMD_SESSION_TAG_DEL;
			item.flow_type = FLOW_SIMPLE;
			snprintf(item.username, sizeof(item.username),
				 "%s", sess.username);
			item.session_tag = sess.ipc_session_tag;
			webd_pool_enqueue(&item); /* ignore if full */

			/* Reply with cookie clear */
			{
				char hdrs[512];
				snprintf(hdrs, sizeof(hdrs),
					 "%s"
					 "Set-Cookie: sg_sid=; HttpOnly; "
					 "SameSite=Strict; Path=/; Max-Age=0\r\n",
					 webd_sec_headers());
				mg_http_reply(c, 200, hdrs,
					      "{\"ok\":true}");
			}
			return -1;
		}

		if (nseg >= 2 && strcmp(segs[1], "change-password") == 0 &&
		    mg_str_eq(hm->method, "POST")) {
			char *password = json_str(hm->body, "$.password");
			if (!password) {
				reply_json(c, 400,
					   "{\"error\":\"Missing password\"}");
				return -1;
			}

			/* Build payload: "username\nnew_password\n" */
			size_t plen = strlen(sess.username) + strlen(password) + 3;
			char *payload = malloc(plen);
			if (payload)
				snprintf(payload, plen, "%s\n%s\n",
					 sess.username, password);
			free(password);

			work_item_t item;
			memset(&item, 0, sizeof(item));
			item.conn_id = c->id;
			item.flow_type = FLOW_CHANGE_PW;
			snprintf(item.username, sizeof(item.username),
				 "%s", sess.username);
			item.session_tag = sess.ipc_session_tag;
			item.payload = payload;
			item.payload_len = payload ? strlen(payload) : 0;

			if (webd_pool_enqueue(&item) != 0) {
				free(payload);
				reply_json(c, 503,
					   "{\"error\":\"Server busy\"}");
				return -1;
			}
			return 0;
		}

		if (nseg >= 2 && strcmp(segs[1], "whoami") == 0 &&
		    mg_str_eq(hm->method, "GET")) {
			work_item_t item;
			memset(&item, 0, sizeof(item));
			item.conn_id = c->id;
			item.flow_type = FLOW_WHOAMI;
			snprintf(item.username, sizeof(item.username),
				 "%s", sess.username);
			item.session_tag = sess.ipc_session_tag;

			if (webd_pool_enqueue(&item) != 0) {
				reply_json(c, 503,
					   "{\"error\":\"Server busy\"}");
				return -1;
			}
			return 0;
		}

		reply_json(c, 404, "{\"error\":\"Not found\"}");
		return -1;
	}

	/* ── All remaining routes require auth ───────────────────────── */
	char token_buf[WEBD_TOKEN_LEN + 1];
	const char *token = extract_bearer(hm, token_buf, sizeof(token_buf));
	webd_session_t sess;
	if (!token || session_lookup(token, &sess) != 0) {
		reply_json(c, 401, "{\"error\":\"Unauthorized\"}");
		return -1;
	}

	/* ── /api/config/... ─────────────────────────────────────────── */
	if (strcmp(segs[0], "config") == 0 && nseg >= 2) {
		const char *type = segs[1];

		/* GET /api/config/{type} — list all entries */
		if (nseg == 2 && mg_str_eq(hm->method, "GET")) {
			/* Check for ?q= search param */
			char *search = query_param(hm->query, "q");

			work_item_t item;
			memset(&item, 0, sizeof(item));
			item.conn_id = c->id;
			item.flow_type = FLOW_CONFIG_LIST;
			snprintf(item.username, sizeof(item.username),
				 "%s", sess.username);
			item.session_tag = sess.ipc_session_tag;
			snprintf(item.extra, sizeof(item.extra), "%s", type);
			item.payload = search; /* may be NULL */
			item.payload_len = search ? strlen(search) : 0;

			if (webd_pool_enqueue(&item) != 0) {
				free(search);
				reply_json(c, 503,
					   "{\"error\":\"Server busy\"}");
				return -1;
			}
			return 0;
		}

		/* GET /api/config/{type}/{id} — get single entry */
		if (nseg >= 3 && mg_str_eq(hm->method, "GET")) {
			char section[512];
			snprintf(section, sizeof(section), "%s:%s\n",
				 type, segs[2]);

			work_item_t item;
			memset(&item, 0, sizeof(item));
			item.conn_id = c->id;
			item.ipc_cmd = SG_CMD_CFG_GET;
			item.flow_type = FLOW_SIMPLE;
			snprintf(item.username, sizeof(item.username),
				 "%s", sess.username);
			item.session_tag = sess.ipc_session_tag;
			item.payload = strdup(section);
			item.payload_len = strlen(section);

			if (webd_pool_enqueue(&item) != 0) {
				free(item.payload);
				reply_json(c, 503,
					   "{\"error\":\"Server busy\"}");
				return -1;
			}
			return 0;
		}

		/* POST /api/config/{type} — create entry */
		if (nseg == 2 && mg_str_eq(hm->method, "POST")) {
			char *kv_raw = json_body_to_kv(hm->body);
			if (!kv_raw) {
				reply_json(c, 400,
					   "{\"error\":\"Invalid body\"}");
				return -1;
			}

			/* Extract id from name or id field */
			char *name = json_str(hm->body, "$.name");
			char *id_field = json_str(hm->body, "$.id");
			const char *entry_id = name ? name : id_field;
			if (!entry_id) entry_id = "new";

			/* Strip routing keys — 'name' and 'id' are entry
			 * identifiers, not config fields.  Sending them in
			 * the payload causes "Unknown key" errors for types
			 * that don't have a 'name' field (e.g. system_admin). */
			static const char *const strip_keys[] = {"name", "id", NULL};
			char *kv = strip_kv_keys(kv_raw, strip_keys);
			free(kv_raw);
			if (!kv) {
				free(name);
				free(id_field);
				reply_json(c, 500,
					   "{\"error\":\"Internal error\"}");
				return -1;
			}

			/* Build apply payload: "type\nid\nkey=val\n..." */
			size_t ap_sz = strlen(type) + strlen(entry_id) +
				       strlen(kv) + 4;
			char *apply_payload = malloc(ap_sz);
			if (apply_payload)
				snprintf(apply_payload, ap_sz, "%s\n%s\n%s",
					 type, entry_id, kv);

			/* Build set payload: "type:id\nkey=val\n..." */
			size_t sp_sz = strlen(type) + strlen(entry_id) +
				       strlen(kv) + 4;
			char *set_payload = malloc(sp_sz);
			if (set_payload)
				snprintf(set_payload, sp_sz, "%s:%s\n%s",
					 type, entry_id, kv);

			/* Pack both payloads with NUL separator */
			size_t total = (apply_payload ? strlen(apply_payload) : 0) +
				       1 +
				       (set_payload ? strlen(set_payload) : 0) +
				       1;
			char *combined = malloc(total);
			if (combined && apply_payload && set_payload) {
				size_t alen = strlen(apply_payload);
				memcpy(combined, apply_payload, alen);
				combined[alen] = '\0';
				size_t slen = strlen(set_payload);
				memcpy(combined + alen + 1, set_payload, slen);
				combined[alen + 1 + slen] = '\0';
			}

			free(kv);
			free(name);
			free(id_field);
			free(apply_payload);
			free(set_payload);

			work_item_t item;
			memset(&item, 0, sizeof(item));
			item.conn_id = c->id;
			item.flow_type = FLOW_CONFIG_CREATE;
			snprintf(item.username, sizeof(item.username),
				 "%s", sess.username);
			item.session_tag = sess.ipc_session_tag;
			snprintf(item.extra, sizeof(item.extra), "%s", type);
			item.payload = combined;
			item.payload_len = total;

			if (webd_pool_enqueue(&item) != 0) {
				free(combined);
				reply_json(c, 503,
					   "{\"error\":\"Server busy\"}");
				return -1;
			}
			return 0;
		}

		/* PUT /api/config/{type}/{id} — update entry */
		if (nseg >= 3 && mg_str_eq(hm->method, "PUT")) {
			char *kv = json_body_to_kv(hm->body);
			if (!kv) {
				reply_json(c, 400,
					   "{\"error\":\"Invalid body\"}");
				return -1;
			}

			work_item_t item;
			memset(&item, 0, sizeof(item));
			item.conn_id = c->id;
			item.flow_type = FLOW_CONFIG_UPDATE;
			snprintf(item.username, sizeof(item.username),
				 "%s", sess.username);
			item.session_tag = sess.ipc_session_tag;
			snprintf(item.extra, sizeof(item.extra), "%s:%s",
				 type, segs[2]);
			item.payload = kv;
			item.payload_len = strlen(kv);

			if (webd_pool_enqueue(&item) != 0) {
				free(kv);
				reply_json(c, 503,
					   "{\"error\":\"Server busy\"}");
				return -1;
			}
			return 0;
		}

		/* DELETE /api/config/{type}/{id} — delete entry */
		if (nseg >= 3 && mg_str_eq(hm->method, "DELETE")) {
			char payload[512];
			snprintf(payload, sizeof(payload), "%s:%s\n",
				 type, segs[2]);

			work_item_t item;
			memset(&item, 0, sizeof(item));
			item.conn_id = c->id;
			item.ipc_cmd = SG_CMD_CFG_DEL;
			item.flow_type = FLOW_SIMPLE;
			snprintf(item.username, sizeof(item.username),
				 "%s", sess.username);
			item.session_tag = sess.ipc_session_tag;
			item.payload = strdup(payload);
			item.payload_len = strlen(payload);

			if (webd_pool_enqueue(&item) != 0) {
				free(item.payload);
				reply_json(c, 503,
					   "{\"error\":\"Server busy\"}");
				return -1;
			}
			return 0;
		}

		reply_json(c, 405,
			   "{\"error\":\"Method not allowed\"}");
		return -1;
	}

	/* ── /api/system/... ─────────────────────────────────────────── */
	if (strcmp(segs[0], "system") == 0 && nseg >= 2) {

		/* GET /api/system/resources[/detail|ram|disk|proctop] */
		if (strcmp(segs[1], "resources") == 0 &&
		    mg_str_eq(hm->method, "GET")) {
			int flow = FLOW_RESOURCES;
			if (nseg >= 3) {
				if (strcmp(segs[2], "detail") == 0)
					flow = FLOW_RESOURCES_DET;
				else if (strcmp(segs[2], "ram") == 0)
					flow = FLOW_RES_RAM;
				else if (strcmp(segs[2], "disk") == 0)
					flow = FLOW_RES_DISK;
				else if (strcmp(segs[2], "proctop") == 0)
					flow = FLOW_RES_PROCTOP;
			}

			work_item_t item;
			memset(&item, 0, sizeof(item));
			item.conn_id = c->id;
			item.flow_type = flow;
			snprintf(item.username, sizeof(item.username),
				 "%s", sess.username);
			item.session_tag = sess.ipc_session_tag;

			if (webd_pool_enqueue(&item) != 0) {
				reply_json(c, 503,
					   "{\"error\":\"Server busy\"}");
				return -1;
			}
			return 0;
		}

		/* GET /api/system/firmware */
		if (strcmp(segs[1], "firmware") == 0) {
			if (nseg == 2 && mg_str_eq(hm->method, "GET")) {
				work_item_t item;
				memset(&item, 0, sizeof(item));
				item.conn_id = c->id;
				item.flow_type = FLOW_FIRMWARE_INFO;
				snprintf(item.username,
					 sizeof(item.username),
					 "%s", sess.username);
				item.session_tag = sess.ipc_session_tag;

				if (webd_pool_enqueue(&item) != 0) {
					reply_json(c, 503,
						   "{\"error\":\"Server busy\"}");
					return -1;
				}
				return 0;
			}

			/* GET /api/system/firmware/progress */
			if (nseg >= 3 &&
			    strcmp(segs[2], "progress") == 0 &&
			    mg_str_eq(hm->method, "GET")) {
				work_item_t item;
				memset(&item, 0, sizeof(item));
				item.conn_id = c->id;
				item.flow_type = FLOW_FIRMWARE_PROG;
				snprintf(item.username,
					 sizeof(item.username),
					 "%s", sess.username);
				item.session_tag = sess.ipc_session_tag;

				if (webd_pool_enqueue(&item) != 0) {
					reply_json(c, 503,
						   "{\"error\":\"Server busy\"}");
					return -1;
				}
				return 0;
			}

			/* POST /api/system/firmware/upgrade — stub */
			if (nseg >= 3 &&
			    strcmp(segs[2], "upgrade") == 0 &&
			    mg_str_eq(hm->method, "POST")) {
				reply_json(c, 501,
					   "{\"error\":\"Firmware upload not yet implemented\"}");
				return -1;
			}
		}

		/* POST /api/system/reboot */
		if (strcmp(segs[1], "reboot") == 0 &&
		    mg_str_eq(hm->method, "POST")) {
			char *device = json_str(hm->body, "$.device");
			char *payload = NULL;
			if (device) {
				size_t plen = strlen(device) + 16;
				payload = malloc(plen);
				if (payload)
					snprintf(payload, plen,
						 "device=%s\n", device);
				free(device);
			} else {
				payload = strdup("");
			}

			work_item_t item;
			memset(&item, 0, sizeof(item));
			item.conn_id = c->id;
			item.flow_type = FLOW_REBOOT;
			snprintf(item.username, sizeof(item.username),
				 "%s", sess.username);
			item.session_tag = sess.ipc_session_tag;
			item.payload = payload;
			item.payload_len = payload ? strlen(payload) : 0;

			if (webd_pool_enqueue(&item) != 0) {
				free(payload);
				reply_json(c, 503,
					   "{\"error\":\"Server busy\"}");
				return -1;
			}
			return 0;
		}

		reply_json(c, 404, "{\"error\":\"Not found\"}");
		return -1;
	}

	/* ── /api/diagnose/... ───────────────────────────────────────── */
	if (strcmp(segs[0], "diagnose") == 0 && nseg >= 2 &&
	    mg_str_eq(hm->method, "POST")) {

		uint32_t cmd;
		if (strcmp(segs[1], "ping") == 0)
			cmd = SG_CMD_NET_PING;
		else if (strcmp(segs[1], "traceroute") == 0)
			cmd = SG_CMD_NET_TRACEROUTE;
		else if (strcmp(segs[1], "nslookup") == 0)
			cmd = SG_CMD_NET_NSLOOKUP;
		else if (strcmp(segs[1], "arping") == 0)
			cmd = SG_CMD_NET_ARPING;
		else {
			reply_json(c, 404,
				   "{\"error\":\"Unknown tool\"}");
			return -1;
		}

		/* Parse target and optional iface from JSON body */
		char *target = json_str(hm->body, "$.target");
		char *iface = json_str(hm->body, "$.iface");

		if (!target) {
			free(iface);
			reply_json(c, 400,
				   "{\"error\":\"Missing target\"}");
			return -1;
		}

		size_t plen = strlen(target) + (iface ? strlen(iface) : 0) + 32;
		char *payload = malloc(plen);
		if (payload) {
			if (iface)
				snprintf(payload, plen,
					 "target=%s\niface=%s\n",
					 target, iface);
			else
				snprintf(payload, plen,
					 "target=%s\n", target);
		}
		free(target);
		free(iface);

		work_item_t item;
		memset(&item, 0, sizeof(item));
		item.conn_id = c->id;
		item.ipc_cmd = cmd;
		item.flow_type = FLOW_DIAGNOSE;
		snprintf(item.username, sizeof(item.username),
			 "%s", sess.username);
		item.session_tag = sess.ipc_session_tag;
		item.payload = payload;
		item.payload_len = payload ? strlen(payload) : 0;

		if (webd_pool_enqueue(&item) != 0) {
			free(payload);
			reply_json(c, 503,
				   "{\"error\":\"Server busy\"}");
			return -1;
		}
		return 0;
	}

	reply_json(c, 404, "{\"error\":\"Not found\"}");
	return -1;
}
