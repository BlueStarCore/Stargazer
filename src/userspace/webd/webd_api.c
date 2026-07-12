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
#include "sg_validate.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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

/*
 * type_uses_name_as_id — true if a config type uses the 'name' field
 * as the section identifier (rather than a separate numeric/opaque id).
 *
 * Examples:
 *   firewall_address:webservers  → name "webservers" IS the section id
 *   firewall_policy:1            → numeric id, "name" is descriptive only
 */
static int type_uses_name_as_id(const char *type)
{
	/* security_ips-profile is a NUMERIC-id table now (like firewall_policy):
	 * the id is the profile id 1..31, 'name' is descriptive only. */
	return strcmp(type, "firewall_address") == 0 ||
	       strcmp(type, "firewall_service") == 0 ||
	       strcmp(type, "system_admin") == 0 ||
	       strcmp(type, "system_admin-profile") == 0;
}

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
 * kv_append_filter - append "key=val\n" to a session-clear filter payload if
 * `val` is non-empty and free of control chars (a newline would forge extra
 * kv lines for mgmtd). Always frees `val` (from json_str). Returns 1 if a
 * constraint was appended, else 0.
 */
static int kv_append_filter(char *buf, size_t cap, size_t *len,
			    const char *key, char *val)
{
	int ok = val && val[0] != '\0';
	for (const char *p = val; ok && *p; p++)
		if ((unsigned char)*p < 0x20) ok = 0;	/* \n \r \t & ctrl */
	if (ok) {
		int n = snprintf(buf + *len, cap - *len, "%s=%s\n", key, val);
		if (n > 0 && (size_t)n < cap - *len) *len += (size_t)n;
		else ok = 0;				/* would truncate → drop */
	}
	free(val);
	return ok;
}

/*
 * kv_append_tuple - append "key=val " (space-joined) to one batch record.
 * Rejects control chars AND spaces, since a space would split the record when
 * mgmtd tokenizes it. Always frees `val`. Returns 1 if appended, else 0.
 */
static int kv_append_tuple(char *buf, size_t cap, size_t *len,
			   const char *key, char *val)
{
	int ok = val && val[0] != '\0';
	for (const char *p = val; ok && *p; p++)
		if ((unsigned char)*p <= 0x20) ok = 0;	/* ctrl or space */
	if (ok) {
		int n = snprintf(buf + *len, cap - *len, "%s=%s ", key, val);
		if (n > 0 && (size_t)n < cap - *len) *len += (size_t)n;
		else ok = 0;
	}
	free(val);
	return ok;
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

/* In-place percent-decode (e.g. "2%2F1" → "2/1"). Path segments are split on
 * literal '/', so a composite id like "<profid>/<seq>" must be sent encoded;
 * decode it here before use. Decoded length is always <= input length. */
static void url_decode_inplace(char *s)
{
	char *o = s;
	for (char *p = s; *p; p++) {
		if (p[0] == '%' && isxdigit((unsigned char)p[1]) &&
		    isxdigit((unsigned char)p[2])) {
			char h[3] = { p[1], p[2], 0 };
			*o++ = (char)strtol(h, NULL, 16);
			p += 2;
		} else {
			*o++ = *p;
		}
	}
	*o = '\0';
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

/* Stage an uploaded blob to a unique /tmp/<prefix>.<rand> file (same
 * constraints as the firmware upload: no mkstemp/stdio under webd's seccomp —
 * generate an [a-z0-9] suffix and open O_WRONLY|O_CREAT|O_EXCL, write raw).
 * On success copies the path into `out` and returns 0; -1 on failure. */
static int webd_stage_file(const char *prefix, const char *buf, size_t len,
			   char *out, size_t outsz)
{
	static const char A36[] = "abcdefghijklmnopqrstuvwxyz0123456789";
	static unsigned long stage_seq;
	int sfd = -1;
	for (int att = 0; att < 128 && sfd < 0; att++) {
		unsigned long v = (stage_seq++ + (unsigned long)att) * 2654435761UL
				^ (unsigned long)(uintptr_t)&att;
		char suf[11];
		for (int i = 0; i < 10; i++) { suf[i] = A36[v % 36]; v /= 36; }
		suf[10] = '\0';
		snprintf(out, outsz, "/tmp/%s.%s", prefix, suf);
		sfd = open(out, O_WRONLY | O_CREAT | O_EXCL, 0600);
	}
	if (sfd < 0) return -1;
	size_t off = 0;
	int ok = 1;
	while (off < len) {
		ssize_t wn = write(sfd, buf + off, len - off);
		if (wn < 0) { if (errno == EINTR) continue; ok = 0; break; }
		off += (size_t)wn;
	}
	if (close(sfd) != 0) ok = 0;
	if (!ok) { unlink(out); return -1; }
	return 0;
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
			if (!payload) {
				free(username);
				free(password);
				reply_json(c, 503,
					   "{\"error\":\"Internal error\"}");
				return -1;
			}
			snprintf(payload, plen, "%s\n%s\n", username, password);

			work_item_t item;
			memset(&item, 0, sizeof(item));
			item.conn_id = c->id;
			item.flow_type = FLOW_LOGIN;
			snprintf(item.username, sizeof(item.username),
				 "%s", username);
			item.payload = payload;
			item.payload_len = strlen(payload);

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

			/* Build payload: "username\nnew_password\nsource\n" */
			size_t plen = strlen(sess.username) + strlen(password) +
				      3 + 11; /* +11 for "admin-flag\n" */
			char *payload = malloc(plen);
			if (!payload) {
				free(password);
				reply_json(c, 503,
					   "{\"error\":\"Internal error\"}");
				return -1;
			}
			snprintf(payload, plen, "%s\n%s\nadmin-flag\n",
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
			item.payload_len = strlen(payload);

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

	/* ── /api/admin/create ───────────────────────────────────────── */
	if (strcmp(segs[0], "admin") == 0 && nseg >= 2 &&
	    strcmp(segs[1], "create") == 0 &&
	    mg_str_eq(hm->method, "POST")) {
		char *username = json_str(hm->body, "$.username");
		char *profile = json_str(hm->body, "$.profile");
		char *password = json_str(hm->body, "$.password");

		if (!username || !profile) {
			free(username);
			free(profile);
			free(password);
			reply_json(c, 400,
				   "{\"error\":\"Missing username or profile\"}");
			return -1;
		}

		/* Build payload: "username\nprofile\npassword\n" */
		size_t plen = strlen(username) + strlen(profile) +
			      (password ? strlen(password) : 0) + 4;
		char *payload = malloc(plen);
		if (!payload) {
			free(username);
			free(profile);
			free(password);
			reply_json(c, 503,
				   "{\"error\":\"Internal error\"}");
			return -1;
		}
		if (password)
			snprintf(payload, plen, "%s\n%s\n%s\n",
				 username, profile, password);
		else
			snprintf(payload, plen, "%s\n%s\n",
				 username, profile);

		free(username);
		free(profile);
		free(password);

		work_item_t item;
		memset(&item, 0, sizeof(item));
		item.conn_id = c->id;
		item.flow_type = FLOW_ADMIN_CREATE;
		snprintf(item.username, sizeof(item.username),
			 "%s", sess.username);
		item.session_tag = sess.ipc_session_tag;
		item.payload = payload;
		item.payload_len = strlen(payload);

		if (webd_pool_enqueue(&item) != 0) {
			free(payload);
			reply_json(c, 503,
				   "{\"error\":\"Server busy\"}");
			return -1;
		}
		return 0;
	}

	/* ── /api/config/... ─────────────────────────────────────────── */
	if (strcmp(segs[0], "config") == 0 && nseg >= 2) {
		const char *type = segs[1];

		/* The entry id (segs[2]) may be percent-encoded so a composite id
		 * like "<profid>/<seq>" survives path splitting — decode it once here. */
		if (nseg >= 3)
			url_decode_inplace(segs[2]);

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
			/* Validate entry ID per the type's id rule (uint / safe-id /
			 * composite profid/seq) — also prevents injection. */
			if (!sg_reg_validate_entry_id(type, segs[2])) {
				reply_json(c, 400,
					   "{\"error\":\"Invalid entry ID\"}");
				return -1;
			}

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
			if (!item.payload) {
				reply_json(c, 500,
					   "{\"error\":\"Internal error\"}");
				return -1;
			}
			item.payload_len = strlen(item.payload);

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

			/* Extract entry id.
			 *
			 * Two identifier conventions:
			 *   - "name-as-id" types (firewall_address, firewall_service,
			 *     system_admin, system_admin-profile): the JSON 'name'
			 *     IS the section identifier.
			 *   - All other types (firewall_policy, network_nat,
			 *     network_route_static, ...): use a separate numeric/
			 *     opaque 'id' field. The 'name' field, if present, is
			 *     just a descriptive label stored in the config payload.
			 *
			 * The previous code used name-as-id for ALL types, which
			 * stored firewall_policy entries as e.g. "firewall_policy:
			 * Allow-HTTPS-Out" — making the section ID and the name
			 * column always identical and conflicting with the
			 * numeric-ID convention used by the boot seed.
			 */
			char *name = json_str(hm->body, "$.name");
			char *id_field = json_str(hm->body, "$.id");
			const char *entry_id = type_uses_name_as_id(type)
				? (name ? name : id_field)
				: (id_field ? id_field : NULL);
			if (!entry_id || !*entry_id) {
				free(kv_raw);
				free(name);
				free(id_field);
				reply_json(c, 400,
					   "{\"error\":\"Missing 'id' field\"}");
				return -1;
			}

			/* Strip 'id' key — it's the entry identifier, not a
			 * config field.  Keep 'name' — some types (e.g.
			 * firewall_address, firewall_service) have 'name'
			 * as a real config key in their schema. */
			static const char *const strip_keys[] = {"id", NULL};
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

			/* Build set payload: "type:id\nkey=val\n..." */
			size_t sp_sz = strlen(type) + strlen(entry_id) +
				       strlen(kv) + 4;
			char *set_payload = malloc(sp_sz);

			if (!apply_payload || !set_payload) {
				free(apply_payload);
				free(set_payload);
				free(kv);
				free(name);
				free(id_field);
				reply_json(c, 500,
					   "{\"error\":\"Internal error\"}");
				return -1;
			}
			snprintf(apply_payload, ap_sz, "%s\n%s\n%s",
				 type, entry_id, kv);
			snprintf(set_payload, sp_sz, "%s:%s\n%s",
				 type, entry_id, kv);

			/* Pack both payloads with NUL separator */
			size_t total = strlen(apply_payload) + 1 +
				       strlen(set_payload) + 1;
			char *combined = malloc(total);
			if (!combined) {
				free(apply_payload);
				free(set_payload);
				free(kv);
				free(name);
				free(id_field);
				reply_json(c, 500,
					   "{\"error\":\"Internal error\"}");
				return -1;
			}
			size_t alen = strlen(apply_payload);
			memcpy(combined, apply_payload, alen);
			combined[alen] = '\0';
			size_t slen = strlen(set_payload);
			memcpy(combined + alen + 1, set_payload, slen);
			combined[alen + 1 + slen] = '\0';

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
			/* Validate entry ID per the type's id rule (uint / safe-id /
			 * composite profid/seq) — also prevents injection. */
			if (!sg_reg_validate_entry_id(type, segs[2])) {
				reply_json(c, 400,
					   "{\"error\":\"Invalid entry ID\"}");
				return -1;
			}

			char *kv_raw = json_body_to_kv(hm->body);
			if (!kv_raw) {
				reply_json(c, 400,
					   "{\"error\":\"Invalid body\"}");
				return -1;
			}
			static const char *const strip_keys[] = {"id", NULL};
			char *kv = strip_kv_keys(kv_raw, strip_keys);
			free(kv_raw);
			if (!kv) {
				reply_json(c, 500,
					   "{\"error\":\"Internal error\"}");
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
			/* Validate entry ID per the type's id rule (uint / safe-id /
			 * composite profid/seq) — also prevents injection. */
			if (!sg_reg_validate_entry_id(type, segs[2])) {
				reply_json(c, 400,
					   "{\"error\":\"Invalid entry ID\"}");
				return -1;
			}

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
			if (!item.payload) {
				reply_json(c, 500,
					   "{\"error\":\"Internal error\"}");
				return -1;
			}
			item.payload_len = strlen(item.payload);

			if (webd_pool_enqueue(&item) != 0) {
				free(item.payload);
				reply_json(c, 503,
					   "{\"error\":\"Server busy\"}");
				return -1;
			}
			return 0;
		}

		/* PATCH /api/config/{type}/{id}/move — reorder entry */
		if (nseg >= 4 && strcmp(segs[3], "move") == 0 &&
		    mg_str_eq(hm->method, "PATCH")) {
			/* Validate the entry id before it reaches mgmtd, like the
			 * GET/PUT/DELETE single-entry routes. */
			if (!sg_is_safe_id(segs[2])) {
				reply_json(c, 400,
					   "{\"error\":\"Invalid id\"}");
				return -1;
			}
			/* Body: {"sequence": N} */
			char *kv_raw = json_body_to_kv(hm->body);
			if (!kv_raw) {
				reply_json(c, 400,
					   "{\"error\":\"Invalid body\"}");
				return -1;
			}
			/* Extract sequence value from kv */
			char seq_val[32] = {0};
			sg_kv_get(kv_raw, "sequence", seq_val, sizeof(seq_val));
			free(kv_raw);

			if (!seq_val[0]) {
				reply_json(c, 400,
					   "{\"error\":\"Missing 'sequence'\"}");
				return -1;
			}

			/* Build CFG_INSERT payload: "type:id\nsequence\n" */
			char payload[512];
			snprintf(payload, sizeof(payload), "%s:%s\n%s\n",
				 type, segs[2], seq_val);

			work_item_t item;
			memset(&item, 0, sizeof(item));
			item.conn_id = c->id;
			item.ipc_cmd = SG_CMD_CFG_INSERT;
			item.flow_type = FLOW_CONFIG_MOVE;
			snprintf(item.username, sizeof(item.username),
				 "%s", sess.username);
			item.session_tag = sess.ipc_session_tag;
			item.payload = strdup(payload);
			if (!item.payload) {
				reply_json(c, 500,
					   "{\"error\":\"Internal error\"}");
				return -1;
			}
			item.payload_len = strlen(item.payload);

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

		/* GET /api/system/resources[/detail|ram|disk|proctop|percore] */
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
				else if (strcmp(segs[2], "percore") == 0)
					flow = FLOW_RES_PERCORE;
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

			/* POST /api/system/firmware/upgrade — multipart upload */
			if (nseg >= 3 &&
			    strcmp(segs[2], "upgrade") == 0 &&
			    mg_str_eq(hm->method, "POST")) {

				/* Find the "firmware" part in multipart body */
				struct mg_http_part part;
				size_t mofs = 0;
				int found = 0;
				while ((mofs = mg_http_next_multipart(
						hm->body, mofs, &part)) > 0) {
					if (mg_str_eq(part.name, "firmware")) {
						found = 1;
						break;
					}
				}

				if (!found || part.body.len == 0) {
					reply_json(c, 400,
						   "{\"error\":\"No firmware file in upload\"}");
					return -1;
				}

				/* Write to a UNIQUE staging file so two concurrent
				 * uploads cannot race on a shared path (one
				 * client's bytes flashed under another's request).
				 * NOT mkstemp(): it opens O_RDWR, which the webd
				 * seccomp filter kills (only O_RDONLY/O_WRONLY are
				 * allowed). Generate an [A-Za-z0-9] suffix — which
				 * also satisfies mgmtd's strict path check — and
				 * open O_WRONLY|O_CREAT|O_EXCL so creation is atomic
				 * against collisions. */
				static const char A36[] =
					"abcdefghijklmnopqrstuvwxyz0123456789";
				static unsigned long stage_seq;
				char stage[64];
				int sfd = -1;
				for (int att = 0; att < 128 && sfd < 0; att++) {
					unsigned long v =
						(stage_seq++ + (unsigned long)att)
							* 2654435761UL
						^ (unsigned long)(uintptr_t)&att;
					char suf[11];
					for (int i = 0; i < 10; i++) {
						suf[i] = A36[v % 36];
						v /= 36;
					}
					suf[10] = '\0';
					snprintf(stage, sizeof(stage),
						 "/tmp/sg-fw-upload.%s", suf);
					sfd = open(stage,
						   O_WRONLY | O_CREAT | O_EXCL,
						   0600);
				}
				if (sfd < 0) {
					reply_json(c, 500,
						   "{\"error\":\"Cannot create firmware staging file\"}");
					return -1;
				}
				/* Write with raw write(2), NOT stdio: fdopen() on a
				 * writable stream issues ioctl(TIOCGWINSZ) (musl
				 * line-buffering probe) which the webd seccomp
				 * filter does not allow and would KILL the worker.
				 * The body is one contiguous buffer. */
				const char *wbuf = part.body.buf;
				size_t wtot = part.body.len, woff = 0;
				int wok = 1;
				while (woff < wtot) {
					ssize_t wn = write(sfd, wbuf + woff,
							   wtot - woff);
					if (wn < 0) {
						if (errno == EINTR)
							continue;
						wok = 0;
						break;
					}
					woff += (size_t)wn;
				}
				if (close(sfd) != 0)
					wok = 0;
				if (!wok) {
					unlink(stage);
					reply_json(c, 500,
						   "{\"error\":\"Failed to write firmware staging file\"}");
					return -1;
				}

				/* Dispatch IPC to mgmtd to process staged file */
				char upbuf[96];
				snprintf(upbuf, sizeof(upbuf), "path=%s\n", stage);
				char *upayload = strdup(upbuf);
				if (!upayload) {
					unlink(stage);
					reply_json(c, 500,
						   "{\"error\":\"Out of memory\"}");
					return -1;
				}

				work_item_t item;
				memset(&item, 0, sizeof(item));
				item.conn_id = c->id;
				item.flow_type = FLOW_FIRMWARE_UPLOAD;
				snprintf(item.username,
					 sizeof(item.username),
					 "%s", sess.username);
				item.session_tag = sess.ipc_session_tag;
				item.payload = upayload;
				item.payload_len = strlen(upayload);

				if (webd_pool_enqueue(&item) != 0) {
					free(upayload);
					unlink(stage); /* mgmtd never got the path */
					reply_json(c, 503,
						   "{\"error\":\"Server busy\"}");
					return -1;
				}
				return 0;
			}
		}

		/* POST /api/system/certificate/import — multipart: certificate, key,
		 * name (+ optional comment). The two PEM files are staged to /tmp and
		 * their paths handed to mgmtd (SG_CMD_CERT_IMPORT) which validates +
		 * stores them; webd never writes into the persistent cert store. */
		if (strcmp(segs[1], "certificate") == 0 &&
		    nseg >= 3 && strcmp(segs[2], "import") == 0 &&
		    mg_str_eq(hm->method, "POST")) {
			struct mg_http_part part;
			size_t mofs = 0;
			struct mg_str cert_b = {0}, key_b = {0};
			char cname[128] = {0}, comment[256] = {0};
			while ((mofs = mg_http_next_multipart(hm->body, mofs, &part)) > 0) {
				if (mg_str_eq(part.name, "certificate"))
					cert_b = part.body;
				else if (mg_str_eq(part.name, "key"))
					key_b = part.body;
				else if (mg_str_eq(part.name, "name")) {
					size_t l = part.body.len < sizeof(cname) - 1
						 ? part.body.len : sizeof(cname) - 1;
					memcpy(cname, part.body.buf, l); cname[l] = '\0';
				} else if (mg_str_eq(part.name, "comment")) {
					size_t l = part.body.len < sizeof(comment) - 1
						 ? part.body.len : sizeof(comment) - 1;
					memcpy(comment, part.body.buf, l); comment[l] = '\0';
				}
			}
			if (cert_b.len == 0 || cname[0] == '\0') {
				reply_json(c, 400,
					   "{\"error\":\"Need a certificate file and a name\"}");
				return -1;
			}

			char cstage[64] = {0}, kstage[64] = {0};
			if (webd_stage_file("sg-cert", cert_b.buf, cert_b.len,
					    cstage, sizeof(cstage)) != 0) {
				reply_json(c, 500,
					   "{\"error\":\"Cannot stage certificate\"}");
				return -1;
			}
			if (key_b.len > 0 &&
			    webd_stage_file("sg-key", key_b.buf, key_b.len,
					    kstage, sizeof(kstage)) != 0) {
				unlink(cstage);
				reply_json(c, 500, "{\"error\":\"Cannot stage key\"}");
				return -1;
			}

			char pbuf[1024];
			snprintf(pbuf, sizeof(pbuf),
				 "name=%s\ncert=%s\n%s%s%s%s%s%s",
				 cname, cstage,
				 kstage[0] ? "key=" : "", kstage[0] ? kstage : "",
				 kstage[0] ? "\n" : "",
				 comment[0] ? "comment=" : "",
				 comment[0] ? comment : "",
				 comment[0] ? "\n" : "");
			char *upayload = strdup(pbuf);
			if (!upayload) {
				unlink(cstage); if (kstage[0]) unlink(kstage);
				reply_json(c, 500, "{\"error\":\"Out of memory\"}");
				return -1;
			}

			work_item_t item;
			memset(&item, 0, sizeof(item));
			item.conn_id = c->id;
			item.flow_type = FLOW_CERT_IMPORT;
			snprintf(item.username, sizeof(item.username),
				 "%s", sess.username);
			item.session_tag = sess.ipc_session_tag;
			item.payload = upayload;
			item.payload_len = strlen(upayload);

			if (webd_pool_enqueue(&item) != 0) {
				free(upayload);
				unlink(cstage); if (kstage[0]) unlink(kstage);
				reply_json(c, 503, "{\"error\":\"Server busy\"}");
				return -1;
			}
			return 0;
		}

		/* GET /api/system/interfaces/live — live kernel operstate overlay */
		if (strcmp(segs[1], "interfaces") == 0 &&
		    nseg >= 3 && strcmp(segs[2], "live") == 0 &&
		    mg_str_eq(hm->method, "GET")) {
			work_item_t item;
			memset(&item, 0, sizeof(item));
			item.conn_id = c->id;
			item.flow_type = FLOW_IFACE_LIVE;
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

	/* ── /api/monitor/sessions ──────────────────────────────────── */
	if (strcmp(segs[0], "monitor") == 0 && nseg == 2 &&
	    strcmp(segs[1], "sessions") == 0 &&
	    mg_str_eq(hm->method, "GET")) {

		work_item_t item;
		memset(&item, 0, sizeof(item));
		item.conn_id = c->id;
		item.ipc_cmd = SG_CMD_SHOW_SESSIONS;
		item.flow_type = FLOW_MONITOR_SESSIONS;
		snprintf(item.username, sizeof(item.username),
			 "%s", sess.username);
		item.session_tag = sess.ipc_session_tag;

		if (webd_pool_enqueue(&item) != 0) {
			reply_json(c, 503, "{\"error\":\"Server busy\"}");
			return -1;
		}
		return 0;
	}

	/* ── POST /api/monitor/sessions/clear ───────────────────────────
	 * Filtered clear, single-session delete, and multi-select batch all
	 * post here. Body is either {proto?,src?,dst?,policy?,iif?,oif?} (one
	 * filter) or {"tuples":[{proto,src,dst},...]} (batch). mgmtd validates
	 * every value and enforces admin; webd only shuttles the payload. */
	if (strcmp(segs[0], "monitor") == 0 && nseg == 3 &&
	    strcmp(segs[1], "sessions") == 0 && strcmp(segs[2], "clear") == 0 &&
	    mg_str_eq(hm->method, "POST")) {
		char kv[SG_PAYLOAD_MAX];
		size_t klen = 0;

		if (mg_json_get(hm->body, "$.tuples", NULL) >= 0) {
			/* Batch: up to 64 "proto=.. src=.. dst=..\n" records. */
			char body[SG_PAYLOAD_MAX];
			size_t blen = 0;
			int i, recs = 0;

			for (i = 0; i < 64; i++) {
				char path[40];
				snprintf(path, sizeof(path), "$.tuples[%d].proto", i);
				char *pr = json_str(hm->body, path);
				snprintf(path, sizeof(path), "$.tuples[%d].src", i);
				char *sr = json_str(hm->body, path);
				snprintf(path, sizeof(path), "$.tuples[%d].dst", i);
				char *ds = json_str(hm->body, path);

				if (!pr && !sr && !ds)
					break;			/* past the array */
				if (!pr || !sr || !ds) {
					free(pr); free(sr); free(ds);
					reply_json(c, 400,
						   "{\"error\":\"Each tuple needs proto, src, dst\"}");
					return -1;
				}
				kv_append_tuple(body, sizeof(body), &blen, "proto", pr);
				kv_append_tuple(body, sizeof(body), &blen, "src",   sr);
				kv_append_tuple(body, sizeof(body), &blen, "dst",   ds);
				if (blen < sizeof(body)) body[blen++] = '\n';
				recs++;
			}
			if (recs == 0) {
				reply_json(c, 400, "{\"error\":\"No tuples\"}");
				return -1;
			}
			klen = (size_t)snprintf(kv, sizeof(kv), "tuples=%d\n", recs);
			if (klen + blen >= sizeof(kv)) {
				reply_json(c, 400,
					   "{\"error\":\"Too many sessions selected\"}");
				return -1;
			}
			memcpy(kv + klen, body, blen);
			klen += blen;
			kv[klen] = '\0';
		} else {
			int n = 0;
			n += kv_append_filter(kv, sizeof(kv), &klen, "proto",
					      json_str(hm->body, "$.proto"));
			n += kv_append_filter(kv, sizeof(kv), &klen, "src",
					      json_str(hm->body, "$.src"));
			n += kv_append_filter(kv, sizeof(kv), &klen, "dst",
					      json_str(hm->body, "$.dst"));
			n += kv_append_filter(kv, sizeof(kv), &klen, "policy",
					      json_str(hm->body, "$.policy"));
			n += kv_append_filter(kv, sizeof(kv), &klen, "iif",
					      json_str(hm->body, "$.iif"));
			n += kv_append_filter(kv, sizeof(kv), &klen, "oif",
					      json_str(hm->body, "$.oif"));
			if (n == 0) {
				reply_json(c, 400,
					   "{\"error\":\"No filter fields (proto|src|dst|policy|iif|oif)\"}");
				return -1;
			}
		}

		work_item_t item;
		memset(&item, 0, sizeof(item));
		item.conn_id     = c->id;
		item.ipc_cmd     = SG_CMD_SESSION_CLEAR;
		item.flow_type   = FLOW_SESSION_CLEAR;
		item.session_tag = sess.ipc_session_tag;
		snprintf(item.username, sizeof(item.username), "%s", sess.username);
		item.payload = strdup(kv);
		if (!item.payload) {
			reply_json(c, 500, "{\"error\":\"Internal error\"}");
			return -1;
		}
		item.payload_len = strlen(item.payload);
		if (webd_pool_enqueue(&item) != 0) {
			free(item.payload);
			reply_json(c, 503, "{\"error\":\"Server busy\"}");
			return -1;
		}
		return 0;
	}

	/* ── /api/monitor/ips ── IPS daemon status (key=value JSON) ──── */
	if (strcmp(segs[0], "monitor") == 0 && nseg == 2 &&
	    strcmp(segs[1], "ips") == 0 &&
	    mg_str_eq(hm->method, "GET")) {

		work_item_t item;
		memset(&item, 0, sizeof(item));
		item.conn_id = c->id;
		item.ipc_cmd = SG_CMD_IPS_STATUS;
		item.flow_type = FLOW_IPS_STATUS;
		snprintf(item.username, sizeof(item.username), "%s", sess.username);
		item.session_tag = sess.ipc_session_tag;
		if (webd_pool_enqueue(&item) != 0) {
			reply_json(c, 503, "{\"error\":\"Server busy\"}");
			return -1;
		}
		return 0;
	}

	/* ── /api/monitor/ssl ── SSL inspection diagnostics ──────────── */
	if (strcmp(segs[0], "monitor") == 0 && nseg == 2 &&
	    strcmp(segs[1], "ssl") == 0 && mg_str_eq(hm->method, "GET")) {
		work_item_t item;
		memset(&item, 0, sizeof(item));
		item.conn_id = c->id;
		item.ipc_cmd = SG_CMD_SSL_DIAG;
		item.flow_type = FLOW_IPS_UPDATE;   /* flow_diagnose → {"output":...} */
		snprintf(item.username, sizeof(item.username), "%s", sess.username);
		item.session_tag = sess.ipc_session_tag;
		if (webd_pool_enqueue(&item) != 0) {
			reply_json(c, 503, "{\"error\":\"Server busy\"}");
			return -1;
		}
		return 0;
	}

	/* ── /api/monitor/ssl-cacert ── SSL inspection CA cert (PEM) ──── */
	if (strcmp(segs[0], "monitor") == 0 && nseg == 2 &&
	    strcmp(segs[1], "ssl-cacert") == 0 && mg_str_eq(hm->method, "GET")) {
		work_item_t item;
		memset(&item, 0, sizeof(item));
		item.conn_id = c->id;
		item.ipc_cmd = SG_CMD_SSL_CACERT;
		item.flow_type = FLOW_IPS_UPDATE;
		snprintf(item.username, sizeof(item.username), "%s", sess.username);
		item.session_tag = sess.ipc_session_tag;
		if (webd_pool_enqueue(&item) != 0) {
			reply_json(c, 503, "{\"error\":\"Server busy\"}");
			return -1;
		}
		return 0;
	}

	/* ── /api/monitor/ips-alerts ── recent IPS alerts (default 20) ─ */
	if (strcmp(segs[0], "monitor") == 0 && nseg == 2 &&
	    strcmp(segs[1], "ips-alerts") == 0 &&
	    mg_str_eq(hm->method, "GET")) {

		work_item_t item;
		memset(&item, 0, sizeof(item));
		item.conn_id = c->id;
		item.ipc_cmd = SG_CMD_IPS_ALERTS;
		item.flow_type = FLOW_IPS_ALERTS;
		snprintf(item.username, sizeof(item.username), "%s", sess.username);
		item.session_tag = sess.ipc_session_tag;
		if (webd_pool_enqueue(&item) != 0) {
			reply_json(c, 503, "{\"error\":\"Server busy\"}");
			return -1;
		}
		return 0;
	}

	/* ── /api/ips/signatures ── catalog signature cho modal Add Sig ── */
	if (strcmp(segs[0], "ips") == 0 && nseg == 2 &&
	    strcmp(segs[1], "signatures") == 0 &&
	    mg_str_eq(hm->method, "GET")) {

		/* ?q= search → forward to mgmtd (response IPC limited to 64KB,
		 * so large rulesets must be filtered server-side). */
		char *search = query_param(hm->query, "q");

		work_item_t item;
		memset(&item, 0, sizeof(item));
		item.conn_id = c->id;
		item.ipc_cmd = SG_CMD_IPS_SIGNATURES;
		item.flow_type = FLOW_IPS_SIGS;
		snprintf(item.username, sizeof(item.username), "%s", sess.username);
		item.session_tag = sess.ipc_session_tag;
		if (search && search[0]) {
			size_t n = strlen(search) + 3; /* "q=" + NUL */
			item.payload = malloc(n);
			if (item.payload) {
				snprintf(item.payload, n, "q=%s", search);
				item.payload_len = strlen(item.payload);
			}
		}
		free(search);
		if (webd_pool_enqueue(&item) != 0) {
			free(item.payload);
			reply_json(c, 503, "{\"error\":\"Server busy\"}");
			return -1;
		}
		return 0;
	}

	/* ── /api/ips/alerts-json ── structured JSON alert log ────────── */
	if (strcmp(segs[0], "ips") == 0 && nseg == 2 &&
	    strcmp(segs[1], "alerts-json") == 0 &&
	    mg_str_eq(hm->method, "GET")) {

		work_item_t item;
		memset(&item, 0, sizeof(item));
		item.conn_id = c->id;
		item.ipc_cmd = SG_CMD_IPS_ALERTS_JSON;
		item.flow_type = FLOW_IPS_ALERTS_JSON;
		snprintf(item.username, sizeof(item.username), "%s", sess.username);
		item.session_tag = sess.ipc_session_tag;
		/* forward optional ?lines=N query param */
		if (hm->query.len > 0) {
			char qbuf[64] = "";
			struct mg_str q = hm->query;
			if (q.len < sizeof(qbuf)) {
				memcpy(qbuf, q.buf, q.len); qbuf[q.len] = '\0';
			}
			snprintf(item.extra, sizeof(item.extra), "%s", qbuf);
		}
		if (webd_pool_enqueue(&item) != 0) {
			reply_json(c, 503, "{\"error\":\"Server busy\"}");
			return -1;
		}
		return 0;
	}

	/* ── GET /api/ips/update-log ── tail ips-update.log ─────────────────── */
	if (strcmp(segs[0], "ips") == 0 && nseg == 2 &&
	    strcmp(segs[1], "update-log") == 0 &&
	    mg_str_eq(hm->method, "GET")) {

		work_item_t item;
		memset(&item, 0, sizeof(item));
		item.conn_id  = c->id;
		item.ipc_cmd  = SG_CMD_IPS_UPDATE_LOG;
		item.flow_type = FLOW_IPS_UPDATE_LOG;
		snprintf(item.username, sizeof(item.username), "%s", sess.username);
		item.session_tag = sess.ipc_session_tag;
		if (webd_pool_enqueue(&item) != 0) {
			reply_json(c, 503, "{\"error\":\"Server busy\"}");
			return -1;
		}
		return 0;
	}

	/* ── POST /api/ips/reload ── hot-reload ipsd (rebuild active.rules) ── */
	if (strcmp(segs[0], "ips") == 0 && nseg == 2 &&
	    strcmp(segs[1], "reload") == 0 &&
	    mg_str_eq(hm->method, "POST")) {

		work_item_t item;
		memset(&item, 0, sizeof(item));
		item.conn_id = c->id;
		item.ipc_cmd = SG_CMD_IPS_REBUILD;
		item.flow_type = FLOW_SIMPLE;
		snprintf(item.username, sizeof(item.username), "%s", sess.username);
		item.session_tag = sess.ipc_session_tag;
		if (webd_pool_enqueue(&item) != 0) {
			reply_json(c, 503, "{\"error\":\"Server busy\"}");
			return -1;
		}
		return 0;
	}

	/* ── POST /api/ips/rulesets-reload ── scan custom dir + upsert DB ─── */
	if (strcmp(segs[0], "ips") == 0 && nseg == 2 &&
	    strcmp(segs[1], "rulesets-reload") == 0 &&
	    mg_str_eq(hm->method, "POST")) {

		work_item_t item;
		memset(&item, 0, sizeof(item));
		item.conn_id  = c->id;
		item.ipc_cmd  = SG_CMD_IPS_RULESETS_RELOAD;
		item.flow_type = FLOW_IPS_UPDATE;   /* uses flow_diagnose → {"output":"..."} */
		snprintf(item.username, sizeof(item.username), "%s", sess.username);
		item.session_tag = sess.ipc_session_tag;
		if (webd_pool_enqueue(&item) != 0) {
			reply_json(c, 503, "{\"error\":\"Server busy\"}");
			return -1;
		}
		return 0;
	}

	/* ── POST /api/ips/update-now ── download rulesets + rebuild ──────── */
	if (strcmp(segs[0], "ips") == 0 && nseg == 2 &&
	    strcmp(segs[1], "update-now") == 0 &&
	    mg_str_eq(hm->method, "POST")) {

		work_item_t item;
		memset(&item, 0, sizeof(item));
		item.conn_id = c->id;
		item.ipc_cmd = SG_CMD_IPS_UPDATE_NOW;
		item.flow_type = FLOW_IPS_UPDATE;
		snprintf(item.username, sizeof(item.username), "%s", sess.username);
		item.session_tag = sess.ipc_session_tag;
		/* Optional: "ids" = comma-separated ruleset IDs to download */
		char *ids_val = json_str(hm->body, "$.ids");
		if (ids_val && ids_val[0]) {
			item.payload = strdup(ids_val);
			item.payload_len = item.payload ? strlen(item.payload) : 0;
		}
		free(ids_val);
		if (webd_pool_enqueue(&item) != 0) {
			reply_json(c, 503, "{\"error\":\"Server busy\"}");
			return -1;
		}
		return 0;
	}

	/* ── POST /api/ips/alerts-clear ── truncate alert log ─────────────── */
	if (strcmp(segs[0], "ips") == 0 && nseg == 2 &&
	    strcmp(segs[1], "alerts-clear") == 0 &&
	    mg_str_eq(hm->method, "POST")) {

		/* Via mgmtd (root): /etc/stargazer/logs is 0700 root, so webd (uid 900)
		 * CANNOT truncate it directly — previously open() failed silently but
		 * still reported {ok:true}. Now delegate the actual deletion to mgmtd. */
		work_item_t item;
		memset(&item, 0, sizeof(item));
		item.conn_id  = c->id;
		item.ipc_cmd  = SG_CMD_IPS_ALERTS_CLEAR;
		item.flow_type = FLOW_SIMPLE;
		snprintf(item.username, sizeof(item.username), "%s", sess.username);
		item.session_tag = sess.ipc_session_tag;
		if (webd_pool_enqueue(&item) != 0) {
			reply_json(c, 503, "{\"error\":\"Server busy\"}");
			return -1;
		}
		return 0;
	}

	/* ── /api/monitor/dhcp-leases ───────────────────────────────── */
	if (strcmp(segs[0], "monitor") == 0 && nseg == 2 &&
	    strcmp(segs[1], "dhcp-leases") == 0 &&
	    mg_str_eq(hm->method, "GET")) {

		work_item_t item;
		memset(&item, 0, sizeof(item));
		item.conn_id = c->id;
		item.ipc_cmd = SG_CMD_DIAG_DHCP_LEASES;
		item.flow_type = FLOW_MONITOR_DHCP;
		snprintf(item.username, sizeof(item.username),
			 "%s", sess.username);
		item.session_tag = sess.ipc_session_tag;

		if (webd_pool_enqueue(&item) != 0) {
			reply_json(c, 503, "{\"error\":\"Server busy\"}");
			return -1;
		}
		return 0;
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
		if (!payload) {
			free(target);
			free(iface);
			reply_json(c, 503,
				   "{\"error\":\"Internal error\"}");
			return -1;
		}
		if (iface)
			snprintf(payload, plen,
				 "target=%s\niface=%s\n",
				 target, iface);
		else
			snprintf(payload, plen,
				 "target=%s\n", target);
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
		item.payload_len = strlen(payload);

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
