/* SPDX-License-Identifier: MIT */
/*
 * webd_api.h — REST API route dispatch
 *
 * All API routes start with /api/. Non-API paths are served as static
 * files by the main event handler.
 */

#ifndef WEBD_API_H
#define WEBD_API_H

#include "mongoose.h"
#include "webd_pool.h"

/* TLS active flag — set in stargazer-webd.c when certs are loaded */
extern int g_tls_active;

/* Base security headers for all JSON API responses. */
#define WEBD_SEC_HEADERS \
	"Content-Type: application/json\r\n" \
	"X-Content-Type-Options: nosniff\r\n" \
	"X-Frame-Options: DENY\r\n" \
	"Content-Security-Policy: default-src 'self'\r\n" \
	"Cache-Control: no-store\r\n"

/* HSTS header — added dynamically when TLS is active */
#define WEBD_HSTS_HEADER \
	"Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"

/*
 * Build full security headers string with HSTS when TLS is active.
 * Uses a static buffer — NOT thread-safe, use from main thread only.
 */
static inline const char *webd_sec_headers(void)
{
	static char buf[512];
	if (g_tls_active)
		snprintf(buf, sizeof(buf), "%s%s",
			 WEBD_SEC_HEADERS, WEBD_HSTS_HEADER);
	else
		snprintf(buf, sizeof(buf), "%s", WEBD_SEC_HEADERS);
	return buf;
}

/*
 * Dispatch an API request. Called from main thread on MG_EV_HTTP_MSG
 * for paths starting with /api/.
 *
 * Returns 0 if the request was dispatched to the thread pool (response
 * will come via MG_EV_WAKEUP), or -1 if the response was sent inline
 * (error cases like 401, 429, 503).
 */
int webd_api_dispatch(struct mg_http_message *hm, struct mg_connection *c);

#endif /* WEBD_API_H */
