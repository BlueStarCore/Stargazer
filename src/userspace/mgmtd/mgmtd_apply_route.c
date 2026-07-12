/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_route.c — Apply handler for network_route_static
 *
 * Extracted from stargazer-mgmtd.c for parallel development.
 */

#include "mgmtd_apply.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

sg_status_t apply_route_static(const char *id, const char *data,
			       char *result, size_t rsize)
{
	char dst[VALBUFSZ], gw[VALBUFSZ], dev[VALBUFSZ];
	char dist[VALBUFSZ], status[VALBUFSZ];
	extract_val(data, "dst", dst, sizeof(dst));
	extract_val(data, "gateway", gw, sizeof(gw));
	extract_val(data, "device", dev, sizeof(dev));
	extract_val(data, "distance", dist, sizeof(dist));
	extract_val(data, "status", status, sizeof(status));

	/* Validate all inputs before any system call */
	if (dst[0] && !sg_is_cidr(dst)) {
		snprintf(result, rsize, "Invalid dst '%s'.", dst);
		return SG_ERR_INVALID_VAL;
	}
	if (gw[0] && !sg_is_ipv4(gw)) {
		snprintf(result, rsize, "Invalid gateway '%s'.", gw);
		return SG_ERR_INVALID_VAL;
	}
	if (dev[0] && !sg_is_iface_name(dev)) {
		snprintf(result, rsize, "Invalid device '%s'.", dev);
		return SG_ERR_INVALID_VAL;
	}
	if (dist[0] && !sg_is_uint_range(dist, 1, 255)) {
		snprintf(result, rsize, "Invalid distance '%s'.", dist);
		return SG_ERR_INVALID_VAL;
	}
	if (dev[0] && !iface_exists(dev)) {
		snprintf(result, rsize,
			 "Device '%s' not present, route not applied.", dev);
		return SG_ERR_NOT_FOUND;
	}

	if (strcmp(status, "disable") == 0) {
		/* Remove this specific route if it exists.
		 * Check ip route output first to avoid deleting a
		 * connected route with the same dst (BusyBox ip route
		 * del ignores proto filter). */
		if (dst[0]) {
			const char *ls[] = {"ip", "route", "show", dst, NULL};
			char *cur = safe_exec(ls);
			if (cur && strstr(cur, "proto static")) {
				const char *del[] = {"ip", "route", "del",
						     dst, NULL};
				free(safe_exec(del));
			}
			free(cur);
		}
		snprintf(result, rsize, "Route %s disabled.", id);
		return SG_OK;
	}
	if (dst[0] == '\0') {
		snprintf(result, rsize, "'dst' not set, route not applied.");
		return SG_ERR_MISSING_ARG;
	}

	/*
	 * Build argv for ip route replace.
	 * "ip route replace DST proto static [via GW] [dev DEV] [metric DIST]"
	 * proto static: marks route as user-managed so flush proto static
	 * correctly removes it before replay.
	 */
	const char *argv[16];
	int argc = 0;
	argv[argc++] = "ip";
	argv[argc++] = "route";
	argv[argc++] = "replace";
	argv[argc++] = dst;
	argv[argc++] = "proto";
	argv[argc++] = "static";
	if (gw[0])  { argv[argc++] = "via";    argv[argc++] = gw;   }
	if (dev[0]) { argv[argc++] = "dev";    argv[argc++] = dev;  }
	if (dist[0]){ argv[argc++] = "metric"; argv[argc++] = dist; }
	argv[argc] = NULL;
	char *out = safe_exec(argv);
	if (out && out[0]) {
		/* Trim trailing newline for cleaner error messages */
		size_t olen = strlen(out);
		while (olen > 0 && (out[olen-1] == '\n' || out[olen-1] == '\r'))
			out[--olen] = '\0';
		snprintf(result, rsize, "Route %s failed: %s", id, out);
		free(out);
		return SG_ERR_SYSTEM_FAIL;
	}
	free(out);

	snprintf(result, rsize, "Route %s applied: %s", id, dst);
	return SG_OK;
}
