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
		if (dst[0]) {
			const char *argv[] = {"ip", "route", "del", dst, NULL};
			free(safe_exec(argv));
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
	 * "ip route replace DST [via GW] [dev DEV] [metric DIST]"
	 */
	const char *argv[14];
	int argc = 0;
	argv[argc++] = "ip";
	argv[argc++] = "route";
	argv[argc++] = "replace";
	argv[argc++] = dst;
	if (gw[0])  { argv[argc++] = "via";    argv[argc++] = gw;   }
	if (dev[0]) { argv[argc++] = "dev";    argv[argc++] = dev;  }
	if (dist[0]){ argv[argc++] = "metric"; argv[argc++] = dist; }
	argv[argc] = NULL;
	free(safe_exec(argv));

	snprintf(result, rsize, "Route %s applied: %s", id, dst);
	return SG_OK;
}
