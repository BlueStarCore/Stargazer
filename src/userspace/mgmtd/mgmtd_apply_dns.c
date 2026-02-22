/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_dns.c — Apply handler for network_dns
 *
 * Stub — Member A fills in the real DNS forwarding implementation.
 */

#include "mgmtd_apply.h"

#include <stdio.h>

sg_status_t apply_dns(const char *id, const char *data,
		      char *result, size_t rsize)
{
	(void)id;
	(void)data;
	snprintf(result, rsize,
		 "Config saved (DNS apply handler not implemented).");
	return SG_OK;
}
