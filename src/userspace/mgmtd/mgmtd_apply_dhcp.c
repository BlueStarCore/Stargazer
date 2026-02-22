/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_dhcp.c — Apply handler for network_dhcp-server
 *
 * Stub — Member A fills in the real DHCP server implementation.
 */

#include "mgmtd_apply.h"

#include <stdio.h>

sg_status_t apply_dhcp(const char *id, const char *data,
		       char *result, size_t rsize)
{
	(void)id;
	(void)data;
	snprintf(result, rsize,
		 "Config saved (DHCP apply handler not implemented).");
	return SG_OK;
}
