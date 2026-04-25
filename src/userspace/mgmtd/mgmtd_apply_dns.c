/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_dns.c — Apply handler for network_dns
 *
 * DNS is always on.  Writes /etc/resolv.conf from saved configuration.
 */

#include "mgmtd_apply.h"

#include <stdio.h>
#include <string.h>

sg_status_t apply_dns(const char *id, const char *data,
		      char *result, size_t rsize)
{
	(void)id;

	char primary[VALBUFSZ], secondary[VALBUFSZ];
	extract_val(data, "primary",   primary,   sizeof(primary));
	extract_val(data, "secondary", secondary, sizeof(secondary));

	if (!primary[0] && !secondary[0]) {
		snprintf(result, rsize, "DNS: no servers configured.");
		return SG_OK;
	}

	FILE *fp = fopen("/etc/resolv.conf", "w");
	if (!fp) {
		snprintf(result, rsize, "Failed to write /etc/resolv.conf.");
		return SG_ERR_IO_FAIL;
	}

	if (primary[0])
		fprintf(fp, "nameserver %s\n", primary);
	if (secondary[0])
		fprintf(fp, "nameserver %s\n", secondary);

	fclose(fp);

	snprintf(result, rsize, "DNS configured (primary: %s%s%s).",
		 primary[0]   ? primary   : "",
		 (primary[0] && secondary[0]) ? ", secondary: " : "",
		 secondary[0] ? secondary : "");
	return SG_OK;
}
