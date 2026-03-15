/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_ntp.c — Apply handler for system_ntp
 *
 * Writes /etc/ntp.conf from saved NTP configuration and signals
 * ntpd to reload if it is running.
 */

#include "mgmtd_apply.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

sg_status_t apply_ntp(const char *id, const char *data,
		      char *result, size_t rsize)
{
	(void)id;

	char server[VALBUFSZ], status[VALBUFSZ];
	extract_val(data, "server", server, sizeof(server));
	extract_val(data, "status", status, sizeof(status));

	if (strcmp(status, "disable") == 0) {
		snprintf(result, rsize, "NTP disabled.");
		return SG_OK;
	}

	if (!server[0]) {
		snprintf(result, rsize, "NTP: no server configured.");
		return SG_OK;
	}

	FILE *fp = fopen("/etc/ntp.conf", "w");
	if (!fp) {
		snprintf(result, rsize, "Failed to write /etc/ntp.conf.");
		return SG_ERR_IO_FAIL;
	}
	fprintf(fp, "server %s iburst\n", server);
	fprintf(fp, "driftfile /var/lib/ntp/ntp.drift\n");
	fclose(fp);

	/* Signal ntpd to reload if running */
	FILE *pidf = fopen("/run/ntpd.pid", "r");
	if (pidf) {
		int ntpd_pid = 0;
		if (fscanf(pidf, "%d", &ntpd_pid) == 1 && ntpd_pid > 0)
			kill(ntpd_pid, SIGHUP);
		fclose(pidf);
	}

	snprintf(result, rsize, "NTP configured (server: %s).", server);
	return SG_OK;
}
