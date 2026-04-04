/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_ntp.c — Apply handler for system_ntp
 *
 * NTP is always on.  The handler stops any existing ntpd, then starts
 * a new BusyBox ntpd under the supervisor (SRC_ALWAYS) so it is
 * automatically restarted on crash.
 */

#include "mgmtd_apply.h"

#include <stdio.h>
#include <string.h>

#define NTP_CHILD_NAME "ntpd"

sg_status_t apply_ntp(const char *id, const char *data,
		      char *result, size_t rsize)
{
	(void)id;

	/* Always stop the old instance first */
	supervisor_stop(NTP_CHILD_NAME);

	char server[VALBUFSZ];
	extract_val(data, "server", server, sizeof(server));

	if (!server[0]) {
		snprintf(result, rsize, "NTP: no server configured, daemon stopped.");
		return SG_OK;
	}

	/* BusyBox ntpd: -n = foreground (required for supervisor), -p = server */
	const char *argv[] = {
		"/usr/sbin/ntpd", "-n", "-p", server, NULL
	};

	/* SRC_ALWAYS — always restart on crash, NTP must never stay down */
	supervisor_start(NTP_CHILD_NAME, argv, SRC_ALWAYS,
			 NULL, NULL, NULL, NULL);

	snprintf(result, rsize, "NTP started (server: %s).", server);
	return SG_OK;
}
