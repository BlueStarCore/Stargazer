/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose_bootlog.c — View boot log and system messages via IPC
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_diagnose_bootlog.h"
#include "cli_ipc.h"
#include <stdio.h>
#include <string.h>

/* View kernel boot log (dmesg) */
int cmd_diagnose_system_bootlog(const char *args, const char *permissions)
{
	(void)permissions;
	char payload[32] = "";

	if (args && *args) {
		/* Optional line count argument */
		snprintf(payload, sizeof(payload), "%s", args);
	}

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_LOG_SYSTEM, payload, &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		printf("  Error [%u]: %s\n", resp.status,
		       resp.extra[0] ? resp.extra : sg_status_str(resp.status));
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

/* Filter dmesg for stargazer init messages */
int cmd_diagnose_system_stargazer_log(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_DIAG_STARGAZER_LOG, "", &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		printf("  Error [%u]: %s\n", resp.status,
		       resp.extra[0] ? resp.extra : sg_status_str(resp.status));
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}

/* Show storage mount status and health */
int cmd_diagnose_system_storage(const char *args, const char *permissions)
{
	(void)args;
	(void)permissions;

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_DIAG_STORAGE, "", &resp) != 0) {
		ipc_resp_free(&resp);
		printf("  Error: could not contact management daemon.\n");
		return 0;
	}

	if (resp.status != SG_OK) {
		printf("  Error [%u]: %s\n", resp.status,
		       resp.extra[0] ? resp.extra : sg_status_str(resp.status));
		ipc_resp_free(&resp);
		return 0;
	}

	if (resp.payload && resp.payload_len > 0)
		printf("%s", resp.payload);

	ipc_resp_free(&resp);
	return 0;
}
