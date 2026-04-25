/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose_dhcp.c — DHCP client/server cross-validation tests
 *
 * Implements "execute diagnose selftest dhcp":
 *   - Mode 0: no local-only tests (all checks need IPC)
 *   - Mode 1: IPC round-trip tests for DHCP cross-validation
 *
 * Tests verify that an interface cannot be both a DHCP client
 * (udhcpc) and a DHCP server (udhcpd) simultaneously.
 *
 * Uses loopback (lo) as the test interface — always exists in
 * the kernel and IPC is Unix socket so lo IP changes are safe.
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_diagnose.h"
#include "cli_ipc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Test counters ────────────────────────────────────────────────────── */

static int dhcp_pass;
static int dhcp_fail;
static int dhcp_total;

/* ── Test constants ───────────────────────────────────────────────────── */

#define TEST_POOL  "__diag_dhcp"
#define TEST_IFACE "lo"

/* CFG_APPLY payloads: "type\nid\nkey=val\n..." */
#define APPLY_POOL_ENABLE \
	"network_dhcp-server\n" TEST_POOL "\n" \
	"interface=" TEST_IFACE "\n" \
	"start-ip=192.168.99.1\n" \
	"end-ip=192.168.99.10\n" \
	"netmask=255.255.255.0\n" \
	"lease-time=3600\n" \
	"status=enable\n"

#define APPLY_IFACE_DHCP \
	"system_interface\n" TEST_IFACE "\n" \
	"mode=dhcp\nstatus=up\nmtu=1500\n"

#define APPLY_IFACE_STATIC \
	"system_interface\n" TEST_IFACE "\n" \
	"mode=static\nip=127.0.0.1/8\nstatus=up\nmtu=1500\n"

/* CFG_SET payloads: "type:id\nkey=val\n..." */
#define SET_IFACE_DHCP \
	"system_interface:" TEST_IFACE "\n" \
	"mode=dhcp\nip=127.0.0.1/8\nstatus=up\nmtu=1500\n"

#define SET_IFACE_STATIC \
	"system_interface:" TEST_IFACE "\n" \
	"mode=static\nstatus=up\nip=127.0.0.1/8\nmtu=1500\n"

#define SET_POOL_ENABLE \
	"network_dhcp-server:" TEST_POOL "\n" \
	"interface=" TEST_IFACE "\n" \
	"start-ip=192.168.99.1\n" \
	"end-ip=192.168.99.10\n" \
	"netmask=255.255.255.0\n" \
	"lease-time=3600\n" \
	"status=enable\n"

#define SET_POOL_DISABLE \
	"network_dhcp-server:" TEST_POOL "\n" \
	"interface=" TEST_IFACE "\n" \
	"start-ip=192.168.99.1\n" \
	"end-ip=192.168.99.10\n" \
	"netmask=255.255.255.0\n" \
	"lease-time=3600\n" \
	"status=disable\n"

/* CFG_DEL / CFG_GET payload: "type:id" */
#define SECTION_POOL  "network_dhcp-server:" TEST_POOL
#define SECTION_IFACE "system_interface:" TEST_IFACE

/* ── Assertion helpers ────────────────────────────────────────────────── */

static void
dhcp_check_status(const char *id, const char *desc,
		  uint32_t opcode, const char *payload,
		  uint32_t expect)
{
	struct ipc_response resp;
	int conn;

	dhcp_total++;
	conn = ipc_send_str(opcode, payload, &resp);

	if (conn == 0 && resp.status == expect) {
		dhcp_pass++;
		printf(C_GREEN "  PASS" C_NC " [%s] %s (status=%u)\n",
		       id, desc, expect);
	} else {
		dhcp_fail++;
		printf(C_RED "  FAIL" C_NC " [%s] %s"
		       " (expected status=%u, got %u)\n",
		       id, desc, expect,
		       conn < 0 ? 999 : resp.status);
	}

	ipc_resp_free(&resp);
}

static void
dhcp_check_not_status(const char *id, const char *desc,
		      uint32_t opcode, const char *payload,
		      uint32_t reject)
{
	struct ipc_response resp;
	int conn;

	dhcp_total++;
	conn = ipc_send_str(opcode, payload, &resp);

	if (conn == 0 && resp.status != reject) {
		dhcp_pass++;
		printf(C_GREEN "  PASS" C_NC " [%s] %s"
		       " (status=%u, not %u)\n",
		       id, desc, resp.status, reject);
	} else {
		dhcp_fail++;
		printf(C_RED "  FAIL" C_NC " [%s] %s"
		       " (got status=%u, must not be %u)\n",
		       id, desc,
		       conn < 0 ? 999 : resp.status, reject);
	}

	ipc_resp_free(&resp);
}

/* Fire-and-forget IPC helper (for setup/teardown, result ignored) */
static void
dhcp_ipc(uint32_t opcode, const char *payload)
{
	struct ipc_response resp;
	ipc_send_str(opcode, payload, &resp);
	ipc_resp_free(&resp);
}

/* ── Test: DHCP cross-validation (IPC required) ──────────────────────── */

static void test_dhcp_cross_validation(void)
{
	/* ── Save original interface config (if any) ──────────────── */
	struct ipc_response orig;
	int had_orig = 0;
	char orig_data[4096] = {0};

	if (ipc_send_str(SG_CMD_CFG_GET, SECTION_IFACE, &orig) == 0 &&
	    orig.status == SG_OK && orig.payload && orig.payload_len > 0) {
		had_orig = 1;
		size_t clen = orig.payload_len;
		if (clen >= sizeof(orig_data))
			clen = sizeof(orig_data) - 1;
		memcpy(orig_data, orig.payload, clen);
		orig_data[clen] = '\0';
	}
	ipc_resp_free(&orig);

	/* ── SEC-DHCP-1: Enable server on DHCP-client interface ───── */
	printf(C_CYAN "\n  --- SEC-DHCP-1: Server on DHCP-client interface"
	       " → reject ---" C_NC "\n");

	/* Set interface lo to mode=dhcp in DB */
	dhcp_ipc(SG_CMD_CFG_SET, SET_IFACE_DHCP);

	/* Try to apply DHCP pool on lo — must be rejected */
	dhcp_check_status("SEC-DHCP-1",
			  "DHCP server on client interface rejected",
			  SG_CMD_CFG_APPLY, APPLY_POOL_ENABLE,
			  SG_ERR_IN_USE);

	/* ── SEC-DHCP-2: Switch to DHCP client with active pool ───── */
	printf(C_CYAN "\n  --- SEC-DHCP-2: Client with active server pool"
	       " → reject ---" C_NC "\n");

	/* Restore interface to static in DB */
	dhcp_ipc(SG_CMD_CFG_SET, SET_IFACE_STATIC);

	/* Put an enabled pool in DB */
	dhcp_ipc(SG_CMD_CFG_SET, SET_POOL_ENABLE);

	/* Try to apply interface with mode=dhcp — must be rejected */
	dhcp_check_status("SEC-DHCP-2",
			  "DHCP client with active server rejected",
			  SG_CMD_CFG_APPLY, APPLY_IFACE_DHCP,
			  SG_ERR_IN_USE);

	/* ── SEC-DHCP-3: Server on static interface (happy path) ──── */
	printf(C_CYAN "\n  --- SEC-DHCP-3: Server on static interface"
	       " → allow ---" C_NC "\n");

	/* Remove pool from DB so dhcpd_iface_conflict doesn't fire */
	dhcp_ipc(SG_CMD_CFG_DEL, SECTION_POOL);

	/* Interface is still static in DB from SEC-DHCP-2 setup.
	 * Apply DHCP pool — cross-validation should pass.
	 * May return SG_OK or SG_ERR_SYSTEM_FAIL (udhcpd on lo),
	 * but must NOT return SG_ERR_IN_USE. */
	dhcp_check_not_status("SEC-DHCP-3",
			      "DHCP server on static interface allowed",
			      SG_CMD_CFG_APPLY, APPLY_POOL_ENABLE,
			      SG_ERR_IN_USE);

	/* Stop any daemon that may have started */
	dhcp_ipc(SG_CMD_CFG_DEL, SECTION_POOL);

	/* ── SEC-DHCP-4: Disabled pool ignored for client switch ──── */
	printf(C_CYAN "\n  --- SEC-DHCP-4: Disabled pool ignored"
	       " → allow client ---" C_NC "\n");

	/* Put a disabled pool in DB */
	dhcp_ipc(SG_CMD_CFG_SET, SET_POOL_DISABLE);

	/* Apply interface with mode=dhcp — disabled pool should not
	 * block.  May return SG_OK or other errors, but must NOT
	 * return SG_ERR_IN_USE. */
	dhcp_check_not_status("SEC-DHCP-4",
			      "disabled pool ignored for DHCP client",
			      SG_CMD_CFG_APPLY, APPLY_IFACE_DHCP,
			      SG_ERR_IN_USE);

	/* Restore lo to static with 127.0.0.1/8 immediately */
	dhcp_ipc(SG_CMD_CFG_APPLY, APPLY_IFACE_STATIC);

	/* ── Cleanup ──────────────────────────────────────────────── */
	dhcp_ipc(SG_CMD_CFG_DEL, SECTION_POOL);

	if (had_orig) {
		/* Restore original interface config */
		char restore[4096 + 256];
		snprintf(restore, sizeof(restore),
			 SECTION_IFACE "\n%s", orig_data);
		dhcp_ipc(SG_CMD_CFG_SET, restore);
	} else {
		/* Interface wasn't in DB before — remove our entry */
		dhcp_ipc(SG_CMD_CFG_DEL, SECTION_IFACE);
	}
}

/* ── Public entry point ───────────────────────────────────────────────── */

int cli_diagnose_test_dhcp(int mode, diag_result_t *out)
{
	dhcp_pass  = 0;
	dhcp_fail  = 0;
	dhcp_total = 0;

	printf("\n  Stargazer DHCP Cross-Validation Tests\n");
	printf("  ======================================\n");

	if (mode == 0) {
		printf("  (no local-only tests — run 'selftest dhcp'"
		       " for full IPC tests)\n");
	}

	if (mode == 1) {
		if (!ipc_available()) {
			printf(C_RED "\n  ERROR" C_NC
			       ": mgmtd socket not found (%s)\n",
			       SG_MGMTD_SOCK);
			printf("  IPC tests skipped."
			       " Run with mgmtd for full test.\n");
		} else {
			test_dhcp_cross_validation();
		}
	}

	/* Summary */
	printf("\n  Results: %d/%d passed", dhcp_pass, dhcp_total);
	if (dhcp_fail > 0)
		printf(C_RED ", %d FAILED" C_NC, dhcp_fail);
	else if (dhcp_total > 0)
		printf(C_GREEN " (all passed)" C_NC);
	printf("\n\n");

	if (out) {
		out->passed = dhcp_pass;
		out->failed = dhcp_fail;
		out->total  = dhcp_total;
	}

	return dhcp_fail > 0 ? 1 : 0;
}
