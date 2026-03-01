/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose_fw.c — Firewall & network validator diagnostics for Stargazer CLI
 *
 * Firewall test suite for "execute diagnose selftest [full]":
 *   - Basic: exercises access-services, interface-name, CIDR, IPv4 validators,
 *            and TFTP allowaccess rejection (SEC-FW-7)
 *   - Full:  IPC round-trip tests for diagnostic commands (requires mgmtd),
 *            INPUT chain structure (SEC-FW-8), CT helper rules (SEC-FW-9)
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_diagnose.h"
#include "cli_ipc.h"
#include "sg_validate.h"

#include <stdio.h>
#include <string.h>

/* ── Test counters ────────────────────────────────────────────────────── */

static int fw_pass;
static int fw_fail;
static int fw_total;

/* ── Generic assertion helper ─────────────────────────────────────────── */

static void fw_check(const char *section, const char *desc,
		     int result, int expected)
{
	fw_total++;
	if (result == expected) {
		fw_pass++;
		printf(C_GREEN "  PASS" C_NC " [%s] %s\n", section, desc);
	} else {
		fw_fail++;
		printf(C_RED "  FAIL" C_NC " [%s] %s (got %d, expected %d)\n",
		       section, desc, result, expected);
	}
}

/* ── SEC-FW-1: sg_is_access_services validator ────────────────────────── */

static void test_access_services(void)
{
	printf(C_CYAN "\n  --- SEC-FW-1: access-services validator ---" C_NC "\n");

	/* Accept: individual valid services */
	fw_check("access-svc", "accept: 'ping'",
		 sg_is_access_services("ping"), 1);
	fw_check("access-svc", "accept: 'ssh'",
		 sg_is_access_services("ssh"), 1);
	fw_check("access-svc", "accept: 'https'",
		 sg_is_access_services("https"), 1);

	/* Accept: multiple valid services */
	fw_check("access-svc", "accept: 'ping ssh https'",
		 sg_is_access_services("ping ssh https"), 1);
	fw_check("access-svc", "accept: all six services",
		 sg_is_access_services("ping ssh https http snmp telnet"), 1);

	/* Accept: empty = no services */
	fw_check("access-svc", "accept: '' (empty = no services)",
		 sg_is_access_services(""), 1);

	/* Accept: NULL treated as empty by validator */
	fw_check("access-svc", "accept: NULL (treated as empty)",
		 sg_is_access_services(NULL), 1);

	/* Reject: unknown services */
	fw_check("access-svc", "reject: 'ftp' (unknown service)",
		 sg_is_access_services("ftp"), 0);
	fw_check("access-svc", "reject: 'ping ftp' (one invalid)",
		 sg_is_access_services("ping ftp"), 0);

	/* Reject: injection attempts */
	fw_check("access-svc", "reject: 'ssh;rm -rf' (injection)",
		 sg_is_access_services("ssh;rm -rf"), 0);

	/* Accept: double space (strtok_r handles it) */
	fw_check("access-svc", "accept: 'ping  ssh' (double space)",
		 sg_is_access_services("ping  ssh"), 1);
}

/* ── SEC-FW-2: sg_is_iface_name validator ─────────────────────────────── */

static void test_iface_name(void)
{
	printf(C_CYAN "\n  --- SEC-FW-2: interface-name validator ---" C_NC "\n");

	/* Accept: valid interface names */
	fw_check("iface", "accept: 'eth0'",
		 sg_is_iface_name("eth0"), 1);
	fw_check("iface", "accept: 'lan1'",
		 sg_is_iface_name("lan1"), 1);
	fw_check("iface", "accept: 'wan'",
		 sg_is_iface_name("wan"), 1);
	fw_check("iface", "accept: 'br-lan'",
		 sg_is_iface_name("br-lan"), 1);

	/* Reject: NULL and empty */
	fw_check("iface", "reject: NULL",
		 sg_is_iface_name(NULL), 0);
	fw_check("iface", "reject: '' (empty)",
		 sg_is_iface_name(""), 0);

	/* Reject: injection and invalid characters */
	fw_check("iface", "reject: 'eth0;reboot' (injection)",
		 sg_is_iface_name("eth0;reboot"), 0);
	fw_check("iface", "reject: '../etc' (path traversal)",
		 sg_is_iface_name("../etc"), 0);
	fw_check("iface", "reject: 'a b' (space)",
		 sg_is_iface_name("a b"), 0);
}

/* ── SEC-FW-3: Diagnostic IPC reachability (mode=1 only) ─────────────── */

static void test_diag_ipc_reachability(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- SEC-FW-3: diagnostic IPC reachability ---" C_NC "\n");

	/* SG_CMD_DIAG_FW_IPTABLES with valid table */
	conn = ipc_send_str(SG_CMD_DIAG_FW_IPTABLES, "table=filter\n", &resp);
	fw_check("diag-ipc", "iptables filter → SG_OK",
		 (conn == 0 && resp.status == SG_OK) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* SG_CMD_DIAG_FW_POLICY */
	conn = ipc_send_str(SG_CMD_DIAG_FW_POLICY, "", &resp);
	fw_check("diag-ipc", "policy → SG_OK",
		 (conn == 0 && resp.status == SG_OK) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* SG_CMD_DIAG_FW_CONNTRACK */
	conn = ipc_send_str(SG_CMD_DIAG_FW_CONNTRACK, "", &resp);
	fw_check("diag-ipc", "conntrack → SG_OK",
		 (conn == 0 && resp.status == SG_OK) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* SG_CMD_DIAG_ROUTES */
	conn = ipc_send_str(SG_CMD_DIAG_ROUTES, "", &resp);
	fw_check("diag-ipc", "routes → SG_OK",
		 (conn == 0 && resp.status == SG_OK) ? 1 : 0, 1);
	ipc_resp_free(&resp);
}

/* ── SEC-FW-4: Diagnostic input validation (mode=1 only) ─────────────── */

static void test_diag_input_validation(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- SEC-FW-4: diagnostic input validation ---" C_NC "\n");

	/* Invalid table name → SG_ERR_INVALID_ARG */
	conn = ipc_send_str(SG_CMD_DIAG_FW_IPTABLES, "table=mangle\n", &resp);
	fw_check("diag-val", "table=mangle → SG_ERR_INVALID_ARG",
		 (conn == 0 && resp.status == SG_ERR_INVALID_ARG) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* Injection attempt → SG_ERR_INVALID_ARG */
	conn = ipc_send_str(SG_CMD_DIAG_FW_IPTABLES,
			    "table=;rm -rf /\n", &resp);
	fw_check("diag-val", "table=;rm -rf / → SG_ERR_INVALID_ARG",
		 (conn == 0 && resp.status == SG_ERR_INVALID_ARG) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* Empty table value → rejected (extract_val overwrites default) */
	conn = ipc_send_str(SG_CMD_DIAG_FW_IPTABLES, "table=\n", &resp);
	fw_check("diag-val", "table= (empty) → SG_ERR_INVALID_ARG",
		 (conn == 0 && resp.status == SG_ERR_INVALID_ARG) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* No payload → defaults to filter → SG_OK */
	conn = ipc_send_str(SG_CMD_DIAG_FW_IPTABLES, "", &resp);
	fw_check("diag-val", "empty payload → SG_OK (default filter)",
		 (conn == 0 && resp.status == SG_OK) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* raw table (whitelisted for CT helper inspection) */
	conn = ipc_send_str(SG_CMD_DIAG_FW_IPTABLES, "table=raw\n", &resp);
	fw_check("diag-val", "table=raw → SG_OK",
		 (conn == 0 && resp.status == SG_OK) ? 1 : 0, 1);
	ipc_resp_free(&resp);
}

/* ── SEC-FW-5: Response payload presence (mode=1 only) ────────────────── */

static void test_diag_payload_presence(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- SEC-FW-5: response payload presence ---" C_NC "\n");

	/* iptables filter should return non-empty payload */
	conn = ipc_send_str(SG_CMD_DIAG_FW_IPTABLES, "table=filter\n", &resp);
	fw_check("payload", "iptables filter → non-empty payload",
		 (conn == 0 && resp.status == SG_OK &&
		  resp.payload != NULL && resp.payload_len > 0) ? 1 : 0, 1);
	ipc_resp_free(&resp);

	/* routes should contain header marker */
	conn = ipc_send_str(SG_CMD_DIAG_ROUTES, "", &resp);
	fw_check("payload", "routes → contains '=== IPv4 Routes ==='",
		 (conn == 0 && resp.status == SG_OK &&
		  resp.payload != NULL &&
		  strstr(resp.payload, "=== IPv4 Routes ===") != NULL) ? 1 : 0,
		 1);
	ipc_resp_free(&resp);
}

/* ── SEC-FW-6: sg_is_cidr and sg_is_ipv4 edge cases ──────────────────── */

static void test_network_validators(void)
{
	printf(C_CYAN "\n  --- SEC-FW-6: CIDR and IPv4 edge cases ---" C_NC "\n");

	/* CIDR accept */
	fw_check("cidr", "accept: '192.168.1.0/24'",
		 sg_is_cidr("192.168.1.0/24"), 1);
	fw_check("cidr", "accept: '10.0.0.1/32' (host route)",
		 sg_is_cidr("10.0.0.1/32"), 1);

	/* CIDR reject */
	fw_check("cidr", "reject: '192.168.1.0' (no prefix)",
		 sg_is_cidr("192.168.1.0"), 0);
	fw_check("cidr", "reject: '192.168.1.0/33' (prefix > 32)",
		 sg_is_cidr("192.168.1.0/33"), 0);
	fw_check("cidr", "reject: '/24' (no IP)",
		 sg_is_cidr("/24"), 0);
	fw_check("cidr", "reject: 'abc/24' (non-IP prefix)",
		 sg_is_cidr("abc/24"), 0);

	/* IPv4 accept */
	fw_check("ipv4", "accept: '192.168.1.1'",
		 sg_is_ipv4("192.168.1.1"), 1);
	fw_check("ipv4", "accept: '0.0.0.0'",
		 sg_is_ipv4("0.0.0.0"), 1);
	fw_check("ipv4", "accept: '255.255.255.255'",
		 sg_is_ipv4("255.255.255.255"), 1);

	/* IPv4 reject */
	fw_check("ipv4", "reject: '' (empty)",
		 sg_is_ipv4(""), 0);
	fw_check("ipv4", "reject: '256.1.1.1' (octet > 255)",
		 sg_is_ipv4("256.1.1.1"), 0);
	fw_check("ipv4", "reject: '1.2.3' (3 octets)",
		 sg_is_ipv4("1.2.3"), 0);
	fw_check("ipv4", "reject: '1.2.3.4.5' (5 octets)",
		 sg_is_ipv4("1.2.3.4.5"), 0);
}

/* ── SEC-FW-7: tftp not an allowaccess service ────────────────────────── */

static void test_tftp_not_allowaccess(void)
{
	printf(C_CYAN "\n  --- SEC-FW-7: tftp not an allowaccess service ---" C_NC "\n");

	fw_check("no-tftp", "reject: 'tftp' (not a management service)",
		 sg_is_access_services("tftp"), 0);
	fw_check("no-tftp", "reject: 'ping ssh tftp' (tftp taints list)",
		 sg_is_access_services("ping ssh tftp"), 0);
	fw_check("no-tftp", "accept: 'ping ssh' (valid without tftp)",
		 sg_is_access_services("ping ssh"), 1);
}

/* ── SEC-FW-8: INPUT chain structure (IPC, mode=1) ───────────────────── */

static void test_input_chain_structure(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- SEC-FW-8: INPUT chain structure ---" C_NC "\n");

	conn = ipc_send_str(SG_CMD_DIAG_FW_POLICY, "", &resp);

	/* ESTABLISHED,RELATED rule must be in INPUT */
	fw_check("input-chain", "ESTABLISHED,RELATED rule present",
		 (conn == 0 && resp.payload &&
		  strstr(resp.payload, "ESTABLISHED")) ? 1 : 0, 1);

	/* Per-interface jump must exist */
	fw_check("input-chain", "per-interface chain jump (SG_IN_) present",
		 (conn == 0 && resp.payload &&
		  strstr(resp.payload, "SG_IN_")) ? 1 : 0, 1);

	/* Policy must be DROP */
	fw_check("input-chain", "policy is DROP",
		 (conn == 0 && resp.payload &&
		  strstr(resp.payload, "policy DROP")) ? 1 : 0, 1);
	ipc_resp_free(&resp);
}

/* ── SEC-FW-9: TFTP CT helper in raw table (IPC, mode=1) ─────────────── */

static void test_ct_helper_tftp(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- SEC-FW-9: TFTP CT helper in raw table ---" C_NC "\n");

	conn = ipc_send_str(SG_CMD_DIAG_FW_IPTABLES, "table=raw\n", &resp);

	/* Raw table must be queryable */
	fw_check("ct-helper", "raw table query → SG_OK",
		 (conn == 0 && resp.status == SG_OK) ? 1 : 0, 1);

	/* CT helper rule must reference tftp */
	fw_check("ct-helper", "CT helper 'tftp' rule present",
		 (conn == 0 && resp.payload &&
		  strstr(resp.payload, "helper") &&
		  strstr(resp.payload, "tftp")) ? 1 : 0, 1);

	/* Rule must target outbound UDP port 69 */
	fw_check("ct-helper", "targets udp dpt:69",
		 (conn == 0 && resp.payload &&
		  strstr(resp.payload, "udp dpt:69")) ? 1 : 0, 1);
	ipc_resp_free(&resp);
}

/* ── Entry point ──────────────────────────────────────────────────────── */

int cli_diagnose_test_firewall(int mode, diag_result_t *out)
{
	fw_pass = fw_fail = fw_total = 0;

	printf("\n  Stargazer Firewall & Network Validator Diagnostics\n");
	printf("  ==================================================\n");

	/* Local-only tests (no IPC needed) */
	test_access_services();
	test_iface_name();
	test_network_validators();
	test_tftp_not_allowaccess();

	/* Full mode: IPC round-trip tests (require mgmtd) */
	if (mode == 1) {
		if (!ipc_available()) {
			printf(C_RED "\n  ERROR" C_NC
			       ": mgmtd socket not found (%s)\n",
			       SG_MGMTD_SOCK);
			printf("  IPC tests skipped."
			       " Start stargazer-mgmtd for full tests.\n");
		} else {
			test_diag_ipc_reachability();
			test_diag_input_validation();
			test_diag_payload_presence();
			test_input_chain_structure();
			test_ct_helper_tftp();
		}
	}

	/* Summary */
	printf("\n  Results: %d/%d passed", fw_pass, fw_total);
	if (fw_fail > 0)
		printf(C_RED ", %d FAILED" C_NC, fw_fail);
	else
		printf(C_GREEN " (all passed)" C_NC);
	printf("\n\n");

	if (out) {
		out->passed = fw_pass;
		out->failed = fw_fail;
		out->total  = fw_total;
	}
	return fw_fail > 0 ? 1 : 0;
}
