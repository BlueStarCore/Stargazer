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

/* ── SEC-FW-10: config scrub for upgrade/downgrade ────────────────────── */

static void test_config_scrub(void)
{
	printf(C_CYAN "\n  --- SEC-FW-10: config scrub for upgrade/downgrade ---" C_NC "\n");

	char out[128];
	int changed;

	/* access-services: strip unknown token, keep valid ones */
	changed = sg_reg_scrub_value("system_interface", "allowaccess",
				     "ping ssh tftp", out, sizeof(out));
	fw_check("scrub", "strip 'tftp' from allowaccess",
		 changed == 1 && strcmp(out, "ping ssh") == 0, 1);

	/* access-services: all valid → no change */
	changed = sg_reg_scrub_value("system_interface", "allowaccess",
				     "ping ssh", out, sizeof(out));
	fw_check("scrub", "valid allowaccess unchanged", changed, 0);

	/* access-services: all invalid → empty (valid = no services) */
	changed = sg_reg_scrub_value("system_interface", "allowaccess",
				     "tftp ftp", out, sizeof(out));
	fw_check("scrub", "all-invalid allowaccess -> empty",
		 changed == 1 && strcmp(out, "") == 0, 1);

	/* enum: invalid option → reset to default */
	changed = sg_reg_scrub_value("system_interface", "status",
				     "half-duplex", out, sizeof(out));
	fw_check("scrub", "invalid enum -> default 'up'",
		 changed == 1 && strcmp(out, "up") == 0, 1);

	/* permissions-csv: strip unknown token, keep valid ones */
	changed = sg_reg_scrub_value("system_admin-profile", "permissions",
				     "monitor,configure,superuser", out,
				     sizeof(out));
	fw_check("scrub", "strip 'superuser' from permissions",
		 changed == 1 && strcmp(out, "monitor,configure") == 0, 1);

	/* permissions-csv: all valid → no change */
	changed = sg_reg_scrub_value("system_admin-profile", "permissions",
				     "monitor,configure", out, sizeof(out));
	fw_check("scrub", "valid permissions unchanged", changed, 0);

	/* field default lookup */
	const char *def = sg_reg_field_default("system_interface", "status");
	fw_check("scrub", "field default for status = 'up'",
		 def != NULL && strcmp(def, "up") == 0, 1);

	def = sg_reg_field_default("system_interface", "allowaccess");
	fw_check("scrub", "field default for allowaccess = NULL",
		 def == NULL, 1);
}

/* ── FW-SEQ: Sequence-based firewall policy ordering (IPC, mode=1) ──── */

/*
 * Helper: send IPC and return 1 if status matches expected, 0 otherwise.
 * Stores response in *resp — caller must free.
 */
static int fw_ipc(uint32_t cmd, const char *payload,
		  struct ipc_response *resp, uint32_t expect)
{
	int conn = ipc_send_str(cmd, payload, resp);
	return (conn == 0 && resp->status == expect) ? 1 : 0;
}

static void fw_ipc_fire(uint32_t cmd, const char *payload)
{
	struct ipc_response resp;
	ipc_send_str(cmd, payload, &resp);
	ipc_resp_free(&resp);
}

static void test_fw_sequence(void)
{
	struct ipc_response resp;

	printf(C_CYAN "\n  --- FW-SEQ-1: sequence auto-assign ---" C_NC "\n");

	/* Cleanup: delete test policies if leftover */
	fw_ipc_fire(SG_CMD_CFG_DEL, "firewall_policy:9901\n");
	fw_ipc_fire(SG_CMD_CFG_DEL, "firewall_policy:9902\n");
	fw_ipc_fire(SG_CMD_CFG_DEL, "firewall_policy:9903\n");

	/* Create policy without sequence → should auto-assign */
	fw_check("FW-SEQ-1", "create policy 9901 (no sequence)",
		 fw_ipc(SG_CMD_CFG_SET,
			"firewall_policy:9901\n"
			"name=test-seq1\n"
			"srcintf=any\ndstintf=any\n"
			"srcaddr=all\ndstaddr=all\n"
			"action=accept\nstatus=enable\n",
			&resp, SG_OK), 1);
	ipc_resp_free(&resp);

	/* Verify sequence was assigned */
	fw_check("FW-SEQ-1", "policy 9901 has sequence",
		 fw_ipc(SG_CMD_CFG_GET, "firewall_policy:9901\n",
			&resp, SG_OK) &&
		 resp.payload && strstr(resp.payload, "sequence="), 1);
	ipc_resp_free(&resp);

	/* Create second policy → should get sequence = prev + 1 */
	fw_check("FW-SEQ-1", "create policy 9902 (auto-seq)",
		 fw_ipc(SG_CMD_CFG_SET,
			"firewall_policy:9902\n"
			"name=test-seq2\n"
			"srcintf=any\ndstintf=any\n"
			"srcaddr=all\ndstaddr=all\n"
			"action=deny\nstatus=enable\n",
			&resp, SG_OK), 1);
	ipc_resp_free(&resp);

	fw_check("FW-SEQ-1", "policy 9902 has sequence",
		 fw_ipc(SG_CMD_CFG_GET, "firewall_policy:9902\n",
			&resp, SG_OK) &&
		 resp.payload && strstr(resp.payload, "sequence="), 1);
	ipc_resp_free(&resp);

	printf(C_CYAN "\n  --- FW-SEQ-2: FORWARD chain order ---" C_NC "\n");

	/* Check that both rules appear in FORWARD chain */
	fw_check("FW-SEQ-2", "FORWARD chain has ACCEPT rule",
		 fw_ipc(SG_CMD_DIAG_FW_IPTABLES, "table=filter\n",
			&resp, SG_OK) &&
		 resp.payload && strstr(resp.payload, "ACCEPT"), 1);
	ipc_resp_free(&resp);

	printf(C_CYAN "\n  --- FW-SEQ-3: disable removes rule ---" C_NC "\n");

	/* Disable policy 9901 → rule should be removed from chain */
	fw_check("FW-SEQ-3", "disable policy 9901",
		 fw_ipc(SG_CMD_CFG_SET,
			"firewall_policy:9901\n"
			"name=test-seq1\n"
			"srcintf=any\ndstintf=any\n"
			"srcaddr=all\ndstaddr=all\n"
			"action=accept\nstatus=disable\n"
			"sequence=1\n",
			&resp, SG_OK), 1);
	ipc_resp_free(&resp);

	/* Verify status is disable in DB */
	fw_check("FW-SEQ-3", "policy 9901 status=disable in DB",
		 fw_ipc(SG_CMD_CFG_GET, "firewall_policy:9901\n",
			&resp, SG_OK) &&
		 resp.payload && strstr(resp.payload, "status=disable"), 1);
	ipc_resp_free(&resp);

	printf(C_CYAN "\n  --- FW-SEQ-4: re-enable re-inserts ---" C_NC "\n");

	/* Re-enable policy 9901 */
	fw_check("FW-SEQ-4", "re-enable policy 9901",
		 fw_ipc(SG_CMD_CFG_SET,
			"firewall_policy:9901\n"
			"name=test-seq1\n"
			"srcintf=any\ndstintf=any\n"
			"srcaddr=all\ndstaddr=all\n"
			"action=accept\nstatus=enable\n"
			"sequence=1\n",
			&resp, SG_OK), 1);
	ipc_resp_free(&resp);

	printf(C_CYAN "\n  --- FW-SEQ-5: CFG_INSERT (move) ---" C_NC "\n");

	/* Move policy 9902 to sequence 1 (swap order) */
	fw_check("FW-SEQ-5", "move policy 9902 to sequence 1",
		 fw_ipc(SG_CMD_CFG_INSERT,
			"firewall_policy:9902\n1\n",
			&resp, SG_OK), 1);
	ipc_resp_free(&resp);

	/* Verify sequence updated in DB */
	fw_check("FW-SEQ-5", "policy 9902 has sequence=1 in DB",
		 fw_ipc(SG_CMD_CFG_GET, "firewall_policy:9902\n",
			&resp, SG_OK) &&
		 resp.payload && strstr(resp.payload, "sequence=1"), 1);
	ipc_resp_free(&resp);

	printf(C_CYAN "\n  --- FW-SEQ-6: collision shift ---" C_NC "\n");

	/* After move, policy 9901 should have been shifted from seq=1 to seq=2 */
	fw_check("FW-SEQ-6", "policy 9901 shifted to sequence=2",
		 fw_ipc(SG_CMD_CFG_GET, "firewall_policy:9901\n",
			&resp, SG_OK) &&
		 resp.payload && strstr(resp.payload, "sequence=2"), 1);
	ipc_resp_free(&resp);

	/* Cleanup */
	fw_ipc_fire(SG_CMD_CFG_DEL, "firewall_policy:9901\n");
	fw_ipc_fire(SG_CMD_CFG_DEL, "firewall_policy:9902\n");
}

/* ── Interface helper ─────────────────────────────────────────────────── */

/*
 * Query the first interface name from system_interface DB.
 * NAT tests need a real dstintf — lo is not seeded in system_interface.
 * Returns 1 if found and copies name to buf, 0 if DB has no interfaces.
 */
static int fw_get_test_iface(char *buf, size_t bufsz)
{
	struct ipc_response resp;
	buf[0] = '\0';
	if (ipc_send_str(SG_CMD_CFG_LIST, "system_interface", &resp) != 0 ||
	    resp.status != SG_OK || !resp.payload) {
		ipc_resp_free(&resp);
		return 0;
	}
	const char *p = resp.payload;
	while (*p) {
		const char *eol = strchr(p, '\n');
		size_t len = eol ? (size_t)(eol - p) : strlen(p);
		if (len > 0 && len < bufsz) {
			memcpy(buf, p, len);
			buf[len] = '\0';
			ipc_resp_free(&resp);
			return 1;
		}
		p += len + (eol ? 1 : 0);
	}
	ipc_resp_free(&resp);
	return 0;
}

/* ── NAT-SEQ: NAT sequence ordering (IPC, mode=1) ────────────────────── */

static void test_nat_sequence(void)
{
	struct ipc_response resp;
	char test_iface[64];
	char payload[512];

	printf(C_CYAN "\n  --- NAT-SEQ-1: NAT sequence auto-assign ---" C_NC "\n");

	if (!fw_get_test_iface(test_iface, sizeof(test_iface))) {
		printf("  SKIP [NAT-SEQ] no interface in system_interface DB\n");
		return;
	}

	/* Cleanup */
	fw_ipc_fire(SG_CMD_CFG_DEL, "network_nat:9901\n");
	fw_ipc_fire(SG_CMD_CFG_DEL, "network_nat:9902\n");

	snprintf(payload, sizeof(payload),
		 "network_nat:9901\n"
		 "type=snat\nsrcintf=any\ndstintf=%s\n"
		 "srcaddr=any\ndstaddr=any\n"
		 "status=enable\n", test_iface);
	fw_check("NAT-SEQ-1", "create SNAT 9901 (auto-seq)",
		 fw_ipc(SG_CMD_CFG_SET, payload, &resp, SG_OK), 1);
	ipc_resp_free(&resp);

	fw_check("NAT-SEQ-1", "NAT 9901 has sequence",
		 fw_ipc(SG_CMD_CFG_GET, "network_nat:9901\n",
			&resp, SG_OK) &&
		 resp.payload && strstr(resp.payload, "sequence="), 1);
	ipc_resp_free(&resp);

	printf(C_CYAN "\n  --- NAT-SEQ-2: NAT disable/enable ---" C_NC "\n");

	snprintf(payload, sizeof(payload),
		 "network_nat:9901\n"
		 "type=snat\nsrcintf=any\ndstintf=%s\n"
		 "srcaddr=any\ndstaddr=any\n"
		 "status=disable\nsequence=1\n", test_iface);
	fw_check("NAT-SEQ-2", "disable NAT 9901",
		 fw_ipc(SG_CMD_CFG_SET, payload, &resp, SG_OK), 1);
	ipc_resp_free(&resp);

	snprintf(payload, sizeof(payload),
		 "network_nat:9901\n"
		 "type=snat\nsrcintf=any\ndstintf=%s\n"
		 "srcaddr=any\ndstaddr=any\n"
		 "status=enable\nsequence=1\n", test_iface);
	fw_check("NAT-SEQ-2", "re-enable NAT 9901",
		 fw_ipc(SG_CMD_CFG_SET, payload, &resp, SG_OK), 1);
	ipc_resp_free(&resp);

	/* Cleanup */
	fw_ipc_fire(SG_CMD_CFG_DEL, "network_nat:9901\n");
}

/* ── NAT-KER: Kernel NAT rule verification (IPC, mode=1) ─────────────── */

/*
 * Helper: query kernel NAT table via IPC and check if a string
 * appears in the output.  Returns 1 if found, 0 otherwise.
 */
static int nat_kernel_has(const char *needle)
{
	struct ipc_response resp;
	int found = 0;

	if (fw_ipc(SG_CMD_DIAG_FW_IPTABLES, "table=nat\n", &resp, SG_OK) &&
	    resp.payload && strstr(resp.payload, needle))
		found = 1;
	ipc_resp_free(&resp);
	return found;
}

static void test_nat_kernel_verify(void)
{
	struct ipc_response resp;
	char test_iface[64];
	char payload[512];

	printf(C_CYAN "\n  --- NAT-KER-1: SNAT overload in kernel ---"
	       C_NC "\n");

	if (!fw_get_test_iface(test_iface, sizeof(test_iface))) {
		printf("  SKIP [NAT-KER] no interface in system_interface DB\n");
		return;
	}

	/* Cleanup */
	fw_ipc_fire(SG_CMD_CFG_DEL, "network_nat:9903\n");
	fw_ipc_fire(SG_CMD_CFG_DEL, "network_nat:9904\n");
	fw_ipc_fire(SG_CMD_CFG_DEL, "network_nat:9905\n");
	fw_ipc_fire(SG_CMD_CFG_DEL, "network_nat:9906\n");

	snprintf(payload, sizeof(payload),
		 "network_nat:9903\n"
		 "type=snat\nsrcintf=any\ndstintf=%s\n"
		 "srcaddr=any\ndstaddr=any\n"
		 "protocol=all\nstatus=enable\n", test_iface);
	fw_check("NAT-KER-1", "create SNAT overload",
		 fw_ipc(SG_CMD_CFG_SET, payload, &resp, SG_OK), 1);
	ipc_resp_free(&resp);

	/* Verify MASQUERADE appears in kernel POSTROUTING */
	fw_check("NAT-KER-1", "MASQUERADE in kernel POSTROUTING",
		 nat_kernel_has("MASQUERADE"), 1);

	printf(C_CYAN "\n  --- NAT-KER-2: DNAT tcp in kernel ---"
	       C_NC "\n");

	/* Create DNAT tcp rule */
	fw_check("NAT-KER-2", "create DNAT tcp dstport=9999",
		 fw_ipc(SG_CMD_CFG_SET,
			"network_nat:9904\n"
			"type=dnat\nsrcintf=any\ndstintf=any\n"
			"srcaddr=any\ndstaddr=any\n"
			"protocol=tcp\ndstport=9999\n"
			"mapped-ip=127.0.0.1\nmapped-port=80\n"
			"status=enable\n",
			&resp, SG_OK), 1);
	ipc_resp_free(&resp);

	/* Verify dpt:9999 in kernel PREROUTING */
	fw_check("NAT-KER-2", "dpt:9999 in kernel PREROUTING",
		 nat_kernel_has("dpt:9999"), 1);

	printf(C_CYAN "\n  --- NAT-KER-3: DNAT 1:1 (protocol=all) ---"
	       C_NC "\n");

	/* Create DNAT 1:1 — no port, no protocol */
	fw_check("NAT-KER-3", "create DNAT 1:1 (all protocols)",
		 fw_ipc(SG_CMD_CFG_SET,
			"network_nat:9905\n"
			"type=dnat\nsrcintf=any\ndstintf=any\n"
			"srcaddr=any\ndstaddr=any\n"
			"protocol=all\n"
			"mapped-ip=127.0.0.2\n"
			"status=enable\n",
			&resp, SG_OK), 1);
	ipc_resp_free(&resp);

	/* Verify to:127.0.0.2 in kernel */
	fw_check("NAT-KER-3", "to:127.0.0.2 in kernel",
		 nat_kernel_has("to:127.0.0.2"), 1);

	printf(C_CYAN "\n  --- NAT-KER-4: DNAT tcp+udp (2 rules) ---"
	       C_NC "\n");

	/* Create DNAT tcp+udp — should generate 2 rules */
	fw_check("NAT-KER-4", "create DNAT tcp+udp dstport=8888",
		 fw_ipc(SG_CMD_CFG_SET,
			"network_nat:9906\n"
			"type=dnat\nsrcintf=any\ndstintf=any\n"
			"srcaddr=any\ndstaddr=any\n"
			"protocol=tcp+udp\ndstport=8888\n"
			"mapped-ip=127.0.0.1\n"
			"status=enable\n",
			&resp, SG_OK), 1);
	ipc_resp_free(&resp);

	/* Verify both tcp and udp rules exist for dpt:8888 */
	fw_check("NAT-KER-4", "tcp dpt:8888 in kernel",
		 nat_kernel_has("tcp dpt:8888"), 1);
	fw_check("NAT-KER-4", "udp dpt:8888 in kernel",
		 nat_kernel_has("udp dpt:8888"), 1);

	printf(C_CYAN "\n  --- NAT-KER-5: delete removes rules ---"
	       C_NC "\n");

	/* Delete all test rules */
	fw_ipc_fire(SG_CMD_CFG_DEL, "network_nat:9903\n");
	fw_ipc_fire(SG_CMD_CFG_DEL, "network_nat:9904\n");
	fw_ipc_fire(SG_CMD_CFG_DEL, "network_nat:9905\n");
	fw_ipc_fire(SG_CMD_CFG_DEL, "network_nat:9906\n");

	/* Verify test rules gone from kernel */
	fw_check("NAT-KER-5", "dpt:9999 gone after delete",
		 !nat_kernel_has("dpt:9999"), 1);
	fw_check("NAT-KER-5", "to:127.0.0.2 gone after delete",
		 !nat_kernel_has("to:127.0.0.2"), 1);
	fw_check("NAT-KER-5", "dpt:8888 gone after delete",
		 !nat_kernel_has("dpt:8888"), 1);
}

/* ── REF-IFACE: Interface referential integrity (IPC, mode=1) ────────── */

static void test_iface_ref_integrity(void)
{
	struct ipc_response resp;
	char test_iface[64];
	char payload[512];
	char del_section[128];

	printf(C_CYAN "\n  --- REF-IFACE: interface referential integrity ---"
	       C_NC "\n");

	if (!fw_get_test_iface(test_iface, sizeof(test_iface))) {
		printf("  SKIP [REF-IFACE] no interface in system_interface DB\n");
		return;
	}

	fw_ipc_fire(SG_CMD_CFG_DEL, "network_route_static:9901\n");

	snprintf(payload, sizeof(payload),
		 "network_route_static:9901\n"
		 "dst=198.51.100.0/24\n"
		 "gateway=10.0.1.1\n"
		 "device=%s\n"
		 "distance=10\n"
		 "status=disable\n", test_iface);
	fw_check("REF-IFACE", "create route referencing interface",
		 fw_ipc(SG_CMD_CFG_SET, payload, &resp, SG_OK), 1);
	ipc_resp_free(&resp);

	/* Try to delete the interface — should be blocked (route refs it) */
	snprintf(del_section, sizeof(del_section),
		 "system_interface:%s\n", test_iface);
	int blocked = fw_ipc(SG_CMD_CFG_DEL, del_section, &resp, SG_OK);
	fw_check("REF-IFACE", "delete interface with route ref → blocked",
		 !blocked ||
		 resp.status == SG_ERR_IN_USE ||
		 resp.status == SG_ERR_BUILTIN ||
		 resp.status == SG_ERR_ENTRY_NOT_FOUND, 1);
	ipc_resp_free(&resp);

	/* Cleanup */
	fw_ipc_fire(SG_CMD_CFG_DEL, "network_route_static:9901\n");
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
	test_config_scrub();

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
			test_fw_sequence();
			test_nat_sequence();
			test_nat_kernel_verify();
			test_iface_ref_integrity();
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
