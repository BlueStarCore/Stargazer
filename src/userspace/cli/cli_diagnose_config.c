/* SPDX-License-Identifier: MIT */
/*
 * cli_diagnose_config.c — Configuration validation diagnostics for Stargazer CLI
 *
 * Implements "execute diagnose test-configure [full]":
 *   - Basic: exercises all sg_validate validators and registry lookups
 *   - Full:  round-trip IPC tests (create/validate/delete config entries)
 *
 * Uses the same PASS/FAIL pattern as cli_diagnose.c (test-permissions).
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_diagnose.h"
#include "cli_cmd_table.h"
#include "cli_readline.h"
#include "cli_ipc.h"
#include "sg_validate.h"

#include <stdio.h>
#include <string.h>

/* ── Test counters ────────────────────────────────────────────────────── */

static int tc_pass;
static int tc_fail;
static int tc_total;

/* ── Generic assertion helper ─────────────────────────────────────────── */

static void tc_check(const char *section, const char *desc,
		     int result, int expected)
{
	tc_total++;
	if (result == expected) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC " [%s] %s\n", section, desc);
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC " [%s] %s (got %d, expected %d)\n",
		       section, desc, result, expected);
	}
}

/* ── Section 1: sg_is_safe_id ─────────────────────────────────────────── */

static void test_safe_id(void)
{
	printf(C_CYAN "\n  --- safe-id validator ---" C_NC "\n");

	/* Accept */
	tc_check("safe-id", "accept: alphanumeric 'hello123'",
		 sg_is_safe_id("hello123"), 1);
	tc_check("safe-id", "accept: with dash 'my-rule'",
		 sg_is_safe_id("my-rule"), 1);
	tc_check("safe-id", "accept: with underscore 'my_rule'",
		 sg_is_safe_id("my_rule"), 1);
	tc_check("safe-id", "accept: with dot 'v2.1'",
		 sg_is_safe_id("v2.1"), 1);
	tc_check("safe-id", "accept: single char 'a'",
		 sg_is_safe_id("a"), 1);
	tc_check("safe-id", "accept: digits only '999'",
		 sg_is_safe_id("999"), 1);

	/* Reject */
	tc_check("safe-id", "reject: NULL",
		 sg_is_safe_id(NULL), 0);
	tc_check("safe-id", "reject: empty ''",
		 sg_is_safe_id(""), 0);
	tc_check("safe-id", "reject: space 'my rule'",
		 sg_is_safe_id("my rule"), 0);
	tc_check("safe-id", "reject: colon 'a:b'",
		 sg_is_safe_id("a:b"), 0);
	tc_check("safe-id", "reject: slash '../etc'",
		 sg_is_safe_id("../etc"), 0);
	tc_check("safe-id", "reject: semicolon 'a;b'",
		 sg_is_safe_id("a;b"), 0);
	tc_check("safe-id", "reject: dollar 'a$b'",
		 sg_is_safe_id("a$b"), 0);
	tc_check("safe-id", "reject: backtick 'a`b'",
		 sg_is_safe_id("a`b"), 0);
	tc_check("safe-id", "reject: newline 'a\\nb'",
		 sg_is_safe_id("a\nb"), 0);
	tc_check("safe-id", "reject: at-sign 'user@host'",
		 sg_is_safe_id("user@host"), 0);
	tc_check("safe-id", "reject: single-quote \"it's\"",
		 sg_is_safe_id("it's"), 0);
	tc_check("safe-id", "reject: equals 'a=b'",
		 sg_is_safe_id("a=b"), 0);
	tc_check("safe-id", "reject: pipe 'a|b'",
		 sg_is_safe_id("a|b"), 0);
}

/* ── Section 2: sg_is_ipv4 ────────────────────────────────────────────── */

static void test_ipv4(void)
{
	printf(C_CYAN "\n  --- IPv4 validator ---" C_NC "\n");

	/* Accept */
	tc_check("ipv4", "accept: 10.0.0.1",
		 sg_is_ipv4("10.0.0.1"), 1);
	tc_check("ipv4", "accept: 0.0.0.0",
		 sg_is_ipv4("0.0.0.0"), 1);
	tc_check("ipv4", "accept: 255.255.255.255",
		 sg_is_ipv4("255.255.255.255"), 1);
	tc_check("ipv4", "accept: 192.168.1.100",
		 sg_is_ipv4("192.168.1.100"), 1);
	tc_check("ipv4", "accept: 1.2.3.4",
		 sg_is_ipv4("1.2.3.4"), 1);

	/* Reject */
	tc_check("ipv4", "reject: NULL",
		 sg_is_ipv4(NULL), 0);
	tc_check("ipv4", "reject: empty",
		 sg_is_ipv4(""), 0);
	tc_check("ipv4", "reject: 256.1.1.1 (octet > 255)",
		 sg_is_ipv4("256.1.1.1"), 0);
	tc_check("ipv4", "reject: 10.0.0 (3 octets)",
		 sg_is_ipv4("10.0.0"), 0);
	tc_check("ipv4", "reject: 10.0.0.0.1 (5 octets)",
		 sg_is_ipv4("10.0.0.0.1"), 0);
	tc_check("ipv4", "reject: abc.def.ghi.jkl (alpha)",
		 sg_is_ipv4("abc.def.ghi.jkl"), 0);
	tc_check("ipv4", "reject: 10.0.0.1/24 (has CIDR suffix)",
		 sg_is_ipv4("10.0.0.1/24"), 0);
	tc_check("ipv4", "reject: 1000.1.1.1 (4-digit octet)",
		 sg_is_ipv4("1000.1.1.1"), 0);
	tc_check("ipv4", "reject: .1.2.3 (leading dot)",
		 sg_is_ipv4(".1.2.3"), 0);
	tc_check("ipv4", "reject: 1.2.3. (trailing dot)",
		 sg_is_ipv4("1.2.3."), 0);
	tc_check("ipv4", "reject: just dots '...'",
		 sg_is_ipv4("..."), 0);
	tc_check("ipv4", "reject: 10.0.0.-1 (negative octet)",
		 sg_is_ipv4("10.0.0.-1"), 0);
}

/* ── Section 3: sg_is_cidr ────────────────────────────────────────────── */

static void test_cidr(void)
{
	printf(C_CYAN "\n  --- CIDR validator ---" C_NC "\n");

	/* Accept */
	tc_check("cidr", "accept: 192.168.1.0/24",
		 sg_is_cidr("192.168.1.0/24"), 1);
	tc_check("cidr", "accept: 10.0.0.0/8",
		 sg_is_cidr("10.0.0.0/8"), 1);
	tc_check("cidr", "accept: 172.16.0.1/32",
		 sg_is_cidr("172.16.0.1/32"), 1);
	tc_check("cidr", "accept: 0.0.0.0/0",
		 sg_is_cidr("0.0.0.0/0"), 1);

	/* Reject */
	tc_check("cidr", "reject: NULL",
		 sg_is_cidr(NULL), 0);
	tc_check("cidr", "reject: empty",
		 sg_is_cidr(""), 0);
	tc_check("cidr", "reject: 192.168.1.0/33 (prefix > 32)",
		 sg_is_cidr("192.168.1.0/33"), 0);
	tc_check("cidr", "reject: 192.168.1.0 (no prefix)",
		 sg_is_cidr("192.168.1.0"), 0);
	tc_check("cidr", "reject: 192.168.1.0/abc (non-numeric prefix)",
		 sg_is_cidr("192.168.1.0/abc"), 0);
	tc_check("cidr", "reject: 999.168.1.0/24 (bad IP)",
		 sg_is_cidr("999.168.1.0/24"), 0);
	tc_check("cidr", "reject: /24 (no IP address)",
		 sg_is_cidr("/24"), 0);
	tc_check("cidr", "reject: 10.0.0.1/ (empty prefix)",
		 sg_is_cidr("10.0.0.1/"), 0);
	tc_check("cidr", "reject: 10.0.0.1/-1 (negative prefix)",
		 sg_is_cidr("10.0.0.1/-1"), 0);
}

/* ── Section 4: sg_is_iface_name ──────────────────────────────────────── */

static void test_iface(void)
{
	printf(C_CYAN "\n  --- iface-name validator ---" C_NC "\n");

	/* Accept */
	tc_check("iface", "accept: eth0",
		 sg_is_iface_name("eth0"), 1);
	tc_check("iface", "accept: wan.1",
		 sg_is_iface_name("wan.1"), 1);
	tc_check("iface", "accept: br-lan",
		 sg_is_iface_name("br-lan"), 1);
	tc_check("iface", "accept: eth0:1 (alias)",
		 sg_is_iface_name("eth0:1"), 1);
	tc_check("iface", "accept: wlan_ap0",
		 sg_is_iface_name("wlan_ap0"), 1);

	/* Reject */
	tc_check("iface", "reject: NULL",
		 sg_is_iface_name(NULL), 0);
	tc_check("iface", "reject: empty",
		 sg_is_iface_name(""), 0);
	tc_check("iface", "reject: space 'eth 0'",
		 sg_is_iface_name("eth 0"), 0);
	tc_check("iface", "reject: semicolon 'eth;0'",
		 sg_is_iface_name("eth;0"), 0);
	tc_check("iface", "reject: dollar 'eth$0'",
		 sg_is_iface_name("eth$0"), 0);
	tc_check("iface", "reject: slash 'eth/0'",
		 sg_is_iface_name("eth/0"), 0);
	tc_check("iface", "reject: backtick 'eth`0`'",
		 sg_is_iface_name("eth`0`"), 0);
}

/* ── Section 5: sg_is_uint_range ──────────────────────────────────────── */

static void test_uint_range(void)
{
	printf(C_CYAN "\n  --- uint-range validator ---" C_NC "\n");

	/* Range 1-255 */
	tc_check("uint", "accept: 1 in [1,255]",
		 sg_is_uint_range("1", 1, 255), 1);
	tc_check("uint", "accept: 255 in [1,255]",
		 sg_is_uint_range("255", 1, 255), 1);
	tc_check("uint", "accept: 128 in [1,255]",
		 sg_is_uint_range("128", 1, 255), 1);
	tc_check("uint", "reject: 0 in [1,255] (below min)",
		 sg_is_uint_range("0", 1, 255), 0);
	tc_check("uint", "reject: 256 in [1,255] (above max)",
		 sg_is_uint_range("256", 1, 255), 0);

	/* Range 576-9200 (MTU) */
	tc_check("uint", "accept: 576 in [576,9200]",
		 sg_is_uint_range("576", 576, 9200), 1);
	tc_check("uint", "accept: 9200 in [576,9200]",
		 sg_is_uint_range("9200", 576, 9200), 1);
	tc_check("uint", "accept: 1500 in [576,9200]",
		 sg_is_uint_range("1500", 576, 9200), 1);
	tc_check("uint", "reject: 575 in [576,9200]",
		 sg_is_uint_range("575", 576, 9200), 0);
	tc_check("uint", "reject: 9201 in [576,9200]",
		 sg_is_uint_range("9201", 576, 9200), 0);

	/* Range 0-128 (password policy) */
	tc_check("uint", "accept: 0 in [0,128]",
		 sg_is_uint_range("0", 0, 128), 1);
	tc_check("uint", "accept: 128 in [0,128]",
		 sg_is_uint_range("128", 0, 128), 1);
	tc_check("uint", "reject: 129 in [0,128]",
		 sg_is_uint_range("129", 0, 128), 0);

	/* Invalid input */
	tc_check("uint", "reject: NULL",
		 sg_is_uint_range(NULL, 0, 100), 0);
	tc_check("uint", "reject: empty",
		 sg_is_uint_range("", 0, 100), 0);
	tc_check("uint", "reject: negative '-1'",
		 sg_is_uint_range("-1", 0, 100), 0);
	tc_check("uint", "reject: alpha 'abc'",
		 sg_is_uint_range("abc", 0, 100), 0);
	tc_check("uint", "reject: mixed '10abc'",
		 sg_is_uint_range("10abc", 0, 100), 0);
	tc_check("uint", "reject: float '1.5'",
		 sg_is_uint_range("1.5", 0, 100), 0);
	tc_check("uint", "reject: hex '0x10'",
		 sg_is_uint_range("0x10", 0, 100), 0);
}

/* ── Section 6: sg_is_tz_token ────────────────────────────────────────── */

static void test_tz_token(void)
{
	printf(C_CYAN "\n  --- tz-token validator ---" C_NC "\n");

	/* Accept */
	tc_check("tz", "accept: UTC",
		 sg_is_tz_token("UTC"), 1);
	tc_check("tz", "accept: Asia/Ho_Chi_Minh",
		 sg_is_tz_token("Asia/Ho_Chi_Minh"), 1);
	tc_check("tz", "accept: US/Eastern",
		 sg_is_tz_token("US/Eastern"), 1);
	tc_check("tz", "accept: Etc/GMT+5",
		 sg_is_tz_token("Etc/GMT+5"), 1);
	tc_check("tz", "accept: Etc/GMT-12",
		 sg_is_tz_token("Etc/GMT-12"), 1);

	/* Reject */
	tc_check("tz", "reject: NULL",
		 sg_is_tz_token(NULL), 0);
	tc_check("tz", "reject: empty",
		 sg_is_tz_token(""), 0);
	tc_check("tz", "reject: space 'US Eastern'",
		 sg_is_tz_token("US Eastern"), 0);
	tc_check("tz", "reject: semicolon 'UTC;date'",
		 sg_is_tz_token("UTC;date"), 0);
	tc_check("tz", "reject: shell injection '$(date)'",
		 sg_is_tz_token("$(date)"), 0);
}

/* ── Section 7: sg_is_permissions_csv ─────────────────────────────────── */

static void test_permissions_csv(void)
{
	printf(C_CYAN "\n  --- permissions-csv validator ---" C_NC "\n");

	/* Accept */
	tc_check("perms", "accept: 'monitor'",
		 sg_is_permissions_csv("monitor"), 1);
	tc_check("perms", "accept: 'configure'",
		 sg_is_permissions_csv("configure"), 1);
	tc_check("perms", "accept: 'admin'",
		 sg_is_permissions_csv("admin"), 1);
	tc_check("perms", "accept: 'monitor,configure'",
		 sg_is_permissions_csv("monitor,configure"), 1);
	tc_check("perms", "accept: 'monitor,configure,admin'",
		 sg_is_permissions_csv("monitor,configure,admin"), 1);

	/* Reject */
	tc_check("perms", "reject: NULL",
		 sg_is_permissions_csv(NULL), 0);
	tc_check("perms", "reject: empty",
		 sg_is_permissions_csv(""), 0);
	tc_check("perms", "reject: 'root' (unknown permission)",
		 sg_is_permissions_csv("root"), 0);
	tc_check("perms", "reject: 'monitor,root'",
		 sg_is_permissions_csv("monitor,root"), 0);
	tc_check("perms", "reject: 'superadmin'",
		 sg_is_permissions_csv("superadmin"), 0);
	tc_check("perms", "reject: 'Monitor' (case sensitive)",
		 sg_is_permissions_csv("Monitor"), 0);
	tc_check("perms", "reject: 'monitor,' (trailing comma)",
		 sg_is_permissions_csv("monitor,"), 0);
	tc_check("perms", "reject: ',monitor' (leading comma)",
		 sg_is_permissions_csv(",monitor"), 0);
}

/* ── Section 8: sg_is_port_or_range ───────────────────────────────────── */

static void test_port_or_range(void)
{
	printf(C_CYAN "\n  --- port-or-range validator ---" C_NC "\n");

	/* Accept */
	tc_check("port", "accept: 80",
		 sg_is_port_or_range("80"), 1);
	tc_check("port", "accept: 1",
		 sg_is_port_or_range("1"), 1);
	tc_check("port", "accept: 65535",
		 sg_is_port_or_range("65535"), 1);
	tc_check("port", "accept: 443",
		 sg_is_port_or_range("443"), 1);
	tc_check("port", "accept: 1024-65535 (range)",
		 sg_is_port_or_range("1024-65535"), 1);
	tc_check("port", "accept: 80-80 (single port range)",
		 sg_is_port_or_range("80-80"), 1);
	tc_check("port", "accept: 8080-8090",
		 sg_is_port_or_range("8080-8090"), 1);

	/* Reject */
	tc_check("port", "reject: 0 (below min)",
		 sg_is_port_or_range("0"), 0);
	tc_check("port", "reject: 65536 (above max)",
		 sg_is_port_or_range("65536"), 0);
	tc_check("port", "reject: 80-22 (start > end)",
		 sg_is_port_or_range("80-22"), 0);
	tc_check("port", "reject: abc (non-numeric)",
		 sg_is_port_or_range("abc"), 0);
	tc_check("port", "reject: 80- (incomplete range)",
		 sg_is_port_or_range("80-"), 0);
	tc_check("port", "reject: -80 (no start)",
		 sg_is_port_or_range("-80"), 0);
	tc_check("port", "reject: 80-90-100 (double dash)",
		 sg_is_port_or_range("80-90-100"), 0);
	tc_check("port", "reject: NULL",
		 sg_is_port_or_range(NULL), 0);
	tc_check("port", "reject: empty",
		 sg_is_port_or_range(""), 0);
}

/* ── Section 9: sg_match_csv_option ───────────────────────────────────── */

static void test_csv_option(void)
{
	printf(C_CYAN "\n  --- csv-option matcher ---" C_NC "\n");

	tc_check("csv", "accept: 'enable' in 'enable,disable'",
		 sg_match_csv_option("enable,disable", "enable"), 1);
	tc_check("csv", "accept: 'disable' in 'enable,disable'",
		 sg_match_csv_option("enable,disable", "disable"), 1);
	tc_check("csv", "accept: 'accept' in 'accept,deny,drop'",
		 sg_match_csv_option("accept,deny,drop", "accept"), 1);
	tc_check("csv", "accept: 'drop' in 'accept,deny,drop'",
		 sg_match_csv_option("accept,deny,drop", "drop"), 1);
	tc_check("csv", "accept: 'all' in 'all,any'",
		 sg_match_csv_option("all,any", "all"), 1);

	tc_check("csv", "reject: 'maybe' in 'enable,disable'",
		 sg_match_csv_option("enable,disable", "maybe"), 0);
	tc_check("csv", "reject: 'en' in 'enable,disable' (prefix match)",
		 sg_match_csv_option("enable,disable", "en"), 0);
	tc_check("csv", "reject: 'enabled' in 'enable,disable' (suffix)",
		 sg_match_csv_option("enable,disable", "enabled"), 0);
	tc_check("csv", "reject: NULL value",
		 sg_match_csv_option("enable,disable", NULL), 0);
	tc_check("csv", "reject: NULL opts",
		 sg_match_csv_option(NULL, "enable"), 0);
}

/* ── Section 10: entry ID validation ──────────────────────────────────── */

static void test_entry_id(void)
{
	printf(C_CYAN "\n  --- entry-id validation ---" C_NC "\n");

	/* firewall_policy: uint IDs */
	tc_check("entry-id", "firewall_policy: accept '1'",
		 sg_reg_validate_entry_id("firewall_policy", "1"), 1);
	tc_check("entry-id", "firewall_policy: accept '100'",
		 sg_reg_validate_entry_id("firewall_policy", "100"), 1);
	tc_check("entry-id", "firewall_policy: accept '99999'",
		 sg_reg_validate_entry_id("firewall_policy", "99999"), 1);
	tc_check("entry-id", "firewall_policy: reject 'abc'",
		 sg_reg_validate_entry_id("firewall_policy", "abc"), 0);
	tc_check("entry-id", "firewall_policy: reject '1.5'",
		 sg_reg_validate_entry_id("firewall_policy", "1.5"), 0);
	tc_check("entry-id", "firewall_policy: reject '-1'",
		 sg_reg_validate_entry_id("firewall_policy", "-1"), 0);
	tc_check("entry-id", "firewall_policy: reject '0x10'",
		 sg_reg_validate_entry_id("firewall_policy", "0x10"), 0);
	tc_check("entry-id", "firewall_policy: reject empty",
		 sg_reg_validate_entry_id("firewall_policy", ""), 0);

	/* firewall_address: safe-id IDs */
	tc_check("entry-id", "firewall_address: accept 'my-addr'",
		 sg_reg_validate_entry_id("firewall_address", "my-addr"), 1);
	tc_check("entry-id", "firewall_address: accept 'addr_1'",
		 sg_reg_validate_entry_id("firewall_address", "addr_1"), 1);
	tc_check("entry-id", "firewall_address: accept 'v2.0'",
		 sg_reg_validate_entry_id("firewall_address", "v2.0"), 1);
	tc_check("entry-id", "firewall_address: reject 'my addr' (space)",
		 sg_reg_validate_entry_id("firewall_address", "my addr"), 0);
	tc_check("entry-id", "firewall_address: reject 'a:b' (colon)",
		 sg_reg_validate_entry_id("firewall_address", "a:b"), 0);
	tc_check("entry-id", "firewall_address: reject '../etc'",
		 sg_reg_validate_entry_id("firewall_address", "../etc"), 0);
	tc_check("entry-id", "firewall_address: reject '$var'",
		 sg_reg_validate_entry_id("firewall_address", "$var"), 0);
	tc_check("entry-id", "firewall_address: reject empty",
		 sg_reg_validate_entry_id("firewall_address", ""), 0);
}

/* ── Section 11: registry lookups ─────────────────────────────────────── */

static void test_registry(void)
{
	printf(C_CYAN "\n  --- registry lookups ---" C_NC "\n");

	/* Type mode */
	tc_check("registry", "firewall_policy is TABLE",
		 sg_reg_type_mode("firewall_policy"), CFG_TABLE);
	tc_check("registry", "system_settings is SINGLE",
		 sg_reg_type_mode("system_settings"), CFG_SINGLE);
	tc_check("registry", "network_nat is TABLE",
		 sg_reg_type_mode("network_nat"), CFG_TABLE);
	tc_check("registry", "system_password-policy is SINGLE",
		 sg_reg_type_mode("system_password-policy"), CFG_SINGLE);
	tc_check("registry", "unknown type returns -1",
		 sg_reg_type_mode("nonexistent_type"), -1);
	tc_check("registry", "NULL type returns -1",
		 sg_reg_type_mode(NULL), -1);

	/* Valid keys */
	tc_check("registry", "'name' valid for firewall_policy",
		 sg_reg_is_valid_key("firewall_policy", "name"), 1);
	tc_check("registry", "'action' valid for firewall_policy",
		 sg_reg_is_valid_key("firewall_policy", "action"), 1);
	tc_check("registry", "'mtu' valid for system_interface",
		 sg_reg_is_valid_key("system_interface", "mtu"), 1);
	tc_check("registry", "'foobar' invalid for firewall_policy",
		 sg_reg_is_valid_key("firewall_policy", "foobar"), 0);
	tc_check("registry", "'password' valid for system_admin",
		 sg_reg_is_valid_key("system_admin", "password"), 1);
	tc_check("registry", "'builtin' NOT a valid key for system_admin",
		 sg_reg_is_valid_key("system_admin", "builtin"), 0);
	tc_check("registry", "key valid for unknown type returns 0",
		 sg_reg_is_valid_key("nonexistent", "name"), 0);

	/* Entry ID kind */
	tc_check("registry", "firewall_policy ID kind is 'uint'",
		 strcmp(sg_reg_entry_id_kind("firewall_policy"), "uint") == 0, 1);
	tc_check("registry", "firewall_address ID kind is 'safe-id'",
		 strcmp(sg_reg_entry_id_kind("firewall_address"), "safe-id") == 0, 1);
	tc_check("registry", "system_admin ID kind is 'safe-id'",
		 strcmp(sg_reg_entry_id_kind("system_admin"), "safe-id") == 0, 1);
}

/* ── Section 12: value validation via registry ────────────────────────── */

static void test_value_validation(void)
{
	printf(C_CYAN "\n  --- value validation (via registry) ---" C_NC "\n");

	/* enum values */
	tc_check("val", "firewall_policy.action = 'accept'",
		 sg_reg_validate_value("firewall_policy", "action", "accept"), 1);
	tc_check("val", "firewall_policy.action = 'deny'",
		 sg_reg_validate_value("firewall_policy", "action", "deny"), 1);
	tc_check("val", "firewall_policy.action = 'drop'",
		 sg_reg_validate_value("firewall_policy", "action", "drop"), 1);
	tc_check("val", "firewall_policy.action = 'ACCEPT' (case)",
		 sg_reg_validate_value("firewall_policy", "action", "ACCEPT"), 0);
	tc_check("val", "firewall_policy.action = 'maybe' (invalid)",
		 sg_reg_validate_value("firewall_policy", "action", "maybe"), 0);
	tc_check("val", "firewall_policy.action = 'accept,deny' (multi)",
		 sg_reg_validate_value("firewall_policy", "action", "accept,deny"), 0);
	tc_check("val", "firewall_policy.action = 'enabled' (close)",
		 sg_reg_validate_value("firewall_policy", "status", "enabled"), 0);

	tc_check("val", "system_interface.status = 'up'",
		 sg_reg_validate_value("system_interface", "status", "up"), 1);
	tc_check("val", "system_interface.status = 'down'",
		 sg_reg_validate_value("system_interface", "status", "down"), 1);
	tc_check("val", "system_interface.status = 'enable' (wrong enum)",
		 sg_reg_validate_value("system_interface", "status", "enable"), 0);

	tc_check("val", "firewall_address.type = 'ipmask'",
		 sg_reg_validate_value("firewall_address", "type", "ipmask"), 1);
	tc_check("val", "firewall_address.type = 'iprange'",
		 sg_reg_validate_value("firewall_address", "type", "iprange"), 1);
	tc_check("val", "firewall_address.type = 'fqdn'",
		 sg_reg_validate_value("firewall_address", "type", "fqdn"), 1);
	tc_check("val", "firewall_address.type = 'wildcard' (invalid)",
		 sg_reg_validate_value("firewall_address", "type", "wildcard"), 0);

	tc_check("val", "network_nat.type = 'snat'",
		 sg_reg_validate_value("network_nat", "type", "snat"), 1);
	tc_check("val", "network_nat.type = 'dnat'",
		 sg_reg_validate_value("network_nat", "type", "dnat"), 1);
	tc_check("val", "network_nat.type = 'masquerade' (invalid)",
		 sg_reg_validate_value("network_nat", "type", "masquerade"), 0);

	tc_check("val", "firewall_service.protocol = 'tcp'",
		 sg_reg_validate_value("firewall_service", "protocol", "tcp"), 1);
	tc_check("val", "firewall_service.protocol = 'udp'",
		 sg_reg_validate_value("firewall_service", "protocol", "udp"), 1);
	tc_check("val", "firewall_service.protocol = 'icmp'",
		 sg_reg_validate_value("firewall_service", "protocol", "icmp"), 1);
	tc_check("val", "firewall_service.protocol = 'gre' (invalid)",
		 sg_reg_validate_value("firewall_service", "protocol", "gre"), 0);

	/* CIDR values */
	tc_check("val", "network_route_static.dst = '10.0.0.0/8'",
		 sg_reg_validate_value("network_route_static", "dst", "10.0.0.0/8"), 1);
	tc_check("val", "network_route_static.dst = '10.0.0.0' (no prefix)",
		 sg_reg_validate_value("network_route_static", "dst", "10.0.0.0"), 0);
	tc_check("val", "firewall_address.subnet = '192.168.1.0/24'",
		 sg_reg_validate_value("firewall_address", "subnet", "192.168.1.0/24"), 1);
	tc_check("val", "system_interface.ip = '172.16.0.1/32'",
		 sg_reg_validate_value("system_interface", "ip", "172.16.0.1/32"), 1);

	/* IPv4 values */
	tc_check("val", "network_route_static.gateway = '10.0.0.1'",
		 sg_reg_validate_value("network_route_static", "gateway", "10.0.0.1"), 1);
	tc_check("val", "network_route_static.gateway = '999.0.0.1' (bad)",
		 sg_reg_validate_value("network_route_static", "gateway", "999.0.0.1"), 0);
	tc_check("val", "network_dns.primary = '8.8.8.8'",
		 sg_reg_validate_value("network_dns", "primary", "8.8.8.8"), 1);
	tc_check("val", "network_nat.mapped-ip = '192.168.1.100'",
		 sg_reg_validate_value("network_nat", "mapped-ip", "192.168.1.100"), 1);

	/* uint values */
	tc_check("val", "network_route_static.distance = '10'",
		 sg_reg_validate_value("network_route_static", "distance", "10"), 1);
	tc_check("val", "network_route_static.distance = '0' (below min)",
		 sg_reg_validate_value("network_route_static", "distance", "0"), 0);
	tc_check("val", "network_route_static.distance = '256' (above max)",
		 sg_reg_validate_value("network_route_static", "distance", "256"), 0);
	tc_check("val", "system_interface.mtu = '1500'",
		 sg_reg_validate_value("system_interface", "mtu", "1500"), 1);
	tc_check("val", "system_interface.mtu = '100' (below 576)",
		 sg_reg_validate_value("system_interface", "mtu", "100"), 0);
	tc_check("val", "system_password-policy.min-length = '0'",
		 sg_reg_validate_value("system_password-policy", "min-length", "0"), 1);
	tc_check("val", "system_password-policy.min-length = '128'",
		 sg_reg_validate_value("system_password-policy", "min-length", "128"), 1);
	tc_check("val", "system_password-policy.min-length = '999' (over 128)",
		 sg_reg_validate_value("system_password-policy", "min-length", "999"), 0);
	tc_check("val", "system_password-policy.min-length = 'abc'",
		 sg_reg_validate_value("system_password-policy", "min-length", "abc"), 0);
	tc_check("val", "system_password-policy.min-length = '-1'",
		 sg_reg_validate_value("system_password-policy", "min-length", "-1"), 0);

	/* NAT port values */
	tc_check("val", "network_nat.dstport = '80'",
		 sg_reg_validate_value("network_nat", "dstport", "80"), 1);
	tc_check("val", "network_nat.dstport = '0' (below min)",
		 sg_reg_validate_value("network_nat", "dstport", "0"), 0);
	tc_check("val", "network_nat.dstport = '65536' (above max)",
		 sg_reg_validate_value("network_nat", "dstport", "65536"), 0);

	/* iface values */
	tc_check("val", "firewall_policy.srcintf = 'eth0'",
		 sg_reg_validate_value("firewall_policy", "srcintf", "eth0"), 1);
	tc_check("val", "firewall_policy.srcintf = 'eth;0' (semicolon)",
		 sg_reg_validate_value("firewall_policy", "srcintf", "eth;0"), 0);

	/* safe-id values */
	tc_check("val", "firewall_policy.name = 'my-policy'",
		 sg_reg_validate_value("firewall_policy", "name", "my-policy"), 1);
	tc_check("val", "firewall_policy.name = 'a:b' (colon)",
		 sg_reg_validate_value("firewall_policy", "name", "a:b"), 0);

	/* tz-token */
	tc_check("val", "system_settings.timezone = 'Asia/Ho_Chi_Minh'",
		 sg_reg_validate_value("system_settings", "timezone", "Asia/Ho_Chi_Minh"), 1);
	tc_check("val", "system_settings.timezone = 'US Eastern' (space)",
		 sg_reg_validate_value("system_settings", "timezone", "US Eastern"), 0);
	tc_check("val", "system_settings.timezone = '$(date)' (inject)",
		 sg_reg_validate_value("system_settings", "timezone", "$(date)"), 0);

	/* permissions-csv */
	tc_check("val", "system_admin-profile.permissions = 'monitor,admin'",
		 sg_reg_validate_value("system_admin-profile", "permissions", "monitor,admin"), 1);
	tc_check("val", "system_admin-profile.permissions = 'root' (invalid)",
		 sg_reg_validate_value("system_admin-profile", "permissions", "root"), 0);

	/* port-or-range */
	tc_check("val", "firewall_service.port-range = '80'",
		 sg_reg_validate_value("firewall_service", "port-range", "80"), 1);
	tc_check("val", "firewall_service.port-range = '1024-65535'",
		 sg_reg_validate_value("firewall_service", "port-range", "1024-65535"), 1);
	tc_check("val", "firewall_service.port-range = '80-22' (start>end)",
		 sg_reg_validate_value("firewall_service", "port-range", "80-22"), 0);

	/* cidr-or */
	tc_check("val", "network_nat.srcaddr = 'any' (keyword)",
		 sg_reg_validate_value("network_nat", "srcaddr", "any"), 1);
	tc_check("val", "network_nat.srcaddr = 'all' (keyword)",
		 sg_reg_validate_value("network_nat", "srcaddr", "all"), 1);
	tc_check("val", "network_nat.srcaddr = '10.0.0.0/8' (cidr)",
		 sg_reg_validate_value("network_nat", "srcaddr", "10.0.0.0/8"), 1);
	tc_check("val", "network_nat.srcaddr = '10.0.0.0' (plain ipv4 rejected)",
		 sg_reg_validate_value("network_nat", "srcaddr", "10.0.0.0"), 0);
	/* 'none' is a valid safe-id (could be an address object name).
	 * Existence check happens later in validate_ref_existence(). */
	tc_check("val", "network_nat.srcaddr = 'none' (valid as object name)",
		 sg_reg_validate_value("network_nat", "srcaddr", "none"), 1);

	/* ref-or */
	tc_check("val", "firewall_policy.srcaddr = 'all'",
		 sg_reg_validate_value("firewall_policy", "srcaddr", "all"), 1);
	tc_check("val", "firewall_policy.srcaddr = 'any'",
		 sg_reg_validate_value("firewall_policy", "srcaddr", "any"), 1);
	tc_check("val", "firewall_policy.srcaddr = 'my-addr' (safe-id ref)",
		 sg_reg_validate_value("firewall_policy", "srcaddr", "my-addr"), 1);
	tc_check("val", "firewall_policy.srcaddr = 'a:b' (invalid ref id)",
		 sg_reg_validate_value("firewall_policy", "srcaddr", "a:b"), 0);

	/* safe-id-or */
	tc_check("val", "firewall_policy.schedule = 'all'",
		 sg_reg_validate_value("firewall_policy", "schedule", "all"), 1);
	tc_check("val", "firewall_policy.schedule = 'any'",
		 sg_reg_validate_value("firewall_policy", "schedule", "any"), 1);
	tc_check("val", "firewall_policy.schedule = 'weekdays' (safe-id)",
		 sg_reg_validate_value("firewall_policy", "schedule", "weekdays"), 1);
	tc_check("val", "firewall_policy.schedule = 'a;b' (invalid)",
		 sg_reg_validate_value("firewall_policy", "schedule", "a;b"), 0);

	/* ref */
	tc_check("val", "system_admin.profile = 'read-write' (safe-id ref)",
		 sg_reg_validate_value("system_admin", "profile", "read-write"), 1);
	tc_check("val", "system_admin.profile = 'a:b' (invalid)",
		 sg_reg_validate_value("system_admin", "profile", "a:b"), 0);

	/* string kind (comment fields — any non-empty) */
	tc_check("val", "firewall_policy.comment = 'hello world'",
		 sg_reg_validate_value("firewall_policy", "comment", "hello world"), 1);
	tc_check("val", "firewall_policy.comment = '$(whoami)' (accepted, string kind)",
		 sg_reg_validate_value("firewall_policy", "comment", "$(whoami)"), 1);
}

/* ── Section 13: field descriptions ────────────────────────────────────── */

/*
 * tc_str — compare two strings (for use with tc_check pattern).
 */
static void tc_str(const char *section, const char *desc,
		   const char *actual, const char *expected)
{
	tc_total++;
	if (actual && expected && strcmp(actual, expected) == 0) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC " [%s] %s\n", section, desc);
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC " [%s] %s (got '%s', expected '%s')\n",
		       section, desc,
		       actual ? actual : "(null)",
		       expected ? expected : "(null)");
	}
}

static void test_field_desc(void)
{
	printf(C_CYAN "\n  --- field descriptions ---" C_NC "\n");

	/* Known descriptions */
	tc_str("field-desc",
	       "network_route_static.dst = 'Destination network'",
	       sg_reg_field_desc("network_route_static", "dst"),
	       "Destination network");
	tc_str("field-desc",
	       "network_route_static.gateway = 'Next-hop gateway address'",
	       sg_reg_field_desc("network_route_static", "gateway"),
	       "Next-hop gateway address");
	tc_str("field-desc",
	       "network_route_static.status = 'Enable or disable this route'",
	       sg_reg_field_desc("network_route_static", "status"),
	       "Enable or disable this route");
	tc_str("field-desc",
	       "system_interface.mtu = 'Maximum transmission unit'",
	       sg_reg_field_desc("system_interface", "mtu"),
	       "Maximum transmission unit");
	tc_str("field-desc",
	       "firewall_policy.action = 'Matching traffic action'",
	       sg_reg_field_desc("firewall_policy", "action"),
	       "Matching traffic action");
	tc_str("field-desc",
	       "firewall_policy.comment = 'Optional description'",
	       sg_reg_field_desc("firewall_policy", "comment"),
	       "Optional description");
	tc_str("field-desc",
	       "system_settings.hostname = 'System hostname'",
	       sg_reg_field_desc("system_settings", "hostname"),
	       "System hostname");
	tc_str("field-desc",
	       "network_dns.primary = 'Primary DNS server'",
	       sg_reg_field_desc("network_dns", "primary"),
	       "Primary DNS server");
	tc_str("field-desc",
	       "system_admin.password = 'Account password'",
	       sg_reg_field_desc("system_admin", "password"),
	       "Account password");
	tc_str("field-desc",
	       "system_password-policy.min-length = 'Minimum password length'",
	       sg_reg_field_desc("system_password-policy", "min-length"),
	       "Minimum password length");
	tc_str("field-desc",
	       "firewall_service.port-range = 'Port or port range'",
	       sg_reg_field_desc("firewall_service", "port-range"),
	       "Port or port range");
	tc_str("field-desc",
	       "network_nat.mapped-ip = 'Translated IP address'",
	       sg_reg_field_desc("network_nat", "mapped-ip"),
	       "Translated IP address");

	/* Unknown type or key returns empty string */
	tc_str("field-desc",
	       "unknown type returns ''",
	       sg_reg_field_desc("nonexistent_type", "dst"),
	       "");
	tc_str("field-desc",
	       "unknown key returns ''",
	       sg_reg_field_desc("firewall_policy", "nonexistent_key"),
	       "");
	tc_str("field-desc",
	       "NULL type returns ''",
	       sg_reg_field_desc(NULL, "dst"),
	       "");
	tc_str("field-desc",
	       "NULL key returns ''",
	       sg_reg_field_desc("firewall_policy", NULL),
	       "");
}

/* ── Section 14: quoted value detection ───────────────────────────────── */

static void test_value_quoting(void)
{
	printf(C_CYAN "\n  --- value quoting (string kind detection) ---"
	       C_NC "\n");

	/* "string" kind fields — should be quoted in show output */
	tc_check("quoting", "firewall_policy.comment kind is 'string'",
		 strcmp(sg_reg_value_kind("firewall_policy", "comment"),
			"string") == 0, 1);
	tc_check("quoting", "firewall_address.comment kind is 'string'",
		 strcmp(sg_reg_value_kind("firewall_address", "comment"),
			"string") == 0, 1);
	tc_check("quoting", "firewall_service.comment kind is 'string'",
		 strcmp(sg_reg_value_kind("firewall_service", "comment"),
			"string") == 0, 1);
	tc_check("quoting", "system_interface.description kind is 'string'",
		 strcmp(sg_reg_value_kind("system_interface", "description"),
			"string") == 0, 1);
	tc_check("quoting", "system_admin-profile.description kind is 'string'",
		 strcmp(sg_reg_value_kind("system_admin-profile", "description"),
			"string") == 0, 1);
	tc_check("quoting", "network_route_static.comment kind is 'string'",
		 strcmp(sg_reg_value_kind("network_route_static", "comment"),
			"string") == 0, 1);

	/* Non-string kind fields — should NOT be quoted */
	tc_check("quoting", "firewall_policy.action kind is NOT 'string'",
		 strcmp(sg_reg_value_kind("firewall_policy", "action"),
			"string") != 0, 1);
	tc_check("quoting", "firewall_policy.status kind is NOT 'string'",
		 strcmp(sg_reg_value_kind("firewall_policy", "status"),
			"string") != 0, 1);
	tc_check("quoting", "system_interface.mtu kind is NOT 'string'",
		 strcmp(sg_reg_value_kind("system_interface", "mtu"),
			"string") != 0, 1);
	tc_check("quoting", "network_route_static.dst kind is NOT 'string'",
		 strcmp(sg_reg_value_kind("network_route_static", "dst"),
			"string") != 0, 1);
	tc_check("quoting", "network_route_static.gateway kind is NOT 'string'",
		 strcmp(sg_reg_value_kind("network_route_static", "gateway"),
			"string") != 0, 1);
	tc_check("quoting", "system_settings.hostname kind is NOT 'string'",
		 strcmp(sg_reg_value_kind("system_settings", "hostname"),
			"string") != 0, 1);
	tc_check("quoting", "network_nat.dstport kind is NOT 'string'",
		 strcmp(sg_reg_value_kind("network_nat", "dstport"),
			"string") != 0, 1);
	tc_check("quoting", "system_admin.profile kind is NOT 'string'",
		 strcmp(sg_reg_value_kind("system_admin", "profile"),
			"string") != 0, 1);
}

/* ── Section 15: command abbreviation resolution ──────────────────────── */

static void tc_resolve(const char *desc, const char *input,
		       int expect_rc, const char *expect_out)
{
	char output[CLI_MAX_LINE];

	output[0] = '\0';
	tc_total++;

	int rc = cli_resolve_cmd(input, output, sizeof(output));

	if (rc != expect_rc) {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC " [cmd-abbr] %s"
		       " (rc=%d, expected %d)\n",
		       desc, rc, expect_rc);
		return;
	}

	if (expect_rc == 0 && strcmp(output, expect_out) != 0) {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC " [cmd-abbr] %s"
		       " (got '%s', expected '%s')\n",
		       desc, output, expect_out);
		return;
	}

	tc_pass++;
	printf(C_GREEN "  PASS" C_NC " [cmd-abbr] %s\n", desc);
}

static void test_cmd_resolve(void)
{
	printf(C_CYAN "\n  --- command abbreviation resolution ---"
	       C_NC "\n");

	/* Save current completions, start fresh for test */
	cli_push();

	/* Register a typical top-level command set */
	cli_register("execute system shutdown",
		     "Shutdown the system");
	cli_register("execute system reboot",
		     "Reboot the system");
	cli_register("exit", "Exit CLI");
	cli_register("show status", "Show system status");
	cli_register("show config", "Show running config");
	cli_register("show configure",
		     "Show config mode options");
	cli_register("configure system admin",
		     "Admin user config");
	cli_register("configure system admin-profile",
		     "Admin profile config");
	cli_register("configure system settings",
		     "System settings");
	cli_register("configure firewall policy",
		     "Firewall policy");
	cli_register("help", "Show help");
	cli_register("set hostname", "Set device hostname");

	/* ── Basic expansion ──────────────────────────────── */

	tc_resolve("expand 'exe sys shut'",
		   "exe sys shut", 0,
		   "execute system shutdown");
	tc_resolve("expand 'exe sys re'",
		   "exe sys re", 0,
		   "execute system reboot");
	tc_resolve("expand 'h' -> help",
		   "h", 0, "help");
	tc_resolve("expand 'exi' -> exit",
		   "exi", 0, "exit");
	tc_resolve("expand 'sh sta' -> show status",
		   "sh sta", 0, "show status");
	tc_resolve("expand 'con fi po'",
		   "con fi po", 0,
		   "configure firewall policy");
	tc_resolve("expand 'con sys se'",
		   "con sys se", 0,
		   "configure system settings");

	/* ── Exact match priority ─────────────────────────── */

	tc_resolve("exact 'admin' beats 'admin-profile'",
		   "con sys admin", 0,
		   "configure system admin");
	tc_resolve("full command unchanged",
		   "execute system shutdown", 0,
		   "execute system shutdown");
	tc_resolve("exact single word 'help'",
		   "help", 0, "help");
	tc_resolve("exact single word 'exit'",
		   "exit", 0, "exit");

	/* ── Ambiguity detection ──────────────────────────── */

	tc_resolve("ambiguous 'ex' -> execute/exit",
		   "ex", -1, NULL);
	tc_resolve("ambiguous 'con sys adm'",
		   "con sys adm", -1, NULL);
	tc_resolve("ambiguous 'sh conf'",
		   "sh conf", -1, NULL);

	/* ── Hyphenated prefix ────────────────────────────── */

	tc_resolve("prefix 'admin-' -> admin-profile",
		   "con sys admin-", 0,
		   "configure system admin-profile");
	tc_resolve("prefix 'admin-p' -> admin-profile",
		   "con sys admin-p", 0,
		   "configure system admin-profile");

	/* ── Longer prefix resolves ambiguity ─────────────── */

	tc_resolve("'sh configu' -> show configure",
		   "sh configu", 0, "show configure");
	tc_resolve("'exe' unique (not exit)",
		   "exe", 0, "execute");

	/* ── Value passthrough ────────────────────────────── */

	tc_resolve("value passthrough 'se hos stargazer'",
		   "se hos stargazer", 0,
		   "set hostname stargazer");
	tc_resolve("dotted value 'se hos fw.example.com'",
		   "se hos fw.example.com", 0,
		   "set hostname fw.example.com");
	tc_resolve("multi value passthrough",
		   "se hos first second third", 0,
		   "set hostname first second third");

	/* ── Edge cases ───────────────────────────────────── */

	tc_resolve("empty input",
		   "", 0, "");
	tc_resolve("unregistered word passes through",
		   "nonexistent", 0, "nonexistent");
	tc_resolve("unregistered + trailing pass through",
		   "nonexistent foo bar", 0,
		   "nonexistent foo bar");

	/* ── Push/pop: configure entry context ────────────── */

	printf(C_CYAN "\n  --- cmd-abbr: configure entry context ---"
	       C_NC "\n");

	cli_push();
	cli_register("set hostname", "Set hostname");
	cli_register("set status", "Set status");
	cli_register("show", "Show parameters");
	cli_register("get hostname", "Get hostname");
	cli_register("get status", "Get status");
	cli_register("unset hostname", "Unset hostname");
	cli_register("unset status", "Unset status");
	cli_register("end", "Save and exit");
	cli_register("abort", "Discard and exit");
	cli_register("next", "Save and continue");

	tc_resolve("ctx: 'se hos myhost'",
		   "se hos myhost", 0,
		   "set hostname myhost");
	tc_resolve("ctx: 'sh' -> show",
		   "sh", 0, "show");
	tc_resolve("ctx: 'g hos' -> get hostname",
		   "g hos", 0, "get hostname");
	tc_resolve("ctx: 'un hos' -> unset hostname",
		   "un hos", 0, "unset hostname");
	tc_resolve("ctx: 'en' -> end",
		   "en", 0, "end");
	tc_resolve("ctx: 'ab' -> abort",
		   "ab", 0, "abort");
	tc_resolve("ctx: 'ne' -> next",
		   "ne", 0, "next");
	tc_resolve("ctx: ambiguous 's' -> set/show",
		   "s", -1, NULL);
	tc_resolve("ctx: 'se sta enable' passthrough",
		   "se sta enable", 0,
		   "set status enable");

	cli_pop();

	/* ── Push/pop: configure table context ────────────── */

	printf(C_CYAN "\n  --- cmd-abbr: configure table context ---"
	       C_NC "\n");

	cli_push();
	cli_register("show", "Show entries");
	cli_register("edit <id>", "Edit entry");
	cli_register("delete <id>", "Delete entry");
	cli_register("end", "Exit context");

	tc_resolve("table: 'sh' -> show",
		   "sh", 0, "show");
	tc_resolve("table: 'ed myid' passthrough",
		   "ed myid", 0, "edit myid");
	tc_resolve("table: 'de myid' passthrough",
		   "de myid", 0, "delete myid");
	tc_resolve("table: 'en' -> end",
		   "en", 0, "end");
	tc_resolve("table: ambiguous 'e' -> edit/end",
		   "e", -1, NULL);

	cli_pop();

	/* Verify top-level context was restored */
	tc_resolve("post-pop: 'h' -> help restored",
		   "h", 0, "help");
	tc_resolve("post-pop: 'exe sys shut' still works",
		   "exe sys shut", 0,
		   "execute system shutdown");

	/* Restore original CLI completions */
	cli_pop();
}

/* ── Section 16: IPC validation (full mode) ───────────────────────────── */

/*
 * ipc_check — send IPC request and check status matches expected.
 */
static void ipc_check(const char *desc, uint32_t opcode,
		      const char *payload, uint32_t expect_status)
{
	struct ipc_response resp;
	int conn;

	tc_total++;
	conn = ipc_send_str(opcode, payload, &resp);

	if (conn < 0) {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC " [IPC/%u] %s (connection failed)\n",
		       opcode, desc);
		return;
	}

	if (resp.status == expect_status) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC " [IPC/%u] %s (status=%u)\n",
		       opcode, desc, resp.status);
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC " [IPC/%u] %s (got %u, expected %u",
		       opcode, desc, resp.status, expect_status);
		if (resp.extra[0])
			printf(": %s", resp.extra);
		printf(")\n");
	}

	ipc_resp_free(&resp);
}

static void test_ipc_cfg_reject(void)
{
	printf(C_CYAN "\n  --- IPC: config commands reject invalid input ---"
	       C_NC "\n");

	/* CFG_SET with unknown type */
	ipc_check("CFG_SET unknown type 'bogus_type'",
		  SG_CMD_CFG_SET,
		  "bogus_type:test\nkey=val\n",
		  SG_ERR_INVALID_ARG);

	/* CFG_SET with injection in type */
	ipc_check("CFG_SET type with colon 'a:b:c'",
		  SG_CMD_CFG_SET,
		  "a:b:c\nkey=val\n",
		  SG_ERR_INVALID_ARG);

	/* CFG_SET with injection chars in ID */
	ipc_check("CFG_SET ID with semicolon '../etc'",
		  SG_CMD_CFG_SET,
		  "firewall_address:../etc\nname=test\n",
		  SG_ERR_INVALID_ARG);

	/* CFG_DEL with unknown type */
	ipc_check("CFG_DEL unknown type 'bogus_type:test'",
		  SG_CMD_CFG_DEL,
		  "bogus_type:test",
		  SG_ERR_INVALID_ARG);

	/* CFG_GET with invalid type ID */
	ipc_check("CFG_GET invalid section 'a;b'",
		  SG_CMD_CFG_GET,
		  "a;b",
		  SG_ERR_INVALID_ARG);

	/* CFG_LIST with invalid prefix */
	ipc_check("CFG_LIST invalid prefix 'a;drop'",
		  SG_CMD_CFG_LIST,
		  "a;drop",
		  SG_ERR_INVALID_ARG);
}

static void test_ipc_admin_reject(void)
{
	printf(C_CYAN "\n  --- IPC: admin commands reject invalid input ---"
	       C_NC "\n");

	/* ADMIN_SET_ENF with bad username */
	ipc_check("ADMIN_SET_ENF username with colon 'a:b'",
		  SG_CMD_ADMIN_SET_ENF,
		  "a:b\nenable\n",
		  SG_ERR_INVALID_ARG);

	/* ADMIN_SET_ENF with bad value (not enable/disable) */
	ipc_check("ADMIN_SET_ENF value 'maybe' (not enable/disable)",
		  SG_CMD_ADMIN_SET_ENF,
		  "admin\nmaybe\n",
		  SG_ERR_INVALID_VAL);

	/* ADMIN_CHECK_PW with bad username */
	ipc_check("ADMIN_CHECK_PW username '../etc'",
		  SG_CMD_ADMIN_CHECK_PW,
		  "../etc\npassword\n",
		  SG_ERR_INVALID_ARG);

	/* ADMIN_LOCK_PW with bad username */
	ipc_check("ADMIN_LOCK_PW username 'a;b'",
		  SG_CMD_ADMIN_LOCK_PW,
		  "a;b",
		  SG_ERR_INVALID_ARG);

	/* ADMIN_CREATE with bad username (no validation, but verify it
	 * does not crash — this tests existing behavior) */
	ipc_check("ADMIN_CREATE username 'a:b' (should reject)",
		  SG_CMD_ADMIN_CREATE,
		  "a:b\nread-write\n",
		  SG_ERR_INVALID_ARG);
}

static void test_ipc_builtin_protect(void)
{
	printf(C_CYAN "\n  --- IPC: builtin objects protected ---" C_NC "\n");

	/* Cannot delete builtin admin */
	ipc_check("ADMIN_DELETE builtin 'admin'",
		  SG_CMD_ADMIN_DELETE,
		  "admin",
		  SG_ERR_BUILTIN);

	/* Cannot delete builtin profile via CFG_DEL */
	ipc_check("CFG_DEL builtin profile 'read-write'",
		  SG_CMD_CFG_DEL,
		  "system_admin-profile:read-write",
		  SG_ERR_BUILTIN);

	ipc_check("CFG_DEL builtin profile 'read-only'",
		  SG_CMD_CFG_DEL,
		  "system_admin-profile:read-only",
		  SG_ERR_BUILTIN);
}

/* ── Section 17: IPC round-trip (full mode) ───────────────────────────── */

static void test_ipc_roundtrip(void)
{
	struct ipc_response resp;
	int conn;
	const char *test_section = "firewall_address:__diag_cfgtest";

	printf(C_CYAN "\n  --- IPC: config create/read/delete round-trip ---"
	       C_NC "\n");

	/* 1. Create entry via CFG_SET */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_address:__diag_cfgtest\n"
			    "name=__diag_cfgtest\n"
			    "subnet=10.99.99.0/24\n"
			    "type=ipmask\n",
			    &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/200] create firewall_address __diag_cfgtest\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/200] create __diag_cfgtest (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
		ipc_resp_free(&resp);
		return;
	}
	ipc_resp_free(&resp);

	/* 2. Read back via CFG_GET */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET, test_section, &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "name=__diag_cfgtest") &&
	    strstr(resp.payload, "subnet=10.99.99.0/24") &&
	    strstr(resp.payload, "type=ipmask")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/100] read back __diag_cfgtest (data matches)\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/100] read back __diag_cfgtest"
		       " (status=%u, payload=%s)\n",
		       conn < 0 ? 999 : resp.status,
		       resp.payload ? resp.payload : "(null)");
	}
	ipc_resp_free(&resp);

	/* 3. Verify it appears in CFG_LIST */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_LIST, "firewall_address", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "__diag_cfgtest")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/101] __diag_cfgtest in CFG_LIST\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/101] __diag_cfgtest not in CFG_LIST"
		       " (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* 4. Update via CFG_SET (overwrite with changed data) */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_address:__diag_cfgtest\n"
			    "name=__diag_cfgtest\n"
			    "subnet=172.16.0.0/12\n"
			    "type=ipmask\n"
			    "comment=roundtrip-test\n",
			    &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/200] update __diag_cfgtest\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/200] update __diag_cfgtest (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* 5. Verify update via CFG_GET */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET, test_section, &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "subnet=172.16.0.0/12") &&
	    strstr(resp.payload, "comment=roundtrip-test")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/100] updated data verified\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/100] updated data mismatch (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* 6. Delete via CFG_DEL */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_DEL, test_section, &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/201] delete __diag_cfgtest\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/201] delete __diag_cfgtest (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* 7. Verify deletion — CFG_GET should return NOT_FOUND */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET, test_section, &resp);
	if (conn == 0 && resp.status != SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/100] __diag_cfgtest gone after delete"
		       " (status=%u)\n", resp.status);
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/100] __diag_cfgtest still exists after"
		       " delete\n");
	}
	ipc_resp_free(&resp);
}

/* ── Section 18: IPC static route round-trip with apply ───────────────── */

static void test_ipc_apply(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- IPC: config apply (runtime handler) ---"
	       C_NC "\n");

	/* Apply a system_settings config — tests the hostname handler */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_APPLY,
			    "system_settings\n0\n"
			    "hostname=stargazer\n"
			    "ip-forward=enable\n"
			    "timezone=UTC\n",
			    &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/202] CFG_APPLY system_settings accepted\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/202] CFG_APPLY system_settings (status=%u",
		       conn < 0 ? 999 : resp.status);
		if (resp.extra[0])
			printf(": %s", resp.extra);
		printf(")\n");
	}
	ipc_resp_free(&resp);

	/* Apply with known type but unknown apply handler (should still OK) */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_APPLY,
			    "network_dns\n0\n"
			    "primary=8.8.8.8\n"
			    "secondary=8.8.4.4\n",
			    &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/202] CFG_APPLY network_dns (no handler OK)\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/202] CFG_APPLY network_dns (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);
}

/* ── Section 19: Nonexistent entry operations ─────────────────────────── */

static void test_ipc_not_found(void)
{
	printf(C_CYAN "\n  --- IPC: not-found behavior ---" C_NC "\n");

	/* CFG_GET for nonexistent entry */
	ipc_check("CFG_GET nonexistent firewall_address:__noexist",
		  SG_CMD_CFG_GET,
		  "firewall_address:__noexist",
		  SG_ERR_ENTRY_NOT_FOUND);

	/* ADMIN_DELETE nonexistent user */
	ipc_check("ADMIN_DELETE nonexistent '__diag_nobody'",
		  SG_CMD_ADMIN_DELETE,
		  "__diag_nobody",
		  SG_ERR_USER_NOT_FOUND);
}

/* ── Section 20: reference metadata (unit tests) ──────────────────────── */

static void test_ref_metadata(void)
{
	printf(C_CYAN "\n  --- reference metadata ---" C_NC "\n");

	/* sg_parse_ref_kind: ref:TYPE */
	{
		char rt[64], ro[64];
		int rc = sg_parse_ref_kind("ref:system_admin-profile",
					   rt, sizeof(rt), ro, sizeof(ro));
		tc_check("ref-meta", "parse ref:system_admin-profile -> 1",
			 rc, 1);
		tc_str("ref-meta", "ref:system_admin-profile type",
		       rt, "system_admin-profile");
		tc_str("ref-meta", "ref:system_admin-profile opts empty",
		       ro, "");
	}

	/* sg_parse_ref_kind: ref-or:TYPE:opts */
	{
		char rt[64], ro[64];
		int rc = sg_parse_ref_kind("ref-or:firewall_address:all,any",
					   rt, sizeof(rt), ro, sizeof(ro));
		tc_check("ref-meta",
			 "parse ref-or:firewall_address:all,any -> 1",
			 rc, 1);
		tc_str("ref-meta", "ref-or type = firewall_address",
		       rt, "firewall_address");
		tc_str("ref-meta", "ref-or opts = all,any",
		       ro, "all,any");
	}

	/* sg_parse_ref_kind: ref-or-cidr:TYPE:opts */
	{
		char rt[64], ro[64];
		int rc = sg_parse_ref_kind("ref-or-cidr:firewall_address:all,any",
					   rt, sizeof(rt), ro, sizeof(ro));
		tc_check("ref-meta",
			 "parse ref-or-cidr:firewall_address:all,any -> 1",
			 rc, 1);
		tc_str("ref-meta", "ref-or-cidr type = firewall_address",
		       rt, "firewall_address");
		tc_str("ref-meta", "ref-or-cidr opts = all,any",
		       ro, "all,any");
	}

	/* sg_parse_ref_kind: non-ref kinds return 0 */
	{
		char rt[64], ro[64];
		tc_check("ref-meta", "parse enum:a,b -> 0",
			 sg_parse_ref_kind("enum:a,b", rt, sizeof(rt),
					   ro, sizeof(ro)), 0);
		tc_check("ref-meta", "parse safe-id -> 0",
			 sg_parse_ref_kind("safe-id", rt, sizeof(rt),
					   ro, sizeof(ro)), 0);
		tc_check("ref-meta", "parse cidr -> 0",
			 sg_parse_ref_kind("cidr", rt, sizeof(rt),
					   ro, sizeof(ro)), 0);
	}

	/* sg_reg_find_referencing: firewall_address -> 4 fields
	 * (NAT srcaddr, NAT dstaddr, policy srcaddr, policy dstaddr) */
	{
		sg_ref_entry_t refs[16];
		int n = sg_reg_find_referencing("firewall_address",
						refs, 16);
		tc_check("ref-meta",
			 "firewall_address referenced by 4 fields",
			 n, 4);
	}

	/* sg_reg_find_referencing: firewall_service -> 1 field */
	{
		sg_ref_entry_t refs[16];
		int n = sg_reg_find_referencing("firewall_service",
						refs, 16);
		tc_check("ref-meta",
			 "firewall_service referenced by 1 field",
			 n, 1);
		if (n >= 1) {
			tc_str("ref-meta", "ref[0].key = service",
			       refs[0].key, "service");
		}
	}

	/* sg_reg_find_referencing: system_admin-profile -> 1 field */
	{
		sg_ref_entry_t refs[16];
		int n = sg_reg_find_referencing("system_admin-profile",
						refs, 16);
		tc_check("ref-meta",
			 "system_admin-profile referenced by 1 field",
			 n, 1);
		if (n >= 1) {
			tc_str("ref-meta", "ref[0].key = profile",
			       refs[0].key, "profile");
		}
	}

	/* sg_reg_find_referencing: network_route_static -> 0 fields */
	{
		sg_ref_entry_t refs[16];
		int n = sg_reg_find_referencing("network_route_static",
						refs, 16);
		tc_check("ref-meta",
			 "network_route_static referenced by 0 fields",
			 n, 0);
	}
}

/* ── Section 21: dispatch table verification ──────────────────────────── */

static void test_dispatch_table(void)
{
	printf(C_CYAN "\n  --- dispatch table verification ---" C_NC "\n");

	/* Return values: exit/logout→1, unknown/empty/NULL→0 */
	tc_check("dispatch", "exit returns 1",
		 cmd_dispatch("exit", "monitor,configure,admin"), 1);
	tc_check("dispatch", "logout returns 1",
		 cmd_dispatch("logout", "monitor,configure,admin"), 1);
	tc_check("dispatch", "unknown returns 0",
		 cmd_dispatch("nonexistent_command_xyz", "admin"), 0);
	tc_check("dispatch", "empty returns 0",
		 cmd_dispatch("", "admin"), 0);
	tc_check("dispatch", "NULL returns 0",
		 cmd_dispatch(NULL, "admin"), 0);

	/* Leading whitespace stripped */
	tc_check("dispatch", "leading spaces '  exit' returns 1",
		 cmd_dispatch("  exit", "monitor,configure,admin"), 1);

	/* Auto-usage prefixes: print children, return 0 */
	tc_check("dispatch", "'show' auto-usage returns 0",
		 cmd_dispatch("show", "monitor,configure,admin"), 0);
	tc_check("dispatch", "'execute system' auto-usage returns 0",
		 cmd_dispatch("execute system", "admin"), 0);
	tc_check("dispatch", "'execute diagnose' auto-usage returns 0",
		 cmd_dispatch("execute diagnose", "admin"), 0);

	/* Permission denial: no matching permission → prints denied, returns 0 */
	tc_check("dispatch", "show status with empty perms → denied",
		 cmd_dispatch("show status", ""), 0);
	tc_check("dispatch", "execute debug enable with monitor-only → denied",
		 cmd_dispatch("execute debug enable", "monitor"), 0);
	tc_check("dispatch", "configure with monitor-only → denied",
		 cmd_dispatch("configure", "monitor"), 0);
	tc_check("dispatch", "execute system shutdown with monitor-only → denied",
		 cmd_dispatch("execute system shutdown", "monitor"), 0);

	/* Permission OR: 'admin' alone (no 'monitor') → denied for show */
	tc_check("dispatch", "show status with 'admin' (no monitor) → denied",
		 cmd_dispatch("show status", "admin"), 0);
}

/* ── Section 22: registry completeness ────────────────────────────────── */

static void test_registry_completeness(void)
{
	printf(C_CYAN "\n  --- registry completeness ---" C_NC "\n");

	const sg_type_info_t *types = sg_reg_types();
	int count = 0;
	int wired = 0;
	int all_labels = 1;
	int all_domains = 1;
	int all_modes = 1;
	int all_req_in_valid = 1;

	for (int i = 0; types[i].name; i++) {
		const char *name = types[i].name;
		count++;

		const char *keys = sg_reg_valid_keys(name);
		if (keys && keys[0])
			wired++;

		const char *label = sg_reg_type_label(name);
		if (!label || !label[0])
			all_labels = 0;

		const char *domain = sg_reg_domain_for(name);
		if (!domain || !domain[0])
			all_domains = 0;

		int mode = sg_reg_type_mode(name);
		if (mode != CFG_TABLE && mode != CFG_SINGLE)
			all_modes = 0;

		/* Check required keys are subset of valid keys */
		const char *req = sg_reg_required_keys(name);
		if (req && req[0]) {
			char buf[512];
			snprintf(buf, sizeof(buf), "%s", req);
			char *tok = buf;
			while (*tok) {
				while (*tok == ' ')
					tok++;
				if (!*tok)
					break;
				char *end = tok;
				while (*end && *end != ' ')
					end++;
				char save = *end;
				*end = '\0';
				if (!sg_reg_is_valid_key(name, tok))
					all_req_in_valid = 0;
				*end = save;
				tok = end;
			}
		}
	}

	tc_check("reg-complete", "wired types have valid keys (>=12)",
		 wired >= 12, 1);
	tc_check("reg-complete", "all types have labels",
		 all_labels, 1);
	tc_check("reg-complete", "all types have domain files",
		 all_domains, 1);
	tc_check("reg-complete", "all types have valid mode (TABLE or SINGLE)",
		 all_modes, 1);
	tc_check("reg-complete", "all required keys are registered as valid",
		 all_req_in_valid, 1);
	tc_check("reg-complete", "at least 15 types registered",
		 count >= 15, 1);
}

/* ── Section 23: default value self-validation ────────────────────────── */

static void test_default_roundtrip(void)
{
	printf(C_CYAN "\n  --- default value self-validation ---" C_NC "\n");

	const sg_type_info_t *types = sg_reg_types();

	for (int i = 0; types[i].name; i++) {
		const char *name = types[i].name;
		const char *defaults = sg_reg_default_values(name);
		if (!defaults || !defaults[0])
			continue;

		char buf[1024];
		snprintf(buf, sizeof(buf), "%s", defaults);
		char *line = buf;

		while (*line) {
			/* Find end of line */
			char *eol = strchr(line, '\n');
			if (eol)
				*eol = '\0';

			/* Skip empty lines */
			if (!*line) {
				if (eol)
					line = eol + 1;
				else
					break;
				continue;
			}

			/* Parse key=value */
			char *eq = strchr(line, '=');
			if (eq) {
				*eq = '\0';
				const char *key = line;
				const char *val = eq + 1;

				char desc[256];
				snprintf(desc, sizeof(desc),
					 "%.40s.%.30s default '%.40s' validates",
					 name, key, val);
				tc_check("defaults", desc,
					 sg_reg_validate_value(name, key, val),
					 1);
			}

			if (eol)
				line = eol + 1;
			else
				break;
		}
	}
}

/* ── Section 24: numeric boundary exhaustive ──────────────────────────── */

static void test_boundary_values(void)
{
	printf(C_CYAN "\n  --- numeric boundary exhaustive ---" C_NC "\n");

	/* system_interface.mtu: 576-65535 */
	tc_check("boundary", "system_interface.mtu = '576' (min)",
		 sg_reg_validate_value("system_interface", "mtu", "576"), 1);
	tc_check("boundary", "system_interface.mtu = '65535' (max)",
		 sg_reg_validate_value("system_interface", "mtu", "65535"), 1);
	tc_check("boundary", "system_interface.mtu = '575' (below min)",
		 sg_reg_validate_value("system_interface", "mtu", "575"), 0);
	tc_check("boundary", "system_interface.mtu = '65536' (above max)",
		 sg_reg_validate_value("system_interface", "mtu", "65536"), 0);

	/* network_nat.dstport: 1-65535 */
	tc_check("boundary", "network_nat.dstport = '1' (min)",
		 sg_reg_validate_value("network_nat", "dstport", "1"), 1);
	tc_check("boundary", "network_nat.dstport = '65535' (max)",
		 sg_reg_validate_value("network_nat", "dstport", "65535"), 1);

	/* network_nat.mapped-port: 1-65535 */
	tc_check("boundary", "network_nat.mapped-port = '1' (min)",
		 sg_reg_validate_value("network_nat", "mapped-port", "1"), 1);
	tc_check("boundary", "network_nat.mapped-port = '65535' (max)",
		 sg_reg_validate_value("network_nat", "mapped-port", "65535"), 1);

	/* network_dns.port and cache-size: not yet in schema — tests
	 * deferred until DNS resolver feature is implemented. */

	/* network_dhcp-server.lease-time: 60-604800 */
	tc_check("boundary", "network_dhcp-server.lease-time = '60' (min)",
		 sg_reg_validate_value("network_dhcp-server", "lease-time", "60"), 1);
	tc_check("boundary", "network_dhcp-server.lease-time = '604800' (max)",
		 sg_reg_validate_value("network_dhcp-server", "lease-time", "604800"), 1);
	tc_check("boundary", "network_dhcp-server.lease-time = '59' (below min)",
		 sg_reg_validate_value("network_dhcp-server", "lease-time", "59"), 0);
	tc_check("boundary", "network_dhcp-server.lease-time = '604801' (above max)",
		 sg_reg_validate_value("network_dhcp-server", "lease-time", "604801"), 0);

	/* system_password-policy.min-uppercase: 0-128 */
	tc_check("boundary", "system_password-policy.min-uppercase = '0' (min)",
		 sg_reg_validate_value("system_password-policy", "min-uppercase", "0"), 1);
	tc_check("boundary", "system_password-policy.min-uppercase = '128' (max)",
		 sg_reg_validate_value("system_password-policy", "min-uppercase", "128"), 1);
	tc_check("boundary", "system_password-policy.min-uppercase = '129' (above max)",
		 sg_reg_validate_value("system_password-policy", "min-uppercase", "129"), 0);

	/* Overflow: huge number for mtu */
	tc_check("boundary", "system_interface.mtu = '99999999999' (overflow)",
		 sg_reg_validate_value("system_interface", "mtu", "99999999999"), 0);

	/* Leading zeros: "01500" — all digits, parses to valid value */
	tc_check("boundary", "system_interface.mtu = '01500' (leading zeros)",
		 sg_reg_validate_value("system_interface", "mtu", "01500"), 1);
}

/* ── Section 25: cross-type key isolation ─────────────────────────────── */

static void test_cross_type_keys(void)
{
	printf(C_CYAN "\n  --- cross-type key isolation ---" C_NC "\n");

	tc_check("key-iso", "'action' invalid for system_interface",
		 sg_reg_is_valid_key("system_interface", "action"), 0);
	tc_check("key-iso", "'mtu' invalid for firewall_policy",
		 sg_reg_is_valid_key("firewall_policy", "mtu"), 0);
	tc_check("key-iso", "'hostname' invalid for network_nat",
		 sg_reg_is_valid_key("network_nat", "hostname"), 0);
	tc_check("key-iso", "'subnet' invalid for system_settings",
		 sg_reg_is_valid_key("system_settings", "subnet"), 0);
	tc_check("key-iso", "'protocol' invalid for network_dns",
		 sg_reg_is_valid_key("network_dns", "protocol"), 0);
}

/* ── Section 26: IPC interface builtin protection (full mode) ─────────── */

static void test_ipc_interface_protection(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- IPC: interface builtin protection ---"
	       C_NC "\n");

	/*
	 * Find an existing interface with builtin=yes by listing all
	 * system_interface entries and checking each one.
	 */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_LIST, "system_interface", &resp);
	if (conn < 0 || resp.status != SG_OK || !resp.payload) {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [iface-prot] cannot list interfaces"
		       " (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
		ipc_resp_free(&resp);
		return;
	}

	/* Find first interface with builtin=yes */
	char builtin_iface[64] = {0};
	const char *p = resp.payload;
	while (*p && !builtin_iface[0]) {
		const char *eol = strchr(p, '\n');
		size_t len = eol ? (size_t)(eol - p) : strlen(p);
		if (len == 0) { p++; continue; }

		char name[64];
		if (len >= sizeof(name)) len = sizeof(name) - 1;
		memcpy(name, p, len);
		name[len] = '\0';

		/* Query this interface's data */
		char section[128];
		snprintf(section, sizeof(section),
			 "system_interface:%s", name);
		struct ipc_response r2;
		int c2 = ipc_send_str(SG_CMD_CFG_GET, section, &r2);
		if (c2 == 0 && r2.status == SG_OK && r2.payload &&
		    strstr(r2.payload, "builtin=yes")) {
			snprintf(builtin_iface, sizeof(builtin_iface),
				 "%s", name);
		}
		ipc_resp_free(&r2);

		p += len;
		if (eol) p++;
	}
	ipc_resp_free(&resp);

	if (!builtin_iface[0]) {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [iface-prot] no builtin interface found"
		       " (sync may not have run)\n");
		return;
	}
	tc_pass++;
	printf(C_GREEN "  PASS" C_NC
	       " [iface-prot] found builtin interface: %s\n",
	       builtin_iface);

	/* Try to delete the builtin interface — expect SG_ERR_BUILTIN */
	char del_section[128];
	snprintf(del_section, sizeof(del_section),
		 "system_interface:%s", builtin_iface);
	ipc_check("delete builtin interface -> BUILTIN",
		  SG_CMD_CFG_DEL, del_section, SG_ERR_BUILTIN);

	/* Verify it still exists */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET, del_section, &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [iface-prot] %s still exists after delete attempt\n",
		       builtin_iface);
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [iface-prot] %s was deleted despite builtin=yes\n",
		       builtin_iface);
	}
	ipc_resp_free(&resp);
}

/* ── Section 22: IPC referential integrity guard (full mode) ──────────── */

static void test_ipc_refguard(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- IPC: referential integrity guard ---"
	       C_NC "\n");

	/* 1. Create firewall_address:__diag_refaddr */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_address:__diag_refaddr\n"
			    "name=__diag_refaddr\n"
			    "subnet=10.88.88.0/24\n"
			    "type=ipmask\n",
			    &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [refguard] create firewall_address __diag_refaddr\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [refguard] create __diag_refaddr (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
		ipc_resp_free(&resp);
		return;
	}
	ipc_resp_free(&resp);

	/* 2. Create firewall_policy:99 referencing __diag_refaddr */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_policy:99\n"
			    "name=__diag_refpol\n"
			    "srcaddr=__diag_refaddr\n"
			    "dstaddr=all\n"
			    "srcintf=any\n"
			    "dstintf=any\n"
			    "action=deny\n"
			    "service=all\n"
			    "schedule=all\n"
			    "status=enable\n",
			    &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [refguard] create firewall_policy:99"
		       " with srcaddr=__diag_refaddr\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [refguard] create policy:99 (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
		ipc_resp_free(&resp);
		goto cleanup;
	}
	ipc_resp_free(&resp);

	/* 3. Delete __diag_refaddr → expect SG_ERR_IN_USE */
	ipc_check("delete referenced __diag_refaddr -> IN_USE",
		  SG_CMD_CFG_DEL,
		  "firewall_address:__diag_refaddr",
		  SG_ERR_IN_USE);

	/* 4. Delete policy:99 → expect SG_OK */
	ipc_check("delete referencing policy:99 -> OK",
		  SG_CMD_CFG_DEL,
		  "firewall_policy:99",
		  SG_OK);

	/* 5. Delete __diag_refaddr → now expect SG_OK */
	ipc_check("delete unreferenced __diag_refaddr -> OK",
		  SG_CMD_CFG_DEL,
		  "firewall_address:__diag_refaddr",
		  SG_OK);

	return;

cleanup:
	/* Best-effort cleanup on early exit */
	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "firewall_policy:99", &resp) == 0)
		ipc_resp_free(&resp);
	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "firewall_address:__diag_refaddr", &resp) == 0)
		ipc_resp_free(&resp);
}

/* ── Section 29: IPC firewall_service CRUD (full mode) ────────────────── */

static void test_ipc_cfg_service_roundtrip(void)
{
	struct ipc_response resp;
	int conn;
	const char *test_section = "firewall_service:__diag_svctest";

	printf(C_CYAN "\n  --- IPC: firewall_service CRUD round-trip ---"
	       C_NC "\n");

	/* 1. Create entry */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_service:__diag_svctest\n"
			    "name=__diag_svctest\n"
			    "protocol=tcp\n"
			    "port-range=8080\n",
			    &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/200] create firewall_service __diag_svctest\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/200] create __diag_svctest (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
		ipc_resp_free(&resp);
		return;
	}
	ipc_resp_free(&resp);

	/* 2. Read back */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET, test_section, &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "protocol=tcp") &&
	    strstr(resp.payload, "port-range=8080")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/100] read back __diag_svctest (data matches)\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/100] read back __diag_svctest (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* 3. Idempotent overwrite with different port */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_service:__diag_svctest\n"
			    "name=__diag_svctest\n"
			    "protocol=tcp\n"
			    "port-range=9090\n",
			    &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/200] overwrite __diag_svctest (idempotent)\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/200] overwrite __diag_svctest (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* 4. Verify overwrite */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET, test_section, &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "port-range=9090")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/100] overwrite verified (port-range=9090)\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/100] overwrite data mismatch (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* 5. Delete */
	ipc_check("delete __diag_svctest",
		  SG_CMD_CFG_DEL, test_section, SG_OK);
}

/* ── Section 30: IPC network_nat CRUD (full mode) ────────────────────── */

static void test_ipc_cfg_nat_roundtrip(void)
{
	struct ipc_response resp;
	int conn;
	const char *test_section = "network_nat:__diag_nattest";

	printf(C_CYAN "\n  --- IPC: network_nat CRUD round-trip ---"
	       C_NC "\n");

	/* 1. Create entry */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "network_nat:__diag_nattest\n"
			    "type=dnat\n"
			    "protocol=tcp\n"
			    "srcaddr=any\n"
			    "dstaddr=10.0.0.0/24\n"
			    "mapped-ip=192.168.1.100\n"
			    "dstport=443\n"
			    "mapped-port=8443\n"
			    "srcintf=any\n"
			    "dstintf=any\n"
			    "status=enable\n",
			    &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/200] create network_nat __diag_nattest\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/200] create __diag_nattest (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
		ipc_resp_free(&resp);
		return;
	}
	ipc_resp_free(&resp);

	/* 2. Read back */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET, test_section, &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "type=dnat") &&
	    strstr(resp.payload, "mapped-ip=192.168.1.100") &&
	    strstr(resp.payload, "dstport=443")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/100] read back __diag_nattest (data matches)\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/100] read back __diag_nattest (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* 3. Delete */
	ipc_check("delete __diag_nattest",
		  SG_CMD_CFG_DEL, test_section, SG_OK);
}

/* ── Section 31: IPC entry ID type enforcement (full mode) ────────────── */

static void test_ipc_entry_id_enforcement(void)
{
	printf(C_CYAN "\n  --- IPC: entry ID type enforcement ---"
	       C_NC "\n");

	/* firewall_policy with non-uint ID "abc" */
	ipc_check("firewall_policy with ID 'abc' (not uint)",
		  SG_CMD_CFG_SET,
		  "firewall_policy:abc\nname=test\naction=deny\n",
		  SG_ERR_INVALID_ARG);

	/* firewall_policy with injection ID "../etc" */
	ipc_check("firewall_policy with ID '../etc' (injection)",
		  SG_CMD_CFG_SET,
		  "firewall_policy:../etc\nname=test\naction=deny\n",
		  SG_ERR_INVALID_ARG);

	/* firewall_address with colon ID "a:b" */
	ipc_check("firewall_address with ID 'a:b' (colon)",
		  SG_CMD_CFG_SET,
		  "firewall_address:a:b\nname=test\ntype=ipmask\n",
		  SG_ERR_INVALID_ARG);

	/* firewall_service with semicolon ID "a;rm" */
	ipc_check("firewall_service with ID 'a;rm' (semicolon)",
		  SG_CMD_CFG_SET,
		  "firewall_service:a;rm\nname=test\nprotocol=tcp\n",
		  SG_ERR_INVALID_ARG);
}

/* ── Section 32: IPC server-side CFG_SET data validation (full mode) ── */

static void test_ipc_cfg_set_validation(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- IPC: CFG_SET server-side data validation ---"
	       C_NC "\n");

	/*
	 * 1. Unknown key — mgmtd must reject keys not in the field_table.
	 *    "bogus_field" is not a valid key for firewall_address.
	 */
	ipc_check("reject unknown key 'bogus_field'",
		  SG_CMD_CFG_SET,
		  "firewall_address:__diag_valtest\n"
		  "name=__diag_valtest\n"
		  "subnet=10.0.0.0/8\n"
		  "type=ipmask\n"
		  "bogus_field=injected\n",
		  SG_ERR_INVALID_ARG);

	/*
	 * 2. Bad CIDR value — subnet field requires valid CIDR notation.
	 */
	ipc_check("reject invalid CIDR 'not-a-cidr'",
		  SG_CMD_CFG_SET,
		  "firewall_address:__diag_valtest\n"
		  "name=__diag_valtest\n"
		  "subnet=not-a-cidr\n"
		  "type=ipmask\n",
		  SG_ERR_INVALID_VAL);

	/*
	 * 3. Bad enum value — type field must be one of ipmask,iprange,fqdn.
	 */
	ipc_check("reject invalid enum 'badtype'",
		  SG_CMD_CFG_SET,
		  "firewall_address:__diag_valtest\n"
		  "name=__diag_valtest\n"
		  "subnet=10.0.0.0/8\n"
		  "type=badtype\n",
		  SG_ERR_INVALID_VAL);

	/*
	 * 4. Missing required field — firewall_address requires name, subnet, type.
	 *    Omit 'subnet' to trigger MISSING_ARG.
	 */
	ipc_check("reject missing required field 'subnet'",
		  SG_CMD_CFG_SET,
		  "firewall_address:__diag_valtest\n"
		  "name=__diag_valtest\n"
		  "type=ipmask\n",
		  SG_ERR_MISSING_ARG);

	/*
	 * 5. Bad IPv4 value — network_route_static gateway must be valid IPv4.
	 */
	ipc_check("reject invalid IPv4 gateway '999.999.999.999'",
		  SG_CMD_CFG_SET,
		  "network_route_static:__diag_valtest\n"
		  "dst=10.0.0.0/8\n"
		  "gateway=999.999.999.999\n"
		  "device=eth0\n"
		  "distance=10\n"
		  "status=enable\n",
		  SG_ERR_INVALID_VAL);

	/*
	 * 6. Bad uint range — distance must be 1-255.
	 */
	ipc_check("reject out-of-range uint distance=999",
		  SG_CMD_CFG_SET,
		  "network_route_static:__diag_valtest\n"
		  "dst=10.0.0.0/8\n"
		  "gateway=10.0.0.1\n"
		  "device=eth0\n"
		  "distance=999\n"
		  "status=enable\n",
		  SG_ERR_INVALID_VAL);

	/*
	 * 7. Bad uint value — distance with non-numeric string.
	 */
	ipc_check("reject non-numeric uint distance=abc",
		  SG_CMD_CFG_SET,
		  "network_route_static:__diag_valtest\n"
		  "dst=10.0.0.0/8\n"
		  "gateway=10.0.0.1\n"
		  "device=eth0\n"
		  "distance=abc\n"
		  "status=enable\n",
		  SG_ERR_INVALID_VAL);

	/*
	 * 8. Bad safe-id value — name field with shell metacharacters.
	 */
	ipc_check("reject unsafe safe-id name='$(rm -rf /)'",
		  SG_CMD_CFG_SET,
		  "firewall_address:__diag_valtest\n"
		  "name=$(rm -rf /)\n"
		  "subnet=10.0.0.0/8\n"
		  "type=ipmask\n",
		  SG_ERR_INVALID_VAL);

	/*
	 * 9. Bad port-or-range — firewall_service port-range must be valid.
	 */
	ipc_check("reject invalid port-range 'abc'",
		  SG_CMD_CFG_SET,
		  "firewall_service:__diag_valtest\n"
		  "name=__diag_valtest\n"
		  "protocol=tcp\n"
		  "port-range=abc\n",
		  SG_ERR_INVALID_VAL);

	/*
	 * 10. Bad permissions-csv — admin-profile permissions must be valid.
	 */
	ipc_check("reject invalid permissions-csv 'root,sudo'",
		  SG_CMD_CFG_SET,
		  "system_admin-profile:__diag_valtest\n"
		  "permissions=root,sudo\n",
		  SG_ERR_INVALID_VAL);

	/*
	 * 11. Positive test — valid payload must be accepted.
	 *     Create, verify, then clean up.
	 */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_address:__diag_valtest\n"
			    "name=__diag_valtest\n"
			    "subnet=10.0.0.0/8\n"
			    "type=ipmask\n",
			    &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/200] valid payload accepted\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/200] valid payload rejected (status=%u",
		       conn < 0 ? 999 : resp.status);
		if (resp.extra[0])
			printf(": %s", resp.extra);
		printf(")\n");
	}
	ipc_resp_free(&resp);

	/* Verify it was actually persisted */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "firewall_address:__diag_valtest", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "subnet=10.0.0.0/8")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/100] valid entry persisted to DB\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/100] valid entry not in DB (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/*
	 * 12. Verify rejected payloads were NOT persisted.
	 *     The unknown-key test used __diag_valtest — the valid test
	 *     above overwrote it with good data.  Send a bad payload now
	 *     and confirm the DB still has the old valid data.
	 */
	(void)ipc_send_str(SG_CMD_CFG_SET,
			   "firewall_address:__diag_valtest\n"
			   "name=__diag_valtest\n"
			   "subnet=GARBAGE\n"
			   "type=ipmask\n",
			   &resp);
	ipc_resp_free(&resp);

	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "firewall_address:__diag_valtest", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "subnet=10.0.0.0/8") &&
	    !strstr(resp.payload, "GARBAGE")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/100] rejected data not persisted"
		       " (DB unchanged)\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/100] rejected data leaked into DB\n");
	}
	ipc_resp_free(&resp);

	/*
	 * 13. Overlong key name (>= 64 bytes) — must be rejected.
	 */
	ipc_check("reject overlong key name (64+ bytes)",
		  SG_CMD_CFG_SET,
		  "firewall_address:__diag_valtest\n"
		  "name=__diag_valtest\n"
		  "subnet=10.0.0.0/8\n"
		  "type=ipmask\n"
		  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		  "aaaaaaaaaaaaaaaaaaaaaaaaa=overflow\n",
		  SG_ERR_INVALID_ARG);

	/*
	 * 14. Long value (600 bytes) — accepted; value limit is
	 *     SG_PAYLOAD_MAX (4096), not 512, to allow long comments.
	 */
	{
		char big[1024];
		const char *pfx = "firewall_address:__diag_valtest\n"
				  "name=__diag_valtest\n"
				  "subnet=10.0.0.0/8\n"
				  "type=ipmask\n"
				  "comment=";
		size_t plen = strlen(pfx);
		memcpy(big, pfx, plen);
		memset(big + plen, 'x', 600);
		big[plen + 600] = '\n';
		big[plen + 601] = '\0';

		ipc_check("accept long value (600 bytes)",
			  SG_CMD_CFG_SET, big, SG_OK);
	}

	/*
	 * 15. Builtin injection — client sends builtin=yes on a
	 *     non-builtin entry.  The flag must NOT be persisted.
	 */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_address:__diag_valtest\n"
			    "name=__diag_valtest\n"
			    "subnet=10.0.0.0/8\n"
			    "type=ipmask\n"
			    "builtin=yes\n",
			    &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/200] CFG_SET with builtin=yes accepted"
		       " (flag stripped)\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/200] CFG_SET with builtin=yes (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* Verify builtin=yes was NOT stored */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "firewall_address:__diag_valtest", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    !strstr(resp.payload, "builtin=yes")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/100] builtin=yes not in DB"
		       " (injection blocked)\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/100] builtin=yes leaked into DB\n");
	}
	ipc_resp_free(&resp);

	/*
	 * 16. Builtin preservation — updating a builtin entry must
	 *     retain builtin=yes even if the client doesn't send it.
	 *     Use system_admin-profile:read-write (seeded as builtin).
	 */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "system_admin-profile:read-write\n"
			    "permissions=monitor,configure,admin\n"
			    "description=Full administrative access\n",
			    &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/200] update builtin profile accepted\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/200] update builtin profile (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* Profile update triggers session tag purge for all admins
	 * using this profile.  Re-acquire tag to continue testing. */
	ipc_reacquire_tag();

	/* Verify builtin=yes was preserved */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "system_admin-profile:read-write", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "builtin=yes")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [IPC/100] builtin=yes preserved after update\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [IPC/100] builtin=yes lost after update\n");
	}
	ipc_resp_free(&resp);

	/*
	 * 17. Near-max payload — verify that a payload at exactly
	 *     SG_PAYLOAD_MAX bytes is accepted without truncation.
	 *     The clean-buffer overflow guard is defense-in-depth;
	 *     it cannot trigger through normal IPC because the data
	 *     portion (after the section line) is always smaller than
	 *     the clean[] buffer (both are SG_PAYLOAD_MAX).
	 */
	{
		/* Section header + required fields consume ~91 bytes.
		 * Fill comment= to push total to exactly SG_PAYLOAD_MAX. */
		char huge[SG_PAYLOAD_MAX + 1];
		const char *pfx = "firewall_address:__diag_valtest\n"
				  "name=__diag_valtest\n"
				  "subnet=10.0.0.0/8\n"
				  "type=ipmask\n"
				  "comment=";
		size_t plen = strlen(pfx);
		memcpy(huge, pfx, plen);
		/* fill + trailing newline = SG_PAYLOAD_MAX - plen */
		size_t fill = SG_PAYLOAD_MAX - plen - 1;
		memset(huge + plen, 'A', fill);
		huge[plen + fill] = '\n';
		huge[plen + fill + 1] = '\0';

		ipc_check("accept near-max payload (no truncation at boundary)",
			  SG_CMD_CFG_SET, huge, SG_OK);
	}

	/* Cleanup */
	ipc_send_str(SG_CMD_CFG_DEL,
		     "firewall_address:__diag_valtest", &resp);
	ipc_resp_free(&resp);
	ipc_send_str(SG_CMD_CFG_DEL,
		     "network_route_static:__diag_valtest", &resp);
	ipc_resp_free(&resp);
	ipc_send_str(SG_CMD_CFG_DEL,
		     "firewall_service:__diag_valtest", &resp);
	ipc_resp_free(&resp);
	ipc_send_str(SG_CMD_CFG_DEL,
		     "system_admin-profile:__diag_valtest", &resp);
	ipc_resp_free(&resp);
}

/* ── Section 33: cmd_table integrity (X-macro arg validation) ─────────── */

static void test_cmd_table_integrity(void)
{
	const char *perms = "monitor,configure,admin";

	printf(C_CYAN "\n  --- cmd_table integrity (arg validation) ---"
	       C_NC "\n");

	/* exit/logout return 1 on success — arg validation makes them
	 * return 0 when extra args are supplied. */
	tc_check("cmd-tbl", "exit returns 1 normally",
		 cmd_dispatch("exit", perms), 1);
	tc_check("cmd-tbl", "exit blocked with extra arg",
		 cmd_dispatch("exit hello", perms), 0);
	tc_check("cmd-tbl", "logout returns 1 normally",
		 cmd_dispatch("logout", perms), 1);
	tc_check("cmd-tbl", "logout blocked with extra arg",
		 cmd_dispatch("logout world", perms), 0);

	/* max_args=0 commands: extra args must be rejected */
	tc_check("cmd-tbl", "help blocked with extra arg",
		 cmd_dispatch("help extra", perms), 0);
	tc_check("cmd-tbl", "show status blocked with extra",
		 cmd_dispatch("show status hello", perms), 0);
	tc_check("cmd-tbl", "show interfaces blocked with extra",
		 cmd_dispatch("show interfaces hello", perms), 0);
	tc_check("cmd-tbl", "show routes blocked with extra",
		 cmd_dispatch("show routes extra", perms), 0);
	tc_check("cmd-tbl", "show config blocked with extra",
		 cmd_dispatch("show config extra", perms), 0);
	tc_check("cmd-tbl", "show firmware blocked with extra",
		 cmd_dispatch("show firmware extra", perms), 0);
	tc_check("cmd-tbl", "execute debug enable blocked with extra",
		 cmd_dispatch("execute debug enable extra", perms), 0);
	tc_check("cmd-tbl", "execute debug disable blocked with extra",
		 cmd_dispatch("execute debug disable extra", perms), 0);
	tc_check("cmd-tbl", "execute debug reset blocked with extra",
		 cmd_dispatch("execute debug reset extra", perms), 0);

	/* Auto-usage prefix: 'show' alone prints subcommands, returns 0 */
	tc_check("cmd-tbl", "show auto-usage (0 args, no handler)",
		 cmd_dispatch("show", perms), 0);
}

/* ── Section 34: cmd_table arg limits ─────────────────────────────────── */

static void test_cmd_arg_limits(void)
{
	const char *perms = "monitor,configure,admin";

	printf(C_CYAN "\n  --- cmd_table arg limits ---" C_NC "\n");

	/*
	 * Only test the "blocked" path (too many args) — these are safe
	 * because cmd_validate_args rejects before the handler runs.
	 * The "within-limit" path can't be tested via cmd_dispatch
	 * because it would actually execute the command (ping, arping,
	 * etc.), blocking or causing side effects.
	 *
	 * The exit/logout tests in test_cmd_table_integrity prove the
	 * validation gate works (return value changes from 1 to 0).
	 */

	/* execute ping: max_args=1, reject at 2 */
	tc_check("arg-lim", "ping: 2 args blocked",
		 cmd_dispatch("execute ping 8.8.8.8 extra", perms), 0);

	/* execute traceroute: max_args=1, reject at 2 */
	tc_check("arg-lim", "traceroute: 2 args blocked",
		 cmd_dispatch("execute traceroute 8.8.8.8 extra", perms), 0);

	/* execute nslookup: max_args=1, reject at 2 */
	tc_check("arg-lim", "nslookup: 2 args blocked",
		 cmd_dispatch("execute nslookup google.com extra", perms), 0);

	/* execute arping: max_args=2, reject at 3 */
	tc_check("arg-lim", "arping: 3 args blocked",
		 cmd_dispatch("execute arping 10.0.0.1 eth0 extra", perms), 0);

	/* execute debug option: max_args=2, reject at 3 */
	tc_check("arg-lim", "debug option: 3 args blocked",
		 cmd_dispatch("execute debug option timestamp on extra", perms), 0);

	/* execute diagnose top: max_args=2, reject at 3
	 * (within-limit dispatches to the interactive handler, so only
	 * test the rejection path here) */
	tc_check("arg-lim", "diagnose top: 3 args blocked",
		 cmd_dispatch("execute diagnose top 1 20 extra", perms), 0);

	/* execute diagnose resources: max_args=1, reject at 2 */
	tc_check("arg-lim", "diagnose resources: 2 args blocked",
		 cmd_dispatch("execute diagnose resources cpu extra", perms), 0);

	/* execute firmware upgrade: max_args=1, reject at 2 */
	tc_check("arg-lim", "firmware upgrade: 2 args blocked",
		 cmd_dispatch("execute firmware upgrade http://x extra", perms), 0);

	/* execute debug cli: max_args=1, reject at 2 */
	tc_check("arg-lim", "debug cli: 2 args blocked",
		 cmd_dispatch("execute debug cli on extra", perms), 0);

	/* execute debug flow trace: max_args=4, reject at 5 */
	tc_check("arg-lim", "debug flow trace: 5 args blocked",
		 cmd_dispatch("execute debug flow trace limit 100 extra extra extra", perms), 0);
}

/* ── Section 35: IPC schema version (DB migration) ────────────────────── */

static void test_ipc_schema_version(void)
{
	struct ipc_response resp;
	int conn;
	const char *test_section = "firewall_address:__diag_schematest";

	printf(C_CYAN "\n  --- IPC: DB schema migration verification ---"
	       C_NC "\n");

	/* 1. mgmtd is alive — proves schema was applied at startup */
	ipc_check("PING mgmtd (schema applied at startup)",
		  SG_CMD_PING, "", SG_OK);

	/* 2. Create entry via CFG_SET — exercises INSERT on migrated schema */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_address:__diag_schematest\n"
			    "name=__diag_schematest\n"
			    "subnet=10.77.77.0/24\n"
			    "type=ipmask\n",
			    &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [schema] create __diag_schematest (INSERT OK)\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [schema] create __diag_schematest (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
		ipc_resp_free(&resp);
		return;
	}
	ipc_resp_free(&resp);

	/* 3. Read back — exercises SELECT on migrated schema */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET, test_section, &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "subnet=10.77.77.0/24")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [schema] read __diag_schematest (SELECT OK)\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [schema] read __diag_schematest (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* 4. Delete — exercises DELETE on migrated schema */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_DEL, test_section, &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [schema] delete __diag_schematest (DELETE OK)\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [schema] delete __diag_schematest (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* 5. Confirm gone — verify schema supports NOT_FOUND properly */
	ipc_check("confirm __diag_schematest deleted",
		  SG_CMD_CFG_GET, test_section, SG_ERR_ENTRY_NOT_FOUND);
}

/* ── IPC resource cleanup tests ───────────────────────────────────────── */

static void test_ipc_resource_cleanup(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- IPC: resource cleanup ---" C_NC "\n");

	/* 1. Rapid IPC calls — catches fd/connection leaks (EMFILE) */
	tc_total++;
	{
		int ok = 1;
		for (int i = 0; i < 50; i++) {
			conn = ipc_send_str(SG_CMD_PING, "", &resp);
			ipc_resp_free(&resp);
			if (conn != 0) {
				ok = 0;
				printf(C_RED "  FAIL" C_NC
				       " [resource] rapid IPC #%d failed"
				       " (fd leak?)\n", i + 1);
				break;
			}
		}
		if (ok) {
			tc_pass++;
			printf(C_GREEN "  PASS" C_NC
			       " [resource] 50 rapid IPC calls"
			       " (no fd leak)\n");
		}
	}

	/* 2. Unknown opcode — exercises error-status cleanup path */
	tc_total++;
	conn = ipc_send(0xFFFF, NULL, 0, &resp);
	if (conn == 0 && resp.status != SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [resource] unknown opcode returns error"
		       " (status=%u)\n", resp.status);
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [resource] unknown opcode: conn=%d status=%u\n",
		       conn, conn == 0 ? resp.status : 0);
	}
	ipc_resp_free(&resp);

	/* 3. Double ipc_resp_free — validates idempotent free safety */
	tc_total++;
	conn = ipc_send_str(SG_CMD_PING, "", &resp);
	ipc_resp_free(&resp);
	ipc_resp_free(&resp);  /* second free must not crash */
	if (conn == 0) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [resource] double ipc_resp_free is safe\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [resource] double free test: conn=%d\n", conn);
	}

	/* 4. Mixed success/error cycles — real-world workload stability */
	tc_total++;
	{
		int ok = 1;
		for (int i = 0; i < 20; i++) {
			if (i % 2 == 0) {
				/* Success path: PING */
				conn = ipc_send_str(SG_CMD_PING, "", &resp);
			} else {
				/* Error path: GET non-existent entry */
				conn = ipc_send_str(SG_CMD_CFG_GET,
						    "firewall_address:"
						    "__diag_nonexist",
						    &resp);
			}
			ipc_resp_free(&resp);
			if (conn != 0) {
				ok = 0;
				printf(C_RED "  FAIL" C_NC
				       " [resource] mixed cycle #%d failed\n",
				       i + 1);
				break;
			}
		}
		if (ok) {
			tc_pass++;
			printf(C_GREEN "  PASS" C_NC
			       " [resource] 20 mixed success/error cycles"
			       " stable\n");
		}
	}
}

/* ── Reference object system tests ──────────────────────────────────────── */

/*
 * test_ipc_ref_object — 5-scenario reference lifecycle test.
 *
 * Creates objects A (address), B (policy referencing A), C (address).
 * Tests: resolve, delete protection, delete referrer, cascade, re-reference.
 */
static void test_ipc_ref_object(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- IPC: reference object lifecycle ---" C_NC "\n");

	/* ── Test 1: Resolve — B references A ── */

	/* 1. Create A */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_address:__diag_addrA\n"
			    "name=__diag_addrA\n"
			    "subnet=10.50.0.0/24\n"
			    "type=ipmask\n",
			    &resp);
	if (conn < 0 || resp.status != SG_OK) {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC " [ref-obj] create addrA (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
		ipc_resp_free(&resp);
		return;
	}
	tc_pass++;
	printf(C_GREEN "  PASS" C_NC " [ref-obj] create addrA\n");
	ipc_resp_free(&resp);

	/* 2. Create B referencing A */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_policy:98\n"
			    "name=__diag_refpol\n"
			    "srcaddr=__diag_addrA\n"
			    "dstaddr=all\n"
			    "srcintf=any\n"
			    "dstintf=any\n"
			    "action=deny\n"
			    "service=all\n"
			    "status=enable\n",
			    &resp);
	if (conn < 0 || resp.status != SG_OK) {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [ref-obj] create policy:98 with srcaddr=addrA"
		       " (status=%u: %s)\n",
		       conn < 0 ? 999 : resp.status,
		       resp.extra[0] ? resp.extra : "");
		ipc_resp_free(&resp);
		goto cleanup;
	}
	tc_pass++;
	printf(C_GREEN "  PASS" C_NC
	       " [ref-obj] create policy:98 with srcaddr=__diag_addrA\n");
	ipc_resp_free(&resp);

	/* 3. Verify A's data intact */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "firewall_address:__diag_addrA", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "subnet=10.50.0.0/24")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [ref-obj] addrA subnet=10.50.0.0/24 intact\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [ref-obj] addrA data check failed\n");
	}
	ipc_resp_free(&resp);

	/* 4. Verify B stores the reference */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "firewall_policy:98", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "srcaddr=__diag_addrA")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [ref-obj] policy:98 srcaddr=__diag_addrA stored\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [ref-obj] policy:98 srcaddr check failed\n");
	}
	ipc_resp_free(&resp);

	/* ── Test 2: Delete referenced A → expect deny ── */

	ipc_check("delete referenced addrA -> IN_USE",
		  SG_CMD_CFG_DEL,
		  "firewall_address:__diag_addrA",
		  SG_ERR_IN_USE);

	/* Verify A still exists */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "firewall_address:__diag_addrA", &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [ref-obj] addrA still exists after blocked delete\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [ref-obj] addrA missing after blocked delete\n");
	}
	ipc_resp_free(&resp);

	/* ── Test 3: Delete referrer B → expect accept ── */

	ipc_check("delete referrer policy:98 -> OK",
		  SG_CMD_CFG_DEL,
		  "firewall_policy:98",
		  SG_OK);

	/* Verify A still exists and unchanged */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "firewall_address:__diag_addrA", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "subnet=10.50.0.0/24")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [ref-obj] addrA unchanged after referrer deleted\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [ref-obj] addrA data changed after referrer deleted\n");
	}
	ipc_resp_free(&resp);

	/* ── Test 4: Change A's subnet, cascade re-apply B ── */

	/* Re-create B */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_policy:98\n"
			    "name=__diag_refpol\n"
			    "srcaddr=__diag_addrA\n"
			    "dstaddr=all\n"
			    "srcintf=any\n"
			    "dstintf=any\n"
			    "action=deny\n"
			    "service=all\n"
			    "status=enable\n",
			    &resp);
	if (conn < 0 || resp.status != SG_OK) {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [ref-obj] re-create policy:98 (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
		ipc_resp_free(&resp);
		goto cleanup;
	}
	tc_pass++;
	printf(C_GREEN "  PASS" C_NC " [ref-obj] re-create policy:98\n");
	ipc_resp_free(&resp);

	/* Update A's subnet (triggers usage_cascade → firewall rebuild) */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_address:__diag_addrA\n"
			    "name=__diag_addrA\n"
			    "subnet=10.60.0.0/24\n"
			    "type=ipmask\n",
			    &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [ref-obj] update addrA subnet (cascade triggered)\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [ref-obj] update addrA subnet (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* Verify A changed */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "firewall_address:__diag_addrA", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "subnet=10.60.0.0/24")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [ref-obj] addrA subnet=10.60.0.0/24 updated\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [ref-obj] addrA subnet not updated\n");
	}
	ipc_resp_free(&resp);

	/* Verify B still references A by name */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "firewall_policy:98", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "srcaddr=__diag_addrA")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [ref-obj] policy:98 still refs addrA after cascade\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [ref-obj] policy:98 ref lost after cascade\n");
	}
	ipc_resp_free(&resp);

	/* ── Test 5: B re-references from A to C — A unchanged ── */

	/* Create C */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_address:__diag_addrC\n"
			    "name=__diag_addrC\n"
			    "subnet=172.20.0.0/16\n"
			    "type=ipmask\n",
			    &resp);
	if (conn < 0 || resp.status != SG_OK) {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC " [ref-obj] create addrC (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
		ipc_resp_free(&resp);
		goto cleanup;
	}
	tc_pass++;
	printf(C_GREEN "  PASS" C_NC " [ref-obj] create addrC\n");
	ipc_resp_free(&resp);

	/* Update B: srcaddr → addrC */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_policy:98\n"
			    "name=__diag_refpol\n"
			    "srcaddr=__diag_addrC\n"
			    "dstaddr=all\n"
			    "srcintf=any\n"
			    "dstintf=any\n"
			    "action=deny\n"
			    "service=all\n"
			    "status=enable\n",
			    &resp);
	if (conn == 0 && resp.status == SG_OK) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [ref-obj] policy:98 re-ref to addrC\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [ref-obj] policy:98 re-ref failed (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
	}
	ipc_resp_free(&resp);

	/* Verify A unchanged */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "firewall_address:__diag_addrA", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "subnet=10.60.0.0/24")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [ref-obj] addrA unchanged after re-reference\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [ref-obj] addrA modified by re-reference\n");
	}
	ipc_resp_free(&resp);

	/* Verify B now references C */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "firewall_policy:98", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "srcaddr=__diag_addrC")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [ref-obj] policy:98 now refs addrC\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [ref-obj] policy:98 srcaddr not updated to addrC\n");
	}
	ipc_resp_free(&resp);

	/* Verify C intact */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "firewall_address:__diag_addrC", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "subnet=172.20.0.0/16")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [ref-obj] addrC subnet=172.20.0.0/16 intact\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [ref-obj] addrC data corrupted\n");
	}
	ipc_resp_free(&resp);

cleanup:
	if (ipc_send_str(SG_CMD_CFG_DEL, "firewall_policy:98", &resp) == 0)
		ipc_resp_free(&resp);
	if (ipc_send_str(SG_CMD_CFG_DEL, "firewall_address:__diag_addrA",
			 &resp) == 0)
		ipc_resp_free(&resp);
	if (ipc_send_str(SG_CMD_CFG_DEL, "firewall_address:__diag_addrC",
			 &resp) == 0)
		ipc_resp_free(&resp);
}

/*
 * test_ipc_ref_existence — Server-side reference existence validation.
 * Reject nonexistent references; accept builtin "all" object.
 */
static void test_ipc_ref_existence(void)
{
	printf(C_CYAN "\n  --- IPC: reference existence validation ---"
	       C_NC "\n");

	/* CFG_SET with nonexistent address → SG_ERR_NOT_FOUND */
	ipc_check("CFG_SET policy with nonexistent srcaddr -> NOT_FOUND",
		  SG_CMD_CFG_SET,
		  "firewall_policy:97\n"
		  "name=__diag_badref\n"
		  "srcaddr=__nonexistent_addr\n"
		  "dstaddr=all\n"
		  "srcintf=any\n"
		  "dstintf=any\n"
		  "action=deny\n"
		  "service=all\n"
		  "status=enable\n",
		  SG_ERR_NOT_FOUND);

	/* CFG_APPLY with nonexistent address → SG_ERR_NOT_FOUND */
	ipc_check("CFG_APPLY policy with nonexistent srcaddr -> NOT_FOUND",
		  SG_CMD_CFG_APPLY,
		  "firewall_policy\n97\n"
		  "name=__diag_badref\n"
		  "srcaddr=__nonexistent_addr\n"
		  "dstaddr=all\n"
		  "srcintf=any\n"
		  "dstintf=any\n"
		  "action=deny\n"
		  "service=all\n"
		  "status=enable\n",
		  SG_ERR_NOT_FOUND);

	/* CFG_SET with builtin "all" → SG_OK */
	ipc_check("CFG_SET policy with srcaddr=all (builtin) -> OK",
		  SG_CMD_CFG_SET,
		  "firewall_policy:97\n"
		  "name=__diag_allref\n"
		  "srcaddr=all\n"
		  "dstaddr=all\n"
		  "srcintf=any\n"
		  "dstintf=any\n"
		  "action=deny\n"
		  "service=all\n"
		  "status=enable\n",
		  SG_OK);

	/* NAT with nonexistent address → SG_ERR_NOT_FOUND */
	ipc_check("CFG_SET NAT with nonexistent srcaddr -> NOT_FOUND",
		  SG_CMD_CFG_SET,
		  "network_nat:__diag_natexist\n"
		  "type=snat\n"
		  "srcintf=any\n"
		  "dstintf=eth0\n"
		  "srcaddr=__nonexistent_addr\n"
		  "dstaddr=all\n"
		  "status=enable\n",
		  SG_ERR_NOT_FOUND);

	/* NAT with raw CIDR → SG_OK (ref-or-cidr accepts CIDR) */
	ipc_check("CFG_SET NAT with raw CIDR srcaddr -> OK",
		  SG_CMD_CFG_SET,
		  "network_nat:__diag_natcidr\n"
		  "type=snat\n"
		  "srcintf=any\n"
		  "dstintf=eth0\n"
		  "srcaddr=192.168.1.0/24\n"
		  "dstaddr=all\n"
		  "status=enable\n",
		  SG_OK);

	/* Cleanup */
	{
		struct ipc_response resp;
		if (ipc_send_str(SG_CMD_CFG_DEL, "firewall_policy:97",
				 &resp) == 0)
			ipc_resp_free(&resp);
		if (ipc_send_str(SG_CMD_CFG_DEL, "network_nat:__diag_natcidr",
				 &resp) == 0)
			ipc_resp_free(&resp);
	}
}

/*
 * test_ipc_immutable — Builtin immutable objects cannot be modified/deleted.
 */
static void test_ipc_immutable(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- IPC: immutable object protection ---"
	       C_NC "\n");

	/* Modify firewall_address:all → SG_ERR_BUILTIN */
	ipc_check("modify immutable address:all -> BUILTIN",
		  SG_CMD_CFG_SET,
		  "firewall_address:all\n"
		  "name=all\n"
		  "subnet=192.168.0.0/16\n"
		  "type=ipmask\n",
		  SG_ERR_BUILTIN);

	/* Delete firewall_address:all → SG_ERR_BUILTIN */
	ipc_check("delete immutable address:all -> BUILTIN",
		  SG_CMD_CFG_DEL,
		  "firewall_address:all",
		  SG_ERR_BUILTIN);

	/* Modify firewall_service:all → SG_ERR_BUILTIN */
	ipc_check("modify immutable service:all -> BUILTIN",
		  SG_CMD_CFG_SET,
		  "firewall_service:all\n"
		  "name=all\n"
		  "protocol=tcp\n",
		  SG_ERR_BUILTIN);

	/* Delete firewall_service:all → SG_ERR_BUILTIN */
	ipc_check("delete immutable service:all -> BUILTIN",
		  SG_CMD_CFG_DEL,
		  "firewall_service:all",
		  SG_ERR_BUILTIN);

	/* Verify address:all data unchanged */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "firewall_address:all", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "subnet=0.0.0.0/0")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [immutable] address:all subnet=0.0.0.0/0 intact\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [immutable] address:all data corrupted\n");
	}
	ipc_resp_free(&resp);

	/* Verify service:all data unchanged */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "firewall_service:all", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "protocol=all")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [immutable] service:all protocol=all intact\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [immutable] service:all data corrupted\n");
	}
	ipc_resp_free(&resp);
}

/*
 * test_ipc_nat_ref — NAT rule referencing a firewall_address object.
 * Tests ref-or-cidr kind and cross-type delete protection.
 */
static void test_ipc_nat_ref(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- IPC: NAT address object reference ---"
	       C_NC "\n");

	/* 1. Create address object */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_address:__diag_nataddr\n"
			    "name=__diag_nataddr\n"
			    "subnet=172.30.0.0/16\n"
			    "type=ipmask\n",
			    &resp);
	if (conn < 0 || resp.status != SG_OK) {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [nat-ref] create nataddr (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
		ipc_resp_free(&resp);
		return;
	}
	tc_pass++;
	printf(C_GREEN "  PASS" C_NC " [nat-ref] create nataddr\n");
	ipc_resp_free(&resp);

	/* 2. Create NAT rule referencing the address */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "network_nat:__diag_natref\n"
			    "type=snat\n"
			    "srcintf=any\n"
			    "dstintf=eth0\n"
			    "srcaddr=__diag_nataddr\n"
			    "dstaddr=all\n"
			    "status=enable\n",
			    &resp);
	if (conn < 0 || resp.status != SG_OK) {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [nat-ref] create NAT with srcaddr=nataddr"
		       " (status=%u: %s)\n",
		       conn < 0 ? 999 : resp.status,
		       resp.extra[0] ? resp.extra : "");
		ipc_resp_free(&resp);
		goto cleanup;
	}
	tc_pass++;
	printf(C_GREEN "  PASS" C_NC
	       " [nat-ref] create NAT with srcaddr=__diag_nataddr\n");
	ipc_resp_free(&resp);

	/* 3. Verify NAT stores the reference */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "network_nat:__diag_natref", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "srcaddr=__diag_nataddr")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [nat-ref] NAT srcaddr=__diag_nataddr stored\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [nat-ref] NAT srcaddr not stored\n");
	}
	ipc_resp_free(&resp);

	/* 4. Delete address → blocked (NAT refs it) */
	ipc_check("delete nataddr referenced by NAT -> IN_USE",
		  SG_CMD_CFG_DEL,
		  "firewall_address:__diag_nataddr",
		  SG_ERR_IN_USE);

	/* 5. Delete NAT → OK */
	ipc_check("delete NAT rule -> OK",
		  SG_CMD_CFG_DEL,
		  "network_nat:__diag_natref",
		  SG_OK);

	/* 6. Delete address → now OK */
	ipc_check("delete unreferenced nataddr -> OK",
		  SG_CMD_CFG_DEL,
		  "firewall_address:__diag_nataddr",
		  SG_OK);

	return;

cleanup:
	if (ipc_send_str(SG_CMD_CFG_DEL, "network_nat:__diag_natref",
			 &resp) == 0)
		ipc_resp_free(&resp);
	if (ipc_send_str(SG_CMD_CFG_DEL, "firewall_address:__diag_nataddr",
			 &resp) == 0)
		ipc_resp_free(&resp);
}

/*
 * test_ipc_service_ref — Service object referenced by firewall policy.
 * Tests ref:firewall_service kind and cross-type delete protection.
 */
static void test_ipc_service_ref(void)
{
	struct ipc_response resp;
	int conn;

	printf(C_CYAN "\n  --- IPC: service object reference ---"
	       C_NC "\n");

	/* 1. Create service object */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_service:__diag_svc\n"
			    "name=__diag_svc\n"
			    "protocol=tcp\n"
			    "port-range=8080\n",
			    &resp);
	if (conn < 0 || resp.status != SG_OK) {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [svc-ref] create service (status=%u)\n",
		       conn < 0 ? 999 : resp.status);
		ipc_resp_free(&resp);
		return;
	}
	tc_pass++;
	printf(C_GREEN "  PASS" C_NC " [svc-ref] create __diag_svc\n");
	ipc_resp_free(&resp);

	/* 2. Create policy referencing the service */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_SET,
			    "firewall_policy:96\n"
			    "name=__diag_svcpol\n"
			    "srcaddr=all\n"
			    "dstaddr=all\n"
			    "srcintf=any\n"
			    "dstintf=any\n"
			    "action=deny\n"
			    "service=__diag_svc\n"
			    "status=enable\n",
			    &resp);
	if (conn < 0 || resp.status != SG_OK) {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [svc-ref] create policy:96 with service=__diag_svc"
		       " (status=%u: %s)\n",
		       conn < 0 ? 999 : resp.status,
		       resp.extra[0] ? resp.extra : "");
		ipc_resp_free(&resp);
		goto cleanup;
	}
	tc_pass++;
	printf(C_GREEN "  PASS" C_NC
	       " [svc-ref] create policy:96 with service=__diag_svc\n");
	ipc_resp_free(&resp);

	/* 3. Verify policy stores the reference */
	tc_total++;
	conn = ipc_send_str(SG_CMD_CFG_GET,
			    "firewall_policy:96", &resp);
	if (conn == 0 && resp.status == SG_OK && resp.payload &&
	    strstr(resp.payload, "service=__diag_svc")) {
		tc_pass++;
		printf(C_GREEN "  PASS" C_NC
		       " [svc-ref] policy:96 service=__diag_svc stored\n");
	} else {
		tc_fail++;
		printf(C_RED "  FAIL" C_NC
		       " [svc-ref] policy:96 service not stored\n");
	}
	ipc_resp_free(&resp);

	/* 4. Delete service → blocked */
	ipc_check("delete service referenced by policy -> IN_USE",
		  SG_CMD_CFG_DEL,
		  "firewall_service:__diag_svc",
		  SG_ERR_IN_USE);

	/* 5. Delete policy → OK */
	ipc_check("delete policy:96 -> OK",
		  SG_CMD_CFG_DEL,
		  "firewall_policy:96",
		  SG_OK);

	/* 6. Delete service → now OK */
	ipc_check("delete unreferenced service -> OK",
		  SG_CMD_CFG_DEL,
		  "firewall_service:__diag_svc",
		  SG_OK);

	return;

cleanup:
	if (ipc_send_str(SG_CMD_CFG_DEL, "firewall_policy:96",
			 &resp) == 0)
		ipc_resp_free(&resp);
	if (ipc_send_str(SG_CMD_CFG_DEL, "firewall_service:__diag_svc",
			 &resp) == 0)
		ipc_resp_free(&resp);
}

/* ── Cleanup helper ───────────────────────────────────────────────────── */

static void cleanup_test_entries(void)
{
	struct ipc_response resp;

	/* Re-acquire tag in case a prior test triggered a session purge */
	ipc_reacquire_tag();

	/* Best-effort cleanup of test entries */
	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "firewall_address:__diag_cfgtest", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted __diag_cfgtest\n");
	ipc_resp_free(&resp);

	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "firewall_policy:99", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted firewall_policy:99\n");
	ipc_resp_free(&resp);

	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "firewall_address:__diag_refaddr", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted __diag_refaddr\n");
	ipc_resp_free(&resp);

	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "firewall_service:__diag_svctest", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted __diag_svctest\n");
	ipc_resp_free(&resp);

	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "network_nat:__diag_nattest", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted __diag_nattest\n");
	ipc_resp_free(&resp);

	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "firewall_address:__diag_schematest", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted __diag_schematest\n");
	ipc_resp_free(&resp);

	/* Reference object test entries */
	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "firewall_policy:98", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted firewall_policy:98\n");
	ipc_resp_free(&resp);

	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "firewall_policy:97", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted firewall_policy:97\n");
	ipc_resp_free(&resp);

	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "firewall_address:__diag_addrA", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted __diag_addrA\n");
	ipc_resp_free(&resp);

	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "firewall_address:__diag_addrC", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted __diag_addrC\n");
	ipc_resp_free(&resp);

	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "network_nat:__diag_natref", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted __diag_natref\n");
	ipc_resp_free(&resp);

	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "network_nat:__diag_natcidr", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted __diag_natcidr\n");
	ipc_resp_free(&resp);

	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "firewall_address:__diag_nataddr", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted __diag_nataddr\n");
	ipc_resp_free(&resp);

	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "firewall_service:__diag_svc", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted __diag_svc\n");
	ipc_resp_free(&resp);

	if (ipc_send_str(SG_CMD_CFG_DEL,
			 "firewall_policy:96", &resp) == 0 &&
	    resp.status == SG_OK)
		printf("  cleanup: deleted firewall_policy:96\n");
	ipc_resp_free(&resp);
}

/* ── Public entry point ───────────────────────────────────────────────── */

int cli_diagnose_test_configure(int mode, diag_result_t *out)
{
	tc_pass  = 0;
	tc_fail  = 0;
	tc_total = 0;

	printf("\n  Stargazer Configuration Validation Diagnostics\n");
	printf("  ===============================================\n");

	/* Basic tests: validator unit tests (no IPC needed) */
	test_safe_id();
	test_ipv4();
	test_cidr();
	test_iface();
	test_uint_range();
	test_tz_token();
	test_permissions_csv();
	test_port_or_range();
	test_csv_option();
	test_entry_id();
	test_registry();
	test_value_validation();
	test_field_desc();
	test_value_quoting();
	test_cmd_resolve();
	test_ref_metadata();
	test_dispatch_table();
	test_cmd_table_integrity();
	test_cmd_arg_limits();
	test_registry_completeness();
	test_default_roundtrip();
	test_boundary_values();
	test_cross_type_keys();

	if (mode == 1) {
		/* Full mode: IPC round-trip tests */
		if (!ipc_available()) {
			printf(C_RED "\n  ERROR" C_NC
			       ": mgmtd socket not found (%s)\n",
			       SG_MGMTD_SOCK);
			printf("  IPC tests skipped."
			       " Start stargazer-mgmtd for full tests.\n");
		} else {
			cleanup_test_entries();
			test_ipc_cfg_reject();
			test_ipc_admin_reject();
			test_ipc_builtin_protect();
			test_ipc_interface_protection();
			test_ipc_roundtrip();
			test_ipc_apply();
			test_ipc_not_found();
			test_ipc_refguard();
			test_ipc_cfg_service_roundtrip();
			test_ipc_cfg_nat_roundtrip();
			test_ipc_entry_id_enforcement();
			test_ipc_cfg_set_validation();
			test_ipc_schema_version();
			test_ipc_resource_cleanup();
			test_ipc_ref_object();
			test_ipc_ref_existence();
			test_ipc_immutable();
			test_ipc_nat_ref();
			test_ipc_service_ref();
			cleanup_test_entries();
		}
	}

	/* Summary */
	printf("\n  Results: %d/%d passed", tc_pass, tc_total);
	if (tc_fail > 0)
		printf(C_RED ", %d FAILED" C_NC, tc_fail);
	else
		printf(C_GREEN " (all passed)" C_NC);
	printf("\n\n");

	if (out) {
		out->passed = tc_pass;
		out->failed = tc_fail;
		out->total  = tc_total;
	}
	return tc_fail > 0 ? 1 : 0;
}
