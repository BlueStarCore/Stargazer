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
	tc_check("val", "network_nat.srcaddr = '10.0.0.0' (plain ipv4 fail)",
		 sg_reg_validate_value("network_nat", "srcaddr", "10.0.0.0"), 0);
	tc_check("val", "network_nat.srcaddr = 'none' (invalid keyword)",
		 sg_reg_validate_value("network_nat", "srcaddr", "none"), 0);

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

	/* SESSION_REV with bad username */
	ipc_check("SESSION_REV username '$var'",
		  SG_CMD_SESSION_REV,
		  "$var",
		  SG_ERR_INVALID_ARG);

	/* SESSION_BUMP with bad username */
	ipc_check("SESSION_BUMP username '`id`'",
		  SG_CMD_SESSION_BUMP,
		  "`id`",
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
			    "ip-forward=enable\n",
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
			    "primary=8.8.8.8\n",
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

	/* sg_reg_find_referencing: firewall_address -> 2 fields */
	{
		sg_ref_entry_t refs[16];
		int n = sg_reg_find_referencing("firewall_address",
						refs, 16);
		tc_check("ref-meta",
			 "firewall_address referenced by 2 fields",
			 n, 2);
		if (n >= 2) {
			tc_str("ref-meta", "ref[0].type = firewall_policy",
			       refs[0].type, "firewall_policy");
			tc_str("ref-meta", "ref[0].key = srcaddr",
			       refs[0].key, "srcaddr");
			tc_str("ref-meta", "ref[1].type = firewall_policy",
			       refs[1].type, "firewall_policy");
			tc_str("ref-meta", "ref[1].key = dstaddr",
			       refs[1].key, "dstaddr");
		}
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

	/* network_dns.port: 1-65535 */
	tc_check("boundary", "network_dns.port = '1' (min)",
		 sg_reg_validate_value("network_dns", "port", "1"), 1);
	tc_check("boundary", "network_dns.port = '65535' (max)",
		 sg_reg_validate_value("network_dns", "port", "65535"), 1);
	tc_check("boundary", "network_dns.port = '0' (below min)",
		 sg_reg_validate_value("network_dns", "port", "0"), 0);
	tc_check("boundary", "network_dns.port = '65536' (above max)",
		 sg_reg_validate_value("network_dns", "port", "65536"), 0);

	/* network_dns.cache-size: 0-100000 */
	tc_check("boundary", "network_dns.cache-size = '0' (min)",
		 sg_reg_validate_value("network_dns", "cache-size", "0"), 1);
	tc_check("boundary", "network_dns.cache-size = '100000' (max)",
		 sg_reg_validate_value("network_dns", "cache-size", "100000"), 1);
	tc_check("boundary", "network_dns.cache-size = '100001' (above max)",
		 sg_reg_validate_value("network_dns", "cache-size", "100001"), 0);

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
			    "name=__diag_nattest\n"
			    "type=dnat\n"
			    "srcaddr=any\n"
			    "dstaddr=10.0.0.0/24\n"
			    "mapped-ip=192.168.1.100\n"
			    "dstport=443\n"
			    "mapped-port=8443\n"
			    "srcintf=any\n"
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

/* ── Cleanup helper ───────────────────────────────────────────────────── */

static void cleanup_test_entries(void)
{
	struct ipc_response resp;

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
}

/* ── Public entry point ───────────────────────────────────────────────── */

int cli_diagnose_test_configure(int mode)
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

	return tc_fail > 0 ? 1 : 0;
}
