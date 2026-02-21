/* SPDX-License-Identifier: MIT */
/*
 * sg_validate.c — Shared config registry and input validators for Stargazer
 *
 * Static tables of config types, valid keys, default values, required
 * fields, and validation rules.  Shared by CLI and mgmtd.
 * Extracted from cli_registry.c.
 */

#define _POSIX_C_SOURCE 200809L

#include "sg_validate.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Type registry ───────────────────────────────────────────────────────── */

struct type_entry {
	const char *name;
	cfg_mode_t  mode;
};

static const struct type_entry type_table[] = {
	{ "network_route_static",   CFG_TABLE  },
	{ "network_route_policy",   CFG_TABLE  },
	{ "network_ospf",           CFG_SINGLE },
	{ "network_rip",            CFG_SINGLE },
	{ "network_bgp",            CFG_SINGLE },
	{ "network_nat",            CFG_TABLE  },
	{ "network_dns",            CFG_SINGLE },
	{ "system_settings",        CFG_SINGLE },
	{ "system_interface",       CFG_TABLE  },
	{ "system_hostname",        CFG_SINGLE },
	{ "system_ntp",             CFG_SINGLE },
	{ "firewall_policy",        CFG_TABLE  },
	{ "firewall_address",       CFG_TABLE  },
	{ "firewall_service",       CFG_TABLE  },
	{ "system_password-policy", CFG_SINGLE },
	{ "system_admin-profile",   CFG_TABLE  },
	{ "system_admin",           CFG_TABLE  },
	{ NULL, 0 }
};

/* ── Valid keys per type ─────────────────────────────────────────────────── */

struct keys_entry {
	const char *type;
	const char *keys;  /* space-separated */
};

static const struct keys_entry keys_table[] = {
	{ "network_route_static",   "dst gateway device distance status comment" },
	{ "network_nat",            "type srcintf dstintf srcaddr dstaddr dstport mapped-ip mapped-port status" },
	{ "system_interface",       "ip status mtu description" },
	{ "system_settings",        "hostname ip-forward timezone" },
	{ "system_hostname",        "hostname" },
	{ "network_dns",            "primary secondary" },
	{ "system_ntp",             "server status" },
	{ "firewall_policy",        "name srcintf dstintf srcaddr dstaddr action service schedule status comment" },
	{ "firewall_address",       "name subnet type comment" },
	{ "firewall_service",       "name protocol port-range comment" },
	{ "system_password-policy", "min-length min-uppercase min-lowercase min-digit min-special" },
	{ "system_admin-profile",   "permissions description" },
	{ "system_admin",           "profile password enforce-change-password enforce-password-policy" },
	{ NULL, NULL }
};

/* ── Required keys per type ──────────────────────────────────────────────── */

struct required_entry {
	const char *type;
	const char *keys;
};

static const struct required_entry required_table[] = {
	{ "network_route_static",   "dst" },
	{ "firewall_policy",        "name srcintf dstintf srcaddr dstaddr action status" },
	{ "firewall_address",       "name subnet type" },
	{ "firewall_service",       "name protocol port-range" },
	{ "system_admin",           "profile" },
	{ "system_admin-profile",   "permissions" },
	{ NULL, NULL }
};

/* ── Default values per type ─────────────────────────────────────────────── */

struct defaults_entry {
	const char *type;
	const char *defaults;  /* "key=val\nkey=val\n..." */
};

static const struct defaults_entry defaults_table[] = {
	{ "firewall_policy",
	  "status=enable\naction=deny\nsrcintf=any\ndstintf=any\nsrcaddr=all\ndstaddr=all" },
	{ "system_admin",
	  "enforce-change-password=enable\nenforce-password-policy=enable" },
	{ "system_interface",
	  "status=up\nmtu=1500" },
	{ "network_route_static",
	  "status=enable\ndistance=10" },
	{ "firewall_address",
	  "type=ipmask" },
	{ "firewall_service",
	  "protocol=tcp" },
	{ "system_password-policy",
	  "min-length=8\nmin-uppercase=0\nmin-lowercase=0\nmin-digit=0\nmin-special=0" },
	{ NULL, NULL }
};

/* ── type:key → kind mapping ─────────────────────────────────────────────── */

struct kind_entry {
	const char *type;
	const char *key;
	const char *kind;
};

static const struct kind_entry kind_table[] = {
	/* cidr */
	{ "network_route_static", "dst",                     "cidr" },
	{ "system_interface",     "ip",                      "cidr" },
	{ "firewall_address",     "subnet",                  "cidr" },

	/* ipv4 */
	{ "network_route_static", "gateway",                 "ipv4" },
	{ "network_nat",          "mapped-ip",               "ipv4" },
	{ "network_dns",          "primary",                 "ipv4" },
	{ "network_dns",          "secondary",               "ipv4" },
	{ "system_ntp",           "server",                  "ipv4" },

	/* iface */
	{ "network_route_static", "device",                  "iface" },
	{ "network_nat",          "srcintf",                 "iface" },
	{ "network_nat",          "dstintf",                 "iface" },
	{ "firewall_policy",      "srcintf",                 "iface" },
	{ "firewall_policy",      "dstintf",                 "iface" },

	/* uint ranges */
	{ "network_route_static",  "distance",               "uint:1:255" },
	{ "system_password-policy","min-length",              "uint:0:128" },
	{ "system_password-policy","min-uppercase",           "uint:0:128" },
	{ "system_password-policy","min-lowercase",           "uint:0:128" },
	{ "system_password-policy","min-digit",               "uint:0:128" },
	{ "system_password-policy","min-special",             "uint:0:128" },
	{ "network_nat",           "dstport",                "uint:1:65535" },
	{ "network_nat",           "mapped-port",            "uint:1:65535" },
	{ "system_interface",      "mtu",                    "uint:576:9200" },

	/* enum */
	{ "network_route_static", "status",                  "enum:enable,disable" },
	{ "network_nat",          "status",                  "enum:enable,disable" },
	{ "system_settings",      "ip-forward",              "enum:enable,disable" },
	{ "system_ntp",           "status",                  "enum:enable,disable" },
	{ "firewall_policy",      "status",                  "enum:enable,disable" },
	{ "system_admin",         "enforce-change-password",  "enum:enable,disable" },
	{ "system_admin",         "enforce-password-policy",  "enum:enable,disable" },
	{ "network_nat",          "type",                    "enum:snat,dnat" },
	{ "system_interface",     "status",                  "enum:up,down" },
	{ "firewall_policy",      "action",                  "enum:accept,deny,drop" },
	{ "firewall_address",     "type",                    "enum:ipmask,iprange,fqdn" },
	{ "firewall_service",     "protocol",                "enum:tcp,udp,icmp" },

	/* cidr-or */
	{ "network_nat",          "srcaddr",                 "cidr-or:any,all" },
	{ "network_nat",          "dstaddr",                 "cidr-or:any,all" },

	/* safe-id */
	{ "system_settings",      "hostname",                "safe-id" },
	{ "system_hostname",      "hostname",                "safe-id" },
	{ "firewall_policy",      "name",                    "safe-id" },
	{ "firewall_address",     "name",                    "safe-id" },
	{ "firewall_service",     "name",                    "safe-id" },

	/* tz-token */
	{ "system_settings",      "timezone",                "tz-token" },

	/* permissions-csv */
	{ "system_admin-profile",  "permissions",            "permissions-csv" },

	/* ref */
	{ "system_admin",          "profile",                "ref:system_admin-profile" },

	/* password-interactive */
	{ "system_admin",          "password",               "password-interactive" },

	/* ref-or */
	{ "firewall_policy",       "srcaddr",                "ref-or:firewall_address:all,any" },
	{ "firewall_policy",       "dstaddr",                "ref-or:firewall_address:all,any" },
	{ "firewall_policy",       "service",                "ref-or:firewall_service:all,any" },

	/* safe-id-or */
	{ "firewall_policy",       "schedule",               "safe-id-or:all,any" },

	/* port-or-range */
	{ "firewall_service",      "port-range",             "port-or-range" },

	{ NULL, NULL, NULL }
};

/* ── Pure validation helpers ─────────────────────────────────────────────── */

int
sg_is_safe_id(const char *s)
{
	if (!s || !*s)
		return 0;
	for (const char *p = s; *p; p++) {
		if (isalnum((unsigned char)*p))
			continue;
		if (*p == '_' || *p == '.' || *p == '-')
			continue;
		return 0;
	}
	return 1;
}

int
sg_is_ipv4(const char *s)
{
	if (!s || !*s)
		return 0;

	int octets = 0;
	const char *p = s;

	while (*p) {
		/* Each octet must start with a digit */
		if (!isdigit((unsigned char)*p))
			return 0;

		long val = 0;
		int digits = 0;
		while (isdigit((unsigned char)*p)) {
			val = val * 10 + (*p - '0');
			digits++;
			if (digits > 3)
				return 0;
			p++;
		}
		if (val > 255)
			return 0;

		octets++;
		if (octets < 4) {
			if (*p != '.')
				return 0;
			p++;
		}
	}
	return octets == 4 && *p == '\0';
}

int
sg_is_cidr(const char *s)
{
	if (!s || !*s)
		return 0;

	/* Find the '/' separator */
	const char *slash = strchr(s, '/');
	if (!slash || slash == s || !*(slash + 1))
		return 0;

	/* Extract IP part */
	size_t ip_len = (size_t)(slash - s);
	if (ip_len >= 64)
		return 0;

	char ip_buf[64];
	memcpy(ip_buf, s, ip_len);
	ip_buf[ip_len] = '\0';

	if (!sg_is_ipv4(ip_buf))
		return 0;

	/* Validate mask */
	return sg_is_uint_range(slash + 1, 0, 32);
}

int
sg_is_iface_name(const char *s)
{
	if (!s || !*s)
		return 0;
	for (const char *p = s; *p; p++) {
		if (isalnum((unsigned char)*p))
			continue;
		if (*p == '_' || *p == '.' || *p == ':' || *p == '-')
			continue;
		return 0;
	}
	return 1;
}

int
sg_is_uint_range(const char *s, int min, int max)
{
	if (!s || !*s)
		return 0;

	/* Digits only */
	for (const char *p = s; *p; p++) {
		if (!isdigit((unsigned char)*p))
			return 0;
	}

	long val = strtol(s, NULL, 10);
	return val >= min && val <= max;
}

int
sg_is_tz_token(const char *s)
{
	if (!s || !*s)
		return 0;
	for (const char *p = s; *p; p++) {
		if (isalnum((unsigned char)*p))
			continue;
		if (*p == '_' || *p == '.' || *p == '/' || *p == '+' || *p == '-')
			continue;
		return 0;
	}
	return 1;
}

int
sg_is_permissions_csv(const char *s)
{
	if (!s || !*s)
		return 0;

	/* Reject leading/trailing commas and empty tokens */
	size_t len = strlen(s);
	if (len > 256)
		return 0;
	if (s[0] == ',' || s[len - 1] == ',')
		return 0;
	if (strstr(s, ",,"))
		return 0;

	/* Work on a mutable copy */
	char buf[257];
	memcpy(buf, s, len + 1);

	char *saveptr = NULL;
	char *tok = strtok_r(buf, ",", &saveptr);
	if (!tok)
		return 0;

	while (tok) {
		if (strcmp(tok, "monitor") != 0 &&
		    strcmp(tok, "configure") != 0 &&
		    strcmp(tok, "admin") != 0)
			return 0;
		tok = strtok_r(NULL, ",", &saveptr);
	}
	return 1;
}

int
sg_is_port_or_range(const char *s)
{
	if (!s || !*s)
		return 0;

	/* Check all characters are digits or a single dash */
	const char *dash = strchr(s, '-');
	if (dash) {
		/* Must not be first or last char */
		if (dash == s || !*(dash + 1))
			return 0;
		/* Only one dash */
		if (strchr(dash + 1, '-'))
			return 0;

		/* Extract a and b */
		size_t a_len = (size_t)(dash - s);
		if (a_len >= 16)
			return 0;

		char a_buf[16];
		memcpy(a_buf, s, a_len);
		a_buf[a_len] = '\0';

		const char *b_str = dash + 1;

		if (!sg_is_uint_range(a_buf, 1, 65535))
			return 0;
		if (!sg_is_uint_range(b_str, 1, 65535))
			return 0;

		long a_val = strtol(a_buf, NULL, 10);
		long b_val = strtol(b_str, NULL, 10);
		return a_val <= b_val;
	}

	return sg_is_uint_range(s, 1, 65535);
}

int
sg_match_csv_option(const char *opts, const char *val)
{
	if (!opts || !val)
		return 0;

	size_t val_len = strlen(val);
	const char *p = opts;

	while (*p) {
		const char *comma = strchr(p, ',');
		size_t span = comma ? (size_t)(comma - p) : strlen(p);

		if (span == val_len && strncmp(p, val, span) == 0)
			return 1;

		if (!comma)
			break;
		p = comma + 1;
	}
	return 0;
}

/* ── Internal helpers ────────────────────────────────────────────────────── */

/*
 * Parse "uint:min:max" kind string into min/max values.
 * Returns 1 on success, 0 on parse error.
 */
static int
parse_uint_kind(const char *kind, int *out_min, int *out_max)
{
	/* kind = "uint:MIN:MAX" */
	const char *p = kind + 5;  /* skip "uint:" */
	char *end;

	long mn = strtol(p, &end, 10);
	if (*end != ':')
		return 0;
	long mx = strtol(end + 1, &end, 10);
	if (*end != '\0')
		return 0;

	*out_min = (int)mn;
	*out_max = (int)mx;
	return 1;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

int
sg_reg_type_mode(const char *type_name)
{
	if (!type_name)
		return -1;
	for (const struct type_entry *e = type_table; e->name; e++) {
		if (strcmp(e->name, type_name) == 0)
			return (int)e->mode;
	}
	return -1;
}

/*
 * Convert "system_admin" to "system admin" — replace first '_' with ' '.
 * Returns pointer to static buffer (not thread-safe, fine for CLI).
 */
const char *
sg_reg_type_label(const char *type_name)
{
	static char buf[128];

	if (!type_name)
		return "";

	size_t len = strlen(type_name);
	if (len >= sizeof(buf))
		len = sizeof(buf) - 1;

	memcpy(buf, type_name, len);
	buf[len] = '\0';

	/* Replace first '_' with ' ' */
	char *us = strchr(buf, '_');
	if (us)
		*us = ' ';

	return buf;
}

const char *
sg_reg_valid_keys(const char *type_name)
{
	if (!type_name)
		return "";
	for (const struct keys_entry *e = keys_table; e->type; e++) {
		if (strcmp(e->type, type_name) == 0)
			return e->keys;
	}
	return "";
}

int
sg_reg_is_valid_key(const char *type_name, const char *key)
{
	if (!type_name || !key)
		return 0;

	const char *keys = sg_reg_valid_keys(type_name);
	if (!*keys)
		return 0;

	size_t key_len = strlen(key);
	const char *p = keys;

	while (*p) {
		/* Skip spaces */
		while (*p == ' ')
			p++;
		if (!*p)
			break;

		const char *start = p;
		while (*p && *p != ' ')
			p++;
		size_t span = (size_t)(p - start);

		if (span == key_len && strncmp(start, key, span) == 0)
			return 1;
	}
	return 0;
}

const char *
sg_reg_required_keys(const char *type_name)
{
	if (!type_name)
		return "";
	for (const struct required_entry *e = required_table; e->type; e++) {
		if (strcmp(e->type, type_name) == 0)
			return e->keys;
	}
	return "";
}

const char *
sg_reg_default_values(const char *type_name)
{
	if (!type_name)
		return "";
	for (const struct defaults_entry *e = defaults_table; e->type; e++) {
		if (strcmp(e->type, type_name) == 0)
			return e->defaults;
	}
	return "";
}

const char *
sg_reg_value_kind(const char *type_name, const char *key)
{
	if (!type_name || !key)
		return "string";
	for (const struct kind_entry *e = kind_table; e->type; e++) {
		if (strcmp(e->type, type_name) == 0 &&
		    strcmp(e->key, key) == 0)
			return e->kind;
	}
	return "string";
}

const char *
sg_reg_value_rule(const char *type_name, const char *key)
{
	static char buf[256];

	const char *kind = sg_reg_value_kind(type_name, key);

	if (strcmp(kind, "cidr") == 0)
		return "CIDR (A.B.C.D/len)";
	if (strcmp(kind, "ipv4") == 0)
		return "IPv4";
	if (strcmp(kind, "iface") == 0)
		return "interface name";
	if (strcmp(kind, "safe-id") == 0)
		return "safe identifier [A-Za-z0-9_.-]";
	if (strcmp(kind, "tz-token") == 0)
		return "timezone token (e.g. Asia/Ho_Chi_Minh)";
	if (strcmp(kind, "permissions-csv") == 0)
		return "CSV: monitor,configure,admin";
	if (strcmp(kind, "port-or-range") == 0)
		return "port or range (e.g. 80, 1024-65535)";
	if (strcmp(kind, "password-interactive") == 0)
		return "interactive prompt";
	if (strcmp(kind, "string") == 0)
		return "string";

	/* uint:min:max → "integer min-max" */
	if (strncmp(kind, "uint:", 5) == 0) {
		int mn, mx;
		if (parse_uint_kind(kind, &mn, &mx))
			snprintf(buf, sizeof(buf), "integer %d-%d", mn, mx);
		else
			snprintf(buf, sizeof(buf), "integer");
		return buf;
	}

	/* enum:a,b,c → "a|b|c" */
	if (strncmp(kind, "enum:", 5) == 0) {
		const char *opts = kind + 5;
		size_t len = strlen(opts);
		if (len >= sizeof(buf))
			len = sizeof(buf) - 1;
		memcpy(buf, opts, len);
		buf[len] = '\0';
		for (char *p = buf; *p; p++) {
			if (*p == ',')
				*p = '|';
		}
		return buf;
	}

	/* cidr-or:a,b → "CIDR or a|b" */
	if (strncmp(kind, "cidr-or:", 8) == 0) {
		const char *opts = kind + 8;
		char alt[64];
		size_t olen = strlen(opts);
		if (olen >= sizeof(alt))
			olen = sizeof(alt) - 1;
		memcpy(alt, opts, olen);
		alt[olen] = '\0';
		for (char *p = alt; *p; p++) {
			if (*p == ',')
				*p = '|';
		}
		snprintf(buf, sizeof(buf), "CIDR or %s", alt);
		return buf;
	}

	/* ref:X → "existing X object" */
	if (strncmp(kind, "ref:", 4) == 0) {
		snprintf(buf, sizeof(buf), "existing %s object", kind + 4);
		return buf;
	}

	/* ref-or:TYPE:a,b → "existing TYPE object or a|b" */
	if (strncmp(kind, "ref-or:", 7) == 0) {
		const char *rest = kind + 7;
		const char *colon = strchr(rest, ':');
		if (colon) {
			size_t tlen = (size_t)(colon - rest);
			char tname[64];
			if (tlen >= sizeof(tname))
				tlen = sizeof(tname) - 1;
			memcpy(tname, rest, tlen);
			tname[tlen] = '\0';

			const char *alts = colon + 1;
			char alt[64];
			size_t alen = strlen(alts);
			if (alen >= sizeof(alt))
				alen = sizeof(alt) - 1;
			memcpy(alt, alts, alen);
			alt[alen] = '\0';
			for (char *p = alt; *p; p++) {
				if (*p == ',')
					*p = '|';
			}
			snprintf(buf, sizeof(buf), "existing %s object or %s",
				 tname, alt);
		} else {
			snprintf(buf, sizeof(buf), "existing %s object", rest);
		}
		return buf;
	}

	/* safe-id-or:a,b → "safe identifier or a|b" */
	if (strncmp(kind, "safe-id-or:", 11) == 0) {
		const char *opts = kind + 11;
		char alt[64];
		size_t olen = strlen(opts);
		if (olen >= sizeof(alt))
			olen = sizeof(alt) - 1;
		memcpy(alt, opts, olen);
		alt[olen] = '\0';
		for (char *p = alt; *p; p++) {
			if (*p == ',')
				*p = '|';
		}
		snprintf(buf, sizeof(buf), "safe identifier or %s", alt);
		return buf;
	}

	return "string";
}

const char *
sg_reg_entry_id_kind(const char *type_name)
{
	if (type_name && strcmp(type_name, "firewall_policy") == 0)
		return "uint";
	return "safe-id";
}

const char *
sg_reg_domain_for(const char *type_name)
{
	if (!type_name)
		return "/etc/stargazer/system.conf";

	/* system_interface is special: maps to network.conf */
	if (strcmp(type_name, "system_interface") == 0)
		return "/etc/stargazer/network.conf";

	if (strncmp(type_name, "network_", 8) == 0)
		return "/etc/stargazer/network.conf";

	if (strncmp(type_name, "firewall_", 9) == 0)
		return "/etc/stargazer/firewall.conf";

	if (strncmp(type_name, "system_", 7) == 0)
		return "/etc/stargazer/system.conf";

	return "/etc/stargazer/system.conf";
}

int
sg_reg_validate_value(const char *type_name, const char *key, const char *val)
{
	if (!type_name || !key || !val)
		return 0;

	const char *kind = sg_reg_value_kind(type_name, key);

	/* cidr */
	if (strcmp(kind, "cidr") == 0)
		return sg_is_cidr(val);

	/* ipv4 */
	if (strcmp(kind, "ipv4") == 0)
		return sg_is_ipv4(val);

	/* iface */
	if (strcmp(kind, "iface") == 0)
		return sg_is_iface_name(val);

	/* uint:min:max */
	if (strncmp(kind, "uint:", 5) == 0) {
		int mn, mx;
		if (!parse_uint_kind(kind, &mn, &mx))
			return 0;
		return sg_is_uint_range(val, mn, mx);
	}

	/* enum:a,b,c */
	if (strncmp(kind, "enum:", 5) == 0)
		return sg_match_csv_option(kind + 5, val);

	/* cidr-or:a,b */
	if (strncmp(kind, "cidr-or:", 8) == 0)
		return sg_match_csv_option(kind + 8, val) || sg_is_cidr(val);

	/* safe-id */
	if (strcmp(kind, "safe-id") == 0)
		return sg_is_safe_id(val);

	/* safe-id-or:a,b */
	if (strncmp(kind, "safe-id-or:", 11) == 0)
		return sg_match_csv_option(kind + 11, val) || sg_is_safe_id(val);

	/* tz-token */
	if (strcmp(kind, "tz-token") == 0)
		return sg_is_tz_token(val);

	/* permissions-csv */
	if (strcmp(kind, "permissions-csv") == 0)
		return sg_is_permissions_csv(val);

	/* port-or-range */
	if (strcmp(kind, "port-or-range") == 0)
		return sg_is_port_or_range(val);

	/* password-interactive — always valid (handled by interactive branch) */
	if (strcmp(kind, "password-interactive") == 0)
		return 1;

	/* ref:X — validate as safe-id (existence check requires IPC, skip) */
	if (strncmp(kind, "ref:", 4) == 0)
		return sg_is_safe_id(val);

	/* ref-or:TYPE:a,b — check against options OR validate as safe-id */
	if (strncmp(kind, "ref-or:", 7) == 0) {
		const char *rest = kind + 7;
		const char *colon = strchr(rest, ':');
		if (colon) {
			if (sg_match_csv_option(colon + 1, val))
				return 1;
		}
		return sg_is_safe_id(val);
	}

	/* string — non-empty */
	return *val != '\0';
}

int
sg_reg_validate_entry_id(const char *type_name, const char *id)
{
	if (!type_name || !id || !*id)
		return 0;

	const char *kind = sg_reg_entry_id_kind(type_name);
	if (strcmp(kind, "uint") == 0) {
		/* Digits only, positive */
		for (const char *p = id; *p; p++) {
			if (!isdigit((unsigned char)*p))
				return 0;
		}
		return 1;
	}
	/* safe-id */
	return sg_is_safe_id(id);
}
