/* SPDX-License-Identifier: MIT */
/*
 * sg_validate.c — Shared config registry and input validators for Stargazer
 *
 * Unified field_table describes every config field (key, kind, required,
 * default) in one place.  Shared by CLI and mgmtd.
 */

#define _POSIX_C_SOURCE 200809L

#include "sg_validate.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Type registry ───────────────────────────────────────────────────────── */

static const sg_type_info_t type_table[] = {
	{ "network_route_static",   CFG_TABLE,  "configure", "Configure static routes"             },
	{ "network_route_policy",   CFG_TABLE,  "configure", "Configure policy-based routing"      },
	{ "network_ospf",           CFG_SINGLE, "configure", "Configure OSPF dynamic routing"      },
	{ "network_rip",            CFG_SINGLE, "configure", "Configure RIP dynamic routing"       },
	{ "network_bgp",            CFG_SINGLE, "configure", "Configure BGP dynamic routing"       },
	{ "network_nat",            CFG_TABLE,  "configure", "Configure NAT rules (SNAT/DNAT)"     },
	{ "network_dns",            CFG_SINGLE, "configure", "Configure DNS settings"              },
	{ "network_dhcp-server",    CFG_TABLE,  "configure", "Configure DHCP server pools"         },
	{ "system_settings",        CFG_SINGLE, "configure", "System general settings"              },
	{ "system_interface",       CFG_TABLE,  "configure", "Configure network interfaces"        },
	{ "system_ntp",             CFG_SINGLE, "configure", "Configure NTP time sync"             },
	{ "firewall_policy",        CFG_TABLE,  "configure", "Configure firewall policies"         },
	{ "firewall_address",       CFG_TABLE,  "configure", "Configure address objects"           },
	{ "firewall_service",       CFG_TABLE,  "configure", "Configure service objects"           },
	{ "system_password-policy", CFG_SINGLE, "admin",     "Configure global password policy"    },
	{ "system_admin-profile",   CFG_TABLE,  "admin",     "Configure admin permission profiles" },
	{ "system_admin",           CFG_TABLE,  "admin",     "Configure admin accounts"            },
	{ NULL, 0, NULL, NULL }
};

/* ── Unified field table ─────────────────────────────────────────────────── */

struct field_entry {
	const char *type;
	const char *key;
	const char *kind;
	int         optional;   /* 0 = required, 1 = optional */
	const char *defval;     /* default value, or NULL */
	const char *desc;       /* human-readable help text */
};

static const struct field_entry field_table[] = {
	/* network_route_static */
	{ "network_route_static", "dst",      "cidr",                0, NULL,     "Destination network"          },
	{ "network_route_static", "gateway",  "ipv4",                0, NULL,     "Next-hop gateway address"     },
	{ "network_route_static", "device",   "iface",               0, NULL,     "Outgoing interface"           },
	{ "network_route_static", "distance", "uint:1:255",          0, "10",     "Administrative distance"      },
	{ "network_route_static", "status",   "enum:enable,disable", 0, "enable", "Enable or disable this route" },
	{ "network_route_static", "comment",  "string",              1, NULL,     "Optional description"         },

	/* network_nat */
	{ "network_nat", "type",        "enum:snat,dnat",        0, NULL,     "NAT type"                    },
	{ "network_nat", "srcintf",     "iface",                 0, NULL,     "Source interface"             },
	{ "network_nat", "dstintf",     "iface",                 0, NULL,     "Destination interface"        },
	{ "network_nat", "srcaddr",     "cidr-or:any,all",       0, NULL,     "Source address or subnet"     },
	{ "network_nat", "dstaddr",     "cidr-or:any,all",       0, NULL,     "Destination address or subnet" },
	{ "network_nat", "dstport",     "uint:1:65535",          0, NULL,     "Destination port"             },
	{ "network_nat", "mapped-ip",   "ipv4",                  0, NULL,     "Translated IP address"        },
	{ "network_nat", "mapped-port", "uint:1:65535",          0, NULL,     "Translated port"              },
	{ "network_nat", "status",      "enum:enable,disable",   0, "enable", "Enable or disable this rule"  },

	/* system_interface */
	{ "system_interface", "ip",          "cidr",             0, NULL,   "Interface IP address and mask"  },
	{ "system_interface", "status",      "enum:up,down",     0, "up",   "Administrative state"           },
	{ "system_interface", "mtu",         "uint:576:65535",   0, "1500", "Maximum transmission unit"      },
	{ "system_interface", "allowaccess", "access-services",  1, NULL,   "Allowed management services"    },
	{ "system_interface", "description", "string",           1, NULL,   "Interface description"          },

	/* system_settings */
	{ "system_settings", "hostname",   "safe-id",             0, "stargazer", "System hostname"      },
	{ "system_settings", "ip-forward", "enum:enable,disable", 0, "enable",    "IPv4 packet forwarding" },
	{ "system_settings", "timezone",   "tz-token",            0, "UTC",       "System timezone"      },

	/* network_dns */
	{ "network_dns", "primary",    "ipv4",                0, NULL,     "Primary DNS server"       },
	{ "network_dns", "secondary",  "ipv4",                0, NULL,     "Secondary DNS server"     },
	{ "network_dns", "listen-on",  "ipv4",                1, NULL,     "Listen address for DNS"   },
	{ "network_dns", "port",       "uint:1:65535",        1, "53",     "DNS listening port"       },
	{ "network_dns", "cache-size", "uint:0:100000",       1, "10000",  "DNS cache size (entries)" },
	{ "network_dns", "status",     "enum:enable,disable", 0, "enable", "Enable or disable DNS"    },

	/* network_dhcp-server */
	{ "network_dhcp-server", "interface",   "iface",               0, NULL,     "Interface to serve DHCP"      },
	{ "network_dhcp-server", "start-ip",    "ipv4",                0, NULL,     "Pool start address"           },
	{ "network_dhcp-server", "end-ip",      "ipv4",                0, NULL,     "Pool end address"             },
	{ "network_dhcp-server", "netmask",     "ipv4",                0, NULL,     "Subnet mask for clients"      },
	{ "network_dhcp-server", "gateway",     "ipv4",                1, NULL,     "Default gateway for clients"  },
	{ "network_dhcp-server", "dns-server",  "ipv4",                1, NULL,     "DNS server for clients"       },
	{ "network_dhcp-server", "domain-name", "safe-id",             1, NULL,     "Domain name for clients"      },
	{ "network_dhcp-server", "lease-time",  "uint:60:604800",      0, "86400",  "Lease time in seconds"        },
	{ "network_dhcp-server", "status",      "enum:enable,disable", 0, "enable", "Enable or disable this pool"  },

	/* system_ntp */
	{ "system_ntp", "server", "ipv4",                0, NULL, "NTP server address"          },
	{ "system_ntp", "status", "enum:enable,disable", 0, NULL, "Enable or disable NTP sync"  },

	/* firewall_policy */
	{ "firewall_policy", "name",     "safe-id",                         0, NULL,     "Policy name"                },
	{ "firewall_policy", "srcintf",  "iface",                           0, "any",    "Source interface"           },
	{ "firewall_policy", "dstintf",  "iface",                           0, "any",    "Destination interface"      },
	{ "firewall_policy", "srcaddr",  "ref-or:firewall_address:all,any", 0, "all",    "Source address object"      },
	{ "firewall_policy", "dstaddr",  "ref-or:firewall_address:all,any", 0, "all",    "Destination address object" },
	{ "firewall_policy", "action",   "enum:accept,deny,drop",           0, "deny",   "Matching traffic action"    },
	{ "firewall_policy", "service",  "ref-or:firewall_service:all,any", 0, "all",    "Service object"             },
	{ "firewall_policy", "schedule", "safe-id-or:all,any",              0, "all",    "Schedule object"            },
	{ "firewall_policy", "status",   "enum:enable,disable",             0, "enable", "Enable or disable this policy" },
	{ "firewall_policy", "comment",  "string",                          1, NULL,     "Optional description"       },

	/* firewall_address */
	{ "firewall_address", "name",    "safe-id",                  0, NULL,     "Address object name"  },
	{ "firewall_address", "subnet",  "cidr",                     0, NULL,     "Network address and mask" },
	{ "firewall_address", "type",    "enum:ipmask,iprange,fqdn", 0, "ipmask", "Address type"         },
	{ "firewall_address", "comment", "string",                   1, NULL,     "Optional description" },

	/* firewall_service */
	{ "firewall_service", "name",       "safe-id",           0, NULL,  "Service object name"  },
	{ "firewall_service", "protocol",   "enum:tcp,udp,icmp", 0, "tcp", "IP protocol"          },
	{ "firewall_service", "port-range", "port-or-range",     0, NULL,  "Port or port range"   },
	{ "firewall_service", "comment",    "string",            1, NULL,  "Optional description" },

	/* system_password-policy */
	{ "system_password-policy", "min-length",    "uint:0:128", 0, "8", "Minimum password length"      },
	{ "system_password-policy", "min-uppercase", "uint:0:128", 0, "0", "Required uppercase characters" },
	{ "system_password-policy", "min-lowercase", "uint:0:128", 0, "0", "Required lowercase characters" },
	{ "system_password-policy", "min-digit",     "uint:0:128", 0, "0", "Required digit characters"    },
	{ "system_password-policy", "min-special",   "uint:0:128", 0, "0", "Required special characters"  },

	/* system_admin-profile */
	{ "system_admin-profile", "permissions", "permissions-csv", 0, NULL, "Granted permissions"  },
	{ "system_admin-profile", "description", "string",          1, NULL, "Profile description"  },

	/* system_admin */
	{ "system_admin", "profile",                  "ref:system_admin-profile", 0, NULL,     "Admin permission profile"            },
	{ "system_admin", "password",                 "password-interactive",     1, NULL,     "Account password"                    },
	{ "system_admin", "enforce-change-password",  "enum:enable,disable",     0, "enable", "Force password change on first login" },
	{ "system_admin", "enforce-password-policy",  "enum:enable,disable",     0, "enable", "Apply password policy rules"         },

	{ NULL, NULL, NULL, 0, NULL, NULL }
};

/* ── Pure validation helpers ─────────────────────────────────────────────── */

int
sg_is_safe_id(const char *s)
{
	if (!s || !*s)
		return 0;
	if (strlen(s) > SG_SAFE_ID_MAX)
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
sg_is_access_services(const char *s)
{
	/* Empty string = no services allowed → valid */
	if (!s || !*s)
		return 1;

	size_t len = strlen(s);
	if (len > 256)
		return 0;

	/* Space-separated tokens: "ping ssh https" */
	char buf[257];
	memcpy(buf, s, len + 1);

	char *saveptr = NULL;
	char *tok = strtok_r(buf, " ", &saveptr);
	if (!tok)
		return 0;

	while (tok) {
		if (strcmp(tok, "ping") != 0 &&
		    strcmp(tok, "ssh") != 0 &&
		    strcmp(tok, "https") != 0 &&
		    strcmp(tok, "http") != 0 &&
		    strcmp(tok, "snmp") != 0 &&
		    strcmp(tok, "telnet") != 0)
			return 0;
		tok = strtok_r(NULL, " ", &saveptr);
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
	for (const sg_type_info_t *e = type_table; e->name; e++) {
		if (strcmp(e->name, type_name) == 0)
			return (int)e->mode;
	}
	return -1;
}

const sg_type_info_t *
sg_reg_types(void)
{
	return type_table;
}

const char *
sg_reg_type_perm(const char *type_name)
{
	if (!type_name)
		return NULL;
	for (const sg_type_info_t *e = type_table; e->name; e++) {
		if (strcmp(e->name, type_name) == 0)
			return e->perm;
	}
	return NULL;
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
	static char buf[512];
	if (!type_name)
		return "";

	buf[0] = '\0';
	size_t pos = 0;
	for (const struct field_entry *f = field_table; f->type; f++) {
		if (strcmp(f->type, type_name) != 0)
			continue;
		if (pos > 0 && pos < sizeof(buf) - 1)
			buf[pos++] = ' ';
		size_t klen = strlen(f->key);
		if (pos + klen < sizeof(buf)) {
			memcpy(buf + pos, f->key, klen);
			pos += klen;
		}
	}
	buf[pos] = '\0';
	return buf;
}

int
sg_reg_is_valid_key(const char *type_name, const char *key)
{
	if (!type_name || !key)
		return 0;
	for (const struct field_entry *f = field_table; f->type; f++) {
		if (strcmp(f->type, type_name) == 0 &&
		    strcmp(f->key, key) == 0)
			return 1;
	}
	return 0;
}

const char *
sg_reg_required_keys(const char *type_name)
{
	static char buf[512];
	if (!type_name)
		return "";

	buf[0] = '\0';
	size_t pos = 0;
	for (const struct field_entry *f = field_table; f->type; f++) {
		if (strcmp(f->type, type_name) != 0 || f->optional)
			continue;
		if (pos > 0 && pos < sizeof(buf) - 1)
			buf[pos++] = ' ';
		size_t klen = strlen(f->key);
		if (pos + klen < sizeof(buf)) {
			memcpy(buf + pos, f->key, klen);
			pos += klen;
		}
	}
	buf[pos] = '\0';
	return buf;
}

const char *
sg_reg_default_values(const char *type_name)
{
	static char buf[1024];
	if (!type_name)
		return "";

	buf[0] = '\0';
	size_t pos = 0;
	for (const struct field_entry *f = field_table; f->type; f++) {
		if (strcmp(f->type, type_name) != 0 || !f->defval)
			continue;
		int n = snprintf(buf + pos, sizeof(buf) - pos,
				 "%s=%s\n", f->key, f->defval);
		if (n > 0 && pos + (size_t)n < sizeof(buf))
			pos += (size_t)n;
	}
	return buf;
}

const char *
sg_reg_value_kind(const char *type_name, const char *key)
{
	if (!type_name || !key)
		return "string";
	for (const struct field_entry *f = field_table; f->type; f++) {
		if (strcmp(f->type, type_name) == 0 &&
		    strcmp(f->key, key) == 0)
			return f->kind;
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
	if (strcmp(kind, "access-services") == 0)
		return "space-separated: ping ssh https http snmp telnet";
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
sg_reg_field_desc(const char *type_name, const char *key)
{
	if (!type_name || !key)
		return "";
	for (const struct field_entry *f = field_table; f->type; f++) {
		if (strcmp(f->type, type_name) == 0 &&
		    strcmp(f->key, key) == 0)
			return f->desc ? f->desc : "";
	}
	return "";
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

	/* access-services */
	if (strcmp(kind, "access-services") == 0)
		return sg_is_access_services(val);

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

/* ── Reference metadata ──────────────────────────────────────────────────── */

int
sg_parse_ref_kind(const char *kind,
                  char *ref_type, size_t ref_sz,
                  char *opts, size_t opts_sz)
{
	if (!kind)
		return 0;

	ref_type[0] = '\0';
	opts[0] = '\0';

	/* ref:TYPE */
	if (strncmp(kind, "ref:", 4) == 0) {
		const char *t = kind + 4;
		size_t tlen = strlen(t);
		if (tlen >= ref_sz) tlen = ref_sz - 1;
		memcpy(ref_type, t, tlen);
		ref_type[tlen] = '\0';
		return 1;
	}

	/* ref-or:TYPE:opts */
	if (strncmp(kind, "ref-or:", 7) == 0) {
		const char *rest = kind + 7;
		const char *colon = strchr(rest, ':');
		if (colon) {
			size_t tlen = (size_t)(colon - rest);
			if (tlen >= ref_sz) tlen = ref_sz - 1;
			memcpy(ref_type, rest, tlen);
			ref_type[tlen] = '\0';

			const char *o = colon + 1;
			size_t olen = strlen(o);
			if (olen >= opts_sz) olen = opts_sz - 1;
			memcpy(opts, o, olen);
			opts[olen] = '\0';
		} else {
			size_t tlen = strlen(rest);
			if (tlen >= ref_sz) tlen = ref_sz - 1;
			memcpy(ref_type, rest, tlen);
			ref_type[tlen] = '\0';
		}
		return 1;
	}

	return 0;
}

int
sg_reg_find_referencing(const char *target_type,
                        sg_ref_entry_t *out, int max)
{
	if (!target_type || !out || max <= 0)
		return 0;

	int count = 0;
	char rt[64], ro[64];

	for (const struct field_entry *f = field_table; f->type; f++) {
		if (!sg_parse_ref_kind(f->kind, rt, sizeof(rt),
		                       ro, sizeof(ro)))
			continue;
		if (strcmp(rt, target_type) == 0) {
			if (count < max) {
				out[count].type = f->type;
				out[count].key = f->key;
				count++;
			}
		}
	}
	return count;
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
