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
#include <net/if.h>
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
	{ "system_session-ttl",    CFG_SINGLE, "configure", "Session idle timeout settings"        },
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
	{ "network_route_static", "device",   "ref-iface:system_interface", 0, NULL, "Outgoing interface"          },
	{ "network_route_static", "distance", "uint:1:255",          0, "10",     "Administrative distance"      },
	{ "network_route_static", "status",   "enum:enable,disable", 0, "enable", "Enable or disable this route" },
	{ "network_route_static", "comment",  "string",              1, NULL,     "Optional description"         },

	/* network_nat */
	{ "network_nat", "type",        "enum:snat,dnat",        0, NULL,     "NAT type"                    },
	{ "network_nat", "srcintf",     "ref-iface-or:system_interface:any", 0, NULL, "Source interface"            },
	{ "network_nat", "dstintf",     "ref-iface-or:system_interface:any", 1, NULL, "Destination interface"       },
	{ "network_nat", "protocol",    "enum:tcp,udp,tcp+udp,all", 0, "all", "Protocol (tcp, udp, tcp+udp, or all)" },
	{ "network_nat", "srcaddr",     "ref-or-cidr:firewall_address:all,any", 0, NULL, "Source address object or subnet" },
	{ "network_nat", "dstaddr",     "ref-or-cidr:firewall_address:all,any", 0, NULL, "Destination address object or subnet" },
	{ "network_nat", "dstport",     "uint:1:65535",          1, NULL,     "Destination port"             },
	{ "network_nat", "mapped-ip",   "ipv4",                  1, NULL,     "Translated IP address"        },
	{ "network_nat", "mapped-port", "uint:1:65535",          1, NULL,     "Translated port"              },
	{ "network_nat", "status",      "enum:enable,disable",   0, "enable", "Enable or disable this rule"  },
	{ "network_nat", "sequence",    "uint:1:9999",           1, NULL,     "Priority (higher = checked first)" },

	/* system_interface */
	{ "system_interface", "mode",        "enum:static,dhcp", 0, "static", "Addressing mode"              },
	{ "system_interface", "ip",          "cidr",             1, "0.0.0.0/0", "Interface IP address and mask"  },
	{ "system_interface", "status",      "enum:up,down",     0, "up",   "Administrative state"           },
	{ "system_interface", "mtu",         "uint:576:65535",   0, "1500", "Maximum transmission unit"      },
	{ "system_interface", "allowaccess", "access-services",  1, NULL,   "Allowed management services"    },
	{ "system_interface", "description", "string",           1, NULL,   "Interface description"          },

	/* system_settings */
	{ "system_settings", "hostname",   "safe-id",             0, "stargazer", "System hostname"      },
	{ "system_settings", "ip-forward", "enum:enable,disable", 0, "enable",    "IPv4 packet forwarding" },
	{ "system_settings", "timezone",   "tz-token",            0, "UTC",       "System timezone"      },

	/* network_dns — always on, no status field */
	{ "network_dns", "primary",   "ipv4", 0, "1.1.1.1", "Primary DNS server"   },
	{ "network_dns", "secondary", "ipv4", 1, "8.8.8.8", "Secondary DNS server" },

	/* network_dhcp-server */
	{ "network_dhcp-server", "interface",   "ref-iface:system_interface", 0, NULL, "Interface to serve DHCP"     },
	{ "network_dhcp-server", "start-ip",    "ipv4",                0, NULL,     "Pool start address"           },
	{ "network_dhcp-server", "end-ip",      "ipv4",                0, NULL,     "Pool end address"             },
	{ "network_dhcp-server", "netmask",     "ipv4",                0, NULL,     "Subnet mask for clients"      },
	{ "network_dhcp-server", "gateway",     "ipv4",                1, NULL,     "Default gateway for clients"  },
	{ "network_dhcp-server", "dns-server",  "ipv4",                1, NULL,     "DNS server for clients"       },
	{ "network_dhcp-server", "domain-name", "safe-id",             1, NULL,     "Domain name for clients"      },
	{ "network_dhcp-server", "lease-time",  "uint:60:604800",      0, "86400",  "Lease time in seconds"        },
	{ "network_dhcp-server", "status",      "enum:enable,disable", 0, "enable", "Enable or disable this pool"  },

	/* system_ntp — always on, no status field */
	{ "system_ntp", "server", "safe-id", 0, "pool.ntp.org", "NTP server address or hostname" },

	/* system_session-ttl — global session idle timeouts */
	{ "system_session-ttl", "tcp-none",        "uint:10:600",   0, "120",  "TCP pre-handshake timeout (seconds)"            },
	{ "system_session-ttl", "tcp-syn-sent",    "uint:10:600",   0, "120",  "TCP SYN_SENT half-open timeout (seconds)"       },
	{ "system_session-ttl", "tcp-syn-recv",    "uint:5:300",    0, "60",   "TCP SYN_RECV timeout (seconds)"                 },
	{ "system_session-ttl", "tcp-established", "uint:60:86400", 0, "3600", "TCP ESTABLISHED idle timeout (seconds)"         },
	{ "system_session-ttl", "tcp-fin-wait",    "uint:10:600",   0, "120",  "TCP FIN_WAIT timeout (seconds)"                 },
	{ "system_session-ttl", "tcp-close-wait",  "uint:5:300",    0, "60",   "TCP CLOSE_WAIT timeout (seconds)"               },
	{ "system_session-ttl", "tcp-last-ack",    "uint:5:120",    0, "30",   "TCP LAST_ACK timeout (seconds)"                 },
	{ "system_session-ttl", "tcp-time-wait",   "uint:10:600",   0, "120",  "TCP TIME_WAIT timeout (seconds)"                },
	{ "system_session-ttl", "tcp-close",       "uint:1:60",     0, "10",   "TCP CLOSE (RST) cleanup timeout (seconds)"      },
	{ "system_session-ttl", "tcp-syn-sent2",   "uint:5:300",    0, "60",   "TCP simultaneous-open timeout (seconds)"        },
	{ "system_session-ttl", "udp",             "uint:10:3600",  0, "180",  "UDP session idle timeout (seconds)"             },
	{ "system_session-ttl", "icmp",            "uint:5:300",    0, "60",   "ICMP session idle timeout (seconds)"            },
	{ "system_session-ttl", "other",           "uint:10:3600",  0, "300",  "Other protocol timeout — GRE, ESP, etc. (seconds)" },

	/* firewall_policy */
	{ "firewall_policy", "name",     "safe-id",                         0, NULL,     "Policy name"                },
	{ "firewall_policy", "srcintf",  "ref-iface-or:system_interface:any", 0, "any",   "Source interface"           },
	{ "firewall_policy", "dstintf",  "ref-iface-or:system_interface:any", 0, "any",   "Destination interface"      },
	{ "firewall_policy", "srcaddr",  "ref:firewall_address",            0, "all",    "Source address object"      },
	{ "firewall_policy", "dstaddr",  "ref:firewall_address",            0, "all",    "Destination address object" },
	{ "firewall_policy", "action",   "enum:accept,deny,drop",           0, "deny",   "Matching traffic action"    },
	{ "firewall_policy", "service",  "ref:firewall_service",            0, "all",    "Service object"             },
	{ "firewall_policy", "schedule", "safe-id-or:all,any",              0, "all",    "Schedule object"            },
	{ "firewall_policy", "status",   "enum:enable,disable",             0, "enable", "Enable or disable this policy" },
	{ "firewall_policy", "comment",  "string",                          1, NULL,     "Optional description"       },
	{ "firewall_policy", "sequence", "uint:1:9999",                     1, NULL,     "Priority (higher = checked first)" },

	/* firewall_address */
	{ "firewall_address", "name",    "safe-id",                  0, NULL,     "Address object name"  },
	{ "firewall_address", "subnet",  "cidr",                     0, NULL,     "Network address and mask" },
	{ "firewall_address", "type",    "enum:ipmask,iprange,fqdn", 0, "ipmask", "Address type"         },
	{ "firewall_address", "comment", "string",                   1, NULL,     "Optional description" },

	/* firewall_service */
	{ "firewall_service", "name",       "safe-id",           0, NULL,  "Service object name"  },
	{ "firewall_service", "protocol",   "enum:tcp,udp,icmp,all", 0, "tcp", "IP protocol"          },
	{ "firewall_service", "port-range", "port-or-range",         1, NULL,  "Port or port range"   },
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

/* ── Key=Value utility functions ────────────────────────────────────────── */

void
sg_kv_get(const char *data, const char *key, char *out, size_t outsz)
{
	out[0] = '\0';
	if (!data || !key || !key[0]) return;

	size_t klen = strlen(key);
	const char *p = data;
	while (*p) {
		const char *eol = strchr(p, '\n');
		size_t llen = eol ? (size_t)(eol - p) : strlen(p);

		if (llen >= klen + 1 &&
		    memcmp(p, key, klen) == 0 && p[klen] == '=') {
			const char *val = p + klen + 1;
			size_t vlen = llen - klen - 1;
			if (vlen >= outsz) vlen = outsz - 1;
			memcpy(out, val, vlen);
			out[vlen] = '\0';
			return;
		}
		p += llen;
		if (eol) p++; else break;
	}
}

int
sg_kv_has_key(const char *data, const char *key)
{
	if (!data || !key || !key[0]) return 0;

	size_t klen = strlen(key);
	const char *p = data;
	while (*p) {
		const char *eol = strchr(p, '\n');
		size_t llen = eol ? (size_t)(eol - p) : strlen(p);

		if (llen >= klen + 1 &&
		    memcmp(p, key, klen) == 0 && p[klen] == '=')
			return 1;

		p += llen;
		if (eol) p++; else break;
	}
	return 0;
}

/* ── Canonical option lists ──────────────────────────────────────────────── */

static const char *const s_access_services[] = {
	"ping", "ssh", "https", "http", "snmp", "telnet", NULL
};

static const char *const s_permissions[] = {
	"monitor", "configure", "admin", NULL
};

const char * const *sg_access_services_opts(void) { return s_access_services; }
const char * const *sg_permissions_opts(void)      { return s_permissions; }

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
sg_is_net_target(const char *s)
{
	if (!s || !*s)
		return 0;
	if (strlen(s) > SG_NET_TARGET_MAX)
		return 0;
	for (const char *p = s; *p; p++) {
		if (isalnum((unsigned char)*p))
			continue;
		if (*p == '_' || *p == '.' || *p == '-' || *p == ':')
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
	if (strlen(s) >= IF_NAMESIZE)   /* IF_NAMESIZE = 16, same as kernel IFNAMSIZ */
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
		const char * const *opts = sg_permissions_opts();
		int found = 0;
		for (int i = 0; opts[i]; i++) {
			if (strcmp(tok, opts[i]) == 0) { found = 1; break; }
		}
		if (!found)
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
		const char * const *opts = sg_access_services_opts();
		int found = 0;
		for (int i = 0; opts[i]; i++) {
			if (strcmp(tok, opts[i]) == 0) { found = 1; break; }
		}
		if (!found)
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

int
sg_reg_is_optional(const char *type_name, const char *key)
{
	if (!type_name || !key)
		return 0;
	for (const struct field_entry *f = field_table; f->type; f++) {
		if (strcmp(f->type, type_name) == 0 &&
		    strcmp(f->key, key) == 0)
			return f->optional;
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
		/* Fields with defaults are backfilled by CFG_SET after
		 * validation — only truly mandatory (no default) keys
		 * need to be present in the user payload. */
		if (f->defval)
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

/*
 * Return ALL registered keys for a type as "key=val\n" lines.
 * Keys with a default get their default value; keys without a
 * default get an empty value ("key=\n").  Internal keys (builtin,
 * password, password-hash) are excluded.
 */
const char *
sg_reg_all_keys_defaults(const char *type_name)
{
	static char buf[2048];
	if (!type_name)
		return "";

	buf[0] = '\0';
	size_t pos = 0;
	for (const struct field_entry *f = field_table; f->type; f++) {
		if (strcmp(f->type, type_name) != 0)
			continue;
		/* Skip internal-only keys */
		if (strcmp(f->key, "builtin") == 0 ||
		    strcmp(f->key, "password") == 0 ||
		    strcmp(f->key, "password-hash") == 0)
			continue;
		const char *v = f->defval ? f->defval : "";
		int n = snprintf(buf + pos, sizeof(buf) - pos,
				 "%s=%s\n", f->key, v);
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
	if (strcmp(kind, "permissions-csv") == 0) {
		const char * const *opts = sg_permissions_opts();
		size_t pos = (size_t)snprintf(buf, sizeof(buf), "CSV: ");
		for (int i = 0; opts[i]; i++) {
			if (i > 0 && pos < sizeof(buf) - 1)
				buf[pos++] = ',';
			size_t olen = strlen(opts[i]);
			if (pos + olen < sizeof(buf)) {
				memcpy(buf + pos, opts[i], olen);
				pos += olen;
			}
		}
		buf[pos] = '\0';
		return buf;
	}
	if (strcmp(kind, "access-services") == 0) {
		const char * const *opts = sg_access_services_opts();
		size_t pos = (size_t)snprintf(buf, sizeof(buf), "space-separated: ");
		for (int i = 0; opts[i]; i++) {
			if (i > 0 && pos < sizeof(buf) - 1)
				buf[pos++] = ' ';
			size_t olen = strlen(opts[i]);
			if (pos + olen < sizeof(buf)) {
				memcpy(buf + pos, opts[i], olen);
				pos += olen;
			}
		}
		buf[pos] = '\0';
		return buf;
	}
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

	/* ref-iface:TYPE → "existing interface" */
	if (strncmp(kind, "ref-iface:", 10) == 0) {
		snprintf(buf, sizeof(buf), "existing interface name");
		return buf;
	}
	/* ref-iface-or:TYPE:a,b → "existing interface or a|b" */
	if (strncmp(kind, "ref-iface-or:", 13) == 0) {
		const char *rest = kind + 13;
		const char *colon = strchr(rest, ':');
		if (colon) {
			char alt[64];
			size_t alen = strlen(colon + 1);
			if (alen >= sizeof(alt))
				alen = sizeof(alt) - 1;
			memcpy(alt, colon + 1, alen);
			alt[alen] = '\0';
			for (char *p = alt; *p; p++) {
				if (*p == ',')
					*p = '|';
			}
			snprintf(buf, sizeof(buf),
				 "existing interface or %s", alt);
		} else {
			snprintf(buf, sizeof(buf), "existing interface name");
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

	/* ref-or-cidr:TYPE:a,b — CIDR or named ref or hardcoded option.
	 * Reject plain IPv4 (e.g. "10.0.0.0") — must be CIDR with /prefix.
	 * Object names that look like IPs (all digits+dots) are also rejected
	 * to avoid ambiguity. */
	if (strncmp(kind, "ref-or-cidr:", 12) == 0) {
		const char *rest = kind + 12;
		const char *colon = strchr(rest, ':');
		if (colon && sg_match_csv_option(colon + 1, val))
			return 1;
		if (sg_is_cidr(val))
			return 1;
		/* Reject if it looks like an IP address (digits+dots only) */
		if (sg_is_ipv4(val))
			return 0;
		return sg_is_safe_id(val);
	}

	/* ref-iface:TYPE — validate as iface name, register as reference.
	 * ref-iface-or:TYPE:a,b — iface name OR one of the listed options. */
	if (strncmp(kind, "ref-iface:", 10) == 0)
		return sg_is_iface_name(val);
	if (strncmp(kind, "ref-iface-or:", 13) == 0) {
		const char *rest = kind + 13;
		const char *colon = strchr(rest, ':');
		if (colon && sg_match_csv_option(colon + 1, val))
			return 1;
		return sg_is_iface_name(val);
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

	/* ref-or-cidr:TYPE:opts — same parsing as ref-or:TYPE:opts */
	if (strncmp(kind, "ref-or-cidr:", 12) == 0) {
		const char *rest = kind + 12;
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

	/* ref-iface:TYPE — same parsing as ref:TYPE */
	if (strncmp(kind, "ref-iface:", 10) == 0) {
		const char *t = kind + 10;
		size_t tlen = strlen(t);
		if (tlen >= ref_sz) tlen = ref_sz - 1;
		memcpy(ref_type, t, tlen);
		ref_type[tlen] = '\0';
		return 1;
	}

	/* ref-iface-or:TYPE:opts — same parsing as ref-or:TYPE:opts */
	if (strncmp(kind, "ref-iface-or:", 13) == 0) {
		const char *rest = kind + 13;
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

/* ── Config scrub helpers ────────────────────────────────────────────────── */

const char *
sg_reg_field_default(const char *type_name, const char *key)
{
	if (!type_name || !key)
		return NULL;
	for (const struct field_entry *f = field_table; f->type; f++) {
		if (strcmp(f->type, type_name) == 0 &&
		    strcmp(f->key, key) == 0)
			return f->defval;
	}
	return NULL;
}

int
sg_reg_scrub_value(const char *type, const char *key, const char *val,
                   char *out, size_t outsz)
{
	if (!type || !key || !val || !out || outsz == 0)
		return 0;

	out[0] = '\0';

	/* If the whole value already validates, keep it unchanged */
	if (sg_reg_validate_value(type, key, val)) {
		size_t vlen = strlen(val);
		if (vlen >= outsz)
			vlen = outsz - 1;
		memcpy(out, val, vlen);
		out[vlen] = '\0';
		return 0;
	}

	const char *kind = sg_reg_value_kind(type, key);

	/* access-services: space-separated, keep individually valid tokens */
	if (strcmp(kind, "access-services") == 0) {
		size_t vlen = strlen(val);
		if (vlen > 256) vlen = 256;
		char buf[257];
		memcpy(buf, val, vlen);
		buf[vlen] = '\0';

		size_t pos = 0;
		char *saveptr = NULL;
		char *tok = strtok_r(buf, " ", &saveptr);
		while (tok) {
			if (sg_is_access_services(tok)) {
				if (pos > 0 && pos < outsz - 1)
					out[pos++] = ' ';
				size_t tlen = strlen(tok);
				if (pos + tlen < outsz) {
					memcpy(out + pos, tok, tlen);
					pos += tlen;
				}
			}
			tok = strtok_r(NULL, " ", &saveptr);
		}
		out[pos] = '\0';
		return 1;
	}

	/* permissions-csv: comma-separated, keep individually valid tokens */
	if (strcmp(kind, "permissions-csv") == 0) {
		size_t vlen = strlen(val);
		if (vlen > 256) vlen = 256;
		char buf[257];
		memcpy(buf, val, vlen);
		buf[vlen] = '\0';

		size_t pos = 0;
		char *saveptr = NULL;
		char *tok = strtok_r(buf, ",", &saveptr);
		while (tok) {
			if (sg_is_permissions_csv(tok)) {
				if (pos > 0 && pos < outsz - 1)
					out[pos++] = ',';
				size_t tlen = strlen(tok);
				if (pos + tlen < outsz) {
					memcpy(out + pos, tok, tlen);
					pos += tlen;
				}
			}
			tok = strtok_r(NULL, ",", &saveptr);
		}
		out[pos] = '\0';
		return 1;
	}

	/* All other kinds: reset to field default (or empty) */
	const char *def = sg_reg_field_default(type, key);
	if (def) {
		size_t dlen = strlen(def);
		if (dlen >= outsz)
			dlen = outsz - 1;
		memcpy(out, def, dlen);
		out[dlen] = '\0';
	}
	return 1;
}
