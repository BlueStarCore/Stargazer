/* SPDX-License-Identifier: MIT */
/*
 * sg_validate.h — Shared config registry and input validators for Stargazer
 *
 * Centralized tables of config types, valid keys, default values, required
 * fields, and validation rules.  Used by both CLI and mgmtd.
 */

#ifndef SG_VALIDATE_H
#define SG_VALIDATE_H

#include <stddef.h>

typedef enum { CFG_TABLE, CFG_SINGLE } cfg_mode_t;

typedef struct {
	const char *name;   /* e.g. "firewall_policy" */
	cfg_mode_t  mode;   /* CFG_TABLE or CFG_SINGLE */
	const char *perm;   /* "configure" or "admin" */
	const char *desc;   /* CLI help text */
} sg_type_info_t;

/* NULL-terminated array of all config types. */
const sg_type_info_t *sg_reg_types(void);

/* ── Canonical option lists ───────────────────────────────────────────── */

/* NULL-terminated arrays of valid tokens for multi-token field kinds.
 * Single source of truth — used by validators, CLI completions, value-rule
 * descriptions, and any other consumer.  Add a new service/permission here
 * and every layer picks it up automatically. */
const char * const *sg_access_services_opts(void);
const char * const *sg_permissions_opts(void);

/* ── Key=Value utility functions ──────────────────────────────────────── */

/*
 * Extract a value from "key=val\nkey2=val2\n" format data.
 * Copies the value for the given key into out (NUL-terminated).
 * If key is not found, out[0] = '\0'.
 */
void sg_kv_get(const char *data, const char *key, char *out, size_t outsz);

/*
 * Check if a key exists in "key=val\n" format data.
 * Returns 1 if found at a line start, 0 otherwise.
 */
int sg_kv_has_key(const char *data, const char *key);

/* ── Pure validators ──────────────────────────────────────────────────── */

#define SG_SAFE_ID_MAX      64
#define SG_NET_TARGET_MAX  253   /* DNS max hostname length */

int sg_is_safe_id(const char *s);
int sg_is_net_target(const char *s);
int sg_is_ipv4(const char *s);
int sg_is_cidr(const char *s);
int sg_is_fqdn(const char *s);
int sg_is_iface_name(const char *s);
int sg_is_uint_range(const char *s, int min, int max);
int sg_is_tz_token(const char *s);
int sg_is_permissions_csv(const char *s);
int sg_is_access_services(const char *s);
int sg_is_port_or_range(const char *s);
int sg_match_csv_option(const char *opts, const char *val);

/* ── Registry lookups ─────────────────────────────────────────────────── */

/* Lookup config type mode. Returns -1 if unknown. */
int sg_reg_type_mode(const char *type_name);

/* Get human-readable label for type (e.g. "firewall policy"). */
const char *sg_reg_type_label(const char *type_name);

/* Get required permission for type ("configure" or "admin"). NULL if unknown. */
const char *sg_reg_type_perm(const char *type_name);

/* Get space-separated list of valid keys for a type. Returns "" if unknown. */
const char *sg_reg_valid_keys(const char *type_name);

/* Check if key is valid for type. Returns 1 if valid, 0 if not. */
int sg_reg_is_valid_key(const char *type_name, const char *key);

/* Check if key is an internal hidden field (not user-settable, not shown).
 * Returns 1 if hidden, 0 otherwise (including unknown keys). */
int sg_reg_is_hidden_key(const char *type_name, const char *key);

/* Check if key is optional. Returns 1 if optional, 0 if required. */
int sg_reg_is_optional(const char *type_name, const char *key);

/* Get ALL registered keys as "key=default\n" lines.
 * Keys without defaults get empty values ("key=\n"). */
const char *sg_reg_all_keys_defaults(const char *type_name);

/* Get space-separated list of required keys. Returns "" if none. */
const char *sg_reg_required_keys(const char *type_name);

/* Get default values as "key=val\nkey=val\n..." string. Returns "" if none. */
const char *sg_reg_default_values(const char *type_name);

/* Get validation kind string for a type:key pair (e.g. "enum:enable,disable"). */
const char *sg_reg_value_kind(const char *type_name, const char *key);

/* Get human-readable validation rule description. */
const char *sg_reg_value_rule(const char *type_name, const char *key);

/* Get custom human-readable description for a type:key pair. */
const char *sg_reg_field_desc(const char *type_name, const char *key);

/* Get the default value for a specific field (type+key). Returns NULL if none. */
const char *sg_reg_field_default(const char *type_name, const char *key);

/*
 * Scrub a single field value against the registry.
 * If val passes validation → copies val to out, returns 0 (no change).
 * If val fails validation → produces a cleaned value in out, returns 1.
 *   - access-services: keeps individually valid tokens, drops invalid ones.
 *   - permissions-csv: keeps individually valid tokens, drops invalid ones.
 *   - other kinds: resets to field default (or empty string if no default).
 */
int sg_reg_scrub_value(const char *type, const char *key, const char *val,
                       char *out, size_t outsz);

/* Get entry ID rule for a type ("uint", "profid/seq", or "safe-id"). */
const char *sg_reg_entry_id_kind(const char *type_name);

/* Nested sub-table lookup: child type for `config <subcmd>` inside a
 * `config <parent_type>/edit` context, or NULL if there is no such sub-table. */
const char *sg_reg_subtable_child(const char *parent_type, const char *subcmd);

/* If `child_type` is a nested sub-table, returns human guidance on how to reach
 * it (so standalone `configure <child>` can be rejected); NULL otherwise. */
const char *sg_reg_subtable_path(const char *child_type);

/* Get domain file path for a type. */
const char *sg_reg_domain_for(const char *type_name);

/* Validate a value against its kind. Returns 1 if valid, 0 if not. */
int sg_reg_validate_value(const char *type_name, const char *key, const char *val);

/* Validate an entry ID. Returns 1 if valid, 0 if not. */
int sg_reg_validate_entry_id(const char *type_name, const char *id);

/* Cross-field semantic check on a FULL entry ("key=val\n" form), e.g.
 * firewall_address type↔subnet/fqdn consistency.  Returns 0 if OK,
 * -1 with a message in errbuf otherwise. */
int sg_check_entry_semantics(const char *type_name, const char *data,
                             char *errbuf, size_t errsz);

/* ── Reference metadata ──────────────────────────────────────────────── */

typedef struct {
	const char *type;      /* referencing type, e.g. "firewall_policy" */
	const char *key;       /* referencing field, e.g. "srcaddr" */
} sg_ref_entry_t;

/* Find all fields that reference target_type via ref: or ref-or: kinds.
 * Fills 'out' up to 'max' entries. Returns count written. */
int sg_reg_find_referencing(const char *target_type,
                            sg_ref_entry_t *out, int max);

/* Parse "ref:TYPE" or "ref-or:TYPE:opts" kind string.
 * Returns 1 if kind is a ref kind, 0 otherwise. */
int sg_parse_ref_kind(const char *kind,
                      char *ref_type, size_t ref_sz,
                      char *opts, size_t opts_sz);

#endif /* SG_VALIDATE_H */
