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

/* ── Pure validators ──────────────────────────────────────────────────── */

int sg_is_safe_id(const char *s);
int sg_is_ipv4(const char *s);
int sg_is_cidr(const char *s);
int sg_is_iface_name(const char *s);
int sg_is_uint_range(const char *s, int min, int max);
int sg_is_tz_token(const char *s);
int sg_is_permissions_csv(const char *s);
int sg_is_port_or_range(const char *s);
int sg_match_csv_option(const char *opts, const char *val);

/* ── Registry lookups ─────────────────────────────────────────────────── */

/* Lookup config type mode. Returns -1 if unknown. */
int sg_reg_type_mode(const char *type_name);

/* Get human-readable label for type (e.g. "firewall policy"). */
const char *sg_reg_type_label(const char *type_name);

/* Get space-separated list of valid keys for a type. Returns "" if unknown. */
const char *sg_reg_valid_keys(const char *type_name);

/* Check if key is valid for type. Returns 1 if valid, 0 if not. */
int sg_reg_is_valid_key(const char *type_name, const char *key);

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

/* Get entry ID rule for a type ("uint" or "safe-id"). */
const char *sg_reg_entry_id_kind(const char *type_name);

/* Get domain file path for a type. */
const char *sg_reg_domain_for(const char *type_name);

/* Validate a value against its kind. Returns 1 if valid, 0 if not. */
int sg_reg_validate_value(const char *type_name, const char *key, const char *val);

/* Validate an entry ID. Returns 1 if valid, 0 if not. */
int sg_reg_validate_entry_id(const char *type_name, const char *id);

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
