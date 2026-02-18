/* SPDX-License-Identifier: MIT */
/*
 * cli_registry.h — Config type/key registry for Stargazer CLI
 *
 * Static tables of config types, valid keys, default values, required
 * fields, and validation rules. Compiled into the CLI binary.
 */

#ifndef CLI_REGISTRY_H
#define CLI_REGISTRY_H

typedef enum { CFG_TABLE, CFG_SINGLE } cfg_mode_t;

/* Lookup config type mode. Returns -1 if unknown. */
int reg_type_mode(const char *type_name);

/* Get human-readable label for type (e.g. "firewall policy"). */
const char *reg_type_label(const char *type_name);

/* Get space-separated list of valid keys for a type. Returns "" if unknown. */
const char *reg_valid_keys(const char *type_name);

/* Check if key is valid for type. Returns 1 if valid, 0 if not. */
int reg_is_valid_key(const char *type_name, const char *key);

/* Get space-separated list of required keys. Returns "" if none. */
const char *reg_required_keys(const char *type_name);

/* Get default values as "key=val\nkey=val\n..." string. Returns "" if none. */
const char *reg_default_values(const char *type_name);

/* Get validation kind string for a type:key pair (e.g. "enum:enable,disable"). */
const char *reg_value_kind(const char *type_name, const char *key);

/* Get human-readable validation rule description. */
const char *reg_value_rule(const char *type_name, const char *key);

/* Get entry ID rule for a type ("uint" or "safe-id"). */
const char *reg_entry_id_kind(const char *type_name);

/* Get domain file path for a type. */
const char *reg_domain_for(const char *type_name);

/* Validate a value against its kind. Returns 1 if valid, 0 if not. */
int reg_validate_value(const char *type_name, const char *key, const char *val);

/* Validate an entry ID. Returns 1 if valid, 0 if not. */
int reg_validate_entry_id(const char *type_name, const char *id);

/* Pure validation helpers. */
int is_safe_id(const char *s);
int is_ipv4(const char *s);
int is_cidr(const char *s);
int is_iface_name(const char *s);
int is_uint_range(const char *s, int min, int max);

#endif /* CLI_REGISTRY_H */
