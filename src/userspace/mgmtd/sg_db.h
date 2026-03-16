/* SPDX-License-Identifier: MIT */
/*
 * sg_db.h — SQLite config storage for Stargazer mgmtd
 *
 * Replaces flat-file INI config with a normalized SQLite database.
 * Schema: config(type, id, key, value) — one row per key=value pair.
 * Single config types (no entry ID) use id="0".
 *
 * All returned strings are heap-allocated; caller must free().
 * Return formats match the old cfg_* functions for IPC compatibility.
 */

#ifndef SG_DB_H
#define SG_DB_H

#include <stddef.h>

#ifndef SG_DB_PATH
#define SG_DB_PATH "/etc/stargazer/stargazer.db"
#endif

/*
 * Open (or create) the database at 'path'.
 * Creates schema if the file is new.
 * Returns 0 on success, -1 on error (logged to stderr).
 */
int sg_db_open(const char *path);

/*
 * Close the database handle. Safe to call if not open.
 */
void sg_db_close(void);

/*
 * Get all key=value pairs for a (type, id) entry.
 * Returns heap string "key=val\nkey=val\n" or NULL if not found.
 * Caller must free().
 */
char *sg_db_get(const char *type, const char *id);

/*
 * Set (replace) all key=value pairs for a (type, id) entry.
 * 'data' is "key=val\nkey=val\n" format.
 * Deletes existing rows and inserts new ones in a transaction.
 * Keys are written in field_table registry order; any keys not found in
 * the registry are appended after, preserving their relative order.
 * This ensures sg_db_get() always returns keys in a stable, predictable
 * order regardless of which key was configured first.
 * Returns 0 on success, -1 on error.
 */
int sg_db_set(const char *type, const char *id, const char *data);

/*
 * Delete all rows for a (type, id) entry.
 * Returns 0 on success (even if nothing deleted), -1 on error.
 */
int sg_db_del(const char *type, const char *id);

/*
 * List all entry IDs for a given type.
 * Returns heap string "id1\nid2\n" or NULL if none found.
 * Caller must free().
 */
char *sg_db_list(const char *type);

/*
 * Get a single value by (type, id, key).
 * Returns heap string or NULL if not found. Caller must free().
 */
char *sg_db_get_val(const char *type, const char *id, const char *key);

/*
 * Set a single value by (type, id, key).
 * Inserts or replaces the row. Returns 0 on success, -1 on error.
 */
int sg_db_set_val(const char *type, const char *id, const char *key,
		  const char *value);

/*
 * Check if any rows exist for a given type.
 * Returns count of distinct IDs, or 0 if none.
 */
int sg_db_count(const char *type);

/*
 * Return the current schema version of the open database.
 * Returns -1 if the database is not open.
 */
int sg_db_schema_version(void);

/*
 * Parse a section string "type:id" into type and id buffers.
 * If no colon, id is set to "0" (single config type).
 */
void sg_db_parse_section(const char *section, char *type, size_t tsz,
			 char *id, size_t isz);

/*
 * Find all entries of a given type where a key matches a value.
 * Returns heap-allocated "type:id\n..." string of matching entries,
 * or NULL if none found.  Caller must free().
 */
char *sg_db_find_referencing(const char *ref_type, const char *ref_key,
			     const char *target_value);

/*
 * List all distinct config types present in the database.
 * Returns heap string "type1\ntype2\n" or NULL if none.
 * Caller must free().
 */
char *sg_db_list_types(void);

/*
 * Delete all rows for a given config type.
 * Returns 0 on success, -1 on error.
 */
int sg_db_purge_type(const char *type);

/* ── Auth lockout helpers ────────────────────────────────────────────────── */

/*
 * Get lockout state for a user.
 * Sets *fail_count and *locked_until (Unix epoch).
 * Returns 0 on success, -1 on error.
 */
int sg_db_lockout_get(const char *username, int *fail_count,
		      long *locked_until);

/*
 * Set lockout state for a user (upsert).
 * Returns 0 on success, -1 on error.
 */
int sg_db_lockout_set(const char *username, int fail_count,
		      long locked_until);

/*
 * Clear lockout state for a user (on successful login).
 * Returns 0 on success, -1 on error.
 */
int sg_db_lockout_clear(const char *username);

#endif /* SG_DB_H */
