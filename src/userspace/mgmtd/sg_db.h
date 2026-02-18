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

#define SG_DB_PATH "/etc/stargazer/stargazer.db"

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
 * Parse a section string "type:id" into type and id buffers.
 * If no colon, id is set to "0" (single config type).
 */
void sg_db_parse_section(const char *section, char *type, size_t tsz,
			 char *id, size_t isz);

#endif /* SG_DB_H */
