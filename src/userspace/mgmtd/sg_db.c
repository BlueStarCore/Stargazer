/* SPDX-License-Identifier: MIT */
/*
 * sg_db.c — SQLite config storage for Stargazer mgmtd
 *
 * Normalized schema: config(type, id, key, value).
 * Each key=value pair from a config section is one row.
 * All mutations wrapped in transactions for atomicity.
 */

#define _POSIX_C_SOURCE 200809L

#include "sg_db.h"
#include "sqlite3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Database handle ─────────────────────────────────────────────────────── */

static sqlite3 *g_db;

/* ── Schema ──────────────────────────────────────────────────────────────── */

static const char *SCHEMA_SQL =
	"CREATE TABLE IF NOT EXISTS config ("
	"  type  TEXT NOT NULL,"
	"  id    TEXT NOT NULL,"
	"  key   TEXT NOT NULL,"
	"  value TEXT NOT NULL DEFAULT '',"
	"  PRIMARY KEY (type, id, key)"
	");"
	"CREATE INDEX IF NOT EXISTS idx_config_type ON config(type);"
	"CREATE INDEX IF NOT EXISTS idx_config_type_id ON config(type, id);"
	/* Auth lockout tracking (used by stargazer-login via sqlite3 CLI) */
	"CREATE TABLE IF NOT EXISTS auth_lockouts ("
	"  username     TEXT PRIMARY KEY,"
	"  fail_count   INTEGER NOT NULL DEFAULT 0,"
	"  locked_until INTEGER NOT NULL DEFAULT 0,"
	"  updated_at   TEXT"
	");";

/* ── Open / Close ────────────────────────────────────────────────────────── */

int sg_db_open(const char *path)
{
	if (g_db)
		return 0; /* already open */

	int rc = sqlite3_open(path, &g_db);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "sg_db: open %s: %s\n",
			path, sqlite3_errmsg(g_db));
		g_db = NULL;
		return -1;
	}

	/* WAL mode for better concurrency (CLI reads while mgmtd writes) */
	sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
	/* Enforce foreign keys if we add them later */
	sqlite3_exec(g_db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);

	/* Create schema */
	char *errmsg = NULL;
	rc = sqlite3_exec(g_db, SCHEMA_SQL, NULL, NULL, &errmsg);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "sg_db: schema: %s\n", errmsg);
		sqlite3_free(errmsg);
		sqlite3_close(g_db);
		g_db = NULL;
		return -1;
	}

	return 0;
}

void sg_db_close(void)
{
	if (g_db) {
		sqlite3_close(g_db);
		g_db = NULL;
	}
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */

void sg_db_parse_section(const char *section, char *type, size_t tsz,
			 char *id, size_t isz)
{
	const char *colon = strchr(section, ':');
	if (colon) {
		size_t tlen = (size_t)(colon - section);
		if (tlen >= tsz) tlen = tsz - 1;
		memcpy(type, section, tlen);
		type[tlen] = '\0';

		const char *idp = colon + 1;
		size_t ilen = strlen(idp);
		if (ilen >= isz) ilen = isz - 1;
		memcpy(id, idp, ilen);
		id[ilen] = '\0';
	} else {
		size_t slen = strlen(section);
		if (slen >= tsz) slen = tsz - 1;
		memcpy(type, section, slen);
		type[slen] = '\0';
		snprintf(id, isz, "0");
	}
}

/*
 * Append a string fragment to a dynamically-growing buffer.
 * Updates *buf, *used, *bufsz. Returns 0 on success, -1 on OOM.
 */
static int buf_append(char **buf, size_t *used, size_t *bufsz,
		      const char *str, size_t len)
{
	while (*used + len + 1 > *bufsz) {
		*bufsz *= 2;
		char *nb = realloc(*buf, *bufsz);
		if (!nb) return -1;
		*buf = nb;
	}
	memcpy(*buf + *used, str, len);
	*used += len;
	(*buf)[*used] = '\0';
	return 0;
}

/* ── sg_db_get ───────────────────────────────────────────────────────────── */

char *sg_db_get(const char *type, const char *id)
{
	if (!g_db || !type || !id) return NULL;

	sqlite3_stmt *stmt;
	const char *sql = "SELECT key, value FROM config "
			  "WHERE type=?1 AND id=?2 ORDER BY rowid;";
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return NULL;

	sqlite3_bind_text(stmt, 1, type, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, id, -1, SQLITE_STATIC);

	size_t bufsz = 1024, used = 0;
	char *buf = malloc(bufsz);
	if (!buf) { sqlite3_finalize(stmt); return NULL; }
	buf[0] = '\0';

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char *k = (const char *)sqlite3_column_text(stmt, 0);
		const char *v = (const char *)sqlite3_column_text(stmt, 1);
		if (!k) continue;
		if (!v) v = "";

		/* Append "key=value\n" */
		size_t klen = strlen(k);
		size_t vlen = strlen(v);

		if (buf_append(&buf, &used, &bufsz, k, klen) < 0 ||
		    buf_append(&buf, &used, &bufsz, "=", 1) < 0 ||
		    buf_append(&buf, &used, &bufsz, v, vlen) < 0 ||
		    buf_append(&buf, &used, &bufsz, "\n", 1) < 0) {
			free(buf);
			sqlite3_finalize(stmt);
			return NULL;
		}
	}

	sqlite3_finalize(stmt);

	if (used == 0) {
		free(buf);
		return NULL;
	}
	return buf;
}

/* ── sg_db_set ───────────────────────────────────────────────────────────── */

int sg_db_set(const char *type, const char *id, const char *data)
{
	if (!g_db || !type || !id) return -1;

	sqlite3_exec(g_db, "BEGIN;", NULL, NULL, NULL);

	/* Delete existing rows for this entry */
	sqlite3_stmt *del;
	const char *del_sql = "DELETE FROM config WHERE type=?1 AND id=?2;";
	if (sqlite3_prepare_v2(g_db, del_sql, -1, &del, NULL) != SQLITE_OK) {
		sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
		return -1;
	}
	sqlite3_bind_text(del, 1, type, -1, SQLITE_STATIC);
	sqlite3_bind_text(del, 2, id, -1, SQLITE_STATIC);
	sqlite3_step(del);
	sqlite3_finalize(del);

	/* Insert new rows from "key=val\nkey=val\n" data */
	if (data && data[0]) {
		sqlite3_stmt *ins;
		const char *ins_sql =
			"INSERT INTO config(type, id, key, value) "
			"VALUES(?1, ?2, ?3, ?4);";
		if (sqlite3_prepare_v2(g_db, ins_sql, -1, &ins, NULL) != SQLITE_OK) {
			sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
			return -1;
		}

		const char *p = data;
		while (*p) {
			/* Skip blank lines */
			if (*p == '\n') { p++; continue; }

			const char *eol = strchr(p, '\n');
			size_t llen = eol ? (size_t)(eol - p) : strlen(p);

			/* Find '=' separator */
			const char *eq = memchr(p, '=', llen);
			if (eq) {
				size_t klen = (size_t)(eq - p);
				const char *val = eq + 1;
				size_t vlen = llen - klen - 1;

				sqlite3_reset(ins);
				sqlite3_bind_text(ins, 1, type, -1, SQLITE_STATIC);
				sqlite3_bind_text(ins, 2, id, -1, SQLITE_STATIC);
				sqlite3_bind_text(ins, 3, p, (int)klen, SQLITE_STATIC);
				sqlite3_bind_text(ins, 4, val, (int)vlen, SQLITE_STATIC);

				if (sqlite3_step(ins) != SQLITE_DONE) {
					sqlite3_finalize(ins);
					sqlite3_exec(g_db, "ROLLBACK;",
						     NULL, NULL, NULL);
					return -1;
				}
			}

			p += llen;
			if (eol) p++;
		}
		sqlite3_finalize(ins);
	}

	sqlite3_exec(g_db, "COMMIT;", NULL, NULL, NULL);
	return 0;
}

/* ── sg_db_del ───────────────────────────────────────────────────────────── */

int sg_db_del(const char *type, const char *id)
{
	if (!g_db || !type || !id) return -1;

	sqlite3_stmt *stmt;
	const char *sql = "DELETE FROM config WHERE type=?1 AND id=?2;";
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return -1;

	sqlite3_bind_text(stmt, 1, type, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, id, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	return (rc == SQLITE_DONE) ? 0 : -1;
}

/* ── sg_db_list ──────────────────────────────────────────────────────────── */

char *sg_db_list(const char *type)
{
	if (!g_db || !type) return NULL;

	sqlite3_stmt *stmt;
	const char *sql = "SELECT DISTINCT id FROM config "
			  "WHERE type=?1 ORDER BY id;";
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return NULL;

	sqlite3_bind_text(stmt, 1, type, -1, SQLITE_STATIC);

	size_t bufsz = 1024, used = 0;
	char *buf = malloc(bufsz);
	if (!buf) { sqlite3_finalize(stmt); return NULL; }
	buf[0] = '\0';

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char *id = (const char *)sqlite3_column_text(stmt, 0);
		if (!id) continue;
		/* Skip synthetic "0" IDs (single config types) */
		if (strcmp(id, "0") == 0) continue;

		size_t ilen = strlen(id);
		if (buf_append(&buf, &used, &bufsz, id, ilen) < 0 ||
		    buf_append(&buf, &used, &bufsz, "\n", 1) < 0) {
			free(buf);
			sqlite3_finalize(stmt);
			return NULL;
		}
	}

	sqlite3_finalize(stmt);

	if (used == 0) {
		free(buf);
		return NULL;
	}
	return buf;
}

/* ── sg_db_get_val ───────────────────────────────────────────────────────── */

char *sg_db_get_val(const char *type, const char *id, const char *key)
{
	if (!g_db || !type || !id || !key) return NULL;

	sqlite3_stmt *stmt;
	const char *sql = "SELECT value FROM config "
			  "WHERE type=?1 AND id=?2 AND key=?3 LIMIT 1;";
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return NULL;

	sqlite3_bind_text(stmt, 1, type, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, id, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, key, -1, SQLITE_STATIC);

	char *result = NULL;
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		const char *v = (const char *)sqlite3_column_text(stmt, 0);
		if (v)
			result = strdup(v);
	}

	sqlite3_finalize(stmt);
	return result;
}

/* ── sg_db_set_val ───────────────────────────────────────────────────────── */

int sg_db_set_val(const char *type, const char *id, const char *key,
		  const char *value)
{
	if (!g_db || !type || !id || !key || !value) return -1;

	sqlite3_stmt *stmt;
	const char *sql =
		"INSERT OR REPLACE INTO config(type, id, key, value) "
		"VALUES(?1, ?2, ?3, ?4);";
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return -1;

	sqlite3_bind_text(stmt, 1, type, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, id, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, key, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 4, value, -1, SQLITE_STATIC);

	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	return (rc == SQLITE_DONE) ? 0 : -1;
}

/* ── sg_db_find_referencing ───────────────────────────────────────────────── */

char *sg_db_find_referencing(const char *ref_type, const char *ref_key,
			     const char *target_value)
{
	if (!g_db || !ref_type || !ref_key || !target_value) return NULL;

	sqlite3_stmt *stmt;
	const char *sql = "SELECT DISTINCT id FROM config "
			  "WHERE type=?1 AND key=?2 AND value=?3;";
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return NULL;

	sqlite3_bind_text(stmt, 1, ref_type, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, ref_key, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, target_value, -1, SQLITE_STATIC);

	size_t bufsz = 256, used = 0;
	char *buf = malloc(bufsz);
	if (!buf) { sqlite3_finalize(stmt); return NULL; }
	buf[0] = '\0';

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char *id = (const char *)sqlite3_column_text(stmt, 0);
		if (!id) continue;

		/* Append "type:id\n" */
		size_t tlen = strlen(ref_type);
		size_t ilen = strlen(id);

		if (buf_append(&buf, &used, &bufsz, ref_type, tlen) < 0 ||
		    buf_append(&buf, &used, &bufsz, ":", 1) < 0 ||
		    buf_append(&buf, &used, &bufsz, id, ilen) < 0 ||
		    buf_append(&buf, &used, &bufsz, "\n", 1) < 0) {
			free(buf);
			sqlite3_finalize(stmt);
			return NULL;
		}
	}

	sqlite3_finalize(stmt);

	if (used == 0) {
		free(buf);
		return NULL;
	}
	return buf;
}

/* ── sg_db_count ─────────────────────────────────────────────────────────── */

int sg_db_count(const char *type)
{
	if (!g_db || !type) return 0;

	sqlite3_stmt *stmt;
	const char *sql = "SELECT COUNT(DISTINCT id) FROM config WHERE type=?1;";
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;

	sqlite3_bind_text(stmt, 1, type, -1, SQLITE_STATIC);

	int count = 0;
	if (sqlite3_step(stmt) == SQLITE_ROW)
		count = sqlite3_column_int(stmt, 0);

	sqlite3_finalize(stmt);
	return count;
}
