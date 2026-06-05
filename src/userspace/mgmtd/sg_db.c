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
#include "sg_validate.h"
#include "sqlite3.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Database handle ─────────────────────────────────────────────────────── */

static sqlite3 *g_db;

/* ── Schema version & hash ───────────────────────────────────────────────── */

#define SG_SCHEMA_VERSION  2
#define SG_SCHEMA_HASH     "8ed796ca"

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
	"  updated_at   TEXT NOT NULL DEFAULT (datetime('now'))"
	");"
	/* Config revisions: each revision is a full snapshot of the config
	 * table, used by configure commit/revisions/rollback. */
	"CREATE TABLE IF NOT EXISTS revisions ("
	"  rev     INTEGER PRIMARY KEY AUTOINCREMENT,"
	"  ts      TEXT NOT NULL DEFAULT (datetime('now')),"
	"  author  TEXT NOT NULL DEFAULT '',"
	"  message TEXT NOT NULL DEFAULT ''"
	");"
	"CREATE TABLE IF NOT EXISTS revision_config ("
	"  rev   INTEGER NOT NULL,"
	"  type  TEXT NOT NULL,"
	"  id    TEXT NOT NULL,"
	"  key   TEXT NOT NULL,"
	"  value TEXT NOT NULL DEFAULT '',"
	"  PRIMARY KEY (rev, type, id, key)"
	");";

/* ── Schema hash safety check ────────────────────────────────────────────── */

static uint32_t schema_djb2(const char *s)
{
	uint32_t h = 5381;
	while (*s)
		h = h * 33 + (unsigned char)*s++;
	return h;
}

/* ── Schema version tracking ─────────────────────────────────────────────── */

static int sg_db_get_version(void)
{
	if (!g_db) return -1;

	sqlite3_stmt *stmt;
	if (sqlite3_prepare_v2(g_db, "PRAGMA user_version;",
			       -1, &stmt, NULL) != SQLITE_OK)
		return -1;

	int ver = 0;
	if (sqlite3_step(stmt) == SQLITE_ROW)
		ver = sqlite3_column_int(stmt, 0);
	sqlite3_finalize(stmt);
	return ver;
}

static int sg_db_set_version(int ver)
{
	if (!g_db) return -1;

	char sql[64];
	snprintf(sql, sizeof(sql), "PRAGMA user_version = %d;", ver);
	return sqlite3_exec(g_db, sql, NULL, NULL, NULL) == SQLITE_OK
		? 0 : -1;
}

static int sg_db_migrate(void)
{
	int db_ver = sg_db_get_version();
	if (db_ver == SG_SCHEMA_VERSION)
		return 0;  /* no migration needed */

	/* Wrap all migrations in a transaction */
	if (sqlite3_exec(g_db, "BEGIN;", NULL, NULL, NULL) != SQLITE_OK)
		return -1;

	/* Forward migrations (upgrade) */
	if (db_ver < 1) {
		/* v0 -> v1: initial schema stamp (tables already created) */
	}
	/* Future: if (db_ver < 2) { ALTER TABLE ADD COLUMN ...; } */

	/* Downgrade: log warning, stamp version.
	 * SQLite ignores unknown columns in SELECT/INSERT,
	 * so extra columns from a newer schema are harmless. */
	if (db_ver > SG_SCHEMA_VERSION)
		fprintf(stderr, "sg_db: DB schema v%d > code v%d"
			" (downgrade)\n", db_ver, SG_SCHEMA_VERSION);

	if (sg_db_set_version(SG_SCHEMA_VERSION) != 0) {
		sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
		return -1;
	}

	if (sqlite3_exec(g_db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
		sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
		return -1;
	}
	return 0;
}

/* ── Open / Close ────────────────────────────────────────────────────────── */

int sg_db_open(const char *path)
{
	if (g_db)
		return 0; /* already open */

	int rc = sqlite3_open(path, &g_db);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "sg_db: open %s: %s\n",
			path, sqlite3_errmsg(g_db));
		sqlite3_close(g_db);  /* sqlite3_open may alloc even on failure */
		g_db = NULL;
		return -1;
	}

	/* WAL mode for better concurrency (CLI reads while mgmtd writes) */
	sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
	/* Enforce foreign keys if we add them later */
	sqlite3_exec(g_db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);

	/* Schema hash safety check — catch drift before anything runs */
	{
		char computed[16];
		snprintf(computed, sizeof(computed), "%08x",
			 schema_djb2(SCHEMA_SQL));
		if (strcmp(computed, SG_SCHEMA_HASH) != 0)
			fprintf(stderr, "sg_db: SCHEMA_SQL changed but"
				" SG_SCHEMA_HASH not updated."
				" Current hash: %s."
				" Update SG_SCHEMA_HASH and bump"
				" SG_SCHEMA_VERSION.\n", computed);
	}

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

	/* Run migrations */
	if (sg_db_migrate() != 0) {
		fprintf(stderr, "sg_db: migration failed\n");
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

/* ── Key-ordered insert helper ───────────────────────────────────────────── */

#define MAX_KV_PAIRS 64

struct kv_entry {
	const char *key;
	int         klen;
	const char *val;
	int         vlen;
	int         done;  /* 1 once inserted */
};

/*
 * Parse 'data' into kv[], then insert rows via 'ins' in field_table registry
 * order for 'type'.  Keys absent from the registry are appended afterwards,
 * preserving their original relative order.
 * Returns 0 on success, -1 if any sqlite3_step() fails.
 */
static int sg_insert_ordered(sqlite3_stmt *ins,
			     const char *type, const char *id,
			     const char *data)
{
	struct kv_entry kv[MAX_KV_PAIRS];
	int nkv = 0;

	/* Step 1: parse "key=val\n..." → kv[] */
	const char *p = data;
	while (*p && nkv < MAX_KV_PAIRS) {
		if (*p == '\n') { p++; continue; }

		const char *eol  = strchr(p, '\n');
		size_t      llen = eol ? (size_t)(eol - p) : strlen(p);
		const char *eq   = memchr(p, '=', llen);
		if (eq) {
			int kl = (int)(eq - p);
			kv[nkv].key  = p;
			kv[nkv].klen = kl;
			kv[nkv].val  = eq + 1;
			kv[nkv].vlen = (int)(llen - (size_t)kl - 1);
			kv[nkv].done = 0;
			nkv++;
		}
		p += llen;
		if (eol) p++;
	}

	/* Step 2: insert in registry order */
	const char *rp = sg_reg_valid_keys(type);
	while (rp && *rp) {
		while (*rp == ' ') rp++;
		if (!*rp) break;
		const char *rend = rp;
		while (*rend && *rend != ' ') rend++;
		int rlen = (int)(rend - rp);

		for (int i = 0; i < nkv; i++) {
			if (kv[i].done || kv[i].klen != rlen)
				continue;
			if (memcmp(kv[i].key, rp, (size_t)rlen) != 0)
				continue;
			sqlite3_reset(ins);
			sqlite3_bind_text(ins, 1, type, -1, SQLITE_STATIC);
			sqlite3_bind_text(ins, 2, id, -1, SQLITE_STATIC);
			sqlite3_bind_text(ins, 3, kv[i].key, kv[i].klen,
					  SQLITE_STATIC);
			sqlite3_bind_text(ins, 4, kv[i].val, kv[i].vlen,
					  SQLITE_STATIC);
			if (sqlite3_step(ins) != SQLITE_DONE)
				return -1;
			kv[i].done = 1;
			break;
		}
		rp = rend;
	}

	/* Step 3: append any keys not found in the registry */
	for (int i = 0; i < nkv; i++) {
		if (kv[i].done) continue;
		sqlite3_reset(ins);
		sqlite3_bind_text(ins, 1, type, -1, SQLITE_STATIC);
		sqlite3_bind_text(ins, 2, id, -1, SQLITE_STATIC);
		sqlite3_bind_text(ins, 3, kv[i].key, kv[i].klen, SQLITE_STATIC);
		sqlite3_bind_text(ins, 4, kv[i].val, kv[i].vlen, SQLITE_STATIC);
		if (sqlite3_step(ins) != SQLITE_DONE)
			return -1;
	}

	return 0;
}

/* ── sg_db_set ───────────────────────────────────────────────────────────── */

int sg_db_set(const char *type, const char *id, const char *data)
{
	if (!g_db || !type || !id) return -1;

	if (sqlite3_exec(g_db, "BEGIN;", NULL, NULL, NULL) != SQLITE_OK)
		return -1;

	/* Delete existing rows for this entry */
	sqlite3_stmt *del;
	const char *del_sql = "DELETE FROM config WHERE type=?1 AND id=?2;";
	if (sqlite3_prepare_v2(g_db, del_sql, -1, &del, NULL) != SQLITE_OK) {
		sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
		return -1;
	}
	sqlite3_bind_text(del, 1, type, -1, SQLITE_STATIC);
	sqlite3_bind_text(del, 2, id, -1, SQLITE_STATIC);
	if (sqlite3_step(del) != SQLITE_DONE) {
		sqlite3_finalize(del);
		sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
		return -1;
	}
	sqlite3_finalize(del);

	/* Insert new rows in field_table registry order */
	if (data && data[0]) {
		sqlite3_stmt *ins;
		const char *ins_sql =
			"INSERT INTO config(type, id, key, value) "
			"VALUES(?1, ?2, ?3, ?4);";
		if (sqlite3_prepare_v2(g_db, ins_sql, -1, &ins, NULL) != SQLITE_OK) {
			sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
			return -1;
		}

		if (sg_insert_ordered(ins, type, id, data) != 0) {
			sqlite3_finalize(ins);
			sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
			return -1;
		}
		sqlite3_finalize(ins);
	}

	if (sqlite3_exec(g_db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
		sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL);
		return -1;
	}
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

/* ── sg_db_list_ordered ───────────────────────────────────────────────────── */

char *sg_db_list_ordered(const char *type, const char *order_key)
{
	if (!g_db || !type || !order_key) return NULL;

	sqlite3_stmt *stmt;
	/*
	 * Left-join: every distinct ID gets a row even if it lacks the
	 * order_key.  COALESCE puts missing keys at 0 (lowest priority).
	 * CAST to INTEGER for numeric sort (not lexicographic).
	 * DESC: higher sequence = higher priority = applied first.
	 * Boot replay inserts with -I (insert at position), so the
	 * highest-priority rule must be inserted first to end up at
	 * the top of the chain.
	 */
	const char *sql =
		"SELECT DISTINCT c.id FROM config c "
		"LEFT JOIN config seq ON seq.type = c.type "
		"  AND seq.id = c.id AND seq.key = ?2 "
		"WHERE c.type = ?1 AND c.id != '0' "
		"ORDER BY CAST(COALESCE(seq.value, '0') AS INTEGER) DESC, "
		"         c.id;";
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return NULL;

	sqlite3_bind_text(stmt, 1, type, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, order_key, -1, SQLITE_STATIC);

	size_t bufsz = 1024, used = 0;
	char *buf = malloc(bufsz);
	if (!buf) { sqlite3_finalize(stmt); return NULL; }
	buf[0] = '\0';

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char *id = (const char *)sqlite3_column_text(stmt, 0);
		if (!id) continue;

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

/* ── sg_db_get_max_int ───────────────────────────────────────────────────── */

char *sg_db_get_max_int(const char *type, const char *key)
{
	if (!g_db || !type || !key) return NULL;

	sqlite3_stmt *stmt;
	const char *sql =
		"SELECT MAX(CAST(value AS INTEGER)) FROM config "
		"WHERE type=?1 AND key=?2;";
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return NULL;

	sqlite3_bind_text(stmt, 1, type, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, key, -1, SQLITE_STATIC);

	char *result = NULL;
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		const char *v = (const char *)sqlite3_column_text(stmt, 0);
		if (v)
			result = strdup(v);
	}

	sqlite3_finalize(stmt);
	return result;
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

/* ── sg_db_list_types ────────────────────────────────────────────────────── */

char *sg_db_list_types(void)
{
	if (!g_db) return NULL;

	sqlite3_stmt *stmt;
	const char *sql = "SELECT DISTINCT type FROM config ORDER BY type;";
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return NULL;

	size_t bufsz = 1024, used = 0;
	char *buf = malloc(bufsz);
	if (!buf) { sqlite3_finalize(stmt); return NULL; }
	buf[0] = '\0';

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char *t = (const char *)sqlite3_column_text(stmt, 0);
		if (!t) continue;

		size_t tlen = strlen(t);
		if (buf_append(&buf, &used, &bufsz, t, tlen) < 0 ||
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

/* ── sg_db_purge_type ───────────────────────────────────────────────────── */

int sg_db_purge_type(const char *type)
{
	if (!g_db || !type) return -1;

	sqlite3_stmt *stmt;
	const char *sql = "DELETE FROM config WHERE type=?1;";
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return -1;

	sqlite3_bind_text(stmt, 1, type, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	return (rc == SQLITE_DONE) ? 0 : -1;
}

/* ── sg_db_schema_version ────────────────────────────────────────────────── */

int sg_db_schema_version(void)
{
	return sg_db_get_version();
}

/* ── Auth lockout helpers ────────────────────────────────────────────────── */

int sg_db_lockout_get(const char *username, int *fail_count,
		      long *locked_until)
{
	if (!g_db || !username) return -1;
	*fail_count = 0;
	*locked_until = 0;

	sqlite3_stmt *stmt;
	const char *sql = "SELECT fail_count, locked_until "
			  "FROM auth_lockouts WHERE username=?1;";
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return -1;

	sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		*fail_count = sqlite3_column_int(stmt, 0);
		*locked_until = (long)sqlite3_column_int64(stmt, 1);
	}
	sqlite3_finalize(stmt);
	return 0;
}

int sg_db_lockout_set(const char *username, int fail_count,
		      long locked_until)
{
	if (!g_db || !username) return -1;

	sqlite3_stmt *stmt;
	const char *sql =
		"INSERT INTO auth_lockouts(username, fail_count, "
		"locked_until, updated_at) "
		"VALUES(?1, ?2, ?3, datetime('now')) "
		"ON CONFLICT(username) DO UPDATE SET "
		"fail_count=excluded.fail_count, "
		"locked_until=excluded.locked_until, "
		"updated_at=datetime('now');";
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return -1;

	sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 2, fail_count);
	sqlite3_bind_int64(stmt, 3, locked_until);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE) ? 0 : -1;
}

int sg_db_lockout_clear(const char *username)
{
	if (!g_db || !username) return -1;

	sqlite3_stmt *stmt;
	const char *sql = "DELETE FROM auth_lockouts WHERE username=?1;";
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return -1;

	sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE) ? 0 : -1;
}

int sg_db_lockout_clear_all(void)
{
	if (!g_db) return -1;

	sqlite3_stmt *stmt;
	const char *sql = "DELETE FROM auth_lockouts;";
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return -1;

	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE) ? 0 : -1;
}

/* ── Transaction helpers ─────────────────────────────────────────────────── */

int sg_db_begin(void)
{
	if (!g_db) return -1;
	return sqlite3_exec(g_db, "BEGIN;", NULL, NULL, NULL) == SQLITE_OK
		? 0 : -1;
}

int sg_db_commit(void)
{
	if (!g_db) return -1;
	return sqlite3_exec(g_db, "COMMIT;", NULL, NULL, NULL) == SQLITE_OK
		? 0 : -1;
}

int sg_db_rollback(void)
{
	if (!g_db) return -1;
	return sqlite3_exec(g_db, "ROLLBACK;", NULL, NULL, NULL) == SQLITE_OK
		? 0 : -1;
}

/* ── Config revisions (configure commit / revisions / rollback) ──────────── *
 *
 * A revision is a full snapshot of the `config` table tagged with a rev id.
 * sg_db_revision_create() snapshots the current config; sg_db_revision_restore()
 * replaces the config table with a revision's snapshot (atomic). The caller
 * (mgmtd) re-applies the restored DB to the kernel via mgmtd_replay_config().
 */

/*
 * sg_db_revision_create — snapshot the current config table as a new revision.
 * Returns the new rev number (> 0) on success, -1 on failure. Atomic.
 */
int sg_db_revision_create(const char *author, const char *message)
{
	if (!g_db) return -1;
	if (sg_db_begin() != 0) return -1;

	sqlite3_stmt *st;
	if (sqlite3_prepare_v2(g_db,
		"INSERT INTO revisions(author,message) VALUES(?1,?2);",
		-1, &st, NULL) != SQLITE_OK) {
		sg_db_rollback();
		return -1;
	}
	sqlite3_bind_text(st, 1, author ? author : "", -1, SQLITE_STATIC);
	sqlite3_bind_text(st, 2, message ? message : "", -1, SQLITE_STATIC);
	int rc = sqlite3_step(st);
	sqlite3_finalize(st);
	if (rc != SQLITE_DONE) { sg_db_rollback(); return -1; }

	long long rev = sqlite3_last_insert_rowid(g_db);

	char *errmsg = NULL;
	char sql[160];
	snprintf(sql, sizeof(sql),
		 "INSERT INTO revision_config(rev,type,id,key,value) "
		 "SELECT %lld,type,id,key,value FROM config;", rev);
	if (sqlite3_exec(g_db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
		sqlite3_free(errmsg);
		sg_db_rollback();
		return -1;
	}

	/* Prune to the most recent 50 revisions so the history (and its
	 * per-rev config snapshots) cannot grow without bound. */
	errmsg = NULL;
	sqlite3_exec(g_db,
		"DELETE FROM revision_config WHERE rev IN "
		"(SELECT rev FROM revisions ORDER BY rev DESC LIMIT -1 OFFSET 50);",
		NULL, NULL, &errmsg);
	if (errmsg) sqlite3_free(errmsg);
	errmsg = NULL;
	sqlite3_exec(g_db,
		"DELETE FROM revisions WHERE rev IN "
		"(SELECT rev FROM revisions ORDER BY rev DESC LIMIT -1 OFFSET 50);",
		NULL, NULL, &errmsg);
	if (errmsg) sqlite3_free(errmsg);

	if (sg_db_commit() != 0) { sg_db_rollback(); return -1; }
	return (int)rev;
}

/*
 * sg_db_revision_exists — 1 if the revision id exists, 0 otherwise.
 */
int sg_db_revision_exists(int rev)
{
	if (!g_db) return 0;
	sqlite3_stmt *st;
	if (sqlite3_prepare_v2(g_db, "SELECT 1 FROM revisions WHERE rev=?1;",
			       -1, &st, NULL) != SQLITE_OK)
		return 0;
	sqlite3_bind_int(st, 1, rev);
	int found = (sqlite3_step(st) == SQLITE_ROW);
	sqlite3_finalize(st);
	return found ? 1 : 0;
}

/*
 * sg_db_revision_list — newest-first list of revisions, one per line:
 *   "rev\tts\tauthor\tmessage\n"
 * Returns a heap string (caller frees), or NULL on error.
 */
char *sg_db_revision_list(void)
{
	if (!g_db) return NULL;
	sqlite3_stmt *st;
	if (sqlite3_prepare_v2(g_db,
		"SELECT rev,ts,author,message FROM revisions "
		"ORDER BY rev DESC LIMIT 100;", -1, &st, NULL) != SQLITE_OK)
		return NULL;

	size_t cap = 1024, len = 0;
	char *buf = malloc(cap);
	if (!buf) { sqlite3_finalize(st); return NULL; }
	buf[0] = '\0';

	while (sqlite3_step(st) == SQLITE_ROW) {
		int rev = sqlite3_column_int(st, 0);
		const char *ts  = (const char *)sqlite3_column_text(st, 1);
		const char *au  = (const char *)sqlite3_column_text(st, 2);
		const char *msg = (const char *)sqlite3_column_text(st, 3);
		char line[512];
		int n = snprintf(line, sizeof(line), "%d\t%s\t%s\t%s\n",
				 rev, ts ? ts : "", au ? au : "", msg ? msg : "");
		if (n < 0) continue;
		if ((size_t)n >= sizeof(line)) n = (int)sizeof(line) - 1;
		if (len + (size_t)n + 1 > cap) {
			while (len + (size_t)n + 1 > cap) cap *= 2;
			char *nb = realloc(buf, cap);
			if (!nb) { free(buf); sqlite3_finalize(st); return NULL; }
			buf = nb;
		}
		memcpy(buf + len, line, (size_t)n);
		len += (size_t)n;
		buf[len] = '\0';
	}
	sqlite3_finalize(st);
	return buf;
}

/*
 * sg_db_revision_restore — replace the config table with the snapshot stored
 * for `rev`. Atomic (all-or-nothing). Returns 0 on success, -1 on failure or
 * if the revision does not exist. The caller must re-apply the restored config
 * to the kernel afterwards.
 */
int sg_db_revision_restore(int rev)
{
	if (!g_db) return -1;
	if (!sg_db_revision_exists(rev)) return -1;
	if (sg_db_begin() != 0) return -1;

	char *errmsg = NULL;
	if (sqlite3_exec(g_db, "DELETE FROM config;", NULL, NULL, &errmsg)
	    != SQLITE_OK) {
		sqlite3_free(errmsg);
		sg_db_rollback();
		return -1;
	}

	sqlite3_stmt *st;
	if (sqlite3_prepare_v2(g_db,
		"INSERT INTO config(type,id,key,value) "
		"SELECT type,id,key,value FROM revision_config WHERE rev=?1;",
		-1, &st, NULL) != SQLITE_OK) {
		sg_db_rollback();
		return -1;
	}
	sqlite3_bind_int(st, 1, rev);
	int rc = sqlite3_step(st);
	sqlite3_finalize(st);
	if (rc != SQLITE_DONE) { sg_db_rollback(); return -1; }

	if (sg_db_commit() != 0) { sg_db_rollback(); return -1; }
	return 0;
}
