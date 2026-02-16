-- Stargazer NGFW control-plane schema (Phase B bootstrap)
-- SQLite schema for auth/admin objects. Future phases will migrate rules and objects.

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
	username TEXT PRIMARY KEY,
	profile  TEXT NOT NULL,
	enforce_change_password INTEGER NOT NULL DEFAULT 0,
	builtin  INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT (datetime('now')),
	updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS profiles (
	name TEXT PRIMARY KEY,
	permissions TEXT NOT NULL,
	description TEXT,
	builtin INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT (datetime('now')),
	updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS auth_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL DEFAULT (datetime('now')),
	username TEXT,
	event TEXT NOT NULL,
	message TEXT
);

CREATE TABLE IF NOT EXISTS config_objects (
	type TEXT NOT NULL,
	object_id TEXT NOT NULL,
	domain_file TEXT,
	data TEXT,
	updated_at TEXT NOT NULL DEFAULT (datetime('now')),
	PRIMARY KEY(type, object_id)
);

CREATE TABLE IF NOT EXISTS firewall_policies (
	id TEXT PRIMARY KEY,
	name TEXT,
	srcintf TEXT,
	dstintf TEXT,
	srcaddr TEXT,
	dstaddr TEXT,
	action TEXT,
	service TEXT,
	schedule TEXT,
	status TEXT,
	comment TEXT,
	updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS firewall_addresses (
	id TEXT PRIMARY KEY,
	name TEXT,
	subnet TEXT,
	type TEXT,
	comment TEXT,
	updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS firewall_services (
	id TEXT PRIMARY KEY,
	name TEXT,
	protocol TEXT,
	port_range TEXT,
	comment TEXT,
	updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS config_revisions (
	rev INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL DEFAULT (datetime('now')),
	author TEXT,
	message TEXT
);

CREATE TABLE IF NOT EXISTS config_revision_files (
	rev INTEGER NOT NULL,
	domain_file TEXT NOT NULL,
	content TEXT,
	PRIMARY KEY(rev, domain_file),
	FOREIGN KEY(rev) REFERENCES config_revisions(rev) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth_lockouts (
	username TEXT PRIMARY KEY,
	fail_count INTEGER NOT NULL DEFAULT 0,
	locked_until INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_auth_events_user ON auth_events(username);
CREATE INDEX IF NOT EXISTS idx_auth_events_ts ON auth_events(ts);
CREATE INDEX IF NOT EXISTS idx_config_objects_type ON config_objects(type);
CREATE INDEX IF NOT EXISTS idx_cfg_rev_files_rev ON config_revision_files(rev);
