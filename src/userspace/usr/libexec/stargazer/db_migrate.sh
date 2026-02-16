#!/bin/sh
# Stargazer Phase C: migrate config data from INI files -> SQLite

CMD_DIR="${CMD_DIR:-/usr/libexec/stargazer}"
. "$CMD_DIR/config_lib.sh"

DB_PATH="${STARGAZER_CONF_DIR}/stargazer.db"
SCHEMA_FILE="$CMD_DIR/db_schema.sql"
SYS_CONF="${STARGAZER_CONF_DIR}/system.conf"
NET_CONF="${STARGAZER_CONF_DIR}/network.conf"
FW_CONF="${STARGAZER_CONF_DIR}/firewall.conf"

esc() {
	printf %s "$1" | sed "s/'/''/g"
}

if ! command -v sqlite3 >/dev/null 2>&1; then
	echo "[DB] sqlite3 not available; skipping migration."
	exit 0
fi

[ -f "$SCHEMA_FILE" ] || {
	echo "[DB] Schema file missing: $SCHEMA_FILE"
	exit 1
}

sqlite3 "$DB_PATH" < "$SCHEMA_FILE" || exit 1
# Backward-compatible schema upgrade for existing DB files
sqlite3 "$DB_PATH" "ALTER TABLE users ADD COLUMN enforce_change_password INTEGER NOT NULL DEFAULT 0;" >/dev/null 2>&1 || true

# Profiles
for p in $(cfg_list "$SYS_CONF" "system_admin-profile"); do
	data=$(cfg_get "$SYS_CONF" "system_admin-profile:${p}" 2>/dev/null)
	perms=$(echo "$data" | grep '^permissions=' | cut -d= -f2-)
	desc=$(echo "$data" | grep '^description=' | cut -d= -f2-)
	bi=$(echo "$data" | grep '^builtin=' | cut -d= -f2-)
	[ "$bi" = "yes" ] && bi_val=1 || bi_val=0
	sqlite3 "$DB_PATH" "INSERT INTO profiles(name, permissions, description, builtin, updated_at)
	VALUES('$(esc "$p")',
	       '$(esc "$perms")',
	       '$(esc "$desc")',
	       ${bi_val}, datetime('now'))
	ON CONFLICT(name) DO UPDATE SET
	permissions=excluded.permissions,
	description=excluded.description,
	builtin=excluded.builtin,
	updated_at=datetime('now');"
done

# Users
for u in $(cfg_list "$SYS_CONF" "system_admin"); do
	data=$(cfg_get "$SYS_CONF" "system_admin:${u}" 2>/dev/null)
	prof=$(echo "$data" | grep '^profile=' | cut -d= -f2-)
	enf=$(echo "$data" | grep '^enforce-change-password=' | cut -d= -f2-)
	# Explicit default: missing key → disable (never leave ambiguous)
	case "$enf" in
		enable)  enf_val=1 ;;
		disable) enf_val=0 ;;
		*)       enf_val=0 ;;
	esac
	bi=$(echo "$data" | grep '^builtin=' | cut -d= -f2-)
	[ "$bi" = "yes" ] && bi_val=1 || bi_val=0
	sqlite3 "$DB_PATH" "INSERT INTO users(username, profile, enforce_change_password, builtin, updated_at)
	VALUES('$(esc "$u")',
	       '$(esc "$prof")',
	       ${enf_val},
	       ${bi_val}, datetime('now'))
	ON CONFLICT(username) DO UPDATE SET
	profile=excluded.profile,
	enforce_change_password=excluded.enforce_change_password,
	builtin=excluded.builtin,
	updated_at=datetime('now');"
done

# Generic object snapshot for all config sections
for _file in "$SYS_CONF" "$NET_CONF" "$FW_CONF"; do
	[ -f "$_file" ] || continue
	for _type in $(cfg_list_types "$_file"); do
		_mode=$(cfg_type_mode "$_type")
		case "$_mode" in
			table)
				for _id in $(cfg_list "$_file" "$_type"); do
					_data=$(cfg_get "$_file" "${_type}:${_id}" 2>/dev/null)
					_blob=$(printf '%s' "$_data" | sed ':a;N;$!ba;s/\n/\\n/g')
					sqlite3 "$DB_PATH" "INSERT INTO config_objects(type, object_id, domain_file, data, updated_at)
					VALUES('$(esc "$_type")','$(esc "$_id")','$(esc "$_file")','$(esc "$_blob")',datetime('now'))
					ON CONFLICT(type, object_id) DO UPDATE SET
					domain_file=excluded.domain_file,
					data=excluded.data,
					updated_at=datetime('now');"
				done
				;;
			single)
				_data=$(cfg_get "$_file" "$_type" 2>/dev/null)
				[ -z "$_data" ] && continue
				_blob=$(printf '%s' "$_data" | sed ':a;N;$!ba;s/\n/\\n/g')
				sqlite3 "$DB_PATH" "INSERT INTO config_objects(type, object_id, domain_file, data, updated_at)
				VALUES('$(esc "$_type")','0','$(esc "$_file")','$(esc "$_blob")',datetime('now'))
				ON CONFLICT(type, object_id) DO UPDATE SET
				domain_file=excluded.domain_file,
				data=excluded.data,
				updated_at=datetime('now');"
				;;
		esac
	done
done

# Firewall typed tables (bootstrap projection)
for _id in $(cfg_list "$FW_CONF" "firewall_policy"); do
	_data=$(cfg_get "$FW_CONF" "firewall_policy:${_id}" 2>/dev/null)
	_name=$(echo "$_data" | grep '^name=' | cut -d= -f2-)
	_srcintf=$(echo "$_data" | grep '^srcintf=' | cut -d= -f2-)
	_dstintf=$(echo "$_data" | grep '^dstintf=' | cut -d= -f2-)
	_srcaddr=$(echo "$_data" | grep '^srcaddr=' | cut -d= -f2-)
	_dstaddr=$(echo "$_data" | grep '^dstaddr=' | cut -d= -f2-)
	_action=$(echo "$_data" | grep '^action=' | cut -d= -f2-)
	_service=$(echo "$_data" | grep '^service=' | cut -d= -f2-)
	_schedule=$(echo "$_data" | grep '^schedule=' | cut -d= -f2-)
	_status=$(echo "$_data" | grep '^status=' | cut -d= -f2-)
	_comment=$(echo "$_data" | grep '^comment=' | cut -d= -f2-)
	sqlite3 "$DB_PATH" "INSERT INTO firewall_policies(id,name,srcintf,dstintf,srcaddr,dstaddr,action,service,schedule,status,comment,updated_at)
	VALUES('$(esc "$_id")','$(esc "$_name")','$(esc "$_srcintf")','$(esc "$_dstintf")','$(esc "$_srcaddr")','$(esc "$_dstaddr")','$(esc "$_action")','$(esc "$_service")','$(esc "$_schedule")','$(esc "$_status")','$(esc "$_comment")',datetime('now'))
	ON CONFLICT(id) DO UPDATE SET
	name=excluded.name,srcintf=excluded.srcintf,dstintf=excluded.dstintf,srcaddr=excluded.srcaddr,dstaddr=excluded.dstaddr,
	action=excluded.action,service=excluded.service,schedule=excluded.schedule,status=excluded.status,comment=excluded.comment,
	updated_at=datetime('now');"
done

for _id in $(cfg_list "$FW_CONF" "firewall_address"); do
	_data=$(cfg_get "$FW_CONF" "firewall_address:${_id}" 2>/dev/null)
	_name=$(echo "$_data" | grep '^name=' | cut -d= -f2-)
	_subnet=$(echo "$_data" | grep '^subnet=' | cut -d= -f2-)
	_type=$(echo "$_data" | grep '^type=' | cut -d= -f2-)
	_comment=$(echo "$_data" | grep '^comment=' | cut -d= -f2-)
	sqlite3 "$DB_PATH" "INSERT INTO firewall_addresses(id,name,subnet,type,comment,updated_at)
	VALUES('$(esc "$_id")','$(esc "$_name")','$(esc "$_subnet")','$(esc "$_type")','$(esc "$_comment")',datetime('now'))
	ON CONFLICT(id) DO UPDATE SET
	name=excluded.name,subnet=excluded.subnet,type=excluded.type,comment=excluded.comment,updated_at=datetime('now');"
done

for _id in $(cfg_list "$FW_CONF" "firewall_service"); do
	_data=$(cfg_get "$FW_CONF" "firewall_service:${_id}" 2>/dev/null)
	_name=$(echo "$_data" | grep '^name=' | cut -d= -f2-)
	_proto=$(echo "$_data" | grep '^protocol=' | cut -d= -f2-)
	_prange=$(echo "$_data" | grep '^port-range=' | cut -d= -f2-)
	_comment=$(echo "$_data" | grep '^comment=' | cut -d= -f2-)
	sqlite3 "$DB_PATH" "INSERT INTO firewall_services(id,name,protocol,port_range,comment,updated_at)
	VALUES('$(esc "$_id")','$(esc "$_name")','$(esc "$_proto")','$(esc "$_prange")','$(esc "$_comment")',datetime('now'))
	ON CONFLICT(id) DO UPDATE SET
	name=excluded.name,protocol=excluded.protocol,port_range=excluded.port_range,comment=excluded.comment,updated_at=datetime('now');"
done

# ── Post-migration verify: detect user/profile count mismatch ──
_ini_user_count=0
for _u in $(cfg_list "$SYS_CONF" "system_admin"); do
	_ini_user_count=$((_ini_user_count + 1))
done
_ini_prof_count=0
for _p in $(cfg_list "$SYS_CONF" "system_admin-profile"); do
	_ini_prof_count=$((_ini_prof_count + 1))
done
_db_user_count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo 0)
_db_prof_count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM profiles;" 2>/dev/null || echo 0)
if [ "$_ini_user_count" != "$_db_user_count" ]; then
	echo "[DB] WARNING: user count mismatch — INI=${_ini_user_count} DB=${_db_user_count}"
fi
if [ "$_ini_prof_count" != "$_db_prof_count" ]; then
	echo "[DB] WARNING: profile count mismatch — INI=${_ini_prof_count} DB=${_db_prof_count}"
fi

# Verify no user has ambiguous enforce_change_password state
_db_null_enf=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users WHERE enforce_change_password IS NULL;" 2>/dev/null || echo 0)
if [ "${_db_null_enf:-0}" -gt 0 ]; then
	echo "[DB] WARNING: ${_db_null_enf} user(s) with NULL enforce_change_password — defaulting to 0"
	sqlite3 "$DB_PATH" "UPDATE users SET enforce_change_password=0 WHERE enforce_change_password IS NULL;" 2>/dev/null || true
fi

echo "[DB] Migration complete: $DB_PATH"
