#!/bin/sh
# Stargazer NGFW - Configuration Library
# Sourced by cmd_configure, cmd_show, cmd_admin, stargazer-cli, stargazer-login,
# and the init service script. Do not execute directly.
#
# Provides:
#   IPC wrappers:    ipc_send, ipc_cfg_get, ipc_cfg_set, ipc_cfg_del, ipc_cfg_list
#   INI config I/O:  cfg_get, cfg_set, cfg_del, cfg_list (IPC-backed or direct)
#   Key metadata:    _get_valid_keys, _show_valid_keys
#   Apply config:    via IPC to mgmtd (no direct system calls)
#
# Architecture:
#   CLI scripts run as unprivileged user.
#   All privileged ops go through stargazer-mgmtd via stargazer-ipc-cli.

STARGAZER_CONF_DIR="/etc/stargazer"

# Root check: used to gate direct-write fallbacks so CLI (UID 1000+) never
# attempts privileged file operations when mgmtd is unavailable.
_is_root() { [ "$(id -u 2>/dev/null)" = "0" ]; }

# ── IPC Client Wrappers ──────────────────────────────────────────────────────
# Abstracts communication with stargazer-mgmtd.
# Returns: sets IPC_STATUS, IPC_EXTRA, IPC_PAYLOAD
# If mgmtd is not running, falls back to direct I/O (for stargazer-login
# which runs as root before mgmtd might not be up yet).

_ipc_cli_bin="/sbin/stargazer-ipc-cli"

_ipc_available() {
	[ -S /run/stargazer-mgmtd.sock ] && command -v "$_ipc_cli_bin" >/dev/null 2>&1
}

# ipc_send <cmd_id> [payload]
# Sets: IPC_STATUS IPC_EXTRA IPC_PAYLOAD IPC_RC
ipc_send() {
	_is_cmd="$1"
	shift
	IPC_STATUS=""
	IPC_EXTRA=""
	IPC_PAYLOAD=""
	IPC_RC=1

	if ! _ipc_available; then
		IPC_STATUS="500"
		IPC_EXTRA="mgmtd not available"
		return 1
	fi

	_is_output=$("$_ipc_cli_bin" "$_is_cmd" "$@" 2>/dev/null)
	_is_rc=$?

	IPC_STATUS=$(echo "$_is_output" | sed -n '1p')
	IPC_EXTRA=$(echo "$_is_output" | sed -n '2p')
	IPC_PAYLOAD=$(echo "$_is_output" | sed '1,2d')
	IPC_RC=$_is_rc

	return $_is_rc
}

# ipc_send_file <cmd_id> <payload_file>
# Same as ipc_send but reads payload from file
ipc_send_file() {
	_isf_cmd="$1"
	_isf_file="$2"
	IPC_STATUS=""
	IPC_EXTRA=""
	IPC_PAYLOAD=""
	IPC_RC=1

	if ! _ipc_available; then
		IPC_STATUS="500"
		IPC_EXTRA="mgmtd not available"
		return 1
	fi

	_isf_output=$("$_ipc_cli_bin" "$_isf_cmd" -f "$_isf_file" 2>/dev/null)
	_isf_rc=$?

	IPC_STATUS=$(echo "$_isf_output" | sed -n '1p')
	IPC_EXTRA=$(echo "$_isf_output" | sed -n '2p')
	IPC_PAYLOAD=$(echo "$_isf_output" | sed '1,2d')
	IPC_RC=$_isf_rc

	return $_isf_rc
}

# Print user-friendly error from IPC response
ipc_print_error() {
	case "$IPC_STATUS" in
		0)   return 0 ;;
		200) echo "  Error: Authorization failed."
		     [ -n "$IPC_EXTRA" ] && echo "  Detail: $IPC_EXTRA" ;;
		201) echo "  Error: Authentication failed." ;;
		202) echo "  Error: Account is locked." ;;
		203) echo "  Error: Profile does not allow this operation."
		     [ -n "$IPC_EXTRA" ] && echo "  Hint: $IPC_EXTRA" ;;
		300|301|302|303)
		     echo "  Error: Not found."
		     [ -n "$IPC_EXTRA" ] && echo "  Detail: $IPC_EXTRA" ;;
		400) echo "  Error: Already exists."
		     [ -n "$IPC_EXTRA" ] && echo "  Detail: $IPC_EXTRA" ;;
		401) echo "  Error: Resource is in use."
		     [ -n "$IPC_EXTRA" ] && echo "  Detail: $IPC_EXTRA" ;;
		402) echo "  Error: Cannot modify built-in object."
		     [ -n "$IPC_EXTRA" ] && echo "  Detail: $IPC_EXTRA" ;;
		500|501|502|503)
		     echo "  Error: Internal system error."
		     echo "  Detail: Processing failed. Please check system logs."
		     [ -n "$IPC_EXTRA" ] && echo "  Hint: $IPC_EXTRA" ;;
		*)   echo "  Error: Operation failed (code: $IPC_STATUS)."
		     [ -n "$IPC_EXTRA" ] && echo "  Detail: $IPC_EXTRA" ;;
	esac
	return 1
}

# ── Display label convention ──────────────────────────────────────────────────
# Internal keys use '_' as hierarchy separator and '-' as word joiner.
# _key_to_label converts: system_admin-profile → "system admin-profile"
# No manual lookup table needed — the convention is self-documenting.

_key_to_label() {
	echo "$1" | tr '_' ' '
}

# ── Config type registry ─────────────────────────────────────────────────────
# Format: "type:table_or_single"

CONFIG_TYPES="
network_route_static:table
network_route_policy:table
network_ospf:single
network_rip:single
network_bgp:single
network_nat:table
network_dns:single
system_settings:single
system_interface:table
system_hostname:single
system_ntp:single
firewall_policy:table
firewall_address:table
firewall_service:table
system_password-policy:single
system_admin-profile:table
system_admin:table
"

# ── cfg_domain_for(config_type) ──────────────────────────────────────────────
# Returns the domain file path for a given config type.

cfg_domain_for() {
	case "$1" in
		system_interface)       echo "$STARGAZER_CONF_DIR/network.conf" ;;
		network_*)              echo "$STARGAZER_CONF_DIR/network.conf" ;;
		firewall_*)             echo "$STARGAZER_CONF_DIR/firewall.conf" ;;
		system_*)               echo "$STARGAZER_CONF_DIR/system.conf" ;;
		*)                      echo "$STARGAZER_CONF_DIR/system.conf" ;;
	esac
}

# ── cfg_type_mode(config_type) ───────────────────────────────────────────────
# Returns "table" or "single" for a given config type.

cfg_type_mode() {
	_ctm_IFS="$IFS"
	IFS='
'
	for _ctm_line in $CONFIG_TYPES; do
		_ctm_k="${_ctm_line%%:*}"
		_ctm_t="${_ctm_line##*:}"
		if [ "$_ctm_k" = "$1" ]; then
			IFS="$_ctm_IFS"
			echo "$_ctm_t"
			return
		fi
	done
	IFS="$_ctm_IFS"
	echo ""
}

# ── Security helpers ─────────────────────────────────────────────────────────

# Allow only safe identifiers for user/profile/object IDs.
# Valid chars: A-Z a-z 0-9 _ . -
_is_safe_id() {
	case "$1" in
		""|*[!A-Za-z0-9_.-]*) return 1 ;;
		*) return 0 ;;
	esac
}

_validate_permissions_csv() {
	_v_csv="$1"
	_v_allow=",monitor,configure,admin,"
	for _v_p in $(echo "$_v_csv" | tr ',' ' '); do
		[ -z "$_v_p" ] && continue
		case "$_v_allow" in
			*",${_v_p},"*) ;;
			*) return 1 ;;
		esac
	done
	return 0
}

_is_uint_range() {
	_ur_v="$1"
	_ur_min="$2"
	_ur_max="$3"
	case "$_ur_v" in
		""|*[!0-9]*) return 1 ;;
	esac
	[ "$_ur_v" -ge "$_ur_min" ] 2>/dev/null && [ "$_ur_v" -le "$_ur_max" ] 2>/dev/null
}

_is_iface_name() {
	case "$1" in
		""|*[!A-Za-z0-9_.:-]*) return 1 ;;
		*) return 0 ;;
	esac
}

_is_ipv4() {
	_ip="$1"
	awk -v ip="$_ip" 'BEGIN{
		n=split(ip,a,"."); if(n!=4) exit 1;
		for(i=1;i<=4;i++){
			if(a[i]!~/^[0-9]+$/) exit 1;
			if(a[i]<0 || a[i]>255) exit 1;
		}
		exit 0
	}' </dev/null >/dev/null 2>&1
}

_is_cidr() {
	_c="$1"
	case "$_c" in
		*/*) ;;
		*) return 1 ;;
	esac
	_ip="${_c%/*}"
	_mask="${_c#*/}"
	_is_ipv4 "$_ip" || return 1
	_is_uint_range "$_mask" 0 32 || return 1
	return 0
}

# ── resolve_login_user(argv1) ─────────────────────────────────────────────
# Single canonical source for the effective login user identity.
# Priority: $1 (argv from caller) → STARGAZER_LOGIN_USER → LOGIN → fail.
# Returns 0 + prints username on success, returns 1 on failure.

resolve_login_user() {
	_rlu_arg="${1:-}"
	_rlu_source=""
	_rlu_user=""

	if [ -n "$_rlu_arg" ]; then
		_rlu_user="$_rlu_arg"
		_rlu_source="argv1"
	elif [ -n "${STARGAZER_LOGIN_USER:-}" ]; then
		_rlu_user="$STARGAZER_LOGIN_USER"
		_rlu_source="STARGAZER_LOGIN_USER"
	elif [ -n "${LOGIN:-}" ]; then
		_rlu_user="$LOGIN"
		_rlu_source="LOGIN"
	else
		return 1
	fi

	# Validate: reject unsafe identifiers
	if ! _is_safe_id "$_rlu_user"; then
		return 1
	fi

	# Export source for audit tracing
	RESOLVED_LOGIN_SOURCE="$_rlu_source"
	echo "$_rlu_user"
	return 0
}

audit_log() {
	_al_event="$1"
	_al_msg="$2"
	_al_user="${STARGAZER_USER:-system}"
	_al_ts="$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || echo unknown-time)"
	_al_line="${_al_ts} user=${_al_user} event=${_al_event} msg=${_al_msg}"

	# Prefer IPC route: mgmtd writes as root with restricted perms (VULN-07)
	if _ipc_available; then
		ipc_send 206 "$_al_line" 2>/dev/null
		return
	fi

	# Fallback: direct write (root context only — init/replay)
	_is_root || return 0
	_al_file="/var/log/stargazer-audit.log"
	[ -d /var/log ] || _al_file="/tmp/stargazer-audit.log"
	if [ ! -f "$_al_file" ]; then
		touch "$_al_file" 2>/dev/null
		chmod 0640 "$_al_file" 2>/dev/null
	fi
	echo "$_al_line" >> "$_al_file" 2>/dev/null
}

# ── Debug runtime/state helpers ───────────────────────────────────────────

STARGAZER_DEBUG_STATE_FILE="/tmp/stargazer-debug.conf"
STARGAZER_DEBUG_LOG_FILE="/tmp/stargazer-debug.log"

debug_state_init() {
	if [ -f "$STARGAZER_DEBUG_STATE_FILE" ]; then
		return
	fi
	cat > "$STARGAZER_DEBUG_STATE_FILE" <<'EOF'
enabled=0
opt_timestamp=1
opt_actor=1
opt_function=1
opt_hierarchy=1
flow_trace=0
flow_limit=0
cli_debug=0
mgmtd_debug=0
auth_admin=0
auth_user=0
EOF
	chmod 600 "$STARGAZER_DEBUG_STATE_FILE" 2>/dev/null || true
}

debug_get() {
	_dg_key="$1"
	_dg_def="$2"
	debug_state_init
	_dg_val=$(grep "^${_dg_key}=" "$STARGAZER_DEBUG_STATE_FILE" 2>/dev/null | tail -1 | cut -d= -f2-)
	if [ -z "$_dg_val" ] && [ -n "$_dg_def" ]; then
		echo "$_dg_def"
		return
	fi
	echo "$_dg_val"
}

debug_set() {
	_ds_key="$1"
	_ds_val="$2"
	debug_state_init
	if grep -q "^${_ds_key}=" "$STARGAZER_DEBUG_STATE_FILE" 2>/dev/null; then
		_ds_tmp="${STARGAZER_DEBUG_STATE_FILE}.tmp.$$"
		awk -v k="$_ds_key" -v v="$_ds_val" -F= \
			'{if($1==k){print k"="v}else{print}}' \
			"$STARGAZER_DEBUG_STATE_FILE" > "$_ds_tmp" && mv "$_ds_tmp" "$STARGAZER_DEBUG_STATE_FILE" 2>/dev/null || return 1
	else
		echo "${_ds_key}=${_ds_val}" >> "$STARGAZER_DEBUG_STATE_FILE" 2>/dev/null || return 1
	fi
	return 0
}

debug_reset() {
	rm -f "$STARGAZER_DEBUG_STATE_FILE" 2>/dev/null || true
	debug_state_init
}

debug_enabled() {
	[ "$(debug_get enabled 0)" = "1" ]
}

debug_feature_enabled() {
	_df_key="$1"
	[ "$(debug_get "$_df_key" 0)" = "1" ]
}

debug_log() {
	_dl_component="$1"
	_dl_actor="$2"
	_dl_func="$3"
	_dl_msg="$4"
	_dl_depth="${5:-0}"

	debug_enabled || return 0

	_dl_line=""
	if [ "$(debug_get opt_timestamp 1)" = "1" ]; then
		_dl_ts="$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || echo unknown-time)"
		_dl_line="${_dl_line}${_dl_ts} "
	fi
	_dl_line="${_dl_line}[DEBUG][${_dl_component}]"
	if [ "$(debug_get opt_actor 1)" = "1" ]; then
		_dl_line="${_dl_line}[actor=${_dl_actor}]"
	fi
	if [ "$(debug_get opt_function 1)" = "1" ]; then
		_dl_line="${_dl_line}[func=${_dl_func}]"
	fi
	if [ "$(debug_get opt_hierarchy 1)" = "1" ] && [ "$_dl_depth" -gt 0 ] 2>/dev/null; then
		_dl_i=0
		_dl_indent=""
		while [ "$_dl_i" -lt "$_dl_depth" ]; do
			_dl_indent="${_dl_indent}  "
			_dl_i=$((_dl_i + 1))
		done
		_dl_line="${_dl_line} ${_dl_indent}${_dl_msg}"
	else
		_dl_line="${_dl_line} ${_dl_msg}"
	fi

	echo "$_dl_line" >> "$STARGAZER_DEBUG_LOG_FILE" 2>/dev/null || true
	echo "$_dl_line"
}

# Backward-compatible auth debug entrypoint
auth_debug() {
	_ad_msg="$1"
	if ! debug_enabled; then
		return 0
	fi
	if ! debug_feature_enabled auth_admin && ! debug_feature_enabled auth_user; then
		return 0
	fi
	debug_log "auth" "system" "auth_debug" "$_ad_msg" 0
}

# ── SQLite sync helpers (Phase C bootstrap) ─────────────────────────────────

STARGAZER_DB_PATH="${STARGAZER_CONF_DIR}/stargazer.db"
STARGAZER_SESSION_REV_FILE="/tmp/stargazer-session.rev"

_db_ready() {
	command -v sqlite3 >/dev/null 2>&1 || return 1
	[ -f "$STARGAZER_DB_PATH" ] || return 1
	return 0
}

_db_escape() {
	# Escape single quotes for SQLite string literals
	# Also strip NUL bytes and control characters (VULN-08)
	printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' | sed "s/'/''/g"
}

# Stricter validation for values used as SQL identifiers/keys
_db_safe_id() {
	case "$1" in
		""|*[!A-Za-z0-9_.-]*) return 1 ;;
		*) return 0 ;;
	esac
}

# Check whether an admin account exists in control-plane config.
# Used by login flow and pre-suid hook to avoid stale/mismatched identities.
admin_exists_in_config() {
	_ae_user="$1"
	if _db_ready; then
		_ae_uq=$(_db_escape "$_ae_user")
		_ae_exists=$(sqlite3 "$STARGAZER_DB_PATH" "SELECT 1 FROM users WHERE username='${_ae_uq}' LIMIT 1;" 2>/dev/null)
		[ "$_ae_exists" = "1" ] && return 0
	fi
	cfg_get "$STARGAZER_CONF_DIR/system.conf" "system_admin:${_ae_user}" >/dev/null 2>&1
}

session_user_rev_get() {
	_sr_user="$1"
	if _ipc_available; then
		ipc_send 400 "$_sr_user"
		[ "$IPC_RC" -eq 0 ] && echo "$IPC_PAYLOAD" && return 0
		echo 0
		return 0
	fi
	# Direct fallback
	_sr_rev=0
	[ -r "$STARGAZER_SESSION_REV_FILE" ] || {
		echo 0
		return
	}
	while IFS=: read -r _u _r || [ -n "$_u" ]; do
		[ "$_u" = "$_sr_user" ] || continue
		_sr_rev="${_r:-0}"
		break
	done < "$STARGAZER_SESSION_REV_FILE"
	case "$_sr_rev" in
		""|*[!0-9]*) _sr_rev=0 ;;
	esac
	echo "$_sr_rev"
}

session_user_rev_set() {
	_ss_user="$1"
	_ss_rev="$2"
	if _ipc_available; then
		# rev_set is handled by mgmtd internally
		return 0
	fi
	# Direct fallback
	_ss_tmp="${STARGAZER_SESSION_REV_FILE}.tmp.$$"
	> "$_ss_tmp"
	if [ -f "$STARGAZER_SESSION_REV_FILE" ]; then
		while IFS=: read -r _u _r || [ -n "$_u" ]; do
			[ -z "$_u" ] && continue
			[ "$_u" = "$_ss_user" ] && continue
			echo "${_u}:${_r}" >> "$_ss_tmp"
		done < "$STARGAZER_SESSION_REV_FILE"
	fi
	echo "${_ss_user}:${_ss_rev}" >> "$_ss_tmp"
	mv -f "$_ss_tmp" "$STARGAZER_SESSION_REV_FILE"
	chmod 644 "$STARGAZER_SESSION_REV_FILE" 2>/dev/null
}

session_user_rev_bump() {
	_sb_user="$1"
	if _ipc_available; then
		ipc_send 401 "$_sb_user"
		return $IPC_RC
	fi
	# Direct fallback
	_sb_old=$(session_user_rev_get "$_sb_user")
	case "$_sb_old" in
		""|*[!0-9]*) _sb_old=0 ;;
	esac
	_sb_new=$((_sb_old + 1))
	session_user_rev_set "$_sb_user" "$_sb_new"
	return 0
}

session_profile_rev_bump() {
	_sp_profile="$1"
	[ -z "$_sp_profile" ] && return 0
	if _db_ready; then
		_sp_q=$(_db_escape "$_sp_profile")
		sqlite3 "$STARGAZER_DB_PATH" "SELECT username FROM users WHERE profile='${_sp_q}';" 2>/dev/null \
		| while IFS= read -r _u; do
			[ -n "$_u" ] && session_user_rev_bump "$_u"
		done
		return 0
	fi
	_sp_sys="$STARGAZER_CONF_DIR/system.conf"
	for _u in $(cfg_list "$_sp_sys" "system_admin"); do
		_up=$(cfg_get "$_sp_sys" "system_admin:${_u}" 2>/dev/null | grep '^profile=' | cut -d= -f2-)
		[ "$_up" = "$_sp_profile" ] && session_user_rev_bump "$_u"
	done
}

admin_get_enforce_policy() {
	_ag_user="$1"
	if _ipc_available; then
		# Get via cfg_get through IPC and parse enforce field
		_ag_data=$(cfg_get "$STARGAZER_CONF_DIR/system.conf" "system_admin:${_ag_user}" 2>/dev/null)
		_ag_enf=$(echo "$_ag_data" | grep '^enforce-change-password=' | cut -d= -f2-)
		case "$_ag_enf" in
			enable|disable) echo "$_ag_enf"; return 0 ;;
		esac
		echo "disable"
		return 0
	fi
	# Direct fallback
	_ag_sys="$STARGAZER_CONF_DIR/system.conf"
	_ag_data=$(_cfg_get_direct "$_ag_sys" "system_admin:${_ag_user}" 2>/dev/null)
	_ag_enf=$(echo "$_ag_data" | grep '^enforce-change-password=' | cut -d= -f2-)
	case "$_ag_enf" in
		enable|disable)
			echo "$_ag_enf"
			return 0
			;;
	esac
	if _db_ready; then
		_ag_q=$(_db_escape "$_ag_user")
		_ag_db=$(sqlite3 "$STARGAZER_DB_PATH" "SELECT enforce_change_password FROM users WHERE username='${_ag_q}' LIMIT 1;" 2>/dev/null)
		[ "$_ag_db" = "1" ] && echo "enable" && return 0
		[ "$_ag_db" = "0" ] && echo "disable" && return 0
	fi
	echo "disable"
}

admin_set_enforce_policy() {
	_as_user="$1"
	_as_val="$2"
	case "$_as_val" in
		enable|disable) ;;
		*) return 1 ;;
	esac

	if _ipc_available; then
		ipc_send 303 "$(printf '%s\n%s' "$_as_user" "$_as_val")"
		return $IPC_RC
	fi

	# Direct fallback (root only — init context)
	_is_root || { echo "  Error: mgmtd unavailable"; return 1; }
	_as_sys="$STARGAZER_CONF_DIR/system.conf"
	_as_sec="system_admin:${_as_user}"
	_as_tmp=$(mktemp /tmp/admin_enforce.XXXXXX 2>/dev/null || echo "/tmp/admin_enforce_$$.tmp")
	if _cfg_get_direct "$_as_sys" "$_as_sec" > "$_as_tmp" 2>/dev/null; then
		_as_sed="${_as_tmp}.sed.$$"
		sed '/^enforce-change-password=/d' "$_as_tmp" > "$_as_sed" && mv "$_as_sed" "$_as_tmp"
		echo "enforce-change-password=${_as_val}" >> "$_as_tmp"
		_cfg_set_direct "$_as_sys" "$_as_sec" "$_as_tmp"
	fi
	rm -f "$_as_tmp"
	return 0
}

_db_sync_section() {
	_ds_file="$1"
	_ds_section="$2"
	_ds_data="$3"
	_db_ready || return 0

	_ds_type="${_ds_section%%:*}"
	_ds_id="${_ds_section#*:}"
	[ "$_ds_type" = "$_ds_id" ] && _ds_id="0"

	_ds_type_e=$(_db_escape "$_ds_type")
	_ds_id_e=$(_db_escape "$_ds_id")
	_ds_file_e=$(_db_escape "$_ds_file")
	_ds_blob=$(sed ':a;N;$!ba;s/\n/\\n/g' "$_ds_data" 2>/dev/null)
	_ds_blob_e=$(_db_escape "$_ds_blob")

	sqlite3 "$STARGAZER_DB_PATH" "INSERT INTO config_objects(type, object_id, domain_file, data, updated_at)
	VALUES('${_ds_type_e}', '${_ds_id_e}', '${_ds_file_e}', '${_ds_blob_e}', datetime('now'))
	ON CONFLICT(type, object_id) DO UPDATE SET
	domain_file=excluded.domain_file,
	data=excluded.data,
	updated_at=datetime('now');" >/dev/null 2>&1 || true

	case "$_ds_type" in
		system_admin-profile)
			_ds_perms=$(grep '^permissions=' "$_ds_data" 2>/dev/null | cut -d= -f2-)
			_ds_desc=$(grep '^description=' "$_ds_data" 2>/dev/null | cut -d= -f2-)
			_ds_bi=$(grep '^builtin=' "$_ds_data" 2>/dev/null | cut -d= -f2-)
			[ "$_ds_bi" = "yes" ] && _ds_bi=1 || _ds_bi=0
			_ds_name_e=$(_db_escape "$_ds_id")
			_ds_perms_e=$(_db_escape "$_ds_perms")
			_ds_desc_e=$(_db_escape "$_ds_desc")
			sqlite3 "$STARGAZER_DB_PATH" "INSERT INTO profiles(name, permissions, description, builtin, updated_at)
			VALUES('${_ds_name_e}','${_ds_perms_e}','${_ds_desc_e}',${_ds_bi},datetime('now'))
			ON CONFLICT(name) DO UPDATE SET
			permissions=excluded.permissions,
			description=excluded.description,
			builtin=excluded.builtin,
			updated_at=datetime('now');" >/dev/null 2>&1 || true
			;;
		system_admin)
			_ds_prof=$(grep '^profile=' "$_ds_data" 2>/dev/null | cut -d= -f2-)
			_ds_enf=$(grep '^enforce-change-password=' "$_ds_data" 2>/dev/null | cut -d= -f2-)
			_ds_bi=$(grep '^builtin=' "$_ds_data" 2>/dev/null | cut -d= -f2-)
			[ "$_ds_enf" = "enable" ] && _ds_enf=1 || _ds_enf=0
			[ "$_ds_bi" = "yes" ] && _ds_bi=1 || _ds_bi=0
			_ds_user_e=$(_db_escape "$_ds_id")
			_ds_prof_e=$(_db_escape "$_ds_prof")
			sqlite3 "$STARGAZER_DB_PATH" "INSERT INTO users(username, profile, enforce_change_password, builtin, updated_at)
			VALUES('${_ds_user_e}','${_ds_prof_e}',${_ds_enf},${_ds_bi},datetime('now'))
			ON CONFLICT(username) DO UPDATE SET
			profile=excluded.profile,
			enforce_change_password=excluded.enforce_change_password,
			builtin=excluded.builtin,
			updated_at=datetime('now');" >/dev/null 2>&1 || true
			;;
	esac
}

_db_delete_section() {
	_dd_section="$1"
	_db_ready || return 0
	_dd_type="${_dd_section%%:*}"
	_dd_id="${_dd_section#*:}"
	[ "$_dd_type" = "$_dd_id" ] && _dd_id="0"
	_dd_type_e=$(_db_escape "$_dd_type")
	_dd_id_e=$(_db_escape "$_dd_id")
	sqlite3 "$STARGAZER_DB_PATH" "DELETE FROM config_objects WHERE type='${_dd_type_e}' AND object_id='${_dd_id_e}';" >/dev/null 2>&1 || true
	case "$_dd_type" in
		system_admin-profile)
			_dd_id_e=$(_db_escape "$_dd_id")
			sqlite3 "$STARGAZER_DB_PATH" "DELETE FROM profiles WHERE name='${_dd_id_e}';" >/dev/null 2>&1 || true
			;;
		system_admin)
			_dd_id_e=$(_db_escape "$_dd_id")
			sqlite3 "$STARGAZER_DB_PATH" "DELETE FROM users WHERE username='${_dd_id_e}';" >/dev/null 2>&1 || true
			;;
	esac
}

cfg_record_revision() {
	_cr_msg="${1:-auto-save}"
	_cr_author="${STARGAZER_USER:-system}"
	_db_ready || return 0
	_cr_msg_e=$(_db_escape "$_cr_msg")
	_cr_author_e=$(_db_escape "$_cr_author")
	sqlite3 "$STARGAZER_DB_PATH" "INSERT INTO config_revisions(author,message) VALUES('${_cr_author_e}','${_cr_msg_e}');" >/dev/null 2>&1 || return 1
	_cr_rev=$(sqlite3 "$STARGAZER_DB_PATH" "SELECT MAX(rev) FROM config_revisions;" 2>/dev/null)
	[ -z "$_cr_rev" ] && return 1

	for _rf in "$STARGAZER_CONF_DIR/system.conf" "$STARGAZER_CONF_DIR/network.conf" "$STARGAZER_CONF_DIR/firewall.conf"; do
		[ -f "$_rf" ] || continue
		_rf_blob=$(sed ':a;N;$!ba;s/\n/\\n/g' "$_rf" 2>/dev/null)
		_rf_e=$(_db_escape "$_rf")
		_rf_blob_e=$(_db_escape "$_rf_blob")
		sqlite3 "$STARGAZER_DB_PATH" "INSERT OR REPLACE INTO config_revision_files(rev,domain_file,content)
		VALUES(${_cr_rev},'${_rf_e}','${_rf_blob_e}');" >/dev/null 2>&1 || true
	done
	audit_log "config_revision" "rev=${_cr_rev} msg=${_cr_msg}"
	echo "$_cr_rev"
	return 0
}

cfg_record_revision_auto() {
	[ -n "${_CFG_REV_GUARD:-}" ] && return 0
	_CFG_REV_GUARD=1
	cfg_record_revision "auto-save" >/dev/null 2>&1 || true
	unset _CFG_REV_GUARD
	return 0
}

cfg_list_revisions() {
	_db_ready || {
		echo "  DB not available"
		return 1
	}
	echo "  === Configuration Revisions ==="
	printf "  %-6s %-24s %-16s %s\n" "REV" "TIME" "AUTHOR" "MESSAGE"
	printf "  %-6s %-24s %-16s %s\n" "---" "----" "------" "-------"
	sqlite3 -separator '|' "$STARGAZER_DB_PATH" "SELECT rev, ts, IFNULL(author,''), IFNULL(message,'') FROM config_revisions ORDER BY rev DESC LIMIT 50;" \
	| while IFS='|' read -r _r _t _a _m; do
		printf "  %-6s %-24s %-16s %s\n" "$_r" "$_t" "$_a" "$_m"
	done
}

cfg_rollback_revision() {
	_rb_rev="$1"
	case "$_rb_rev" in
		""|*[!0-9]*)
			echo "  Usage: configure rollback <rev>"
			return 1
			;;
	esac
	_db_ready || {
		echo "  DB not available"
		return 1
	}
	_rb_count=$(sqlite3 "$STARGAZER_DB_PATH" "SELECT COUNT(*) FROM config_revision_files WHERE rev=${_rb_rev};" 2>/dev/null)
	[ "${_rb_count:-0}" -gt 0 ] 2>/dev/null || {
		echo "  Revision not found: $_rb_rev"
		return 1
	}

	sqlite3 -separator '|' "$STARGAZER_DB_PATH" "SELECT domain_file, content FROM config_revision_files WHERE rev=${_rb_rev};" \
	| while IFS='|' read -r _f _c; do
		_tmp="${_f}.rollback.$$"
		printf '%s' "$_c" | sed 's/\\n/\
/g' > "$_tmp"
		mv -f "$_tmp" "$_f"
	done

	cfg_replay "$STARGAZER_CONF_DIR/system.conf" 2>/dev/null
	cfg_replay "$STARGAZER_CONF_DIR/network.conf" 2>/dev/null
	cfg_replay "$STARGAZER_CONF_DIR/firewall.conf" 2>/dev/null

	if [ -x "${CMD_DIR:-/usr/libexec/stargazer}/db_migrate.sh" ]; then
		sh "${CMD_DIR:-/usr/libexec/stargazer}/db_migrate.sh" >/dev/null 2>&1
	fi
	audit_log "config_rollback" "rev=${_rb_rev}"
	echo "  Rolled back to revision $_rb_rev"
	return 0
}

# ── Direct INI config I/O (used by root callers when mgmtd unavailable) ─────
# These _direct variants are the original implementations.

_cfg_get_direct() {
	_cg_file="$1"
	_cg_section="$2"
	[ ! -f "$_cg_file" ] && return 1
	_cg_found=0
	while IFS= read -r _cg_line || [ -n "$_cg_line" ]; do
		case "$_cg_line" in
			"[${_cg_section}]")
				_cg_found=1
				continue
				;;
			"["*)
				[ "$_cg_found" -eq 1 ] && break
				;;
			"#"*|"")
				continue
				;;
			*)
				[ "$_cg_found" -eq 1 ] && echo "$_cg_line"
				;;
		esac
	done < "$_cg_file"
	[ "$_cg_found" -eq 1 ] && return 0 || return 1
}

_cfg_set_direct() {
	_cs_file="$1"
	_cs_section="$2"
	_cs_data="$3"
	_cs_tmp=$(mktemp "${_cs_file}.XXXXXX" 2>/dev/null) || _cs_tmp="${_cs_file}.tmp.$$"

	mkdir -p "$(dirname "$_cs_file")"

	if [ ! -f "$_cs_file" ]; then
		echo "[${_cs_section}]" > "$_cs_file"
		cat "$_cs_data" >> "$_cs_file"
		echo "" >> "$_cs_file"
		chmod 640 "$_cs_file" 2>/dev/null; chgrp stargazer "$_cs_file" 2>/dev/null
		_db_sync_section "$_cs_file" "$_cs_section" "$_cs_data"
		cfg_record_revision_auto
		return 0
	fi

	_cs_found=0
	_cs_skip=0
	_cs_wrote=0
	> "$_cs_tmp"

	while IFS= read -r _cs_line || [ -n "$_cs_line" ]; do
		case "$_cs_line" in
			"[${_cs_section}]")
				_cs_found=1
				_cs_skip=1
				echo "[${_cs_section}]" >> "$_cs_tmp"
				cat "$_cs_data" >> "$_cs_tmp"
				echo "" >> "$_cs_tmp"
				_cs_wrote=1
				continue
				;;
			"["*)
				_cs_skip=0
				;;
		esac
		[ "$_cs_skip" -eq 1 ] && continue
		echo "$_cs_line" >> "$_cs_tmp"
	done < "$_cs_file"

	if [ "$_cs_found" -eq 0 ]; then
		echo "[${_cs_section}]" >> "$_cs_tmp"
		cat "$_cs_data" >> "$_cs_tmp"
		echo "" >> "$_cs_tmp"
	fi

	mv -f "$_cs_tmp" "$_cs_file"
	chmod 640 "$_cs_file" 2>/dev/null; chgrp stargazer "$_cs_file" 2>/dev/null
	_db_sync_section "$_cs_file" "$_cs_section" "$_cs_data"
	cfg_record_revision_auto
}

_cfg_del_direct() {
	_cd_file="$1"
	_cd_section="$2"
	_cd_tmp=$(mktemp "${_cd_file}.XXXXXX" 2>/dev/null) || _cd_tmp="${_cd_file}.tmp.$$"
	[ ! -f "$_cd_file" ] && return 1
	_cd_skip=0
	> "$_cd_tmp"

	while IFS= read -r _cd_line || [ -n "$_cd_line" ]; do
		case "$_cd_line" in
			"[${_cd_section}]")
				_cd_skip=1
				continue
				;;
			"["*)
				_cd_skip=0
				;;
		esac
		[ "$_cd_skip" -eq 1 ] && continue
		echo "$_cd_line" >> "$_cd_tmp"
	done < "$_cd_file"

	mv -f "$_cd_tmp" "$_cd_file"
	chmod 640 "$_cd_file" 2>/dev/null; chgrp stargazer "$_cd_file" 2>/dev/null
	_db_delete_section "$_cd_section"
	cfg_record_revision_auto
}

_cfg_list_direct() {
	_cl_file="$1"
	_cl_prefix="$2"
	[ ! -f "$_cl_file" ] && return
	while IFS= read -r _cl_line || [ -n "$_cl_line" ]; do
		case "$_cl_line" in
			"[${_cl_prefix}:"*"]")
				_cl_id="${_cl_line#"[${_cl_prefix}:"}"
				_cl_id="${_cl_id%]}"
				echo "$_cl_id"
				;;
		esac
	done < "$_cl_file"
}

# ── IPC-backed config I/O ───────────────────────────────────────────────────
# These route through mgmtd when available, falling back to direct I/O
# when running as root (init / stargazer-login before mgmtd starts).

# cfg_get <file> <section>
cfg_get() {
	if _ipc_available; then
		ipc_send 100 "$2"
		[ "$IPC_RC" -eq 0 ] && echo "$IPC_PAYLOAD" && return 0
		return 1
	fi
	_cfg_get_direct "$@"
}

# cfg_set <file> <section> <tmpfile>
cfg_set() {
	if _ipc_available; then
		# Payload: "section\ndata" — use printf+cat to preserve trailing newline
		_cs_payload=$(printf '%s\n' "$2"; cat "$3"; printf '\n')
		ipc_send 200 "$_cs_payload"
		return $IPC_RC
	fi
	_is_root || { echo "  Error: mgmtd unavailable (config write denied)"; return 1; }
	_cfg_set_direct "$@"
}

# cfg_del <file> <section>
cfg_del() {
	if _ipc_available; then
		ipc_send 201 "$2"
		return $IPC_RC
	fi
	_is_root || { echo "  Error: mgmtd unavailable (config delete denied)"; return 1; }
	_cfg_del_direct "$@"
}

# cfg_list <file> <prefix>
cfg_list() {
	if _ipc_available; then
		ipc_send 101 "$2"
		[ "$IPC_RC" -eq 0 ] && echo "$IPC_PAYLOAD" && return 0
		return 1
	fi
	_cfg_list_direct "$@"
}

# ── cfg_list_types(file) ────────────────────────────────────────────────────
# List unique config types present in a domain file.
# Returns lines like "system_settings" or "system_interface" (without entry IDs).

cfg_list_types() {
	_clt_file="$1"
	_clt_seen=""
	[ ! -f "$_clt_file" ] && return
	while IFS= read -r _clt_line || [ -n "$_clt_line" ]; do
		case "$_clt_line" in
			"["*"]")
				_clt_inner="${_clt_line#\[}"
				_clt_inner="${_clt_inner%\]}"
				# Strip :id for table types
				_clt_type="${_clt_inner%%:*}"
				case "|$_clt_seen|" in
					*"|${_clt_type}|"*) ;;
					*) echo "$_clt_type"
					   _clt_seen="${_clt_seen}|${_clt_type}" ;;
				esac
				;;
		esac
	done < "$_clt_file"
}

# ── cfg_replay(file) ────────────────────────────────────────────────────────
# Parse all sections and call _apply_config_direct for each.
# Used for boot-time replay of saved configuration (runs as root).

cfg_replay() {
	_cr_file="$1"
	[ ! -f "$_cr_file" ] && return
	_cr_section=""
	_cr_tmp="/tmp/cfg_replay_$$.tmp"

	while IFS= read -r _cr_line || [ -n "$_cr_line" ]; do
		case "$_cr_line" in
			"["*"]")
				# Apply previous section if any
				if [ -n "$_cr_section" ] && [ -s "$_cr_tmp" ]; then
					_cr_type="${_cr_section%%:*}"
					_cr_id="${_cr_section#*:}"
					[ "$_cr_type" = "$_cr_id" ] && _cr_id="0"
					_apply_config_direct "$_cr_type" "$_cr_id" "$_cr_tmp" 2>/dev/null
				fi
				# Start new section
				_cr_section="${_cr_line#\[}"
				_cr_section="${_cr_section%\]}"
				> "$_cr_tmp"
				;;
			"#"*|"")
				continue
				;;
			*)
				[ -n "$_cr_section" ] && echo "$_cr_line" >> "$_cr_tmp"
				;;
		esac
	done < "$_cr_file"

	# Apply last section
	if [ -n "$_cr_section" ] && [ -s "$_cr_tmp" ]; then
		_cr_type="${_cr_section%%:*}"
		_cr_id="${_cr_section#*:}"
		[ "$_cr_type" = "$_cr_id" ] && _cr_id="0"
		_apply_config_direct "$_cr_type" "$_cr_id" "$_cr_tmp" 2>/dev/null
	fi

	rm -f "$_cr_tmp"
}

# ── Password policy ──────────────────────────────────────────────────────────
# check_password_policy(password, username, [enforce_override])
# Returns: 0=no policy enforced, 1=satisfied, 2=policy violation (reason in IPC_EXTRA)
#          Direct fallback: 2=special, 3=uppercase, 4=lowercase, 5=digit, 6=length, 7=username
#
# When mgmtd is available, delegates to opcode 304 (single source of truth in C).
# Falls back to local shell validation when mgmtd is not running (init/replay).

check_password_policy() {
	_cpp_pass="$1"
	_cpp_user="$2"
	_cpp_enforce_override="$3"

	if _ipc_available; then
		_cpp_payload=$(printf '%s\n%s' "$_cpp_user" "$_cpp_pass")
		[ -n "$_cpp_enforce_override" ] && \
			_cpp_payload=$(printf '%s\n%s\n%s' "$_cpp_user" "$_cpp_pass" "$_cpp_enforce_override")
		ipc_send 304 "$_cpp_payload"
		if [ "$IPC_RC" -eq 0 ]; then
			return 1  # satisfied (or not enforced)
		else
			# IPC_EXTRA contains the reason string from mgmtd
			return 2  # generic policy failure
		fi
	fi

	# Direct fallback (root/init context — mgmtd not running)
	_check_password_policy_direct "$_cpp_pass" "$_cpp_user" "$_cpp_enforce_override"
}

# _check_password_policy_direct — local shell validation (init/replay fallback)
# Same return codes as original: 0=no policy, 1=satisfied, 2-7=violation
_check_password_policy_direct() {
	_cpp_pass="$1"
	_cpp_user="$2"
	_cpp_enforce_override="$3"

	_cpp_enforce="$_cpp_enforce_override"

	if [ -z "$_cpp_enforce" ]; then
		_cpp_conf="$STARGAZER_CONF_DIR/system.conf"
		_cpp_enforce=$(_cfg_get_direct "$_cpp_conf" "system_admin:${_cpp_user}" 2>/dev/null \
			| grep '^enforce-password-policy=' | cut -d= -f2-)
	fi

	if [ "$_cpp_enforce" != "enable" ]; then
		return 0  # no policy enforced
	fi

	_cpp_conf="$STARGAZER_CONF_DIR/system.conf"
	_cpp_policy=$(_cfg_get_direct "$_cpp_conf" "system_password-policy" 2>/dev/null)

	_cpp_min_len=$(echo "$_cpp_policy" | grep '^min-length=' | cut -d= -f2-)
	_cpp_min_upper=$(echo "$_cpp_policy" | grep '^min-uppercase=' | cut -d= -f2-)
	_cpp_min_lower=$(echo "$_cpp_policy" | grep '^min-lowercase=' | cut -d= -f2-)
	_cpp_min_digit=$(echo "$_cpp_policy" | grep '^min-digit=' | cut -d= -f2-)
	_cpp_min_special=$(echo "$_cpp_policy" | grep '^min-special=' | cut -d= -f2-)

	: "${_cpp_min_len:=0}"
	: "${_cpp_min_upper:=0}"
	: "${_cpp_min_lower:=0}"
	: "${_cpp_min_digit:=0}"
	: "${_cpp_min_special:=0}"

	# Apply MIN_PASS_LEN=8 floor (match C behavior)
	if [ "$_cpp_min_len" -le 0 ]; then
		_cpp_min_len=8
	fi

	# Check length
	_cpp_len=$(printf '%s' "$_cpp_pass" | wc -c)
	if [ "$_cpp_min_len" -gt 0 ] && [ "$_cpp_len" -lt "$_cpp_min_len" ]; then
		return 6
	fi

	# Count character classes using awk (byte comparison, ASCII)
	_cpp_counts=$(printf '%s' "$_cpp_pass" | awk '{
		u=0; l=0; d=0; s=0
		for (i=1; i<=length($0); i++) {
			c = substr($0, i, 1)
			if (c ~ /[A-Z]/) u++
			else if (c ~ /[a-z]/) l++
			else if (c ~ /[0-9]/) d++
			else s++
		}
		printf "%d %d %d %d", u, l, d, s
	}')
	_cpp_cnt_upper=$(echo "$_cpp_counts" | awk '{print $1}')
	_cpp_cnt_lower=$(echo "$_cpp_counts" | awk '{print $2}')
	_cpp_cnt_digit=$(echo "$_cpp_counts" | awk '{print $3}')
	_cpp_cnt_special=$(echo "$_cpp_counts" | awk '{print $4}')

	if [ "$_cpp_min_upper" -gt 0 ] && [ "$_cpp_cnt_upper" -lt "$_cpp_min_upper" ]; then
		return 3
	fi
	if [ "$_cpp_min_lower" -gt 0 ] && [ "$_cpp_cnt_lower" -lt "$_cpp_min_lower" ]; then
		return 4
	fi
	if [ "$_cpp_min_digit" -gt 0 ] && [ "$_cpp_cnt_digit" -lt "$_cpp_min_digit" ]; then
		return 5
	fi
	if [ "$_cpp_min_special" -gt 0 ] && [ "$_cpp_cnt_special" -lt "$_cpp_min_special" ]; then
		return 2
	fi

	# Check contains username
	case "$_cpp_pass" in
		*"$_cpp_user"*) return 7 ;;
	esac

	return 1  # satisfied
}

# password_policy_reason(rc) — returns human-readable reason for check_password_policy return code
password_policy_reason() {
	_ppr_rc="$1"
	# When IPC was used, reason came from IPC_EXTRA
	if [ -n "$IPC_EXTRA" ] && [ "$_ppr_rc" = "2" ]; then
		echo "$IPC_EXTRA"
		return
	fi
	# Fallback: local reason strings (for direct mode)
	case "$_ppr_rc" in
		0) echo "no policy enforced" ;;
		1) echo "password meets policy" ;;
		2) echo "not enough special characters" ;;
		3) echo "not enough uppercase characters" ;;
		4) echo "not enough lowercase characters" ;;
		5) echo "not enough digits" ;;
		6) echo "password too short" ;;
		7) echo "password must not contain username" ;;
		*) echo "unknown policy failure" ;;
	esac
}

# register_password(username, password, [enforce_override])
# Validates password against policy, then hashes and sets it.
# When mgmtd is available, opcode 302 validates + sets server-side.
# Returns 0 on success, 1 on failure.
register_password() {
	_rp_user="$1"
	_rp_pass="$2"
	_rp_enforce_override="$3"

	if _ipc_available; then
		# mgmtd 302 now validates policy server-side before setting
		_set_password "$_rp_user" "$_rp_pass"
		_rp_rc=$?
		if [ "$_rp_rc" -ne 0 ]; then
			# IPC_EXTRA has the error reason from mgmtd
			[ -n "$IPC_EXTRA" ] && echo "  Error: $IPC_EXTRA"
			return 1
		fi
		return 0
	fi

	# Direct fallback (root/init)
	# Check if user exists (skip for new admin creation)
	if [ -z "$_rp_enforce_override" ]; then
		if ! grep -q "^${_rp_user}:" /etc/passwd 2>/dev/null; then
			if ! admin_exists_in_config "$_rp_user"; then
				echo "  Error: user '$_rp_user' does not exist."
				return 1
			fi
		fi
	fi

	_check_password_policy_direct "$_rp_pass" "$_rp_user" "$_rp_enforce_override"
	_rp_rc=$?

	case "$_rp_rc" in
		0|1) ;;  # ok
		*)
			echo "  Error: $(password_policy_reason "$_rp_rc")"
			return 1 ;;
	esac

	_set_password_direct "$_rp_user" "$_rp_pass"
}

# ── _set_password(user, pass) ────────────────────────────────────────────────
# Routes through mgmtd if available (privilege separation).
# Falls back to direct shadow manipulation when running as root (init context).

_set_password() {
	_sp_user="$1"
	_sp_pass="$2"

	if _ipc_available; then
		ipc_send 302 "$(printf '%s\n%s' "$_sp_user" "$_sp_pass")"
		return $IPC_RC
	fi

	# Direct fallback (root only — init context)
	_is_root || { echo "  Error: mgmtd unavailable (password change denied)"; return 1; }
	_set_password_direct "$_sp_user" "$_sp_pass"
}

_set_password_direct() {
	_sp_user="$1"
	_sp_pass="$2"
	_sp_hash=""

	if command -v stargazer-hashpw >/dev/null 2>&1; then
		_sp_hash=$(printf '%s\n' "$_sp_pass" | stargazer-hashpw 2>/dev/null)
	elif command -v mkpasswd >/dev/null 2>&1; then
		_sp_hash=$(mkpasswd -m sha-512 "$_sp_pass" 2>/dev/null)
	elif command -v openssl >/dev/null 2>&1; then
		_sp_hash=$(openssl passwd -6 "$_sp_pass" 2>/dev/null)
	fi

	if [ -z "$_sp_hash" ]; then
		echo "  Error: no password hashing tool available"
		return 1
	fi

	_sp_tmp=$(mktemp /etc/shadow.XXXXXX 2>/dev/null) || _sp_tmp="/etc/shadow.tmp.$$"
	if [ -f /etc/shadow ] && grep -q "^${_sp_user}:" /etc/shadow 2>/dev/null; then
		chmod 640 "$_sp_tmp" 2>/dev/null
		awk -v u="$_sp_user" -v h="$_sp_hash" -F: \
			'BEGIN{OFS=":"; hit=0} $1==u{$2=h; hit=1} {print} END{exit(hit?0:1)}' \
			/etc/shadow > "$_sp_tmp" || {
				rm -f "$_sp_tmp"
				return 1
			}
		mv "$_sp_tmp" /etc/shadow || {
			rm -f "$_sp_tmp"
			return 1
		}
	else
		if [ ! -f /etc/shadow ]; then
			echo "  Error: /etc/shadow not found"
			return 1
		fi
		echo "${_sp_user}:${_sp_hash}:19700:0:99999:7:::" >> /etc/shadow || return 1
	fi
	chmod 640 /etc/shadow 2>/dev/null
	return 0
}

# ── User management ─────────────────────────────────────────────────────────
# Routes through mgmtd if available. Falls back to direct for root context.

_create_system_user() {
	_csu_user="$1"
	_csu_shell="${2:-/bin/sh}"

	if _ipc_available; then
		# mgmtd handles user creation internally via ADMIN_CREATE
		return 0
	fi

	_is_root || { echo "  Error: mgmtd unavailable (user creation denied)"; return 1; }
	_create_system_user_direct "$_csu_user" "$_csu_shell"
}

_create_system_user_direct() {
	_csu_user="$1"
	_csu_shell="${2:-/bin/sh}"

	grep -q "^${_csu_user}:" /etc/passwd 2>/dev/null && return 0

	_csu_uid=1000
	while grep -q "^[^:]*:[^:]*:${_csu_uid}:" /etc/passwd 2>/dev/null; do
		_csu_uid=$((_csu_uid + 1))
	done
	_csu_gid="$_csu_uid"

	echo "${_csu_user}:x:${_csu_uid}:${_csu_gid}:Stargazer Admin:/home/${_csu_user}:${_csu_shell}" >> /etc/passwd

	if [ -f /etc/shadow ]; then
		echo "${_csu_user}::19700:0:99999:7:::" >> /etc/shadow
	fi

	echo "${_csu_user}:x:${_csu_gid}:" >> /etc/group

	# Add user to stargazer group for socket + config access
	if grep -q '^stargazer:' /etc/group 2>/dev/null; then
		_csu_sg_line=$(grep '^stargazer:' /etc/group)
		_csu_members="${_csu_sg_line##*:}"
		if [ -n "$_csu_members" ]; then
			_csu_new="${_csu_sg_line},${_csu_user}"
		else
			_csu_new="${_csu_sg_line}${_csu_user}"
		fi
		_csu_gtmp=$(mktemp /etc/group.XXXXXX 2>/dev/null) || _csu_gtmp="/etc/group.tmp.$$"
		sed "s|^stargazer:.*|${_csu_new}|" /etc/group > "$_csu_gtmp" && mv "$_csu_gtmp" /etc/group
	fi

	mkdir -p "/home/${_csu_user}" 2>/dev/null
	chown "${_csu_uid}:${_csu_gid}" "/home/${_csu_user}" 2>/dev/null

	return 0
}

_delete_system_user() {
	_dsu_user="$1"

	if _ipc_available; then
		# mgmtd handles user deletion internally via ADMIN_DELETE
		return 0
	fi

	_is_root || { echo "  Error: mgmtd unavailable (user deletion denied)"; return 1; }
	_delete_system_user_direct "$_dsu_user"
}

_delete_system_user_direct() {
	_dsu_user="$1"

	if [ -f /etc/passwd ]; then
		_dsu_tmp=$(mktemp /etc/passwd.XXXXXX 2>/dev/null) || _dsu_tmp="/etc/passwd.tmp.$$"
		sed "/^${_dsu_user}:/d" /etc/passwd > "$_dsu_tmp" && mv "$_dsu_tmp" /etc/passwd
	fi

	if [ -f /etc/shadow ]; then
		_dsu_tmp=$(mktemp /etc/shadow.XXXXXX 2>/dev/null) || _dsu_tmp="/etc/shadow.tmp.$$"
		chmod 640 "$_dsu_tmp" 2>/dev/null
		sed "/^${_dsu_user}:/d" /etc/shadow > "$_dsu_tmp" && mv "$_dsu_tmp" /etc/shadow
	fi

	if [ -f /etc/group ]; then
		_dsu_tmp=$(mktemp /etc/group.XXXXXX 2>/dev/null) || _dsu_tmp="/etc/group.tmp.$$"
		sed "/^${_dsu_user}:/d" /etc/group > "$_dsu_tmp" && mv "$_dsu_tmp" /etc/group
	fi

	return 0
}

# ── _get_valid_keys(config_type) ─────────────────────────────────────────────

_get_valid_keys() {
	case "$1" in
		network_route_static) echo "dst gateway device distance status comment" ;;
		network_nat)          echo "type srcintf dstintf srcaddr dstaddr dstport mapped-ip mapped-port status" ;;
		system_interface)     echo "ip status mtu description" ;;
		system_settings)      echo "hostname ip-forward timezone" ;;
		system_hostname)      echo "hostname" ;;
		network_dns)          echo "primary secondary" ;;
		system_ntp)           echo "server status" ;;
		firewall_policy)      echo "name srcintf dstintf srcaddr dstaddr action service schedule status comment" ;;
		firewall_address)     echo "name subnet type comment" ;;
		firewall_service)     echo "name protocol port-range comment" ;;
		system_password-policy) echo "min-length min-uppercase min-lowercase min-digit min-special" ;;
		system_admin-profile) echo "permissions description" ;;
		system_admin)         echo "profile password enforce-change-password enforce-password-policy" ;;
		*)                    echo "" ;;
	esac
}

# ── cfg_required_keys(config_type) ───────────────────────────────────────────
# Returns space-separated mandatory keys for a config type.

cfg_required_keys() {
	case "$1" in
		network_route_static) echo "dst" ;;
		firewall_policy)      echo "name srcintf dstintf srcaddr dstaddr action status" ;;
		firewall_address)     echo "name subnet type" ;;
		firewall_service)     echo "name protocol port-range" ;;
		system_admin)         echo "profile" ;;
		system_admin-profile) echo "permissions" ;;
		*)                    echo "" ;;
	esac
}

# ── cfg_validate_required(config_type, tmpfile) ──────────────────────────────
# Returns 0 if all required keys present, 1 + prints missing keys to stdout.

cfg_validate_required() {
	_vr_type="$1"
	_vr_file="$2"
	_vr_keys=$(cfg_required_keys "$_vr_type")
	[ -z "$_vr_keys" ] && return 0
	_vr_missing=""
	for _vr_k in $_vr_keys; do
		if ! grep -q "^${_vr_k}=" "$_vr_file" 2>/dev/null; then
			_vr_missing="$_vr_missing $_vr_k"
		fi
	done
	if [ -n "$_vr_missing" ]; then
		echo "$_vr_missing"
		return 1
	fi
	return 0
}

# ── cfg_default_values(config_type) ──────────────────────────────────────────
# Outputs key=value lines for sensible defaults when creating new entries.

cfg_default_values() {
	case "$1" in
		firewall_policy)
			printf '%s\n' "status=enable" "action=deny" "srcintf=any" "dstintf=any" "srcaddr=all" "dstaddr=all"
			;;
		system_admin)
			printf '%s\n' "enforce-change-password=enable" "enforce-password-policy=enable"
			;;
		system_interface)
			printf '%s\n' "status=up" "mtu=1500"
			;;
		network_route_static)
			printf '%s\n' "status=enable" "distance=10"
			;;
		firewall_address)
			printf '%s\n' "type=ipmask"
			;;
		firewall_service)
			printf '%s\n' "protocol=tcp"
			;;
		system_password-policy)
			printf '%s\n' "min-length=8" "min-uppercase=0" "min-lowercase=0" "min-digit=0" "min-special=0"
			;;
	esac
}

# ── Generic key/value metadata (shared by CLI parser + completion) ─────────

cfg_is_valid_key() {
	_ck_type="$1"
	_ck_key="$2"
	_ck_keys=$(_get_valid_keys "$_ck_type")
	[ -z "$_ck_keys" ] && return 0
	for _ck in $_ck_keys; do
		[ "$_ck" = "$_ck_key" ] && return 0
	done
	return 1
}

cfg_entry_id_kind() {
	_ci_type="$1"
	case "$_ci_type" in
		firewall_policy) echo "uint" ;;
		*) echo "safe-id" ;;
	esac
}

cfg_entry_id_rule() {
	_ci_type="$1"
	_ci_kind=$(cfg_entry_id_kind "$_ci_type")
	case "$_ci_kind" in
		uint) echo "number" ;;
		safe-id) echo "string [A-Za-z0-9_.-]" ;;
		*) echo "id" ;;
	esac
}

cfg_validate_entry_id() {
	_ci_type="$1"
	_ci_id="$2"
	_ci_kind=$(cfg_entry_id_kind "$_ci_type")
	case "$_ci_kind" in
		uint)
			case "$_ci_id" in
				""|*[!0-9]*) return 1 ;;
				*) return 0 ;;
			esac
			;;
		safe-id)
			_is_safe_id "$_ci_id"
			;;
		*)
			[ -n "$_ci_id" ]
			;;
	esac
}

cfg_value_kind() {
	_cv_type="$1"
	_cv_key="$2"
	case "${_cv_type}:${_cv_key}" in
		network_route_static:dst|system_interface:ip|firewall_address:subnet) echo "cidr" ;;
		network_route_static:gateway|network_nat:mapped-ip|network_dns:primary|network_dns:secondary|system_ntp:server) echo "ipv4" ;;
		network_route_static:device|network_nat:srcintf|network_nat:dstintf|firewall_policy:srcintf|firewall_policy:dstintf) echo "iface" ;;
		network_route_static:distance) echo "uint:1:255" ;;
		network_route_static:status|network_nat:status|system_settings:ip-forward|system_ntp:status|firewall_policy:status|system_admin:enforce-change-password|system_admin:enforce-password-policy) echo "enum:enable,disable" ;;
		system_password-policy:min-length) echo "uint:0:128" ;;
		system_password-policy:min-uppercase|system_password-policy:min-lowercase|system_password-policy:min-digit|system_password-policy:min-special) echo "uint:0:128" ;;
		network_nat:type) echo "enum:snat,dnat" ;;
		network_nat:srcaddr|network_nat:dstaddr) echo "cidr-or:any,all" ;;
		network_nat:dstport|network_nat:mapped-port) echo "uint:1:65535" ;;
		system_interface:status) echo "enum:up,down" ;;
		system_interface:mtu) echo "uint:576:9200" ;;
		system_settings:hostname|system_hostname:hostname) echo "safe-id" ;;
		system_settings:timezone) echo "tz-token" ;;
		firewall_policy:action) echo "enum:accept,deny,drop" ;;
		firewall_policy:name|firewall_address:name|firewall_service:name) echo "safe-id" ;;
		firewall_policy:srcaddr|firewall_policy:dstaddr) echo "ref-or:firewall_address:all,any" ;;
		firewall_policy:service) echo "ref-or:firewall_service:all,any" ;;
		firewall_policy:schedule) echo "safe-id-or:all,any" ;;
		firewall_address:type) echo "enum:ipmask,iprange,fqdn" ;;
		firewall_service:protocol) echo "enum:tcp,udp,icmp" ;;
		firewall_service:port-range) echo "port-or-range" ;;
		system_admin-profile:permissions) echo "permissions-csv" ;;
		system_admin:profile) echo "ref:system_admin-profile" ;;
		system_admin:password) echo "password-interactive" ;;
		*) echo "string" ;;
	esac
}

_cfg_ref_list() {
	_cr_type="$1"
	_cr_file=$(cfg_domain_for "$_cr_type")
	cfg_list "$_cr_file" "$_cr_type" 2>/dev/null
}

_cfg_ref_exists() {
	_ce_type="$1"
	_ce_val="$2"
	_ce_file=$(cfg_domain_for "$_ce_type")

	# Match by object-id first
	if cfg_get "$_ce_file" "${_ce_type}:${_ce_val}" >/dev/null 2>&1; then
		return 0
	fi

	# Match by 'name=' field for object types that carry display names
	for _ce_id in $(cfg_list "$_ce_file" "$_ce_type" 2>/dev/null); do
		_ce_data=$(cfg_get "$_ce_file" "${_ce_type}:${_ce_id}" 2>/dev/null)
		_ce_name=$(echo "$_ce_data" | grep '^name=' | cut -d= -f2-)
		[ "$_ce_name" = "$_ce_val" ] && return 0
	done
	return 1
}

cfg_value_rule() {
	_cr_type="$1"
	_cr_key="$2"
	_cr_kind=$(cfg_value_kind "$_cr_type" "$_cr_key")
	case "$_cr_kind" in
		cidr) echo "CIDR (A.B.C.D/len)" ;;
		ipv4) echo "IPv4" ;;
		iface) echo "interface name" ;;
		uint:*)
			_cr_min=${_cr_kind#uint:}
			_cr_min=${_cr_min%%:*}
			_cr_max=${_cr_kind##*:}
			echo "integer ${_cr_min}-${_cr_max}"
			;;
		enum:*)
			echo "${_cr_kind#enum:}" | tr ',' '|'
			;;
		cidr-or:*)
			_cr_alt=${_cr_kind#cidr-or:}
			echo "CIDR or $(echo "$_cr_alt" | tr ',' '|')"
			;;
		ref:*)
			echo "existing ${_cr_kind#ref:} object"
			;;
		ref-or:*)
			_cr_t=${_cr_kind#ref-or:}
			_cr_t=${_cr_t%%:*}
			_cr_alt=${_cr_kind#ref-or:${_cr_t}:}
			echo "existing ${_cr_t} object or $(echo "$_cr_alt" | tr ',' '|')"
			;;
		safe-id) echo "safe identifier [A-Za-z0-9_.-]" ;;
		safe-id-or:*)
			_cr_alt=${_cr_kind#safe-id-or:}
			echo "safe identifier or $(echo "$_cr_alt" | tr ',' '|')"
			;;
		tz-token) echo "timezone token (e.g. Asia/Ho_Chi_Minh)" ;;
		permissions-csv) echo "CSV: monitor,configure,admin" ;;
		port-or-range) echo "port or range (e.g. 80, 1024-65535)" ;;
		password-interactive) echo "interactive prompt" ;;
		*) echo "string" ;;
	esac
}

cfg_value_suggestions() {
	_cs_type="$1"
	_cs_key="$2"
	_cs_kind=$(cfg_value_kind "$_cs_type" "$_cs_key")
	case "$_cs_kind" in
		cidr) echo "A.B.C.D/24" ;;
		ipv4) echo "A.B.C.D" ;;
		iface) echo "eth0 wan lan" ;;
		uint:0:128) echo "0 1 2 4 8" ;;
		uint:1:255) echo "1 10 20 100" ;;
		uint:576:9200) echo "1500 9000" ;;
		enum:*) echo "${_cs_kind#enum:}" | tr ',' ' ' ;;
		cidr-or:*)
			_cs_alt=${_cs_kind#cidr-or:}
			echo "A.B.C.D/24 $(echo "$_cs_alt" | tr ',' ' ')"
			;;
		ref:*)
			_cs_ref=${_cs_kind#ref:}
			_cs_seen=""
			_cs_out=""
			for _cs_v in $(_cfg_ref_list "$_cs_ref"); do
				[ -z "$_cs_v" ] && continue
				case "|$_cs_seen|" in
					*"|${_cs_v}|"*) ;;
					*) _cs_out="${_cs_out} ${_cs_v}"; _cs_seen="${_cs_seen}|${_cs_v}" ;;
				esac
			done
			[ "$_cs_ref" = "system_admin-profile" ] && for _d in read-write read-only; do
				case "|$_cs_seen|" in
					*"|${_d}|"*) ;;
					*) _cs_out="${_cs_out} ${_d}"; _cs_seen="${_cs_seen}|${_d}" ;;
				esac
			done
			echo "${_cs_out# }"
			;;
		ref-or:*)
			_cs_ref=${_cs_kind#ref-or:}
			_cs_ref_t=${_cs_ref%%:*}
			_cs_alt=${_cs_kind#ref-or:${_cs_ref_t}:}
			_cs_seen=""
			_cs_out=""
			for _cs_v in $(_cfg_ref_list "$_cs_ref_t"); do
				[ -z "$_cs_v" ] && continue
				case "|$_cs_seen|" in *"|${_cs_v}|"*) ;; *) _cs_out="${_cs_out} ${_cs_v}"; _cs_seen="${_cs_seen}|${_cs_v}" ;; esac
			done
			for _cs_v in $(echo "$_cs_alt" | tr ',' ' '); do
				case "|$_cs_seen|" in *"|${_cs_v}|"*) ;; *) _cs_out="${_cs_out} ${_cs_v}"; _cs_seen="${_cs_seen}|${_cs_v}" ;; esac
			done
			echo "${_cs_out# }"
			;;
		safe-id-or:*) echo "${_cs_kind#safe-id-or:}" | tr ',' ' ' ;;
		permissions-csv) echo "monitor configure admin monitor,configure,admin" ;;
		port-or-range) echo "80 443 1024-65535" ;;
		*) echo "" ;;
	esac
}

cfg_validate_value() {
	_cv_type="$1"
	_cv_key="$2"
	_cv_val="$3"
	_cv_kind=$(cfg_value_kind "$_cv_type" "$_cv_key")

	case "$_cv_kind" in
		cidr)
			_is_cidr "$_cv_val" || return 1
			;;
		ipv4)
			_is_ipv4 "$_cv_val" || return 1
			;;
		iface)
			_is_iface_name "$_cv_val" || return 1
			;;
		uint:*)
			_cv_min=${_cv_kind#uint:}
			_cv_min=${_cv_min%%:*}
			_cv_max=${_cv_kind##*:}
			_is_uint_range "$_cv_val" "$_cv_min" "$_cv_max" || return 1
			;;
		enum:*)
			_cv_ok=1
			for _cv_e in $(echo "${_cv_kind#enum:}" | tr ',' ' '); do
				[ "$_cv_val" = "$_cv_e" ] && _cv_ok=0 && break
			done
			[ "$_cv_ok" -eq 0 ] || return 1
			;;
		cidr-or:*)
			_cv_ok=1
			for _cv_e in $(echo "${_cv_kind#cidr-or:}" | tr ',' ' '); do
				[ "$_cv_val" = "$_cv_e" ] && _cv_ok=0 && break
			done
			[ "$_cv_ok" -eq 0 ] || _is_cidr "$_cv_val" || return 1
			;;
		ref:*)
			_cv_ref=${_cv_kind#ref:}
			_is_safe_id "$_cv_val" || return 1
			_cfg_ref_exists "$_cv_ref" "$_cv_val" || return 1
			;;
		ref-or:*)
			_cv_ref=${_cv_kind#ref-or:}
			_cv_ref_t=${_cv_ref%%:*}
			_cv_alt=${_cv_kind#ref-or:${_cv_ref_t}:}
			for _cv_e in $(echo "$_cv_alt" | tr ',' ' '); do
				[ "$_cv_val" = "$_cv_e" ] && return 0
			done
			_is_safe_id "$_cv_val" || return 1
			_cfg_ref_exists "$_cv_ref_t" "$_cv_val" || return 1
			;;
		safe-id)
			_is_safe_id "$_cv_val" || return 1
			;;
		safe-id-or:*)
			for _cv_e in $(echo "${_cv_kind#safe-id-or:}" | tr ',' ' '); do
				[ "$_cv_val" = "$_cv_e" ] && return 0
			done
			_is_safe_id "$_cv_val" || return 1
			;;
		tz-token)
			case "$_cv_val" in
				""|*[!A-Za-z0-9_./+-]*) return 1 ;;
				*) ;;
			esac
			;;
		permissions-csv)
			[ -n "$_cv_val" ] || return 1
			_validate_permissions_csv "$_cv_val" || return 1
			;;
		port-or-range)
			case "$_cv_val" in
				*[!0-9-]*) return 1 ;;
				*-[0-9]*)
					_cv_a="${_cv_val%-*}"
					_cv_b="${_cv_val#*-}"
					_is_uint_range "$_cv_a" 1 65535 || return 1
					_is_uint_range "$_cv_b" 1 65535 || return 1
					[ "$_cv_a" -le "$_cv_b" ] 2>/dev/null || return 1
					;;
				*)
					_is_uint_range "$_cv_val" 1 65535 || return 1
					;;
			esac
			;;
		password-interactive)
			# handled by interactive branch in cmd_configure
			return 0
			;;
		*)
			[ -n "$_cv_val" ] || return 1
			;;
	esac

	return 0
}

_show_valid_keys() {
	echo ""
	echo "  Available keys for '$1':"
	case "$1" in
		network_route_static)
			echo "    dst          Destination network (e.g. 10.0.0.0/24)"
			echo "    gateway      Next-hop IP address"
			echo "    device       Outgoing interface"
			echo "    distance     Administrative distance (1-255)"
			echo "    status       enable | disable"
			echo "    comment      Description text"
			;;
		network_nat)
			echo "    type         snat | dnat"
			echo "    srcintf      Source interface (for SNAT)"
			echo "    dstintf      Destination interface"
			echo "    srcaddr      Source address/mask"
			echo "    dstaddr      Destination address/mask"
			echo "    dstport      Destination port (for DNAT)"
			echo "    mapped-ip    Translated IP address"
			echo "    mapped-port  Translated port"
			echo "    status       enable | disable"
			;;
		system_interface)
			echo "    ip           IP address/mask (e.g. 192.168.1.1/24)"
			echo "    status       up | down"
			echo "    mtu          MTU value"
			echo "    description  Interface description"
			;;
		system_settings)
			echo "    hostname     System hostname"
			echo "    ip-forward   enable | disable"
			echo "    timezone     System timezone"
			;;
		system_hostname)
			echo "    hostname     System hostname"
			;;
		firewall_policy)
			echo "    name         Policy name"
			echo "    srcintf      Source interface"
			echo "    dstintf      Destination interface"
			echo "    srcaddr      Source address object"
			echo "    dstaddr      Destination address object"
			echo "    action       accept | deny | drop"
			echo "    service      Service object"
			echo "    schedule     Schedule name"
			echo "    status       enable | disable"
			echo "    comment      Description text"
			;;
		firewall_address)
			echo "    name         Address object name"
			echo "    subnet       IP/mask (e.g. 10.0.0.0/24)"
			echo "    type         ipmask | iprange | fqdn"
			echo "    comment      Description text"
			;;
		firewall_service)
			echo "    name         Service name"
			echo "    protocol     tcp | udp | icmp"
			echo "    port-range   Port or range (e.g. 80 or 1024-65535)"
			echo "    comment      Description text"
			;;
		system_password-policy)
			echo "    min-length    Minimum password length (0=no check)"
			echo "    min-uppercase Minimum uppercase characters (0=no check)"
			echo "    min-lowercase Minimum lowercase characters (0=no check)"
			echo "    min-digit     Minimum digit characters (0=no check)"
			echo "    min-special   Minimum special characters (0=no check)"
			;;
		system_admin-profile)
			echo "    description   Profile description text"
			;;
		system_admin)
			echo "    profile       Admin profile name (e.g. read-write)"
			echo "    password      Set user password (interactive)"
			echo "    enforce-change-password   enable | disable"
			echo "    enforce-password-policy   enable | disable"
			;;
		*)
			echo "    (any key=value accepted)"
			;;
	esac
}

_get_value_hint() {
	_gh_type="$1"
	_gh_key="$2"
	cfg_value_rule "$_gh_type" "$_gh_key"
}

_get_value_suggestions() {
	_gs_type="$1"
	_gs_key="$2"
	cfg_value_suggestions "$_gs_type" "$_gs_key"
}

# ── _apply_config(type, id, tmpfile) ─────────────────────────────────────────
# Apply configuration to the running system.
# Routes through mgmtd when available (privilege separation).
# Falls back to direct system calls when running as root (init/replay).

_apply_config() {
	_apply_name="$1"
	_apply_id="$2"
	_apply_file="$3"

	if _ipc_available; then
		# Send through IPC: payload = "type\nid\ndata"
		_ipc_payload=$(printf '%s\n%s\n' "$_apply_name" "$_apply_id"; cat "$_apply_file"; printf '\n')
		ipc_send 202 "$_ipc_payload"
		if [ "$IPC_RC" -eq 0 ]; then
			[ -n "$IPC_PAYLOAD" ] && echo "$IPC_PAYLOAD"
			return 0
		else
			ipc_print_error
			return 1
		fi
	fi

	# Direct fallback (root only — init/replay context)
	_is_root || { echo "  Error: mgmtd unavailable (apply denied)"; return 1; }
	_apply_config_direct "$_apply_name" "$_apply_id" "$_apply_file"
}

_apply_config_direct() {
	_apply_name="$1"
	_apply_id="$2"
	_apply_file="$3"

	case "$_apply_name" in
		network_route_static)
			_dst=$(grep '^dst=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_gw=$(grep '^gateway=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_dev=$(grep '^device=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_status=$(grep '^status=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_dist=$(grep '^distance=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			if [ "$_status" = "disable" ]; then
				ip route del "$_dst" 2>/dev/null
				echo "  Route $_apply_id disabled."
				return 0
			fi
			if [ -z "$_dst" ]; then
				echo "  Warning: 'dst' not set, route not applied."
				return 1
			fi
			if ! _is_cidr "$_dst"; then
				echo "  Error: invalid dst '$_dst' (expected x.x.x.x/len)"
				return 1
			fi
			[ -n "$_gw" ] && ! _is_ipv4 "$_gw" && {
				echo "  Error: invalid gateway '$_gw'"
				return 1
			}
			[ -n "$_dev" ] && ! _is_iface_name "$_dev" && {
				echo "  Error: invalid device '$_dev'"
				return 1
			}
			[ -n "$_dist" ] && ! _is_uint_range "$_dist" 1 255 && {
				echo "  Error: invalid distance '$_dist' (1-255)"
				return 1
			}
			if [ -n "$_gw" ] && [ -n "$_dev" ]; then
				ip route replace "$_dst" via "$_gw" dev "$_dev" 2>&1 | sed 's/^/  /'
			elif [ -n "$_gw" ]; then
				ip route replace "$_dst" via "$_gw" 2>&1 | sed 's/^/  /'
			elif [ -n "$_dev" ]; then
				ip route replace "$_dst" dev "$_dev" 2>&1 | sed 's/^/  /'
			else
				ip route replace "$_dst" 2>&1 | sed 's/^/  /'
			fi
			echo "  Route $_apply_id applied: $_dst"
			return 0
			;;
		network_nat)
			_type=$(grep '^type=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_srcintf=$(grep '^srcintf=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_dstport=$(grep '^dstport=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_mapped_ip=$(grep '^mapped-ip=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_mapped_port=$(grep '^mapped-port=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_status=$(grep '^status=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			[ "$_status" = "disable" ] && return
			case "$_type" in
				snat|dnat) ;;
				*) echo "  Error: invalid NAT type '$_type' (snat|dnat)"; return 1 ;;
			esac
			[ -n "$_srcintf" ] && ! _is_iface_name "$_srcintf" && {
				echo "  Error: invalid srcintf '$_srcintf'"
				return 1
			}
			[ -n "$_dstport" ] && ! _is_uint_range "$_dstport" 1 65535 && {
				echo "  Error: invalid dstport '$_dstport' (1-65535)"
				return 1
			}
			[ -n "$_mapped_ip" ] && ! _is_ipv4 "$_mapped_ip" && {
				echo "  Error: invalid mapped-ip '$_mapped_ip'"
				return 1
			}
			[ -n "$_mapped_port" ] && ! _is_uint_range "$_mapped_port" 1 65535 && {
				echo "  Error: invalid mapped-port '$_mapped_port' (1-65535)"
				return 1
			}
			case "$_type" in
				snat)
					[ -n "$_srcintf" ] && iptables -t nat -A POSTROUTING -o "$_srcintf" -j MASQUERADE 2>&1 | sed 's/^/  /'
					echo "  SNAT rule $_apply_id applied."
					;;
				dnat)
					if [ -n "$_dstport" ] && [ -n "$_mapped_ip" ]; then
						_target="$_mapped_ip"
						[ -n "$_mapped_port" ] && _target="${_target}:${_mapped_port}"
						iptables -t nat -A PREROUTING -p tcp --dport "$_dstport" -j DNAT --to-destination "$_target" 2>&1 | sed 's/^/  /'
						echo "  DNAT rule $_apply_id applied."
					fi
					;;
			esac
			;;
		system_interface)
			_ip=$(grep '^ip=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_status=$(grep '^status=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_mtu=$(grep '^mtu=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			if ! _is_iface_name "$_apply_id"; then
				echo "  Error: invalid interface name '$_apply_id'"
				return 1
			fi
			[ -n "$_ip" ] && ! _is_cidr "$_ip" && {
				echo "  Error: invalid ip '$_ip'"
				return 1
			}
			[ -n "$_mtu" ] && ! _is_uint_range "$_mtu" 576 9200 && {
				echo "  Error: invalid mtu '$_mtu' (576-9200)"
				return 1
			}
			case "$_status" in
				""|up|down) ;;
				*) echo "  Error: invalid status '$_status' (up|down)"; return 1 ;;
			esac
			if [ -n "$_ip" ]; then
				ip addr flush dev "$_apply_id" 2>/dev/null
				ip addr add "$_ip" dev "$_apply_id" 2>&1 | sed 's/^/  /'
			fi
			case "$_status" in
				up)   ip link set "$_apply_id" up 2>&1 | sed 's/^/  /' ;;
				down) ip link set "$_apply_id" down 2>&1 | sed 's/^/  /' ;;
			esac
			[ -n "$_mtu" ] && ip link set "$_apply_id" mtu "$_mtu" 2>&1 | sed 's/^/  /'
			echo "  Interface $_apply_id configured."
			return 0
			;;
		system_settings)
			_hostname=$(grep '^hostname=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_ipfwd=$(grep '^ip-forward=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			[ -n "$_hostname" ] && ! _is_safe_id "$_hostname" && {
				echo "  Error: invalid hostname '$_hostname'"
				return 1
			}
			[ -n "$_hostname" ] && hostname "$_hostname" 2>/dev/null && echo "$_hostname" > /etc/hostname
			case "$_ipfwd" in
				""|enable)  [ -n "$_ipfwd" ] && echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null ;;
				disable) echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null ;;
				*) echo "  Error: invalid ip-forward '$_ipfwd' (enable|disable)"; return 1 ;;
			esac
			echo "  System settings applied."
			;;
		system_password-policy)
			# Validate all fields are non-negative integers
			for _ppk in min-length min-uppercase min-lowercase min-digit min-special; do
				_ppv=$(grep "^${_ppk}=" "$_apply_file" 2>/dev/null | cut -d= -f2-)
				if [ -n "$_ppv" ]; then
					case "$_ppv" in
						*[!0-9]*|"")
							echo "  Error: invalid value for '$_ppk': '$_ppv' (integer 0-128)"
							return 1
							;;
					esac
					if [ "$_ppv" -gt 128 ]; then
						echo "  Error: '$_ppk' value too large (max 128)"
						return 1
					fi
				fi
			done
			echo "  Password policy updated."
			audit_log "password_policy_apply" "updated"
			return 0
			;;
		system_hostname)
			_name=$(grep '^hostname=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			if [ -n "$_name" ]; then
				if ! _is_safe_id "$_name"; then
					echo "  Error: invalid hostname '$_name'"
					return 1
				fi
				hostname "$_name" 2>/dev/null
				echo "$_name" > /etc/hostname
				echo "  Hostname set to '$_name'."
			fi
			return 0
			;;
		system_admin-profile)
			_prof_name="$_apply_id"
			_perms=$(grep '^permissions=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_desc=$(grep '^description=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_desc="${_desc:-Custom profile}"
			_builtin=$(grep '^builtin=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			if ! _is_safe_id "$_prof_name"; then
				echo "  Error: invalid profile name '$_prof_name'"
				audit_log "admin_profile_reject" "invalid-name=${_prof_name}"
				return 1
			fi
			if [ -z "$_perms" ]; then
				echo "  Warning: 'permissions' not set, profile not applied."
				audit_log "admin_profile_reject" "name=${_prof_name} reason=missing-permissions"
				return 1
			fi
			if ! _validate_permissions_csv "$_perms"; then
				echo "  Error: invalid permissions list '$_perms'"
				audit_log "admin_profile_reject" "name=${_prof_name} reason=invalid-perms"
				return 1
			fi
			audit_log "admin_profile_apply" "name=${_prof_name} perms=${_perms}"
			echo "  Profile '$_prof_name' loaded (perms: $_perms)."
			session_profile_rev_bump "$_prof_name"
			return 0
			;;
		system_admin)
			_adm_name="$_apply_id"
			_profile=$(grep '^profile=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_password=$(grep '^password=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_enforce=$(grep '^enforce-change-password=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_enforce_policy=$(grep '^enforce-password-policy=' "$_apply_file" 2>/dev/null | cut -d= -f2-)
			_existing=$(cfg_get "$STARGAZER_CONF_DIR/system.conf" "system_admin:${_adm_name}" 2>/dev/null)
			_existing_enforce=$(echo "$_existing" | grep '^enforce-change-password=' | cut -d= -f2-)
			_existing_enforce_policy=$(echo "$_existing" | grep '^enforce-password-policy=' | cut -d= -f2-)
			if [ -z "$_enforce" ]; then
				if [ -n "$_existing" ]; then
					_enforce="${_existing_enforce:-disable}"
				else
					# New admin default: force change password on first login
					_enforce="enable"
				fi
				if grep -q '^enforce-change-password=' "$_apply_file" 2>/dev/null; then
					_ac_sed="${_apply_file}.sed.$$"
					sed "s|^enforce-change-password=.*|enforce-change-password=${_enforce}|" "$_apply_file" > "$_ac_sed" && mv "$_ac_sed" "$_apply_file"
				else
					echo "enforce-change-password=${_enforce}" >> "$_apply_file"
				fi
			fi
			# Handle enforce-password-policy default
			if [ -z "$_enforce_policy" ]; then
				if [ -n "$_existing" ]; then
					_enforce_policy="${_existing_enforce_policy:-enable}"
				else
					_enforce_policy="enable"
				fi
				if grep -q '^enforce-password-policy=' "$_apply_file" 2>/dev/null; then
					_ac_sed="${_apply_file}.sed.$$"
					sed "s|^enforce-password-policy=.*|enforce-password-policy=${_enforce_policy}|" "$_apply_file" > "$_ac_sed" && mv "$_ac_sed" "$_apply_file"
				else
					echo "enforce-password-policy=${_enforce_policy}" >> "$_apply_file"
				fi
			fi
			case "$_enforce" in
				enable|disable) ;;
				*)
					echo "  Error: invalid enforce-change-password '$_enforce' (enable|disable)"
					audit_log "admin_apply_reject" "name=${_adm_name} reason=invalid-enforce value=${_enforce}"
					return 1
					;;
			esac
			case "$_enforce_policy" in
				enable|disable) ;;
				*)
					echo "  Error: invalid enforce-password-policy '$_enforce_policy' (enable|disable)"
					audit_log "admin_apply_reject" "name=${_adm_name} reason=invalid-enforce-policy value=${_enforce_policy}"
					return 1
					;;
			esac
			if ! _is_safe_id "$_adm_name"; then
				echo "  Error: invalid admin name '$_adm_name'"
				audit_log "admin_apply_reject" "invalid-name=${_adm_name}"
				return 1
			fi
			if [ -z "$_profile" ]; then
				echo "  Warning: 'profile' not set, admin not applied."
				audit_log "admin_apply_reject" "name=${_adm_name} reason=missing-profile"
				return 1
			fi
			if ! _is_safe_id "$_profile"; then
				echo "  Error: invalid profile name '$_profile'"
				audit_log "admin_apply_reject" "name=${_adm_name} reason=invalid-profile-name"
				return 1
			fi
			# Check profile exists in system.conf
			_prof_perms=$(cfg_get "$STARGAZER_CONF_DIR/system.conf" "system_admin-profile:${_profile}" 2>/dev/null \
				| grep '^permissions=' | cut -d= -f2-)
			if [ -z "$_prof_perms" ]; then
				echo "  Error: profile '$_profile' does not exist."
				audit_log "admin_apply_reject" "name=${_adm_name} reason=profile-not-found profile=${_profile}"
				return 1
			fi
			# Create Linux user if not exists
			if ! grep -q "^${_adm_name}:" /etc/passwd 2>/dev/null; then
				if ! _create_system_user "$_adm_name" /sbin/stargazer-cli; then
					echo "  Error: failed to create Linux user '$_adm_name'."
					audit_log "admin_apply_reject" "name=${_adm_name} reason=create-user-failed"
					return 1
				fi
				echo "  Linux user '$_adm_name' created."
				audit_log "admin_create" "name=${_adm_name} profile=${_profile}"
			fi
			# Handle password if set
			if [ -n "$_password" ]; then
				if ! register_password "$_adm_name" "$_password" "$_enforce_policy"; then
					audit_log "admin_apply_reject" "name=${_adm_name} reason=set-password-failed"
					return 1
				fi
				# Remove password from temp file (don't store plaintext)
				_ac_sed="${_apply_file}.sed.$$"
				sed '/^password=/d' "$_apply_file" > "$_ac_sed" && mv "$_ac_sed" "$_apply_file"
				echo "  Password set for '$_adm_name'."
				audit_log "admin_password_set" "name=${_adm_name}"
			fi
			audit_log "admin_apply" "name=${_adm_name} profile=${_profile}"
			echo "  Admin '$_adm_name' applied (profile: $_profile)."
			session_user_rev_bump "$_adm_name"
			return 0
			;;
		*)
			echo "  (config saved — no auto-apply handler for $_apply_name)"
			return 0
			;;
	esac
}
