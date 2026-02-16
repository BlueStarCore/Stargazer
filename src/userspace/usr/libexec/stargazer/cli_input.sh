#!/bin/sh
# Stargazer NGFW - Interactive readline with Tab completion and ? help
# Sourced by stargazer-cli. Do not execute directly.
#
# PERFORMANCE: All completion logic uses pure shell builtins (case/for/IFS).
# Zero forks on Tab or ? — critical for responsive CLI on ARM64 BusyBox.
#
# Provides: cli_readline <prompt>
#   - Tab: cycle through matching completions
#   - ?: show available next words with descriptions
#   - Backspace, Ctrl-C, Ctrl-D, Ctrl-U, Ctrl-W handled
#   - Sets $REPLY to user input

# ── Command registry ────────────────────────────────────────────────────────
_CLI_CMDS=""
_CLI_PATHS=""
_CLI_STACK=""
_CLI_STACK_N=0
_CLI_HISTORY=""
_CLI_HISTORY_N=0
_CLI_HISTORY_MAX=100
_CLI_HISTORY_FILE="/tmp/stargazer_cli_history_$(id -u 2>/dev/null || echo 0)"

cli_register() {
	_CLI_CMDS="${_CLI_CMDS}${1}|${2}
"
	_CLI_PATHS="${_CLI_PATHS}${1}
"
}

# Save current registry onto stack and start fresh (for sub-contexts)
cli_push() {
	_CLI_STACK_N=$((_CLI_STACK_N + 1))
	eval "_CLI_STACK_CMDS_${_CLI_STACK_N}=\$_CLI_CMDS"
	eval "_CLI_STACK_PATHS_${_CLI_STACK_N}=\$_CLI_PATHS"
	_CLI_CMDS=""
	_CLI_PATHS=""
}

# Restore from stack
cli_pop() {
	[ "$_CLI_STACK_N" -le 0 ] && return
	eval "_CLI_CMDS=\$_CLI_STACK_CMDS_${_CLI_STACK_N}"
	eval "_CLI_PATHS=\$_CLI_STACK_PATHS_${_CLI_STACK_N}"
	eval "_CLI_STACK_CMDS_${_CLI_STACK_N}="
	eval "_CLI_STACK_PATHS_${_CLI_STACK_N}="
	_CLI_STACK_N=$((_CLI_STACK_N - 1))
}

# ── Word helpers (pure shell, no awk) ───────────────────────────────────────
# Extract Nth word into _NTH — no subshell, no fork
# Usage: _cli_nth "string" N   →  result in $_NTH
_cli_nth() {
	_nth_i=1
	_NTH=""
	_nth_IFS="$IFS"
	IFS=' '
	for _nth_w in $1; do
		if [ "$_nth_i" -eq "$2" ]; then
			_NTH="$_nth_w"
			IFS="$_nth_IFS"
			return
		fi
		_nth_i=$((_nth_i + 1))
	done
	_NTH=""
	IFS="$_nth_IFS"
}

# ── Completion engine (zero-fork) ──────────────────────────────────────────

_cli_build_tab_matches() {
	_input="$1"
	_TAB_RESULT=""
	_seen=""

	case "$_input" in
		*" ")
			# Trailing space → complete next word
			_IFS_T="$IFS"
			IFS=' '
			set -- $_input
			_depth=$#
			IFS="$_IFS_T"
			_target=$((_depth + 1))
			_IFS_S="$IFS"
			IFS='
'
			for _p in $_CLI_PATHS; do
				case "$_p" in
					${_input}*)
						_cli_nth "$_p" "$_target"
						[ -z "$_NTH" ] && continue
						_cand="${_input}${_NTH}"
						case "|$_seen|" in
							*"|${_cand}|"*) ;;
							*) _TAB_RESULT="${_TAB_RESULT}${_cand}
"
							   _seen="${_seen}|${_cand}" ;;
						esac
						;;
				esac
			done
			IFS="$_IFS_S"
			;;
		*)
			# No trailing space → complete partial word
			_IFS_T="$IFS"
			IFS=' '
			set -- $_input
			_nw=$#
			IFS="$_IFS_T"
			if [ "$_nw" -le 1 ]; then
				_partial="$_input"
				_IFS_S="$IFS"
				IFS='
'
				for _p in $_CLI_PATHS; do
					_first="${_p%% *}"
					case "$_first" in
						${_partial}*)
							case "|$_seen|" in
								*"|${_first}|"*) ;;
								*) _TAB_RESULT="${_TAB_RESULT}${_first}
"
								   _seen="${_seen}|${_first}" ;;
							esac
							;;
					esac
				done
				IFS="$_IFS_S"
			else
				_partial="${_input##* }"
				_prefix="${_input% *}"
				_IFS_T="$IFS"
				IFS=' '
				set -- $_prefix
				_target=$#
				IFS="$_IFS_T"
				_target=$((_target + 1))
				_IFS_S="$IFS"
				IFS='
'
				for _p in $_CLI_PATHS; do
					case "$_p" in
						${_prefix}\ ${_partial}*)
							_cli_nth "$_p" "$_target"
							[ -z "$_NTH" ] && continue
							_cand="${_prefix} ${_NTH}"
							case "|$_seen|" in
								*"|${_cand}|"*) ;;
								*) _TAB_RESULT="${_TAB_RESULT}${_cand}
"
								   _seen="${_seen}|${_cand}" ;;
							esac
							;;
					esac
				done
				IFS="$_IFS_S"
			fi
			;;
	esac
}

# _cli_build_help "raw_buffer"
# If buffer ends with space → show next-level words
# If buffer has partial word (no trailing space) → show matches at current level
_cli_build_help() {
	_raw="$1"
	_HELP_RESULT=""
	_seen=""
	_h_exact_cmd="$_raw"
	while [ "$_h_exact_cmd" != "${_h_exact_cmd% }" ]; do
		_h_exact_cmd="${_h_exact_cmd% }"
	done
	_h_exact_desc=""

	if [ -n "$_h_exact_cmd" ]; then
		_IFS_S="$IFS"
		IFS='
'
		for _entry in $_CLI_CMDS; do
			[ -z "$_entry" ] && continue
			_path="${_entry%%|*}"
			_desc="${_entry#*|}"
			[ "$_path" = "$_h_exact_cmd" ] || continue
			_h_exact_desc="$_desc"
			break
		done
		IFS="$_IFS_S"
	fi

	if [ -n "$_h_exact_desc" ]; then
		_pad="<Enter>                        "
		_pad="${_pad%"${_pad#????????????????????????}"}"
		_HELP_RESULT="${_HELP_RESULT}  ${_pad} ${_h_exact_desc}
"
	fi

	# Determine mode: partial word or next word?
	case "$_raw" in
		"")
			# Empty → show all top-level words
			_h_prefix=""
			_h_target=1
			_h_pattern=""
			;;
		*" ")
			# Trailing space → show next-level words after complete input
			_h_prefix="$_raw"
			# strip trailing spaces for matching
			while [ "$_h_prefix" != "${_h_prefix% }" ]; do
				_h_prefix="${_h_prefix% }"
			done
			_IFS_T="$IFS"; IFS=' '
			set -- $_h_prefix
			_h_target=$(($# + 1))
			IFS="$_IFS_T"
			_h_pattern="${_h_prefix}"
			;;
		*)
			# No trailing space → partial word, show matches at THIS level
			_h_partial="${_raw##* }"
			_h_prefix="${_raw% *}"
			# If single word, prefix is empty
			if [ "$_h_prefix" = "$_raw" ]; then
				_h_prefix=""
				_h_target=1
			else
				_IFS_T="$IFS"; IFS=' '
				set -- $_h_prefix
				_h_target=$(($# + 1))
				IFS="$_IFS_T"
			fi
			# Pattern: prefix + partial filter
			if [ -n "$_h_prefix" ]; then
				_h_pattern="${_h_prefix} ${_h_partial}"
			else
				_h_pattern="${_h_partial}"
			fi
			;;
	esac

	_IFS_S="$IFS"
	IFS='
'
	for _entry in $_CLI_CMDS; do
		[ -z "$_entry" ] && continue
		_path="${_entry%%|*}"
		_desc="${_entry#*|}"
		[ -z "$_path" ] && continue
		case "$_path" in
			${_h_pattern}*)
				_cli_nth "$_path" "$_h_target"
				[ -z "$_NTH" ] && continue
				case "|$_seen|" in
					*"|${_NTH}|"*) ;;
					*)
						_pad="$_NTH                        "
						_pad="${_pad%"${_pad#????????????????????????}"}"
						_HELP_RESULT="${_HELP_RESULT}  ${_pad} ${_desc}
"
						_seen="${_seen}|${_NTH}"
						;;
				esac
				;;
		esac
	done
	IFS="$_IFS_S"
}

# ── Terminal helpers ────────────────────────────────────────────────────────

_cli_redraw() {
	printf '\r\033[K%s%s' "$_cli_prompt" "$_cli_buf"
}

_cli_hist_get() {
	_h_idx="$1"
	_HIST_LINE=""
	_h_i=1
	_h_IFS="$IFS"
	IFS='
'
	for _h_l in $_CLI_HISTORY; do
		if [ "$_h_i" -eq "$_h_idx" ]; then
			_HIST_LINE="$_h_l"
			break
		fi
		_h_i=$((_h_i + 1))
	done
	IFS="$_h_IFS"
}

_cli_hist_add() {
	_h_line="$1"
	[ -z "$_h_line" ] && return
	if [ "$_CLI_HISTORY_N" -gt 0 ]; then
		_cli_hist_get "$_CLI_HISTORY_N"
		[ "$_HIST_LINE" = "$_h_line" ] && return
	fi
	_CLI_HISTORY="${_CLI_HISTORY}${_h_line}
"
	_CLI_HISTORY_N=$((_CLI_HISTORY_N + 1))

	if [ "$_CLI_HISTORY_N" -gt "$_CLI_HISTORY_MAX" ]; then
		_h_new=""
		_h_i=0
		_h_IFS="$IFS"
		IFS='
'
		for _h_l in $_CLI_HISTORY; do
			_h_i=$((_h_i + 1))
			[ "$_h_i" -eq 1 ] && continue
			_h_new="${_h_new}${_h_l}
"
		done
		IFS="$_h_IFS"
		_CLI_HISTORY="$_h_new"
		_CLI_HISTORY_N=$_CLI_HISTORY_MAX
	fi

	# Persist to file (for C readline and cross-session history)
	# Safety: refuse to write through symlinks (BUG-CLI-06)
	if [ -L "$_CLI_HISTORY_FILE" ]; then
		rm -f "$_CLI_HISTORY_FILE" 2>/dev/null
	fi
	echo "$_h_line" >> "$_CLI_HISTORY_FILE" 2>/dev/null
}

# Load history from file on startup
_cli_hist_load() {
	[ -f "$_CLI_HISTORY_FILE" ] || return
	# Refuse to read symlinks (BUG-CLI-06)
	[ -L "$_CLI_HISTORY_FILE" ] && { rm -f "$_CLI_HISTORY_FILE" 2>/dev/null; return; }
	while IFS= read -r _hl_line; do
		[ -z "$_hl_line" ] && continue
		_CLI_HISTORY="${_CLI_HISTORY}${_hl_line}
"
		_CLI_HISTORY_N=$((_CLI_HISTORY_N + 1))
	done < "$_CLI_HISTORY_FILE"
}
_cli_hist_load

# ── Main readline function ─────────────────────────────────────────────────

cli_readline() {
	_cli_prompt="$1"

	# ── Fast path: use C readline binary if available ──
	if command -v stargazer-readline >/dev/null 2>&1; then
		_cr_tmpfile=$(mktemp /tmp/cli_comps.XXXXXX 2>/dev/null || echo "/tmp/cli_comps_${UID:-0}_$$_$(date +%s).txt")
		_cr_IFS="$IFS"
		IFS='
'
		if > "$_cr_tmpfile" 2>/dev/null; then
			for _cr_entry in $_CLI_CMDS; do
				[ -z "$_cr_entry" ] && continue
				echo "$_cr_entry" >> "$_cr_tmpfile"
			done
			IFS="$_cr_IFS"
			REPLY=$(stargazer-readline "$_cli_prompt" "$_cr_tmpfile" "$_CLI_HISTORY_FILE")
			rm -f "$_cr_tmpfile" >/dev/null 2>&1 || true
			return
		fi
		IFS="$_cr_IFS"
	fi

	# ── Fallback: pure shell readline ──
	_cli_buf=""
	_tab_matches=""
	_tab_count=0
	_tab_idx=0
	_tab_prefix=""
	_hist_idx=$((_CLI_HISTORY_N + 1))

	_cli_saved_tty=$(stty -g 2>/dev/null)
	stty raw -echo 2>/dev/null

	printf '%s' "$_cli_prompt"

	while true; do
		_c=$(dd bs=1 count=1 2>/dev/null)
		_ord=$(printf '%d' "'$_c" 2>/dev/null || echo 0)

		case "$_ord" in
			10|13) # Enter
				printf '\r\n'
				_cli_hist_add "$_cli_buf"
				break
				;;
			3) # Ctrl-C
				_cli_buf=""
				printf '\r\n'
				break
				;;
			4) # Ctrl-D
				if [ -z "$_cli_buf" ]; then
					_cli_buf="exit"
					printf '\r\n'
					break
				fi
				;;
			21) # Ctrl-U — clear line
				_cli_buf=""
				_tab_matches=""
				_tab_count=0
				_cli_redraw
				;;
			23) # Ctrl-W — delete last word
				while [ "$_cli_buf" != "${_cli_buf% }" ]; do
					_cli_buf="${_cli_buf% }"
				done
				_cli_buf="${_cli_buf% *}"
				[ -n "$_cli_buf" ] && _cli_buf="$_cli_buf "
				case "$_cli_buf" in " ") _cli_buf="" ;; esac
				_tab_matches=""
				_tab_count=0
				_cli_redraw
				;;
			27) # ESC sequence (arrows)
				_e1=$(dd bs=1 count=1 2>/dev/null)
				_e2=$(dd bs=1 count=1 2>/dev/null)
				if [ "$_e1" = "[" ]; then
					case "$_e2" in
						A) # Up
							if [ "$_CLI_HISTORY_N" -gt 0 ] && [ "$_hist_idx" -gt 1 ]; then
								_hist_idx=$((_hist_idx - 1))
								_cli_hist_get "$_hist_idx"
								_cli_buf="$_HIST_LINE"
								_cli_redraw
							fi
							_tab_matches=""
							_tab_count=0
							;;
						B) # Down
							if [ "$_hist_idx" -le "$_CLI_HISTORY_N" ]; then
								_hist_idx=$((_hist_idx + 1))
								if [ "$_hist_idx" -eq $((_CLI_HISTORY_N + 1)) ]; then
									_cli_buf=""
								else
									_cli_hist_get "$_hist_idx"
									_cli_buf="$_HIST_LINE"
								fi
								_cli_redraw
							fi
							_tab_matches=""
							_tab_count=0
							;;
					esac
				fi
				;;
			127|8) # Backspace
				if [ -n "$_cli_buf" ]; then
					_cli_buf="${_cli_buf%?}"
					_cli_redraw
				fi
				_tab_matches=""
				_tab_count=0
				;;
			9) # Tab ─────────────────────────────────────────────
				_match_input="$_cli_buf"
				while [ "$_match_input" != "${_match_input% }" ]; do
					_match_input="${_match_input% }"
				done

				if [ -z "$_tab_matches" ] || [ "$_tab_prefix" != "$_match_input" ]; then
					_tab_prefix="$_match_input"
					_cli_build_tab_matches "$_cli_buf"
					_tab_matches="$_TAB_RESULT"
					_tab_idx=0
					_tab_count=0
					_IFS_S="$IFS"
					IFS='
'
					for _tl in $_tab_matches; do
						[ -n "$_tl" ] && _tab_count=$((_tab_count + 1))
					done
					IFS="$_IFS_S"
				else
					_tab_idx=$((_tab_idx + 1))
				fi

				if [ "$_tab_count" -gt 0 ]; then
					[ "$_tab_idx" -ge "$_tab_count" ] && _tab_idx=0
					_ln=0
					_completed=""
					_IFS_S="$IFS"
					IFS='
'
					for _tl in $_tab_matches; do
						[ -z "$_tl" ] && continue
						if [ "$_ln" -eq "$_tab_idx" ]; then
							_completed="$_tl"
							break
						fi
						_ln=$((_ln + 1))
					done
					IFS="$_IFS_S"
					if [ -n "$_completed" ]; then
						_cli_buf="${_completed}"
						# Append trailing space on unique match for faster typing
						[ "$_tab_count" -eq 1 ] && _cli_buf="${_cli_buf} "
						_cli_redraw
					fi
				fi
				;;
			63) # ? ──────────────────────────────────────────────
				# Pass raw buffer — help function handles partial vs complete
				_cli_build_help "$_cli_buf"
				printf '\r\n'
				if [ -n "$_HELP_RESULT" ]; then
					stty "$_cli_saved_tty" 2>/dev/null
					printf '%s' "$_HELP_RESULT"
					stty raw -echo 2>/dev/null
				else
					if [ -n "$_cli_buf" ]; then
						printf '  No matching command.\r\n'
					else
						printf '  <cr>  Execute command\r\n'
					fi
				fi
				_cli_redraw
				_tab_matches=""
				_tab_count=0
				;;
			*) # Printable character
				if [ "$_ord" -ge 32 ] && [ "$_ord" -le 126 ]; then
					_cli_buf="${_cli_buf}${_c}"
					printf '%s' "$_c"
				fi
				_tab_matches=""
				_tab_count=0
				;;
		esac
	done

	stty "$_cli_saved_tty" 2>/dev/null
	REPLY="$_cli_buf"
}
