/* SPDX-License-Identifier: MIT */
/*
 * cli_configure.c — Interactive configure mode for Stargazer CLI
 *
 * C translation of cmd_configure.
 * Three context types: table (show/edit/delete/end),
 * entry (set/unset/show/get/next/end/abort),
 * single (set/unset/show/get/end/abort).
 *
 * All config I/O goes through IPC (opcodes 100-202, 301, 304, 500-502).
 * In-memory key=value buffer replaces temp files.
 */

#define _DEFAULT_SOURCE

#include "cli_configure.h"
#include "cli_readline.h"
#include "cli_ipc.h"
#include "cli_debug.h"
#include "sg_validate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

/* ── In-memory key=value buffer ───────────────────────────────────────── */

#define KV_MAX_ENTRIES 64
#define KV_MAX_KEY     64
#define KV_MAX_VAL     512

struct kv_pair {
	char key[KV_MAX_KEY];
	char val[KV_MAX_VAL];
};

struct kv_buf {
	struct kv_pair entries[KV_MAX_ENTRIES];
	int count;
	int modified;
};

static int cfg_dbg(void)
{
	return dbg_enabled() &&
	       strcmp(dbg_get("cli_debug", "0"), "1") == 0;
}

static void kv_init(struct kv_buf *b)
{
	b->count = 0;
	b->modified = 0;
}

static const char *kv_get(const struct kv_buf *b, const char *key)
{
	for (int i = 0; i < b->count; i++) {
		if (strcmp(b->entries[i].key, key) == 0)
			return b->entries[i].val;
	}
	return NULL;
}

static int kv_set(struct kv_buf *b, const char *key, const char *val)
{
	for (int i = 0; i < b->count; i++) {
		if (strcmp(b->entries[i].key, key) == 0) {
			snprintf(b->entries[i].val, KV_MAX_VAL, "%s", val);
			b->modified = 1;
			return 0;
		}
	}
	if (b->count < KV_MAX_ENTRIES) {
		snprintf(b->entries[b->count].key, KV_MAX_KEY, "%s", key);
		snprintf(b->entries[b->count].val, KV_MAX_VAL, "%s", val);
		b->count++;
		b->modified = 1;
		return 0;
	}
	return -1;
}

static void kv_unset(struct kv_buf *b, const char *key)
{
	for (int i = 0; i < b->count; i++) {
		if (strcmp(b->entries[i].key, key) == 0) {
			memmove(&b->entries[i], &b->entries[i + 1],
				(size_t)(b->count - i - 1) * sizeof(b->entries[0]));
			b->count--;
			b->modified = 1;
			return;
		}
	}
}

/* Parse "key=val\nkey=val\n..." into kv_buf */
static void kv_parse(struct kv_buf *b, const char *data)
{
	const char *p = data;
	while (p && *p) {
		const char *eol = strchr(p, '\n');
		size_t llen = eol ? (size_t)(eol - p) : strlen(p);

		if (llen > 0) {
			const char *eq = memchr(p, '=', llen);
			if (eq && b->count < KV_MAX_ENTRIES) {
				size_t klen = (size_t)(eq - p);
				size_t vlen = llen - klen - 1;
				if (klen > 0 && klen < KV_MAX_KEY) {
					memcpy(b->entries[b->count].key, p, klen);
					b->entries[b->count].key[klen] = '\0';
					if (vlen >= KV_MAX_VAL)
						vlen = KV_MAX_VAL - 1;
					memcpy(b->entries[b->count].val, eq + 1, vlen);
					b->entries[b->count].val[vlen] = '\0';
					b->count++;
				}
			}
		}
		if (!eol)
			break;
		p = eol + 1;
	}
}

/* Serialize kv_buf to "key=val\nkey=val\n..." */
static size_t kv_serialize(const struct kv_buf *b, char *out, size_t out_sz)
{
	size_t pos = 0;
	for (int i = 0; i < b->count; i++) {
		int n = snprintf(out + pos, out_sz - pos,
				 "%s=%s\n", b->entries[i].key,
				 b->entries[i].val);
		if (n < 0 || pos + (size_t)n >= out_sz)
			break;
		pos += (size_t)n;
	}
	return pos;
}

/* Check whether a value should be quoted in FortiGate-style output.
 * Free-text "string" kind → quoted; structured kinds (enum, uint, etc.) → bare. */
static int value_needs_quote(const char *type, const char *key)
{
	const char *kind = sg_reg_value_kind(type, key);
	return strcmp(kind, "string") == 0;
}

/* ── Helpers ──────────────────────────────────────────────────────────── */

/* Strip surrounding double quotes in-place: "foo" → foo */
static void strip_quotes(char *s)
{
	size_t len = strlen(s);
	if (len >= 2 && s[0] == '"' && s[len - 1] == '"') {
		memmove(s, s + 1, len - 2);
		s[len - 2] = '\0';
	}
}

static void parse_line(const char *line,
		       char *cmd, size_t cmd_sz,
		       char *key, size_t key_sz,
		       char *val, size_t val_sz)
{
	cmd[0] = key[0] = val[0] = '\0';

	/* Skip leading whitespace */
	while (*line == ' ' || *line == '\t')
		line++;

	/* Extract command */
	const char *sp = strchr(line, ' ');
	if (!sp) {
		snprintf(cmd, cmd_sz, "%s", line);
		return;
	}
	size_t clen = (size_t)(sp - line);
	if (clen >= cmd_sz) clen = cmd_sz - 1;
	memcpy(cmd, line, clen);
	cmd[clen] = '\0';

	/* Skip spaces after command */
	const char *rest = sp + 1;
	while (*rest == ' ') rest++;
	if (!*rest) return;

	/* Extract key */
	sp = strchr(rest, ' ');
	if (!sp) {
		snprintf(key, key_sz, "%s", rest);
		return;
	}
	size_t klen = (size_t)(sp - rest);
	if (klen >= key_sz) klen = key_sz - 1;
	memcpy(key, rest, klen);
	key[klen] = '\0';

	/* Extract value (rest of line) */
	const char *v = sp + 1;
	while (*v == ' ') v++;
	if (*v) snprintf(val, val_sz, "%s", v);

	strip_quotes(key);
	strip_quotes(val);
}

/* Trim leading and trailing whitespace in-place */
static char *trim(char *s)
{
	while (*s == ' ' || *s == '\t') s++;
	size_t len = strlen(s);
	while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t'))
		s[--len] = '\0';
	return s;
}

/* Read password from terminal with echo disabled.
 * Uses the pre-opened tty fd from cli_get_tty_fd() — safe inside sandbox
 * (open("/dev/tty") would be killed by seccomp/Landlock). */
static int read_password(const char *prompt, char *buf, size_t buf_sz)
{
	struct termios old, noecho;
	int tty = cli_get_tty_fd();
	if (tty < 0) tty = STDIN_FILENO;

	printf("%s", prompt);
	fflush(stdout);

	if (tcgetattr(tty, &old) != 0) {
		/* Can't control echo — fall back to visible read */
		if (fgets(buf, (int)buf_sz, stdin)) {
			size_t len = strlen(buf);
			if (len > 0 && buf[len - 1] == '\n')
				buf[--len] = '\0';
			return (int)len;
		}
		return 0;
	}
	noecho = old;
	noecho.c_lflag &= ~(tcflag_t)ECHO;
	noecho.c_lflag |= ICANON;
	tcsetattr(tty, TCSANOW, &noecho);

	int pos = 0;
	char c;
	while (pos < (int)buf_sz - 1) {
		ssize_t n = read(tty, &c, 1);
		if (n <= 0) break;
		if (c == '\n' || c == '\r') break;
		buf[pos++] = c;
	}
	buf[pos] = '\0';

	tcsetattr(tty, TCSANOW, &old);
	printf("\n");

	return pos;
}

/* Reject unexpected trailing arguments in configure contexts */
static int cfg_reject_extra(const char *extra, const char *cmd_name)
{
	if (extra && extra[0]) {
		printf("  Error: unexpected argument after '%s': %s\n",
		       cmd_name, extra);
		return 1;
	}
	return 0;
}

/* Check if required fields are present. Returns NULL if OK, or space-sep missing keys. */
static const char *validate_required(const char *type_name,
				     const struct kv_buf *b)
{
	static char missing[512];
	missing[0] = '\0';

	const char *req = sg_reg_required_keys(type_name);
	if (!req || !*req)
		return NULL;

	/* Walk space-separated required keys */
	char reqbuf[256];
	snprintf(reqbuf, sizeof(reqbuf), "%s", req);
	char *tok = reqbuf;
	int any_missing = 0;

	while (*tok) {
		while (*tok == ' ') tok++;
		if (!*tok) break;

		char *end = tok;
		while (*end && *end != ' ') end++;
		char saved = *end;
		*end = '\0';

		if (!kv_get(b, tok)) {
			size_t mlen = strlen(missing);
			snprintf(missing + mlen, sizeof(missing) - mlen,
				 " %s", tok);
			any_missing = 1;
		}

		*end = saved;
		tok = end;
	}

	return any_missing ? missing : NULL;
}

/*
 * Register value-level completions for a key based on its kind.
 * For example, "enum:enable,disable" registers "set status enable"
 * and "set status disable". ref:TYPE queries mgmtd via IPC.
 */
static void register_value_completions(const char *key, const char *kind)
{
	if (!kind || !*kind)
		return;

	char regpath[CLI_MAX_LINE], regdesc[CLI_MAX_LINE];

	/* ── enum:a,b,c ──────────────────────────────────────────────── */
	if (strncmp(kind, "enum:", 5) == 0) {
		char buf[256];
		snprintf(buf, sizeof(buf), "%s", kind + 5);
		char *p = buf;
		while (*p) {
			char *comma = strchr(p, ',');
			if (comma) *comma = '\0';
			snprintf(regpath, sizeof(regpath), "set %s %s", key, p);
			snprintf(regdesc, sizeof(regdesc), "%s", p);
			cli_register(regpath, regdesc);
			if (comma) p = comma + 1; else break;
		}
		return;
	}

	/* ── ref:TYPE — fetch entries via IPC ─────────────────────────── */
	if (strncmp(kind, "ref:", 4) == 0) {
		const char *ref_type = kind + 4;
		struct ipc_response resp;
		if (ipc_send_str(SG_CMD_CFG_LIST, ref_type, &resp) == 0 &&
		    resp.payload && resp.payload_len > 0) {
			const char *p = resp.payload;
			while (*p) {
				const char *eol = strchr(p, '\n');
				size_t len = eol ? (size_t)(eol - p) : strlen(p);
				if (len == 0) { p++; continue; }
				char id[256];
				if (len >= sizeof(id)) len = sizeof(id) - 1;
				memcpy(id, p, len);
				id[len] = '\0';
				snprintf(regpath, sizeof(regpath),
					 "set %s %s", key, id);
				snprintf(regdesc, sizeof(regdesc),
					 "%s (existing %s)", id, ref_type);
				cli_register(regpath, regdesc);
				p += len;
				if (eol) p++;
			}
		}
		ipc_resp_free(&resp);
		return;
	}

	/* ── ref-or:TYPE:a,b — options + IPC entries ─────────────────── */
	if (strncmp(kind, "ref-or:", 7) == 0) {
		char buf[256];
		snprintf(buf, sizeof(buf), "%s", kind + 7);
		/* Parse "TYPE:a,b" */
		char *colon = strchr(buf, ':');
		if (colon) {
			*colon = '\0';
			const char *ref_type = buf;
			char *opts = colon + 1;

			/* Register hardcoded options */
			char *p = opts;
			while (*p) {
				char *comma = strchr(p, ',');
				if (comma) *comma = '\0';
				snprintf(regpath, sizeof(regpath),
					 "set %s %s", key, p);
				snprintf(regdesc, sizeof(regdesc), "%s", p);
				cli_register(regpath, regdesc);
				if (comma) p = comma + 1; else break;
			}

			/* Fetch entries from referenced type */
			struct ipc_response resp;
			if (ipc_send_str(SG_CMD_CFG_LIST, ref_type, &resp) == 0 &&
			    resp.payload && resp.payload_len > 0) {
				p = resp.payload;
				while (*p) {
					const char *eol = strchr(p, '\n');
					size_t len = eol ? (size_t)(eol - p) : strlen(p);
					if (len == 0) { p++; continue; }
					char id[256];
					if (len >= sizeof(id)) len = sizeof(id) - 1;
					memcpy(id, p, len);
					id[len] = '\0';
					snprintf(regpath, sizeof(regpath),
						 "set %s %s", key, id);
					snprintf(regdesc, sizeof(regdesc),
						 "%s (%s)", id, ref_type);
					cli_register(regpath, regdesc);
					p += len;
					if (eol) p++;
				}
			}
			ipc_resp_free(&resp);
		}
		return;
	}

	/* ── safe-id-or:a,b — register hardcoded options ─────────────── */
	if (strncmp(kind, "safe-id-or:", 11) == 0) {
		char buf[256];
		snprintf(buf, sizeof(buf), "%s", kind + 11);
		char *p = buf;
		while (*p) {
			char *comma = strchr(p, ',');
			if (comma) *comma = '\0';
			snprintf(regpath, sizeof(regpath), "set %s %s", key, p);
			snprintf(regdesc, sizeof(regdesc), "%s", p);
			cli_register(regpath, regdesc);
			if (comma) p = comma + 1; else break;
		}
		return;
	}

	/* ── cidr-or:a,b — register hardcoded options ────────────────── */
	if (strncmp(kind, "cidr-or:", 8) == 0) {
		char buf[256];
		snprintf(buf, sizeof(buf), "%s", kind + 8);
		char *p = buf;
		while (*p) {
			char *comma = strchr(p, ',');
			if (comma) *comma = '\0';
			snprintf(regpath, sizeof(regpath), "set %s %s", key, p);
			snprintf(regdesc, sizeof(regdesc), "%s", p);
			cli_register(regpath, regdesc);
			if (comma) p = comma + 1; else break;
		}
		return;
	}

	/* ── permissions-csv — register known permission values ───────── */
	if (strcmp(kind, "permissions-csv") == 0) {
		static const char *perms[] = {
			"monitor", "configure", "admin", NULL
		};
		for (int i = 0; perms[i]; i++) {
			snprintf(regpath, sizeof(regpath),
				 "set %s %s", key, perms[i]);
			snprintf(regdesc, sizeof(regdesc),
				 "%s permission", perms[i]);
			cli_register(regpath, regdesc);
		}
		return;
	}

	/* Other kinds (cidr, ipv4, uint, safe-id, etc.) — no value completions */
}

/* Register set commands for a config type */
static void register_set_cmds(const char *type_name)
{
	const char *keys = sg_reg_valid_keys(type_name);
	if (!keys || !*keys) {
		cli_register("set", "Set a parameter (set <key> <value>)");
		return;
	}

	char keybuf[512];
	snprintf(keybuf, sizeof(keybuf), "%s", keys);
	char *tok = keybuf;

	while (*tok) {
		while (*tok == ' ') tok++;
		if (!*tok) break;

		char *end = tok;
		while (*end && *end != ' ') end++;
		char saved = *end;
		*end = '\0';

		char regpath[CLI_MAX_LINE], regdesc[CLI_MAX_LINE];
		const char *desc = sg_reg_field_desc(type_name, tok);
		snprintf(regpath, sizeof(regpath), "set %s", tok);
		snprintf(regdesc, sizeof(regdesc), "%s", desc);
		cli_register(regpath, regdesc);

		/* Register value-level completions based on kind */
		const char *kind = sg_reg_value_kind(type_name, tok);
		if (kind)
			register_value_completions(tok, kind);

		*end = saved;
		tok = end;
	}
}

/* Register unset/get completions for each valid key */
static void register_unset_get_cmds(const char *type_name)
{
	const char *keys = sg_reg_valid_keys(type_name);
	if (!keys || !*keys)
		return;

	char keybuf[512];
	snprintf(keybuf, sizeof(keybuf), "%s", keys);
	char *tok = keybuf;

	while (*tok) {
		while (*tok == ' ') tok++;
		if (!*tok) break;

		char *end = tok;
		while (*end && *end != ' ') end++;
		char saved = *end;
		*end = '\0';

		char regpath[CLI_MAX_LINE], regdesc[CLI_MAX_LINE];
		snprintf(regpath, sizeof(regpath), "unset %s", tok);
		snprintf(regdesc, sizeof(regdesc), "Unset %s", tok);
		cli_register(regpath, regdesc);

		snprintf(regpath, sizeof(regpath), "get %s", tok);
		snprintf(regdesc, sizeof(regdesc), "Get %s", tok);
		cli_register(regpath, regdesc);

		*end = saved;
		tok = end;
	}
}

/* Register entry context sub-commands */
static void register_entry_cmds(const char *type_name)
{
	cli_register("show", "Show all parameters for this entry");
	cli_register("next", "Save entry and return to table");
	cli_register("end", "Save entry and exit context");
	cli_register("abort", "Discard changes and exit");
	register_set_cmds(type_name);
	register_unset_get_cmds(type_name);
}

/* Register table context sub-commands */
static void register_table_cmds(const char *type_name)
{
	const char *id_kind = sg_reg_entry_id_kind(type_name);
	char edit_desc[64], del_desc[64];
	snprintf(edit_desc, sizeof(edit_desc), "Allow: %s", id_kind);
	snprintf(del_desc, sizeof(del_desc), "Allow: %s", id_kind);
	cli_register("show", "Show all entries");
	cli_register("edit <id>", edit_desc);
	cli_register("delete <id>", del_desc);
	cli_register("end", "Exit this context");
}

/* Register single context sub-commands */
static void register_single_cmds(const char *type_name)
{
	cli_register("show", "Show all parameters");
	cli_register("end", "Save and exit");
	cli_register("abort", "Discard changes and exit");
	register_set_cmds(type_name);
	register_unset_get_cmds(type_name);
}

/* ── Reference existence check ────────────────────────────────────────── */

/*
 * Check if a ref: or ref-or: value actually exists.
 * Returns 1 if OK (not a ref, or is a hardcoded option, or entry exists).
 * Returns 0 if the referenced entry does not exist.
 */
static int check_ref_exists(const char *type_name, const char *key,
			    const char *val)
{
	const char *kind = sg_reg_value_kind(type_name, key);
	char rt[64], ro[64];

	if (!sg_parse_ref_kind(kind, rt, sizeof(rt), ro, sizeof(ro)))
		return 1; /* not a ref kind — always valid */

	/* Check hardcoded options (e.g. "all", "any") */
	if (ro[0] && sg_match_csv_option(ro, val)) {
		if (cfg_dbg())
			fprintf(stderr,
				"[CFG-DBG] ref check: %s=%s"
				" (hardcoded option)\n", key, val);
		return 1;
	}

	/* Check if entry exists via IPC */
	char section[512];
	snprintf(section, sizeof(section), "%s:%s", rt, val);

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_CFG_GET, section, &resp) == 0 &&
	    resp.status == SG_OK) {
		if (cfg_dbg())
			fprintf(stderr,
				"[CFG-DBG] ref check: %s=%s"
				" (exists in %s)\n", key, val, rt);
		ipc_resp_free(&resp);
		return 1;
	}
	if (cfg_dbg())
		fprintf(stderr,
			"[CFG-DBG] ref check: %s=%s"
			" (NOT FOUND in %s)\n", key, val, rt);
	ipc_resp_free(&resp);
	return 0;
}

/* ── Apply config via IPC ─────────────────────────────────────────────── */

static int apply_config(const char *type_name, const char *id,
			const struct kv_buf *b)
{
	if (cfg_dbg())
		fprintf(stderr,
			"[CFG-DBG] apply: sending CFG_APPLY"
			" type=%s id=%s\n", type_name, id);

	char payload[4096];
	int hdr_len = snprintf(payload, sizeof(payload), "%s\n%s\n",
			       type_name, id);
	if (hdr_len < 0 || (size_t)hdr_len >= sizeof(payload)) return -1;

	char data[2048];
	kv_serialize(b, data, sizeof(data));

	size_t total = (size_t)hdr_len + strlen(data);
	if (total >= sizeof(payload)) return -1;
	memcpy(payload + hdr_len, data, strlen(data) + 1);

	struct ipc_response resp;
	if (ipc_send(SG_CMD_CFG_APPLY, payload, total, &resp) != 0) {
		if (cfg_dbg())
			fprintf(stderr,
				"[CFG-DBG] apply: IPC send failed\n");
		return -1;
	}

	if (resp.status != SG_OK) {
		if (cfg_dbg())
			fprintf(stderr,
				"[CFG-DBG] apply: FAILED status=%u\n",
				resp.status);
		if (resp.extra[0])
			printf("  Error: %s\n", resp.extra);
		else
			printf("  Error: %s\n", sg_status_str(resp.status));
		ipc_resp_free(&resp);
		return -1;
	}

	if (cfg_dbg())
		fprintf(stderr, "[CFG-DBG] apply: OK\n");
	if (resp.payload && resp.payload[0])
		printf("%s", resp.payload);
	ipc_resp_free(&resp);
	return 0;
}

/* ── Password handling ────────────────────────────────────────────────── */

static int handle_password(const char *entry_id, struct kv_buf *b)
{
	char pw1[256], pw2[256];

	read_password("  New password: ", pw1, sizeof(pw1));

	/* Check password policy via IPC.
	 * mgmtd ADMIN_CHECK_PW payload: "username\npassword[\nenforce_override]" */
	const char *enf = kv_get(b, "enforce-password-policy");
	char policy_payload[1024];
	snprintf(policy_payload, sizeof(policy_payload), "%s\n%s\n%s",
		 entry_id, pw1, enf ? enf : "");

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_ADMIN_CHECK_PW, policy_payload, &resp) == 0) {
		if (resp.status == SG_ERR_POLICY_FAIL) {
			if (resp.extra[0])
				printf("  Error: %s\n", resp.extra);
			else
				printf("  Error: password does not meet policy\n");
			ipc_resp_free(&resp);
			explicit_bzero(policy_payload, sizeof(policy_payload));
			return -1;
		}
		ipc_resp_free(&resp);
	}
	explicit_bzero(policy_payload, sizeof(policy_payload));

	read_password("  Retype password: ", pw2, sizeof(pw2));

	if (strcmp(pw1, pw2) != 0) {
		printf("  Passwords don't match.\n");
		explicit_bzero(pw1, sizeof(pw1));
		explicit_bzero(pw2, sizeof(pw2));
		return -1;
	}

	if (kv_set(b, "password", pw1) != 0) {
		printf("  Error: too many configuration entries (max %d).\n",
		       KV_MAX_ENTRIES);
		explicit_bzero(pw1, sizeof(pw1));
		explicit_bzero(pw2, sizeof(pw2));
		return -1;
	}
	printf("  Password will be set on save.\n");

	/* Clear from stack */
	explicit_bzero(pw1, sizeof(pw1));
	explicit_bzero(pw2, sizeof(pw2));
	return 0;
}

/* ── Entry context ────────────────────────────────────────────────────── */

static int context_entry(const char *type_name, const char *label,
			 const char *entry_id, int *exit_all)
{
	struct kv_buf data;
	kv_init(&data);
	int is_new = 0;
	int password_cleared = 0;

	if (cfg_dbg())
		fprintf(stderr,
			"[CFG-DBG] enter entry: %s:%s\n",
			type_name, entry_id);

	/* Load existing data via IPC */
	char section[512];
	snprintf(section, sizeof(section), "%s:%s", type_name, entry_id);

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_CFG_GET, section, &resp) == 0 &&
	    resp.status == SG_OK && resp.payload) {
		kv_parse(&data, resp.payload);
		if (cfg_dbg())
			fprintf(stderr,
				"[CFG-DBG] loaded existing entry"
				" %s (%d keys)\n",
				entry_id, data.count);
		printf("  Editing entry %s.\n", entry_id);
	} else {
		is_new = 1;
		/* Apply defaults */
		const char *defs = sg_reg_default_values(type_name);
		if (defs && *defs) {
			kv_parse(&data, defs);
			data.modified = 1;
			if (cfg_dbg())
				fprintf(stderr,
					"[CFG-DBG] new entry %s"
					" (defaults: %d keys)\n",
					entry_id, data.count);
			printf("  Creating new entry %s (defaults applied).\n",
			       entry_id);
		} else {
			if (cfg_dbg())
				fprintf(stderr,
					"[CFG-DBG] new entry %s"
					" (no defaults)\n",
					entry_id);
			printf("  Creating new entry %s.\n", entry_id);
		}
	}
	ipc_resp_free(&resp);

	cli_push();
	register_entry_cmds(type_name);

	char prompt[384];
	snprintf(prompt, sizeof(prompt), "(%s-%s) # ", label, entry_id);

	const char *line;
	while ((line = cli_readline(prompt)) != NULL) {
		char cmd[64], key[64], val[512];
		char linebuf[1024];
		snprintf(linebuf, sizeof(linebuf), "%s", line);
		char *trimmed = trim(linebuf);
		if (!*trimmed) continue;

		char resolved[CLI_MAX_LINE];
		if (cli_resolve_cmd(trimmed, resolved,
				    sizeof(resolved)) != 0)
			continue;

		parse_line(resolved, cmd, sizeof(cmd),
			   key, sizeof(key), val, sizeof(val));

		if (cfg_dbg())
			fprintf(stderr,
				"[CFG-DBG] entry cmd: %s%s%s%s%s\n",
				cmd,
				key[0] ? " " : "", key,
				val[0] ? " " : "", val);

		if (strcmp(cmd, "set") == 0) {
			if (!key[0]) {
				printf("  Usage: set <key> <value>\n");
				continue;
			}
			if (!sg_reg_is_valid_key(type_name, key)) {
				if (cfg_dbg())
					fprintf(stderr,
						"[CFG-DBG] set: invalid"
						" key '%s'\n", key);
				printf("  Error: invalid key '%s' for %s\n",
				       key, type_name);
				printf("  Valid: %s\n",
				       sg_reg_valid_keys(type_name));
				continue;
			}
			/* Password: interactive prompt */
			if (strcmp(type_name, "system_admin") == 0 &&
			    strcmp(key, "password") == 0) {
				if (handle_password(entry_id, &data) == 0)
					password_cleared = 0;
				continue;
			}
			if (!val[0]) {
				printf("  Usage: set %s <value>\n", key);
				printf("  Expected: %s\n",
				       sg_reg_value_rule(type_name, key));
				continue;
			}
			if (!sg_reg_validate_value(type_name, key, val)) {
				if (cfg_dbg())
					fprintf(stderr,
						"[CFG-DBG] set:"
						" invalid value"
						" %s='%s'\n",
						key, val);
				printf("  Error: invalid value for '%s': '%s'\n",
				       key, val);
				printf("  Expected: %s\n",
				       sg_reg_value_rule(type_name, key));
				continue;
			}
			if (!check_ref_exists(type_name, key, val)) {
				char rt[64], ro[64];
				sg_parse_ref_kind(
					sg_reg_value_kind(type_name, key),
					rt, sizeof(rt), ro, sizeof(ro));
				printf("  Error: '%s' does not exist"
				       " as a %s entry\n",
				       val, sg_reg_type_label(rt));
				continue;
			}
			if (kv_set(&data, key, val) != 0) {
				printf("  Error: too many configuration entries (max %d).\n",
				       KV_MAX_ENTRIES);
				continue;
			}
			if (cfg_dbg())
				fprintf(stderr,
					"[CFG-DBG] set: %s=%s"
					" (valid)\n", key, val);
		} else if (strcmp(cmd, "unset") == 0) {
			if (!key[0]) {
				printf("  Usage: unset <key>\n");
				continue;
			}
			if (cfg_reject_extra(val, "unset"))
				continue;
			if (!sg_reg_is_valid_key(type_name, key)) {
				printf("  Error: invalid key '%s' for %s\n",
				       key, type_name);
				continue;
			}
			if (strcmp(type_name, "system_admin") == 0 &&
			    strcmp(key, "password") == 0) {
				password_cleared = 1;
				data.modified = 1;
			}
			kv_unset(&data, key);
			if (cfg_dbg())
				fprintf(stderr,
					"[CFG-DBG] unset: %s\n",
					key);
		} else if (strcmp(cmd, "get") == 0) {
			if (!key[0]) {
				printf("  Usage: get <key>\n");
				continue;
			}
			if (cfg_reject_extra(val, "get"))
				continue;
			if (!sg_reg_is_valid_key(type_name, key)) {
				printf("  Error: invalid key '%s' for %s\n",
				       key, type_name);
				continue;
			}
			const char *v = kv_get(&data, key);
			if (v) {
				if (strcmp(type_name, "system_admin") == 0 &&
				    strcmp(key, "password") == 0)
					printf("  %s = ********\n", key);
				else
					printf("  %s = %s\n", key, v);
			} else {
				printf("  %s: (not set)\n", key);
			}
		} else if (strcmp(cmd, "show") == 0) {
			if (cfg_reject_extra(key, "show"))
				continue;
			if (data.count > 0) {
				printf("    edit \"%s\"\n", entry_id);
				for (int i = 0; i < data.count; i++) {
					if (strcmp(data.entries[i].key,
						   "builtin") == 0)
						continue;
					if (strcmp(type_name,
						   "system_admin") == 0 &&
					    strcmp(data.entries[i].key,
						   "password") == 0) {
						printf("        set password"
						       " ********\n");
					} else if (value_needs_quote(
							type_name,
							data.entries[i].key)) {
						printf("        set %s"
						       " \"%s\"\n",
						       data.entries[i].key,
						       data.entries[i].val);
					} else {
						printf("        set %s"
						       " %s\n",
						       data.entries[i].key,
						       data.entries[i].val);
					}
				}
				printf("    next\n");
			} else {
				printf("  (empty -- use 'set <key> <value>')\n");
			}
		} else if (strcmp(cmd, "next") == 0 ||
			   strcmp(cmd, "end") == 0) {
			if (cfg_reject_extra(key, cmd))
				continue;
			/* Warn if empty */
			if (!data.modified && data.count == 0) {
				printf("  Entry has no configuration."
				       " Use 'set' or 'abort'.\n");
				continue;
			}
			if (data.modified) {
				/* Validate required fields */
				const char *miss = validate_required(
					type_name, &data);
				if (miss) {
					if (cfg_dbg())
						fprintf(stderr,
							"[CFG-DBG] save:"
							" missing"
							" required:%s\n",
							miss);
					printf("  Error: missing required"
					       " field(s):%s\n", miss);
					printf("  Use 'set <key> <value>' to"
					       " fill them, or 'abort'"
					       " to discard.\n");
					continue;
				}
				if (cfg_dbg())
					fprintf(stderr,
						"[CFG-DBG] save:"
						" required fields OK\n");
				/* New admin must have password */
				if (is_new &&
				    strcmp(type_name, "system_admin") == 0 &&
				    !kv_get(&data, "password")) {
					printf("  Error: new admin requires"
					       " a password.\n");
					printf("  Use 'set password' to set"
					       " one, or 'abort' to"
					       " discard.\n");
					continue;
				}
				/* Password was unset — validate against
				 * global policy before saving */
				if (password_cleared &&
				    strcmp(type_name,
					   "system_admin") == 0) {
					const char *enf = kv_get(&data,
						"enforce-password-policy");
					char pp[768];
					snprintf(pp, sizeof(pp),
						 "%s\n\n%s",
						 entry_id,
						 enf ? enf : "");
					struct ipc_response pr;
					int blocked = 0;
					if (ipc_send_str(
						SG_CMD_ADMIN_CHECK_PW,
						pp, &pr) == 0 &&
					    pr.status ==
						SG_ERR_POLICY_FAIL) {
						blocked = 1;
						printf("  Error: cannot"
						       " clear password"
						       " — password"
						       " policy"
						       " requires a"
						       " valid"
						       " password.\n");
						if (pr.extra[0])
							printf("  Policy:"
							       " %s\n",
							       pr.extra);
						printf("  Use 'set"
						       " password' to"
						       " set a"
						       " compliant"
						       " password.\n");
					}
					ipc_resp_free(&pr);
					if (blocked)
						continue;
					/* Policy allows clearing —
					 * lock password in shadow */
					struct ipc_response lr;
					if (ipc_send_str(
						SG_CMD_ADMIN_LOCK_PW,
						entry_id, &lr) == 0 &&
					    lr.status == SG_OK) {
						printf("  Password"
						       " cleared.\n");
					} else {
						printf("  Error: failed"
						       " to clear"
						       " password.\n");
						ipc_resp_free(&lr);
						continue;
					}
					ipc_resp_free(&lr);
					password_cleared = 0;
				}
				/* Apply via IPC */
				if (apply_config(type_name, entry_id,
						 &data) != 0) {
					printf("  Apply failed."
					       " Changes not saved.\n");
					continue;
				}
				/* Strip password before persisting */
				kv_unset(&data, "password");
				/* Persist via IPC */
				char payload[4096];
				int hdr_len = snprintf(payload,
					sizeof(payload), "%s\n",
					section);
				char serial[2048];
				kv_serialize(&data, serial, sizeof(serial));
				size_t total = (size_t)hdr_len +
					strlen(serial);
				if (total < sizeof(payload)) {
					memcpy(payload + hdr_len, serial,
					       strlen(serial) + 1);
					struct ipc_response sresp;
					int rc = ipc_send(SG_CMD_CFG_SET,
						payload, total, &sresp);
					if (rc != 0 ||
					    sresp.status != SG_OK) {
						printf("  WARNING: applied"
						       " but failed to"
						       " save config.\n");
						if (sresp.extra[0])
							printf("  %s\n",
							       sresp.extra);
					}
					if (cfg_dbg())
						fprintf(stderr,
							"[CFG-DBG]"
							" persist:"
							" %s\n",
							(rc == 0 &&
							 sresp.status
							 == SG_OK)
							? "OK"
							: "FAILED");
					ipc_resp_free(&sresp);
				} else {
					printf("  WARNING: config too"
					       " large to save.\n");
				}
			}
			if (strcmp(cmd, "end") == 0 && exit_all)
				*exit_all = 1;
			break;
		} else if (strcmp(cmd, "abort") == 0) {
			if (cfg_reject_extra(key, "abort"))
				continue;
			if (cfg_dbg())
				fprintf(stderr,
					"[CFG-DBG] abort entry:"
					" %s:%s\n",
					type_name, entry_id);
			printf("  Changes discarded.\n");
			break;
		} else {
			printf("  Unknown command: %s (try '?')\n", cmd);
		}
	}

	/* Clear any sensitive data (passwords) from memory */
	if (strcmp(type_name, "system_admin") == 0)
		explicit_bzero(&data, sizeof(data));

	if (cfg_dbg())
		fprintf(stderr,
			"[CFG-DBG] exit entry: %s:%s\n",
			type_name, entry_id);
	cli_pop();
	return 0;
}

/* ── Table context ────────────────────────────────────────────────────── */

static int context_table(const char *type_name, const char *label)
{
	if (cfg_dbg())
		fprintf(stderr,
			"[CFG-DBG] enter table: %s (%s)\n",
			type_name, label);

	cli_push();
	register_table_cmds(type_name);

	char prompt[128];
	snprintf(prompt, sizeof(prompt), "(%s) # ", label);

	const char *line;
	while ((line = cli_readline(prompt)) != NULL) {
		char cmd[64], arg[256], extra[256];
		char linebuf[1024];
		snprintf(linebuf, sizeof(linebuf), "%s", line);
		char *trimmed = trim(linebuf);
		if (!*trimmed) continue;

		char resolved[CLI_MAX_LINE];
		if (cli_resolve_cmd(trimmed, resolved,
				    sizeof(resolved)) != 0)
			continue;

		parse_line(resolved, cmd, sizeof(cmd),
			   arg, sizeof(arg), extra, sizeof(extra));

		if (cfg_dbg())
			fprintf(stderr,
				"[CFG-DBG] table cmd: %s%s%s\n",
				cmd, arg[0] ? " " : "", arg);

		if (strcmp(cmd, "show") == 0) {
			if (cfg_reject_extra(arg, "show"))
				continue;
			/* List all entries via IPC */
			struct ipc_response resp;
			if (ipc_send_str(SG_CMD_CFG_LIST, type_name,
					 &resp) == 0 &&
			    resp.status == SG_OK && resp.payload) {
				char *ids = resp.payload;
				char *id = ids;
				int found = 0;

				printf("config %s\n", label);
				while (id && *id) {
					char *nl = strchr(id, '\n');
					if (nl) *nl = '\0';
					if (*id) {
						found = 1;
						char section[512];
						snprintf(section,
							 sizeof(section),
							 "%s:%s",
							 type_name, id);
						struct ipc_response dr;
						if (ipc_send_str(
							SG_CMD_CFG_GET,
							section,
							&dr) == 0 &&
						    dr.status == SG_OK &&
						    dr.payload) {
							printf("    edit"
							       " \"%s\"\n",
							       id);
							const char *p =
								dr.payload;
							while (*p) {
								const char *eol =
									strchr(p,
									       '\n');
								size_t llen = eol
									? (size_t)(eol - p)
									: strlen(p);
								if (llen > 0) {
									const char *eq =
										memchr(p, '=', llen);
									if (eq) {
										size_t klen =
											(size_t)(eq - p);
										if (klen == 7 &&
										    strncmp(p, "builtin", 7) == 0) {
											p += llen;
											if (eol) p++;
											continue;
										}
										if (klen == 8 &&
										    strncmp(p, "password", 8) == 0) {
											printf("        set password"
											       " ********\n");
										} else {
											char kbuf[64];
											if (klen >= sizeof(kbuf))
												klen = sizeof(kbuf) - 1;
											memcpy(kbuf, p, klen);
											kbuf[klen] = '\0';
											if (value_needs_quote(type_name,
													      kbuf))
												printf("        set %.*s"
												       " \"%.*s\"\n",
												       (int)klen, p,
												       (int)(llen - klen - 1),
												       eq + 1);
											else
												printf("        set %.*s"
												       " %.*s\n",
												       (int)klen, p,
												       (int)(llen - klen - 1),
												       eq + 1);
										}
									}
								}
								p += llen;
								if (eol) p++;
							}
							printf("    next\n");
						}
						ipc_resp_free(&dr);
					}
					if (!nl) break;
					id = nl + 1;
				}
				if (!found)
					printf("  No entries configured.\n");
				else
					printf("end\n");
			} else {
				printf("  No entries configured.\n");
			}
			ipc_resp_free(&resp);
		} else if (strcmp(cmd, "edit") == 0) {
			if (!arg[0]) {
				printf("  Usage: edit <id>  (expected: %s)\n",
				       sg_reg_entry_id_kind(type_name));
				continue;
			}
			if (cfg_reject_extra(extra, "edit"))
				continue;
			if (!sg_reg_validate_entry_id(type_name, arg)) {
				printf("  Error: invalid ID '%s' for %s\n",
				       arg, type_name);
				printf("  Expected: %s\n",
				       sg_reg_entry_id_kind(type_name));
				continue;
			}
			int exit_all = 0;
			context_entry(type_name, label, arg, &exit_all);
			if (exit_all)
				break;
		} else if (strcmp(cmd, "delete") == 0) {
			if (!arg[0]) {
				printf("  Usage: delete <id>  (expected: %s)\n",
				       sg_reg_entry_id_kind(type_name));
				continue;
			}
			if (cfg_reject_extra(extra, "delete"))
				continue;
			if (!sg_reg_validate_entry_id(type_name, arg)) {
				printf("  Error: invalid ID '%s' for %s\n",
				       arg, type_name);
				continue;
			}
			/* Special handling for admin deletion */
			if (strcmp(type_name, "system_admin") == 0) {
				/* Use ADMIN_DELETE opcode */
				struct ipc_response resp;
				if (ipc_send_str(SG_CMD_ADMIN_DELETE, arg,
						 &resp) == 0) {
					if (resp.status == SG_OK) {
						printf("  Admin '%s'"
						       " deleted.\n", arg);
					} else {
						if (resp.extra[0])
							printf("  Error:"
							       " %s\n",
							       resp.extra);
						else
							printf("  Error:"
							       " %s\n",
							       sg_status_str(
								resp.status));
					}
				} else {
					printf("  Error: IPC failed\n");
				}
				ipc_resp_free(&resp);
			} else if (strcmp(type_name,
					 "system_admin-profile") == 0) {
				/* Check if built-in or in use */
				char section[512];
				snprintf(section, sizeof(section),
					 "%s:%s", type_name, arg);
				struct ipc_response gresp;
				int is_builtin = 0;
				if (ipc_send_str(SG_CMD_CFG_GET, section,
						 &gresp) == 0 &&
				    gresp.status == SG_OK &&
				    gresp.payload) {
					if (strstr(gresp.payload,
						   "builtin=yes"))
						is_builtin = 1;
				}
				ipc_resp_free(&gresp);

				if (is_builtin) {
					printf("  Error: cannot delete"
					       " built-in profile"
					       " '%s'\n", arg);
					continue;
				}
				/* Delete via IPC */
				struct ipc_response dresp;
				if (ipc_send_str(SG_CMD_CFG_DEL, section,
						 &dresp) == 0 &&
				    dresp.status == SG_OK) {
					printf("  Profile '%s'"
					       " deleted.\n", arg);
				} else {
					if (dresp.extra[0])
						printf("  Error: %s\n",
						       dresp.extra);
					else
						printf("  Error: delete"
						       " failed\n");
				}
				ipc_resp_free(&dresp);
			} else {
				/* Generic delete */
				char section[512];
				snprintf(section, sizeof(section),
					 "%s:%s", type_name, arg);
				struct ipc_response dresp;
				if (ipc_send_str(SG_CMD_CFG_DEL, section,
						 &dresp) == 0 &&
				    dresp.status == SG_OK) {
					printf("  Entry %s deleted.\n", arg);
				} else {
					if (dresp.extra[0])
						printf("  Error: %s\n",
						       dresp.extra);
					else
						printf("  Entry %s"
						       " not found.\n",
						       arg);
				}
				ipc_resp_free(&dresp);
			}
		} else if (strcmp(cmd, "end") == 0 ||
			   strcmp(cmd, "abort") == 0) {
			if (cfg_reject_extra(arg, cmd))
				continue;
			break;
		} else {
			printf("  Unknown command: %s (try '?')\n", cmd);
		}
	}

	if (cfg_dbg())
		fprintf(stderr,
			"[CFG-DBG] exit table: %s\n", type_name);
	cli_pop();
	return 0;
}

/* ── Single context ───────────────────────────────────────────────────── */

static int context_single(const char *type_name, const char *label)
{
	struct kv_buf data;
	kv_init(&data);

	if (cfg_dbg())
		fprintf(stderr,
			"[CFG-DBG] enter single: %s (%s)\n",
			type_name, label);

	/* Load existing data via IPC */
	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_CFG_GET, type_name, &resp) == 0 &&
	    resp.status == SG_OK && resp.payload) {
		kv_parse(&data, resp.payload);
		if (cfg_dbg())
			fprintf(stderr,
				"[CFG-DBG] loaded single %s"
				" (%d keys)\n",
				type_name, data.count);
	} else {
		/* Apply defaults */
		const char *defs = sg_reg_default_values(type_name);
		if (defs && *defs) {
			kv_parse(&data, defs);
			data.modified = 1;
			if (cfg_dbg())
				fprintf(stderr,
					"[CFG-DBG] single %s"
					" defaults (%d keys)\n",
					type_name, data.count);
		}
	}
	ipc_resp_free(&resp);

	cli_push();
	register_single_cmds(type_name);

	char prompt[128];
	snprintf(prompt, sizeof(prompt), "(%s) # ", label);

	const char *line;
	while ((line = cli_readline(prompt)) != NULL) {
		char cmd[64], key[64], val[512];
		char linebuf[1024];
		snprintf(linebuf, sizeof(linebuf), "%s", line);
		char *trimmed = trim(linebuf);
		if (!*trimmed) continue;

		char resolved[CLI_MAX_LINE];
		if (cli_resolve_cmd(trimmed, resolved,
				    sizeof(resolved)) != 0)
			continue;

		parse_line(resolved, cmd, sizeof(cmd),
			   key, sizeof(key), val, sizeof(val));

		if (cfg_dbg())
			fprintf(stderr,
				"[CFG-DBG] single cmd: %s%s%s%s%s\n",
				cmd,
				key[0] ? " " : "", key,
				val[0] ? " " : "", val);

		if (strcmp(cmd, "set") == 0) {
			if (!key[0] || !val[0]) {
				if (key[0]) {
					printf("  Expected: %s\n",
					       sg_reg_value_rule(type_name,
							      key));
				}
				printf("  Usage: set <key> <value>\n");
				continue;
			}
			if (!sg_reg_is_valid_key(type_name, key)) {
				if (cfg_dbg())
					fprintf(stderr,
						"[CFG-DBG] set: invalid"
						" key '%s'\n", key);
				printf("  Error: invalid key '%s'"
				       " for %s\n", key, type_name);
				printf("  Valid: %s\n",
				       sg_reg_valid_keys(type_name));
				continue;
			}
			if (!sg_reg_validate_value(type_name, key, val)) {
				if (cfg_dbg())
					fprintf(stderr,
						"[CFG-DBG] set:"
						" invalid value"
						" %s='%s'\n",
						key, val);
				printf("  Error: invalid value for '%s':"
				       " '%s'\n", key, val);
				printf("  Expected: %s\n",
				       sg_reg_value_rule(type_name, key));
				continue;
			}
			if (!check_ref_exists(type_name, key, val)) {
				char rt[64], ro[64];
				sg_parse_ref_kind(
					sg_reg_value_kind(type_name, key),
					rt, sizeof(rt), ro, sizeof(ro));
				printf("  Error: '%s' does not exist"
				       " as a %s entry\n",
				       val, sg_reg_type_label(rt));
				continue;
			}
			if (kv_set(&data, key, val) != 0) {
				printf("  Error: too many configuration entries (max %d).\n",
				       KV_MAX_ENTRIES);
				continue;
			}
			if (cfg_dbg())
				fprintf(stderr,
					"[CFG-DBG] set: %s=%s"
					" (valid)\n", key, val);
		} else if (strcmp(cmd, "unset") == 0) {
			if (!key[0]) {
				printf("  Usage: unset <key>\n");
				continue;
			}
			if (cfg_reject_extra(val, "unset"))
				continue;
			if (!sg_reg_is_valid_key(type_name, key)) {
				printf("  Error: invalid key '%s'"
				       " for %s\n", key, type_name);
				continue;
			}
			kv_unset(&data, key);
			if (cfg_dbg())
				fprintf(stderr,
					"[CFG-DBG] unset: %s\n",
					key);
		} else if (strcmp(cmd, "get") == 0) {
			if (!key[0]) {
				printf("  Usage: get <key>\n");
				continue;
			}
			if (cfg_reject_extra(val, "get"))
				continue;
			if (!sg_reg_is_valid_key(type_name, key)) {
				printf("  Error: invalid key '%s'"
				       " for %s\n", key, type_name);
				continue;
			}
			const char *v = kv_get(&data, key);
			if (v)
				printf("  %s = %s\n", key, v);
			else
				printf("  %s: (not set)\n", key);
		} else if (strcmp(cmd, "show") == 0) {
			if (cfg_reject_extra(key, "show"))
				continue;
			if (data.count > 0) {
				printf("config %s\n", label);
				for (int i = 0; i < data.count; i++) {
					if (value_needs_quote(
						    type_name,
						    data.entries[i].key))
						printf("    set %s"
						       " \"%s\"\n",
						       data.entries[i].key,
						       data.entries[i].val);
					else
						printf("    set %s"
						       " %s\n",
						       data.entries[i].key,
						       data.entries[i].val);
				}
				printf("end\n");
			} else {
				printf("  (empty -- use"
				       " 'set <key> <value>')\n");
			}
		} else if (strcmp(cmd, "end") == 0) {
			if (cfg_reject_extra(key, "end"))
				continue;
			if (data.modified) {
				/* Validate required fields */
				const char *miss = validate_required(
					type_name, &data);
				if (miss) {
					if (cfg_dbg())
						fprintf(stderr,
							"[CFG-DBG] save:"
							" missing"
							" required:%s\n",
							miss);
					printf("  Error: missing required"
					       " field(s):%s\n", miss);
					printf("  Use 'set' or 'abort'.\n");
					continue;
				}
				if (cfg_dbg())
					fprintf(stderr,
						"[CFG-DBG] save:"
						" required fields OK\n");
				/* Apply via IPC */
				if (apply_config(type_name, "0",
						 &data) != 0) {
					printf("  Apply failed.\n");
					continue;
				}
				/* Persist via IPC */
				char payload[4096];
				int hdr_len = snprintf(payload,
					sizeof(payload), "%s\n",
					type_name);
				char serial[2048];
				kv_serialize(&data, serial, sizeof(serial));
				size_t total = (size_t)hdr_len +
					strlen(serial);
				if (total < sizeof(payload)) {
					memcpy(payload + hdr_len, serial,
					       strlen(serial) + 1);
					struct ipc_response sresp;
					int rc = ipc_send(SG_CMD_CFG_SET,
						payload, total, &sresp);
					if (rc != 0 ||
					    sresp.status != SG_OK) {
						printf("  WARNING: applied"
						       " but failed to"
						       " save config.\n");
						if (sresp.extra[0])
							printf("  %s\n",
							       sresp.extra);
					}
					if (cfg_dbg())
						fprintf(stderr,
							"[CFG-DBG]"
							" persist:"
							" %s\n",
							(rc == 0 &&
							 sresp.status
							 == SG_OK)
							? "OK"
							: "FAILED");
					ipc_resp_free(&sresp);
				} else {
					printf("  WARNING: config too"
					       " large to save.\n");
				}
			}
			break;
		} else if (strcmp(cmd, "abort") == 0) {
			if (cfg_reject_extra(key, "abort"))
				continue;
			if (cfg_dbg())
				fprintf(stderr,
					"[CFG-DBG] abort single:"
					" %s\n", type_name);
			printf("  Changes discarded.\n");
			break;
		} else {
			printf("  Unknown: %s (try '?')\n", cmd);
		}
	}

	if (cfg_dbg())
		fprintf(stderr,
			"[CFG-DBG] exit single: %s\n", type_name);
	cli_pop();
	return 0;
}

/* ── Commit / Revisions / Rollback ────────────────────────────────────── */

static void cmd_commit(int argc, const char **argv)
{
	const char *msg = "manual commit";
	char msgbuf[256];
	if (argc > 0) {
		msgbuf[0] = '\0';
		for (int i = 0; i < argc; i++) {
			size_t len = strlen(msgbuf);
			if (i > 0)
				snprintf(msgbuf + len,
					 sizeof(msgbuf) - len, " ");
			len = strlen(msgbuf);
			snprintf(msgbuf + len, sizeof(msgbuf) - len,
				 "%s", argv[i]);
		}
		msg = msgbuf;
	}

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_COMMIT, msg, &resp) == 0 &&
	    resp.status == SG_OK) {
		if (resp.payload)
			printf("  Commit complete. Revision: %s\n",
			       resp.payload);
		else
			printf("  Commit complete.\n");
	} else {
		printf("  Commit failed.\n");
	}
	ipc_resp_free(&resp);
}

static void cmd_revisions(void)
{
	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_REVISIONS, "", &resp) == 0 &&
	    resp.status == SG_OK && resp.payload) {
		printf("%s", resp.payload);
	} else {
		printf("  No revisions found.\n");
	}
	ipc_resp_free(&resp);
}

static void cmd_rollback(const char *rev)
{
	if (!rev || !*rev) {
		printf("  Usage: configure rollback <revision>\n");
		return;
	}

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_ROLLBACK, rev, &resp) == 0 &&
	    resp.status == SG_OK) {
		printf("  Rollback to revision %s complete.\n", rev);
	} else {
		if (resp.extra[0])
			printf("  Error: %s\n", resp.extra);
		else
			printf("  Rollback failed.\n");
	}
	ipc_resp_free(&resp);
}

/* ── Main entry point ─────────────────────────────────────────────────── */

int cli_configure(int argc, const char **argv)
{
	if (argc == 0) {
		printf("  Usage: configure <category> <subcategory>\n");
		printf("  Examples:\n");
		printf("    configure network route static\n");
		printf("    configure system settings\n");
		printf("    configure firewall policy\n");
		printf("  Type 'configure ?' for all options.\n");
		return 0;
	}

	/* Handle commit/revisions/rollback */
	if (strcmp(argv[0], "commit") == 0) {
		cmd_commit(argc - 1, argv + 1);
		return 0;
	}
	if (strcmp(argv[0], "revisions") == 0) {
		cmd_revisions();
		return 0;
	}
	if (strcmp(argv[0], "rollback") == 0) {
		cmd_rollback(argc > 1 ? argv[1] : NULL);
		return 0;
	}

	/* Build config key from args: "network route static" → "network_route_static" */
	char type_key[128];
	type_key[0] = '\0';
	for (int i = 0; i < argc; i++) {
		size_t cur = strlen(type_key);
		if (i > 0) {
			snprintf(type_key + cur,
				 sizeof(type_key) - cur, "_");
			cur++;
		}
		snprintf(type_key + cur, sizeof(type_key) - cur,
			 "%s", argv[i]);
	}

	/* Look up type mode */
	int mode = sg_reg_type_mode(type_key);
	if (mode < 0) {
		if (cfg_dbg())
			fprintf(stderr,
				"[CFG-DBG] configure: unknown"
				" type_key=%s\n", type_key);
		printf("  Unknown config path:");
		for (int i = 0; i < argc; i++)
			printf(" %s", argv[i]);
		printf("\n  Run 'configure ?' to see available options.\n");
		return 0;
	}

	if (cfg_dbg())
		fprintf(stderr,
			"[CFG-DBG] configure: type=%s mode=%s\n",
			type_key,
			mode == CFG_TABLE ? "TABLE" : "SINGLE");

	const char *label = sg_reg_type_label(type_key);

	if (mode == CFG_TABLE)
		context_table(type_key, label);
	else
		context_single(type_key, label);

	return 0;
}
