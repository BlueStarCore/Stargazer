/* SPDX-License-Identifier: MIT */
/*
 * cli_configure.c — Interactive configure mode for Stargazer CLI
 *
 * C translation of cmd_configure (698 lines shell).
 * Three context types: table (show/edit/delete/end),
 * entry (set/unset/show/get/next/end/abort),
 * single (set/unset/show/get/end/abort).
 *
 * All config I/O goes through IPC (opcodes 100-202, 301, 304, 500-502).
 * In-memory key=value buffer replaces temp files.
 */

#define _POSIX_C_SOURCE 200809L

#include "cli_configure.h"
#include "cli_readline.h"
#include "cli_ipc.h"
#include "cli_registry.h"

#include <fcntl.h>
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

static void kv_set(struct kv_buf *b, const char *key, const char *val)
{
	for (int i = 0; i < b->count; i++) {
		if (strcmp(b->entries[i].key, key) == 0) {
			snprintf(b->entries[i].val, KV_MAX_VAL, "%s", val);
			b->modified = 1;
			return;
		}
	}
	if (b->count < KV_MAX_ENTRIES) {
		snprintf(b->entries[b->count].key, KV_MAX_KEY, "%s", key);
		snprintf(b->entries[b->count].val, KV_MAX_VAL, "%s", val);
		b->count++;
		b->modified = 1;
	}
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

/* ── Helpers ──────────────────────────────────────────────────────────── */

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

/* Read password from terminal with echo disabled */
static int read_password(const char *prompt, char *buf, size_t buf_sz)
{
	struct termios old, noecho;
	int tty = open("/dev/tty", 0); /* O_RDONLY */
	if (tty < 0) tty = STDIN_FILENO;

	printf("%s", prompt);
	fflush(stdout);

	tcgetattr(tty, &old);
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

	if (tty != STDIN_FILENO)
		close(tty);
	return pos;
}

/* Check if required fields are present. Returns NULL if OK, or space-sep missing keys. */
static const char *validate_required(const char *type_name,
				     const struct kv_buf *b)
{
	static char missing[512];
	missing[0] = '\0';

	const char *req = reg_required_keys(type_name);
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
	const char *keys = reg_valid_keys(type_name);
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
		const char *rule = reg_value_rule(type_name, tok);
		snprintf(regpath, sizeof(regpath), "set %s", tok);
		snprintf(regdesc, sizeof(regdesc), "Set %s (%s)", tok, rule);
		cli_register(regpath, regdesc);

		/* Register value-level completions based on kind */
		const char *kind = reg_value_kind(type_name, tok);
		if (kind)
			register_value_completions(tok, kind);

		*end = saved;
		tok = end;
	}
}

/* Register unset/get completions for each valid key */
static void register_unset_get_cmds(const char *type_name)
{
	const char *keys = reg_valid_keys(type_name);
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
	const char *id_kind = reg_entry_id_kind(type_name);
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

/* ── Apply config via IPC ─────────────────────────────────────────────── */

static int apply_config(const char *type_name, const char *id,
			const struct kv_buf *b)
{
	char payload[4096];
	int hdr_len = snprintf(payload, sizeof(payload), "%s\n%s\n",
			       type_name, id);
	if (hdr_len < 0) return -1;

	char data[2048];
	kv_serialize(b, data, sizeof(data));

	size_t total = (size_t)hdr_len + strlen(data);
	if (total >= sizeof(payload)) return -1;
	memcpy(payload + hdr_len, data, strlen(data) + 1);

	struct ipc_response resp;
	if (ipc_send(SG_CMD_CFG_APPLY, payload, total, &resp) != 0)
		return -1;

	if (resp.status != SG_OK) {
		if (resp.extra[0])
			printf("  Error: %s\n", resp.extra);
		else
			printf("  Error: %s\n", sg_status_str(resp.status));
		ipc_resp_free(&resp);
		return -1;
	}

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
	char policy_payload[512];
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
			return -1;
		}
		ipc_resp_free(&resp);
	}

	read_password("  Retype password: ", pw2, sizeof(pw2));

	if (strcmp(pw1, pw2) != 0) {
		printf("  Passwords don't match.\n");
		return -1;
	}

	kv_set(b, "password", pw1);
	printf("  Password will be set on save.\n");

	/* Clear from stack */
	memset(pw1, 0, sizeof(pw1));
	memset(pw2, 0, sizeof(pw2));
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

	/* Load existing data via IPC */
	char section[512];
	snprintf(section, sizeof(section), "%s:%s", type_name, entry_id);

	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_CFG_GET, section, &resp) == 0 &&
	    resp.status == SG_OK && resp.payload) {
		kv_parse(&data, resp.payload);
		printf("  Editing entry %s.\n", entry_id);
	} else {
		is_new = 1;
		/* Apply defaults */
		const char *defs = reg_default_values(type_name);
		if (defs && *defs) {
			kv_parse(&data, defs);
			data.modified = 1;
			printf("  Creating new entry %s (defaults applied).\n",
			       entry_id);
		} else {
			printf("  Creating new entry %s.\n", entry_id);
		}
	}
	ipc_resp_free(&resp);

	cli_push();
	register_entry_cmds(type_name);

	char prompt[128];
	snprintf(prompt, sizeof(prompt), "(%s-%s) # ", label, entry_id);

	const char *line;
	while ((line = cli_readline(prompt)) != NULL) {
		char cmd[64], key[64], val[512];
		char linebuf[1024];
		snprintf(linebuf, sizeof(linebuf), "%s", line);
		char *trimmed = trim(linebuf);
		if (!*trimmed) continue;

		parse_line(trimmed, cmd, sizeof(cmd),
			   key, sizeof(key), val, sizeof(val));

		if (strcmp(cmd, "set") == 0) {
			if (!key[0]) {
				printf("  Usage: set <key> <value>\n");
				continue;
			}
			if (!reg_is_valid_key(type_name, key)) {
				printf("  Error: invalid key '%s' for %s\n",
				       key, type_name);
				printf("  Valid: %s\n",
				       reg_valid_keys(type_name));
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
				       reg_value_rule(type_name, key));
				continue;
			}
			if (!reg_validate_value(type_name, key, val)) {
				printf("  Error: invalid value for '%s': '%s'\n",
				       key, val);
				printf("  Expected: %s\n",
				       reg_value_rule(type_name, key));
				continue;
			}
			kv_set(&data, key, val);
		} else if (strcmp(cmd, "unset") == 0) {
			if (!key[0]) {
				printf("  Usage: unset <key>\n");
				continue;
			}
			if (!reg_is_valid_key(type_name, key)) {
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
		} else if (strcmp(cmd, "get") == 0) {
			if (!key[0]) {
				printf("  Usage: get <key>\n");
				continue;
			}
			if (!reg_is_valid_key(type_name, key)) {
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
			if (data.count > 0) {
				printf("  == Entry %s ==\n", entry_id);
				for (int i = 0; i < data.count; i++) {
					if (strcmp(type_name, "system_admin") == 0 &&
					    strcmp(data.entries[i].key, "password") == 0)
						printf("    %s=********\n",
						       data.entries[i].key);
					else
						printf("    %s=%s\n",
						       data.entries[i].key,
						       data.entries[i].val);
				}
			} else {
				printf("  (empty -- use 'set <key> <value>')\n");
			}
		} else if (strcmp(cmd, "next") == 0 ||
			   strcmp(cmd, "end") == 0) {
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
					printf("  Error: missing required"
					       " field(s):%s\n", miss);
					printf("  Use 'set <key> <value>' to"
					       " fill them, or 'abort'"
					       " to discard.\n");
					continue;
				}
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
					char pp[512];
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
					ipc_send(SG_CMD_CFG_SET, payload,
						 total, &sresp);
					ipc_resp_free(&sresp);
				}
			}
			if (strcmp(cmd, "end") == 0 && exit_all)
				*exit_all = 1;
			break;
		} else if (strcmp(cmd, "abort") == 0) {
			printf("  Changes discarded.\n");
			break;
		} else {
			printf("  Unknown command: %s (try '?')\n", cmd);
		}
	}

	cli_pop();
	return 0;
}

/* ── Table context ────────────────────────────────────────────────────── */

static int context_table(const char *type_name, const char *label)
{
	cli_push();
	register_table_cmds(type_name);

	char prompt[128];
	snprintf(prompt, sizeof(prompt), "(%s) # ", label);

	const char *line;
	while ((line = cli_readline(prompt)) != NULL) {
		char cmd[64], arg[256], dummy[4];
		char linebuf[1024];
		snprintf(linebuf, sizeof(linebuf), "%s", line);
		char *trimmed = trim(linebuf);
		if (!*trimmed) continue;

		parse_line(trimmed, cmd, sizeof(cmd),
			   arg, sizeof(arg), dummy, sizeof(dummy));

		if (strcmp(cmd, "show") == 0) {
			/* List all entries via IPC */
			struct ipc_response resp;
			if (ipc_send_str(SG_CMD_CFG_LIST, type_name,
					 &resp) == 0 &&
			    resp.status == SG_OK && resp.payload) {
				/* Parse ID list (newline-separated) */
				char *ids = resp.payload;
				char *id = ids;
				int found = 0;

				while (id && *id) {
					char *nl = strchr(id, '\n');
					if (nl) *nl = '\0';
					if (*id) {
						found = 1;
						/* Get entry data */
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
							printf("  == Entry"
							       " %s ==\n",
							       id);
							/* Print indented */
							const char *p =
								dr.payload;
							while (*p) {
								const char *eol =
									strchr(p,
									       '\n');
								if (eol) {
									printf("    %.*s\n",
									       (int)(eol - p),
									       p);
									p = eol + 1;
								} else {
									printf("    %s\n",
									       p);
									break;
								}
							}
							printf("\n");
						}
						ipc_resp_free(&dr);
					}
					if (!nl) break;
					id = nl + 1;
				}
				if (!found)
					printf("  No entries configured.\n");
			} else {
				printf("  No entries configured.\n");
			}
			ipc_resp_free(&resp);
		} else if (strcmp(cmd, "edit") == 0) {
			if (!arg[0]) {
				printf("  Usage: edit <id>  (expected: %s)\n",
				       reg_entry_id_kind(type_name));
				continue;
			}
			if (!reg_validate_entry_id(type_name, arg)) {
				printf("  Error: invalid ID '%s' for %s\n",
				       arg, type_name);
				printf("  Expected: %s\n",
				       reg_entry_id_kind(type_name));
				continue;
			}
			int exit_all = 0;
			context_entry(type_name, label, arg, &exit_all);
			if (exit_all)
				break;
		} else if (strcmp(cmd, "delete") == 0) {
			if (!arg[0]) {
				printf("  Usage: delete <id>  (expected: %s)\n",
				       reg_entry_id_kind(type_name));
				continue;
			}
			if (!reg_validate_entry_id(type_name, arg)) {
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
					printf("  Entry %s not found.\n", arg);
				}
				ipc_resp_free(&dresp);
			}
		} else if (strcmp(cmd, "end") == 0 ||
			   strcmp(cmd, "abort") == 0) {
			break;
		} else {
			printf("  Unknown command: %s (try '?')\n", cmd);
		}
	}

	cli_pop();
	return 0;
}

/* ── Single context ───────────────────────────────────────────────────── */

static int context_single(const char *type_name, const char *label)
{
	struct kv_buf data;
	kv_init(&data);

	/* Load existing data via IPC */
	struct ipc_response resp;
	if (ipc_send_str(SG_CMD_CFG_GET, type_name, &resp) == 0 &&
	    resp.status == SG_OK && resp.payload) {
		kv_parse(&data, resp.payload);
	} else {
		/* Apply defaults */
		const char *defs = reg_default_values(type_name);
		if (defs && *defs) {
			kv_parse(&data, defs);
			data.modified = 1;
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

		parse_line(trimmed, cmd, sizeof(cmd),
			   key, sizeof(key), val, sizeof(val));

		if (strcmp(cmd, "set") == 0) {
			if (!key[0] || !val[0]) {
				if (key[0]) {
					printf("  Expected: %s\n",
					       reg_value_rule(type_name,
							      key));
				}
				printf("  Usage: set <key> <value>\n");
				continue;
			}
			if (!reg_is_valid_key(type_name, key)) {
				printf("  Error: invalid key '%s'"
				       " for %s\n", key, type_name);
				printf("  Valid: %s\n",
				       reg_valid_keys(type_name));
				continue;
			}
			if (!reg_validate_value(type_name, key, val)) {
				printf("  Error: invalid value for '%s':"
				       " '%s'\n", key, val);
				printf("  Expected: %s\n",
				       reg_value_rule(type_name, key));
				continue;
			}
			kv_set(&data, key, val);
		} else if (strcmp(cmd, "unset") == 0) {
			if (!key[0]) {
				printf("  Usage: unset <key>\n");
				continue;
			}
			if (!reg_is_valid_key(type_name, key)) {
				printf("  Error: invalid key '%s'"
				       " for %s\n", key, type_name);
				continue;
			}
			kv_unset(&data, key);
		} else if (strcmp(cmd, "get") == 0) {
			if (!key[0]) {
				printf("  Usage: get <key>\n");
				continue;
			}
			if (!reg_is_valid_key(type_name, key)) {
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
			if (data.count > 0) {
				printf("  == %s ==\n", label);
				for (int i = 0; i < data.count; i++)
					printf("    %s=%s\n",
					       data.entries[i].key,
					       data.entries[i].val);
			} else {
				printf("  (empty -- use"
				       " 'set <key> <value>')\n");
			}
		} else if (strcmp(cmd, "end") == 0) {
			if (data.modified) {
				/* Validate required fields */
				const char *miss = validate_required(
					type_name, &data);
				if (miss) {
					printf("  Error: missing required"
					       " field(s):%s\n", miss);
					printf("  Use 'set' or 'abort'.\n");
					continue;
				}
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
					ipc_send(SG_CMD_CFG_SET, payload,
						 total, &sresp);
					ipc_resp_free(&sresp);
				}
			}
			break;
		} else if (strcmp(cmd, "abort") == 0) {
			printf("  Changes discarded.\n");
			break;
		} else {
			printf("  Unknown: %s (try '?')\n", cmd);
		}
	}

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
	int mode = reg_type_mode(type_key);
	if (mode < 0) {
		printf("  Unknown config path:");
		for (int i = 0; i < argc; i++)
			printf(" %s", argv[i]);
		printf("\n  Run 'configure ?' to see available options.\n");
		return 0;
	}

	const char *label = reg_type_label(type_key);

	if (mode == CFG_TABLE)
		context_table(type_key, label);
	else
		context_single(type_key, label);

	return 0;
}
