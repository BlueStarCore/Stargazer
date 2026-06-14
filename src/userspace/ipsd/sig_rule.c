/* SPDX-License-Identifier: MIT */
/*
 * sig_rule.c - ET-OPEN-subset rule parser + payload matching (see sig_rule.h).
 */
#include "sig_rule.h"
#include "proto_buf.h"   /* struct match_buffers (P6 sticky buffers)     */

#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasecmp */
#include <ctype.h>
#include <stdio.h>
#include <dirent.h>    /* per-profile map dir scan */

#ifdef HAVE_PCRE        /* P4 — regex (PCRE2), JIT off, with ReDoS limits */
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#define PCRE_MATCH_LIMIT 10000   /* backtrack-step ceiling per match (anti-ReDoS) */
#define PCRE_DEPTH_LIMIT 1000
#endif

/* ---- small helpers ------------------------------------------------------- */
/*
Logic: Convert a hex character ('0'-'f') to its numeric value (0-15).
*/
static int hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/*
 * Decode a Snort-style content value: ASCII runs interleaved with |hh hh| (hex)
 * and \escape (\", \;, \\, \|...). Returns byte count, -1 on error (unbalanced
 * |...| / bad hex).
 Logic: Decode a rule's content string.
 */
static int decode_content(const char *s, uint8_t *out, int outcap)
{
	int n = 0, hex = 0;

	while (*s) {
		if (*s == '|') {                 /* toggle hex mode */
			hex = !hex;
			s++;
		} else if (hex) {
			if (*s == ' ' || *s == '\t') { s++; continue; }
			int hi = hexval((unsigned char)s[0]);
			int lo = s[1] ? hexval((unsigned char)s[1]) : -1;
			if (hi < 0 || lo < 0) return -1;
			if (n < outcap) out[n++] = (uint8_t)(hi * 16 + lo);
			s += 2;
		} else if (*s == '\\' && s[1]) {  /* escape: take next char verbatim */
			s++;
			if (n < outcap) out[n++] = (uint8_t)*s;
			s++;
		} else {
			if (n < outcap) out[n++] = (uint8_t)*s;
			s++;
		}
	}
	return hex ? -1 : n;                      /* | still open → error */
}

static int parse_proto(const char *s)
{
	if (!strcasecmp(s, "tcp"))  return SIG_PROTO_TCP;
	if (!strcasecmp(s, "udp"))  return SIG_PROTO_UDP;
	if (!strcasecmp(s, "icmp")) return SIG_PROTO_ICMP;
	return SIG_PROTO_ANY;                     /* "ip"/"any"/variable → any */
}

static int parse_action(const char *s)
{
	if (!strcasecmp(s, "drop") || !strcasecmp(s, "reject") ||
	    !strcasecmp(s, "sdrop"))
		return SIG_DROP;
	return SIG_ALERT;                         /* alert/log/pass… → alert */
}

/*
 * Snort port-variable expansion table.
 * Variables that represent IP groups ($HTTP_SERVERS, $SQL_SERVERS …) may
 * appear in the port position in some rule files; they expand to "any" (n=0).
 * Source-address variables ($HOME_NET, $EXTERNAL_NET …) are silently ignored
 * at the IP level — IP-group matching is a known MVP limitation.
 */
static const struct {
	const char    *name;
	uint16_t       ports[SIG_DPORT_MAX];
	uint8_t        n;
} PORT_VARS[] = {
	{ "$HTTP_PORTS",      {80, 8080, 8000, 8008},    4 },
	{ "$HTTPS_PORTS",     {443, 8443},                2 },
	{ "$HTTP_SERVERS",    {0},                        0 }, /* IP var → any */
	{ "$SQL_SERVERS",     {0},                        0 }, /* IP var → any */
	{ "$DNS_SERVERS",     {53},                       1 },
	{ "$SMTP_SERVERS",    {25, 587, 465},             3 },
	{ "$SSH_PORTS",       {22},                       1 },
	{ "$FTP_PORTS",       {21, 2121},                 2 },
	{ "$ORACLE_PORTS",    {1521},                     1 },
	{ "$SHELLCODE_PORTS", {0},                        0 }, /* → any */
	{ "$FILE_DATA_PORTS", {80, 110, 143},             3 },
	{ NULL,               {0},                        0 },
};

/*
 * Parse a port field from a Snort rule header into a port list.
 * "any" / "!" prefix / ranges "a:b" / unknown vars → n_out=0 (any port).
 * Port lists "[a,b,c]" → parsed up to SIG_DPORT_MAX entries.
 * Known $VARIABLE names → expanded from PORT_VARS table above.
 */
static void parse_port_to_list(const char *s, uint16_t *list, uint8_t *n_out)
{
	*n_out = 0;
	if (!s || !*s) return;

	/* Negation, "any", ranges → treat as any */
	if (*s == '!' || !strcasecmp(s, "any")) return;

	/* Known Snort variable */
	if (*s == '$') {
		for (int i = 0; PORT_VARS[i].name; i++) {
			if (!strcmp(s, PORT_VARS[i].name)) {
				*n_out = PORT_VARS[i].n;
				for (uint8_t j = 0; j < PORT_VARS[i].n; j++)
					list[j] = PORT_VARS[i].ports[j];
				return;
			}
		}
		return; /* unknown var → any */
	}

	/* Port list "[a,b,c]" */
	if (*s == '[') {
		s++;
		uint8_t n = 0;
		while (*s && *s != ']' && n < SIG_DPORT_MAX) {
			while (*s == ' ' || *s == ',') s++;
			if (!*s || *s == ']') break;
			/* skip negated entries "!port" */
			if (*s == '!') { while (*s && *s != ',' && *s != ']') s++; continue; }
			char tok[8]; int ti = 0;
			while (*s && *s != ',' && *s != ']' && ti < 7)
				tok[ti++] = *s++;
			tok[ti] = '\0';
			/* skip ranges */
			if (strchr(tok, ':')) continue;
			long v = atol(tok);
			if (v > 0 && v < 65536) list[n++] = (uint16_t)v;
		}
		*n_out = n;
		return;
	}

	/* Range "a:b" → any (we don't store ranges) */
	if (strchr(s, ':')) return;

	/* Plain integer */
	for (const char *q = s; *q; q++)
		if (!isdigit((unsigned char)*q)) return;
	long v = atol(s);
	if (v > 0 && v < 65536) { list[0] = (uint16_t)v; *n_out = 1; }
}

/* Inline port-list membership test used by verify_rule. */
static int port_match(const uint16_t *list, uint8_t n, uint16_t port)
{
	if (!n) return 1;                          /* n==0 → any */
	for (uint8_t i = 0; i < n; i++)
		if (list[i] == port) return 1;
	return 0;
}

static uint8_t parse_flags(const char *s)
{
	uint8_t f = 0;
	for (; *s; s++) {
		switch (*s) {
		case 'F': case 'f': f |= SIG_TCP_FIN; break;
		case 'S': case 's': f |= SIG_TCP_SYN; break;
		case 'R': case 'r': f |= SIG_TCP_RST; break;
		case 'P': case 'p': f |= SIG_TCP_PSH; break;
		case 'A': case 'a': f |= SIG_TCP_ACK; break;
		case 'U': case 'u': f |= SIG_TCP_URG; break;
		default: break;                   /* ignore 0-2 and modifiers + ! * , */
		}
	}
	return f;
}

/*
 * P0 — narrowing keyword NOT yet supported → return a sig_unsup bit (0 if not).
 * Encountering these means we CANNOT evaluate the rule's narrowing condition →
 * the rule must be CLAMPED to ALERT (not DROP) to avoid false blocks from a
 * partial match.
 */
static uint8_t unsup_bit(const char *key)
{
	/* P4: pcre handled separately (parse_pcre — compile or cap). */
	/* P3: byte_test/byte_jump handled separately. byte_extract/byte_math unsupported. */
	if (!strcmp(key, "byte_extract") || !strcmp(key, "byte_math"))
		return SIG_U_BYTEOP;
	/* P2: distance/within/dsize supported → no longer capped. */
	if (!strcmp(key, "isdataat") || !strcmp(key, "urilen"))
		return SIG_U_DSIZE;
	/* P5: flowbits handled separately (not capped here). */
	/* http_* sticky buffers / content modifiers — no protocol buffer yet, so
	 * content tagged http_* would match on the raw payload (broader) → cap ALERT. */
	if (!strncmp(key, "http_", 5))                  return SIG_U_HTTPBUF;
	return 0;
}

/*
 * Parse a non-negative integer with an upper bound (anti-overflow → no negative/
 * huge array indices). Error / negative / over max → return -1 (treated as "unset").
 */
static int parse_uint_field(const char *s, long max)
{
	if (!s || !*s) return -1;
	char *end = NULL;
	long v = strtol(s, &end, 10);
	if (end == s || v < 0 || v > max) return -1;
	return (int)v;
}

/* P2 — parse a SIGNED integer with bounds (distance may be negative). Error → 0. */
static int parse_int_field(const char *s, long lo, long hi)
{
	if (!s || !*s) return 0;
	char *end = NULL;
	long v = strtol(s, &end, 10);
	if (end == s) return 0;
	if (v < lo) v = lo;
	if (v > hi) v = hi;
	return (int)v;
}

/*
 * P2 — parse dsize: ">N" (>N), "<N" (<N), "N" (==N), "N<>M" (N..M).
 * Fill min/max via pointers (-1 = no bound). Bounds-checked against overflow.
 */
static void parse_dsize(const char *s, int *mn, int *mx)
{
	*mn = -1; *mx = -1;
	while (*s == ' ' || *s == '\t') s++;
	if (*s == '>') {
		int v = parse_uint_field(s + 1, 65535);
		if (v >= 0 && v < 65535) *mn = v + 1;     /* dsize > v */
	} else if (*s == '<') {
		int v = parse_uint_field(s + 1, 65535);
		if (v > 0) *mx = v - 1;                    /* dsize < v */
	} else {
		const char *rng = strstr(s, "<>");
		if (rng) {                                 /* "N<>M" */
			int a = parse_uint_field(s, 65535);
			int b = parse_uint_field(rng + 2, 65535);
			if (a >= 0) *mn = a;
			if (b >= 0) *mx = b;
		} else {                                   /* "N" */
			int v = parse_uint_field(s, 65535);
			if (v >= 0) { *mn = v; *mx = v; }
		}
	}
}

/* ---- P3: byte_test / byte_jump ------------------------------------------- */

/* Split a string on commas, trim, into tok[][64]. Returns the token count. */
static int split_csv(const char *s, char tok[][64], int maxtok)
{
	int n = 0;
	while (*s && n < maxtok) {
		while (*s == ' ' || *s == '\t') s++;
		int j = 0;
		while (*s && *s != ',' && j < 63) tok[n][j++] = *s++;
		while (j > 0 && (tok[n][j-1] == ' ' || tok[n][j-1] == '\t')) j--;
		tok[n][j] = '\0';
		n++;
		if (*s == ',') s++;
	}
	return n;
}

/*
 * Parse byte_test: "<bytes>,[!]<op>,<value>,<offset>[,relative][,big|little]".
 * Returns 0 if fully supported (op filled in), non-zero if complex/error
 * (caller caps to ALERT).
 */
static int parse_byte_test(const char *val, int after, struct sig_byteop *op)
{
	char tok[12][64];
	int nt = split_csv(val, tok, 12);
	if (nt < 4) return 1;
	memset(op, 0, sizeof(*op));
	op->kind = SIG_BYTE_TEST; op->after_content = after; op->multiplier = 1;
	op->nbytes = (uint8_t)atoi(tok[0]);
	if (op->nbytes < 1 || op->nbytes > 8) return 1;
	const char *o = tok[1];
	if (*o == '!') { op->negate = 1; o++; }
	if (!*o || !strchr("<>=&|", *o)) return 1;
	op->oper  = *o;
	op->value = (int32_t)strtol(tok[2], NULL, 0);   /* 0x.. auto-detected as hex */
	op->offset = (int32_t)strtol(tok[3], NULL, 0);
	for (int i = 4; i < nt; i++) {
		if (!strcmp(tok[i], "relative")) op->relative = 1;
		else if (!strcmp(tok[i], "little")) op->little = 1;
		else if (!strcmp(tok[i], "big") || !tok[i][0]) ;
		else return 1;   /* string/dce/dec… unsupported → cap */
	}
	return 0;
}

/*
 * Parse byte_jump: "<bytes>,<offset>[,relative][,little|big]
 *                   [,multiplier <m>][,post_offset <n>]".
 */
static int parse_byte_jump(const char *val, int after, struct sig_byteop *op)
{
	char tok[12][64];
	int nt = split_csv(val, tok, 12);
	if (nt < 2) return 1;
	memset(op, 0, sizeof(*op));
	op->kind = SIG_BYTE_JUMP; op->after_content = after; op->multiplier = 1;
	op->nbytes = (uint8_t)atoi(tok[0]);
	if (op->nbytes < 1 || op->nbytes > 8) return 1;
	op->offset = (int32_t)strtol(tok[1], NULL, 0);
	for (int i = 2; i < nt; i++) {
		if (!strcmp(tok[i], "relative")) op->relative = 1;
		else if (!strcmp(tok[i], "little")) op->little = 1;
		else if (!strcmp(tok[i], "big") || !tok[i][0]) ;
		else if (!strncmp(tok[i], "multiplier", 10)) {
			const char *sp = strchr(tok[i], ' ');
			if (sp) op->multiplier = atoi(sp + 1);
		} else if (!strncmp(tok[i], "post_offset", 11)) {
			const char *sp = strchr(tok[i], ' ');
			if (sp) op->post_offset = atoi(sp + 1);
		} else return 1;   /* from_beginning/align/dce → cap */
	}
	return 0;
}

/* Read nbytes at pos (big/little). BOUNDS-CHECKED. Returns 1 if read succeeded. */
static int read_field(const uint8_t *p, int len, int pos, int nbytes,
		      int little, int64_t *out)
{
	if (pos < 0 || nbytes < 1 || nbytes > 8 || pos + nbytes > len)
		return 0;
	uint64_t v = 0;
	for (int i = 0; i < nbytes; i++) {
		uint8_t b = little ? p[pos + (nbytes - 1 - i)] : p[pos + i];
		v = (v << 8) | b;
	}
	*out = (int64_t)v;
	return 1;
}

/* Apply one byteop. byte_test: returns 1/0 (match). byte_jump: moves the cursor,
 * returns 1. Read failure (out of buffer) → 0 (fail-closed for this rule). */
static int apply_byteop(const struct sig_byteop *op, const uint8_t *p, int len,
			int *cursor)
{
	int pos = op->relative ? (*cursor + op->offset) : op->offset;
	int64_t v;
	if (!read_field(p, len, pos, op->nbytes, op->little, &v))
		return 0;

	if (op->kind == SIG_BYTE_TEST) {
		int r;
		switch (op->oper) {
		case '<': r = (v <  op->value); break;
		case '>': r = (v >  op->value); break;
		case '=': r = (v == op->value); break;
		case '&': r = ((v & op->value) != 0); break;
		case '|': r = ((v | op->value) != 0); break;
		default:  r = 0;
		}
		return op->negate ? !r : r;
	}
	/* BYTE_JUMP: jump the cursor by the read value; CLAMP [0,len] to stay in bounds. */
	int64_t nc = (int64_t)pos + op->nbytes +
		     v * op->multiplier + op->post_offset;
	if (nc < 0)   nc = 0;
	if (nc > len) nc = len;
	*cursor = (int)nc;
	return 1;
}

/* ---- P5: flowbits -------------------------------------------------------- */

static inline int fb_get(const struct flowbit_state *s, int id)
{
	return (s->bits[id >> 6] >> (id & 63)) & 1u;
}
static inline void fb_set(struct flowbit_state *s, int id)
{
	s->bits[id >> 6] |= (uint64_t)1u << (id & 63);
}
static inline void fb_clear(struct flowbit_state *s, int id)
{
	s->bits[id >> 6] &= ~((uint64_t)1u << (id & 63));
}

/* Find-or-add a flag name in the ruleset's global table. Returns id, -1 if full/error. */
static int flowbit_intern(struct sig_ruleset *rs, const char *name)
{
	for (int i = 0; i < rs->n_fb_names; i++)
		if (!strcmp(rs->fb_names[i], name))
			return i;
	if (rs->n_fb_names >= SIG_MAX_FLOWBITS)
		return -1;
	if (rs->n_fb_names == rs->cap_fb_names) {
		int nc = rs->cap_fb_names ? rs->cap_fb_names * 2 : 64;
		void *pn = realloc(rs->fb_names, (size_t)nc * SIG_FB_NAME_MAX);
		uint8_t *pe = realloc(rs->fb_ever_set, (size_t)nc);
		if (!pn || !pe) { free(pn == rs->fb_names ? NULL : pn); return -1; }
		rs->fb_names    = pn;
		rs->fb_ever_set = pe;
		rs->cap_fb_names = nc;
	}
	int id = rs->n_fb_names++;
	snprintf(rs->fb_names[id], SIG_FB_NAME_MAX, "%s", name);
	rs->fb_ever_set[id] = 0;
	return id;
}

/*
 * Parse one flowbits keyword: "set,Name" / "isset,Name" / "noalert" / "unset,
 * Name" / "toggle,Name" / "isnotset,Name". Attach to rule + intern the name.
 */
static void parse_flowbits(struct sig_ruleset *rs, struct sig_rule *r,
			   const char *val)
{
	char tok[3][64];
	int nt = split_csv(val, tok, 3);
	if (nt < 1) return;

	if (!strcmp(tok[0], "noalert")) { r->fb_noalert = 1; return; }
	if (nt < 2) return;                       /* other ops need a flag name */

	int op;
	if      (!strcmp(tok[0], "isset"))    op = SIG_FB_ISSET;
	else if (!strcmp(tok[0], "isnotset")) op = SIG_FB_ISNOTSET;
	else if (!strcmp(tok[0], "set"))      op = SIG_FB_SET;
	else if (!strcmp(tok[0], "unset"))    op = SIG_FB_UNSET;
	else if (!strcmp(tok[0], "toggle"))   op = SIG_FB_TOGGLE;
	else return;                              /* unknown op → skip safely */

	int id = flowbit_intern(rs, tok[1]);
	if (id < 0 || r->n_fb >= SIG_MAX_FB_RULE) return;
	/* fb_ever_set is marked WHEN the rule commits to L2 (not here) so that a
	 * setter that gets SKIPPED/L1 is not counted as "set" — avoids isnotset
	 * false-drop. */
	r->flowbits[r->n_fb].op      = (uint8_t)op;
	r->flowbits[r->n_fb].flag_id = (int16_t)id;
	r->n_fb++;
}

/* ---- P4: pcre ------------------------------------------------------------ */
/*
 * Parse "pcre:/regex/flags". HAVE_PCRE: compile (cached). Failure / no pcre
 * build → CLAMP to ALERT (P0). Modifiers: i/s/m → regex flags; R → relative
 * (from end of prev content); U/H/P → buffer (http_uri/header/body — reuses P6).
 */
static void parse_pcre(struct sig_rule *r, const char *val)
{
#ifdef HAVE_PCRE
	const char *s = val;
	while (*s == ' ' || *s == '\t') s++;
	if (*s == '"') s++;                 /* in case a quote is left over */
	if (*s != '/') goto cap;
	s++;
	const char *pat = s;
	const char *end = strrchr(s, '/');  /* trailing '/' separates flags */
	if (!end || end <= pat) goto cap;
	size_t plen = (size_t)(end - pat);

	uint32_t opts = 0;
	int relative = 0, buffer = SIG_BUF_RAW;
	for (const char *f = end + 1; *f && *f != '"'; f++) {
		switch (*f) {
		case 'i': opts |= PCRE2_CASELESS;  break;
		case 's': opts |= PCRE2_DOTALL;    break;
		case 'm': opts |= PCRE2_MULTILINE; break;
		case 'R': relative = 1;            break;
		case 'U': case 'I': buffer = SIG_BUF_HTTP_URI;    break;
		case 'H': buffer = SIG_BUF_HTTP_HEADER;           break;
		case 'P': buffer = SIG_BUF_HTTP_BODY;             break;
		default:  break;                   /* G/B/O… ignore */
		}
	}

	char tmp[2048];
	if (plen == 0 || plen >= sizeof(tmp)) goto cap;
	memcpy(tmp, pat, plen);
	tmp[plen] = '\0';

	int errcode; PCRE2_SIZE erroff;
	pcre2_code *code = pcre2_compile((PCRE2_SPTR)tmp, plen, opts,
					 &errcode, &erroff, NULL);
	if (!code) goto cap;                /* broken regex → cap */
	r->pcre          = code;
	r->pcre_relative = (uint8_t)relative;
	r->pcre_buffer   = (uint8_t)buffer;
	return;
cap:
#else
	(void)val;
#endif
	r->has_unsup |= SIG_U_PCRE;
	r->fidelity   = SIG_FID_ALERT;
}

/* ---- parse options (...) ------------------------------------------------- */
/*
It scans the options string, using while loops to split key-value pairs on the
         ':' and ';' delimiters. Then, based on the key (such as "content",
         "nocase", "sid"), it fills the data into struct sig_rule.
*/
static int parse_options(struct sig_ruleset *rs, struct sig_rule *r,
			 const char *p)
{
	int cur = -1;   /* most recent content, for attaching nocase/offset/depth */

	while (*p) {
		char key[24]; int k = 0;
		char val[SIG_CONTENT_MAX + 64]; int vlen = 0;

		while (*p == ' ' || *p == '\t' || *p == ';') p++;
		if (!*p) break;

		/* read keyword up to ':' or ';' */
		while (*p && *p != ':' && *p != ';' && k < (int)sizeof(key) - 1) {
			if (*p == ' ' || *p == '\t') { p++; continue; }
			key[k++] = *p++;
		}
		key[k] = '\0';

		/* read value if there is a ':' */
		if (*p == ':') {
			p++;
			while (*p == ' ' || *p == '\t') p++;
			if (*p == '"') {              /* string: up to unescaped '"' */
				p++;
				while (*p && *p != '"') {
					if (*p == '\\' && p[1]) {  /* keep the escape pair intact */
						if (vlen < (int)sizeof(val) - 1) val[vlen++] = *p;
						p++;
						if (vlen < (int)sizeof(val) - 1) val[vlen++] = *p;
						p++;
					} else {
						if (vlen < (int)sizeof(val) - 1) val[vlen++] = *p;
						p++;
					}
				}
				if (*p == '"') p++;
			} else {                      /* token up to ';' */
				while (*p && *p != ';') {
					if (vlen < (int)sizeof(val) - 1) val[vlen++] = *p;
					p++;
				}
			}
		}
		val[vlen] = '\0';

		/* dispatch */
		if (!strcmp(key, "content")) {
			if (r->n_content < SIG_MAX_CONTENT) {
				uint8_t tmp[SIG_CONTENT_MAX];
				int clen = decode_content(val, tmp, sizeof(tmp));
				if (clen > 0) {
					struct sig_content *c = &r->content[r->n_content];
					c->data = malloc((size_t)clen);
					if (!c->data) return -1;
					memcpy(c->data, tmp, (size_t)clen);
					c->len = clen; c->nocase = 0;
					c->offset = -1; c->depth = -1;
					c->distance = -1; c->within = -1;
					c->relative = 0;
					c->buffer = SIG_BUF_RAW;
					cur = r->n_content++;
				}
			}
		} else if (!strcmp(key, "nocase")) {
			if (cur >= 0) r->content[cur].nocase = 1;
		} else if (!strcmp(key, "offset")) {
			if (cur >= 0) r->content[cur].offset = parse_uint_field(val, 65535);
		} else if (!strcmp(key, "depth")) {
			if (cur >= 0) r->content[cur].depth = parse_uint_field(val, 65535);
		} else if (!strcmp(key, "sgprof")) {
			/* Per-policy scoping (Stargazer): BITMASK of profiles containing
			 * this rule (mgmtd dedups by sid at compile time → ORs in the bit
			 * of every profile with the sid). Hex value "0x..". ORed for
			 * safety if it appears multiple times. */
			r->prof_mask |= (uint32_t)strtoul(val, NULL, 0);
		} else if (!strcmp(key, "http_uri") ||     /* P6 — sticky buffers */
			   !strcmp(key, "http_raw_uri")) {
			if (cur >= 0) r->content[cur].buffer = SIG_BUF_HTTP_URI;
		} else if (!strcmp(key, "http_header") ||
			   !strcmp(key, "http_raw_header")) {
			if (cur >= 0) r->content[cur].buffer = SIG_BUF_HTTP_HEADER;
		} else if (!strcmp(key, "http_method")) {
			if (cur >= 0) r->content[cur].buffer = SIG_BUF_HTTP_METHOD;
		} else if (!strcmp(key, "http_client_body")) {
			if (cur >= 0) r->content[cur].buffer = SIG_BUF_HTTP_BODY;
		} else if (!strcmp(key, "tls_sni") || !strcmp(key, "tls.sni")) {
			if (cur >= 0) r->content[cur].buffer = SIG_BUF_TLS_SNI;
		} else if (!strcmp(key, "distance")) {     /* P2 — relative positioning */
			if (cur >= 0) {
				r->content[cur].distance =
					parse_int_field(val, -65535, 65535);
				r->content[cur].relative = 1;
			}
		} else if (!strcmp(key, "within")) {
			if (cur >= 0) {
				int v = parse_uint_field(val, 65535);
				if (v >= 0) r->content[cur].within = v;
				r->content[cur].relative = 1;
			}
		} else if (!strcmp(key, "dsize")) {
			parse_dsize(val, &r->dsize_min, &r->dsize_max);
		} else if (!strcmp(key, "pcre")) {            /* P4 */
			parse_pcre(r, val);
		} else if (!strcmp(key, "flowbits")) {        /* P5 */
			parse_flowbits(rs, r, val);
		} else if (!strcmp(key, "flow")) {            /* P6 */
			char ft[8][64];
			int nt = split_csv(val, ft, 8);
			for (int i = 0; i < nt; i++) {
				if (!strcmp(ft[i], "established"))
					r->flow_flags |= SIG_FLOW_ESTABLISHED;
				else if (!strcmp(ft[i], "to_server") ||
					 !strcmp(ft[i], "from_client"))
					r->flow_flags |= SIG_FLOW_TO_SERVER;
				else if (!strcmp(ft[i], "to_client") ||
					 !strcmp(ft[i], "from_server"))
					r->flow_flags |= SIG_FLOW_TO_CLIENT;
				/* stateless/no_stream/only_stream → unconstrained */
			}
		} else if (!strcmp(key, "byte_test") ||
			   !strcmp(key, "byte_jump")) {       /* P3 */
			struct sig_byteop op;
			int rc = 1;
			if (r->n_byteop < SIG_MAX_BYTEOP)
				rc = (key[5] == 't')
				   ? parse_byte_test(val, r->n_content, &op)
				   : parse_byte_jump(val, r->n_content, &op);
			if (rc == 0) {
				r->byteop[r->n_byteop++] = op;
			} else {
				/* complex/full → cap ALERT (don't apply a wrong constraint). */
				r->has_unsup |= SIG_U_BYTEOP;
				r->fidelity   = SIG_FID_ALERT;
			}
		} else if (!strcmp(key, "flags")) {
			r->flags_set = parse_flags(val);
		} else if (!strcmp(key, "sid")) {
			r->sid = (uint32_t)strtoul(val, NULL, 10);
		} else if (!strcmp(key, "rev")) {
			r->rev = (uint32_t)strtoul(val, NULL, 10);
		} else if (!strcmp(key, "msg")) {
			size_t mn = strlen(val);
			if (mn >= sizeof(r->msg)) mn = sizeof(r->msg) - 1;
			memcpy(r->msg, val, mn);
			r->msg[mn] = '\0';
		} else {
			/* P0 — unsupported narrowing keyword → cap ALERT + count.
			 * Annotation keywords (reference/metadata/classtype/priority/
			 * gid/target/flow/fast_pattern…) don't narrow the match → skipped
			 * safely (unsup_bit returns 0). */
			uint8_t ub = unsup_bit(key);
			if (ub) {
				r->has_unsup |= ub;
				r->fidelity   = SIG_FID_ALERT;
			}
		}
	}
	return 0;
}

/* ---- ruleset ------------------------------------------------------------- */

int sig_ruleset_init(struct sig_ruleset *rs)
{
	memset(rs, 0, sizeof(*rs));
	return 0;
}

static struct sig_rule *ruleset_new(struct sig_ruleset *rs)
{
	if (rs->n_rules == rs->cap_rules) {
		int n = rs->cap_rules ? rs->cap_rules * 2 : 64;
		struct sig_rule *p = realloc(rs->rules, (size_t)n * sizeof(*p));
		if (!p) return NULL;
		rs->rules = p;
		rs->cap_rules = n;
	}
	struct sig_rule *r = &rs->rules[rs->n_rules];
	memset(r, 0, sizeof(*r));
	r->fast = -1;
	r->dsize_min = -1;
	r->dsize_max = -1;
	return r;
}

int sig_parse_line(struct sig_ruleset *rs, const char *line)
{
	char buf[16384];   /* matches acc in sig_load_file — don't truncate long rules */
	const char *q = line;

	while (*q == ' ' || *q == '\t') q++;
	if (*q == '\0' || *q == '#' || *q == '\n')
		return 1;                                  /* empty / comment */

	snprintf(buf, sizeof(buf), "%s", q);

	char *lp = strchr(buf, '(');
	char *rp = strrchr(buf, ')');
	if (!lp || !rp || rp < lp)
		return -1;                                 /* missing (...) */
	*rp = '\0';
	*lp = '\0';
	const char *header  = buf;
	const char *options = lp + 1;

	char action[16], proto[16], sip[64], sport[40], dir[8], dip[64], dport[40];
	if (sscanf(header, "%15s %15s %63s %39s %7s %63s %39s",
		   action, proto, sip, sport, dir, dip, dport) != 7)
		return -1;                                 /* bad header */

	struct sig_rule *r = ruleset_new(rs);
	if (!r) return -1;
	r->action = parse_action(action);
	r->proto  = parse_proto(proto);
	parse_port_to_list(dport, r->dport_list, &r->n_dport);

	if (parse_options(rs, r, options) < 0) {
		/* clean up content allocated by the failed rule, don't commit */
		for (int i = 0; i < r->n_content; i++) free(r->content[i].data);
		memset(r, 0, sizeof(*r));
		return SIG_LINE_ERROR;
	}

	if (r->n_content == 0) {
		/* Rule with NO content. The engine only has content-based signatures
		 * (L2) — the "L1 signature" layer (flow-stats matching) was REMOVED.
		 * Classify for reporting:
		 *   - reputation/IP-list/catch-all (proto any, no dport, no flags)
		 *   - otherwise (proto/dport/flags) → nothing to inspect → drop.
		 * (SYN-flood/port-scan anomalies are still handled by
		 * flow_rule_match_builtin.) */
		int rc = (r->proto == SIG_PROTO_ANY && r->n_dport == 0 &&
			  r->flags_set == 0)
			 ? SIG_LINE_SKIP_REP
			 : SIG_LINE_SKIP_NOCONTENT;
		memset(r, 0, sizeof(*r));
		return rc;
	}

	/* Rule with NO `sid` keyword (r->sid==0): untraceable, usually a malformed/
	 * local line; here it often matches common content on normal traffic →
	 * false-positive. Valid ET/Snort/custom rules always have a sid → drop
	 * safely. */
	if (r->sid == 0) {
		for (int i = 0; i < r->n_content; i++) free(r->content[i].data);
		memset(r, 0, sizeof(*r));
		return SIG_LINE_SKIP_NOSID;
	}

	/* P0 — content too weak (1 content ≤ 2 bytes) + an unsupported narrowing
	 * keyword remains → useless prefilter + missing narrowing condition → match
	 * too broad → drop. */
	if (r->has_unsup && r->n_content == 1 && r->content[0].len <= 2) {
		for (int i = 0; i < r->n_content; i++) free(r->content[i].data);
		memset(r, 0, sizeof(*r));
		return SIG_LINE_SKIP_UNSUP;
	}

	/* fast pattern = LONGEST content (most selective) */
	r->fast = 0;
	for (int i = 1; i < r->n_content; i++)
		if (r->content[i].len > r->content[r->fast].len)
			r->fast = i;

	/* P5 — this L2 rule actually loaded → the flags it sets/toggles are "trusted". */
	for (int i = 0; i < r->n_fb; i++) {
		int op = r->flowbits[i].op, id = r->flowbits[i].flag_id;
		if ((op == SIG_FB_SET || op == SIG_FB_TOGGLE) &&
		    id >= 0 && id < rs->n_fb_names)
			rs->fb_ever_set[id] = 1;
	}

	/* Table default action; profile maps override `action` and reset it back to
	 * this on every scope reload. */
	r->base_action = r->action;

	int fid = r->fidelity;
	rs->n_rules++;
	return (fid == SIG_FID_ALERT) ? SIG_LINE_ALERT : SIG_LINE_FULL;
}

static void tally_line(int rc, struct sig_load_stats *s, int *added)
{
	switch (rc) {
	case SIG_LINE_FULL:
		(*added)++; s->loaded++; s->loaded_full++;  break;
	case SIG_LINE_ALERT:
		(*added)++; s->loaded++; s->loaded_alert++; break;
	case SIG_LINE_BLANK:
		s->skipped++; break;
	case SIG_LINE_SKIP_UNSUP:
		s->skipped++; s->skipped_unsupported++; break;
	case SIG_LINE_SKIP_REP:
		s->skipped++; s->skipped_reputation++;  break;
	case SIG_LINE_SKIP_NOCONTENT:
		s->skipped++; s->skipped_no_content++;  break;
	case SIG_LINE_SKIP_NOSID:
		s->skipped++; s->skipped_no_sid++;      break;
	default: /* SIG_LINE_ERROR */
		s->errors++; break;
	}
}

int sig_load_file(struct sig_ruleset *rs, const char *path,
		  struct sig_load_stats *st)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;

	/* acc MUST be large enough for the longest rule; ln matches the compiler's
	 * buffer (8192) so lines aren't truncated mid-line. Old BUG: ln[4096] <
	 * line[8192] in mgmtd_ips_compile → ET rules > 4095 bytes were truncated,
	 * losing sid + narrowing conditions (flow/offset/depth at the end) → only a
	 * broad content left → false-positive sid=0. */
	char acc[16384]; size_t al = 0;
	char ln[8192];
	int added = 0;
	struct sig_load_stats s = { 0 };

	while (fgets(ln, sizeof(ln), f)) {
		size_t l = strlen(ln);
		int had_nl = (l > 0 && ln[l - 1] == '\n');   /* physical line ended? */
		while (l && (ln[l - 1] == '\n' || ln[l - 1] == '\r')) ln[--l] = '\0';

		int backslash = (l && ln[l - 1] == '\\');    /* Snort-style line continuation */
		if (backslash) ln[--l] = '\0';

		if (al + l < sizeof(acc)) { memcpy(acc + al, ln, l + 1); al += l; }

		/* physical line NOT finished (fgets filled the buffer, no '\n' yet) OR
		 * '\' continuation → keep accumulating, do NOT parse. This is the
		 * long-line fix. */
		if (!had_nl || backslash)
			continue;

		tally_line(sig_parse_line(rs, acc), &s, &added);
		al = 0; acc[0] = '\0';
	}
	if (al > 0)   /* last line of file with no trailing newline */
		tally_line(sig_parse_line(rs, acc), &s, &added);
	fclose(f);
	if (st) *st = s;
	return added;
}

/* ---- sid index + per-profile selection maps ----------------------------- */

static uint32_t sid_hash(uint32_t x)
{
	x ^= x >> 16; x *= 0x7feb352dU;
	x ^= x >> 15; x *= 0x846ca68bU;
	x ^= x >> 16;
	return x;
}

/* (Re)build the open-addressed sid → rule-index table. Degrades to "no index"
 * (rs_by_sid returns NULL) on OOM — the maps then simply find no rules. */
static void sig_build_sid_index(struct sig_ruleset *rs)
{
	free(rs->sid_index);
	rs->sid_index = NULL;
	rs->sid_index_cap = 0;
	int cap = 64;
	while (cap < rs->n_rules * 2) cap <<= 1;
	int32_t *idx = malloc((size_t)cap * sizeof(int32_t));
	if (!idx) return;
	for (int i = 0; i < cap; i++) idx[i] = -1;
	for (int i = 0; i < rs->n_rules; i++) {
		uint32_t h = sid_hash(rs->rules[i].sid) & (uint32_t)(cap - 1);
		while (idx[h] != -1) h = (h + 1) & (uint32_t)(cap - 1);
		idx[h] = i;
	}
	rs->sid_index = idx;
	rs->sid_index_cap = cap;
}

static struct sig_rule *rs_by_sid(struct sig_ruleset *rs, uint32_t sid)
{
	if (!rs->sid_index) return NULL;
	uint32_t mask = (uint32_t)(rs->sid_index_cap - 1);
	uint32_t h = sid_hash(sid) & mask;
	for (int probes = 0; probes < rs->sid_index_cap; probes++) {
		int32_t i = rs->sid_index[h];
		if (i == -1) return NULL;
		if (rs->rules[i].sid == sid) return &rs->rules[i];
		h = (h + 1) & mask;
	}
	return NULL;
}

int sig_load_profile_maps(struct sig_ruleset *rs, const char *prof_dir)
{
	for (int i = 0; i < rs->n_rules; i++) {       /* reset to inert */
		rs->rules[i].prof_mask      = 0;
		rs->rules[i].prof_drop_mask = 0;
		rs->rules[i].action         = rs->rules[i].base_action;
	}
	DIR *d = opendir(prof_dir);
	if (!d) return -1;
	struct dirent *de;
	while ((de = readdir(d))) {
		int profid = 0; char tail[8] = "";
		if (sscanf(de->d_name, "%d.%7s", &profid, tail) != 2 ||
		    strcmp(tail, "rules") != 0 || profid < 1 || profid > 31)
			continue;                         /* not "<1..31>.rules" */
		char path[512];
		snprintf(path, sizeof(path), "%s/%s", prof_dir, de->d_name);
		FILE *f = fopen(path, "r");
		if (!f) continue;
		uint32_t bit = 1u << (profid - 1);
		char line[128];
		while (fgets(line, sizeof(line), f)) {
			uint32_t sid = 0; char act[16] = "";
			if (sscanf(line, "%u %15s", &sid, act) < 1 || sid == 0)
				continue;
			struct sig_rule *r = rs_by_sid(rs, sid);
			if (!r) continue;
			r->prof_mask |= bit;              /* member of this profile */
			/* PER-PROFILE action: "block" → this profile's drop bit; any
			 * other token ("alert"/unknown) → leave clear (= ALERT). No
			 * cross-profile interference — each profid owns its own bit. */
			if (!strcmp(act, "block"))
				r->prof_drop_mask |= bit;
			else
				r->prof_drop_mask &= ~bit;
		}
		fclose(f);
	}
	closedir(d);
	return 0;
}

int sig_build(struct sig_ruleset *rs)
{
	/* P5 — skip propagation: a rule relying on isset/isnotset of a flag that NO
	 * rule sets → untrustworthy condition → CLAMP to ALERT (not DROP) to avoid
	 * isnotset-always-true causing a false-drop. */
	for (int i = 0; i < rs->n_rules; i++) {
		struct sig_rule *r = &rs->rules[i];
		for (int j = 0; j < r->n_fb; j++) {
			int op = r->flowbits[j].op;
			if (op != SIG_FB_ISSET && op != SIG_FB_ISNOTSET)
				continue;
			int id = r->flowbits[j].flag_id;
			if (id < 0 || id >= rs->n_fb_names || !rs->fb_ever_set[id])
				r->fidelity = SIG_FID_ALERT;
		}
	}

	/* AC uses nocase=1 as the PREFILTER for every rule; exact case is left to
	 * the verify step (per-content nocase) — the fast pattern only filters. */
	if (ac_init(&rs->ac, 1) != 0)
		return -1;
	for (int i = 0; i < rs->n_rules; i++) {
		struct sig_rule *r = &rs->rules[i];
		if (r->fast < 0) continue;
		struct sig_content *c = &r->content[r->fast];
		if (ac_add_pattern(&rs->ac, c->data, c->len, i) != 0)
			return -1;
	}
	if (ac_build(&rs->ac) != 0)
		return -1;
	sig_build_sid_index(rs);   /* sid → rule index for the per-profile maps */
	rs->built = 1;
	return 0;
}

/* ---- matching ------------------------------------------------------------ */

/* find needle in hay[from .. to) ; return start index or -1 */
static int mem_find(const uint8_t *hay, const uint8_t *needle, int nlen,
		    int nocase, int from, int to)
{
	if (nlen <= 0) return from;
	for (int s = from; s + nlen <= to; s++) {
		int k = 0;
		for (; k < nlen; k++) {
			uint8_t a = hay[s + k], b = needle[k];
			if (nocase) {
				if (a >= 'A' && a <= 'Z') a += 32;
				if (b >= 'A' && b <= 'Z') b += 32;
			}
			if (a != b) break;
		}
		if (k == nlen) return s;
	}
	return -1;
}

/* Fully verify one rule against a payload. 1 = match, 0 = no match. */
static int verify_rule(const struct sig_rule *r, const uint8_t *p, int len,
		       const struct flow_ctx *fc)
{
	/* Per-policy scoping: prof_mask is set from the per-profile selection maps
	 * (which profiles include this rule). The flow carries prof_id (1..31) = the
	 * profile of the policy that allowed it (skb mark/NFQA_MARK). When the flow
	 * has a profile, the rule applies ONLY if it is a member of that profile
	 * (prof_mask bit set) — a rule in no active profile is inert. prof_id==0
	 * (IPS off / unmarked) keeps the legacy match-all (fail-safe). */
	if (fc->prof_id &&
	    !(r->prof_mask & (1u << (fc->prof_id - 1)))) return 0;

	if (r->proto != SIG_PROTO_ANY && fc->proto != r->proto) return 0;
	if (!port_match(r->dport_list, r->n_dport, fc->dport))  return 0;
	if (r->flags_set && (fc->tcp_flags & r->flags_set) != r->flags_set) return 0;

	/* P6 — flow: filter by direction/state (cheap, cuts many false reports). */
	if ((r->flow_flags & SIG_FLOW_ESTABLISHED) && !fc->established) return 0;
	if ((r->flow_flags & SIG_FLOW_TO_SERVER)   && !fc->to_server)   return 0;
	if ((r->flow_flags & SIG_FLOW_TO_CLIENT)   &&  fc->to_server)   return 0;

	/* P5 — flowbits isset/isnotset (condition). REQUIRES the flow to be tracked
	 * (fc->fb != NULL); not tracked → not satisfied → no match (fail-safe). */
	for (int i = 0; i < r->n_fb; i++) {
		const struct sig_flowbit *b = &r->flowbits[i];
		if (b->op == SIG_FB_ISSET) {
			if (!fc->fb || !fb_get(fc->fb, b->flag_id)) return 0;
		} else if (b->op == SIG_FB_ISNOTSET) {
			if (!fc->fb || fb_get(fc->fb, b->flag_id)) return 0;
		}
	}

	/* P2 — dsize: payload length (reassembled stream for TCP, packet for UDP). */
	if (r->dsize_min >= 0 && len < r->dsize_min) return 0;
	if (r->dsize_max >= 0 && len > r->dsize_max) return 0;

	/*
	 * P2 — content positioning. last_end = end of the previous content match.
	 *   relative (distance/within): window [last_end+distance, +within) —
	 *     correct Snort semantics for multi-content rules.
	 *   absolute (offset/depth): window [offset, offset+depth), INDEPENDENT of
	 *     the previous match → old content-only rules keep their behavior.
	 * Every lo/hi is clamped to [0,len] before mem_find (anti negative/overflow index).
	 */
	int last_end = 0, bop = 0, cur_buf = SIG_BUF_RAW;
	for (int i = 0; i < r->n_content; i++) {
		/* P3 — byteop interleaved BEFORE content i (read on RAW, in order). */
		while (bop < r->n_byteop && r->byteop[bop].after_content == i) {
			if (!apply_byteop(&r->byteop[bop], p, len, &last_end))
				return 0;
			bop++;
		}

		const struct sig_content *c = &r->content[i];

		/* P6 — select the match buffer. RAW = payload/stream; other regions
		 * come from fc->bufs (must be extracted). No buffer → no match (fail-safe). */
		const uint8_t *bp = p;
		int blen = len;
		if (c->buffer != SIG_BUF_RAW) {
			if (!fc->bufs) return 0;
			bp   = fc->bufs->b[c->buffer];
			blen = fc->bufs->len[c->buffer];
			if (!bp || blen <= 0) return 0;
		}
		/* buffer change → reset the relative-positioning cursor. */
		if (c->buffer != cur_buf) { last_end = 0; cur_buf = c->buffer; }

		int lo, hi;
		if (c->relative) {
			lo = last_end + c->distance;
			hi = (c->within >= 0) ? lo + c->within : blen;
		} else {
			int base = (c->offset >= 0) ? c->offset : 0;
			lo = base > last_end ? base : last_end;
			hi = (c->depth >= 0) ? base + c->depth : blen;
		}

		if (lo < 0)    lo = 0;
		if (hi > blen) hi = blen;
		if (lo > hi)   return 0;

		int s = mem_find(bp, c->data, c->len, c->nocase, lo, hi);
		if (s < 0) return 0;
		last_end = s + c->len;
	}
	/* P3 — byteops after the last content. */
	while (bop < r->n_byteop) {
		if (!apply_byteop(&r->byteop[bop], p, len, &last_end))
			return 0;
		bop++;
	}

#ifdef HAVE_PCRE
	/* P4 — pcre is the FINAL VERIFY STEP (after AC prefilter + content anchors).
	 * Match/depth limits guard against ReDoS; JIT off so the interpreter honors
	 * the limits. */
	if (r->pcre) {
		const uint8_t *sp = p;
		int slen = len;
		if (r->pcre_buffer != SIG_BUF_RAW) {
			if (!fc->bufs) return 0;
			sp   = fc->bufs->b[r->pcre_buffer];
			slen = fc->bufs->len[r->pcre_buffer];
			if (!sp || slen <= 0) return 0;
		}
		PCRE2_SIZE startoff = 0;
		if (r->pcre_relative && r->pcre_buffer == SIG_BUF_RAW &&
		    last_end >= 0 && last_end <= slen)
			startoff = (PCRE2_SIZE)last_end;

		pcre2_match_data *md = pcre2_match_data_create(1, NULL);
		if (!md) return 0;
		pcre2_match_context *mctx = pcre2_match_context_create(NULL);
		if (mctx) {
			pcre2_set_match_limit(mctx, PCRE_MATCH_LIMIT);
			pcre2_set_depth_limit(mctx, PCRE_DEPTH_LIMIT);
		}
		int rc = pcre2_match((const pcre2_code *)r->pcre, sp,
				     (PCRE2_SIZE)slen, startoff, 0, md, mctx);
		pcre2_match_data_free(md);
		if (mctx) pcre2_match_context_free(mctx);
		if (rc < 0) return 0;   /* NOMATCH / limit → rule does not match */
	}
#endif
	return 1;
}

struct match_ctx {
	const struct sig_ruleset *rs;
	const uint8_t *payload;
	int            len;
	const struct flow_ctx *fc;
	int            best;          /* rule index */
	int            best_action;
};

static int on_fast_hit(int rule_idx, size_t end_pos, void *ctx)
{
	struct match_ctx *m = ctx;
	const struct sig_rule *r = &m->rs->rules[rule_idx];
	(void)end_pos;

	if (!verify_rule(r, m->payload, m->len, m->fc))
		return 0;                                /* prefilter hit but verify failed */

	int action = sig_eff_action(r, m->fc ? m->fc->prof_id : 0);
	if (r->fidelity == SIG_FID_ALERT)
		action = SIG_ALERT;                      /* P0 fidelity-cap */
	if (action > m->best_action) {
		m->best_action = action;
		m->best        = rule_idx;
	}
	return m->best_action == SIG_DROP ? 1 : 0;       /* got a DROP → stop early */
}

int sig_verify(const struct sig_ruleset *rs, int rule_idx,
	       const uint8_t *buf, int len, const struct flow_ctx *fc)
{
	if (!rs || rule_idx < 0 || rule_idx >= rs->n_rules || !buf || len < 0)
		return 0;
	return verify_rule(&rs->rules[rule_idx], buf, len, fc);
}

void sig_flowbits_apply(const struct sig_rule *r, struct flowbit_state *fb)
{
	if (!r || !fb) return;
	for (int i = 0; i < r->n_fb; i++) {
		const struct sig_flowbit *b = &r->flowbits[i];
		switch (b->op) {
		case SIG_FB_SET:    fb_set(fb, b->flag_id);   break;
		case SIG_FB_UNSET:  fb_clear(fb, b->flag_id); break;
		case SIG_FB_TOGGLE:
			if (fb_get(fb, b->flag_id)) fb_clear(fb, b->flag_id);
			else                        fb_set(fb, b->flag_id);
			break;
		default: break;   /* isset/isnotset: no side effect */
		}
	}
}

int sig_match(const struct sig_ruleset *rs, const uint8_t *payload, size_t len,
	      const struct flow_ctx *fc)
{
	if (!rs->built) return -1;

	struct match_ctx m = {
		.rs = rs, .payload = payload, .len = (int)len, .fc = fc,
		.best = -1, .best_action = -1,
	};
	ac_search(&rs->ac, payload, len, on_fast_hit, &m);
	return m.best;
}

void sig_ruleset_free(struct sig_ruleset *rs)
{
	for (int i = 0; i < rs->n_rules; i++) {
		for (int j = 0; j < rs->rules[i].n_content; j++)
			free(rs->rules[i].content[j].data);
#ifdef HAVE_PCRE
		if (rs->rules[i].pcre)
			pcre2_code_free((pcre2_code *)rs->rules[i].pcre);
#endif
	}
	free(rs->rules);
	free(rs->sid_index);
	free(rs->fb_names);        /* P5 */
	free(rs->fb_ever_set);
	ac_free(&rs->ac);
	memset(rs, 0, sizeof(*rs));
}
