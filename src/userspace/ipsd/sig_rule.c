/* SPDX-License-Identifier: MIT */
/*
 * sig_rule.c - parser rule ET-OPEN-subset + khớp payload (xem sig_rule.h).
 */
#include "sig_rule.h"
#include "flow_rule.h"   /* struct flow_stats (dùng trong sig_flow_match) */

#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasecmp */
#include <ctype.h>
#include <stdio.h>

/* ---- tiện ích nhỏ -------------------------------------------------------- */
/*
Logic: Chuyển ký tự hex ('0'-'f') thành giá trị số (0-15)
*/
static int hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/*
 * Decode giá trị content kiểu Snort: đoạn ASCII xen kẽ |hh hh| (hex), và
 * \escape (\", \;, \\, \|...). Trả số byte, -1 nếu lỗi (|...| lệch cặp / hex sai).
 Logic: Giải mã chuỗi nội dung cua rules.
 */
static int decode_content(const char *s, uint8_t *out, int outcap)
{
	int n = 0, hex = 0;

	while (*s) {
		if (*s == '|') {                 /* bật/tắt chế độ hex */
			hex = !hex;
			s++;
		} else if (hex) {
			if (*s == ' ' || *s == '\t') { s++; continue; }
			int hi = hexval((unsigned char)s[0]);
			int lo = s[1] ? hexval((unsigned char)s[1]) : -1;
			if (hi < 0 || lo < 0) return -1;
			if (n < outcap) out[n++] = (uint8_t)(hi * 16 + lo);
			s += 2;
		} else if (*s == '\\' && s[1]) {  /* escape: lấy ký tự sau nguyên văn */
			s++;
			if (n < outcap) out[n++] = (uint8_t)*s;
			s++;
		} else {
			if (n < outcap) out[n++] = (uint8_t)*s;
			s++;
		}
	}
	return hex ? -1 : n;                      /* còn mở | → lỗi */
}

static int parse_proto(const char *s)
{
	if (!strcasecmp(s, "tcp"))  return SIG_PROTO_TCP;
	if (!strcasecmp(s, "udp"))  return SIG_PROTO_UDP;
	if (!strcasecmp(s, "icmp")) return SIG_PROTO_ICMP;
	return SIG_PROTO_ANY;                     /* "ip"/"any"/biến → any */
}

static int parse_action(const char *s)
{
	if (!strcasecmp(s, "drop") || !strcasecmp(s, "reject") ||
	    !strcasecmp(s, "sdrop"))
		return SIG_DROP;
	return SIG_ALERT;                         /* alert/log/pass… → alert */
}

/* Port chỉ nhận số đơn; "any"/biến `$..`/danh sách `[..]`/dải `a:b` → 0 (any). */
static uint16_t parse_port(const char *s)
{
	if (!s || !*s) return 0;
	for (const char *q = s; *q; q++)
		if (!isdigit((unsigned char)*q)) return 0;
	long v = atol(s);
	return (v > 0 && v < 65536) ? (uint16_t)v : 0;
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
		default: break;                   /* bỏ qua số 0-2 và modifier + ! * , */
		}
	}
	return f;
}

/* ---- parse options (...) ------------------------------------------------- */
/*
Nó quét chuỗi options, dùng các vòng lặp
         while để tách key-value dựa trên dấu : và ;. Sau đó, dựa vào key (như
         "content", "nocase", "sid"), nó điền dữ liệu vào struct sig_rule.
*/
static int parse_options(struct sig_rule *r, const char *p)
{
	int cur = -1;   /* content gần nhất, để gắn nocase/offset/depth */

	while (*p) {
		char key[24]; int k = 0;
		char val[SIG_CONTENT_MAX + 64]; int vlen = 0;

		while (*p == ' ' || *p == '\t' || *p == ';') p++;
		if (!*p) break;

		/* đọc keyword tới ':' hoặc ';' */
		while (*p && *p != ':' && *p != ';' && k < (int)sizeof(key) - 1) {
			if (*p == ' ' || *p == '\t') { p++; continue; }
			key[k++] = *p++;
		}
		key[k] = '\0';

		/* đọc value nếu có ':' */
		if (*p == ':') {
			p++;
			while (*p == ' ' || *p == '\t') p++;
			if (*p == '"') {              /* chuỗi: tới '"' chưa-escape */
				p++;
				while (*p && *p != '"') {
					if (*p == '\\' && p[1]) {  /* giữ nguyên cặp escape */
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
			} else {                      /* token tới ';' */
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
					cur = r->n_content++;
				}
			}
		} else if (!strcmp(key, "nocase")) {
			if (cur >= 0) r->content[cur].nocase = 1;
		} else if (!strcmp(key, "offset")) {
			if (cur >= 0) r->content[cur].offset = atoi(val);
		} else if (!strcmp(key, "depth")) {
			if (cur >= 0) r->content[cur].depth = atoi(val);
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
		}
		/* else: field chưa hỗ trợ → bỏ qua */
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
	return r;
}

int sig_parse_line(struct sig_ruleset *rs, const char *line)
{
	char buf[8192];
	const char *q = line;

	while (*q == ' ' || *q == '\t') q++;
	if (*q == '\0' || *q == '#' || *q == '\n')
		return 1;                                  /* rỗng / comment */

	snprintf(buf, sizeof(buf), "%s", q);

	char *lp = strchr(buf, '(');
	char *rp = strrchr(buf, ')');
	if (!lp || !rp || rp < lp)
		return -1;                                 /* thiếu (...) */
	*rp = '\0';
	*lp = '\0';
	const char *header  = buf;
	const char *options = lp + 1;

	char action[16], proto[16], sip[64], sport[40], dir[8], dip[64], dport[40];
	if (sscanf(header, "%15s %15s %63s %39s %7s %63s %39s",
		   action, proto, sip, sport, dir, dip, dport) != 7)
		return -1;                                 /* header lỗi */

	struct sig_rule *r = ruleset_new(rs);
	if (!r) return -1;
	r->action = parse_action(action);
	r->proto  = parse_proto(proto);
	r->dport  = parse_port(dport);

	if (parse_options(r, options) < 0) {
		/* dọn content đã cấp của rule lỗi, không commit */
		for (int i = 0; i < r->n_content; i++) free(r->content[i].data);
		memset(r, 0, sizeof(*r));
		return -1;
	}

	if (r->n_content == 0) {
		/* Rule không content → L1 flow-rule (proto/dport/flags).
		 * Lưu vào l1_rules thay vì bỏ qua — đây là output của rule_gen
		 * và rule scan/flood không cần payload. */
		if (rs->n_l1 == rs->cap_l1) {
			int nc = rs->cap_l1 ? rs->cap_l1 * 2 : 32;
			struct sig_flow_rule *p =
				realloc(rs->l1_rules, (size_t)nc * sizeof(*p));
			if (!p) { memset(r, 0, sizeof(*r)); return -1; }
			rs->l1_rules = p;
			rs->cap_l1   = nc;
		}
		struct sig_flow_rule *fr = &rs->l1_rules[rs->n_l1++];
		fr->sid       = r->sid;
		fr->rev       = r->rev;
		fr->action    = r->action;
		fr->proto     = (uint8_t)r->proto;
		fr->dport     = r->dport;
		fr->flags_set = r->flags_set;
		size_t mn = strlen(r->msg);
		if (mn >= sizeof(fr->msg)) mn = sizeof(fr->msg) - 1;
		memcpy(fr->msg, r->msg, mn);
		fr->msg[mn] = '\0';
		memset(r, 0, sizeof(*r));
		return 0;   /* nạp thành công vào L1 */
	}

	/* fast pattern = content DÀI NHẤT (chọn lọc tốt nhất) */
	r->fast = 0;
	for (int i = 1; i < r->n_content; i++)
		if (r->content[i].len > r->content[r->fast].len)
			r->fast = i;

	rs->n_rules++;
	return 0;
}

int sig_load_file(struct sig_ruleset *rs, const char *path,
		  struct sig_load_stats *st)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;

	char acc[8192]; size_t al = 0;
	char ln[4096];
	int added = 0;
	struct sig_load_stats s = { 0, 0, 0 };

	while (fgets(ln, sizeof(ln), f)) {
		size_t l = strlen(ln);
		while (l && (ln[l - 1] == '\n' || ln[l - 1] == '\r')) ln[--l] = '\0';

		int cont = (l && ln[l - 1] == '\\');       /* nối dòng */
		if (cont) ln[--l] = '\0';

		if (al + l < sizeof(acc)) { memcpy(acc + al, ln, l + 1); al += l; }
		if (cont) continue;

		int rc = sig_parse_line(rs, acc);
		if (rc == 0)       { added++; s.loaded++; }
		else if (rc == 1)  { s.skipped++; }
		else               { s.errors++; }
		al = 0; acc[0] = '\0';
	}
	fclose(f);
	if (st) *st = s;
	return added;
}

int sig_build(struct sig_ruleset *rs)
{
	/* AC dùng nocase=1 làm PREFILTER cho mọi rule; tính đúng hoa/thường để
	 * bước verify (theo nocase từng content) lo — fast pattern chỉ để lọc. */
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
	rs->built = 1;
	return 0;
}

/* ---- khớp ---------------------------------------------------------------- */

/* tìm needle trong hay[from .. to) ; trả index bắt đầu hoặc -1 */
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

/* Verify đầy đủ một rule trên payload. 1 = khớp, 0 = không. */
static int verify_rule(const struct sig_rule *r, const uint8_t *p, int len,
		       const struct flow_ctx *fc)
{
	if (r->proto != SIG_PROTO_ANY && fc->proto != r->proto) return 0;
	if (r->dport != 0 && fc->dport != r->dport)             return 0;
	if (r->flags_set && (fc->tcp_flags & r->flags_set) != r->flags_set) return 0;

	int pos = 0;                                    /* ép thứ tự content */
	for (int i = 0; i < r->n_content; i++) {
		const struct sig_content *c = &r->content[i];
		int base = (c->offset >= 0) ? c->offset : 0;
		int lo   = base > pos ? base : pos;
		int hi   = (c->depth >= 0) ? base + c->depth : len;
		if (hi > len) hi = len;

		int s = mem_find(p, c->data, c->len, c->nocase, lo, hi);
		if (s < 0) return 0;
		pos = s + c->len;
	}
	return 1;
}

struct match_ctx {
	const struct sig_ruleset *rs;
	const uint8_t *payload;
	int            len;
	const struct flow_ctx *fc;
	int            best;          /* index rule */
	int            best_action;
};

static int on_fast_hit(int rule_idx, size_t end_pos, void *ctx)
{
	struct match_ctx *m = ctx;
	const struct sig_rule *r = &m->rs->rules[rule_idx];
	(void)end_pos;

	if (!verify_rule(r, m->payload, m->len, m->fc))
		return 0;                                /* prefilter trúng nhưng verify trượt */

	if (r->action > m->best_action) {
		m->best_action = r->action;
		m->best        = rule_idx;
	}
	return m->best_action == SIG_DROP ? 1 : 0;       /* có DROP → dừng sớm */
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

int sig_flow_match(const struct sig_ruleset *rs, const struct flow_ctx *fc,
		   const struct flow_stats *fs)
{
	if (!rs || !fc || !fs)
		return -1;

	int best = -1, best_action = -1;

	for (int i = 0; i < rs->n_l1; i++) {
		const struct sig_flow_rule *r = &rs->l1_rules[i];

		if (r->proto != SIG_PROTO_ANY && (uint8_t)fc->proto != r->proto)
			continue;
		if (r->dport != 0 && fc->dport != r->dport)
			continue;
		/* flags_set: kiểm trên tcp_flags_fwd tích lũy (có gói nào set không?) */
		if (r->flags_set &&
		    (fs->tcp_flags_fwd & r->flags_set) != r->flags_set)
			continue;

		if (r->action > best_action) {
			best_action = r->action;
			best = i;
		}
		if (best_action == SIG_DROP)
			break;
	}
	return best;
}

void sig_ruleset_free(struct sig_ruleset *rs)
{
	for (int i = 0; i < rs->n_rules; i++)
		for (int j = 0; j < rs->rules[i].n_content; j++)
			free(rs->rules[i].content[j].data);
	free(rs->rules);
	free(rs->l1_rules);
	ac_free(&rs->ac);
	memset(rs, 0, sizeof(*rs));
}
