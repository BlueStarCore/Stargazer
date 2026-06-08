/* SPDX-License-Identifier: MIT */
/*
 * rule_gen.c - Rule Generation Unit (xem rule_gen.h).
 */
#include "rule_gen.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>   /* IPPROTO_* */

/* ---- ánh xạ proto <-> tên ------------------------------------------------ */

static const char *proto_name(uint8_t p)
{
	switch (p) {
	case IPPROTO_TCP:  return "tcp";
	case IPPROTO_UDP:  return "udp";
	case IPPROTO_ICMP: return "icmp";
	default:           return "ip";
	}
}

static uint8_t proto_num(const char *s)
{
	if (!strcmp(s, "tcp"))  return IPPROTO_TCP;
	if (!strcmp(s, "udp"))  return IPPROTO_UDP;
	if (!strcmp(s, "icmp")) return IPPROTO_ICMP;
	return 0;
}

/* Bit cờ TCP → chữ cái Snort (thứ tự F S R P A U). */
static void flags_to_str(uint8_t f, char *out, size_t n)
{
	size_t k = 0;
	const struct { uint8_t bit; char ch; } map[] = {
		{ SIG_TCP_FIN, 'F' }, { SIG_TCP_SYN, 'S' }, { SIG_TCP_RST, 'R' },
		{ SIG_TCP_PSH, 'P' }, { SIG_TCP_ACK, 'A' }, { SIG_TCP_URG, 'U' },
	};
	for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++)
		if ((f & map[i].bit) && k + 1 < n)
			out[k++] = map[i].ch;
	out[k] = '\0';
}

static uint8_t str_to_flags(const char *s)
{
	uint8_t f = 0;
	for (; *s && *s != ';' && *s != '"'; s++) {
		switch (*s) {
		case 'F': f |= SIG_TCP_FIN; break;
		case 'S': f |= SIG_TCP_SYN; break;
		case 'R': f |= SIG_TCP_RST; break;
		case 'P': f |= SIG_TCP_PSH; break;
		case 'A': f |= SIG_TCP_ACK; break;
		case 'U': f |= SIG_TCP_URG; break;
		default: break;
		}
	}
	return f;
}

/* ---- dựng dòng rule Snort ------------------------------------------------ */

/* Trả độ dài viết được (>0) hoặc -1 nếu tràn buffer. */
static int build_rule(char *buf, size_t n, uint8_t proto, uint16_t dport,
		      uint8_t flags, double score, uint32_t sid)
{
	const char *pr = proto_name(proto);
	int has_port = (proto == IPPROTO_TCP || proto == IPPROTO_UDP) && dport > 0;
	char portbuf[8];
	char fl[8];
	char flagopt[24];
	int  r;

	if (has_port)
		snprintf(portbuf, sizeof(portbuf), "%u", dport);
	else
		snprintf(portbuf, sizeof(portbuf), "any");

	flags_to_str(flags, fl, sizeof(fl));

	/* tuỳ chọn flags: chỉ thêm cho TCP và khi có cờ */
	if (proto == IPPROTO_TCP && flags)
		snprintf(flagopt, sizeof(flagopt), " flags:%s;", fl);
	else
		flagopt[0] = '\0';

	r = snprintf(buf, n,
		"alert %s any any -> any %s "
		"(msg:\"AUTO: proto=%s dport=%s flags=%s score=%.2f\";%s sid:%u; rev:1;)",
		pr, portbuf, pr, portbuf, fl[0] ? fl : "-", score, flagopt, sid);

	return (r > 0 && (size_t)r < n) ? r : -1;
}

/* ---- bảng tần suất (mảng kết hợp nhỏ, ≤256) ------------------------------ */

static struct rule_gen_entry *lookup(struct rule_gen_ctx *ctx, uint8_t proto,
				     uint16_t dport, uint8_t flags)
{
	for (int i = 0; i < RULE_GEN_TABLE_SZ; i++) {
		struct rule_gen_entry *e = &ctx->table[i];
		if (e->used && e->proto == proto && e->dport == dport &&
		    e->flags_set == flags)
			return e;
	}
	return NULL;
}

/* Tìm hoặc chèn entry cho bộ khoá; đầy thì thay slot ít dùng nhất (LRU). */
static struct rule_gen_entry *find_or_insert(struct rule_gen_ctx *ctx,
					     uint8_t proto, uint16_t dport,
					     uint8_t flags)
{
	struct rule_gen_entry *e = lookup(ctx, proto, dport, flags);
	int      lru = 0;
	time_t   lru_t;

	if (e)
		return e;

	for (int i = 0; i < RULE_GEN_TABLE_SZ; i++)
		if (!ctx->table[i].used) {        /* còn slot trống */
			e = &ctx->table[i];
			goto claim;
		}

	/* đầy → thay slot last_seen nhỏ nhất */
	lru_t = ctx->table[0].last_seen;
	for (int i = 1; i < RULE_GEN_TABLE_SZ; i++)
		if (ctx->table[i].last_seen < lru_t) {
			lru_t = ctx->table[i].last_seen;
			lru = i;
		}
	e = &ctx->table[lru];
claim:
	memset(e, 0, sizeof(*e));
	e->used = 1;
	e->proto = proto;
	e->dport = dport;
	e->flags_set = flags;
	return e;
}

/* ---- API ----------------------------------------------------------------- */

void rule_gen_init(struct rule_gen_ctx *ctx, uint32_t min_support,
		   double score_threshold, uint32_t sid_start)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->min_support     = min_support ? min_support : 3;
	ctx->score_threshold = score_threshold;
	ctx->sid_counter     = sid_start ? sid_start : RULE_GEN_SID_BASE;
	pthread_mutex_init(&ctx->lock, NULL);
}

int rule_gen_feed(struct rule_gen_ctx *ctx, const struct rule_gen_input *in,
		  struct sig_ruleset *rs)
{
	int emitted = 0;

	/* Chuẩn hoá khoá: port chỉ có nghĩa với TCP/UDP; cờ chỉ với TCP. */
	uint8_t  proto = in->proto;
	uint16_t dport = (proto == IPPROTO_TCP || proto == IPPROTO_UDP) ? in->dport : 0;
	uint8_t  flags = (proto == IPPROTO_TCP) ? in->tcp_flags : 0;

	pthread_mutex_lock(&ctx->lock);

	struct rule_gen_entry *e = find_or_insert(ctx, proto, dport, flags);
	if (e->count != UINT32_MAX)
		e->count++;
	e->last_seen = time(NULL);

	if (!e->rule_emitted &&
	    in->ml_score >= ctx->score_threshold &&
	    e->count >= ctx->min_support) {
		uint32_t sid = ctx->sid_counter++;   /* dưới lock → an toàn */

		if (build_rule(e->rule, sizeof(e->rule), proto, dport, flags,
			       in->ml_score, sid) > 0) {
			e->rule_emitted = 1;
			e->sid = sid;
			ctx->rules_emitted++;
			emitted = 1;
			/* hook nạp vào ruleset sống (best-effort; rule không content
			 * hiện bị sig_parse_line bỏ qua — xem ghi chú ở header). */
			if (rs)
				sig_parse_line(rs, e->rule);
		} else {
			/* tràn buffer (không nên xảy ra) → trả SID lại, không sinh */
			ctx->sid_counter--;
		}
	}

	pthread_mutex_unlock(&ctx->lock);
	return emitted;
}

int rule_gen_save(const struct rule_gen_ctx *ctx, const char *path)
{
	/* ctx const nhưng vẫn cần khoá để chụp nhất quán — bỏ const nội bộ. */
	struct rule_gen_ctx *c = (struct rule_gen_ctx *)ctx;
	FILE *f;

	pthread_mutex_lock(&c->lock);
	f = fopen(path, "w");
	if (!f) {
		pthread_mutex_unlock(&c->lock);
		return -1;
	}
	fprintf(f, "# Stargazer IPS - auto-generated rules (do not edit by hand)\n");
	for (int i = 0; i < RULE_GEN_TABLE_SZ; i++) {
		const struct rule_gen_entry *e = &c->table[i];
		if (e->used && e->rule_emitted && e->rule[0])
			fprintf(f, "%s\n", e->rule);
	}
	fclose(f);
	pthread_mutex_unlock(&c->lock);
	return 0;
}

/* Trích proto/dport/flags/sid từ một dòng rule (định dạng do ta sinh). */
static int parse_saved(const char *line, uint8_t *proto, uint16_t *dport,
		       uint8_t *flags, uint32_t *sid)
{
	char a[16], pr[16], s1[32], s2[32], dir[8], d1[32], dp[40];
	const char *p;

	if (sscanf(line, "%15s %15s %31s %31s %7s %31s %39s",
		   a, pr, s1, s2, dir, d1, dp) != 7)
		return -1;

	*proto = proto_num(pr);
	*dport = isdigit((unsigned char)dp[0]) ? (uint16_t)atoi(dp) : 0;

	*flags = 0;
	p = strstr(line, "flags:");
	if (p)
		*flags = str_to_flags(p + 6);

	p = strstr(line, "sid:");
	*sid = p ? (uint32_t)strtoul(p + 4, NULL, 10) : 0;
	return 0;
}

int rule_gen_load(struct rule_gen_ctx *ctx, struct sig_ruleset *rs,
		  const char *path)
{
	FILE *f = fopen(path, "r");
	char  line[RULE_GEN_RULE_MAX + 64];
	int   loaded = 0;

	if (!f)
		return (errno == ENOENT) ? 0 : -1;

	pthread_mutex_lock(&ctx->lock);
	while (fgets(line, sizeof(line), f)) {
		uint8_t  proto, flags;
		uint16_t dport;
		uint32_t sid;
		size_t   l = strlen(line);

		while (l && (line[l - 1] == '\n' || line[l - 1] == '\r'))
			line[--l] = '\0';
		if (l == 0 || line[0] == '#')
			continue;
		if (parse_saved(line, &proto, &dport, &flags, &sid) != 0)
			continue;

		struct rule_gen_entry *e = find_or_insert(ctx, proto, dport, flags);
		e->count        = ctx->min_support;  /* coi như đã đủ support */
		e->rule_emitted = 1;
		e->sid          = sid;
		e->last_seen    = time(NULL);
		snprintf(e->rule, sizeof(e->rule), "%s", line);
		ctx->rules_emitted++;
		if (sid >= ctx->sid_counter)         /* tránh tái dùng SID */
			ctx->sid_counter = sid + 1;
		loaded++;
		if (rs)
			sig_parse_line(rs, line);
	}
	pthread_mutex_unlock(&ctx->lock);
	fclose(f);
	return loaded;
}

void rule_gen_free(struct rule_gen_ctx *ctx)
{
	pthread_mutex_destroy(&ctx->lock);
	memset(ctx, 0, sizeof(*ctx));
}
