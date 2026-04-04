/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_dynbuf.h — Simple heap-backed dynamic string buffer
 *
 * Used by iptables-restore generators (firewall, NAT) to build
 * the restore script in memory before piping to the child process.
 */

#ifndef MGMTD_DYNBUF_H
#define MGMTD_DYNBUF_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct dynbuf {
	char   *data;
	size_t  used;
	size_t  size;
};

static inline int dbuf_init(struct dynbuf *b, size_t initial)
{
	b->data = malloc(initial);
	if (!b->data) return -1;
	b->used = 0;
	b->size = initial;
	b->data[0] = '\0';
	return 0;
}

static inline void dbuf_free(struct dynbuf *b)
{
	free(b->data);
	b->data = NULL;
	b->used = 0;
	b->size = 0;
}

static inline int dbuf_append(struct dynbuf *b, const char *s, size_t len)
{
	while (b->used + len + 1 > b->size) {
		size_t newsz = b->size * 2;
		char *nb = realloc(b->data, newsz);
		if (!nb) return -1;
		b->data = nb;
		b->size = newsz;
	}
	memcpy(b->data + b->used, s, len);
	b->used += len;
	b->data[b->used] = '\0';
	return 0;
}

__attribute__((format(printf, 2, 3)))
static inline int dbuf_printf(struct dynbuf *b, const char *fmt, ...)
{
	char tmp[512];
	va_list ap;
	va_start(ap, fmt);
	int len = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	if (len < 0) return -1;
	return dbuf_append(b, tmp, (size_t)len);
}

#endif /* MGMTD_DYNBUF_H */
