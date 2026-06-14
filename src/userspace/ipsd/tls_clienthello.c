/* SPDX-License-Identifier: MIT */
/*
 * tls_clienthello.c - Parse SNI từ TLS ClientHello (xem tls_clienthello.h).
 *
 * Cấu trúc đi qua (mọi độ dài là big-endian, RFC 8446 §4.1.2 + RFC 6066 §3):
 *
 *   TLS record:
 *     [0]      content_type   (22 = handshake)
 *     [1..2]   legacy_version
 *     [3..4]   record_length
 *   Handshake (trong record):
 *     [0]      msg_type       (1 = ClientHello)
 *     [1..3]   length (3 byte)
 *     [4..5]   client_version
 *     [6..37]  random (32 byte)
 *     [38]     session_id_len (1) + session_id
 *     [..]     cipher_suites: len(2) + data
 *     [..]     compression:   len(1) + data
 *     [..]     extensions:    len(2) + data
 *   Extension server_name (type 0x0000):
 *     server_name_list: list_len(2)
 *       entry: name_type(1, 0=host_name) + name_len(2) + name
 *
 * Nguyên tắc: mỗi lần đọc đều kiểm còn đủ byte trong CẢ buffer thật LẪN khung
 * độ dài khai báo. Thiếu byte buffer → NEED_MORE. Độ dài khai báo vượt khung
 * cha → MALFORMED. Không bao giờ đọc ngoài biên.
 */
#include "tls_clienthello.h"

#include <string.h>

#define TLS_CT_HANDSHAKE   22
#define TLS_HS_CLIENTHELLO  1
#define TLS_EXT_SERVER_NAME 0x0000
#define TLS_SNI_HOST_NAME   0x00

/*
 * Cursor đọc tuần tự với bounds-check. `lim` là biên trên hiện hành (có thể
 * hẹp hơn buffer thật khi đang ở trong một khung độ dài con). need_more cho
 * biết việc thiếu byte là do buffer cụt (true) hay do khung khai báo sai
 * (false) — quyết định NEED_MORE vs MALFORMED ở caller.
 */
struct cur {
	const uint8_t *p;
	size_t         off;
	size_t         lim;   /* không đọc tới/quá lim */
};

/* Còn đủ n byte trước lim? */
static int have(const struct cur *c, size_t n)
{
	return c->off + n <= c->lim;
}

static uint8_t rd8(struct cur *c)
{
	return c->p[c->off++];
}

static uint16_t rd16(struct cur *c)
{
	uint16_t v = (uint16_t)((c->p[c->off] << 8) | c->p[c->off + 1]);
	c->off += 2;
	return v;
}

static uint32_t rd24(struct cur *c)
{
	uint32_t v = (uint32_t)((c->p[c->off] << 16) |
				(c->p[c->off + 1] << 8) |
				 c->p[c->off + 2]);
	c->off += 3;
	return v;
}

/* Bỏ qua n byte (caller đã kiểm have()). */
static void skip(struct cur *c, size_t n)
{
	c->off += n;
}

/*
 * Tìm SNI host_name trong khối extensions [ext_off, ext_end).
 * Trả TLS_CH_OK (has_sni 0/1), hoặc TLS_CH_MALFORMED nếu độ dài lồng sai.
 * Thiếu byte trong khung extensions đã khai báo = MALFORMED (vì record_len
 * nói nó phải có đủ); thiếu byte buffer thật được caller chặn từ trước.
 */
static enum tls_ch_result parse_extensions(struct cur *c, size_t ext_end,
					   struct tls_clienthello *out)
{
	while (c->off < ext_end) {
		/* mỗi extension header = 4 byte */
		if (c->off + 4 > ext_end)
			return TLS_CH_MALFORMED;
		uint16_t etype = rd16(c);
		uint16_t elen  = rd16(c);
		if (c->off + elen > ext_end)
			return TLS_CH_MALFORMED;

		if (etype != TLS_EXT_SERVER_NAME) {
			skip(c, elen);
			continue;
		}

		/* --- server_name extension --- */
		size_t sn_end = c->off + elen;
		if (c->off + 2 > sn_end)
			return TLS_CH_MALFORMED;
		uint16_t list_len = rd16(c);
		if (c->off + list_len > sn_end)
			return TLS_CH_MALFORMED;
		size_t list_end = c->off + list_len;

		while (c->off < list_end) {
			if (c->off + 3 > list_end)
				return TLS_CH_MALFORMED;
			uint8_t  ntype = rd8(c);
			uint16_t nlen  = rd16(c);
			if (c->off + nlen > list_end)
				return TLS_CH_MALFORMED;

			if (ntype == TLS_SNI_HOST_NAME) {
				if (nlen == 0 || nlen >= TLS_SNI_MAX)
					return TLS_CH_MALFORMED;
				memcpy(out->sni, c->p + c->off, nlen);
				out->sni[nlen] = '\0';
				out->has_sni = 1;
				return TLS_CH_OK;   /* lấy host_name đầu tiên */
			}
			skip(c, nlen);
		}
		/* server_name có nhưng không có host_name entry */
		return TLS_CH_OK;
	}
	return TLS_CH_OK;   /* không có server_name extension */
}

enum tls_ch_result tls_parse_clienthello(const uint8_t *buf, size_t len,
					 struct tls_clienthello *out)
{
	if (!out)
		return TLS_CH_MALFORMED;
	memset(out, 0, sizeof(*out));
	if (!buf)
		return TLS_CH_NEED_MORE;

	struct cur c = { .p = buf, .off = 0, .lim = len };

	/* --- TLS record header (5 byte) --- */
	if (!have(&c, 5))
		return TLS_CH_NEED_MORE;
	uint8_t  ctype = rd8(&c);
	uint16_t rver  = rd16(&c);      /* legacy record version — chỉ tham khảo */
	uint16_t rlen  = rd16(&c);
	(void)rver;

	if (ctype != TLS_CT_HANDSHAKE)
		return TLS_CH_NOT_CH;
	if (rlen == 0)
		return TLS_CH_MALFORMED;
	out->record_len = rlen;

	/*
	 * Biên record: handshake phải nằm trọn trong rlen. Nếu buffer thật chưa
	 * đủ rlen → NEED_MORE. Nếu đủ → thu hẹp lim về cuối record để mọi độ dài
	 * con được kiểm theo khung record (chống khai man vượt record).
	 */
	if (!have(&c, rlen))
		return TLS_CH_NEED_MORE;
	size_t rec_end = c.off + rlen;
	c.lim = rec_end;

	/* --- Handshake header (4 byte) --- */
	if (!have(&c, 4))
		return TLS_CH_MALFORMED;
	uint8_t  htype = rd8(&c);
	uint32_t hlen  = rd24(&c);

	if (htype != TLS_HS_CLIENTHELLO)
		return TLS_CH_NOT_CH;
	if (c.off + hlen > rec_end)
		return TLS_CH_MALFORMED;
	/* thu hẹp tiếp về khung handshake */
	c.lim = c.off + hlen;

	/* client_version(2) + random(32) */
	if (!have(&c, 2 + 32))
		return TLS_CH_MALFORMED;
	out->legacy_version = rd16(&c);
	skip(&c, 32);

	/* session_id: len(1) + data */
	if (!have(&c, 1))
		return TLS_CH_MALFORMED;
	uint8_t sid_len = rd8(&c);
	if (!have(&c, sid_len))
		return TLS_CH_MALFORMED;
	skip(&c, sid_len);

	/* cipher_suites: len(2) + data */
	if (!have(&c, 2))
		return TLS_CH_MALFORMED;
	uint16_t cs_len = rd16(&c);
	if ((cs_len & 1) || !have(&c, cs_len))   /* phải là bội số 2 byte */
		return TLS_CH_MALFORMED;
	skip(&c, cs_len);

	/* compression_methods: len(1) + data */
	if (!have(&c, 1))
		return TLS_CH_MALFORMED;
	uint8_t comp_len = rd8(&c);
	if (!have(&c, comp_len))
		return TLS_CH_MALFORMED;
	skip(&c, comp_len);

	/*
	 * extensions: tùy chọn. Không còn byte = ClientHello không có extension
	 * (TLS 1.2 cũ) → OK, không SNI.
	 */
	if (c.off == c.lim)
		return TLS_CH_OK;
	if (!have(&c, 2))
		return TLS_CH_MALFORMED;
	uint16_t ext_len = rd16(&c);
	if (c.off + ext_len > c.lim)
		return TLS_CH_MALFORMED;

	return parse_extensions(&c, c.off + ext_len, out);
}

const char *tls_ch_result_str(enum tls_ch_result r)
{
	switch (r) {
	case TLS_CH_OK:        return "OK";
	case TLS_CH_NEED_MORE: return "NEED_MORE";
	case TLS_CH_NOT_CH:    return "NOT_CLIENTHELLO";
	case TLS_CH_MALFORMED: return "MALFORMED";
	}
	return "?";
}
