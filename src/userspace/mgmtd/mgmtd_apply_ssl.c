/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_ssl.c — Steering traffic HTTPS vào stargazer-ssld (SSL inspection)
 *
 * Khi config `security_ssl-inspection` bật, ta REDIRECT các flow TLS được
 * forward vào cổng nghe của ssld bằng một luật trong *nat PREROUTING:
 *
 *   -A PREROUTING -i <srcintf> -p tcp --dport 443 -j REDIRECT --to-ports 8443
 *
 * CHỐNG LOOP — vì sao KHÔNG cần `-m owner` ở đây:
 *   Kết nối ssld mở RA server thật là traffic do CHÍNH firewall sinh ra
 *   (local-out) → đi qua chain OUTPUT, KHÔNG quay lại PREROUTING. Vì vậy luật
 *   REDIRECT ở PREROUTING không bao giờ bắt lại traffic của ssld → không loop.
 *   Cơ chế giới hạn đúng là SCOPE THEO INTERFACE NỘI BỘ (`-i srcintf`): chỉ
 *   redirect traffic ĐẾN TỪ vùng LAN, không đụng traffic box tự sinh, không
 *   đụng traffic vào từ WAN. (`-m owner` chỉ hợp lệ ở OUTPUT/POSTROUTING, đặt
 *   vào PREROUTING sẽ lỗi — nên tuyệt đối không dùng ở đây.)
 *
 * Luật này được nhúng vào *nat restore của rebuild_nat_chains() để cả bảng nat
 * là một lần restore nguyên tử (không xung đột flush với DNAT/SNAT của user).
 *
 * Fail-safe: thiếu config / disabled / input bẩn → KHÔNG emit luật → traffic
 * đi bình thường (không chặn). SSL inspection là tùy chọn, off-by-default.
 */

#include "mgmtd_apply.h"
#include "mgmtd_dynbuf.h"
#include "sg_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SSL_CFG_TYPE   "security_ssl-inspection"
#define SSL_CFG_ID     "default"
#define SSL_DEF_PORTS  "443"
#define SSL_DEF_LISTEN "8443"

/* Chỉ chấp nhận danh sách cổng dạng "443" hoặc "443,8443" (số + dấu phẩy),
 * mỗi cổng 1..65535. Chặn injection vào input iptables-restore. */
static int valid_port_list(const char *s)
{
	if (!s || !*s)
		return 0;
	int val = 0, ndigit = 0, nport = 0;
	for (const char *p = s;; p++) {
		if (*p >= '0' && *p <= '9') {
			val = val * 10 + (*p - '0');
			if (++ndigit > 5 || val > 65535)
				return 0;
		} else if (*p == ',' || *p == '\0') {
			if (ndigit == 0 || val < 1)
				return 0;
			nport++;
			if (*p == '\0')
				break;
			val = 0; ndigit = 0;
		} else {
			return 0;             /* ký tự lạ */
		}
	}
	return nport > 0;
}

/* Cổng nghe đơn 1..65535. */
static int valid_single_port(const char *s)
{
	if (!s || !*s)
		return 0;
	int val = 0, n = 0;
	for (const char *p = s; *p; p++) {
		if (*p < '0' || *p > '9')
			return 0;
		val = val * 10 + (*p - '0');
		if (++n > 5 || val > 65535)
			return 0;
	}
	return val >= 1;
}

/* Tên interface an toàn cho iptables (chữ/số . _ - @, độ dài hợp lý). */
static int valid_ifname(const char *s)
{
	if (!s || !*s || strlen(s) > 31)
		return 0;
	for (const char *p = s; *p; p++) {
		char c = *p;
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') ||
		      c == '.' || c == '_' || c == '-' || c == '@'))
			return 0;
	}
	return 1;
}

static int is_any(const char *s)
{
	return !s || !*s || !strcmp(s, "any") || !strcmp(s, "all");
}

int emit_ssl_steering(struct dynbuf *buf)
{
	char *status = sg_db_get_val(SSL_CFG_TYPE, SSL_CFG_ID, "status");
	int on = status && strcmp(status, "enable") == 0;
	free(status);
	if (!on)
		return 0;                       /* tắt / chưa cấu hình */

	char *ports   = sg_db_get_val(SSL_CFG_TYPE, SSL_CFG_ID, "ports");
	char *listen  = sg_db_get_val(SSL_CFG_TYPE, SSL_CFG_ID, "listen-port");
	char *srcintf = sg_db_get_val(SSL_CFG_TYPE, SSL_CFG_ID, "srcintf");

	const char *p_ports  = (ports  && *ports)  ? ports  : SSL_DEF_PORTS;
	const char *p_listen = (listen && *listen) ? listen : SSL_DEF_LISTEN;

	int rc = -1;

	/* Defensive: dù config đã được validate lúc set, vẫn kiểm lại trước khi
	 * ghép vào input iptables-restore (fail-safe nếu DB bị sửa tay). */
	if (!valid_port_list(p_ports) || !valid_single_port(p_listen)) {
		mgmt_log("ERROR", "emit_ssl_steering: ports/listen-port không hợp lệ "
			 "(ports='%s' listen='%s') — bỏ qua steering", p_ports, p_listen);
		goto done;
	}
	if (!is_any(srcintf) && !valid_ifname(srcintf)) {
		mgmt_log("ERROR", "emit_ssl_steering: srcintf '%s' không hợp lệ — "
			 "bỏ qua steering", srcintf);
		goto done;
	}

	dbuf_printf(buf, "-A PREROUTING");
	if (!is_any(srcintf))
		dbuf_printf(buf, " -i %s", srcintf);
	else
		mgmt_log("INFO", "emit_ssl_steering: srcintf không đặt — redirect "
			 "MỌI interface (khuyến nghị đặt interface LAN)");

	dbuf_printf(buf, " -p tcp");
	if (strchr(p_ports, ','))
		dbuf_printf(buf, " -m multiport --dports %s", p_ports);
	else
		dbuf_printf(buf, " --dport %s", p_ports);

	dbuf_printf(buf, " -j REDIRECT --to-ports %s\n", p_listen);

	mgmt_log("INFO", "SSL inspection steering: -i %s tcp dports %s -> :%s",
		 is_any(srcintf) ? "any" : srcintf, p_ports, p_listen);
	rc = 1;

done:
	free(ports);
	free(listen);
	free(srcintf);
	return rc;
}

/* ── Validation cho CFG_SET ─────────────────────────────────────────────── */

sg_status_t validate_ssl_inspection(const char *id, const char *data,
				    char *result, size_t rsize)
{
	(void)id;
	char status[VALBUFSZ], ports[VALBUFSZ], listen[VALBUFSZ], srcintf[VALBUFSZ];
	extract_val(data, "status",      status,  sizeof(status));
	extract_val(data, "ports",       ports,   sizeof(ports));
	extract_val(data, "listen-port", listen,  sizeof(listen));
	extract_val(data, "srcintf",     srcintf, sizeof(srcintf));

	if (status[0] && strcmp(status, "enable") && strcmp(status, "disable")) {
		snprintf(result, rsize, "status phải là enable/disable");
		return SG_ERR_INVALID_VAL;
	}
	if (ports[0] && !valid_port_list(ports)) {
		snprintf(result, rsize, "ports không hợp lệ '%s' (vd 443 hoặc 443,8443)",
			 ports);
		return SG_ERR_INVALID_VAL;
	}
	if (listen[0] && !valid_single_port(listen)) {
		snprintf(result, rsize, "listen-port không hợp lệ '%s'", listen);
		return SG_ERR_INVALID_VAL;
	}
	if (srcintf[0] && !is_any(srcintf) && !valid_ifname(srcintf)) {
		snprintf(result, rsize, "srcintf không hợp lệ '%s'", srcintf);
		return SG_ERR_INVALID_VAL;
	}
	snprintf(result, rsize, "SSL inspection config hợp lệ");
	return SG_OK;
}
