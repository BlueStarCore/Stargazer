/* SPDX-License-Identifier: MIT */
/*
 * nfq.h - NFQUEUE I/O cho stargazer-ipsd (raw AF_NETLINK, không libnetfilter_queue).
 *
 * ipsd nhận gói từ kernel qua NFQUEUE (kernel queue N gói đầu của mỗi flow),
 * parse IP/TCP/UDP header để lấy tuple + payload + TCP window (feature #13),
 * rồi trả verdict ACCEPT/DROP kèm set connmark cho flow đó.
 *
 * Connmark bits dùng cho IPS (không đụng SG_CMK_DIRTY bit0 của mgmtd):
 *   SG_CMK_IPS_BLOCK     (bit 1) → mọi gói sau DROP
 *   SG_CMK_IPS_INSPECTED (bit 2) → offload, khỏi queue
 *
 * Connmark được set qua NFQA_CT → CTA_MARK trong message verdict
 * (Linux ≥ 3.16: kernel cập nhật conntrack mark từ verdict).
 *
 * Iptables rules (do mgmtd thêm khi IPS bật, per-policy):
 *   <match> -m connmark --mark 0x2/0x2 -j DROP   (flow đã kết án)
 *   <match> -m connbytes --connbytes-dir both --connbytes-mode bytes \
 *           --connbytes 0:K -m connmark ! --mark 0x4/0x4 \
 *           -j NFQUEUE --queue-num Q   (P1: soi K byte đầu, 2 chiều)
 */
#ifndef SG_NFQ_H
#define SG_NFQ_H

#include <stdint.h>
#include "sig_rule.h"   /* SIG_TCP_*, SIG_PROTO_*, struct flow_ctx */

/* ---- connmark bits IPS (tách rời DIRTY bit0 + policy_id bit8-31 của mgmtd) -- */
#define SG_CMK_IPS_BLOCK       0x00000002u   /* bit 1 — flow kết án → DROP       */
#define SG_CMK_IPS_INSPECTED   0x00000004u   /* bit 2 — soi xong → offload       */
#define SG_CMK_IPS_WATCH       0x00000008u   /* bit 3 — giữ soi quá K (keep-alive)*/
#define SG_CMK_IPS_MASK        0x0000000Eu   /* bit 1-3                          */

/* ---- context NFQUEUE ------------------------------------------------------ */
struct nfq_ctx {
	int      fd;           /* AF_NETLINK socket */
	uint16_t queue_num;
	uint32_t portid;       /* netlink port ID của process */
};

/* ---- thông tin gói từ NFQUEUE --------------------------------------------- */
#define NFQ_RAW_MAX 65536

struct nfq_pkt {
	/* NFQUEUE packet ID (cần cho verdict) */
	uint32_t  id;

	/* tuple (host byte order) */
	uint8_t   proto;        /* IPPROTO_TCP / UDP / ICMP / other */
	uint32_t  src_ip;
	uint32_t  dst_ip;
	uint16_t  sport;
	uint16_t  dport;

	/* TCP cờ của GÓI NÀY (không phải tích lũy) */
	uint8_t   tcp_flags;    /* SIG_TCP_* */

	/* TCP seq của byte payload đầu (host order) — đặt segment vào reass (P1) */
	uint32_t  tcp_seq;

	/* TCP window của gói SYN forward (feature #13); -1 nếu không phải SYN */
	int32_t   init_win;

	/* L4 payload (trỏ vào raw_buf) */
	const uint8_t *payload;
	uint16_t       plen;

	/* raw IP packet từ NFQA_PAYLOAD */
	uint8_t   raw_buf[NFQ_RAW_MAX];
	uint16_t  raw_len;
};

/* ---- API ------------------------------------------------------------------ */

/*
 * Mở NFQUEUE: tạo socket, bind, PF_BIND, queue BIND + COPY_PACKET +
 * CONNTRACK flag. Trả 0/-1.
 */
int  nfq_open(struct nfq_ctx *ctx, uint16_t queue_num);

/*
 * Parse raw IP packet data[0..len) vào *pkt.
 * THUẦN HÀM — không I/O, testable trên host.
 * Trả 0 nếu OK, -1 nếu header lỗi/quá ngắn.
 */
int  nfq_parse_packet(const uint8_t *data, uint16_t len, struct nfq_pkt *pkt);

/*
 * Nhận một gói từ NFQUEUE, gọi nfq_parse_packet(). Block cho đến khi có gói.
 * Trả 0 nếu có gói hợp lệ, -1 nếu lỗi (EINTR = bình thường, thử lại).
 */
int  nfq_recv(struct nfq_ctx *ctx, struct nfq_pkt *pkt);

/*
 * Gửi verdict cho gói `id`. `accept` = 1 → NF_ACCEPT; 0 → NF_DROP.
 * `connmark` = giá trị set vào connmark của flow (0 = không set).
 * `connmark_mask` = mask cho CTA_MARK (chỉ các bit trong mask mới bị sửa).
 * Trả 0/-1.
 */
int  nfq_verdict(struct nfq_ctx *ctx, uint32_t id, int accept,
		 uint32_t connmark, uint32_t connmark_mask);

/* Đóng socket, giải phóng ctx. */
void nfq_close(struct nfq_ctx *ctx);

/* flow_ctx từ nfq_pkt (để truyền vào ips_evaluate). */
static inline void nfq_pkt_to_flow_ctx(const struct nfq_pkt *p,
					struct flow_ctx *fc)
{
	fc->proto     = (uint8_t)(p->proto == 6 ? SIG_PROTO_TCP :
				  p->proto == 17 ? SIG_PROTO_UDP :
				  p->proto == 1  ? SIG_PROTO_ICMP :
				  SIG_PROTO_ANY);
	fc->dport     = p->dport;
	fc->tcp_flags = p->tcp_flags;
	fc->established = 0;   /* P6 — caller (main.c) đặt lại từ conntrack/dir */
	fc->to_server   = 1;
	fc->fb          = NULL; /* P5 — chỉ flow TCP có pool mới track cờ */
	fc->bufs        = NULL; /* P6 — caller trích vùng cho TCP đã ghép */
}

#endif /* SG_NFQ_H */
