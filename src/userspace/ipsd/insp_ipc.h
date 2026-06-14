/* SPDX-License-Identifier: MIT */
/*
 * insp_ipc.h — Phase 4: kênh IPC inspection (ipsd server ⇄ ssld client).
 *
 * ssld giải mã HTTPS rồi đẩy plaintext qua đây để CHÍNH engine stateful của
 * ipsd (reass + Aho-Corasick streaming + verify + flowbits) soi — thay cho việc
 * ssld tự gọi sig_match per-chunk. Bắt được pattern vắt qua nhiều TLS record.
 *
 * ADDITIVE + GATED: chạy trong thread riêng, KHÔNG đụng NFQUEUE main loop hay
 * struct CTA_ML. Tắt SSL inspection → ssld không chạy → server im.
 *
 * Vận tải: AF_UNIX SOCK_SEQPACKET tại INSP_SOCK_PATH — mỗi message = 1 datagram.
 * Một socket cho mỗi kết nối proxy của ssld (handler thread sở hữu riêng flow).
 */
#ifndef SG_IPSD_INSP_IPC_H
#define SG_IPSD_INSP_IPC_H

#include <stdint.h>

struct sig_reload;
struct ips_config;

#define INSP_SOCK_PATH   "/run/stargazer-ipsd-insp.sock"
#define INSP_MAX_PLAIN   16384      /* = REASS_MAX_BYTES: chunk plaintext tối đa */

/* loại message */
enum {
	INSP_OPEN    = 1,   /* ssld → ipsd: bắt đầu 1 flow HTTPS */
	INSP_DATA    = 2,   /* ssld → ipsd: 1 chunk plaintext (kèm theo sau header) */
	INSP_CLOSE   = 3,   /* ssld → ipsd: kết thúc flow */
	INSP_VERDICT = 128, /* ipsd → ssld: verdict cho 1 chunk */
};

/* verdict.action */
enum { INSP_PASS = 0, INSP_ALERT = 1, INSP_DROP = 2 };

struct insp_hdr {
	uint16_t type;       /* INSP_* */
	uint16_t flags;
	uint32_t conn_id;    /* tham chiếu (1 socket/flow nên không bắt buộc) */
};

struct insp_open_body {
	uint32_t srv_ip;     /* đích thật (network order) — log */
	uint16_t srv_port;   /* → fc.dport */
	uint8_t  profile_id; /* → fc.prof_id (0 = áp mọi rule) */
	uint8_t  _pad;
	char     sni[256];   /* host cho log */
	/* Phase 2 — leg client→ssld để ipsd đọc CTA_ML (ML cho HTTPS). Host order
	 * cho cli_port/fw_port; ip network order. ssld lấy bằng getpeername (client)
	 * + getsockname (fw, sau REDIRECT). 0 = không có (ML không chấm). */
	uint32_t leg_cli_ip;
	uint32_t leg_fw_ip;
	uint16_t leg_cli_port;
	uint16_t leg_fw_port;
};

struct insp_data_body {       /* theo sau là `len` byte plaintext trong cùng datagram */
	uint8_t  dir;        /* 0=to_server, 1=to_client */
	uint8_t  _pad[3];
	uint32_t chunk_id;
	uint32_t len;
};

struct insp_verdict_body {
	uint32_t chunk_id;
	uint8_t  action;     /* INSP_PASS / INSP_ALERT / INSP_DROP */
	uint8_t  src;        /* 0 = signature (ML để Pha 2) */
	uint8_t  _pad[2];
	float    score;
	uint32_t sid;
	char     msg[128];
};

/*
 * Khởi động IPC inspection server (tạo acceptor thread; mỗi kết nối → 1 handler
 * thread sở hữu insp_flow riêng, rdlock(ruleset) khi soi — dùng chung an toàn
 * với NFQUEUE). Trả 0 nếu OK, -1 nếu lỗi (caller log + chạy tiếp không IPC).
 */
int insp_ipc_start(struct sig_reload *sr, const struct ips_config *cfg);

#endif /* SG_IPSD_INSP_IPC_H */
