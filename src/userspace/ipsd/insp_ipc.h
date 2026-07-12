/* SPDX-License-Identifier: MIT */
/*
 * insp_ipc.h — Phase 4: inspection IPC channel (ipsd server ⇄ ssld client).
 *
 * ssld decrypts HTTPS then pushes plaintext here so that ipsd's OWN stateful
 * engine (reass + Aho-Corasick streaming + verify + flowbits) inspects it —
 * instead of ssld calling sig_match per-chunk itself. Catches patterns spanning
 * multiple TLS records.
 *
 * ADDITIVE + GATED: runs in its own thread, does NOT touch the NFQUEUE main loop
 * or the CTA_ML struct. Disable SSL inspection → ssld does not run → server idle.
 *
 * Transport: AF_UNIX SOCK_SEQPACKET at INSP_SOCK_PATH — each message = 1 datagram.
 * One socket per ssld proxy connection (handler thread owns its own flow).
 */
#ifndef SG_IPSD_INSP_IPC_H
#define SG_IPSD_INSP_IPC_H

#include <stdint.h>

struct sig_reload;
struct ips_config;

#define INSP_SOCK_PATH   "/run/stargazer-ipsd-insp.sock"
#define INSP_MAX_PLAIN   16384      /* = REASS_MAX_BYTES: max plaintext chunk */

/* message type */
enum {
	INSP_OPEN    = 1,   /* ssld → ipsd: start an HTTPS flow */
	INSP_DATA    = 2,   /* ssld → ipsd: one plaintext chunk (follows the header) */
	INSP_CLOSE   = 3,   /* ssld → ipsd: end of flow */
	INSP_SCORE   = 4,   /* ssld → ipsd: ML-only (cert mode, no plaintext) → verdict */
	INSP_VERDICT = 128, /* ipsd → ssld: verdict for one chunk / score */
};

/* verdict.action */
enum { INSP_PASS = 0, INSP_ALERT = 1, INSP_DROP = 2 };

struct insp_hdr {
	uint16_t type;       /* INSP_* */
	uint16_t flags;
	uint32_t conn_id;    /* reference (1 socket/flow so not mandatory) */
};

struct insp_open_body {
	uint32_t srv_ip;     /* real destination (network order) — log */
	uint16_t srv_port;   /* → fc.dport */
	uint8_t  profile_id; /* → fc.prof_id (0 = apply every rule) */
	uint8_t  _pad;
	char     sni[256];   /* host for log */
	/* Phase 2 — leg client→ssld so ipsd can read CTA_ML (ML for HTTPS). Host order
	 * for cli_port/fw_port; ip network order. ssld obtains them via getpeername (client)
	 * + getsockname (fw, after REDIRECT). 0 = none (ML not scored). */
	uint32_t leg_cli_ip;
	uint32_t leg_fw_ip;
	uint16_t leg_cli_port;
	uint16_t leg_fw_port;
};

struct insp_data_body {       /* followed by `len` plaintext bytes in the same datagram */
	uint8_t  dir;        /* 0=to_server, 1=to_client */
	uint8_t  _pad[3];
	uint32_t chunk_id;
	uint32_t len;
};

struct insp_verdict_body {
	uint32_t chunk_id;
	uint8_t  action;     /* INSP_PASS / INSP_ALERT / INSP_DROP */
	uint8_t  src;        /* 0 = signature (ML in Phase 2) */
	uint8_t  _pad[2];
	float    score;
	uint32_t sid;
	char     msg[128];
};

/*
 * Start the inspection IPC server (create acceptor thread; each connection → 1 handler
 * thread owning its own insp_flow, rdlock(ruleset) during inspection — safely shared
 * with NFQUEUE). Returns 0 on success, -1 on error (caller logs + continues without IPC).
 */
int insp_ipc_start(struct sig_reload *sr, const struct ips_config *cfg);

#endif /* SG_IPSD_INSP_IPC_H */
