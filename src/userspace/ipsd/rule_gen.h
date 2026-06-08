/* SPDX-License-Identifier: MIT */
/*
 * rule_gen.h - Rule Generation Unit (vòng phản hồi kín của IPS hybrid).
 *
 * Hiện thực "Rule Generation Unit" trong:
 *   Korde, Tarapore, Shinde, Dhore, "Hybrid Intrusion Detection with Rule
 *   Generation", CCSIT 2012, LNICST 85, pp. 345-354.
 *
 * Ý tưởng: khi ML (anomaly engine) bắt được một flow bất thường mà signature
 * KHÔNG bắt (ips_score ≥ ngưỡng && sig_match == -1), ta coi đó là tấn công
 * "lạ" và tự SINH một flow-rule mới từ thuộc tính của flow, rồi nạp vào ruleset
 * sống — lần sau gặp lại sẽ bị bắt bởi signature (rẻ hơn, không cần ML).
 *
 * FER (Frequent Episode Rule) của paper rút gọn thành: chỉ sinh rule khi một
 * bộ (proto, dport, flags) bất thường xuất hiện ĐỦ NHIỀU lần (≥ min_support) —
 * tránh sinh rule từ một lần nhiễu ngẫu nhiên.
 *
 * AN TOÀN: chỉ sinh rule action ALERT (không bao giờ tự DROP). Người vận hành
 * xem qua `diagnose ips signatures` rồi mới nâng lên DROP thủ công.
 *
 * GIỚI HẠN hiện tại: rule sinh ra là flow-rule (không content). sig_parse_line()
 * hiện bỏ qua rule không content (engine match đang AC-only), nên các rule này
 * được rule_gen tự lưu/nạp; việc KHỚP chúng cần engine flow-rule lớp 1 (đang chờ).
 */
#ifndef SG_RULE_GEN_H
#define SG_RULE_GEN_H

#include <stdint.h>
#include <time.h>
#include <pthread.h>

#include "sig_rule.h"   /* struct sig_ruleset, sig_parse_line */

#define RULE_GEN_TABLE_SZ   256
#define RULE_GEN_SID_BASE   9000000u   /* dải SID dành cho rule tự sinh */
#define RULE_GEN_RULE_MAX   256        /* độ dài tối đa một dòng rule    */

/* Dữ liệu một flow bất thường (ML xác nhận) đưa vào rule_gen. */
struct rule_gen_input {
	/* từ gói NFQUEUE */
	uint8_t  proto;        /* IPPROTO_TCP / IPPROTO_UDP / IPPROTO_ICMP */
	uint16_t dport;
	uint8_t  tcp_flags;    /* bitmask SIG_TCP_* (FIN/SYN/RST/PSH/ACK/URG) */
	uint32_t dsize;        /* payload L4 gói này */
	int      land;         /* src_ip == dst_ip ? 1 : 0 */

	/* từ struct sg_nf_conn_ml */
	uint32_t syn_count, ack_count, psh_count;
	uint64_t bytes_fwd, bytes_bwd;
	uint32_t pkts_fwd, pkts_bwd;

	/* từ kết quả ML */
	double   ml_score;     /* ips_score() ∈ [0,1] */
	uint32_t flow_count;   /* (tuỳ chọn) support ngoài; rule_gen tự đếm nội bộ */
};

struct rule_gen_entry {
	uint8_t  proto;
	uint16_t dport;
	uint8_t  flags_set;
	uint32_t count;        /* số lần thấy bộ này (= support) */
	time_t   last_seen;
	int      rule_emitted; /* 1 = đã sinh rule cho bộ này (chống trùng) */
	int      used;         /* slot đang dùng */
	uint32_t sid;          /* SID đã cấp khi sinh */
	char     rule[RULE_GEN_RULE_MAX]; /* dòng rule Snort đã sinh (để lưu) */
};

struct rule_gen_ctx {
	struct rule_gen_entry table[RULE_GEN_TABLE_SZ];
	uint32_t        min_support;
	double          score_threshold;
	uint32_t        sid_counter;
	uint32_t        rules_emitted;
	pthread_mutex_t lock;
};

/* min_support=0 → mặc định 3; sid_start=0 → mặc định RULE_GEN_SID_BASE. */
void rule_gen_init(struct rule_gen_ctx *ctx, uint32_t min_support,
		   double score_threshold, uint32_t sid_start);

/*
 * Nạp một flow bất thường (ML đã xác nhận). Tăng bộ đếm tần suất cho bộ
 * (proto, dport, flags). Trả 1 nếu vừa SINH một rule mới, 0 nếu chưa. Khi sinh:
 * gọi sig_parse_line() để nạp vào *rs (có thể NULL nếu chỉ muốn cache nội bộ).
 * Thread-safe (mutex).
 */
int rule_gen_feed(struct rule_gen_ctx *ctx, const struct rule_gen_input *in,
		  struct sig_ruleset *rs);

/* Ghi cache rule tự sinh ra file (mỗi dòng một rule, cú pháp Snort). 0/-1. */
int rule_gen_save(const struct rule_gen_ctx *ctx, const char *path);

/* Nạp lại rule đã lưu vào ctx (và vào *rs nếu khác NULL) lúc khởi động.
 * Trả số rule nạp được, -1 nếu lỗi đọc (file không tồn tại → 0). */
int rule_gen_load(struct rule_gen_ctx *ctx, struct sig_ruleset *rs,
		  const char *path);

void rule_gen_free(struct rule_gen_ctx *ctx);

#endif /* SG_RULE_GEN_H */
