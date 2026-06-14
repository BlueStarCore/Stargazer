/* SPDX-License-Identifier: MIT */
/*
 * engine.h - điều phối pipeline phát hiện hybrid (signature → ML → fusion).
 *
 * Thứ tự CỐ Ý: signature chạy TRƯỚC. Nếu signature khớp → quyết định ngay theo
 * signature và KHÔNG chạy ML (tiết kiệm inference; tấn công "đã biết" thì chặn
 * luôn, khỏi cần điểm bất thường). Chỉ khi KHÔNG có signature nào khớp mới chấm
 * ML rồi so ngưỡng. Đây là tầng ghép sig_rule + ips_model + fusion lại.
 */
#ifndef SG_ENGINE_H
#define SG_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "fusion.h"      /* ips_config, ips_decision */
#include "feature.h"     /* FEAT_COUNT */
#include "sig_rule.h"    /* sig_ruleset, flow_ctx */
#include "flow_rule.h"   /* flow_stats */

/*
 * Đánh giá một flow/gói. Thứ tự pipeline:
 *   [L1-builtin]  flow_rule_match_builtin(fc, fs)     — anomaly (SYN-flood…), không payload
 *   [L2]          sig_match(rs, payload, plen, fc)     — Aho-Corasick payload (signature)
 *   [ML]          ips_score(feat)                      — LightGBM
 *
 * fs == NULL → bỏ qua cả hai lớp L1 (dùng khi không có flow stats).
 * Mọi lớp đều short-circuit: khớp thì trả ngay, không chạy lớp sau.
 */
struct ips_decision ips_evaluate(const struct ips_config *cfg,
				 const struct sig_ruleset *rs,
				 const uint8_t *payload, size_t plen,
				 const struct flow_ctx *fc,
				 const double feat[FEAT_COUNT],
				 const struct flow_stats *fs);

/*
 * Biến thể cho P1 reassembly: lớp L2 đã được tính SẴN trên DÒNG ĐÃ GHÉP (ở
 * main.c qua reass + streaming AC) nên KHÔNG chạy sig_match per-packet.
 *   l2_ready    : 1 → dùng l2_sig_idx/l2_sig_action làm kết quả L2 (đã fidelity-
 *                 cap); 0 → hành xử như ips_evaluate (tự sig_match trên payload).
 *   l2_sig_idx  : index rule L2 khớp (trong rs->rules), -1 nếu không khớp.
 *   l2_sig_action: action ĐÃ cap của rule đó (SIG_ALERT/SIG_DROP).
 * Thứ tự vẫn L1-builtin → L1-user → L2 → ML (L1 vẫn ưu tiên trước L2).
 */
struct ips_decision ips_evaluate_full(const struct ips_config *cfg,
				      const struct sig_ruleset *rs,
				      const uint8_t *payload, size_t plen,
				      const struct flow_ctx *fc,
				      const double feat[FEAT_COUNT],
				      const struct flow_stats *fs,
				      int l2_ready, int l2_sig_idx,
				      int l2_sig_action);

#endif /* SG_ENGINE_H */
