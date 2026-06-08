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
 *   [L1-builtin]  flow_rule_match_builtin(fc, fs)     — rẻ nhất, không payload
 *   [L1-user]     sig_flow_match(rs, fc, fs)           — user-defined flow rule
 *   [L2]          sig_match(rs, payload, plen, fc)     — Aho-Corasick payload
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

#endif /* SG_ENGINE_H */
