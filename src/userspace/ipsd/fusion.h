/* SPDX-License-Identifier: MIT */
/*
 * fusion.h - gộp kết quả signature + ML thành verdict cuối (decision fusion).
 *
 * Đóng góp cốt lõi của hybrid IPS: signature (đã biết, FP thấp) và ML (lạ/zero-
 * day) bù khuyết nhau. Quy tắc: lấy mức NẶNG NHẤT của hai nguồn; mode `detect`
 * hạ mọi DROP xuống ALERT (chỉ log, không chặn).
 *
 * Nhãn model: class 1 = TẤN CÔNG (notebook: 0=BENIGN, 1=attack) → điểm CAO =
 * tấn công → chặn khi score ≥ thr_block. Default thr_block=0.95 (THRESHOLD lúc
 * train), thr_alert=0.50.
 */
#ifndef SG_FUSION_H
#define SG_FUSION_H

#include <stdint.h>

/* Giá trị tăng dần theo độ nặng để so sánh trực tiếp. */
enum ips_verdict { IPS_PASS = 0, IPS_ALERT = 1, IPS_DROP = 2 };
enum ips_mode    { IPS_MODE_DETECT = 0, IPS_MODE_PREVENT = 1 };
enum ips_reason  { IPS_R_NONE = 0, IPS_R_SIGNATURE, IPS_R_ML_BLOCK, IPS_R_ML_ALERT };

struct ips_config {
	int    mode;        /* IPS_MODE_*                                      */
	double thr_block;   /* score ≥ → DROP  (mặc định 0.95)                 */
	double thr_alert;   /* score ≥ → ALERT (mặc định 0.50)                 */
};

struct ips_decision {
	int      verdict;           /* enum ips_verdict — đã áp mode                   */
	int      reason;            /* enum ips_reason — lý do phát hiện (trước downgrade) */
	int      sig_rule;          /* index rule signature khớp, -1 nếu không          */
	double   score;             /* ML score = P(tấn công); -1 nếu ML không chạy     */
	int      ml_evaluated;      /* 1 nếu đã chấm ML; 0 nếu bỏ qua (signature short-circuit) */
	uint32_t matched_sid;       /* SID của rule khớp; 0 = không có / ML-only        */
	char     matched_msg[128];  /* msg của rule khớp; rỗng nếu ML-only              */
};

/* Đặt cấu hình mặc định: prevent, block 0.95, alert 0.50. */
void ips_config_default(struct ips_config *cfg);

/*
 * Gộp một verdict. sig_idx = kết quả sig_match() (-1 nếu không khớp);
 * sig_action = action của rule khớp (SIG_DROP/SIG_ALERT), chỉ xét khi sig_idx≥0;
 * score = ips_score() ∈ [0,1].
 */
struct ips_decision ips_fuse(const struct ips_config *cfg,
			     int sig_idx, int sig_action, double score);

const char *ips_verdict_str(int v);
const char *ips_reason_str(int r);

#endif /* SG_FUSION_H */
