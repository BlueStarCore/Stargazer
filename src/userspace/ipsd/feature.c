/* SPDX-License-Identifier: MIT */
/*
 * feature.c - 14 feature cho LightGBM (xem feature.h).
 *
 * Mọi feature tính bằng double (userspace, không bị ràng buộc no-float của
 * kernel). Công thức bám ĐÚNG định nghĩa CICFlowMeter — model được train trên
 * output của nó nên runtime phải khớp:
 *   - phương sai/độ lệch chuẩn dùng MẪU (chia n-1), như SummaryStatistics.
 *   - Down/Up Ratio = chia NGUYÊN (bwd/fwd) rồi mới ép double.
 *   - Flag Count để THÔ (không clamp 0/1) — tree tự xử trị ngoài dải train.
 *   - Init_Win_bytes_forward = -1 khi không có (khớp feature_infos [-1:65535]).
 */
#include "feature.h"

#include <math.h>
#include <stddef.h>

const char *const feature_names[FEAT_COUNT] = {
	"Flow IAT Std", "Flow IAT Min", "Flow IAT Mean", "Fwd IAT Std",
	"Packet Length Variance", "Packet Length Std",
	"Fwd Packet Length Mean", "Bwd Packet Length Mean",
	"SYN Flag Count", "ACK Flag Count", "PSH Flag Count", "URG Flag Count",
	"Down/Up Ratio", "Init_Win_bytes_forward",
};

/*
 * Phương sai MẪU: var = (Σx² − (Σx)²/n) / (n−1). n<2 → 0 (CICFlowMeter cũng
 * trả 0/NaN→0 khi <2 mẫu). Chặn âm do sai số dấu phẩy động.
 */
static double sample_var(double sum, double sqsum, uint64_t n)
{
	double v;

	if (n < 2)
		return 0.0;
	v = (sqsum - sum * sum / (double)n) / (double)(n - 1);
	return v > 0.0 ? v : 0.0;
}

/* Mirror struct phải đúng kích thước kernel; bắt lỗi lệch layout ngay lúc build.
 * 144 byte trên LP64 (x86-64 host + aarch64 target, cùng quy tắc canh lề). */
_Static_assert(sizeof(struct sg_nf_conn_ml) == 144,
	       "sg_nf_conn_ml lệch layout so với kernel nf_conn_ml — kiểm lại field/thứ tự");

void feature_extract(const struct sg_nf_conn_ml *ml,
		     uint32_t pkts_fwd, uint32_t pkts_bwd,
		     int32_t init_win_fwd, double out[FEAT_COUNT])
{
	/* --- Flow IAT (µs; iat_sum_us đã là µs trong kernel) --- */
	double iat_sum = (double)ml->iat_sum_us;

	out[FEAT_FLOW_IAT_STD]  = sqrt(sample_var(iat_sum,
				       (double)ml->flow_iat_sq_sum, ml->iat_count));
	out[FEAT_FLOW_IAT_MIN]  = (ml->flow_iat_min == UINT32_MAX)
				  ? 0.0 : (double)ml->flow_iat_min;
	out[FEAT_FLOW_IAT_MEAN] = ml->iat_count
				  ? iat_sum / (double)ml->iat_count : 0.0;

	/* --- Fwd IAT (chỉ chiều forward) --- */
	out[FEAT_FWD_IAT_STD] = sqrt(sample_var((double)ml->fwd_iat_sum,
				     (double)ml->fwd_iat_sq_sum, ml->fwd_iat_count));

	/* --- Packet Length (payload, cả hai chiều) --- */
	double pvar = sample_var((double)ml->pktlen_sum,
				 (double)ml->pktlen_sq_sum, ml->pktlen_count);
	out[FEAT_PKTLEN_VAR] = pvar;
	out[FEAT_PKTLEN_STD] = sqrt(pvar);

	/* --- Mean payload mỗi chiều (số gói từ ACCT) --- */
	out[FEAT_FWD_PKTLEN_MEAN] = pkts_fwd
				    ? (double)ml->bytes_fwd / (double)pkts_fwd : 0.0;
	out[FEAT_BWD_PKTLEN_MEAN] = pkts_bwd
				    ? (double)ml->bytes_bwd / (double)pkts_bwd : 0.0;

	/* --- Flag counts (thô) --- */
	out[FEAT_SYN_CNT] = (double)ml->syn_count;
	out[FEAT_ACK_CNT] = (double)ml->ack_count;
	out[FEAT_PSH_CNT] = (double)ml->psh_count;
	out[FEAT_URG_CNT] = (double)ml->urg_count;

	/* --- Down/Up Ratio = chia NGUYÊN bwd/fwd rồi ép double (khớp CICFlowMeter) --- */
	out[FEAT_DOWNUP_RATIO] = pkts_fwd ? (double)(pkts_bwd / pkts_fwd) : 0.0;

	/* --- Init window forward; -1 nếu chưa biết --- */
	out[FEAT_INIT_WIN_FWD] = (init_win_fwd < 0) ? -1.0 : (double)init_win_fwd;
}
