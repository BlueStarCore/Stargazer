/* SPDX-License-Identifier: MIT */
/*
 * model_test.c - smoke test cho wrapper ML, chạy trên HOST.
 *
 *   gcc -O2 -Wall -Wextra -o /tmp/model_test ips_model.c model/predict.c model_test.c -lm
 *
 * Không khẳng định "flow này phải bị chặn" (đó là việc của fusion + threshold);
 * chỉ kiểm wrapper chạy đúng KỸ THUẬT: số feature khớp, điểm ∈ [0,1], tất định,
 * và model có PHẢN HỒI (hai input khác nhau cho điểm khác nhau).
 */
#include "ips_model.h"
#include "model/predict.h"

#include <stdio.h>

static int g_failed;

static void check(int cond, const char *name)
{
	printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name);
	if (!cond) g_failed++;
}

int main(void)
{
	/* vector T1 của feature_test (một flow "có thật") */
	double v1[FEAT_COUNT] = { //web attack sample
      1372180.71,   /* [0] Flow IAT Std */
      4,            /* [1] Flow IAT Min */
      398855.2308,  /* [2] Flow IAT Mean */
      56141.02125,  /* [3] Fwd IAT Std */
      109775.5524,  /* [4] Pkt Length Variance */
      331.3239387,  /* [5] Pkt Length Std */
      146,          /* [6] Fwd Pkt Length Mean */
      331.5714286,  /* [7] Bwd Pkt Length Mean */
      0,            /* [8] SYN */
      0,            /* [9] ACK */
      1,            /* [10] PSH */
      0,            /* [11] URG */
      1,            /* [12] Down/Up Ratio */
      29200,        /* [13] Init_Win_fwd */
  };
	/* vector khác hẳn: DDoS */
	double v2[14] = {	
      21700000,       /* [0] Flow IAT Std */
      19,             /* [1] Flow IAT Min */
      6582775.636,    /* [2] Flow IAT Mean */
      27200000,       /* [3] Fwd IAT Std */
      6192667.308,    /* [4] Pkt Length Variance */
      2488.507044,    /* [5] Pkt Length Std */
      7,              /* [6] Fwd Pkt Length Mean */
      2900.25,        /* [7] Bwd Pkt Length Mean */
      0,              /* [8] SYN */
      1,              /* [9] ACK */
      0,              /* [10] PSH */
      0,              /* [11] URG */
      0,              /* [12] Down/Up Ratio */
      256,            /* [13] Init_Win_fwd */
  };
	double zero[14] = {
      13400000,      /* [0] Flow IAT Std */
      29,            /* [1] Flow IAT Min */
      4266407,       /* [2] Flow IAT Mean */
      94867.03992,   /* [3] Fwd IAT Std */
      5990.727273,   /* [4] Pkt Length Variance */
      77.39978858,   /* [5] Pkt Length Std */
      28.2,          /* [6] Fwd Pkt Length Mean */
      48.5,          /* [7] Bwd Pkt Length Mean */
      0,             /* [8] SYN */
      0,             /* [9] ACK */
      1,             /* [10] PSH */
      0,             /* [11] URG */
      1,             /* [12] Down/Up Ratio */
      8192,          /* [13] Init_Win_fwd */
  };

	printf("model: get_num_feature()=%d\n", get_num_feature());
	check(get_num_feature() == FEAT_COUNT, "model dùng đúng 14 feature");

	double s1 = ips_score(v1);
	double s2 = ips_score(v2);
	double sz = ips_score(zero);
	printf("  score(v1)=%.6f  score(v2)=%.6f  score(zero)=%.6f\n", s1, s2, sz);

	check(s1 >= 0.0 && s1 <= 1.0, "score(v1) ∈ [0,1]");
	check(s2 >= 0.0 && s2 <= 1.0, "score(v2) ∈ [0,1]");
	check(sz >= 0.0 && sz <= 1.0, "score(zero) ∈ [0,1]");

	/* tất định: gọi lại cùng input ra cùng điểm */
	check(ips_score(v1) == s1, "tất định (cùng input → cùng điểm)");

	/* model phản hồi: ít nhất hai trong ba vector cho điểm khác nhau */
	check(!(s1 == s2 && s2 == sz), "model phản hồi khác nhau theo input");

	printf("\n%s (%d test thất bại)\n",
	       g_failed ? "=== CÓ LỖI ===" : "=== TẤT CẢ PASS ===", g_failed);
	return g_failed ? 1 : 0;
}
