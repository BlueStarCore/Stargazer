/* SPDX-License-Identifier: MIT */
/*
 * sig_dump.c - harness HOST: nạp một file .rules (ET OPEN / Snort) và báo cáo.
 *
 *   gcc -O2 -Wall -Wextra -o /tmp/sig_dump ac.c sig_rule.c sig_dump.c
 *   /tmp/sig_dump <file.rules> [payload] [dport] [tcp|udp|icmp]
 *
 * Mục đích: chứng minh "tương thích ET OPEN" — đếm rule nạp được / bỏ qua /
 * lỗi, cỡ automaton, và (tùy chọn) thử khớp một payload.
 */
#include "sig_rule.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int proto_of(const char *s)
{
	if (!s) return SIG_PROTO_TCP;
	if (!strcasecmp(s, "udp"))  return SIG_PROTO_UDP;
	if (!strcasecmp(s, "icmp")) return SIG_PROTO_ICMP;
	return SIG_PROTO_TCP;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "dùng: %s <file.rules> [payload] [dport] [tcp|udp|icmp]\n",
			argv[0]);
		return 2;
	}

	struct sig_ruleset    rs;
	struct sig_load_stats st;

	sig_ruleset_init(&rs);
	int rc = sig_load_file(&rs, argv[1], &st);
	if (rc < 0) {
		fprintf(stderr, "không mở được %s\n", argv[1]);
		return 1;
	}
	if (sig_build(&rs) != 0) {
		fprintf(stderr, "sig_build thất bại\n");
		sig_ruleset_free(&rs);
		return 1;
	}

	/* ---- báo cáo nạp (độ phủ thật, P0) ---- */
	printf("== Nạp ruleset: %s ==\n", argv[1]);
	printf("  rule nạp              : %d (full=%d, alert-cap=%d)\n",
	       st.loaded, st.loaded_full, st.loaded_alert);
	if (st.loaded)
		printf("  %% thực sự enforce     : %.1f%%\n",
		       100.0 * st.loaded_full / st.loaded);
	printf("  dòng bỏ qua           : %d (unsupported=%d, reputation=%d, no-content=%d)\n",
	       st.skipped, st.skipped_unsupported, st.skipped_reputation,
	       st.skipped_no_content);
	printf("  dòng lỗi cú pháp      : %d\n", st.errors);
	printf("  AC: %d node  (~%.1f MB DFA đầy đủ)\n",
	       rs.ac.n_nodes,
	       (double)rs.ac.n_nodes * sizeof(struct ac_node) / (1024.0 * 1024.0));

	/* phân bố action + vài rule mẫu */
	int n_drop = 0, n_alert = 0;
	for (int i = 0; i < rs.n_rules; i++) {
		if (rs.rules[i].action == SIG_DROP) n_drop++;
		else                                n_alert++;
	}
	printf("  action: %d alert, %d drop\n", n_alert, n_drop);

	printf("  5 rule đầu:\n");
	for (int i = 0; i < rs.n_rules && i < 5; i++) {
		struct sig_rule *r = &rs.rules[i];
		printf("    sid=%-8u proto=%d dport=%-5u ncontent=%d fastlen=%d  %s\n",
		       r->sid, r->proto, r->dport, r->n_content,
		       r->fast >= 0 ? r->content[r->fast].len : 0, r->msg);
	}

	/* ---- thử khớp payload (tùy chọn) ---- */
	if (argc >= 3) {
		struct flow_ctx fc = {
			.proto = (uint8_t)proto_of(argc >= 5 ? argv[4] : "tcp"),
			.dport = (uint16_t)(argc >= 4 ? atoi(argv[3]) : 0),
			.tcp_flags = 0,
		};
		int idx = sig_match(&rs, (const uint8_t *)argv[2], strlen(argv[2]), &fc);

		printf("\n== Thử khớp ==\n  payload=\"%s\" dport=%u proto=%d\n",
		       argv[2], fc.dport, fc.proto);
		if (idx >= 0)
			printf("  → KHỚP sid=%u action=%s msg=%s\n",
			       rs.rules[idx].sid,
			       rs.rules[idx].action == SIG_DROP ? "DROP" : "ALERT",
			       rs.rules[idx].msg);
		else
			printf("  → không khớp rule nào\n");
	}

	sig_ruleset_free(&rs);
	return 0;
}
