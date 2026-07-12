/* SPDX-License-Identifier: MIT */
/*
 * sig_dump.c - HOST harness: load a .rules file (ET OPEN / Snort) and report.
 *
 *   gcc -O2 -Wall -Wextra -o /tmp/sig_dump ac.c sig_rule.c sig_dump.c
 *   /tmp/sig_dump <file.rules> [payload] [dport] [tcp|udp|icmp]
 *
 * Purpose: demonstrate "ET OPEN compatibility" — count rules loaded / skipped /
 * errored, automaton size, and (optionally) test-match a payload.
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
		fprintf(stderr, "usage: %s <file.rules> [payload] [dport] [tcp|udp|icmp]\n",
			argv[0]);
		return 2;
	}

	struct sig_ruleset    rs;
	struct sig_load_stats st;

	sig_ruleset_init(&rs);
	int rc = sig_load_file(&rs, argv[1], &st);
	if (rc < 0) {
		fprintf(stderr, "could not open %s\n", argv[1]);
		return 1;
	}
	if (sig_build(&rs) != 0) {
		fprintf(stderr, "sig_build failed\n");
		sig_ruleset_free(&rs);
		return 1;
	}

	/* ---- load report (true coverage, P0) ---- */
	printf("== Load ruleset: %s ==\n", argv[1]);
	printf("  rules loaded          : %d (full=%d, alert-cap=%d)\n",
	       st.loaded, st.loaded_full, st.loaded_alert);
	if (st.loaded)
		printf("  %% actually enforced   : %.1f%%\n",
		       100.0 * st.loaded_full / st.loaded);
	printf("  lines skipped         : %d (unsupported=%d, reputation=%d, no-content=%d, no-sid=%d)\n",
	       st.skipped, st.skipped_unsupported, st.skipped_reputation,
	       st.skipped_no_content, st.skipped_no_sid);
	printf("  syntax-error lines    : %d\n", st.errors);
	printf("  AC: %d nodes  (~%.1f MB full DFA)\n",
	       rs.ac.n_nodes,
	       (double)rs.ac.n_nodes * sizeof(struct ac_node) / (1024.0 * 1024.0));

	/* action distribution + a few sample rules */
	int n_drop = 0, n_alert = 0;
	for (int i = 0; i < rs.n_rules; i++) {
		if (rs.rules[i].action == SIG_DROP) n_drop++;
		else                                n_alert++;
	}
	printf("  action: %d alert, %d drop\n", n_alert, n_drop);

	printf("  first 5 rules:\n");
	for (int i = 0; i < rs.n_rules && i < 5; i++) {
		struct sig_rule *r = &rs.rules[i];
		printf("    sid=%-8u proto=%d dport=%-5u ncontent=%d fastlen=%d  %s\n",
		       r->sid, r->proto, r->dport, r->n_content,
		       r->fast >= 0 ? r->content[r->fast].len : 0, r->msg);
	}

	/* ---- test-match payload (optional) ---- */
	if (argc >= 3) {
		struct flow_ctx fc = {
			.proto = (uint8_t)proto_of(argc >= 5 ? argv[4] : "tcp"),
			.dport = (uint16_t)(argc >= 4 ? atoi(argv[3]) : 0),
			.tcp_flags = 0,
		};
		int idx = sig_match(&rs, (const uint8_t *)argv[2], strlen(argv[2]), &fc);

		printf("\n== Test match ==\n  payload=\"%s\" dport=%u proto=%d\n",
		       argv[2], fc.dport, fc.proto);
		if (idx >= 0)
			printf("  → MATCH sid=%u action=%s msg=%s\n",
			       rs.rules[idx].sid,
			       rs.rules[idx].action == SIG_DROP ? "DROP" : "ALERT",
			       rs.rules[idx].msg);
		else
			printf("  → no rule matched\n");
	}

	sig_ruleset_free(&rs);
	return 0;
}
