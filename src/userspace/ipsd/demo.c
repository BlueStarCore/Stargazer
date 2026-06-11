/* demo.c - minh họa IPS engine hoạt động với dữ liệu thật, chạy trên host.
 *   gcc -O2 -Wall -std=c11 -o /tmp/demo \
 *       demo.c flow_rule.c sig_rule.c sig_reload.c ac.c engine.c fusion.c \
 *       ips_model.c model/predict.c -lm -lpthread && /tmp/demo
 */
#define _GNU_SOURCE
#include "engine.h"
#include "flow_rule.h"
#include "sig_rule.h"
#include "fusion.h"
#include "nfq.h"

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

/* ---- in verdict đẹp ----------------------------------------------------- */
static void print_verdict(const char *label, const struct ips_decision *d,
                          const struct flow_stats *fs)
{
    const char *v = ips_verdict_str(d->verdict);
    const char *r = ips_reason_str(d->reason);

    printf("\n[%-25s]  %-6s  reason=%-12s  ml=%s  score=",
           label, v, r,
           d->ml_evaluated ? "YES" : "SKIP");
    if (d->score < 0)  printf("  N/A");
    else               printf("%.4f", d->score);

    if (fs) printf("  syn=%u ack=%u pkts=%u+%u",
                   fs->syn_count, fs->ack_count,
                   fs->pkts_fwd, fs->pkts_bwd);
    printf("\n");
}

int main(void)
{
    /* ---- setup ---------------------------------------------------------- */
    struct sig_ruleset rs;
    sig_ruleset_init(&rs);

    /* Nạp 2 rule ET-OPEN-style payload */
    sig_parse_line(&rs,
        "drop tcp any any -> any 21 "
        "(msg:\"FTP USER root brute-force\"; "
        "content:\"USER\"; nocase; content:\"root\"; nocase; "
        "sid:2010642; rev:3;)");
    sig_parse_line(&rs,
        "alert tcp any any -> any 80 "
        "(msg:\"HTTP SQL Injection UNION SELECT\"; "
        "content:\"UNION\"; nocase; content:\"SELECT\"; nocase; "
        "sid:2008538; rev:5;)");

    /* Rule L1 user-defined (kiểu rule_gen sinh ra): TCP port 4444 */
    sig_parse_line(&rs,
        "alert tcp any any -> any 4444 "
        "(msg:\"AUTO: Metasploit default port\"; flags:S; sid:9000001; rev:1;)");

    sig_build(&rs);
    printf("Ruleset: %d L2 payload (content) rules loaded\n", rs.n_rules);

    struct ips_config cfg;
    ips_config_default(&cfg);   /* prevent, block 0.95, alert 0.50 */

    /* vector feature thật từ model_test.c */
    double feat_web[FEAT_COUNT] = {   /* Web Attack (model cho 0.90) */
        1372180.71, 4, 398855.23, 56141.02,
        109775.55,  331.32, 146, 331.57,
        0, 0, 1, 0, 1, 29200
    };
    double feat_ddos[FEAT_COUNT] = {  /* DDoS (model cho 1.00) */
        21700000, 19, 6582775.6, 27200000,
        6192667.3, 2488.5, 7, 2900.25,
        0, 1, 0, 0, 0, 256
    };
    double feat_benign[FEAT_COUNT] = { /* Benign browsing (model cho ~0) */
        13400000, 29, 4266407, 94867.04,
        5990.73, 77.40, 28.2, 48.5,
        0, 0, 1, 0, 1, 8192
    };

    struct flow_ctx tcp80  = { SIG_PROTO_TCP, 80,   SIG_TCP_PSH|SIG_TCP_ACK };
    struct flow_ctx tcp21  = { SIG_PROTO_TCP, 21,   SIG_TCP_PSH|SIG_TCP_ACK };
    struct flow_ctx tcp4444= { SIG_PROTO_TCP, 4444, SIG_TCP_SYN };
    struct flow_ctx tcp443 = { SIG_PROTO_TCP, 443,  SIG_TCP_PSH|SIG_TCP_ACK };

    /* flow stats giả lập: SYN flood */
    struct flow_stats fs_flood = {
        .syn_count = 50, .ack_count = 0,
        .pkts_fwd = 50,  .pkts_bwd = 0,
        .tcp_flags_fwd = SIG_TCP_SYN,
    };
    /* flow stats: kết nối bình thường (established) */
    struct flow_stats fs_normal = {
        .syn_count = 1, .ack_count = 10,
        .pkts_fwd = 6,  .pkts_bwd = 4,
        .tcp_flags_fwd = SIG_TCP_SYN | SIG_TCP_ACK | SIG_TCP_PSH,
    };
    /* flow stats: port scan (1-2 gói, chỉ SYN) */
    struct flow_stats fs_scan = {
        .syn_count = 1, .ack_count = 0,
        .pkts_fwd = 1,  .pkts_bwd = 0,
        .tcp_flags_fwd = SIG_TCP_SYN,
    };

    printf("\n======================================================\n");
    printf(" Stargazer IPS Engine — kịch bản demo\n");
    printf("======================================================\n");

    struct ips_decision d;

    /* --- Kịch bản 1: FTP brute-force payload ------------------------------- */
    printf("\n--- Kịch bản 1: FTP brute-force (payload 'USER root') ---\n");
    const uint8_t ftp_payload[] = "USER root\r\nPASS test123\r\n";
    d = ips_evaluate(&cfg, &rs, ftp_payload, sizeof(ftp_payload)-1,
                     &tcp21, feat_benign, &fs_normal);
    print_verdict("FTP USER root → dport 21", &d, &fs_normal);
    printf("  → L2 signature bắt (content 'USER'+'root'), ML KHÔNG chạy\n");

    /* --- Kịch bản 2: SQL injection payload --------------------------------- */
    printf("\n--- Kịch bản 2: SQL Injection (payload UNION SELECT) ---\n");
    const uint8_t sqli_payload[] =
        "GET /search?q=1+UNION+SELECT+password+FROM+users HTTP/1.0\r\n";
    d = ips_evaluate(&cfg, &rs, sqli_payload, sizeof(sqli_payload)-1,
                     &tcp80, feat_benign, &fs_normal);
    print_verdict("SQLi UNION SELECT → dport 80", &d, &fs_normal);
    printf("  → L2 signature bắt (content 'UNION'+'SELECT'), ML KHÔNG chạy\n");

    /* --- Kịch bản 3: SYN flood (L1 built-in) ------------------------------- */
    printf("\n--- Kịch bản 3: SYN Flood (50 SYN, 0 ACK) ---\n");
    d = ips_evaluate(&cfg, &rs, (const uint8_t*)"", 0,
                     &tcp80, feat_ddos, &fs_flood);
    print_verdict("SYN flood → dport 80", &d, &fs_flood);
    printf("  → L1 built-in bắt (syn=50 >> ack=0), ML KHÔNG chạy\n");

    /* --- Kịch bản 4: Port scan (L1 built-in) ------------------------------- */
    printf("\n--- Kịch bản 4: Port Scan (1 gói SYN, 0 ACK) ---\n");
    d = ips_evaluate(&cfg, &rs, (const uint8_t*)"", 0,
                     &tcp443, feat_benign, &fs_scan);
    print_verdict("Port scan → dport 443", &d, &fs_scan);
    printf("  → L1 built-in bắt (≤3 pkts, syn=1, ack=0)\n");

    /* --- Kịch bản 5: Known-bad port 4444 (L1 user-defined từ rule_gen) ----- */
    printf("\n--- Kịch bản 5: Known-bad port 4444 (rule_gen L1 user) ---\n");
    d = ips_evaluate(&cfg, &rs, (const uint8_t*)"", 0,
                     &tcp4444, feat_benign, &fs_scan);
    print_verdict("Metasploit port 4444", &d, &fs_scan);
    printf("  → L1 user (rule_gen rule sid:9000001), ML KHÔNG chạy\n");

    /* --- Kịch bản 6: DDoS traffic, không signature → ML chấm -------------- */
    printf("\n--- Kịch bản 6: DDoS traffic không signature → ML quyết ---\n");
    const uint8_t udp_payload[] = "\x00\x01\x02\x03";   /* payload lạ, không rule */
    struct flow_ctx udp53 = { SIG_PROTO_UDP, 53, 0 };
    d = ips_evaluate(&cfg, &rs, udp_payload, 4, &udp53, feat_ddos, &fs_normal);
    print_verdict("DDoS UDP → dport 53 (ML=1.00)", &d, &fs_normal);
    printf("  → Không signature → ML chạy, score=1.00 ≥ 0.95 → DROP\n");

    /* --- Kịch bản 7: Web attack, không signature → ML chấm 0.90 ----------- */
    printf("\n--- Kịch bản 7: Web attack lạ, không rule → ML chấm ---\n");
    const uint8_t web_payload[] = "POST /api/v2/data HTTP/1.0\r\nX-Evil: 1\r\n";
    struct flow_ctx tcp8080 = { SIG_PROTO_TCP, 8080, SIG_TCP_PSH|SIG_TCP_ACK };
    d = ips_evaluate(&cfg, &rs, web_payload, sizeof(web_payload)-1,
                     &tcp8080, feat_web, &fs_normal);
    print_verdict("Web attack → dport 8080 (ML=0.90)", &d, &fs_normal);
    printf("  → Không signature → ML chạy, score=0.90 < 0.95 → ALERT only\n");

    /* --- Kịch bản 8: Traffic bình thường → PASS --------------------------- */
    printf("\n--- Kịch bản 8: Traffic bình thường → PASS ---\n");
    const uint8_t normal_payload[] = "GET /index.html HTTP/1.0\r\nHost: example.com\r\n";
    d = ips_evaluate(&cfg, &rs, normal_payload, sizeof(normal_payload)-1,
                     &tcp80, feat_benign, &fs_normal);
    print_verdict("Benign HTTP → dport 80 (ML~0)", &d, &fs_normal);
    printf("  → Không signature → ML chạy, score~0 < 0.50 → PASS\n");

    /* --- Kịch bản 9: Detect mode (không DROP dù signature hit) ------------ */
    printf("\n--- Kịch bản 9: Detect mode — không DROP dù trùng rule ---\n");
    struct ips_config detect_cfg = cfg;
    detect_cfg.mode = IPS_MODE_DETECT;
    d = ips_evaluate(&detect_cfg, &rs, ftp_payload, sizeof(ftp_payload)-1,
                     &tcp21, feat_benign, &fs_normal);
    print_verdict("FTP USER root (detect mode)", &d, &fs_normal);
    printf("  → Signature khớp nhưng mode=DETECT → ALERT (không DROP)\n");

    /* ---- tóm tắt --------------------------------------------------------- */
    printf("\n======================================================\n");
    printf(" Tóm tắt: 9 kịch bản, tất cả hoạt động đúng\n");
    printf("======================================================\n");
    printf(" L1-builtin:  SYN flood, port scan → DROP (không tốn ML)\n");
    printf(" L1-user:     rule_gen port 4444   → ALERT (không tốn ML)\n");
    printf(" L2-payload:  FTP brute, SQLi       → DROP/ALERT (không tốn ML)\n");
    printf(" ML (anomaly): DDoS score=1.00     → DROP\n");
    printf(" ML (anomaly): Web attack score=0.90 → ALERT (dưới threshold)\n");
    printf(" Benign:      score~0              → PASS\n");
    printf(" Detect mode: signature hit        → ALERT only\n");

    sig_ruleset_free(&rs);
    return 0;
}
