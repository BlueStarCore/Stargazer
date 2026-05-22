/* test_sql_injection_protection.c - Test SQL injection protection */

#include <stdio.h>
#include <string.h>
#include "../src/userspace/common/sg_validate.h"

typedef struct {
    const char *input;
    int expected_valid;
    const char *description;
} test_case_t;

int main(void)
{
    test_case_t tests[] = {
        /* Valid IDs */
        {"1", 1, "Simple numeric ID"},
        {"policy1", 1, "Alphanumeric ID"},
        {"test-policy", 1, "ID with hyphen"},
        {"test_policy", 1, "ID with underscore"},
        {"test.policy.1", 1, "ID with dots"},
        {"MyPolicy-123_v2.0", 1, "Complex valid ID"},

        /* SQL Injection attempts */
        {"'; DROP TABLE firewall_policy; --", 0, "SQL injection (DROP TABLE)"},
        {"1' OR '1'='1", 0, "SQL injection (OR clause)"},
        {"1; DELETE FROM users", 0, "SQL injection (DELETE)"},
        {"' UNION SELECT * FROM admin --", 0, "SQL injection (UNION)"},

        /* Path traversal */
        {"../../etc/passwd", 0, "Path traversal (../)"},
        {"../../../etc/shadow", 0, "Path traversal (multiple ../)"},

        /* Command injection */
        {"$(whoami)", 0, "Command injection (command substitution)"},
        {"`id`", 0, "Command injection (backticks)"},
        {"test|whoami", 0, "Command injection (pipe)"},
        {"test;ls", 0, "Command injection (semicolon)"},

        /* XSS attempts */
        {"<script>alert(1)</script>", 0, "XSS (script tag)"},
        {"<img src=x onerror=alert(1)>", 0, "XSS (img tag)"},

        /* Special characters */
        {"test policy", 0, "Space character"},
        {"test\npolicy", 0, "Newline character"},
        {"test\x00policy", 0, "Null byte"},
        {"test{policy}", 0, "Curly braces"},
        {"test[policy]", 0, "Square brackets"},
        {"test\\policy", 0, "Backslash"},

        /* Edge cases */
        {"", 0, "Empty string"},
        {NULL, 0, "NULL pointer"},
    };

    int num_tests = sizeof(tests) / sizeof(tests[0]);
    int passed = 0;
    int failed = 0;

    printf("=== SQL Injection Protection Tests ===\n\n");

    for (int i = 0; i < num_tests; i++) {
        test_case_t *t = &tests[i];
        int result = sg_is_safe_id(t->input);
        int test_passed = (result == t->expected_valid);

        if (test_passed) {
            printf("✓ PASS: %s\n", t->description);
            if (t->input) {
                printf("        Input: \"%s\" → %s\n",
                       t->input, result ? "VALID" : "INVALID");
            } else {
                printf("        Input: NULL → INVALID\n");
            }
            passed++;
        } else {
            printf("✗ FAIL: %s\n", t->description);
            if (t->input) {
                printf("        Input: \"%s\"\n", t->input);
                printf("        Expected: %s, Got: %s\n",
                       t->expected_valid ? "VALID" : "INVALID",
                       result ? "VALID" : "INVALID");
            }
            failed++;
        }
        printf("\n");
    }

    printf("========================================\n");
    printf("Results: %d passed, %d failed / %d total\n",
           passed, failed, num_tests);
    printf("========================================\n");

    return (failed == 0) ? 0 : 1;
}
