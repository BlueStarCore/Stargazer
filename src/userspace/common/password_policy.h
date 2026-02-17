/* SPDX-License-Identifier: MIT */
/*
 * password_policy.h — Shared password policy validation for Stargazer NGFW
 *
 * Used by: stargazer-logind, stargazer-mgmtd
 * Pure validation logic — no I/O, no config reading.
 */

#ifndef STARGAZER_PASSWORD_POLICY_H
#define STARGAZER_PASSWORD_POLICY_H

#define PW_MIN_PASS_LEN      8   /* policy-enforced floor */
#define PW_MIN_PASS_LEN_ABS  1   /* absolute minimum (policy disabled) */

struct password_policy {
	int min_length;
	int min_uppercase;
	int min_lowercase;
	int min_digit;
	int min_special;
};

/*
 * Check password against policy.
 * Returns: 1=satisfied, 2=special, 3=uppercase, 4=lowercase,
 *          5=digit, 6=length, 7=contains-username
 */
int pw_check_policy(const char *password, const char *username,
		    const struct password_policy *pol);

/* Human-readable reason for a pw_check_policy return code */
const char *pw_policy_reason(int rc);

#endif /* STARGAZER_PASSWORD_POLICY_H */
