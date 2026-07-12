/* SPDX-License-Identifier: MIT */
/*
 * password_policy.c — Shared password policy validation for Stargazer NGFW
 *
 * Pure validation logic — no I/O, no config reading.
 * Character classification uses byte comparison (ASCII, locale-independent).
 */

#include "password_policy.h"
#include <string.h>

int pw_check_policy(const char *password, const char *username,
		    const struct password_policy *pol)
{
	int cnt_upper = 0, cnt_lower = 0, cnt_digit = 0, cnt_special = 0;
	int len = 0;

	for (const char *p = password; *p; p++) {
		len++;
		if (*p >= 'A' && *p <= 'Z')      cnt_upper++;
		else if (*p >= 'a' && *p <= 'z')  cnt_lower++;
		else if (*p >= '0' && *p <= '9')  cnt_digit++;
		else                              cnt_special++;
	}

	if (pol->min_length > 0 && len < pol->min_length)
		return 6;
	if (pol->min_uppercase > 0 && cnt_upper < pol->min_uppercase)
		return 3;
	if (pol->min_lowercase > 0 && cnt_lower < pol->min_lowercase)
		return 4;
	if (pol->min_digit > 0 && cnt_digit < pol->min_digit)
		return 5;
	if (pol->min_special > 0 && cnt_special < pol->min_special)
		return 2;

	/* Reject password containing username */
	if (username && username[0] && strstr(password, username))
		return 7;

	return 1; /* satisfied */
}

const char *pw_policy_reason(int rc)
{
	switch (rc) {
	case 2: return "not enough special characters";
	case 3: return "not enough uppercase characters";
	case 4: return "not enough lowercase characters";
	case 5: return "not enough digits";
	case 6: return "password too short";
	case 7: return "password must not contain username";
	default: return "password does not meet policy";
	}
}
