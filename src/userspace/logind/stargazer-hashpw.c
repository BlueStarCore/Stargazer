/* SPDX-License-Identifier: MIT */
/*
 * stargazer-hashpw — SHA-512 password hashing utility
 *
 * Usage: echo "plaintext" | stargazer-hashpw
 * Output: SHA-512 crypt(3) hash to stdout
 *
 * Reads password from stdin (not argv) to avoid /proc/PID/cmdline leak.
 * Replaces dependency on BusyBox mkpasswd / openssl passwd.
 */

#define _GNU_SOURCE
#include <crypt.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SALT_LEN 16
#define MAX_PASS 256

int main(int argc, char *argv[])
{
	(void)argv;
	if (argc != 1) {
		fprintf(stderr, "Usage: echo '<password>' | stargazer-hashpw\n");
		fprintf(stderr, "Reads password from stdin (one line).\n");
		return 1;
	}

	/* Read password from stdin — avoids /proc/PID/cmdline exposure */
	char password[MAX_PASS];
	if (!fgets(password, sizeof(password), stdin)) {
		fprintf(stderr, "Failed to read password from stdin\n");
		return 1;
	}

	/* Strip trailing newline */
	size_t len = strlen(password);
	if (len > 0 && password[len - 1] == '\n')
		password[len - 1] = '\0';

	if (password[0] == '\0') {
		fprintf(stderr, "Empty password\n");
		return 1;
	}

	/* Generate random salt from /dev/urandom */
	static const char charset[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"0123456789./";

	unsigned char raw[SALT_LEN];
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		perror("open /dev/urandom");
		explicit_bzero(password, sizeof(password));
		return 1;
	}

	ssize_t n = read(fd, raw, sizeof(raw));
	close(fd);
	if (n != (ssize_t)sizeof(raw)) {
		fprintf(stderr, "Failed to read urandom\n");
		explicit_bzero(password, sizeof(password));
		return 1;
	}

	/* Build salt string: $6$<random>$ */
	char salt[4 + SALT_LEN + 1]; /* "$6$" + chars + "$" + NUL */
	salt[0] = '$';
	salt[1] = '6';
	salt[2] = '$';
	for (int i = 0; i < SALT_LEN; i++)
		salt[3 + i] = charset[raw[i] % (sizeof(charset) - 1)];
	salt[3 + SALT_LEN] = '$';
	salt[4 + SALT_LEN] = '\0';

	char *hash = crypt(password, salt);
	explicit_bzero(password, sizeof(password));

	if (!hash) {
		fprintf(stderr, "crypt() failed\n");
		return 1;
	}

	printf("%s\n", hash);
	return 0;
}
