/* SPDX-License-Identifier: MIT */
/*
 * relay_test.c - test bơm byte hai chiều bằng socketpair.
 *
 * Sơ đồ: dựng hai socketpair mô phỏng hai kết nối, cho relay_pump nối hai đầu
 * trong (proxy), rồi điều khiển hai đầu ngoài (client/upstream) từ main thread.
 *
 *   client_ext ── client_int ──[relay_pump (thread)]── up_int ── up_ext
 *
 * Ghi vào client_ext phải hiện ra ở up_ext, và ngược lại. Đóng một đầu phải
 * lan FIN sang đầu kia (half-close). Chạy dưới ASan.
 */
#include "relay.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>

static int g_fail;

#define CHECK(cond, msg) do {                                            \
	if (!(cond)) { printf("  FAIL: %s\n", msg); g_fail++; }          \
	else         { printf("  ok:   %s\n", msg); }                    \
} while (0)

struct pump_args { int a, b; };

static void *pump_thread(void *arg)
{
	struct pump_args *p = arg;
	relay_pump(p->a, p->b);
	return NULL;
}

struct write_args { int fd; const char *d; size_t n; };

static void *write_thread(void *arg)
{
	struct write_args *w = arg;
	relay_write_all(w->fd, w->d, w->n);
	return NULL;
}

/* Đọc đúng n byte (lặp) — tránh đọc thiếu do phân mảnh. */
static int read_n(int fd, char *buf, size_t n)
{
	size_t off = 0;
	while (off < n) {
		ssize_t r = read(fd, buf + off, n - off);
		if (r <= 0)
			return -1;
		off += (size_t)r;
	}
	return 0;
}

int main(void)
{
	int cs[2], us[2];   /* client pair, upstream pair */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, cs) < 0 ||
	    socketpair(AF_UNIX, SOCK_STREAM, 0, us) < 0) {
		perror("socketpair");
		return 2;
	}
	int client_ext = cs[0], client_int = cs[1];
	int up_int = us[0], up_ext = us[1];

	struct pump_args pa = { .a = client_int, .b = up_int };
	pthread_t th;
	pthread_create(&th, NULL, pump_thread, &pa);

	printf("== test 1: client -> upstream ==\n");
	{
		const char *msg = "GET / HTTP/1.1\r\n";
		relay_write_all(client_ext, msg, strlen(msg));
		char buf[64] = {0};
		CHECK(read_n(up_ext, buf, strlen(msg)) == 0, "đọc đủ byte ở upstream");
		CHECK(memcmp(buf, msg, strlen(msg)) == 0, "nội dung khớp chiều ->");
	}

	printf("== test 2: upstream -> client ==\n");
	{
		const char *msg = "HTTP/1.1 200 OK\r\n";
		relay_write_all(up_ext, msg, strlen(msg));
		char buf[64] = {0};
		CHECK(read_n(client_ext, buf, strlen(msg)) == 0, "đọc đủ byte ở client");
		CHECK(memcmp(buf, msg, strlen(msg)) == 0, "nội dung khớp chiều <-");
	}

	printf("== test 3: dữ liệu lớn (vượt 1 buffer) ==\n");
	{
		size_t big = RELAY_BUF_SIZE * 3 + 123;
		char *out = malloc(big), *in = malloc(big);
		for (size_t i = 0; i < big; i++) out[i] = (char)(i & 0xff);
		/* ghi trong thread riêng để tránh deadlock khi buffer đầy */
		struct write_args wa = { client_ext, out, big };
		pthread_t wt;
		pthread_create(&wt, NULL, write_thread, &wa);
		CHECK(read_n(up_ext, in, big) == 0, "đọc đủ khối lớn");
		CHECK(memcmp(out, in, big) == 0, "khối lớn khớp nguyên vẹn");
		pthread_join(wt, NULL);
		free(out); free(in);
	}

	printf("== test 4: half-close lan FIN ==\n");
	{
		/* đóng đầu ghi client_ext → client_int đọc EOF → pump shutdown up_int
		 * write → up_ext đọc EOF. */
		shutdown(client_ext, SHUT_WR);
		char buf[8];
		ssize_t r = read(up_ext, buf, sizeof(buf));
		CHECK(r == 0, "upstream nhận EOF sau khi client half-close");

		/* chiều còn lại vẫn gửi được */
		const char *msg = "late";
		relay_write_all(up_ext, msg, strlen(msg));
		char b2[8] = {0};
		CHECK(read_n(client_ext, b2, strlen(msg)) == 0,
		      "upstream->client vẫn chạy sau half-close");
	}

	printf("== test 5: đóng nốt → pump kết thúc ==\n");
	{
		shutdown(up_ext, SHUT_WR);
		close(up_ext);
		/* pump phải thoát; join với timeout mềm bằng cách đóng client_ext */
		shutdown(client_ext, SHUT_RDWR);
		close(client_ext);
		pthread_join(th, NULL);
		CHECK(1, "relay_pump thoát sạch khi cả hai chiều đóng");
	}

	close(client_int); close(up_int);

	if (g_fail) {
		printf("\n== %d TEST FAIL ==\n", g_fail);
		return 1;
	}
	printf("\n== TẤT CẢ relay TEST PASS ==\n");
	return 0;
}
