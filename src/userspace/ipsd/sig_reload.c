/* SPDX-License-Identifier: MIT */
/*
 * sig_reload.c - hot-reload ruleset (xem sig_reload.h + Snort README.reload).
 */
#define _GNU_SOURCE   /* pipe2, O_CLOEXEC, pthread_rwlock_t, sigaction */
#include "sig_reload.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

/* Con trỏ module-level cho signal handler — bắt buộc vì handler không nhận arg.
 * Chỉ set một lần trong sig_reload_init(); không bao giờ đổi sau đó. */
static struct sig_reload *sr_global = NULL;

/*
 * P0 — độ phủ thật: ghi breakdown ra file để mgmtd/UI đọc (SG_CMD_IPS_STATUS).
 * "% thực sự enforce" = loaded_full / (loaded_full+loaded_alert). Không giấu.
 */
#define IPSD_STATS_FILE "/run/stargazer-ipsd.stats"
static void write_load_stats(const struct sig_load_stats *st)
{
	FILE *f = fopen(IPSD_STATS_FILE, "w");
	if (!f)
		return;
	fprintf(f,
		"loaded=%d\nloaded_full=%d\nloaded_alert=%d\n"
		"skipped=%d\nskipped_unsupported=%d\nskipped_reputation=%d\n"
		"skipped_no_content=%d\nskipped_no_sid=%d\nerrors=%d\n",
		st->loaded, st->loaded_full, st->loaded_alert,
		st->skipped, st->skipped_unsupported, st->skipped_reputation,
		st->skipped_no_content, st->skipped_no_sid, st->errors);
	fclose(f);
}

/* ---- signal handler (async-signal-safe: chỉ write) ----------------------- */

static void sigusr1_handler(int sig)
{
	(void)sig;
	if (!sr_global)
		return;
	char b = 'R';
	/* write() là async-signal-safe. Lỗi bỏ qua — nếu pipe đầy thì SIGUSR1
	 * đã được báo hiệu rồi (1 byte tồn đọng = đủ để trigger). */
	(void)write(sr_global->pipe_wr, &b, 1);
}

/* ---- reload thread -------------------------------------------------------- */

static void *reload_thread_fn(void *arg)
{
	struct sig_reload *sr = arg;
	struct sig_ruleset *fresh;
	struct sig_load_stats st;
	int rc;

	/* [a] cấp phát + init ruleset mới */
	fresh = malloc(sizeof(*fresh));
	if (!fresh) {
		fprintf(stderr, "sig_reload: malloc failed\n");
		goto fail_early;
	}
	sig_ruleset_init(fresh);

	/* [b] nạp từ đĩa */
	pthread_mutex_lock(&sr->spawn_lock);
	char path[256];
	memcpy(path, sr->rules_path, sizeof(path));
	pthread_mutex_unlock(&sr->spawn_lock);

	rc = sig_load_file(fresh, path, &st);
	if (rc < 0) {
		fprintf(stderr,
			"sig_reload: cannot open %s — rollback (loaded=%d skip=%d err=%d)\n",
			path, st.loaded, st.skipped, st.errors);
		sig_ruleset_free(fresh);
		free(fresh);
		goto fail;
	}
	if (st.loaded == 0) {
		fprintf(stderr,
			"sig_reload: %s yielded 0 rules — rollback (skip=%d err=%d)\n",
			path, st.skipped, st.errors);
		sig_ruleset_free(fresh);
		free(fresh);
		goto fail;
	}
	fprintf(stderr,
		"sig_reload: loaded %d rules (full=%d alert-cap=%d | skip=%d "
		"[unsup=%d reputation=%d no-content=%d no-sid=%d] err=%d) from %s\n",
		st.loaded, st.loaded_full, st.loaded_alert, st.skipped,
		st.skipped_unsupported, st.skipped_reputation,
		st.skipped_no_content, st.skipped_no_sid, st.errors, path);
	write_load_stats(&st);

	/* [c] build AC — bước tốn kém; bản cũ vẫn chạy trong lúc này */
	if (sig_build(fresh) != 0) {
		fprintf(stderr, "sig_reload: sig_build failed — rollback\n");
		sig_ruleset_free(fresh);
		free(fresh);
		goto fail;
	}

	/* [d-f] swap dưới write-lock: sau khi lock xong KHÔNG malloc/free */
	{
		struct sig_ruleset *old;
		pthread_rwlock_wrlock(&sr->rwlock);
		old        = sr->active;
		sr->active = fresh;     /* atomic từ góc nhìn reader */
		sr->pending = NULL;
		pthread_rwlock_unlock(&sr->rwlock);

		/* [g] free bản cũ SAU khi đã unlock — không còn reader nào giữ ref */
		sig_ruleset_free(old);
		free(old);
	}

	/* [h] thống kê + đánh dấu rảnh */
	sr->reload_count++;
	sr->last_result = 0;
	pthread_mutex_lock(&sr->spawn_lock);
	sr->thread = 0;
	pthread_mutex_unlock(&sr->spawn_lock);
	return NULL;

fail:
	sr->reload_errors++;
	sr->last_result = -1;
fail_early:
	pthread_mutex_lock(&sr->spawn_lock);
	sr->pending = NULL;
	sr->thread  = 0;
	pthread_mutex_unlock(&sr->spawn_lock);
	return NULL;
}

/* ---- API ------------------------------------------------------------------ */

int sig_reload_init(struct sig_reload *sr, const char *rules_path)
{
	struct sig_ruleset *initial;
	struct sig_load_stats st;
	int fds[2];

	memset(sr, 0, sizeof(*sr));
	sr->pipe_rd = sr->pipe_wr = -1;

	/* ruleset ban đầu */
	initial = malloc(sizeof(*initial));
	if (!initial)
		return -1;
	sig_ruleset_init(initial);

	if (sig_load_file(initial, rules_path, &st) < 0 || st.loaded == 0) {
		fprintf(stderr,
			"sig_reload_init: failed to load %s (loaded=%d err=%d)\n",
			rules_path, st.loaded, st.errors);
		sig_ruleset_free(initial);
		free(initial);
		return -1;
	}
	if (sig_build(initial) != 0) {
		fprintf(stderr, "sig_reload_init: sig_build failed\n");
		sig_ruleset_free(initial);
		free(initial);
		return -1;
	}
	sr->active = initial;
	snprintf(sr->rules_path, sizeof(sr->rules_path), "%s", rules_path);

	/* self-pipe non-blocking + close-on-exec */
	if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0) {
		sig_ruleset_free(initial);
		free(initial);
		return -1;
	}
	sr->pipe_rd = fds[0];
	sr->pipe_wr = fds[1];

	if (pthread_rwlock_init(&sr->rwlock, NULL) != 0 ||
	    pthread_mutex_init(&sr->spawn_lock, NULL) != 0) {
		close(sr->pipe_rd);
		close(sr->pipe_wr);
		sig_ruleset_free(initial);
		free(initial);
		return -1;
	}

	/* SIGUSR1 handler: async-signal-safe, SA_RESTART agar syscall tidak terputus */
	sr_global = sr;
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigusr1_handler;
	sa.sa_flags   = SA_RESTART;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGUSR1, &sa, NULL);

	fprintf(stderr,
		"sig_reload_init: ready (%d rules: full=%d alert-cap=%d | "
		"skip unsup=%d reputation=%d no-content=%d no-sid=%d err=%d) from %s\n",
		st.loaded, st.loaded_full, st.loaded_alert,
		st.skipped_unsupported, st.skipped_reputation,
		st.skipped_no_content, st.skipped_no_sid, st.errors, rules_path);
	write_load_stats(&st);
	return 0;
}

/* Spawn reload thread. Caller MUST hold spawn_lock. Trả 0/-1. */
static int spawn_reload_locked(struct sig_reload *sr)
{
	if (sr->thread != 0)
		return 1;    /* đang reload rồi */

	pthread_t tid;
	if (pthread_create(&tid, NULL, reload_thread_fn, sr) != 0) {
		fprintf(stderr, "sig_reload: pthread_create failed\n");
		return -1;
	}
	/* detach: thread tự dọn; sig_reload_wait() join bằng cách poll sr->thread */
	pthread_detach(tid);
	sr->thread = tid;
	return 0;
}

int sig_reload_handle_signal(struct sig_reload *sr)
{
	/* drain pipe (có thể nhiều byte nếu signal đến nhiều lần) */
	char buf[64];
	while (read(sr->pipe_rd, buf, sizeof(buf)) > 0)
		;

	pthread_mutex_lock(&sr->spawn_lock);
	int rc = spawn_reload_locked(sr);
	pthread_mutex_unlock(&sr->spawn_lock);

	if (rc == 1) {
		fprintf(stderr, "sig_reload: reload in progress, skipping\n");
		return 1;
	}
	return rc;
}

int sig_reload_match(struct sig_reload *sr, const uint8_t *payload,
		     size_t len, const struct flow_ctx *fc)
{
	pthread_rwlock_rdlock(&sr->rwlock);
	int r = sig_match(sr->active, payload, len, fc);
	pthread_rwlock_unlock(&sr->rwlock);
	return r;
}

int sig_reload_trigger(struct sig_reload *sr, const char *new_path)
{
	pthread_mutex_lock(&sr->spawn_lock);
	if (new_path && new_path[0])
		snprintf(sr->rules_path, sizeof(sr->rules_path), "%s", new_path);
	int rc = spawn_reload_locked(sr);
	pthread_mutex_unlock(&sr->spawn_lock);
	return (rc == 1) ? 1 : rc;    /* 1 = đang bận, 0 = started, -1 = error */
}

int sig_reload_wait(struct sig_reload *sr)
{
	/* poll sr->thread (đã detach nên không join được) với sleep ngắn */
	for (int i = 0; i < 5000; i++) {
		pthread_mutex_lock(&sr->spawn_lock);
		int idle = (sr->thread == 0);
		pthread_mutex_unlock(&sr->spawn_lock);
		if (idle)
			return sr->last_result;
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 }; /* 1ms */
		nanosleep(&ts, NULL);
	}
	/* sau 5 giây vẫn không xong — bất thường, trả lỗi */
	fprintf(stderr, "sig_reload_wait: timeout waiting for reload thread\n");
	return -1;
}

void sig_reload_free(struct sig_reload *sr)
{
	if (!sr)
		return;

	/* đợi thread xong trước khi free */
	sig_reload_wait(sr);

	if (sr->active) {
		sig_ruleset_free(sr->active);
		free(sr->active);
		sr->active = NULL;
	}
	if (sr->pipe_rd >= 0) { close(sr->pipe_rd); sr->pipe_rd = -1; }
	if (sr->pipe_wr >= 0) { close(sr->pipe_wr); sr->pipe_wr = -1; }

	pthread_rwlock_destroy(&sr->rwlock);
	pthread_mutex_destroy(&sr->spawn_lock);

	if (sr_global == sr)
		sr_global = NULL;
}
