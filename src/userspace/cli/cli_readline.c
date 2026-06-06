/* SPDX-License-Identifier: MIT */
/*
 * cli_readline.c — Embedded readline engine for Stargazer CLI
 *
 * Refactored from stargazer-readline.c into a library form.
 * No main(), no stdout capture — returns buffer directly.
 *
 * Features:
 *   - Raw terminal mode (termios)
 *   - Character-by-character read (no dd fork per char)
 *   - Backspace, Ctrl-C, Ctrl-D, Ctrl-U, Ctrl-W
 *   - Arrow keys (up/down for history, left/right cursor movement)
 *   - Tab completion: cycle through registered candidates
 *   - ? help: display matching entries
 *   - Home/End keys
 *   - UTF-8 aware (multi-byte passthrough)
 *   - Completion push/pop stack for nested CLI contexts
 *   - In-process history with on-demand file I/O
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "cli_readline.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* Terminal writes: non-actionable on failure, suppress warn_unused_result */
static inline void tty_write(int fd, const void *buf, size_t len)
{
	if (write(fd, buf, len) < 0) { /* terminal I/O, ignore */ }
}

/* ── Data structures ──────────────────────────────────────────────────── */

struct cli_completion {
	char path[CLI_MAX_LINE];
	char desc[CLI_MAX_DESC];
};

struct cli_comp_set {
	struct cli_completion entries[CLI_MAX_COMPS];
	int count;
};

static struct cli_comp_set comp_stack[CLI_MAX_STACK];
static int stack_depth = 0;
static struct cli_comp_set current_comps;	/* active completion set */

static char hist[CLI_MAX_HIST][CLI_MAX_LINE];
static int nhist = 0;

static struct termios orig_termios;
static int have_orig = 0;	/* orig_termios captured? (else don't restore) */
static int raw_mode = 0;
static int tty_fd = -1;

/* Internal static buffer returned by cli_readline() */
static char line_buf[CLI_MAX_LINE];

/* Paste buffer: captures remaining tty input before TCSAFLUSH discards it */
#define PASTE_BUF_SIZE (CLI_MAX_LINE * 8)	/* 32 KiB */
static char paste_buf[PASTE_BUF_SIZE];
static int  paste_len = 0;
static int  paste_pos = 0;

/* Idle callback — fired every ~5 seconds while blocked on input */
static cli_idle_cb_t rl_idle_cb = NULL;
static struct timespec last_idle_check;

void cli_set_idle_cb(cli_idle_cb_t cb)
{
	rl_idle_cb = cb;
	clock_gettime(CLOCK_MONOTONIC, &last_idle_check);
}

/* ── Terminal ─────────────────────────────────────────────────────────── */

/*
 * Open a terminal device for interactive I/O.
 * Try /dev/tty first (controlling terminal), fall back to /dev/console.
 * Returns fd on success, -1 on failure.
 */
static int open_terminal(void)
{
	int fd = open("/dev/tty", O_RDWR | O_NOCTTY);
	if (fd >= 0)
		return fd;
	fd = open("/dev/console", O_RDWR | O_NOCTTY);
	if (fd >= 0)
		return fd;
	/* Last resort: stderr may still be the terminal (inherited fd
	 * survives even when the device node is not openable by UID). */
	if (isatty(STDERR_FILENO))
		return dup(STDERR_FILENO);
	return -1;
}

/*
 * disable_raw() — leave raw mode but keep ECHO off.
 *
 * Between readline calls the CLI dispatches commands.  If we restored
 * orig_termios (which has ECHO on), any keystrokes typed during command
 * output would be echoed into the display.  Instead we switch to a
 * "quiet" mode: OPOST on (so printf works), ECHO off (no stray input),
 * ICANON off (don't buffer).  cli_term_cleanup() restores the true
 * original settings on exit.
 */
static void disable_raw(void)
{
	if (raw_mode && tty_fd >= 0) {
		struct termios quiet = orig_termios;
		quiet.c_lflag &= ~(unsigned)(ECHO | ICANON);
		tcsetattr(tty_fd, TCSANOW, &quiet);
		raw_mode = 0;
	}
}

static int enable_raw(void)
{
	struct termios t;

	if (tty_fd < 0)
		return -1;
	if (!isatty(tty_fd))
		return -1;
	if (tcgetattr(tty_fd, &orig_termios) != 0)
		return -1;
	have_orig = 1;

	t = orig_termios;
	t.c_iflag &= ~(unsigned)(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
	t.c_oflag &= ~(unsigned)(OPOST);
	t.c_cflag |= CS8;
	t.c_lflag &= ~(unsigned)(ECHO | ICANON | IEXTEN | ISIG);
	t.c_cc[VMIN] = 1;
	t.c_cc[VTIME] = 0;

	if (tcsetattr(tty_fd, TCSANOW, &t) != 0)
		return -1;

	raw_mode = 1;
	return 0;
}

/*
 * drain_pending() — capture remaining bytes from the tty buffer.
 *
 * When the user pastes multiple lines, the kernel tty buffer holds
 * lines 2..N while we process line 1 char-by-char.  Before calling
 * disable_raw() (which uses TCSAFLUSH and would discard them), we
 * drain everything into paste_buf so subsequent cli_readline() calls
 * can serve those lines without touching the tty.
 *
 * Must be called while still in raw mode.
 */
static void drain_pending(void)
{
	if (tty_fd < 0)
		return;

	/* Compact: shift unread data to front */
	if (paste_pos > 0 && paste_pos < paste_len) {
		memmove(paste_buf, paste_buf + paste_pos,
			(size_t)(paste_len - paste_pos));
		paste_len -= paste_pos;
		paste_pos = 0;
	} else if (paste_pos >= paste_len) {
		paste_len = 0;
		paste_pos = 0;
	}

	/* Switch to non-blocking so we can drain without stalling */
	int flags = fcntl(tty_fd, F_GETFL, 0);
	if (flags < 0)
		return;
	fcntl(tty_fd, F_SETFL, flags | O_NONBLOCK);

	while (paste_len < PASTE_BUF_SIZE) {
		ssize_t n = read(tty_fd, paste_buf + paste_len,
				 (size_t)(PASTE_BUF_SIZE - paste_len));
		if (n <= 0)
			break;	/* EAGAIN or real error */
		paste_len += (int)n;
	}

	/* Restore blocking mode */
	fcntl(tty_fd, F_SETFL, flags);
}

/*
 * paste_extract_line() — pull the next complete line from paste_buf.
 *
 * Scans for \n or \r, strips leading whitespace (indentation from
 * pasted config blocks), skips empty lines, copies result into
 * line_buf, advances paste_pos.
 *
 * Returns 1 if a line was extracted, 0 if no complete line available.
 */
static int paste_extract_line(void)
{
	while (paste_pos < paste_len) {
		/* Find next newline */
		int start = paste_pos;
		int eol = -1;
		for (int i = start; i < paste_len; i++) {
			if (paste_buf[i] == '\n' || paste_buf[i] == '\r') {
				eol = i;
				break;
			}
		}
		if (eol < 0)
			return 0;	/* no complete line yet */

		/* Advance past the newline (and optional \r\n pair) */
		paste_pos = eol + 1;
		if (paste_pos < paste_len &&
		    paste_buf[eol] == '\r' &&
		    paste_buf[paste_pos] == '\n')
			paste_pos++;

		/* Strip leading whitespace */
		while (start < eol &&
		       (paste_buf[start] == ' ' || paste_buf[start] == '\t'))
			start++;

		int llen = eol - start;
		if (llen <= 0)
			continue;	/* skip empty lines */

		if (llen >= CLI_MAX_LINE)
			llen = CLI_MAX_LINE - 1;
		memcpy(line_buf, paste_buf + start, (size_t)llen);
		line_buf[llen] = '\0';
		return 1;
	}
	return 0;
}

/* ── Public terminal API ──────────────────────────────────────────────── */

int cli_term_init(void)
{
	if (tty_fd >= 0)
		return 0;	/* already initialized */

	tty_fd = open_terminal();
	if (tty_fd < 0) {
		/* Last resort: stdin might be the terminal */
		if (isatty(STDIN_FILENO))
			tty_fd = dup(STDIN_FILENO);
	}
	if (tty_fd < 0)
		return -1;

	/* Discard any input typed before CLI was ready (during boot/login).
	 * Without this, stale keystrokes echo into the first prompt. */
	tcflush(tty_fd, TCIFLUSH);

	/* Capture the true original termios now so cli_term_cleanup() can
	 * always restore a real setting — even if the process exits before
	 * enable_raw() ever ran (sandbox failure, early WHOAMI exit). */
	if (tcgetattr(tty_fd, &orig_termios) == 0)
		have_orig = 1;

	current_comps.count = 0;
	stack_depth = 0;
	return 0;
}

void cli_term_cleanup(void)
{
	/* Restore true original terminal settings (with ECHO) on exit —
	 * but only if we actually captured them, else we'd apply a zeroed
	 * termios and leave the parent shell in a degraded state. */
	if (tty_fd >= 0) {
		if (have_orig)
			tcsetattr(tty_fd, TCSANOW, &orig_termios);
		close(tty_fd);
		tty_fd = -1;
	}
	raw_mode = 0;
}

int cli_get_tty_fd(void)
{
	return tty_fd;
}

void cli_term_echo_on(void)
{
	if (tty_fd < 0) return;
	struct termios t;
	if (tcgetattr(tty_fd, &t) != 0) return;
	t.c_lflag |= (unsigned)(ECHO | ICANON);
	tcsetattr(tty_fd, TCSANOW, &t);
}

void cli_term_echo_off(void)
{
	if (tty_fd < 0) return;
	struct termios t;
	if (tcgetattr(tty_fd, &t) != 0) return;
	t.c_lflag &= ~(unsigned)(ECHO | ICANON);
	tcsetattr(tty_fd, TCSANOW, &t);
}

/* ── Completion registry ──────────────────────────────────────────────── */

void cli_register(const char *path, const char *desc)
{
	if (current_comps.count >= CLI_MAX_COMPS)
		return;

	struct cli_completion *e = &current_comps.entries[current_comps.count];
	strncpy(e->path, path ? path : "", CLI_MAX_LINE - 1);
	e->path[CLI_MAX_LINE - 1] = '\0';
	strncpy(e->desc, desc ? desc : "", CLI_MAX_DESC - 1);
	e->desc[CLI_MAX_DESC - 1] = '\0';
	current_comps.count++;
}

void cli_push(void)
{
	if (stack_depth >= CLI_MAX_STACK)
		return;

	memcpy(&comp_stack[stack_depth], &current_comps,
	       sizeof(struct cli_comp_set));
	stack_depth++;
	current_comps.count = 0;
}

void cli_pop(void)
{
	if (stack_depth <= 0)
		return;

	stack_depth--;
	memcpy(&current_comps, &comp_stack[stack_depth],
	       sizeof(struct cli_comp_set));
}

void cli_clear(void)
{
	current_comps.count = 0;
}

void cli_print_help(void)
{
	/* Find longest command path for alignment */
	int max_len = 0;
	for (int i = 0; i < current_comps.count; i++) {
		int len = (int)strlen(current_comps.entries[i].path);
		if (len > max_len)
			max_len = len;
	}
	if (max_len > 40)
		max_len = 40;

	printf("\n  === Stargazer NGFW — Command Reference ===\n\n");
	for (int i = 0; i < current_comps.count; i++) {
		printf("  %-*s  %s\n", max_len,
		       current_comps.entries[i].path,
		       current_comps.entries[i].desc);
	}
	printf("\n  Press Tab for completion, ? for context help.\n\n");
}

/* ── Terminal dimensions ───────────────────────────────────────────────── */

static int get_term_cols(void)
{
	struct winsize ws;
	if (tty_fd >= 0 && ioctl(tty_fd, TIOCGWINSZ, &ws) == 0 &&
	    ws.ws_col > 0)
		return ws.ws_col;
	return 80;
}

/* ── Redraw ───────────────────────────────────────────────────────────── */

/*
 * Track which terminal row the cursor sits on (0-based, relative to
 * the start of the prompt).  Needed so full-redraw can move the
 * terminal cursor back to row 0 before clearing + rewriting.
 */
static int rl_cursor_row;

/*
 * Full redraw: moves to the start of the prompt, clears everything
 * below (multi-row safe), writes prompt + full buffer, then positions
 * the cursor at the requested offset.  The terminal wraps naturally
 * when content exceeds the width — no horizontal scrolling.
 *
 * All output is batched into one write() to avoid flicker on serial.
 */
static void redraw_at(const char *prompt, const char *buf, int cursor)
{
	int cols = get_term_cols();
	int plen = (int)strlen(prompt);
	int blen = (int)strlen(buf);

	char out[CLI_MAX_LINE + CLI_MAX_LINE + 128];
	int o = 0;

	/* Step 1: move to the first row of our content */
	if (rl_cursor_row > 0)
		o += snprintf(out + o, sizeof(out) - (size_t)o,
			      "\033[%dA", rl_cursor_row);
	out[o++] = '\r';

	/* Step 2: clear from here to end of screen (all wrapped rows) */
	memcpy(out + o, "\033[J", 3);
	o += 3;

	/* Step 3: write prompt + buffer (terminal wraps naturally) */
	memcpy(out + o, prompt, (size_t)plen);
	o += plen;
	if (blen > 0) {
		memcpy(out + o, buf, (size_t)blen);
		o += blen;
	}

	/* Force deferred wrap: if content ends at exact column boundary,
	 * the terminal holds cursor at rightmost col (pending wrap).
	 * Emit \n\r to resolve it so row tracking stays correct. */
	int end_abs_chk = plen + blen;
	if (cols > 0 && end_abs_chk > 0 && end_abs_chk % cols == 0) {
		out[o++] = '\n';
		out[o++] = '\r';
	}

	/* Step 4: position cursor at the requested offset.
	 * After writing, cursor is at char position (plen + blen).
	 * We want it at (plen + cursor). */
	int end_abs  = plen + blen;
	int end_row  = cols > 0 ? end_abs / cols : 0;
	int want_abs = plen + cursor;
	int want_row = cols > 0 ? want_abs / cols : 0;
	int want_col = cols > 0 ? want_abs % cols : 0;

	if (end_row > want_row)
		o += snprintf(out + o, sizeof(out) - (size_t)o,
			      "\033[%dA", end_row - want_row);
	/* Set column absolutely (1-based) */
	o += snprintf(out + o, sizeof(out) - (size_t)o,
		      "\033[%dG", want_col + 1);

	tty_write(tty_fd, out, (size_t)o);
	rl_cursor_row = want_row;
}


/*
 * Redraw buffer only — keeps the prompt on screen.
 * Moves cursor to the start of the buffer (right after prompt),
 * clears everything after, writes the new buffer, positions cursor.
 * Used for history up/down, tab completion, ctrl-u.
 */
static void redraw_buf(const char *prompt, const char *buf, int cursor)
{
	int cols = get_term_cols();
	int plen = (int)strlen(prompt);
	int blen = (int)strlen(buf);

	/* Where the buffer starts (right after prompt) */
	int buf_start_row = cols > 0 ? plen / cols : 0;
	int buf_start_col = cols > 0 ? plen % cols : 0;

	char out[CLI_MAX_LINE + 128];
	int o = 0;

	/* Move cursor to buffer start position */
	if (rl_cursor_row > buf_start_row)
		o += snprintf(out + o, sizeof(out) - (size_t)o,
			      "\033[%dA", rl_cursor_row - buf_start_row);
	else if (rl_cursor_row < buf_start_row)
		o += snprintf(out + o, sizeof(out) - (size_t)o,
			      "\033[%dB", buf_start_row - rl_cursor_row);
	o += snprintf(out + o, sizeof(out) - (size_t)o,
		      "\033[%dG", buf_start_col + 1);

	/* Clear from here to end of screen */
	memcpy(out + o, "\033[J", 3);
	o += 3;

	/* Write buffer */
	if (blen > 0) {
		memcpy(out + o, buf, (size_t)blen);
		o += blen;
	}

	/* Force deferred wrap at exact column boundary */
	int end_abs_chk = plen + blen;
	if (cols > 0 && end_abs_chk > 0 && end_abs_chk % cols == 0) {
		out[o++] = '\n';
		out[o++] = '\r';
	}

	/* Position cursor */
	int end_abs  = plen + blen;
	int end_row  = cols > 0 ? end_abs / cols : 0;
	int want_abs = plen + cursor;
	int want_row = cols > 0 ? want_abs / cols : 0;
	int want_col = cols > 0 ? want_abs % cols : 0;

	if (end_row > want_row)
		o += snprintf(out + o, sizeof(out) - (size_t)o,
			      "\033[%dA", end_row - want_row);
	o += snprintf(out + o, sizeof(out) - (size_t)o,
		      "\033[%dG", want_col + 1);

	tty_write(tty_fd, out, (size_t)o);
	rl_cursor_row = want_row;
}

/*
 * Redraw from a given buffer position to end of buffer.
 *
 * @from:   buffer offset where rewriting starts (clear + rewrite)
 * @cursor: buffer offset where the terminal cursor should end up
 *
 * Positions the terminal cursor at @from (using absolute escapes,
 * so callers don't need to pre-position), clears to end of screen,
 * writes buf[from..blen-1], then positions cursor at @cursor.
 *
 * Used for delete/backspace/insert in the middle of the line.
 * For delete/backspace: from == cursor (both at the deletion point).
 * For insert-in-middle: from = cursor - inserted_len (start at the
 * inserted text), cursor = after the inserted text.
 */
static void redraw_from(const char *prompt, const char *buf,
			int from, int cursor)
{
	int cols = get_term_cols();
	int plen = (int)strlen(prompt);
	int blen = (int)strlen(buf);
	int tail = blen - from;

	char out[CLI_MAX_LINE + 128];
	int o = 0;

	/* Step 1: move terminal cursor to the 'from' position */
	int from_abs = plen + from;
	int from_row = cols > 0 ? from_abs / cols : 0;
	int from_col = cols > 0 ? from_abs % cols : 0;

	if (rl_cursor_row > from_row)
		o += snprintf(out + o, sizeof(out) - (size_t)o,
			      "\033[%dA", rl_cursor_row - from_row);
	else if (rl_cursor_row < from_row)
		o += snprintf(out + o, sizeof(out) - (size_t)o,
			      "\033[%dB", from_row - rl_cursor_row);
	o += snprintf(out + o, sizeof(out) - (size_t)o,
		      "\033[%dG", from_col + 1);

	/* Step 2: clear from here to end of screen */
	memcpy(out + o, "\033[J", 3);
	o += 3;

	/* Step 3: write buffer from 'from' to end */
	if (tail > 0) {
		memcpy(out + o, buf + from, (size_t)tail);
		o += tail;
	}

	/* Force deferred wrap at exact column boundary */
	int end_abs_chk = plen + blen;
	if (cols > 0 && end_abs_chk > 0 && end_abs_chk % cols == 0) {
		out[o++] = '\n';
		out[o++] = '\r';
	}

	/* Step 4: position cursor at 'cursor' */
	int end_abs  = plen + blen;
	int end_row  = cols > 0 ? end_abs / cols : 0;
	int want_abs = plen + cursor;
	int want_row = cols > 0 ? want_abs / cols : 0;
	int want_col = cols > 0 ? want_abs % cols : 0;

	if (end_row > want_row)
		o += snprintf(out + o, sizeof(out) - (size_t)o,
			      "\033[%dA", end_row - want_row);
	o += snprintf(out + o, sizeof(out) - (size_t)o,
		      "\033[%dG", want_col + 1);

	tty_write(tty_fd, out, (size_t)o);
	rl_cursor_row = want_row;
}

/* ── Word extraction (nth word from string) ───────────────────────────── */

static int word_count(const char *s)
{
	int n = 0;
	int in_word = 0;

	for (; *s; s++) {
		if (*s == ' ') {
			in_word = 0;
		} else if (!in_word) {
			in_word = 1;
			n++;
		}
	}
	return n;
}

static const char *nth_word(const char *s, int n, int *wlen)
{
	int idx = 0;
	const char *start = NULL;
	int in_word = 0;

	for (; *s; s++) {
		if (*s == ' ') {
			if (in_word && idx == n) {
				*wlen = (int)(s - start);
				return start;
			}
			in_word = 0;
		} else if (!in_word) {
			in_word = 1;
			idx++;
			start = s;
		}
	}
	if (in_word && idx == n) {
		*wlen = (int)(s - start);
		return start;
	}
	*wlen = 0;
	return NULL;
}

/* ── Tab completion ───────────────────────────────────────────────────── */

static int tab_find_matches(const char *buf,
			    char matches[][CLI_MAX_LINE], int max_matches)
{
	int count = 0;
	int trailing_space = (buf[0] != '\0' && buf[strlen(buf) - 1] == ' ');

	if (trailing_space) {
		/* Complete next word */
		int depth = word_count(buf);
		int target = depth + 1;

		for (int i = 0; i < current_comps.count && count < max_matches; i++) {
			if (strncmp(current_comps.entries[i].path, buf,
				    strlen(buf)) != 0)
				continue;
			int wl;
			const char *w = nth_word(current_comps.entries[i].path,
						 target, &wl);
			if (!w || wl == 0)
				continue;

			/* Build candidate: buf + word */
			char cand[CLI_MAX_LINE];
			snprintf(cand, sizeof(cand), "%.*s%.*s",
				 (int)strlen(buf), buf, wl, w);

			/* Deduplicate */
			int dup = 0;
			for (int j = 0; j < count; j++) {
				if (strcmp(matches[j], cand) == 0) {
					dup = 1;
					break;
				}
			}
			if (!dup)
				snprintf(matches[count++], CLI_MAX_LINE,
					 "%s", cand);
		}
	} else {
		/* Complete partial word */
		int nw = word_count(buf);
		if (nw <= 1) {
			/* Single partial word */
			for (int i = 0; i < current_comps.count && count < max_matches; i++) {
				int wl;
				const char *first = nth_word(
					current_comps.entries[i].path, 1, &wl);
				if (!first)
					continue;
				if (strncmp(first, buf, strlen(buf)) != 0)
					continue;

				char cand[CLI_MAX_LINE];
				snprintf(cand, sizeof(cand), "%.*s", wl, first);

				int dup = 0;
				for (int j = 0; j < count; j++) {
					if (strcmp(matches[j], cand) == 0) {
						dup = 1;
						break;
					}
				}
				if (!dup)
					snprintf(matches[count++], CLI_MAX_LINE,
						 "%s", cand);
			}
		} else {
			/* Multi-word: find prefix and partial */
			const char *last_space = strrchr(buf, ' ');
			if (!last_space)
				return 0;
			int prefix_len = (int)(last_space - buf + 1);
			const char *partial = last_space + 1;
			size_t plen = strlen(partial);

			for (int i = 0; i < current_comps.count && count < max_matches; i++) {
				if (strncmp(current_comps.entries[i].path, buf,
					    (size_t)prefix_len) != 0)
					continue;
				/* Check the next word starts with partial */
				const char *rest =
					current_comps.entries[i].path + prefix_len;
				if (strncmp(rest, partial, plen) != 0)
					continue;

				int wl;
				const char *w = nth_word(
					current_comps.entries[i].path, nw, &wl);
				if (!w)
					continue;

				char cand[CLI_MAX_LINE];
				snprintf(cand, sizeof(cand), "%.*s%.*s",
					 prefix_len, buf, wl, w);

				int dup = 0;
				for (int j = 0; j < count; j++) {
					if (strcmp(matches[j], cand) == 0) {
						dup = 1;
						break;
					}
				}
				if (!dup)
					snprintf(matches[count++], CLI_MAX_LINE,
						 "%s", cand);
			}
		}
	}

	return count;
}

/* ── ? help ───────────────────────────────────────────────────────────── */

static void show_help(const char *buf)
{
	int trailing_space = (buf[0] != '\0' && buf[strlen(buf) - 1] == ' ');
	int depth;
	const char *pattern;
	int target;
	char exact_cmd[CLI_MAX_LINE];
	char exact_desc[CLI_MAX_DESC];

	exact_cmd[0] = '\0';
	exact_desc[0] = '\0';

	if (buf[0] == '\0') {
		depth = 0;
		target = 1;
		pattern = "";
	} else if (trailing_space) {
		depth = word_count(buf);
		target = depth + 1;
		pattern = buf;
	} else {
		/* Partial — show matches at current level */
		depth = word_count(buf);
		target = depth;
		const char *last_space = strrchr(buf, ' ');
		if (last_space)
			pattern = buf;	/* full match prefix */
		else
			pattern = "";
	}

	if (buf[0] != '\0') {
		snprintf(exact_cmd, sizeof(exact_cmd), "%s", buf);
		while (exact_cmd[0] != '\0' &&
		       exact_cmd[strlen(exact_cmd) - 1] == ' ')
			exact_cmd[strlen(exact_cmd) - 1] = '\0';
	}

	if (exact_cmd[0] != '\0') {
		for (int i = 0; i < current_comps.count; i++) {
			if (strcmp(current_comps.entries[i].path,
				   exact_cmd) == 0) {
				snprintf(exact_desc, sizeof(exact_desc), "%s",
					 current_comps.entries[i].desc);
				break;
			}
		}
	}

	if (exact_cmd[0] != '\0' && exact_desc[0] != '\0') {
		char enter_line[CLI_MAX_LINE];
		snprintf(enter_line, sizeof(enter_line),
			 "  %-24s %s\r\n", "<Enter>", exact_desc);
		tty_write(tty_fd, enter_line, strlen(enter_line));
	}

	char seen[CLI_MAX_COMPS][64];
	int nseen = 0;

	for (int i = 0; i < current_comps.count; i++) {
		/* Check if path matches pattern prefix */
		if (pattern[0] != '\0') {
			if (trailing_space || buf[0] == '\0') {
				if (strncmp(current_comps.entries[i].path,
					    pattern, strlen(pattern)) != 0)
					continue;
			} else {
				/* Partial match: check the full buf as prefix */
				size_t blen = strlen(buf);
				if (strncmp(current_comps.entries[i].path,
					    buf, blen) != 0) {
					/* Also try matching up to last space */
					const char *ls = strrchr(buf, ' ');
					if (ls) {
						size_t pl = (size_t)(ls - buf + 1);
						if (strncmp(current_comps.entries[i].path,
							    buf, pl) != 0)
							continue;
					} else {
						continue;
					}
				}
			}
		}

		int wl;
		const char *w = nth_word(current_comps.entries[i].path,
					 target, &wl);
		if (!w || wl == 0)
			continue;

		/* Deduplicate by word */
		char word[64];
		int copy_len = wl < 63 ? wl : 63;
		memcpy(word, w, (size_t)copy_len);
		word[copy_len] = '\0';

		int dup = 0;
		for (int j = 0; j < nseen; j++) {
			if (strcmp(seen[j], word) == 0) {
				dup = 1;
				break;
			}
		}
		if (dup)
			continue;
		if (nseen < CLI_MAX_COMPS)
			snprintf(seen[nseen++], 64, "%s", word);

		/* Print with padding */
		char line[CLI_MAX_LINE];
		snprintf(line, sizeof(line), "  %-24s %s\r\n", word,
			 current_comps.entries[i].desc);
		tty_write(tty_fd, line, strlen(line));
	}

	if (nseen == 0) {
		if (buf[0] != '\0' && exact_desc[0] == '\0') {
			const char *msg = "  Not a command.\r\n";
			tty_write(tty_fd, msg, strlen(msg));
		} else if (buf[0] == '\0') {
			const char *msg = "  <cr>  Execute command\r\n";
			tty_write(tty_fd, msg, strlen(msg));
		}
	}
}

/* ── History ──────────────────────────────────────────────────────────── */

static void hist_add(const char *line)
{
	if (!line[0])
		return;
	/* Don't duplicate last entry */
	if (nhist > 0 && strcmp(hist[nhist - 1], line) == 0)
		return;
	if (nhist < CLI_MAX_HIST) {
		snprintf(hist[nhist++], CLI_MAX_LINE, "%s", line);
	} else {
		/* Shift up */
		memmove(hist[0], hist[1],
			(size_t)(CLI_MAX_HIST - 1) * CLI_MAX_LINE);
		snprintf(hist[CLI_MAX_HIST - 1], CLI_MAX_LINE, "%s", line);
	}
}

/* ── IPC-based history (works inside sandbox) ─────────────────────────── */

#include "cli_ipc.h"

void cli_hist_load_ipc(void)
{
	struct ipc_response resp = {0};
	if (ipc_send_str(SG_CMD_HISTORY_LOAD, "", &resp) != 0 ||
	    resp.status != SG_OK || !resp.payload) {
		ipc_resp_free(&resp);
		return;
	}

	/* Parse lines from response */
	char *p = resp.payload;
	while (*p) {
		char *nl = strchr(p, '\n');
		if (nl) *nl = '\0';

		size_t len = strlen(p);
		while (len > 0 && (p[len - 1] == '\r'))
			p[--len] = '\0';

		if (len > 0)
			hist_add(p);

		if (!nl) break;
		p = nl + 1;
	}

	ipc_resp_free(&resp);
}

void cli_hist_save_ipc(const char *username)
{
	if (nhist == 0 || !username || !username[0])
		return;

	/* Build payload: "user=<username>\n<line1>\n<line2>\n..."
	 * Capped at SG_PAYLOAD_MAX — the IPC layer rejects larger messages.
	 * Heap-allocated to avoid a 51 KB stack frame. */
	char *payload = malloc(SG_PAYLOAD_MAX);
	if (!payload)
		return;

	size_t pos = 0;

	int n = snprintf(payload, SG_PAYLOAD_MAX, "user=%s\n", username);
	/* snprintf returns the untruncated length; clamp so an over-long
	 * username cannot push pos past the buffer for the loop below
	 * (same guard the per-line append already applies). */
	if (n > 0 && (size_t)n < SG_PAYLOAD_MAX)
		pos = (size_t)n;

	for (int i = 0; i < nhist; i++) {
		n = snprintf(payload + pos, SG_PAYLOAD_MAX - pos,
			     "%s\n", hist[i]);
		if (n > 0 && (size_t)n < SG_PAYLOAD_MAX - pos)
			pos += (size_t)n;
	}

	struct ipc_response resp = {0};
	if (ipc_send(SG_CMD_HISTORY_SAVE, payload, pos, &resp) < 0)
		fprintf(stderr, "cli: history save failed (IPC error)\n");
	ipc_resp_free(&resp);
	free(payload);
}

/* ── Abbreviation resolution ──────────────────────────────────────────── */

int cli_resolve_cmd(const char *input, char *output, size_t out_sz)
{
	int nwords = word_count(input);

	if (nwords == 0) {
		if (out_sz > 0)
			output[0] = '\0';
		return 0;
	}

	char resolved[CLI_MAX_LINE];
	size_t rpos = 0;

	resolved[0] = '\0';

	for (int depth = 1; depth <= nwords; depth++) {
		int iwlen;
		const char *iw = nth_word(input, depth, &iwlen);

		if (!iw || iwlen == 0)
			break;

		/* Collect unique candidate words at this depth */
		char cands[64][64];
		int ncands = 0;
		int exact = 0;
		char exact_word[64];

		for (int i = 0; i < current_comps.count; i++) {
			/* Words 1..depth-1 must match resolved prefix */
			int prefix_ok = 1;

			for (int d = 1; d < depth; d++) {
				int rwlen, ewlen;
				const char *rw = nth_word(resolved,
							  d, &rwlen);
				const char *ew = nth_word(
					current_comps.entries[i].path,
					d, &ewlen);

				if (!rw || !ew || rwlen != ewlen ||
				    strncmp(rw, ew,
					    (size_t)rwlen) != 0) {
					prefix_ok = 0;
					break;
				}
			}
			if (!prefix_ok)
				continue;

			int ewlen;
			const char *ew = nth_word(
				current_comps.entries[i].path,
				depth, &ewlen);

			if (!ew || ewlen == 0)
				continue;

			/* Exact match takes priority */
			if (ewlen == iwlen &&
			    strncmp(ew, iw, (size_t)iwlen) == 0) {
				exact = 1;
				int cl = ewlen < 63 ? ewlen : 63;
				memcpy(exact_word, ew, (size_t)cl);
				exact_word[cl] = '\0';
				break;
			}

			/* Prefix match */
			if (ewlen > iwlen &&
			    strncmp(ew, iw, (size_t)iwlen) == 0) {
				char cand[64];
				int cl = ewlen < 63 ? ewlen : 63;
				memcpy(cand, ew, (size_t)cl);
				cand[cl] = '\0';

				int dup = 0;
				for (int j = 0; j < ncands; j++) {
					if (strcmp(cands[j], cand) == 0) {
						dup = 1;
						break;
					}
				}
				if (!dup && ncands < 64)
					snprintf(cands[ncands++], 64,
						 "%s", cand);
			}
		}

		if (exact) {
			if (rpos > 0)
				resolved[rpos++] = ' ';
			size_t wl = strlen(exact_word);
			if (rpos + wl < sizeof(resolved)) {
				memcpy(resolved + rpos, exact_word, wl);
				rpos += wl;
			}
			resolved[rpos] = '\0';
		} else if (ncands == 1) {
			if (rpos > 0)
				resolved[rpos++] = ' ';
			size_t wl = strlen(cands[0]);
			if (rpos + wl < sizeof(resolved)) {
				memcpy(resolved + rpos, cands[0], wl);
				rpos += wl;
			}
			resolved[rpos] = '\0';
		} else if (ncands > 1) {
			printf("  Ambiguous command: '%.*s',"
			       " could be:", iwlen, iw);
			for (int j = 0; j < ncands; j++)
				printf(" %s", cands[j]);
			printf("\n");
			return -1;
		} else {
			/* No match — pass through remaining words */
			for (int d = depth; d <= nwords; d++) {
				int wl;
				const char *w = nth_word(input, d, &wl);
				if (!w)
					break;
				if (rpos > 0)
					resolved[rpos++] = ' ';
				if (rpos + (size_t)wl < sizeof(resolved)) {
					memcpy(resolved + rpos,
					       w, (size_t)wl);
					rpos += (size_t)wl;
				}
				resolved[rpos] = '\0';
			}
			break;
		}
	}

	snprintf(output, out_sz, "%s", resolved);
	return 0;
}

/* ── Main readline loop ──────────────────────────────────────────────── */

const char *cli_readline(const char *prompt)
{
	char buf[CLI_MAX_LINE];
	int pos = 0;		/* buffer length */
	int cursor = 0;		/* cursor position within buffer */

	/* Tab state */
	char tab_matches[64][CLI_MAX_LINE];
	int tab_count = 0;
	int tab_idx = 0;
	int tab_active = 0;
	char tab_base[CLI_MAX_LINE];

	int hist_idx = nhist;
	char hist_saved[CLI_MAX_LINE];

	buf[0] = '\0';
	tab_base[0] = '\0';
	hist_saved[0] = '\0';

	if (tty_fd < 0)
		return NULL;

	/* Fast-path: serve lines from paste buffer before touching tty */
	if (paste_extract_line()) {
		printf("%s%s\n", prompt, line_buf);
		fflush(stdout);
		hist_add(line_buf);
		return line_buf;
	}

	/*
	 * If the paste buffer has a partial line (no trailing newline),
	 * seed the char-by-char buffer with it.  Without this, the
	 * fragment stays in paste_buf and drain_pending() would later
	 * compact it to the front, merging it with the NEXT line's data
	 * (because the continuation was already consumed by char-by-char
	 * reading).
	 */
	if (paste_pos < paste_len) {
		int remaining = paste_len - paste_pos;
		if (remaining > 0 && remaining < CLI_MAX_LINE - 1) {
			/* Strip leading whitespace like paste_extract_line */
			int s = paste_pos;
			while (s < paste_len &&
			       (paste_buf[s] == ' ' || paste_buf[s] == '\t'))
				s++;
			int frag_len = paste_len - s;
			if (frag_len > 0 && frag_len < CLI_MAX_LINE - 1) {
				memcpy(buf, paste_buf + s, (size_t)frag_len);
				buf[frag_len] = '\0';
				pos = frag_len;
				cursor = frag_len;
			}
		}
		paste_pos = paste_len = 0;
	}

	/* Discard any input typed during command execution.  ECHO is off
	 * between readline calls so keystrokes aren't visible, but they
	 * still accumulate in the kernel tty buffer.  Flush them before
	 * switching to raw mode so they don't leak into the next command. */
	if (paste_pos >= paste_len)
		tcflush(tty_fd, TCIFLUSH);

	if (enable_raw() != 0) {
		/* Fallback: just read a line in cooked mode.
		 * Arrow keys and history will NOT work. */
		static int warned;
		if (!warned) {
			const char *msg =
				"\r\n  [warn] raw mode unavailable — "
				"arrow keys/history disabled\r\n";
			tty_write(tty_fd, msg, strlen(msg));
			warned = 1;
		}
		int rfd = tty_fd;
		char ch;
		/* Continue after any paste fragment already seeded into buf
		 * above (pos/cursor) rather than overwriting it from 0. */
		int bpos = (pos > 0 && pos < CLI_MAX_LINE - 1) ? pos : 0;

		tty_write(tty_fd, prompt, strlen(prompt));
		if (bpos > 0)
			tty_write(tty_fd, buf, (size_t)bpos);
		while (bpos < CLI_MAX_LINE - 1) {
			if (read(rfd, &ch, 1) <= 0)
				break;
			if (ch == '\n' || ch == '\r')
				break;
			buf[bpos++] = ch;
		}
		buf[bpos] = '\0';
		snprintf(line_buf, sizeof(line_buf), "%s", buf);
		return line_buf;
	}

	rl_cursor_row = 0;
	tty_write(tty_fd, prompt, strlen(prompt));
	if (pos > 0) {
		tty_write(tty_fd, buf, (size_t)pos);
		int cols = get_term_cols();
		int seed_abs = (int)strlen(prompt) + pos;
		/* Force deferred wrap at exact column boundary */
		if (cols > 0 && seed_abs > 0 && seed_abs % cols == 0)
			tty_write(tty_fd, "\n\r", 2);
		rl_cursor_row = cols > 0 ? seed_abs / cols : 0;
	}

	while (1) {
		/* ── Idle callback with 5-second poll ────────────── */
		if (rl_idle_cb) {
			struct timespec now;
			clock_gettime(CLOCK_MONOTONIC, &now);
			long elapsed = now.tv_sec - last_idle_check.tv_sec;
			if (elapsed >= 5) {
				if (rl_idle_cb() != 0) {
					disable_raw();
					return NULL;
				}
				clock_gettime(CLOCK_MONOTONIC,
					      &last_idle_check);
				elapsed = 0;
			}
			struct timespec timeout;
			timeout.tv_sec  = 5 - elapsed;
			timeout.tv_nsec = 0;
			struct pollfd pfd = { .fd = tty_fd,
					      .events = POLLIN };
			int pr = ppoll(&pfd, 1, &timeout, NULL);
			if (pr == 0)
				continue;	/* timeout — check fires */
			if (pr < 0) {
				if (errno == EINTR)
					continue;
				paste_pos = paste_len = 0;
				disable_raw();
				return NULL;
			}
		}

		char c;
		ssize_t n = read(tty_fd, &c, 1);
		if (n <= 0) {
			paste_pos = paste_len = 0;
			disable_raw();
			return NULL;	/* EOF */
		}

		switch (c) {
		case '\r':
		case '\n':
			tty_write(tty_fd, "\r\n", 2);
			hist_add(buf);
			drain_pending();
			disable_raw();
			snprintf(line_buf, sizeof(line_buf), "%s", buf);
			return line_buf;

		case 3: /* Ctrl-C */
			buf[0] = '\0';
			pos = 0;
			cursor = 0;
			paste_pos = paste_len = 0;	/* cancel entire paste */
			tcflush(tty_fd, TCIFLUSH);	/* discard tty input */
			tty_write(tty_fd, "\r\n", 2);
			disable_raw();
			line_buf[0] = '\0';
			return line_buf;

		case 1: /* Ctrl-A — move cursor to start of line */
			if (cursor > 0) {
				cursor = 0;
				int cols = get_term_cols();
				int plen = (int)strlen(prompt);
				int wr = cols > 0 ? plen / cols : 0;
				int wc = cols > 0 ? plen % cols : 0;
				char esc[32];
				int el = 0;
				if (rl_cursor_row > wr)
					el += snprintf(esc + el,
						       sizeof(esc) - (size_t)el,
						       "\033[%dA",
						       rl_cursor_row - wr);
				el += snprintf(esc + el,
					       sizeof(esc) - (size_t)el,
					       "\033[%dG", wc + 1);
				tty_write(tty_fd, esc, (size_t)el);
				rl_cursor_row = wr;
			}
			break;

		case 4: /* Ctrl-D — EOF on empty line, delete char otherwise */
			if (pos == 0) {
				paste_pos = paste_len = 0;
				tcflush(tty_fd, TCIFLUSH);
				tty_write(tty_fd, "\r\n", 2);
				disable_raw();
				return NULL;	/* EOF on empty line */
			}
			if (cursor < pos) {
				int next = cursor + 1;
				while (next < pos &&
				       (buf[next] & 0xC0) == 0x80)
					next++;
				memmove(buf + cursor, buf + next,
					(size_t)(pos - next + 1));
				pos -= (next - cursor);
				redraw_from(prompt, buf, cursor, cursor);
			}
			break;

		case 5: /* Ctrl-E — move cursor to end of line */
			if (cursor < pos) {
				cursor = pos;
				int cols = get_term_cols();
				int wa = (int)strlen(prompt) + pos;
				int wr = cols > 0 ? wa / cols : 0;
				int wc = cols > 0 ? wa % cols : 0;
				char esc[32];
				int el = 0;
				if (wr > rl_cursor_row)
					el += snprintf(esc + el,
						       sizeof(esc) - (size_t)el,
						       "\033[%dB",
						       wr - rl_cursor_row);
				el += snprintf(esc + el,
					       sizeof(esc) - (size_t)el,
					       "\033[%dG", wc + 1);
				tty_write(tty_fd, esc, (size_t)el);
				rl_cursor_row = wr;
			}
			break;

		case 21: /* Ctrl-U — clear line */
			buf[0] = '\0';
			pos = 0;
			cursor = 0;
			tab_count = 0;
			tab_active = 0;
			redraw_buf(prompt, buf, cursor);
			break;

		case 23: /* Ctrl-W — delete word before cursor */
			if (cursor > 0) {
				int old_cursor = cursor;
				while (cursor > 0 && buf[cursor - 1] == ' ')
					cursor--;
				while (cursor > 0 && buf[cursor - 1] != ' ')
					cursor--;
				memmove(buf + cursor, buf + old_cursor,
					(size_t)(pos - old_cursor + 1));
				pos -= (old_cursor - cursor);
			}
			tab_count = 0;
			tab_active = 0;
			redraw_from(prompt, buf, cursor, cursor);
			break;

		case 27: { /* ESC sequence */
			char seq[2];
			/* A lone Escape press sends only 0x1b. With VMIN=1 a
			 * blocking read() would hang until the next keystroke,
			 * appearing frozen. Poll briefly for the CSI/SS3
			 * continuation; if none arrives, treat ESC as a no-op. */
			struct pollfd epf = { .fd = tty_fd, .events = POLLIN };
			if (poll(&epf, 1, 50) <= 0 || !(epf.revents & POLLIN))
				break;
			if (read(tty_fd, &seq[0], 1) <= 0)
				break;
			if (poll(&epf, 1, 50) <= 0 || !(epf.revents & POLLIN))
				break;
			if (read(tty_fd, &seq[1], 1) <= 0)
				break;
			/*
			 * Handle both CSI (\033[) and SS3 (\033O)
			 * prefixes. Some terminals (VT100 application
			 * mode, QEMU console) send \033O for arrow
			 * keys instead of \033[.
			 */
			if (seq[0] == '[' || seq[0] == 'O') {
				if (seq[1] == 'A') { /* Up */
					if (hist_idx == nhist)
						snprintf(hist_saved,
							 sizeof(hist_saved),
							 "%s", buf);
					if (hist_idx > 0) {
						hist_idx--;
						snprintf(buf, sizeof(buf),
							 "%s",
							 hist[hist_idx]);
						pos = (int)strlen(buf);
						cursor = pos;
						redraw_buf(prompt, buf, cursor);
					}
					tab_count = 0;
					tab_active = 0;
				} else if (seq[1] == 'B') { /* Down */
					if (hist_idx < nhist) {
						hist_idx++;
						if (hist_idx == nhist) {
							snprintf(buf,
								 sizeof(buf),
								 "%s",
								 hist_saved);
							pos = (int)strlen(buf);
						} else {
							snprintf(buf,
								 sizeof(buf),
								 "%s",
								 hist[hist_idx]);
							pos = (int)strlen(buf);
						}
						cursor = pos;
						redraw_buf(prompt, buf, cursor);
					}
					tab_count = 0;
					tab_active = 0;
				} else if (seq[1] == 'C') { /* Right */
					if (cursor < pos) {
						int prev = cursor;
						cursor++;
						while (cursor < pos &&
						       (buf[cursor] & 0xC0) == 0x80)
							cursor++;
						int cols = get_term_cols();
						int pa = (int)strlen(prompt) + prev;
						int na = (int)strlen(prompt) + cursor;
						int pr2 = cols > 0 ? pa / cols : 0;
						int nr = cols > 0 ? na / cols : 0;
						if (nr == pr2) {
							char esc[16];
							int el = snprintf(esc, sizeof(esc),
									  "\033[%dC",
									  cursor - prev);
							tty_write(tty_fd, esc, (size_t)el);
						} else {
							int nc = cols > 0 ? na % cols : 0;
							char esc[32];
							int el = snprintf(esc, sizeof(esc),
									  "\033[B\033[%dG",
									  nc + 1);
							tty_write(tty_fd, esc, (size_t)el);
						}
						rl_cursor_row = nr;
					}
				} else if (seq[1] == 'D') { /* Left */
					if (cursor > 0) {
						int prev = cursor;
						cursor--;
						while (cursor > 0 &&
						       (buf[cursor] & 0xC0) == 0x80)
							cursor--;
						int cols = get_term_cols();
						int pa = (int)strlen(prompt) + prev;
						int na = (int)strlen(prompt) + cursor;
						int pr2 = cols > 0 ? pa / cols : 0;
						int nr = cols > 0 ? na / cols : 0;
						if (nr == pr2) {
							char esc[16];
							int el = snprintf(esc, sizeof(esc),
									  "\033[%dD",
									  prev - cursor);
							tty_write(tty_fd, esc, (size_t)el);
						} else {
							int nc = cols > 0 ? na % cols : 0;
							char esc[32];
							int el = snprintf(esc, sizeof(esc),
									  "\033[A\033[%dG",
									  nc + 1);
							tty_write(tty_fd, esc, (size_t)el);
						}
						rl_cursor_row = nr;
					}
				} else if (seq[1] == 'H') { /* Home */
					if (cursor > 0) {
						cursor = 0;
						int cols = get_term_cols();
						int plen = (int)strlen(prompt);
						int wr = cols > 0 ? plen / cols : 0;
						int wc = cols > 0 ? plen % cols : 0;
						char esc[32];
						int el = 0;
						if (rl_cursor_row > wr)
							el += snprintf(esc + el,
								       sizeof(esc) - (size_t)el,
								       "\033[%dA",
								       rl_cursor_row - wr);
						el += snprintf(esc + el,
							       sizeof(esc) - (size_t)el,
							       "\033[%dG", wc + 1);
						tty_write(tty_fd, esc, (size_t)el);
						rl_cursor_row = wr;
					}
				} else if (seq[1] == 'F') { /* End */
					if (cursor < pos) {
						cursor = pos;
						int cols = get_term_cols();
						int wa = (int)strlen(prompt) + pos;
						int wr = cols > 0 ? wa / cols : 0;
						int wc = cols > 0 ? wa % cols : 0;
						char esc[32];
						int el = 0;
						if (wr > rl_cursor_row)
							el += snprintf(esc + el,
								       sizeof(esc) - (size_t)el,
								       "\033[%dB",
								       wr - rl_cursor_row);
						el += snprintf(esc + el,
							       sizeof(esc) - (size_t)el,
							       "\033[%dG", wc + 1);
						tty_write(tty_fd, esc, (size_t)el);
						rl_cursor_row = wr;
					}
				} else if (seq[0] == '[' &&
					   seq[1] == '3') {
					/* Delete key: \033[3~ */
					char tilde;
					if (read(tty_fd, &tilde, 1) > 0 &&
					    tilde == '~' && cursor < pos) {
						int next = cursor + 1;
						while (next < pos &&
						       (buf[next] & 0xC0) == 0x80)
							next++;
						memmove(buf + cursor,
							buf + next,
							(size_t)(pos - next + 1));
						pos -= (next - cursor);
						redraw_from(prompt, buf,
							    cursor, cursor);
					}
				}
			}
			break;
		}

		case 127:
		case 8: /* Backspace */
			if (cursor > 0) {
				/* Handle UTF-8: find start of previous char */
				int prev = cursor - 1;
				while (prev > 0 && (buf[prev] & 0xC0) == 0x80)
					prev--;
				int del_len = cursor - prev;
				memmove(buf + prev, buf + cursor,
					(size_t)(pos - cursor + 1));
				pos -= del_len;
				cursor = prev;
				if (cursor == pos && del_len == 1) {
					/* Backspace at end, single byte:
					 * just erase visually — no redraw */
					int cols = get_term_cols();
					int plen = (int)strlen(prompt);
					int old_abs = plen + cursor + 1;
					int new_abs = plen + cursor;
					int old_row = cols > 0 ? old_abs / cols : 0;
					int new_row = cols > 0 ? new_abs / cols : 0;
					if (old_row == new_row) {
						tty_write(tty_fd, "\b \b", 3);
					} else {
						/* Crossed row boundary upward */
						int nc = cols > 0 ? new_abs % cols : 0;
						char esc[32];
						int el = snprintf(esc, sizeof(esc),
								  "\033[A\033[%dG\033[K",
								  nc + 1);
						tty_write(tty_fd, esc, (size_t)el);
					}
					rl_cursor_row = new_row;
				} else {
					redraw_from(prompt, buf, cursor, cursor);
				}
			}
			tab_count = 0;
			tab_active = 0;
			break;

		case '\t': { /* Tab completion */
			if (!tab_active) {
				snprintf(tab_base, sizeof(tab_base),
					 "%s", buf);
				tab_count = tab_find_matches(tab_base,
							     tab_matches, 64);
				tab_idx = 0;
				tab_active = 1;
			} else {
				tab_idx++;
			}

			if (tab_count > 0) {
				if (tab_idx >= tab_count)
					tab_idx = 0;
				snprintf(buf, sizeof(buf), "%s",
					 tab_matches[tab_idx]);
				pos = (int)strlen(buf);
				cursor = pos;
				redraw_buf(prompt, buf, cursor);
			}
			break;
		}

		case '?': /* Help */
			tty_write(tty_fd, "\r\n", 2);
			show_help(buf);
			/* Help output scrolled the terminal — our row
			 * tracking is invalid.  Reset before redraw. */
			rl_cursor_row = 0;
			redraw_at(prompt, buf, cursor);
			tab_count = 0;
			tab_active = 0;
			break;

		default:
			/* Printable or UTF-8 */
			if ((unsigned char)c >= 32) {
				if (pos < CLI_MAX_LINE - 1) {
					/* Check for UTF-8 multi-byte */
					int bytes = 1;
					if ((c & 0xE0) == 0xC0)
						bytes = 2;
					else if ((c & 0xF0) == 0xE0)
						bytes = 3;
					else if ((c & 0xF8) == 0xF0)
						bytes = 4;

					char ins[4];
					ins[0] = c;
					int got = 1;
					for (int b = 1;
					     b < bytes &&
					     pos + got < CLI_MAX_LINE - 1;
					     b++) {
						char cb;
						if (read(tty_fd, &cb, 1) <= 0)
							break;
						ins[got++] = cb;
					}

					/* Insert at cursor position */
					if (pos + got < CLI_MAX_LINE) {
						memmove(buf + cursor + got,
							buf + cursor,
							(size_t)(pos - cursor + 1));
						memcpy(buf + cursor, ins,
						       (size_t)got);
						pos += got;
						cursor += got;
						if (cursor == pos) {
							/* Append at end: just
							 * echo — terminal
							 * wraps naturally. */
							tty_write(tty_fd, ins,
								  (size_t)got);
							int plen = (int)
							    strlen(prompt);
							int cols =
							    get_term_cols();
							int abs_pos =
							    plen + cursor;
							/* Force deferred wrap */
							if (cols > 0 &&
							    abs_pos > 0 &&
							    abs_pos % cols == 0)
								tty_write(tty_fd,
									  "\n\r", 2);
							rl_cursor_row = cols > 0
							    ? abs_pos / cols
							    : 0;
						} else {
							redraw_from(prompt, buf,
								    cursor - got,
								    cursor);
						}
					}
				}
				tab_count = 0;
				tab_active = 0;
			}
			break;
		}
	}
}
