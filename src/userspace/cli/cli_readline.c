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

#include "cli_readline.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
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
static int raw_mode = 0;
static int tty_fd = -1;

/* Internal static buffer returned by cli_readline() */
static char line_buf[CLI_MAX_LINE];

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

static void disable_raw(void)
{
	if (raw_mode && tty_fd >= 0) {
		tcsetattr(tty_fd, TCSAFLUSH, &orig_termios);
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

	t = orig_termios;
	t.c_iflag &= ~(unsigned)(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
	t.c_oflag &= ~(unsigned)(OPOST);
	t.c_cflag |= CS8;
	t.c_lflag &= ~(unsigned)(ECHO | ICANON | IEXTEN | ISIG);
	t.c_cc[VMIN] = 1;
	t.c_cc[VTIME] = 0;

	if (tcsetattr(tty_fd, TCSAFLUSH, &t) != 0)
		return -1;

	raw_mode = 1;
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

	current_comps.count = 0;
	stack_depth = 0;
	return 0;
}

void cli_term_cleanup(void)
{
	disable_raw();
	if (tty_fd >= 0) {
		close(tty_fd);
		tty_fd = -1;
	}
	raw_mode = 0;
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

/* ── Redraw ───────────────────────────────────────────────────────────── */

static void redraw_at(const char *prompt, const char *buf, int cursor)
{
	int len = (int)strlen(buf);

	/* Move to start, clear line, write prompt + buffer */
	tty_write(tty_fd, "\r\033[K", 4);
	tty_write(tty_fd, prompt, strlen(prompt));
	tty_write(tty_fd, buf, (size_t)len);
	/* Move cursor back if not at end */
	if (cursor < len) {
		char esc[16];
		int n = snprintf(esc, sizeof(esc), "\033[%dD", len - cursor);
		tty_write(tty_fd, esc, (size_t)n);
	}
}

static void redraw(const char *prompt, const char *buf)
{
	redraw_at(prompt, buf, (int)strlen(buf));
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

void cli_hist_load(const char *file)
{
	FILE *fp;
	char line[CLI_MAX_LINE];

	if (!file || !file[0])
		return;

	fp = fopen(file, "r");
	if (!fp)
		return;

	while (fgets(line, sizeof(line), fp)) {
		size_t len = strlen(line);
		while (len > 0 &&
		       (line[len - 1] == '\n' || line[len - 1] == '\r')) {
			line[len - 1] = '\0';
			len--;
		}
		hist_add(line);
	}

	fclose(fp);
}

void cli_hist_save(const char *file)
{
	char tmppath[CLI_MAX_LINE + 32];
	FILE *fp;

	if (!file || !file[0])
		return;

	snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d",
		 file, (int)getpid());
	fp = fopen(tmppath, "w");
	if (!fp)
		return;

	for (int i = 0; i < nhist; i++)
		fprintf(fp, "%s\n", hist[i]);

	fclose(fp);
	chmod(tmppath, 0600);
	if (rename(tmppath, file) != 0)
		unlink(tmppath);
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
		int bpos = 0;

		tty_write(tty_fd, prompt, strlen(prompt));
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

	tty_write(tty_fd, prompt, strlen(prompt));

	while (1) {
		char c;
		ssize_t n = read(tty_fd, &c, 1);
		if (n <= 0) {
			disable_raw();
			return NULL;	/* EOF */
		}

		switch (c) {
		case '\r':
		case '\n':
			tty_write(tty_fd, "\r\n", 2);
			hist_add(buf);
			disable_raw();
			snprintf(line_buf, sizeof(line_buf), "%s", buf);
			return line_buf;

		case 3: /* Ctrl-C */
			buf[0] = '\0';
			pos = 0;
			cursor = 0;
			tty_write(tty_fd, "\r\n", 2);
			disable_raw();
			line_buf[0] = '\0';
			return line_buf;

		case 4: /* Ctrl-D */
			if (pos == 0) {
				tty_write(tty_fd, "\r\n", 2);
				disable_raw();
				return NULL;	/* EOF on empty line */
			}
			break;

		case 21: /* Ctrl-U — clear line */
			buf[0] = '\0';
			pos = 0;
			cursor = 0;
			tab_count = 0;
			tab_active = 0;
			redraw(prompt, buf);
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
			redraw_at(prompt, buf, cursor);
			break;

		case 27: { /* ESC sequence */
			char seq[2];
			if (read(tty_fd, &seq[0], 1) <= 0)
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
						redraw(prompt, buf);
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
						redraw(prompt, buf);
					}
					tab_count = 0;
					tab_active = 0;
				} else if (seq[1] == 'C') { /* Right */
					if (cursor < pos) {
						/* Skip UTF-8 continuation bytes */
						cursor++;
						while (cursor < pos &&
						       (buf[cursor] & 0xC0) == 0x80)
							cursor++;
						redraw_at(prompt, buf, cursor);
					}
				} else if (seq[1] == 'D') { /* Left */
					if (cursor > 0) {
						cursor--;
						while (cursor > 0 &&
						       (buf[cursor] & 0xC0) == 0x80)
							cursor--;
						redraw_at(prompt, buf, cursor);
					}
				} else if (seq[1] == 'H') { /* Home */
					cursor = 0;
					redraw_at(prompt, buf, cursor);
				} else if (seq[1] == 'F') { /* End */
					cursor = pos;
					redraw_at(prompt, buf, cursor);
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
						redraw_at(prompt, buf,
							  cursor);
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
				redraw_at(prompt, buf, cursor);
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
				redraw(prompt, buf);
			}
			break;
		}

		case '?': /* Help */
			tty_write(tty_fd, "\r\n", 2);
			show_help(buf);
			redraw(prompt, buf);
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
						redraw_at(prompt, buf, cursor);
					}
				}
				tab_count = 0;
				tab_active = 0;
			}
			break;
		}
	}
}
