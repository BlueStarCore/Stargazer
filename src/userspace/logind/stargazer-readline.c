/* SPDX-License-Identifier: MIT */
/*
 * stargazer-readline — C readline helper for Stargazer CLI
 *
 * Usage: stargazer-readline <prompt> [completions_file]
 * Output: single line of user input to stdout
 *
 * Features:
 *   - Raw terminal mode (termios)
 *   - Character-by-character read (no dd fork per char)
 *   - Backspace, Ctrl-C, Ctrl-D, Ctrl-U, Ctrl-W
 *   - Arrow keys (up/down for history from stdin pipe or file)
 *   - Tab completion: reads candidates from completions_file
 *   - ? help: reads and displays matching entries from completions_file
 *   - UTF-8 aware (multi-byte passthrough)
 *
 * Completions file format (one entry per line):
 *   path|description
 * Example:
 *   show|Display current settings
 *   configure system|Enter system configuration
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#define MAX_LINE    4096
#define MAX_COMPS   1024
#define MAX_HIST    100
#define MAX_DESC    256

struct completion {
	char path[MAX_LINE];
	char desc[MAX_DESC];
};

static struct completion comps[MAX_COMPS];
static int ncomps;

static char hist[MAX_HIST][MAX_LINE];
static int nhist;

static char history_path[MAX_LINE];

static struct termios orig_termios;
static int raw_mode;
static int tty_fd = -1;   /* fd for terminal I/O (keystrokes + display) */
static int out_fd = -1;   /* saved original stdout for result output    */

/* ── Terminal ──────────────────────────────────────────────────────────── */

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
	if (tty_fd < 0)
		return -1;
	if (!isatty(tty_fd))
		return -1;
	if (tcgetattr(tty_fd, &orig_termios) != 0)
		return -1;

	struct termios t = orig_termios;
	t.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
	t.c_oflag &= ~(OPOST);
	t.c_cflag |= CS8;
	t.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
	t.c_cc[VMIN] = 1;
	t.c_cc[VTIME] = 0;

	if (tcsetattr(tty_fd, TCSAFLUSH, &t) != 0)
		return -1;

	raw_mode = 1;
	return 0;
}

/* ── Completion loading ───────────────────────────────────────────────── */

static void load_completions(const char *file)
{
	ncomps = 0;
	if (!file)
		return;

	FILE *fp = fopen(file, "r");
	if (!fp)
		return;

	char line[MAX_LINE + MAX_DESC + 2];
	while (fgets(line, sizeof(line), fp) && ncomps < MAX_COMPS) {
		size_t len = strlen(line);
		if (len > 0 && line[len - 1] == '\n')
			line[len - 1] = '\0';
		if (line[0] == '\0')
			continue;

		char *sep = strchr(line, '|');
		if (sep) {
			*sep = '\0';
			strncpy(comps[ncomps].path, line, MAX_LINE - 1);
			comps[ncomps].path[MAX_LINE - 1] = '\0';
			strncpy(comps[ncomps].desc, sep + 1, MAX_DESC - 1);
			comps[ncomps].desc[MAX_DESC - 1] = '\0';
		} else {
			strncpy(comps[ncomps].path, line, MAX_LINE - 1);
			comps[ncomps].path[MAX_LINE - 1] = '\0';
			comps[ncomps].desc[0] = '\0';
		}
		ncomps++;
	}
	fclose(fp);
}

/* ── Redraw ───────────────────────────────────────────────────────────── */

static void redraw_at(const char *prompt, const char *buf, int cursor)
{
	/* Move to start, clear line, write prompt + buffer */
	write(tty_fd, "\r\033[K", 4);
	write(tty_fd, prompt, strlen(prompt));
	int len = (int)strlen(buf);
	write(tty_fd, buf, (size_t)len);
	/* Move cursor back if not at end */
	if (cursor < len) {
		char esc[16];
		int n = snprintf(esc, sizeof(esc), "\033[%dD", len - cursor);
		write(tty_fd, esc, (size_t)n);
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

static int tab_find_matches(const char *buf, char matches[][MAX_LINE], int max_matches)
{
	int count = 0;
	int trailing_space = (buf[0] != '\0' && buf[strlen(buf) - 1] == ' ');

	if (trailing_space) {
		/* Complete next word */
		int depth = word_count(buf);
		int target = depth + 1;

		for (int i = 0; i < ncomps && count < max_matches; i++) {
			if (strncmp(comps[i].path, buf, strlen(buf)) != 0)
				continue;
			int wl;
			const char *w = nth_word(comps[i].path, target, &wl);
			if (!w || wl == 0)
				continue;

			/* Build candidate: buf + word */
			char cand[MAX_LINE];
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
				snprintf(matches[count++], MAX_LINE, "%s", cand);
		}
	} else {
		/* Complete partial word */
		int nw = word_count(buf);
		if (nw <= 1) {
			/* Single partial word */
			for (int i = 0; i < ncomps && count < max_matches; i++) {
				int wl;
				const char *first = nth_word(comps[i].path, 1, &wl);
				if (!first)
					continue;
				if (strncmp(first, buf, strlen(buf)) != 0)
					continue;

				char cand[MAX_LINE];
				snprintf(cand, sizeof(cand), "%.*s", wl, first);

				int dup = 0;
				for (int j = 0; j < count; j++) {
					if (strcmp(matches[j], cand) == 0) {
						dup = 1;
						break;
					}
				}
				if (!dup)
					snprintf(matches[count++], MAX_LINE, "%s", cand);
			}
		} else {
			/* Multi-word: find prefix and partial */
			const char *last_space = strrchr(buf, ' ');
			if (!last_space)
				return 0;
			int prefix_len = (int)(last_space - buf + 1);
			const char *partial = last_space + 1;
			size_t plen = strlen(partial);

			for (int i = 0; i < ncomps && count < max_matches; i++) {
				if (strncmp(comps[i].path, buf, prefix_len) != 0)
					continue;
				/* Check the next word starts with partial */
				const char *rest = comps[i].path + prefix_len;
				if (strncmp(rest, partial, plen) != 0)
					continue;

				int wl;
				const char *w = nth_word(comps[i].path, nw, &wl);
				if (!w)
					continue;

				char cand[MAX_LINE];
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
					snprintf(matches[count++], MAX_LINE, "%s", cand);
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
	char exact_cmd[MAX_LINE];
	exact_cmd[0] = '\0';
	char exact_desc[MAX_DESC];
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
			pattern = buf; /* full match prefix */
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
		for (int i = 0; i < ncomps; i++) {
			if (strcmp(comps[i].path, exact_cmd) == 0) {
				snprintf(exact_desc, sizeof(exact_desc), "%s", comps[i].desc);
				break;
			}
		}
	}

	if (exact_cmd[0] != '\0' && exact_desc[0] != '\0') {
		char enter_line[MAX_LINE];
		snprintf(enter_line, sizeof(enter_line), "  %-24s %s\r\n", "<Enter>", exact_desc);
		write(tty_fd, enter_line, strlen(enter_line));
	}

	char seen[MAX_COMPS][64];
	int nseen = 0;

	for (int i = 0; i < ncomps; i++) {
		/* Check if path matches pattern prefix */
		if (pattern[0] != '\0') {
			if (trailing_space || buf[0] == '\0') {
				if (strncmp(comps[i].path, pattern, strlen(pattern)) != 0)
					continue;
			} else {
				/* Partial match: check the full buf as prefix */
				size_t blen = strlen(buf);
				if (strncmp(comps[i].path, buf, blen) != 0) {
					/* Also try matching up to last space */
					const char *ls = strrchr(buf, ' ');
					if (ls) {
						size_t plen = (size_t)(ls - buf + 1);
						if (strncmp(comps[i].path, buf, plen) != 0)
							continue;
					} else {
						continue;
					}
				}
			}
		}

		int wl;
		const char *w = nth_word(comps[i].path, target, &wl);
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
		if (nseen < MAX_COMPS)
			snprintf(seen[nseen++], 64, "%s", word);

		/* Print with padding */
		char line[MAX_LINE];
		snprintf(line, sizeof(line), "  %-24s %s\r\n", word, comps[i].desc);
		write(tty_fd, line, strlen(line));
	}

	if (nseen == 0) {
		if (buf[0] != '\0' && exact_desc[0] == '\0') {
			const char *msg = "  Not a command.\r\n";
			write(tty_fd, msg, strlen(msg));
		} else if (buf[0] == '\0') {
			const char *msg = "  <cr>  Execute command\r\n";
			write(tty_fd, msg, strlen(msg));
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
	if (nhist < MAX_HIST) {
		snprintf(hist[nhist++], MAX_LINE, "%s", line);
	} else {
		/* Shift up */
		memmove(hist[0], hist[1], (size_t)(MAX_HIST - 1) * MAX_LINE);
		snprintf(hist[MAX_HIST - 1], MAX_LINE, "%s", line);
	}
}

static void default_history_path(char *out, size_t outlen)
{
	const char *env = getenv("STARGAZER_HISTORY_FILE");

	if (env && env[0]) {
		snprintf(out, outlen, "%s", env);
		return;
	}

	snprintf(out, outlen, "/tmp/stargazer_cli_history_%ld", (long)getuid());
}

static void load_history(const char *file)
{
	FILE *fp;
	char line[MAX_LINE];

	if (!file || !file[0])
		return;

	fp = fopen(file, "r");
	if (!fp)
		return;

	while (fgets(line, sizeof(line), fp)) {
		size_t len = strlen(line);
		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
			line[len - 1] = '\0';
			len--;
		}
		hist_add(line);
	}

	fclose(fp);
}

static void save_history(const char *file)
{
	char tmppath[MAX_LINE + 32];
	FILE *fp;

	if (!file || !file[0])
		return;

	snprintf(tmppath, sizeof(tmppath), "%s.tmp.%d", file, (int)getpid());
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

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: stargazer-readline <prompt> [completions_file] [history_file]\n");
		return 1;
	}

	const char *prompt = argv[1];
	const char *comp_file = argc > 2 ? argv[2] : NULL;
	const char *hist_file = argc > 3 ? argv[3] : NULL;

	if (hist_file && hist_file[0])
		snprintf(history_path, sizeof(history_path), "%s", hist_file);
	else
		default_history_path(history_path, sizeof(history_path));

	load_completions(comp_file);
	load_history(history_path);

	/*
	 * Open a terminal device for interactive I/O.
	 * This makes us independent of shell-level /dev/tty redirections.
	 * stdout (fd 1) is kept untouched for $(…) capture by the caller.
	 */
	out_fd = dup(STDOUT_FILENO);
	tty_fd = open_terminal();
	if (tty_fd < 0) {
		/* Last resort: stdin might be the terminal (direct invocation) */
		if (isatty(STDIN_FILENO))
			tty_fd = dup(STDIN_FILENO);
	}

	if (enable_raw() != 0) {
		/* Fallback: just read a line in cooked mode */
		int rfd = (tty_fd >= 0) ? tty_fd : STDIN_FILENO;
		int wfd = (tty_fd >= 0) ? tty_fd : STDERR_FILENO;
		write(wfd, prompt, strlen(prompt));
		char buf[MAX_LINE];
		int bpos = 0;
		char ch;
		while (bpos < MAX_LINE - 1) {
			if (read(rfd, &ch, 1) <= 0)
				break;
			if (ch == '\n' || ch == '\r')
				break;
			buf[bpos++] = ch;
		}
		buf[bpos] = '\0';
		dprintf(out_fd, "%s\n", buf);
		if (tty_fd >= 0) close(tty_fd);
		if (out_fd >= 0) close(out_fd);
		return 0;
	}

	/* Cleanup on exit */
	atexit(disable_raw);

	char buf[MAX_LINE];
	int pos = 0;    /* buffer length */
	int cursor = 0; /* cursor position within buffer */
	buf[0] = '\0';

	/* Tab state */
	char tab_matches[64][MAX_LINE];
	int tab_count = 0;
	int tab_idx = 0;
	int tab_active = 0;
	char tab_base[MAX_LINE];
	tab_base[0] = '\0';

	int hist_idx = nhist;
	char hist_saved[MAX_LINE];
	hist_saved[0] = '\0';

	write(tty_fd, prompt, strlen(prompt));

	while (1) {
		char c;
		ssize_t n = read(tty_fd, &c, 1);
		if (n <= 0)
			break;

		switch (c) {
		case '\r':
		case '\n':
			write(tty_fd, "\r\n", 2);
			hist_add(buf);
			save_history(history_path);
			goto done;

		case 3: /* Ctrl-C */
			buf[0] = '\0';
			pos = 0;
			cursor = 0;
			write(tty_fd, "\r\n", 2);
			goto done;

		case 4: /* Ctrl-D */
			if (pos == 0) {
				snprintf(buf, sizeof(buf), "exit");
				pos = 4;
				cursor = 4;
				write(tty_fd, "\r\n", 2);
				goto done;
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
			if (seq[0] == '[') {
				if (seq[1] == 'A') { /* Up */
					if (hist_idx == nhist)
						snprintf(hist_saved, sizeof(hist_saved), "%s", buf);
					if (hist_idx > 0) {
						hist_idx--;
						snprintf(buf, sizeof(buf), "%s", hist[hist_idx]);
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
							snprintf(buf, sizeof(buf), "%s", hist_saved);
							pos = (int)strlen(buf);
						} else {
							snprintf(buf, sizeof(buf), "%s", hist[hist_idx]);
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
				}
			}
			break;
		}

		case 127:
		case 8: /* Backspace */
			if (cursor > 0) {
				/* Handle UTF-8: find start of previous character */
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
				snprintf(tab_base, sizeof(tab_base), "%s", buf);
				tab_count = tab_find_matches(tab_base, tab_matches, 64);
				tab_idx = 0;
				tab_active = 1;
			} else {
				tab_idx++;
			}

			if (tab_count > 0) {
				if (tab_idx >= tab_count)
					tab_idx = 0;
				snprintf(buf, sizeof(buf), "%s", tab_matches[tab_idx]);
				pos = (int)strlen(buf);
				cursor = pos;
				redraw(prompt, buf);
			}
			break;
		}

		case '?': /* Help */
			write(tty_fd, "\r\n", 2);
			show_help(buf);
			redraw(prompt, buf);
			tab_count = 0;
			tab_active = 0;
			break;

		default:
			/* Printable or UTF-8 */
			if ((unsigned char)c >= 32) {
				if (pos < MAX_LINE - 1) {
					/* Check for UTF-8 multi-byte */
					int bytes = 1;
					if ((c & 0xE0) == 0xC0) bytes = 2;
					else if ((c & 0xF0) == 0xE0) bytes = 3;
					else if ((c & 0xF8) == 0xF0) bytes = 4;

					char ins[4];
					ins[0] = c;
					int got = 1;
					for (int b = 1; b < bytes && pos + got < MAX_LINE - 1; b++) {
						char cb;
						if (read(tty_fd, &cb, 1) <= 0)
							break;
						ins[got++] = cb;
					}

					/* Insert at cursor position */
					if (pos + got < MAX_LINE) {
						memmove(buf + cursor + got,
							buf + cursor,
							(size_t)(pos - cursor + 1));
						memcpy(buf + cursor, ins, (size_t)got);
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

done:
	disable_raw();
	dprintf(out_fd, "%s\n", buf);
	if (tty_fd >= 0)
		close(tty_fd);
	if (out_fd >= 0)
		close(out_fd);
	return 0;
}
