#!/usr/bin/env python3
"""Stargazer readline feature tests.

Covers:
- Persistent history recall via Up/Down arrows
- Tab completion cycling across multiple matches
"""

import os
import pty
import re
import select
import shutil
import subprocess
import tempfile
import time

PROJECT_ROOT = "/home/rusted/projects/Stargazer"
SRC = os.path.join(PROJECT_ROOT, "src/userspace/logind/stargazer-readline.c")

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def build_test_binary(workdir: str) -> str:
    bin_path = os.path.join(workdir, "stargazer-readline-host")
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        raise RuntimeError("gcc/cc not found")
    subprocess.check_call([cc, "-Wall", "-Wextra", "-O2", "-o", bin_path, SRC])
    return bin_path


def normalize_last_line(raw: bytes, prompt: str) -> str:
    txt = raw.decode("utf-8", errors="ignore")
    txt = ANSI_RE.sub("", txt)
    txt = txt.replace("\r", "\n")
    lines = [ln for ln in txt.split("\n") if ln != ""]
    if not lines:
        return ""
    last = lines[-1]
    if last.startswith(prompt):
        last = last[len(prompt):]
    return last


def run_session(bin_path: str, prompt: str, comp_file: str, hist_file: str, keys: bytes) -> str:
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(bin_path, [bin_path, prompt, comp_file, hist_file])

    time.sleep(0.05)
    os.write(fd, keys)
    os.set_blocking(fd, False)

    out = bytearray()
    deadline = time.time() + 5.0
    child_exited = False

    while time.time() < deadline:
        if not child_exited:
            wpid, _status = os.waitpid(pid, os.WNOHANG)
            child_exited = (wpid == pid)

        rlist, _, _ = select.select([fd], [], [], 0.1)
        if not rlist:
            if child_exited:
                break
            continue

        try:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            out.extend(chunk)
        except OSError:
            if child_exited:
                break

    if not child_exited:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
    return normalize_last_line(bytes(out), prompt)


def assert_eq(name: str, actual: str, expected: str) -> None:
    if actual != expected:
        raise AssertionError(f"{name} failed: expected={expected!r}, actual={actual!r}")
    print(f"PASS: {name}")


def write_completions(path: str, entries: list[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(e + "\n")


def test_history_up_down(bin_path: str, wd: str) -> None:
    comp = os.path.join(wd, "comp.txt")
    hist = os.path.join(wd, "hist1.txt")
    write_completions(comp, ["configure system|Enter system config"])

    assert_eq(
        "history seed command",
        run_session(bin_path, "SG> ", comp, hist, b"bad syntax\r"),
        "bad syntax",
    )
    assert_eq(
        "history up recalls latest",
        run_session(bin_path, "SG> ", comp, hist, b"\x1b[A\r"),
        "bad syntax",
    )

    run_session(bin_path, "SG> ", comp, hist, b"cmd1\r")
    run_session(bin_path, "SG> ", comp, hist, b"cmd2\r")
    run_session(bin_path, "SG> ", comp, hist, b"cmd3\r")
    assert_eq(
        "history down moves newer",
        run_session(bin_path, "SG> ", comp, hist, b"\x1b[A\x1b[A\x1b[B\r"),
        "cmd3",
    )


def test_tab_cycle_no_partial(bin_path: str, wd: str) -> None:
    comp = os.path.join(wd, "comp2.txt")
    hist = os.path.join(wd, "hist2.txt")
    write_completions(
        comp,
        [
            "execute|Execute runtime actions",
            "configure system setting|System settings",
            "configure system interface|Interface settings",
        ],
    )

    assert_eq(
        "tab cycle case1",
        run_session(bin_path, "SG> ", comp, hist, b"configure system \t\t\r"),
        "configure system interface",
    )

    assert_eq(
        "tab no trailing space",
        run_session(bin_path, "SG> ", comp, hist, b"ex\t\r"),
        "execute",
    )


def test_tab_cycle_partial(bin_path: str, wd: str) -> None:
    comp = os.path.join(wd, "comp3.txt")
    hist = os.path.join(wd, "hist3.txt")
    write_completions(
        comp,
        [
            "configure system admin-profile|Admin profile",
            "configure system admin|Admin user",
        ],
    )

    assert_eq(
        "tab cycle case2",
        run_session(bin_path, "SG> ", comp, hist, b"configure system ad\t\t\r"),
        "configure system admin",
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="sg_readline_test_") as wd:
        bin_path = build_test_binary(wd)
        test_history_up_down(bin_path, wd)
        test_tab_cycle_no_partial(bin_path, wd)
        test_tab_cycle_partial(bin_path, wd)
        print("ALL PASSED")


if __name__ == "__main__":
    main()
