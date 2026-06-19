#!/usr/bin/env python3
"""Prepend a 42-school header to source files (idempotent).

The header is the canonical 11-line, 80-column banner. Usage:
    gen-42-header.py <file>...
A file that already starts with the banner top is left untouched, so the script
is safe to re-run. Author/date are fixed project metadata (no live clock — keeps
re-runs byte-stable). Comment delimiters are chosen per file extension.
"""
import sys

USER = "dlesieur"
MAIL = "dev.pro.photo@gmail.com"
DATE = "2026/06/19 00:00:00"
WIDTH = 80

# Right-hand ASCII logo rows (right-aligned to the content edge), one per body line 3..9.
LOGO = [
    ":::      ::::::::",
    ":+:      :+:    :+:",
    "+:+ +:+         +:+",
    "+#+  +:+       +#+",
    "+#+#+#+#+#+   +#+",
    "#+#    #+#",
    "###   ########.fr",
]

# (open, fill, close) comment delimiters per extension; fill is the bar character run.
DELIMS = {
    "rs": ("/*", "*", "*/"),
    "go": ("/*", "*", "*/"),
    "proto": ("/*", "*", "*/"),
    "sh": ("#", "*", "#"),
    "py": ("#", "*", "#"),
}


def body_line(left, right, open_d, close_d):
    """One framed line: `<open> <74-col content> <close>`, right-aligned logo."""
    inner = WIDTH - len(open_d) - len(close_d) - 2
    pad = inner - len(left) - len(right)
    content = left + " " * max(pad, 1) + right
    return f"{open_d} {content[:inner].ljust(inner)} {close_d}"


def bar(open_d, fill, close_d):
    """The top/bottom rule line."""
    inner = WIDTH - len(open_d) - len(close_d) - 2
    return f"{open_d} {fill * inner} {close_d}"


def header(filename, open_d, fill, close_d):
    """Build the 11-line banner for one filename."""
    rows = [
        bar(open_d, fill, close_d),
        body_line("", "", open_d, close_d),
        body_line("", LOGO[0], open_d, close_d),
        body_line(f"  {filename}", LOGO[1], open_d, close_d),
        body_line("", LOGO[2], open_d, close_d),
        body_line(f"  By: {USER} <{MAIL}>", LOGO[3], open_d, close_d),
        body_line("", LOGO[4], open_d, close_d),
        body_line(f"  Created: {DATE} by {USER}", LOGO[5], open_d, close_d),
        body_line(f"  Updated: {DATE} by {USER}", LOGO[6], open_d, close_d),
        body_line("", "", open_d, close_d),
        bar(open_d, fill, close_d),
    ]
    return "\n".join(rows) + "\n"


def apply(path):
    """Prepend the header to one file if it lacks one; return True if changed."""
    ext = path.rsplit(".", 1)[-1]
    if ext not in DELIMS:
        return False
    open_d, fill, close_d = DELIMS[ext]
    text = open(path, encoding="utf-8").read()
    if text.startswith(f"{open_d} {fill * 4}"):
        return False
    block = header(path.rsplit("/", 1)[-1], open_d, fill, close_d)
    open(path, "w", encoding="utf-8").write(block + "\n" + text)
    return True


def main(argv):
    changed = sum(apply(p) for p in argv[1:])
    print(f"42-header: {changed} file(s) updated")


if __name__ == "__main__":
    main(sys.argv)
