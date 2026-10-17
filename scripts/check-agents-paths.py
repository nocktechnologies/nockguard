#!/usr/bin/env python3
"""Fail when AGENTS.md names a repo path that git does not track.

Checks markdown link targets and path-like tokens in backtick spans and fenced
code. A token is path-like when it is made only of word characters, dots,
dashes and slashes, and contains "/" or ends in a file extension; URLs, globs,
<placeholders>, flags and shell expressions never match. Every path must stay
inside the repo root and match a tracked file or directory.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATH = re.compile(r"/?[\w.-]+(?:/[\w.-]*)*")
EXTENSION = re.compile(r"\.[A-Za-z][A-Za-z0-9]*$")
LINK = re.compile(r"\]\(([^)\s]+)\)")
SPAN = re.compile(r"`([^`]+)`")


def candidates(text):
    in_fence = False
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            tokens = line.split()
        else:
            tokens = [t for span in SPAN.findall(line) for t in span.split()]
            tokens += [link.split("#", 1)[0] for link in LINK.findall(line)]
        for token in tokens:
            if "..." in token:  # Go package pattern such as ./...
                continue
            token = re.sub(r"[.,:;]$", "", token)
            if PATH.fullmatch(token) and ("/" in token or EXTENSION.search(token)):
                yield lineno, token


def main():
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.split("\0")
    known = set(tracked)
    for path in tracked:
        parent = os.path.dirname(path)
        while parent and parent not in known:
            known.add(parent)
            parent = os.path.dirname(parent)

    text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    hits = list(candidates(text))
    bad = []
    for lineno, token in hits:
        path = os.path.normpath(token)
        if os.path.isabs(token) or path == ".." or path.startswith("../"):
            bad.append(f"AGENTS.md:{lineno}: {token}: outside the repo root")
        elif path not in known:
            bad.append(f"AGENTS.md:{lineno}: {token}: not a tracked file or directory")

    if not hits:
        bad.append("AGENTS.md: no path-like spans found; the checker is broken")
    for line in bad:
        print(line, file=sys.stderr)
    if bad:
        return 1
    print(f"AGENTS.md: {len(hits)} paths checked, all tracked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
