#!/usr/bin/env python3
"""
Scan exported decompilations for lingering undefined* tokens.

This is a lightweight hygiene check for Ghidra exports; it flags any
undefined types that should be rewritten via locals metadata or postprocess
rules.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable, List, Tuple

UNDEFINED_PATTERN = re.compile(r"\bundefined\d+\b|\bundefined\b")


def strip_non_code(text: str) -> str:
    result: List[str] = []
    length = len(text)
    i = 0
    state = "code"

    while i < length:
        ch = text[i]
        if state == "code":
            if ch == "/" and i + 1 < length:
                nxt = text[i + 1]
                if nxt == "/":
                    state = "line_comment"
                    result.append("  ")
                    i += 2
                    continue
                if nxt == "*":
                    state = "block_comment"
                    result.append("  ")
                    i += 2
                    continue
            if ch == '"':
                state = "string"
                result.append(" ")
                i += 1
                continue
            if ch == "'":
                state = "char"
                result.append(" ")
                i += 1
                continue
            result.append(ch)
            i += 1
            continue

        if state == "line_comment":
            if ch == "\n":
                state = "code"
                result.append("\n")
            else:
                result.append(" ")
            i += 1
            continue

        if state == "block_comment":
            if ch == "*" and i + 1 < length and text[i + 1] == "/":
                state = "code"
                result.append("  ")
                i += 2
                continue
            if ch == "\n":
                result.append("\n")
            else:
                result.append(" ")
            i += 1
            continue

        if state == "string":
            if ch == "\\" and i + 1 < length:
                result.append("  ")
                i += 2
                continue
            if ch == '"':
                state = "code"
                result.append(" ")
                i += 1
                continue
            if ch == "\n":
                result.append("\n")
            else:
                result.append(" ")
            i += 1
            continue

        if state == "char":
            if ch == "\\" and i + 1 < length:
                result.append("  ")
                i += 2
                continue
            if ch == "'":
                state = "code"
                result.append(" ")
                i += 1
                continue
            if ch == "\n":
                result.append("\n")
            else:
                result.append(" ")
            i += 1
            continue

    return "".join(result)


def iter_files(xzregh_dir: Path, include_headers: bool) -> Iterable[Path]:
    patterns = ["*.c"]
    if include_headers:
        patterns.append("*.h")
    for pattern in patterns:
        for path in sorted(xzregh_dir.glob(pattern)):
            if path.name == "xzre_types.h":
                continue
            yield path


def scan_file(path: Path) -> List[Tuple[int, str]]:
    matches: List[Tuple[int, str]] = []
    raw_text = path.read_text(encoding="utf-8")
    cleaned = strip_non_code(raw_text)
    raw_lines = raw_text.splitlines()
    for lineno, line in enumerate(cleaned.splitlines(), 1):
        if UNDEFINED_PATTERN.search(line):
            matches.append((lineno, raw_lines[lineno - 1].rstrip()))
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Report undefined* tokens in exported decompilations."
    )
    parser.add_argument(
        "--xzregh-dir",
        type=Path,
        default=Path("xzregh"),
        help="Directory containing exported decompilations.",
    )
    parser.add_argument(
        "--include-headers",
        action="store_true",
        help="Also scan headers (skipping xzre_types.h).",
    )
    args = parser.parse_args()

    if not args.xzregh_dir.exists():
        print(f"[check_undefined] missing directory: {args.xzregh_dir}", file=sys.stderr)
        return 2

    found = False
    for path in iter_files(args.xzregh_dir, args.include_headers):
        hits = scan_file(path)
        if not hits:
            continue
        found = True
        for lineno, line in hits:
            print(f"{path}:{lineno}: {line}")

    if found:
        return 1
    print("[check_undefined] ok: no undefined* tokens found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
