#!/usr/bin/env python3
"""
Sync plate comments from the Ghidra project into the Ghidra decomp dump (xzregh/).

Given the JSON export produced by ExportAutoDocComments.py, this script injects
the corresponding block comment ahead of each function wrapper in xzregh/.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Optional


AUTODOC_TAG = "AutoDoc:"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Apply plate comments exported from Ghidra into xzregh/*.c files."
    )
    parser.add_argument(
        "--comments-json",
        required=True,
        type=Path,
        help="Path to JSON mapping function names to comment text (from Ghidra).",
    )
    parser.add_argument(
        "--xzregh-dir",
        type=Path,
        default=Path("xzregh"),
        help="Directory containing the decompiled C files.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report changes without writing files.",
    )
    parser.add_argument(
        "--ensure-include",
        help='If provided, ensure each file contains this include line (e.g. \'#include "xzre_types.h"\').',
    )
    return parser.parse_args()


def derive_function_name(file_path: Path) -> Optional[str]:
    stem = file_path.stem
    if "_" not in stem:
        return None
    return stem.split("_", 1)[1]


def strip_existing_autodoc(text: str) -> str:
    lines = text.splitlines()
    result: List[str] = []
    i = 0
    n = len(lines)

    while i < n:
        stripped = lines[i].strip()
        if stripped.startswith("//") or stripped.startswith("#include") or not stripped:
            result.append(lines[i])
            i += 1
            continue
        if stripped.startswith("/*"):
            i += 1
            while i < n and "*/" not in lines[i]:
                i += 1
            if i < n:
                i += 1
            while i < n and not lines[i].strip():
                i += 1
            continue
        break

    result.extend(lines[i:])
    updated = "\n".join(result)
    if text.endswith("\n"):
        updated += "\n"
    return updated


def wrap_comment(comment_text: str) -> List[str]:
    lines = ["/*"]
    for raw_line in comment_text.splitlines():
        if raw_line:
            lines.append(f" * {raw_line}")
        else:
            lines.append(" *")
    lines.append(" */")
    return lines


def insert_comment(content: str, comment_lines: List[str]) -> str:
    lines = content.splitlines()
    insert_idx = 0
    while insert_idx < len(lines) and lines[insert_idx].startswith("//"):
        insert_idx += 1
    while insert_idx < len(lines) and not lines[insert_idx].strip():
        insert_idx += 1

    new_lines = lines[:insert_idx] + comment_lines + lines[insert_idx:]
    trailing_newline = content.endswith("\n")
    updated = "\n".join(new_lines)
    if trailing_newline:
        updated += "\n"
    return updated


def ensure_include(content: str, include_line: str) -> str:
    if not include_line or include_line in content:
        return content

    lines = content.splitlines()
    insert_idx = 0

    while insert_idx < len(lines) and lines[insert_idx].startswith("//"):
        insert_idx += 1

    while insert_idx < len(lines) and not lines[insert_idx].strip():
        insert_idx += 1

    if insert_idx < len(lines) and lines[insert_idx].startswith("/*"):
        while insert_idx < len(lines) and "*/" not in lines[insert_idx]:
            insert_idx += 1
        if insert_idx < len(lines):
            insert_idx += 1

    if insert_idx < len(lines) and lines[insert_idx].strip():
        lines.insert(insert_idx, "")
        insert_idx += 1

    lines.insert(insert_idx, include_line)
    lines.insert(insert_idx + 1, "")

    updated = "\n".join(lines)
    if content.endswith("\n"):
        updated += "\n"
    return updated


def apply_comment(file_path: Path, comment_text: str, include_line: Optional[str], dry_run: bool) -> bool:
    original = file_path.read_text(encoding="utf-8")
    stripped = strip_existing_autodoc(original)
    body = comment_text
    if not body.lstrip().startswith(AUTODOC_TAG):
        body = f"{AUTODOC_TAG} {body}"
    updated = insert_comment(stripped, wrap_comment(body))
    if include_line:
        updated = ensure_include(updated, include_line)
    if updated == original:
        return False
    if not dry_run:
        file_path.write_text(updated, encoding="utf-8")
    return True


def main() -> None:
    args = parse_args()

    comment_map: Dict[str, str] = json.loads(args.comments_json.read_text(encoding="utf-8"))

    updated = 0
    missing: List[str] = []

    for c_file in sorted(args.xzregh_dir.glob("*.c")):
        func_name = derive_function_name(c_file)
        if not func_name:
            continue

        lookup_names = [func_name]
        if func_name.startswith("_"):
            stripped = func_name.lstrip("_")
            if stripped:
                lookup_names.append(stripped)
        else:
            lookup_names.append(f"_{func_name}")

        comment = None
        for candidate in lookup_names:
            comment = comment_map.get(candidate)
            if comment:
                break

        if not comment:
            missing.append(func_name)
            continue

        if apply_comment(c_file, comment, args.ensure_include, args.dry_run):
            updated += 1

    if args.dry_run:
        print(f"[dry-run] {updated} files would be updated.")
    else:
        print(f"Applied Ghidra comments to {updated} files.")

    if missing:
        print(
            "Warning: {} functions in xzregh have no exported comment.".format(
                len(missing)
            )
        )


if __name__ == "__main__":
    main()
