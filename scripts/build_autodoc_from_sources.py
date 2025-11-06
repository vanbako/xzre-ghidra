#!/usr/bin/env python3
"""
One-time helper to seed function AutoDoc entries from the upstream xzre sources.

The generated JSON becomes the long-term source of truth and should be edited
manually (or by Codex) as the reverse-engineering effort progresses. Re-running
this script will only backfill missing entries unless --force is supplied.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Optional


AUTODOC_TAG = "AutoDoc: Generated from upstream sources."


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate metadata/functions_autodoc.json from upstream sources."
    )
    parser.add_argument(
        "--header",
        type=Path,
        default=Path("xzre/xzre.h"),
        help="Header file with Doxygen comments to reuse.",
    )
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=Path("xzre/xzre_code"),
        help="Directory containing upstream C implementations.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("metadata/functions_autodoc.json"),
        help="Destination JSON file for AutoDoc entries.",
    )
    parser.add_argument(
        "--max-snippet-lines",
        type=int,
        default=120,
        help="Maximum number of implementation lines to include per entry.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Regenerate all entries, overwriting existing documentation.",
    )
    return parser.parse_args()


def load_header_docs(header_path: Path) -> Dict[str, str]:
    text = header_path.read_text(encoding="utf-8")
    docs: Dict[str, str] = {}
    comment_iter = re.finditer(r"/\*\*((?:.|\n)*?)\*/", text, re.MULTILINE)
    for match in comment_iter:
        comment = match.group(1)
        tail = text[match.end() :].lstrip()
        proto_match = re.match(
            r"(?:extern\s+)?[A-Za-z_][A-Za-z0-9_\s\*\(\),]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            tail,
            re.DOTALL,
        )
        if not proto_match:
            continue
        name = proto_match.group(1)
        docs.setdefault(name, comment)
    return docs


def extract_source_snippet(source_path: Path) -> List[str]:
    if not source_path.is_file():
        return []
    lines = [line.rstrip("\n") for line in source_path.read_text(encoding="utf-8").splitlines()]
    idx = 0
    n_lines = len(lines)
    while idx < n_lines and not lines[idx].strip():
        idx += 1
    if idx < n_lines and lines[idx].lstrip().startswith("/*"):
        while idx < n_lines and "*/" not in lines[idx]:
            idx += 1
        if idx < n_lines:
            idx += 1
    while idx < n_lines and not lines[idx].strip():
        idx += 1
    while idx < n_lines and lines[idx].lstrip().startswith("#include"):
        idx += 1
    while idx < n_lines and not lines[idx].strip():
        idx += 1
    return lines[idx:]


def normalise_doc_comment(comment: str) -> List[str]:
    cleaned: List[str] = []
    for line in comment.splitlines():
        stripped = line.strip()
        if stripped.startswith("*"):
            stripped = stripped[1:].lstrip()
        cleaned.append(stripped)

    while cleaned and not cleaned[0]:
        cleaned.pop(0)
    while cleaned and not cleaned[-1]:
        cleaned.pop()
    return cleaned


def build_autodoc_entry(
    func_name: str,
    doc_lines: Optional[List[str]],
    snippet_lines: List[str],
    max_snippet_lines: int,
) -> Optional[str]:
    if not doc_lines and not snippet_lines:
        return None

    lines: List[str] = [AUTODOC_TAG, ""]
    if doc_lines:
        lines.append("Source summary (xzre/xzre.h):")
        for line in doc_lines:
            lines.append(f"  {line}" if line else "")
        lines.append("")

    if snippet_lines:
        lines.append(f"Upstream implementation excerpt (xzre/xzre_code/{func_name}.c):")
        for raw_line in snippet_lines[:max_snippet_lines]:
            safe_line = raw_line.replace("*/", "* /")
            lines.append(f"    {safe_line}")
        if len(snippet_lines) > max_snippet_lines:
            lines.append("    ...")

    while lines and lines[-1] == "":
        lines.pop()

    return "\n".join(lines)


def derive_function_name(file_path: Path) -> Optional[str]:
    stem = file_path.stem
    if "_" not in stem:
        return None
    return stem.split("_", 1)[1]


def main() -> None:
    args = parse_args()

    docs = load_header_docs(args.header)
    metadata_dir = args.output.parent
    metadata_dir.mkdir(parents=True, exist_ok=True)

    existing: Dict[str, str] = {}
    if args.output.exists():
        existing = json.loads(args.output.read_text(encoding="utf-8"))
        if not args.force:
            print(f"Loaded {len(existing)} existing entries from {args.output}")
        else:
            print(f"Overwriting existing entries in {args.output}")

    new_entries: Dict[str, str] = {} if args.force else dict(existing)

    for c_file in sorted(args.source_dir.glob("*.c")):
        func_name = derive_function_name(c_file)
        if not func_name:
            continue
        if not args.force and func_name in new_entries:
            continue

        doc_comment = docs.get(func_name)
        doc_lines = normalise_doc_comment(doc_comment) if doc_comment else None
        snippet_lines = extract_source_snippet(c_file)

        entry = build_autodoc_entry(func_name, doc_lines, snippet_lines, args.max_snippet_lines)
        if entry:
            new_entries[func_name] = entry

    args.output.write_text(json.dumps(new_entries, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote {len(new_entries)} entries to {args.output}")


if __name__ == "__main__":
    main()
