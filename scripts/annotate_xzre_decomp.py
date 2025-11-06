#!/usr/bin/env python3
"""
Annotate Ghidra-exported decompilations with upstream documentation.

The script copies Doxygen-style comments from xzre/xzre.h (when available)
and embeds an excerpt of the original implementation from xzre/xzre_code().
When a function has no upstream C source, existing plate comments exported
from Ghidra can be used as the authoritative fallback so documentation stays
aligned with the reverse-engineered project.
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
        description="Inject upstream documentation into xzregh/*.c files."
    )
    parser.add_argument(
        "--xzregh-dir",
        type=Path,
        default=Path("xzregh"),
        help="Directory containing Ghidra-exported .c files.",
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
        help="Directory with upstream C implementations.",
    )
    parser.add_argument(
        "--max-snippet-lines",
        type=int,
        default=120,
        help="Maximum number of implementation lines to embed per comment.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute changes without writing files.",
    )
    parser.add_argument(
        "--emit-json",
        type=Path,
        help="Optional path to emit a JSON map of function -> AutoDoc text.",
    )
    parser.add_argument(
        "--skip-decomp",
        action="store_true",
        help="Do not modify any files inside xzregh/.",
    )
    parser.add_argument(
        "--fallback-json",
        type=Path,
        help="Optional AutoDoc JSON exported from Ghidra to reuse when no upstream snippet exists.",
    )
    return parser.parse_args()


def load_header_docs(header_path: Path) -> Dict[str, str]:
    """Return a mapping of function name -> documentation block from xzre.h."""
    text = header_path.read_text(encoding="utf-8")
    docs: Dict[str, str] = {}

    comment_iter = re.finditer(r"/\*\*((?:.|\n)*?)\*/", text, re.MULTILINE)
    for match in comment_iter:
        comment = match.group(1)
        tail = text[match.end() :]
        # Trim leading whitespace/newlines before the prototype.
        tail = tail.lstrip()
        proto_match = re.match(
            r"(?:extern\s+)?[A-Za-z_][A-Za-z0-9_\s\*\(\),]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            tail,
            re.DOTALL,
        )
        if not proto_match:
            continue
        name = proto_match.group(1)
        # Avoid overwriting if multiple comments precede the same symbol.
        docs.setdefault(name, comment)
    return docs


def extract_source_snippet(source_path: Path) -> List[str]:
    """Extract the core implementation from the upstream C file."""
    if not source_path.is_file():
        return []

    lines = [line.rstrip("\n") for line in source_path.read_text(encoding="utf-8").splitlines()]

    idx = 0
    n_lines = len(lines)

    # Skip initial blank lines.
    while idx < n_lines and not lines[idx].strip():
        idx += 1

    # Skip leading comment block (license header).
    if idx < n_lines and lines[idx].lstrip().startswith("/*"):
        while idx < n_lines and "*/" not in lines[idx]:
            idx += 1
        if idx < n_lines:
            idx += 1

    # Skip blank lines after comment.
    while idx < n_lines and not lines[idx].strip():
        idx += 1

    # Skip include directives.
    while idx < n_lines and lines[idx].lstrip().startswith("#include"):
        idx += 1

    # Skip trailing blank lines before the implementation.
    while idx < n_lines and not lines[idx].strip():
        idx += 1

    snippet = lines[idx:]
    return snippet


def normalise_doc_comment(comment: str) -> List[str]:
    """Convert a Doxygen block into raw text lines."""
    cleaned: List[str] = []
    for line in comment.splitlines():
        stripped = line.strip()
        if stripped.startswith("*"):
            stripped = stripped[1:].lstrip()
        cleaned.append(stripped)

    # Trim leading/trailing empty lines for neatness.
    while cleaned and not cleaned[0]:
        cleaned.pop(0)
    while cleaned and not cleaned[-1]:
        cleaned.pop()

    return cleaned


def build_autodoc_blocks(
    func_name: str,
    doc_lines: Optional[List[str]],
    snippet_lines: List[str],
    max_snippet_lines: int,
) -> (List[str], List[str]):
    """Construct both wrapped comment lines (for C files) and raw comment text."""
    raw: List[str] = [AUTODOC_TAG, ""]

    if doc_lines:
        raw.append("Source summary (xzre/xzre.h):")
        for doc_line in doc_lines:
            if doc_line:
                raw.append(f"  {doc_line}")
            else:
                raw.append("")
        raw.append("")

    if snippet_lines:
        raw.append(f"Upstream implementation excerpt (xzre/xzre_code/{func_name}.c):")
        limit = min(len(snippet_lines), max_snippet_lines)
        for raw_line in snippet_lines[:limit]:
            safe_line = raw_line.replace("*/", "* /")
            raw.append(f"    {safe_line}")
        if len(snippet_lines) > max_snippet_lines:
            raw.append("    ...")
        raw.append("")

    # Ensure there is at least one blank line separating sections.
    if raw and raw[-1] == "":
        raw = raw[:-1]

    wrapped: List[str] = ["/*"]
    for line in raw:
        if line:
            wrapped.append(f" * {line}")
        else:
            wrapped.append(" *")
    wrapped.append(" */")
    return wrapped, raw


def build_from_existing_comment(comment_text: str) -> (List[str], List[str]):
    """Wrap an existing comment text (typically exported from Ghidra)."""
    raw = [line.rstrip() for line in comment_text.splitlines()]
    while raw and not raw[0]:
        raw.pop(0)
    while raw and not raw[-1]:
        raw.pop()
    if not raw:
        return [], []
    if raw[0] != AUTODOC_TAG:
        raw = [AUTODOC_TAG, ""] + raw
    wrapped = ["/*"]
    for line in raw:
        if line:
            wrapped.append(f" * {line}")
        else:
            wrapped.append(" *")
    wrapped.append(" */")
    return wrapped, raw


def strip_existing_autodoc(text: str) -> str:
    """Remove a previously generated AutoDoc block, if present."""
    pattern = re.compile(
        r"(?:\n[ \t]*){0,2}/\*\n \* " + re.escape(AUTODOC_TAG) + r"(?:.|\n)*?\*/\n?",
        re.MULTILINE,
    )
    return pattern.sub("", text, count=1)


def insert_comment(content: str, comment_lines: List[str]) -> str:
    """Insert comment_lines into the file content after the header banner."""
    lines = content.splitlines()
    insert_idx = 0
    while insert_idx < len(lines) and lines[insert_idx].startswith("//"):
        insert_idx += 1
    while insert_idx < len(lines) and not lines[insert_idx].strip():
        insert_idx += 1

    separator = []
    if insert_idx >= len(lines) or lines[insert_idx].strip():
        separator = [""]
    new_lines = lines[:insert_idx] + comment_lines + separator + lines[insert_idx:]
    # Preserve trailing newline if the original had one.
    trailing_newline = content.endswith("\n")
    joined = "\n".join(new_lines)
    if trailing_newline:
        joined += "\n"
    return joined


def annotate_file(
    file_path: Path,
    comment_lines: List[str],
    dry_run: bool,
) -> bool:
    """Apply the generated comment to the target file."""
    original = file_path.read_text(encoding="utf-8")
    stripped = strip_existing_autodoc(original)
    updated = insert_comment(stripped, comment_lines)
    if updated == original:
        return False
    if not dry_run:
        file_path.write_text(updated, encoding="utf-8")
    return True


def derive_function_name(file_path: Path) -> Optional[str]:
    """Extract function name from the decomp filename."""
    stem = file_path.stem
    if "_" not in stem:
        return None
    return stem.split("_", 1)[1]


def main() -> None:
    args = parse_args()

    docs = load_header_docs(args.header)
    changed_files = 0
    processed = 0

    autodoc_map: Dict[str, str] = {}
    fallback_map: Dict[str, str] = {}
    if args.fallback_json and args.fallback_json.exists():
        fallback_map = json.loads(args.fallback_json.read_text(encoding="utf-8"))

    for c_file in sorted(args.xzregh_dir.glob("*.c")):
        func_name = derive_function_name(c_file)
        if not func_name:
            continue

        doc_comment = docs.get(func_name)
        doc_lines = normalise_doc_comment(doc_comment) if doc_comment else None

        snippet_lines = extract_source_snippet(args.source_dir / f"{func_name}.c")

        if doc_lines or snippet_lines:
            wrapped_comment, raw_lines = build_autodoc_blocks(
                func_name, doc_lines, snippet_lines, args.max_snippet_lines
            )
        else:
            fallback_comment = fallback_map.get(func_name)
            if not fallback_comment:
                continue
            wrapped_comment, raw_lines = build_from_existing_comment(fallback_comment)
            if not wrapped_comment:
                continue

        comment_text = "\n".join(raw_lines)
        autodoc_map[func_name] = comment_text
        processed += 1

        if args.skip_decomp:
            continue

        if annotate_file(c_file, wrapped_comment, args.dry_run):
            changed_files += 1

    if args.emit_json:
        args.emit_json.parent.mkdir(parents=True, exist_ok=True)
        if args.emit_json.exists() and not args.dry_run:
            args.emit_json.unlink()
        if args.dry_run:
            print(f"[dry-run] Would write AutoDoc JSON to {args.emit_json}")
        else:
            args.emit_json.write_text(
                json.dumps(autodoc_map, indent=2, sort_keys=True), encoding="utf-8"
            )

    if args.skip_decomp:
        prefix = "[dry-run] " if args.dry_run else ""
        print(f"{prefix}Prepared AutoDoc entries for {processed} functions.")
    else:
        if args.dry_run:
            print(f"[dry-run] {changed_files} files would be updated.")
        else:
            print(f"Annotated {changed_files} files.")


if __name__ == "__main__":
    main()
