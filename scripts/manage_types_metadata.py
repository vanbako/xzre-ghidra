#!/usr/bin/env python3
"""
Convert between the human-maintained xzre type header and a structured JSON
metadata file so typedefs, structs, enums, and related declarations can flow
through the same refresh pipeline as function docs.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


ATTR_TOKEN = "__attribute__"


def remove_attributes(text: str) -> str:
    """Strip GCC-style __attribute__((...)) blocks to simplify parsing."""

    result: List[str] = []
    i = 0
    length = len(text)
    while i < length:
        if text.startswith(ATTR_TOKEN, i):
            i += len(ATTR_TOKEN)
            while i < length and text[i].isspace():
                i += 1
            if i < length and text[i] == "(":
                depth = 0
                while i < length:
                    char = text[i]
                    if char == "(":
                        depth += 1
                    elif char == ")":
                        depth -= 1
                        if depth == 0:
                            i += 1
                            break
                    i += 1
            continue
        result.append(text[i])
        i += 1
    return "".join(result)


def split_preamble(header_text: str) -> Tuple[List[str], str]:
    """Extract leading preprocessor lines (e.g., #pragma once)."""

    lines = header_text.splitlines()
    preamble: List[str] = []
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()
        if not stripped:
            idx += 1
            continue
        if stripped.startswith("#"):
            preamble.append(stripped)
            idx += 1
            continue
        break
    body = "\n".join(lines[idx:]).lstrip("\n")
    return preamble, body


def split_statements(body: str) -> List[str]:
    """Split the header body into top-level statements terminated by ';'."""

    statements: List[str] = []
    start: Optional[int] = None
    brace = paren = bracket = 0
    in_line_comment = False
    in_block_comment = False
    in_string = False
    string_char = ""
    i = 0
    length = len(body)

    while i < length:
        ch = body[i]
        nxt = body[i + 1] if i + 1 < length else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue

        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == string_char:
                in_string = False
            i += 1
            continue

        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue

        if ch in ("'", '"'):
            in_string = True
            string_char = ch
            i += 1
            continue

        if start is None:
            if ch.isspace():
                i += 1
                continue
            start = i

        if ch == "{":
            brace += 1
        elif ch == "}":
            brace = max(brace - 1, 0)
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(paren - 1, 0)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(bracket - 1, 0)

        if (
            ch == ";"
            and brace == 0
            and paren == 0
            and bracket == 0
            and not in_block_comment
            and not in_line_comment
            and not in_string
            and start is not None
        ):
            statements.append(body[start : i + 1].strip())
            start = None

        i += 1

    return [stmt for stmt in statements if stmt and stmt != ";"]


def split_declarators(text: str) -> List[str]:
    """Split a declaration into individual declarator strings."""

    chunks: List[str] = []
    current: List[str] = []
    brace = paren = bracket = 0
    in_string = False
    string_char = ""

    for ch in text:
        if in_string:
            current.append(ch)
            if ch == "\\":
                continue
            if ch == string_char:
                in_string = False
            continue

        if ch in ("'", '"'):
            in_string = True
            string_char = ch
            current.append(ch)
            continue

        if ch == "{":
            brace += 1
        elif ch == "}":
            brace = max(brace - 1, 0)
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(paren - 1, 0)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(bracket - 1, 0)

        if ch == "," and brace == 0 and paren == 0 and bracket == 0:
            chunk = "".join(current).strip()
            if chunk:
                chunks.append(chunk)
            current = []
            continue

        current.append(ch)

    tail = "".join(current).strip()
    if tail:
        chunks.append(tail)
    return chunks


def remove_trailing_params(decl: str) -> str:
    """Drop the trailing parameter list from a function prototype."""

    decl = decl.rstrip()
    if not decl.endswith(")"):
        return decl

    depth = 0
    i = len(decl) - 1
    while i >= 0:
        ch = decl[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            depth -= 1
            if depth == 0:
                return decl[:i].rstrip()
        i -= 1
    return decl


IDENT_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*$")
FUNC_PTR_RE = re.compile(r"\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)$")


def extract_name_from_decl(chunk: str) -> Optional[str]:
    """Best-effort extraction of the identifier being declared."""

    chunk = remove_attributes(chunk).strip()
    if not chunk:
        return None

    chunk = remove_trailing_params(chunk)

    while chunk.endswith("]"):
        idx = chunk.rfind("[")
        if idx == -1:
            break
        chunk = chunk[:idx].rstrip()

    match = FUNC_PTR_RE.search(chunk)
    if match:
        return match.group(1)

    while chunk.endswith("*"):
        chunk = chunk[:-1].rstrip()

    match = IDENT_RE.search(chunk)
    if match:
        return match.group(1)

    return None


def extract_declarator_names(text: str) -> List[str]:
    chunks = split_declarators(text)
    names = []
    for chunk in chunks:
        name = extract_name_from_decl(chunk)
        if name:
            names.append(name)
    return names


def classify_statement(stmt: str) -> Tuple[str, List[str]]:
    stripped = stmt.lstrip()

    if stripped.startswith("typedef enum"):
        names = extract_declarator_names(stripped[len("typedef") :].rstrip(";").strip())
        return "enum", names
    if stripped.startswith("enum"):
        names = extract_struct_or_enum_names(stripped, "enum")
        return "enum", names
    if stripped.startswith("typedef struct"):
        names = extract_declarator_names(stripped[len("typedef") :].rstrip(";").strip())
        return "struct", names
    if stripped.startswith("typedef union"):
        names = extract_declarator_names(stripped[len("typedef") :].rstrip(";").strip())
        return "union", names
    if stripped.startswith("struct"):
        names = extract_struct_or_enum_names(stripped, "struct")
        return "struct", names
    if stripped.startswith("union"):
        names = extract_struct_or_enum_names(stripped, "union")
        return "union", names
    if stripped.startswith("typedef"):
        names = extract_declarator_names(stripped[len("typedef") :].rstrip(";").strip())
        return "typedef", names
    if stripped.startswith("extern"):
        names = extract_declarator_names(stripped[len("extern") :].rstrip(";").strip())
        return "declaration", names
    if "(" in stripped and stripped.endswith(");"):
        names = extract_function_names(stripped)
        return "declaration", names
    return "unknown", []


TAG_NAME_RE = re.compile(r"^(struct|union|enum)\s+([A-Za-z_][A-Za-z0-9_]*)")


def extract_struct_or_enum_names(stmt: str, keyword: str) -> List[str]:
    text = remove_attributes(stmt.rstrip(";").strip())
    names: List[str] = []

    match = TAG_NAME_RE.match(text)
    if match and match.group(1) == keyword:
        names.append(match.group(2))

    brace_idx = text.find("{")
    if brace_idx == -1:
        return names

    depth = 0
    i = brace_idx
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                remainder = text[i + 1 :].strip()
                if remainder:
                    names.extend(
                        ident
                        for ident in extract_declarator_names(remainder)
                        if ident not in names
                    )
                break
        i += 1
    return names


FUNC_NAME_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.S)


def extract_function_names(stmt: str) -> List[str]:
    text = remove_attributes(stmt.rstrip(";"))
    matches = FUNC_NAME_RE.findall(text)
    if not matches:
        return []
    return [matches[-1]]


def build_metadata(header_text: str) -> Dict[str, object]:
    preamble, body = split_preamble(header_text)
    statements = split_statements(body)

    entries = []
    for stmt in statements:
        kind, names = classify_statement(stmt)
        entries.append({"kind": kind, "names": names, "code": stmt})

    return {
        "version": 1,
        "preamble": preamble,
        "entries": entries,
    }


def format_comment_block(text: str) -> str:
    lines = ["/*"]
    for raw_line in text.rstrip().splitlines():
        line = raw_line.rstrip()
        if line:
            lines.append(" * " + line)
        else:
            lines.append(" *")
    lines.append(" */")
    return "\n".join(lines)


def resolve_entry_doc(entry: Dict[str, object], doc_map: Dict[str, str]) -> Optional[str]:
    doc = entry.get("doc")
    if doc:
        return doc
    if not doc_map:
        return None
    for name in entry.get("names", []):
        mapped = doc_map.get(name)
        if mapped:
            return mapped
    return None


def render_header(
    metadata: Dict[str, object],
    include_preamble: bool,
    doc_map: Optional[Dict[str, str]] = None,
) -> str:
    lines: List[str] = []
    if include_preamble:
        for line in metadata.get("preamble", []):
            lines.append(line)
        if metadata.get("preamble"):
            lines.append("")
    doc_map = doc_map or {}
    for entry in metadata.get("entries", []):
        doc_text = resolve_entry_doc(entry, doc_map)
        if doc_text:
            lines.append(format_comment_block(doc_text))
        lines.append(entry["code"])
        lines.append("")
    text = "\n".join(lines).rstrip() + "\n"
    return text


def load_metadata(path: Path) -> Dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def save_metadata(path: Path, metadata: Dict[str, object]) -> None:
    path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")


def cmd_extract(args: argparse.Namespace) -> None:
    header_text = Path(args.header).read_text(encoding="utf-8")
    metadata = build_metadata(header_text)
    save_metadata(Path(args.json), metadata)


def load_doc_map(path: Optional[Path]) -> Dict[str, str]:
    if not path:
        return {}
    if not path.exists():
        raise FileNotFoundError("type doc file not found: {}".format(path))
    with path.open("r", encoding="utf-8") as doc_file:
        data = json.load(doc_file)
    if not isinstance(data, dict):
        raise ValueError("type doc file must contain a JSON object")
    return {str(k): str(v) for k, v in data.items()}


def cmd_render(args: argparse.Namespace) -> None:
    metadata = load_metadata(Path(args.json))
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc_map = load_doc_map(Path(args.docs)) if args.docs else {}
    content = render_header(
        metadata,
        include_preamble=not args.skip_preamble,
        doc_map=doc_map,
    )
    output_path.write_text(content, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Manage xzre type metadata (header <-> JSON)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract_parser = subparsers.add_parser("extract", help="Convert header to JSON.")
    extract_parser.add_argument("--header", required=True, help="Path to header file.")
    extract_parser.add_argument(
        "--json", required=True, help="Output JSON metadata path."
    )
    extract_parser.set_defaults(func=cmd_extract)

    render_parser = subparsers.add_parser(
        "render", help="Render header from JSON metadata."
    )
    render_parser.add_argument("--json", required=True, help="Metadata JSON path.")
    render_parser.add_argument("--output", required=True, help="Header output path.")
    render_parser.add_argument(
        "--skip-preamble",
        action="store_true",
        help="Omit preamble lines when rendering.",
    )
    render_parser.add_argument(
        "--docs",
        help="Optional JSON mapping of type names to documentation comments.",
    )
    render_parser.set_defaults(func=cmd_render)

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
