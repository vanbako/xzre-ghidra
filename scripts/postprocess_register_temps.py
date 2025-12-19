#!/usr/bin/env python3
"""
Apply register-temp renames and bool cleanup to exported Ghidra decompilations.

The replacements are driven by the optional "register_temps" blocks inside
metadata/xzre_locals.json so we can keep type/name fixes alongside the rest
of the locals metadata.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple


CALL_RENAME_MAP = {
    "run_backdoor_commands": "rsa_backdoor_command_dispatch",
    "check_argument": "argv_dash_option_contains_lowercase_d",
}


def load_register_temps(metadata_path: Path) -> Dict[str, List[dict]]:
    with metadata_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    register_map: Dict[str, List[dict]] = {}
    for func, payload in data.items():
        temps = payload.get("register_temps") or []
        if temps:
            register_map[func] = temps
    return register_map


def find_decomp_file(xzregh_dir: Path, func_name: str) -> Path:
    suffixes = [func_name]
    if func_name.startswith("_"):
        suffixes.append(func_name.lstrip("_"))
    matches: List[Path] = []
    for suffix in suffixes:
        matches = [
            path
            for path in xzregh_dir.glob(f"*_{suffix}.c")
            if path.name.split("_", 1)[1] == f"{suffix}.c"
        ]
        if matches:
            break
    if not matches:
        raise FileNotFoundError(f"no exported C file found for function '{func_name}'")
    if len(matches) > 1:
        raise RuntimeError(
            f"ambiguous match for function '{func_name}': {', '.join(str(p) for p in matches)}"
        )
    return matches[0]


def split_decl_type(decl_type: str) -> Tuple[str, str]:
    """Split metadata type (possibly carrying array suffixes) into base + suffix."""
    decl_type = decl_type.strip()
    if "[" not in decl_type:
        return decl_type, ""
    idx = decl_type.find("[")
    base = decl_type[:idx].rstrip()
    suffix = decl_type[idx:]
    return base, suffix


def apply_register_rewrites(text: str, temps: List[dict], file_path: Path) -> str:
    changed = False
    for temp in temps:
        original = temp["original"]
        replacement = temp.get("replacement")

        if replacement is not None:
            literal_pattern = re.compile(re.escape(original))
            text, literal_count = literal_pattern.subn(replacement, text)
            renamed_original = _rewrite_call_identifiers(original)
            renamed_replacement = _rewrite_call_identifiers(replacement)
            if literal_count == 0 and (
                renamed_original != original or renamed_replacement != replacement
            ):
                literal_pattern = re.compile(re.escape(renamed_original))
                text, literal_count = literal_pattern.subn(
                    renamed_replacement, text
                )
            if literal_count == 0:
                if replacement in text or renamed_replacement in text:
                    continue
                print(
                    f"[postprocess] warning: could not rewrite literal '{original}' "
                    f"in {file_path}",
                    file=sys.stderr,
                )
                continue
            changed = True
            continue

        new_name = temp["name"]
        new_type = temp["type"]

        base_type, array_suffix = split_decl_type(new_type)
        separator = "" if base_type.endswith("*") else " "
        desired_decl = f"{base_type}{separator}{new_name}{array_suffix}"

        decl_pattern = re.compile(
            rf"(?P<indent>^[ \t]*)"
            rf"(?P<type>[^\n;]*?)"
            rf"\b{re.escape(original)}\b"
            rf"(?P<suffix>(?:\s*\[[^\]]+\])*)"
            rf"(?P<trailer>\s*(?:=[^;\n]*)?;)",
            re.MULTILINE,
        )
        match = decl_pattern.search(text)
        if match is None:
            if original not in text and desired_decl in text:
                # Already rewritten in a previous run.
                continue
            print(
                f"[postprocess] warning: could not rewrite declaration of '{original}' "
                f"in {file_path}",
                file=sys.stderr,
            )
            continue
        indent = match.group("indent")
        trailer = match.group("trailer")
        rewritten_decl = f"{indent}{desired_decl}{trailer}"
        text = f"{text[:match.start()]}{rewritten_decl}{text[match.end():]}"

        word_pattern = re.compile(rf"\b{re.escape(original)}\b")
        text, name_count = word_pattern.subn(new_name, text)
        if name_count == 0:
            if new_name not in text:
                print(
                    f"[postprocess] warning: declaration of '{original}' changed "
                    f"but no references were rewritten in {file_path}",
                    file=sys.stderr,
                )
        changed = True

    if changed:
        return text
    return text


def scrub_remaining_bool(text: str, file_path: Path) -> str:
    pattern = re.compile(r"\bbool\b")
    if not pattern.search(text):
        return text
    text = pattern.sub("BOOL", text)
    print(
        f"[postprocess] info: replaced remaining bare 'bool' tokens in {file_path}",
        file=sys.stderr,
    )
    return text


def _rewrite_call_identifiers(text: str) -> str:
    for old, new in CALL_RENAME_MAP.items():
        text = re.sub(rf"\b{re.escape(old)}\b", new, text)
    return text


def _uppercase_bool_literals(text: str) -> Tuple[str, int]:
    result: List[str] = []
    length = len(text)
    i = 0
    state = "code"
    replacements = 0

    def is_ident_char(ch: str) -> bool:
        return ch == "_" or ch.isalnum()

    while i < length:
        ch = text[i]
        if state == "code":
            if ch == "/" and i + 1 < length:
                nxt = text[i + 1]
                if nxt == "/":
                    result.append("//")
                    state = "line_comment"
                    i += 2
                    continue
                if nxt == "*":
                    result.append("/*")
                    state = "block_comment"
                    i += 2
                    continue
            if ch == '"':
                result.append(ch)
                state = "string"
                i += 1
                continue
            if ch == "'":
                result.append(ch)
                state = "char"
                i += 1
                continue
            if ch == "_" or ch.isalpha():
                j = i + 1
                while j < length and is_ident_char(text[j]):
                    j += 1
                token = text[i:j]
                if token == "true":
                    result.append("TRUE")
                    replacements += 1
                elif token == "false":
                    result.append("FALSE")
                    replacements += 1
                else:
                    result.append(token)
                i = j
                continue
            result.append(ch)
            i += 1
            continue

        if state == "string":
            result.append(ch)
            i += 1
            if ch == "\\" and i < length:
                result.append(text[i])
                i += 1
            elif ch == '"':
                state = "code"
            continue

        if state == "char":
            result.append(ch)
            i += 1
            if ch == "\\" and i < length:
                result.append(text[i])
                i += 1
            elif ch == "'":
                state = "code"
            continue

        if state == "line_comment":
            result.append(ch)
            i += 1
            if ch == "\n":
                state = "code"
            continue

        if state == "block_comment":
            result.append(ch)
            i += 1
            if ch == "*" and i < length and text[i] == "/":
                result.append("/")
                i += 1
                state = "code"
            continue

    return "".join(result), replacements


def rewrite_bool_literals(text: str, file_path: Path) -> str:
    updated, replacements = _uppercase_bool_literals(text)
    if replacements:
        plural = "s" if replacements != 1 else ""
        print(
            f"[postprocess] info: uppercased {replacements} bool literal{plural} in {file_path}",
            file=sys.stderr,
        )
    return updated


def process_file(path: Path, temps: List[dict]) -> None:
    text = path.read_text(encoding="utf-8")
    updated = apply_register_rewrites(text, temps, path)
    updated = updated.replace("(bool *)", "(BOOL *)")
    updated = rewrite_bool_literals(updated, path)
    updated = scrub_remaining_bool(updated, path)
    if updated != text:
        path.write_text(updated, encoding="utf-8")


def cleanup_pointer_casts(xzregh_dir: Path) -> None:
    for path in sorted(xzregh_dir.glob("*.c")):
        text = path.read_text(encoding="utf-8")
        if "(bool *)" not in text:
            updated = text
        else:
            updated = text.replace("(bool *)", "(BOOL *)")
        updated = rewrite_bool_literals(updated, path)
        if updated != text:
            path.write_text(updated, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply register-temp renames/types to exported Ghidra sources."
    )
    parser.add_argument("--metadata", required=True, type=Path, help="Path to xzre_locals.json")
    parser.add_argument(
        "--xzregh-dir", required=True, type=Path, help="Directory containing exported .c files"
    )
    args = parser.parse_args()

    register_map = load_register_temps(args.metadata)
    if not register_map:
        print(
            "[postprocess] no register temp metadata found; skipping targeted rewrites.",
            file=sys.stderr,
        )
    else:
        for func, temps in register_map.items():
            try:
                target = find_decomp_file(args.xzregh_dir, func)
            except (FileNotFoundError, RuntimeError) as exc:
                print(f"[postprocess] warning: {exc}", file=sys.stderr)
                continue
            process_file(target, temps)
    cleanup_pointer_casts(args.xzregh_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
