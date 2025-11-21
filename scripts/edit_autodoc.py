#!/usr/bin/env python3
"""
Small helper for updating metadata/functions_autodoc.json one function at a time.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict


DEFAULT_METADATA_PATH = Path("metadata/functions_autodoc.json")


def load_metadata(path: Path) -> Dict[str, str]:
    if not path.exists():
        raise FileNotFoundError(f"metadata file not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"metadata is not a JSON object: {path}")
    return data


def write_metadata(path: Path, data: Dict[str, str]) -> None:
    serialized = json.dumps(data, indent=2, ensure_ascii=False)
    serialized += "\n"
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        handle.write(serialized)
    tmp_path.replace(path)


def open_in_editor(initial_text: str) -> str:
    editor = (
        os.environ.get("VISUAL")
        or os.environ.get("EDITOR")
        or "vi"
    )
    with tempfile.NamedTemporaryFile(
        mode="w+", suffix=".md", delete=False
    ) as tmp:
        tmp_path = Path(tmp.name)
        tmp.write(initial_text)
        tmp.flush()
    try:
        subprocess.run([editor, str(tmp_path)], check=True)
        return tmp_path.read_text(encoding="utf-8")
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Edit a single entry in metadata/functions_autodoc.json"
    )
    parser.add_argument("function", help="Function identifier / key to update")
    parser.add_argument(
        "--metadata",
        type=Path,
        default=DEFAULT_METADATA_PATH,
        help="Path to functions_autodoc.json (default: %(default)s)",
    )
    parser.add_argument(
        "--set",
        dest="set_text",
        help="Provide the new text inline on the command line",
    )
    parser.add_argument(
        "--file",
        dest="file_path",
        type=Path,
        help="Read the new text from the specified file",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read the new text from stdin",
    )
    parser.add_argument(
        "--editor",
        action="store_true",
        help="Open $EDITOR/$VISUAL to modify the entry (default when no other input option is supplied)",
    )
    parser.add_argument(
        "--print",
        action="store_true",
        help="Print the existing entry and exit",
    )
    args = parser.parse_args()

    metadata_path = args.metadata
    data = load_metadata(metadata_path)

    function_key = args.function
    existing = data.get(function_key, "")

    if args.print and not any(
        [args.set_text, args.file_path, args.stdin, args.editor]
    ):
        if existing:
            sys.stdout.write(existing)
            if not existing.endswith("\n"):
                sys.stdout.write("\n")
        else:
            print(f"(no entry found for {function_key})")
        return 0

    if not any([args.set_text, args.file_path, args.stdin, args.editor]):
        args.editor = True

    if args.set_text is not None:
        new_text = args.set_text
    elif args.file_path is not None:
        new_text = args.file_path.read_text(encoding="utf-8")
    elif args.stdin:
        new_text = sys.stdin.read()
    elif args.editor:
        seed = existing or f"# {function_key}\n\n"
        new_text = open_in_editor(seed)
    else:
        parser.error("no input method provided")
        return 2

    if new_text == existing:
        print(f"[noop] {function_key} unchanged")
        return 0

    data[function_key] = new_text
    write_metadata(metadata_path, data)
    action = "updated" if existing else "created"
    print(f"[{action}] {function_key} -> {metadata_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
