#!/usr/bin/env python3
"""
Extracts local variable declarations from the decompiled xzre sources.

This script leverages Clang's JSON AST dump to recover local variable names and
type strings for each function defined under xzre/xzre_code. The resulting data
is stored as JSON for consumption by the Ghidra automation pipeline.
"""

import argparse
import json
import os
import subprocess
import sys
from collections import OrderedDict
from typing import Any, Dict, Iterable, List, Tuple

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
XZRE_SOURCE_DIRS = [
    os.path.join(REPO_ROOT, "xzre", "xzre_code"),
    os.path.join(REPO_ROOT, "xzre"),
]
DEFAULT_OUTPUT_PATH = os.path.join(REPO_ROOT, "metadata", "xzre_locals.json")


class AstParseError(RuntimeError):
    """Raised when the Clang AST cannot be parsed."""


def _get_loc_file(loc: Dict[str, Any]) -> str:
    """
    Recover the source filename recorded by Clang for a node location.
    Clang nests locations via an ``includedFrom`` block, so unwrap it if needed.
    """
    if not isinstance(loc, dict):
        return ""
    if "includedFrom" in loc and isinstance(loc["includedFrom"], dict):
        return _get_loc_file(loc["includedFrom"])
    return loc.get("file", "") or ""


def _collect_var_decls(node: Dict[str, Any], locals_out: List[Dict[str, Any]]) -> None:
    """
    Recursively descend the AST subtree rooted at *node* and record each VarDecl.
    """
    if not isinstance(node, dict):
        return

    if node.get("kind") == "VarDecl":
        name = node.get("name")
        qual_type = (node.get("type") or {}).get("qualType")
        if name and qual_type:
            entry = OrderedDict()
            entry["name"] = name
            entry["type"] = qual_type
            loc = node.get("loc") or {}
            line = loc.get("line")
            if isinstance(line, int):
                entry["line"] = line
            locals_out.append(entry)
        # Do not descend further; locals declared with initializer expressions
        # can contain nested VarDecls we do not want to double-count.
        return

    for child in node.get("inner") or []:
        _collect_var_decls(child, locals_out)


def _process_function(
    node: Dict[str, Any], rel_source: str, abs_source: str
) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Inspect a FunctionDecl node and return its local variable list when the
    definition resides in *rel_source*. Returns an empty name when the function
    does not match the requested source file or lacks a body.
    """
    if node.get("kind") != "FunctionDecl":
        return ("", [])

    func_name = node.get("name")
    if not func_name:
        return ("", [])

    # Ignore forward declarations from headers.
    loc = node.get("loc") or {}
    node_file = _get_loc_file(loc)
    node_abs = ""
    if node_file:
        node_abs = os.path.abspath(os.path.join(REPO_ROOT, node_file))
    else:
        range_info = node.get("range") or {}
        range_begin = range_info.get("begin") or {}
        range_file = _get_loc_file(range_begin)
        if not range_file:
            if node.get("isImplicit"):
                return ("", [])
            node_abs = abs_source
        else:
            node_abs = os.path.abspath(os.path.join(REPO_ROOT, range_file))
    if os.path.normpath(node_abs) != os.path.normpath(abs_source):
        return ("", [])

    body = None
    for child in node.get("inner") or []:
        if isinstance(child, dict) and child.get("kind") == "CompoundStmt":
            body = child
            break
    if body is None:
        return ("", [])

    locals_out: List[Dict[str, Any]] = []
    _collect_var_decls(body, locals_out)
    return (func_name, locals_out)


def _iter_json_objects(blob: str) -> Iterable[Dict[str, Any]]:
    """
    Stream JSON objects produced by ``clang -ast-dump=json``. Clang emits one
    JSON object per top-level declaration with whitespace separators.
    """
    decoder = json.JSONDecoder()
    length = len(blob)
    idx = 0
    while idx < length:
        try:
            obj, end_idx = decoder.raw_decode(blob, idx)
            yield obj
            idx = end_idx
            while idx < length and blob[idx].isspace():
                idx += 1
        except json.JSONDecodeError as exc:
            context = blob[idx : min(idx + 200, length)]
            raise AstParseError(f"failed to decode AST JSON near: {context!r}") from exc


def extract_from_source(path: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Run Clang on *path* and return a mapping of function name -> locals metadata.
    """
    rel_source = os.path.relpath(path, REPO_ROOT).replace(os.sep, "/")
    abs_source = os.path.abspath(path)

    clang_cmd = [
        "clang",
        "-std=gnu17",
        "-fsyntax-only",
        "-fno-color-diagnostics",
        "-w",  # Squash warning chatter (still logged on stderr by #warning).
        "-I",
        os.path.join(REPO_ROOT, "xzre"),
        "-Xclang",
        "-ast-dump=json",
        path,
    ]

    result = subprocess.run(
        clang_cmd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if result.stderr:
        # Forward preprocessing warnings to stdout so the pipeline log captures them.
        sys.stderr.write(result.stderr)

    functions: Dict[str, List[Dict[str, Any]]] = OrderedDict()
    for root in _iter_json_objects(result.stdout):
        stack = [root]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                name, locals_list = _process_function(node, rel_source, abs_source)
                if name:
                    functions[name] = locals_list
                stack.extend(node.get("inner") or [])
            elif isinstance(node, list):
                stack.extend(node)
    return functions


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract local variable metadata from xzre sources."
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_PATH,
        help="Destination JSON file (default: %(default)s).",
    )
    return parser.parse_args(argv)


def main() -> None:
    args = parse_args(sys.argv[1:])
    sources = []
    seen = set()
    for directory in XZRE_SOURCE_DIRS:
        if not os.path.isdir(directory):
            continue
        for entry in sorted(os.listdir(directory)):
            if not entry.endswith(".c"):
                continue
            path = os.path.join(directory, entry)
            if not os.path.isfile(path):
                continue
            norm = os.path.normpath(path)
            if norm in seen:
                continue
            seen.add(norm)
            sources.append(path)

    if not sources:
        dirs = ", ".join(XZRE_SOURCE_DIRS)
        raise SystemExit(f"no C sources found under {dirs}")

    existing_data: Dict[str, Dict[str, Any]] = {}
    output_path = os.path.abspath(args.output)
    if os.path.exists(output_path):
        with open(output_path, "r", encoding="utf-8") as existing_file:
            try:
                existing_data = json.load(existing_file)
            except json.JSONDecodeError:
                existing_data = {}

    all_functions: Dict[str, Dict[str, Any]] = OrderedDict()
    for source_path in sources:
        rel_source = os.path.relpath(source_path, REPO_ROOT).replace(os.sep, "/")
        try:
            func_map = extract_from_source(source_path)
        except subprocess.CalledProcessError as exc:
            sys.stderr.write(
                f"warning: clang failed for {rel_source} (exit {exc.returncode}); skipping\n"
            )
            continue
        except AstParseError as exc:
            sys.stderr.write(
                f"warning: failed to parse AST for {rel_source}: {exc}\n"
            )
            continue

        for func_name, locals_list in func_map.items():
            if func_name in all_functions:
                # Multiple definitions for the same function should not occur; warn
                # and prefer the latest copy in case the local data evolved.
                sys.stderr.write(
                    f"warning: duplicate definition for {func_name}; overwriting\n"
                )
            entry = OrderedDict(
                source=rel_source,
                locals=locals_list,
            )
            existing_entry = existing_data.get(func_name)
            if isinstance(existing_entry, dict):
                for key, value in existing_entry.items():
                    if key in entry:
                        continue
                    entry[key] = value
            all_functions[func_name] = entry

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as outf:
        json.dump(all_functions, outf, indent=2)
        outf.write("\n")

    print(
        f"Wrote local variable metadata for {len(all_functions)} functions to {output_path}"
    )


if __name__ == "__main__":
    main()
