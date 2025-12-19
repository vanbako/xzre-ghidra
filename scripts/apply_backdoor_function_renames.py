#!/usr/bin/env python3
"""
Apply function renames from metadata/backdoor_function_renames.json.

Updates metadata and documentation sources, while skipping pipeline outputs.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, Optional, Pattern, Tuple


EXCLUDED_PATHS = [
    Path(".git"),
    Path(".ghidra_home"),
    Path(".ghidra_user"),
    Path(".vscode"),
    Path("ghidra_projects"),
    Path("ghidra_scripts/generated"),
    Path("third_party"),
    Path("xzre"),
    Path("xzregh"),
]


def _load_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path, data) -> None:
    serialized = json.dumps(data, indent=2, ensure_ascii=True)
    serialized += "\n"
    path.write_text(serialized, encoding="utf-8")


def _load_mapping(path: Path) -> Dict[str, str]:
    data = _load_json(path)
    if not isinstance(data, dict):
        raise ValueError("rename map is not a JSON object: {}".format(path))
    mapping = {}
    for old, new in data.items():
        if not isinstance(old, str) or not isinstance(new, str):
            raise ValueError("rename map contains non-string entries")
        if old == new:
            continue
        mapping[old] = new
    collisions = {}
    for old, new in mapping.items():
        if new in collisions and collisions[new] != old:
            raise ValueError(
                "rename map has duplicate target '{}': {}, {}".format(
                    new, collisions[new], old
                )
            )
        collisions[new] = old
    return mapping


def _build_pattern(keys: Iterable[str], allow_underscore: bool) -> Optional[Pattern[str]]:
    keys = sorted((re.escape(k) for k in keys), key=len, reverse=True)
    if not keys:
        return None
    if allow_underscore:
        prefix = r"(?<![A-Za-z0-9_])"
        suffix = r"(?![A-Za-z0-9_])"
    else:
        prefix = r"(?<![A-Za-z0-9])"
        suffix = r"(?![A-Za-z0-9])"
    return re.compile(prefix + r"(?:{})".format("|".join(keys)) + suffix)


def _replace_text(text: str, pattern: Optional[Pattern[str]], mapping: Dict[str, str]) -> str:
    if not pattern:
        return text
    return pattern.sub(lambda m: mapping.get(m.group(0), m.group(0)), text)


def _replace_in_data(value, pattern: Optional[Pattern[str]], mapping: Dict[str, str]):
    if isinstance(value, str):
        return _replace_text(value, pattern, mapping)
    if isinstance(value, list):
        return [_replace_in_data(item, pattern, mapping) for item in value]
    if isinstance(value, dict):
        return {key: _replace_in_data(val, pattern, mapping) for key, val in value.items()}
    return value


def _rename_dict_keys(data: Dict[str, object], mapping: Dict[str, str], label: str) -> Tuple[Dict[str, object], bool]:
    renamed = {}
    changed = False
    for key, value in data.items():
        new_key = mapping.get(key, key)
        if new_key in renamed:
            raise ValueError(
                "{}: rename collision for '{}' -> '{}'".format(label, key, new_key)
            )
        renamed[new_key] = value
        if new_key != key:
            changed = True
    return renamed, changed


def _path_is_excluded(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True
    for excluded in EXCLUDED_PATHS:
        if rel == excluded or rel.parts[: len(excluded.parts)] == excluded.parts:
            return True
    return False


def _iter_text_files(root: Path, extensions: Iterable[str]) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        if _path_is_excluded(base, root):
            dirnames[:] = []
            continue
        pruned = []
        for name in dirnames:
            candidate = base / name
            if not _path_is_excluded(candidate, root):
                pruned.append(name)
        dirnames[:] = pruned
        for filename in filenames:
            path = base / filename
            if _path_is_excluded(path, root):
                continue
            if path.suffix in extensions:
                yield path


def _update_linker_map(path: Path, mapping: Dict[str, str], dry_run: bool) -> bool:
    data = _load_json(path)
    if not isinstance(data, list):
        raise ValueError("linker map is not a list: {}".format(path))
    changed = False
    for entry in data:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if name in mapping:
            entry["name"] = mapping[name]
            changed = True
    if changed and not dry_run:
        _write_json(path, data)
    return changed


def _update_functions_autodoc(path: Path, mapping: Dict[str, str], strict_pattern: Optional[Pattern[str]], dry_run: bool) -> bool:
    data = _load_json(path)
    if not isinstance(data, dict):
        raise ValueError("AutoDoc metadata is not a JSON object: {}".format(path))
    renamed, key_changed = _rename_dict_keys(data, mapping, "functions_autodoc")
    value_changed = False
    updated = {}
    for key, value in renamed.items():
        new_value = _replace_in_data(value, strict_pattern, mapping)
        if new_value != value:
            value_changed = True
        updated[key] = new_value
    changed = key_changed or value_changed
    if changed and not dry_run:
        _write_json(path, updated)
    return changed


def _update_locals(path: Path, mapping: Dict[str, str], dry_run: bool) -> bool:
    data = _load_json(path)
    if not isinstance(data, dict):
        raise ValueError("locals metadata is not a JSON object: {}".format(path))
    renamed, key_changed = _rename_dict_keys(data, mapping, "xzre_locals")
    if key_changed and not dry_run:
        _write_json(path, renamed)
    return key_changed


def _update_type_docs(path: Path, mapping: Dict[str, str], strict_pattern: Optional[Pattern[str]], dry_run: bool) -> bool:
    data = _load_json(path)
    if not isinstance(data, dict):
        raise ValueError("type_docs metadata is not a JSON object: {}".format(path))
    updated = _replace_in_data(data, strict_pattern, mapping)
    if updated != data and not dry_run:
        _write_json(path, updated)
    return updated != data


def _update_xzre_types(path: Path, mapping: Dict[str, str], strict_pattern: Optional[Pattern[str]], dry_run: bool) -> bool:
    data = _load_json(path)
    if not isinstance(data, dict):
        raise ValueError("xzre_types metadata is not a JSON object: {}".format(path))
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise ValueError("xzre_types metadata missing entries list: {}".format(path))
    changed = False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        names = entry.get("names")
        if isinstance(names, list):
            new_names = []
            renamed = False
            for name in names:
                if isinstance(name, str) and name in mapping:
                    new_names.append(mapping[name])
                    renamed = True
                else:
                    new_names.append(name)
            if renamed:
                entry["names"] = new_names
                changed = True
        code = entry.get("code")
        if isinstance(code, str):
            new_code = _replace_text(code, strict_pattern, mapping)
            if new_code != code:
                entry["code"] = new_code
                changed = True
    preamble = data.get("preamble")
    if isinstance(preamble, str):
        new_preamble = _replace_text(preamble, strict_pattern, mapping)
        if new_preamble != preamble:
            data["preamble"] = new_preamble
            changed = True
    if changed and not dry_run:
        _write_json(path, data)
    return changed


def _update_text_files(root: Path, mapping: Dict[str, str], loose_pattern: Optional[Pattern[str]], dry_run: bool) -> int:
    changed = 0
    for path in _iter_text_files(root, extensions={".md", ".py"}):
        text = path.read_text(encoding="utf-8")
        updated = _replace_text(text, loose_pattern, mapping)
        if updated != text:
            changed += 1
            if not dry_run:
                path.write_text(updated, encoding="utf-8")
    return changed


def _rename_markdown_files(root: Path, mapping: Dict[str, str], loose_pattern: Optional[Pattern[str]], dry_run: bool) -> int:
    renames = []
    for path in _iter_text_files(root, extensions={".md"}):
        new_name = _replace_text(path.name, loose_pattern, mapping)
        if new_name != path.name:
            target = path.with_name(new_name)
            if target.exists():
                raise ValueError("rename target already exists: {}".format(target))
            renames.append((path, target))
    for src, dst in renames:
        if not dry_run:
            src.rename(dst)
    return len(renames)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply backdoor function renames across metadata and docs."
    )
    parser.add_argument(
        "--mapping",
        default="metadata/backdoor_function_renames.json",
        help="Path to backdoor_function_renames.json (default: %(default)s)",
    )
    parser.add_argument(
        "--root",
        default=None,
        help="Repo root (defaults to parent of this script)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report changes without writing files",
    )
    args = parser.parse_args()

    root = Path(args.root) if args.root else Path(__file__).resolve().parents[1]
    root = root.resolve()
    mapping_path = Path(args.mapping)
    if not mapping_path.is_absolute():
        mapping_path = (root / mapping_path).resolve()

    mapping = _load_mapping(mapping_path)
    if not mapping:
        print("No renames found in {}".format(mapping_path))
        return 0

    strict_pattern = _build_pattern(mapping.keys(), allow_underscore=True)
    loose_pattern = _build_pattern(mapping.keys(), allow_underscore=False)

    changed = False
    changes = []

    linker_map = root / "metadata/linker_map.json"
    if linker_map.exists():
        if _update_linker_map(linker_map, mapping, args.dry_run):
            changes.append(str(linker_map))
            changed = True

    autodoc = root / "metadata/functions_autodoc.json"
    if autodoc.exists():
        if _update_functions_autodoc(autodoc, mapping, strict_pattern, args.dry_run):
            changes.append(str(autodoc))
            changed = True

    locals_path = root / "metadata/xzre_locals.json"
    if locals_path.exists():
        if _update_locals(locals_path, mapping, args.dry_run):
            changes.append(str(locals_path))
            changed = True

    types_path = root / "metadata/xzre_types.json"
    if types_path.exists():
        if _update_xzre_types(types_path, mapping, strict_pattern, args.dry_run):
            changes.append(str(types_path))
            changed = True

    type_docs = root / "metadata/type_docs.json"
    if type_docs.exists():
        if _update_type_docs(type_docs, mapping, strict_pattern, args.dry_run):
            changes.append(str(type_docs))
            changed = True

    text_changes = _update_text_files(root, mapping, loose_pattern, args.dry_run)
    if text_changes:
        changed = True

    renamed_files = _rename_markdown_files(root, mapping, loose_pattern, args.dry_run)
    if renamed_files:
        changed = True

    if args.dry_run:
        print("Dry run: {} metadata files, {} text files, {} md renames".format(
            len(changes), text_changes, renamed_files
        ))
    else:
        print("Updated: {} metadata files, {} text files, {} md renames".format(
            len(changes), text_changes, renamed_files
        ))
    if not changed:
        print("No changes needed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
