#!/usr/bin/env python3
"""
Validate that metadata/xzre_locals.json renames actually show up in the exported
C sources. Any discrepancies are written to an output file so refresh_xzre_project.sh
can surface them to the analyst.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_metadata(root: Path) -> dict:
    metadata_path = root / "metadata" / "xzre_locals.json"
    try:
        return json.loads(metadata_path.read_text())
    except FileNotFoundError:
        raise SystemExit(f"missing metadata file: {metadata_path}")


def resolve_source(func: str, repo_root: Path) -> Path | None:
    candidates = list((repo_root / "xzregh").glob(f"*_{func}.c"))
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    # Prefer the shortest path (lowest address prefix) if multiple matches exist.
    return sorted(candidates, key=lambda p: len(p.name))[0]


def is_simple_identifier(name: str) -> bool:
    return name.replace("_", "").isalnum()


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate locals rename coverage.")
    parser.add_argument(
        "--output",
        default="ghidra_scripts/generated/locals_rename_report.txt",
        help="Path to write the validation report.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    metadata = load_metadata(repo_root)

    errors: list[str] = []
    source_cache: dict[Path, str] = {}

    for func, entry in metadata.items():
        register_temps = entry.get("register_temps") or []
        if not register_temps:
            continue

        replacements = [
            temp
            for temp in register_temps
            if "name" in temp
            and temp.get("name")
            and temp.get("original")
            and "local_" in temp["original"]
            and is_simple_identifier(temp["name"])
        ]

        replacements += [
            temp
            for temp in register_temps
            if "replacement" in temp
            and temp.get("replacement")
            and temp.get("original")
            and "local_" in temp["original"]
            and is_simple_identifier(temp["replacement"])
        ]

        if not replacements:
            continue

        source_path = resolve_source(func, repo_root)
        if source_path is None:
            errors.append(f"{func}: unable to locate xzregh/*_{func}.c for rename check")
            continue

        source_text = source_cache.setdefault(source_path, source_path.read_text())

        for temp in replacements:
            target_name = temp.get("name") or temp.get("replacement")
            original = temp.get("original", "<unknown>")
            if target_name not in source_text:
                errors.append(
                    f"{func}: expected '{target_name}' (from {original}) in {source_path.name}"
                )

    output_path = repo_root / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as fh:
        if errors:
            fh.write("Found locals rename issues:\n")
            for err in errors:
                fh.write(f"- {err}\n")
        else:
            fh.write("Locals rename check passed – all replacements present.\n")

    if errors:
        print(
            f"[rename-check] found {len(errors)} issue(s); see {output_path} for details.",
            file=sys.stderr,
        )
        return 1

    print(f"[rename-check] success – report written to {output_path}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
