#!/usr/bin/env python3
"""
Dump the obfuscated string blobs from liblzma_la-crc64-fast.o and emit a
commented hexdump plus a best-effort plaintext table derived from the
EncodedStringId enum. This runs in the refresh pipeline so analysts can
inspect the string trie/mask side by side with the decoded labels.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, Tuple


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        default="xzre/liblzma_la-crc64-fast.o",
        help="Path to liblzma_la-crc64-fast.o",
    )
    parser.add_argument(
        "--linker-map",
        default="metadata/linker_map.json",
        help="Path to linker_map.json for symbol offsets",
    )
    parser.add_argument(
        "--types",
        default="metadata/xzre_types.json",
        help="Path to xzre_types.json (to scrape EncodedStringId names)",
    )
    parser.add_argument(
        "--output-dir",
        default="/tmp/xzre_rodata",
        help="Directory to write dumps into (defaults to /tmp so the repo stays clean).",
    )
    return parser.parse_args()


def load_linker_offsets(path: Path) -> Dict[str, Tuple[int, str]]:
    with path.open("r", encoding="utf-8") as fh:
        entries = json.load(fh)
    result = {}
    for entry in entries:
        name = entry.get("name")
        if name in {"string_action_data", "string_mask_data"}:
            result[name] = (int(entry["offset"]), entry.get("section", ""))
    return result


def load_encoded_strings(path: Path) -> Dict[int, str]:
    with path.open("r", encoding="utf-8") as fh:
        types = json.load(fh)
    entries = types.get("entries", []) if isinstance(types, dict) else []
    enum_block = next(
        (
            block
            for block in entries
            if isinstance(block, dict)
            and block.get("kind") == "enum"
            and "EncodedStringId" in block.get("names", [])
        ),
        None,
    )
    mapping: Dict[int, str] = {}
    if enum_block is None:
        return mapping
    pattern = re.compile(r"STR_[A-Za-z0-9_]+\\s*=\\s*0x([0-9a-fA-F]+)")
    for line in enum_block["code"].splitlines():
        if "STR_" not in line:
            continue
        name = line.strip().split("=")[0].strip().rstrip(",")
        match = pattern.search(line)
        if not match:
            continue
        mapping[int(match.group(1), 16)] = name
    return mapping


def friendly(name: str) -> str:
    text = name.removeprefix("STR_")
    text = text.replace("_", " ").strip()
    replacements = {
        " percent s": "%s",
        " percent d": "%d",
        " percent ld": "%ld",
        " ssh 2 0": "SSH-2.0",
        " ssh_2_0": "SSH-2.0",
        " ssh 2": "SSH-2.0",
        " ssh 2_0": "SSH-2.0",
        " 48s": "%48s",
        " 2c": "2C",
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    return text


def hexdump(blob: bytes) -> Iterable[str]:
    for offset in range(0, len(blob), 16):
        chunk = blob[offset : offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        yield f"{offset:08x}  {hex_part:<47}  {ascii_part}"


def main() -> int:
    args = parse_args()
    root = Path.cwd()
    binary_path = (root / args.binary).resolve()
    linker_map_path = (root / args.linker_map).resolve()
    types_path = (root / args.types).resolve()
    out_dir = (root / args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    offsets = load_linker_offsets(linker_map_path)
    sizes = {
        "string_action_data": 0x1460,
        "string_mask_data": 0x770,
    }
    payload = binary_path.read_bytes()

    summary_lines = []
    for name, (offset, section) in offsets.items():
        size = sizes.get(name)
        if size is None:
            continue
        blob = payload[offset : offset + size]
        (out_dir / f"{name}.bin").write_bytes(blob)
        txt_path = out_dir / f"{name}.txt"
        with txt_path.open("w", encoding="utf-8") as fh:
            fh.write(f"# {name} @ file offset 0x{offset:x} ({section}), {size:#x} bytes\\n")
            for line in hexdump(blob):
                fh.write(line + "\\n")
        summary_lines.append(f"{name}: offset=0x{offset:x} section={section} size={size:#x}")

    string_ids = load_encoded_strings(types_path)
    table_path = out_dir / "encoded_string_ids.txt"
    with table_path.open("w", encoding="utf-8") as fh:
        fh.write("# EncodedStringId hints (derived from metadata/xzre_types.json)\\n")
        for key in sorted(string_ids):
            name = string_ids[key]
            fh.write(f"{key:#06x}  {name}  # {friendly(name)}\\n")

    summary_path = out_dir / "string_rodata_summary.txt"
    with summary_path.open("w", encoding="utf-8") as fh:
        fh.write("Obfuscated string blobs exported from liblzma_la-crc64-fast.o\\n")
        for line in summary_lines:
            fh.write(f"{line}\\n")
        fh.write("\\nEncodings (best-effort de-obfuscation from enum names) written to encoded_string_ids.txt\\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
