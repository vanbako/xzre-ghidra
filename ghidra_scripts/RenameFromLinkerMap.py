# Renames functions to their xzre identifiers using the linker script map.
# Usage inside headless Ghidra:
#   -postScript RenameFromLinkerMap.py [optional path to xzre.lds.in]
# @category xzre

import os
import re

from ghidra.program.model.symbol import SourceType

MAP_DEFAULT = os.path.join("xzre", "xzre.lds.in")
MAP_PATTERN = re.compile(
    r"""/\*\s*([0-9A-Fa-f]+)\s*\*/\s*(DEFSYM2|DEFSYM)\(([^,]+),\s*([^)]+)\)"""
)


def load_map(path):
    entries = []
    with open(path, "r") as handle:
        for line in handle:
            raw = line.strip()
            if not raw or "DEFSYM" not in raw:
                continue
            if "//" in raw:
                raw = raw.split("//", 1)[0].strip()
            match = MAP_PATTERN.match(raw)
            if not match:
                continue
            offset_hex, _, name, _ = match.groups()
            entries.append((int(offset_hex, 16), name.strip()))
    return entries


def main():
    script_args = getScriptArgs()
    map_path = script_args[0] if script_args else MAP_DEFAULT
    if not os.path.isabs(map_path):
        map_path = os.path.abspath(os.path.join(os.getcwd(), map_path))
    if not os.path.exists(map_path):
        printerr("Map file not found: {}".format(map_path))
        return

    map_entries = load_map(map_path)
    if not map_entries:
        printerr("No DEFSYM entries found in {}".format(map_path))
        return

    func_manager = currentProgram.getFunctionManager()
    func_iter = func_manager.getFunctions(True)
    try:
        first_func = next(func_iter)
    except StopIteration:
        printerr("Program has no functions to rename.")
        return

    min_func_offset = first_func.getEntryPoint().getOffset()
    for func in func_iter:
        addr_offset = func.getEntryPoint().getOffset()
        if addr_offset < min_func_offset:
            min_func_offset = addr_offset

    min_map_offset = min(offset for offset, _ in map_entries)
    base = min_func_offset - min_map_offset
    print("Computed base offset: 0x{:X}".format(base))

    renamed = 0
    missing = 0
    unchanged = 0

    txn = currentProgram.startTransaction("Rename from xzre linker map")
    try:
        for offset, desired_name in map_entries:
            address = toAddr(base + offset)
            func = func_manager.getFunctionAt(address)
            if func is None:
                missing += 1
                continue
            current_name = func.getName()
            if current_name == desired_name:
                unchanged += 1
                continue
            try:
                func.setName(desired_name, SourceType.USER_DEFINED)
                renamed += 1
                print(
                    "Renamed {} -> {} at {}".format(
                        current_name, desired_name, address
                    )
                )
            except Exception as exc:
                printerr(
                    "Failed to rename {} at {}: {}".format(
                        current_name, address, exc
                    )
                )
        print(
            "Rename summary: renamed={}, unchanged={}, missing={}".format(
                renamed, unchanged, missing
            )
        )
    finally:
        success = True
        currentProgram.endTransaction(txn, success)


if __name__ == "__main__":
    main()
