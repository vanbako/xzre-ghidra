# Renames functions to their xzre identifiers using a linker-map metadata file.
# Usage inside headless Ghidra:
#   -postScript RenameFromLinkerMap.py [optional path to metadata/linker_map.json]
# @category xzre

import json
import os
import re

from ghidra.program.model.symbol import SourceType

MAP_DEFAULT = os.path.join("metadata", "linker_map.json")
MAP_PATTERN = re.compile(
    r"""/\*\s*([0-9A-Fa-f]+)\s*\*/\s*(DEFSYM2|DEFSYM)\(([^,]+),\s*([^)]+)\)"""
)


def _load_from_json(path):
    with open(path, "r") as handle:
        data = json.load(handle)
    entries = []
    for entry in data:
        offset = int(entry["offset"])
        name = entry["name"]
        section = entry.get("section", "")
        entries.append((offset, name, section))
    return entries


def _load_from_lds(path):
    entries = []
    current_section = None
    with open(path, "r") as handle:
        for line in handle:
            raw = line.strip()
            if not raw or "DEFSYM" not in raw:
                continue
            if "//" in raw:
                raw = raw.split("//", 1)[0].strip()
            if raw.startswith("DEFSYM_START("):
                current_section = raw[len("DEFSYM_START(") : -1].strip()
                continue
            if raw.startswith("DEFSYM_END"):
                current_section = None
                continue
            match = MAP_PATTERN.match(raw)
            if not match:
                continue
            offset_hex, entry_type, name, trailing = match.groups()
            if entry_type == "DEFSYM":
                section = trailing.strip()
            else:
                section = current_section
            entries.append((int(offset_hex, 16), name.strip(), section))
    return entries


def load_map(path):
    if path.lower().endswith(".json"):
        return _load_from_json(path)
    return _load_from_lds(path)


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

    min_map_offset = min(offset for offset, _, _ in map_entries)
    base = min_func_offset - min_map_offset
    print("Computed base offset: 0x{:X}".format(base))

    renamed = 0
    missing = 0
    unchanged = 0
    data_created = 0
    data_renamed = 0
    data_unchanged = 0
    data_failures = 0

    symbol_table = currentProgram.getSymbolTable()

    txn = currentProgram.startTransaction("Rename from xzre linker map")
    try:
        for offset, desired_name, section in map_entries:
            address = toAddr(base + offset)
            if section and ".text" not in section:
                symbol = symbol_table.getPrimarySymbol(address)
                if symbol is None:
                    try:
                        symbol_table.createLabel(
                            address, desired_name, SourceType.USER_DEFINED
                        )
                        data_created += 1
                        print(
                            "Created data label {} at {}".format(
                                desired_name, address
                            )
                        )
                    except Exception as exc:
                        data_failures += 1
                        printerr(
                            "Failed to create data label {} at {}: {}".format(
                                desired_name, address, exc
                            )
                        )
                else:
                    current_name = symbol.getName()
                    if current_name == desired_name:
                        data_unchanged += 1
                    else:
                        try:
                            symbol.setName(desired_name, SourceType.USER_DEFINED)
                            data_renamed += 1
                            print(
                                "Renamed data {} -> {} at {}".format(
                                    current_name, desired_name, address
                                )
                            )
                        except Exception as exc:
                            data_failures += 1
                            printerr(
                                "Failed to rename data {} at {}: {}".format(
                                    current_name, address, exc
                                )
                            )
                continue
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
            "Rename summary: funcs renamed={}, funcs unchanged={}, funcs missing={}; "
            "data created={}, data renamed={}, data unchanged={}, data failures={}".format(
                renamed,
                unchanged,
                missing,
                data_created,
                data_renamed,
                data_unchanged,
                data_failures,
            )
        )
    finally:
        success = True
        currentProgram.endTransaction(txn, success)


if __name__ == "__main__":
    main()
