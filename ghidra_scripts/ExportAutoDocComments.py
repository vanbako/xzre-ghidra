# Export function plate comments to JSON for downstream tooling.
#@author Codex
#@category xzre

import json
import os
import codecs
import copy

try:
    string_types = (basestring,)  # type: ignore[name-defined]
except NameError:
    string_types = (str,)

from ghidra.program.model.listing import CodeUnit


DATA_AUTODOC_SYMBOLS = {
    "backdoor_hooks_data_blob",
}


def extract_plate_comment(entry):
    if isinstance(entry, string_types):
        return entry
    if isinstance(entry, dict):
        text = entry.get("plate") or entry.get("comment") or entry.get("text")
        if text is not None:
            return text
    return None

def parse_args(raw_args):
    output_path = None
    metadata_path = None
    for arg in raw_args:
        if arg.startswith("output="):
            output_path = arg.split("=", 1)[1]
        elif arg.startswith("metadata="):
            metadata_path = arg.split("=", 1)[1]
    if not output_path:
        raise RuntimeError("output=<path> argument is required")
    return os.path.expanduser(output_path), (os.path.expanduser(metadata_path) if metadata_path else None)


def main():
    output_file, metadata_file = parse_args(getScriptArgs())
    out_dir = os.path.dirname(output_file)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir)

    comment_map = {}
    listing = currentProgram.getListing()
    symbol_table = currentProgram.getSymbolTable()

    fm = currentProgram.getFunctionManager()
    it = fm.getFunctions(True)
    while it.hasNext():
        func = it.next()
        comment = func.getComment()
        if comment:
            comment_map[func.getName()] = comment

    for name in DATA_AUTODOC_SYMBOLS:
        symbols = symbol_table.getSymbols(name)
        if symbols is None:
            continue
        target = None
        while symbols.hasNext():
            sym = symbols.next()
            if target is None:
                target = sym
            if sym.isGlobal():
                target = sym
                break
        if target is None:
            continue
        code_unit = listing.getCodeUnitAt(target.getAddress())
        if code_unit is None:
            continue
        comment = code_unit.getComment(CodeUnit.PLATE_COMMENT)
        if comment:
            comment_map[name] = comment

    metadata = None
    metadata_plate_map = {}
    if metadata_file and os.path.exists(metadata_file):
        with codecs.open(metadata_file, "r", "utf-8") as fh:
            metadata = json.load(fh)
        for key, value in metadata.items():
            plate = extract_plate_comment(value)
            if plate is not None:
                metadata_plate_map[key] = plate
        for name in DATA_AUTODOC_SYMBOLS:
            if name in comment_map:
                continue
            meta_comment = metadata_plate_map.get(name)
            if meta_comment:
                comment_map[name] = meta_comment

    if metadata:
        ordered_map = {}
        for key, meta_value in metadata.items():
            if isinstance(meta_value, dict):
                entry = copy.deepcopy(meta_value)
                if key in comment_map:
                    entry["plate"] = comment_map[key]
                elif key in metadata_plate_map:
                    entry["plate"] = metadata_plate_map[key]
                ordered_map[key] = entry
            else:
                if key in comment_map:
                    ordered_map[key] = comment_map[key]
                else:
                    ordered_map[key] = meta_value
        for key, value in comment_map.items():
            ordered_map.setdefault(key, value)
        if ordered_map == metadata:
            with codecs.open(metadata_file, "r", "utf-8") as fh:
                contents = fh.read()
            with codecs.open(output_file, "w", "utf-8") as fh:
                fh.write(contents)
            return
        ordered_map_serialized = ordered_map
    else:
        ordered_map_serialized = comment_map

    serialized = json.dumps(ordered_map_serialized, indent=2, ensure_ascii=False)
    serialized += "\n"
    with codecs.open(output_file, "w", "utf-8") as fh:
        fh.write(serialized)

    print("Exported {} comments to {}".format(len(comment_map), output_file))


if __name__ == "__main__":
    main()
