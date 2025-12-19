# Apply AutoDoc comments generated from upstream sources.
#@author Codex
#@category xzre

import json
import os
import codecs

from ghidra.program.model.listing import Function, CodeUnit

try:
    string_types = (basestring,)  # type: ignore[name-defined]
except NameError:
    string_types = (str,)


DATA_AUTODOC_SYMBOLS = {
    "backdoor_hooks_data_blob",
}


AUTO_TAG = "AutoDoc:"


def extract_plate_comment(entry):
    if isinstance(entry, string_types):
        return entry
    if isinstance(entry, dict):
        text = entry.get("plate") or entry.get("comment") or entry.get("text")
        if text is not None:
            return text
    raise RuntimeError("AutoDoc entry must be a string or object with a 'plate' key")


def parse_args(raw_args):
    comments_path = None
    for arg in raw_args:
        if arg.startswith("comments="):
            comments_path = arg.split("=", 1)[1]
            break
    if not comments_path:
        raise RuntimeError("comments=<path> argument is required")
    return os.path.expanduser(comments_path)


def strip_existing_autodoc(comment_text):
    if not comment_text:
        return None
    idx = comment_text.find(AUTO_TAG)
    if idx == -1:
        return comment_text
    prefix = comment_text[:idx].rstrip()
    return prefix if prefix else None


def main():
    comments_file = parse_args(getScriptArgs())
    if not os.path.exists(comments_file):
        print("AutoDoc comments file not found: {}".format(comments_file))
        return

    with codecs.open(comments_file, "r", "utf-8") as fh:
        raw_comment_map = json.load(fh)
        comment_map = {}
        for name, entry in raw_comment_map.items():
            comment_map[name] = extract_plate_comment(entry)

    listing = currentProgram.getListing()
    symbol_table = currentProgram.getSymbolTable()

    fm = currentProgram.getFunctionManager()
    name_map = {}
    it = fm.getFunctions(True)
    while it.hasNext():
        func = it.next()
        if isinstance(func, Function):
            name_map.setdefault(func.getName(), func)

    data_symbol_map = {}
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
        if target is not None:
            data_symbol_map[name] = target

    applied = 0
    missing = []
    for name, comment in comment_map.items():
        func = name_map.get(name)
        if func is None:
            data_symbol = data_symbol_map.get(name)
            if data_symbol is None:
                if name not in DATA_AUTODOC_SYMBOLS:
                    missing.append(name)
                continue
            code_unit = listing.getCodeUnitAt(data_symbol.getAddress())
            if code_unit is None:
                missing.append(name)
                continue
            existing = code_unit.getComment(CodeUnit.PLATE_COMMENT)
            base = strip_existing_autodoc(existing)
            if base:
                new_comment = base + "\n\n" + comment
            else:
                new_comment = comment
            if existing == new_comment:
                continue
            code_unit.setComment(CodeUnit.PLATE_COMMENT, new_comment)
            applied += 1
            continue
        existing = func.getComment()
        base = strip_existing_autodoc(existing)
        if base:
            new_comment = base + "\n\n" + comment
        else:
            new_comment = comment
        if existing == new_comment:
            continue
        func.setComment(new_comment)
        applied += 1

    cleared = 0
    for name, func in name_map.items():
        if name in comment_map:
            continue
        existing = func.getComment()
        if not existing or AUTO_TAG not in existing:
            continue
        base = strip_existing_autodoc(existing)
        if base == existing:
            continue
        func.setComment(base)
        cleared += 1

    print("AutoDoc comments applied: {}".format(applied))
    if cleared:
        print("AutoDoc comments cleared: {}".format(cleared))
    if missing:
        print("AutoDoc comments missing functions: {}".format(", ".join(sorted(missing))))


if __name__ == "__main__":
    main()
