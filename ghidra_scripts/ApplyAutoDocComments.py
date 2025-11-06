# Apply AutoDoc comments generated from upstream sources.
#@author Codex
#@category xzre

import json
import os

from ghidra.program.model.listing import Function


AUTO_TAG = "AutoDoc: Generated from upstream sources."


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

    with open(comments_file, "r", encoding="utf-8") as fh:
        comment_map = json.load(fh)

    fm = currentProgram.getFunctionManager()
    name_map = {}
    it = fm.getFunctions(True)
    while it.hasNext():
        func = it.next()
        if isinstance(func, Function):
            name_map.setdefault(func.getName(), func)

    applied = 0
    missing = []
    for name, comment in comment_map.items():
        func = name_map.get(name)
        if func is None:
            missing.append(name)
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

    print("AutoDoc comments applied: {}".format(applied))
    if missing:
        print("AutoDoc comments missing functions: {}".format(", ".join(sorted(missing))))


if __name__ == "__main__":
    main()
