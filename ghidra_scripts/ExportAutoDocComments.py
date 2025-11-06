# Export function plate comments to JSON for downstream tooling.
#@author Codex
#@category xzre

import json
import os


def parse_args(raw_args):
    output_path = None
    for arg in raw_args:
        if arg.startswith("output="):
            output_path = arg.split("=", 1)[1]
            break
    if not output_path:
        raise RuntimeError("output=<path> argument is required")
    return os.path.expanduser(output_path)


def main():
    output_file = parse_args(getScriptArgs())
    out_dir = os.path.dirname(output_file)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir)

    comment_map = {}
    fm = currentProgram.getFunctionManager()
    it = fm.getFunctions(True)
    while it.hasNext():
        func = it.next()
        comment = func.getComment()
        if comment:
            comment_map[func.getName()] = comment

    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump(comment_map, fh, indent=2, sort_keys=True, ensure_ascii=False)

    print("Exported {} comments to {}".format(len(comment_map), output_file))


if __name__ == "__main__":
    main()
