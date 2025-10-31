#!/usr/bin/env python3
"""Compare header prototypes against Ghidra dumps while tolerating known quirks."""

import argparse
import re
from collections import OrderedDict


def normalize_spaces(text):
    return re.sub(r"\s+", " ", text.strip())


def canonicalize_type(type_str):
    t = normalize_spaces(type_str)
    t = t.replace("( ", "(").replace(" )", ")")
    t = t.replace("const ", "")
    t = re.sub(r"\bstruct\s+", "", t)
    t = re.sub(r"\benum\s+", "", t)
    t = t.replace("unsigned char", "uchar")
    t = t.replace("unsigned int", "uint")
    t = re.sub(r"\bunsigned\b", "uint", t)
    t = re.sub(r"BOOL\s*\(\*\s*appender\s*\)\s*\([^)]*\)", "appender*", t)
    t = t.replace(" *", "*").replace("* ", "*")
    return t


def canonicalize_name(name):
    return name or ""


def split_params(param_blob):
    blob = param_blob.strip()
    if not blob or blob == "void":
        return []
    items = []
    depth = 0
    current = []
    for ch in blob:
        if ch == "," and depth == 0:
            items.append("".join(current).strip())
            current = []
        else:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            current.append(ch)
    if current:
        items.append("".join(current).strip())
    return items


def parse_prototype(raw):
    raw = normalize_spaces(raw)
    if "(" not in raw or ")" not in raw:
        raise ValueError(f"Could not parse prototype: {raw}")
    head, tail = raw.split("(", 1)
    name_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", head)
    if not name_match:
        raise ValueError(f"Could not extract function name from: {raw}")
    func_name = name_match.group(1)
    ret = head[: name_match.start()].strip()
    params_blob = tail.rsplit(")", 1)[0]
    params = []
    for param in split_params(params_blob):
        if param == "void":
            continue
        name_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", param)
        if name_match:
            param_name = param[name_match.start():]
            type_part = param[: name_match.start()].strip()
            if not type_part:
                type_part = param_name
                param_name = ""
        else:
            type_part = param
            param_name = ""
        params.append((normalize_spaces(type_part), param_name.strip()))
    return func_name, normalize_spaces(ret), params


def parse_header(path):
    prototypes = OrderedDict()
    with open(path, "r") as f:
        buffer = ""
        capturing = False
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            if not capturing:
                if stripped.startswith("extern "):
                    buffer = stripped[len("extern ") :]
                    capturing = True
            else:
                buffer += " " + stripped
            if stripped.endswith(";") and capturing:
                statement = buffer[:-1].strip()
                if "(" in statement and ")" in statement:
                    name, ret, params = parse_prototype(statement)
                    prototypes[name] = (ret, params)
                buffer = ""
                capturing = False
    return prototypes


def parse_ghidra(path):
    prototypes = OrderedDict()
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(" ", 2)
            if len(parts) < 3:
                continue
            _, name, proto = parts
            parsed_name, ret, params = parse_prototype(proto)
            if parsed_name != name:
                raise ValueError(
                    f"Name mismatch in Ghidra prototype: {name} vs {parsed_name}"
                )
            prototypes[name] = (ret, params)
    return prototypes


def compare(header, ghidra):
    errors = []
    missing = []
    for name, (g_ret, g_params) in ghidra.items():
        if name not in header:
            missing.append(name)
            continue
        h_ret, h_params = header[name]
        if canonicalize_type(g_ret) != canonicalize_type(h_ret):
            errors.append((name, "return", h_ret, g_ret))
            continue
        if len(g_params) != len(h_params):
            errors.append(
                (name, "param_count", len(h_params), len(g_params))
            )
            continue
        for idx, ((h_type, h_name), (g_type, g_name)) in enumerate(
            zip(h_params, g_params)
        ):
            if canonicalize_type(h_type) != canonicalize_type(g_type):
                errors.append(
                    (
                        name,
                        f"param_type_{idx}",
                        h_type,
                        g_type,
                    )
                )
                break
    return missing, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--header",
        default="ghidra_scripts/xzre_types_import_preprocessed.h",
        help="Header file with extern prototypes.",
    )
    parser.add_argument(
        "--signatures",
        default="/tmp/ghidra_signatures.txt",
        help="Output from ListFunctionSignatures.py.",
    )
    args = parser.parse_args()

    header_protos = parse_header(args.header)
    ghidra_protos = parse_ghidra(args.signatures)

    missing, errors = compare(header_protos, ghidra_protos)

    if not missing and not errors:
        print("Signatures match within tolerated differences.")
        return

    if missing:
        print("Missing in header ({}): {}".format(len(missing), ", ".join(sorted(missing))))
    if errors:
        print("Mismatches ({}):".format(len(errors)))
        for name, kind, expected, actual in errors:
            print("  {} [{}] expected='{}' actual='{}'".format(name, kind, expected, actual))


if __name__ == "__main__":
    main()
