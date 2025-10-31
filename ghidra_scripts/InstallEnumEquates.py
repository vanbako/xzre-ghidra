# Installs equates for key xzre enums by parsing the preprocessed header.
# @category xzre

import re
import os


TARGET_ENUMS = (
    "EncodedStringId",
    "CommandFlags1",
    "CommandFlags2",
    "CommandFlags3",
)

COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.S)
COMMENT_LINE = re.compile(r"//.*?$", re.M)
IDENT_PATTERN = r"[A-Za-z_][A-Za-z0-9_]*"
ENUM_PATTERN = re.compile(
    r"(typedef\s+)?enum\s*(?:(" + IDENT_PATTERN + r")\s*)?\{", re.S
)


def strip_comments(text):
    text = COMMENT_BLOCK.sub("", text)
    text = COMMENT_LINE.sub("", text)
    return text


def eval_expr(expr):
    safe_globals = {"__builtins__": None}
    expr = expr.strip()
    try:
        value = eval(expr, safe_globals, {})
    except Exception as exc:
        raise ValueError("Failed to evaluate expression '{}': {}".format(expr, exc))
    if not isinstance(value, (int, long)):
        raise ValueError(
            "Expression '{}' did not evaluate to an integer (got {})".format(
                expr, type(value)
            )
        )
    return int(value)


def extract_enum_bodies(text):
    enums = {}
    position = 0
    length = len(text)
    while True:
        match = ENUM_PATTERN.search(text, position)
        if not match:
            break
        typedef = match.group(1) is not None
        name_before = match.group(2)
        body_start = match.end()

        brace_level = 1
        i = body_start
        while i < length and brace_level > 0:
            ch = text[i]
            if ch == "{":
                brace_level += 1
            elif ch == "}":
                brace_level -= 1
            i += 1
        body_end = i - 1
        body = text[body_start:body_end]

        tail = text[i:]
        name = None
        if typedef:
            name_match = re.match(r"\s*(" + IDENT_PATTERN + r")", tail)
            if name_match:
                name = name_match.group(1)
                tail_offset = name_match.end()
            else:
                tail_offset = 0
        else:
            name = name_before
            tail_offset = 0

        if name:
            enums[name] = body

        semi_index = tail.find(";")
        if semi_index >= 0:
            position = i + semi_index + 1
        else:
            position = i + tail_offset
    return enums


def parse_enum_body(body):
    entries = []
    for raw_entry in body.split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        if "=" in entry:
            name, expr = entry.split("=", 1)
            entries.append((name.strip(), expr.strip()))
        else:
            entries.append((entry, None))
    values = {}
    current_value = -1
    for name, expr in entries:
        if expr is not None:
            current_value = eval_expr(expr)
        else:
            current_value += 1
        values[name] = current_value
    return values


def load_enum_values(header_path):
    with open(header_path, "r") as handle:
        text = handle.read()
    clean = strip_comments(text)
    enums = {}
    bodies = extract_enum_bodies(clean)
    for enum_name in TARGET_ENUMS:
        body = bodies.get(enum_name)
        if not body:
            printerr(
                "Could not locate enum definition for {} in {}".format(
                    enum_name, header_path
                )
            )
            continue
        enums[enum_name] = parse_enum_body(body)
    return enums


def install_equates(enum_values, equate_table):
    created = 0
    existing = 0
    for enumerator, value in enum_values.items():
        try:
            equate_table.createEquate(enumerator, value)
            created += 1
        except Exception as exc:
            message = str(exc)
            if "exists" in message or "Duplicate" in message:
                existing += 1
                continue
            printerr(
                "Failed to create equate {}={:#x}: {}".format(enumerator, value, exc)
            )
    return created, existing


def resolve_header_path(args):
    if args:
        candidate = args[0]
        if not os.path.isabs(candidate):
            candidate = os.path.abspath(candidate)
        return candidate
    # default relative to current working directory
    return os.path.abspath(
        os.path.join(os.getcwd(), "ghidra_scripts", "xzre_types_import_preprocessed.h")
    )


def main():
    script_args = getScriptArgs()
    header_path = resolve_header_path(script_args)
    if not os.path.exists(header_path):
        printerr("Header file not found: {}".format(header_path))
        return

    enum_map = load_enum_values(header_path)
    if not enum_map:
        printerr("No enums parsed from {}; nothing to install.".format(header_path))
        return

    equate_table = currentProgram.getEquateTable()
    total_created = 0
    total_existing = 0
    for enum_name in TARGET_ENUMS:
        values = enum_map.get(enum_name)
        if not values:
            continue
        created, existing = install_equates(values, equate_table)
        total_created += created
        total_existing += existing
        print(
            "Equates for {}: created={}, already-present={}".format(
                enum_name, created, existing
            )
        )

    print(
        "Equate installation complete: created={}, already-present={}".format(
            total_created, total_existing
        )
    )


if __name__ == "__main__":
    main()
