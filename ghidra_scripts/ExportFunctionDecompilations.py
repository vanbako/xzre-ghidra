# Export decompiled output for every function into individual files.
# Usage (headless):
#   -postScript ExportFunctionDecompilations.py [out=<dir>]
# Defaults to writing under ./xzregh relative to the current working directory.
# @category xzre

import os
import re
import shutil

from ghidra.app.decompiler import DecompInterface

OUTPUT_DEFAULT = "xzregh"


def resolve_path(candidate):
    if candidate is None:
        return None
    if os.path.isabs(candidate):
        return candidate
    return os.path.abspath(os.path.join(os.getcwd(), candidate))


def ensure_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)


def sanitize_name(name):
    if not name:
        return "function"
    sanitized = re.sub(r"[^0-9A-Za-z_]+", "_", name)
    sanitized = sanitized.strip("_")
    if not sanitized:
        sanitized = "function"
    return sanitized


def make_unique_path(base_dir, entry_hex, func_name):
    stem = "{}_{}".format(entry_hex, sanitize_name(func_name))
    candidate = os.path.join(base_dir, stem + ".c")
    if not os.path.exists(candidate):
        return candidate
    index = 1
    while True:
        candidate = os.path.join(base_dir, "{}_{}_{:02d}.c".format(entry_hex, sanitize_name(func_name), index))
        if not os.path.exists(candidate):
            return candidate
        index += 1


def decompile_function(ifc, func, monitor):
    try:
        result = ifc.decompileFunction(func, 60, monitor)
        if result is None:
            return False, "/* Decompiler returned None */"
        if not result.decompileCompleted():
            message = result.getErrorMessage() or "unknown error"
            return False, "/* Decompilation failed: {} */".format(message)
        decomp = result.getDecompiledFunction()
        if decomp is None:
            return False, "/* Decompiler returned no function body */"
        text = decomp.getC()
        if text is None:
            return False, "/* Decompiler produced no C output */"
        return True, text
    except Exception as exc:  # pragma: no cover - defensive
        return False, "/* Exception during decompilation: {} */".format(exc)


def main():
    args = getScriptArgs()
    out_dir = OUTPUT_DEFAULT
    types_path = None
    for arg in args:
        if arg.startswith("out="):
            out_dir = arg.split("=", 1)[1]
        elif arg.startswith("types="):
            types_path = arg.split("=", 1)[1]

    out_dir = resolve_path(out_dir)
    ensure_directory(out_dir)
    if types_path:
        types_path = resolve_path(types_path)
        if types_path and os.path.exists(types_path):
            dest_name = os.path.basename(types_path) or "xzre_types.h"
            shutil.copyfile(types_path, os.path.join(out_dir, dest_name))
            print("Copied {} to {}".format(types_path, os.path.join(out_dir, dest_name)))
        else:
            printerr("Type header not found: {}".format(types_path))

    fm = currentProgram.getFunctionManager()
    functions = list(fm.getFunctions(True))
    if not functions:
        printerr("Program has no functions to export.")
        return
    functions.sort(key=lambda func: func.getEntryPoint().getOffset())

    monitor.initialize(len(functions))

    ifc = DecompInterface()
    try:
        if not ifc.openProgram(currentProgram):
            raise RuntimeError("Decompiler failed to open program.")

        for idx, func in enumerate(functions):
            monitor.checkCanceled()
            monitor.setProgress(idx)
            entry = func.getEntryPoint().getOffset()
            entry_hex = "0x{:X}".format(entry)
            success, text = decompile_function(ifc, func, monitor)
            path = make_unique_path(out_dir, entry_hex[2:], func.getName())
            with open(path, "w") as handle:
                handle.write("// {}\n".format(path))
                handle.write("// Function: {} @ {}\n".format(func.getName(), entry_hex))
                handle.write("// Calling convention: {}\n".format(func.getCallingConventionName()))
                handle.write("// Prototype: {}\n\n".format(func.getSignature().getPrototypeString(True)))
                handle.write(text)
                if not text.endswith("\n"):
                    handle.write("\n")
            if success:
                print("Exported {} to {}".format(func.getName(), path))
            else:
                printerr("Warning: {} decompilation incomplete; see {}".format(func.getName(), path))
    finally:
        ifc.dispose()


if __name__ == "__main__":
    main()
