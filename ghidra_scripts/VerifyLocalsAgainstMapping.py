"""
Validate that locals recorded in the xzre source mapping have been applied to the
current program. Reports any functions missing expected locals or entirely absent
from the binary.
@category xzre
"""

import json
import os


def _find_function_by_name(fm, name):
    func_iter = fm.getFunctions(True)
    for func in func_iter:
        if func.getName() == name:
            return func
    return None


def _load_mapping(default_path, args):
    mapping_path = default_path
    for arg in args:
        if arg.startswith("map="):
            mapping_path = arg.split("=", 1)[1]
    mapping_path = os.path.abspath(mapping_path)
    if not os.path.exists(mapping_path):
        raise RuntimeError("locals mapping not found at {}".format(mapping_path))
    with open(mapping_path, "r") as infile:
        return mapping_path, json.load(infile)


def _gather_local_names(func):
    names = set()
    try:
        for var in func.getLocalVariables():
            try:
                name = var.getName()
            except Exception:
                continue
            if name:
                names.add(name)
    except Exception:
        pass

    stack_frame = func.getStackFrame()
    if stack_frame is not None:
        try:
            for var in stack_frame.getLocals():
                try:
                    name = var.getName()
                except Exception:
                    continue
                if name:
                    names.add(name)
        except Exception:
            pass
    return names


def main():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    default_mapping = os.path.join(script_dir, "generated", "xzre_locals.json")
    mapping_path, mapping = _load_mapping(default_mapping, getScriptArgs())

    println("Verifying locals using mapping {}".format(mapping_path))

    fm = currentProgram.getFunctionManager()

    missing_functions = []
    missing_locals = []

    for func_name, payload in mapping.items():
        func = _find_function_by_name(fm, func_name)
        if func is None:
            missing_functions.append(func_name)
            continue

        expected = [entry.get("name") for entry in (payload.get("locals") or []) if entry.get("name")]
        if not expected:
            continue

        present_names = _gather_local_names(func)
        missing = sorted(name for name in expected if name not in present_names)
        if missing:
            missing_locals.append((func_name, missing))

    if missing_locals:
        println("Functions with missing locals:")
        for func_name, names in missing_locals:
            println("  {} -> {}".format(func_name, ", ".join(names)))
    else:
        println("All mapped locals present in the analyzed functions.")

    if missing_functions:
        println("Mapping references {} function(s) absent from the program:".format(len(missing_functions)))
        for func_name in missing_functions:
            println("  {}".format(func_name))
    else:
        println("All mapped functions found in the current program.")


if __name__ == "__main__":
    main()
