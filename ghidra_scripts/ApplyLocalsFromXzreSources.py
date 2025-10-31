# Applies local variable names and types extracted from the decompiled xzre
# sources onto the active program.
# @category xzre

import json
import os

from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.symbol import SourceType

try:
    from java.lang import Throwable  # type: ignore
except ImportError:  # pragma: no cover - non-Jython environments
    class Throwable(Exception):
        pass


def _find_function_by_name(fm, target_name):
    funcs = fm.getFunctions(True)
    for func in funcs:
        if func.getName() == target_name:
            return func
    return None


class TypeResolver(object):
    """
    Lightweight helper that feeds individual type strings through Ghidra's C
    parser and returns resolved DataType instances while avoiding persistent
    typedef clutter in the data type manager.
    """

    def __init__(self, dtm, monitor):
        self._dtm = dtm
        self._parser = CParser(dtm)
        self._monitor = monitor
        self._counter = 0

    def parse(self, type_str):
        name = "__xzre_tmp_type_{}".format(self._counter)
        self._counter += 1
        typedef = None
        snippet = None
        stripped = type_str.strip()
        array_suffix = None
        if "[" in stripped and stripped.endswith("]"):
            idx = stripped.find("[")
            array_suffix = stripped[idx:]
            base = stripped[:idx].rstrip()
            snippet = "typedef {} {}{};\n".format(base, name, array_suffix)
        else:
            snippet = "typedef {} {};\n".format(stripped, name)
        try:
            self._parser.parse(snippet)
            typedef = self._dtm.getDataType("/" + name)
            if typedef is None:
                return None
            data_type = typedef
            if hasattr(typedef, "getDataType"):
                try:
                    data_type = typedef.getDataType()
                except Exception:
                    # Fallback to the typedef itself; better than nothing.
                    data_type = typedef
            return data_type
        except (Exception, Throwable) as exc:
            printerr("Type parse failed for '{}': {}".format(type_str, exc))
            return None
        finally:
            if typedef is not None:
                try:
                    self._dtm.remove(typedef, self._monitor)
                except Exception:
                    # If removal fails, leave the typedef behind rather than
                    # interrupting the pipeline.
                    pass


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


def _variable_score(var, target_dt):
    score = 0
    target_len = -1
    if target_dt is not None and hasattr(target_dt, "getLength"):
        try:
            target_len = target_dt.getLength()
        except Exception:
            target_len = -1

    try:
        var_len = var.getLength()
    except Exception:
        var_len = -1

    if target_len >= 0 and var_len >= 0:
        score += abs(target_len - var_len)

    if var.getSource() == SourceType.USER_DEFINED:
        score += 5

    name = var.getName() or ""
    if name and not (name.startswith("local_") or name.startswith("stack") or name.startswith("param")):
        score += 2

    storage = var.getVariableStorage()
    if storage is not None and storage.isRegisterStorage():
        score += 1  # Slightly prefer stack storage by keeping register vars later.
    return score


def _choose_variable(candidates, target_dt):
    if not candidates:
        return None
    best = None
    best_score = None
    for var in candidates:
        score = _variable_score(var, target_dt)
        if best is None or score < best_score:
            best = var
            best_score = score
    return best


def _apply_locals_to_function(func, locals_data, type_resolver):
    existing_locals = list(func.getLocalVariables())
    if not existing_locals:
        println("Skipping {}: function has no locals in current program".format(func.getName()))
        return 0, len(locals_data)

    candidates = list(existing_locals)
    updated = 0
    skipped = 0

    for entry in locals_data:
        monitor.checkCanceled()
        name = entry.get("name")
        type_str = entry.get("type")
        if not name:
            skipped += 1
            continue

        dt = None
        if type_str:
            dt = type_resolver.parse(type_str)

        target_var = _choose_variable(candidates, dt)
        if target_var is None:
            printerr("No available local slot for {} in {}".format(name, func.getName()))
            skipped += 1
            continue

        if dt is not None:
            try:
                target_var.setDataType(dt, SourceType.USER_DEFINED)
            except Exception as exc:
                printerr(
                    "Failed to set type '{}' on {}::{}: {}".format(
                        type_str, func.getName(), target_var.getName(), exc
                    )
                )

        try:
            target_var.setName(name, SourceType.USER_DEFINED)
        except Exception as exc:
            printerr(
                "Failed to rename {} to '{}' in {}: {}".format(
                    target_var.getName(), name, func.getName(), exc
                )
            )
            skipped += 1
            candidates.remove(target_var)
            continue

        candidates.remove(target_var)
        updated += 1

    return updated, skipped


def main():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    default_mapping = os.path.join(script_dir, "generated", "xzre_locals.json")
    mapping_path, mapping = _load_mapping(default_mapping, getScriptArgs())

    println("Applying locals from {}".format(mapping_path))
    fm = currentProgram.getFunctionManager()
    dtm = currentProgram.getDataTypeManager()
    resolver = TypeResolver(dtm, monitor)

    txn = currentProgram.startTransaction("Apply locals from xzre sources")
    success = False
    applied_total = 0
    skipped_total = 0
    missing_total = 0
    try:
        for func_name, payload in mapping.items():
            monitor.checkCanceled()
            func = _find_function_by_name(fm, func_name)
            if func is None:
                printerr("Function {} not found in current program".format(func_name))
                missing_total += 1
                continue
            locals_data = payload.get("locals") or []
            updated, skipped = _apply_locals_to_function(func, locals_data, resolver)
            applied_total += updated
            skipped_total += skipped
        success = True
    finally:
        currentProgram.endTransaction(txn, success)

    println(
        "Locals applied: {} updated, {} skipped, {} functions missing".format(
            applied_total, skipped_total, missing_total
        )
    )


if __name__ == "__main__":
    main()
