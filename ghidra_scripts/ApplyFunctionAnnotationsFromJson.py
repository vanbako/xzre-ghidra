# Apply parameter names/types (and locals when possible) from a JSON description.
# Usage (headless):
#   -postScript ApplyFunctionAnnotationsFromJson.py [json=<path>] [apply_params=true|false] [apply_locals=true|false]
# Defaults: json=reports/unmapped_functions.json, apply_params=true, apply_locals=true.
# @category xzre

import json
import os

from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.symbol import SourceType

JSON_DEFAULT = os.path.join("reports", "unmapped_functions.json")


class TypeResolver(object):
    """
    Parse C type strings into DataType instances via the built-in C parser.
    """

    def __init__(self, dtm):
        self._dtm = dtm
        self._parser = CParser(dtm)
        self._counter = 0

    def parse(self, type_str):
        if not type_str:
            return None
        stripped = type_str.strip()
        if not stripped:
            return None
        name = "__xzre_tmp_type_{}".format(self._counter)
        self._counter += 1
        snippet = None
        if "[" in stripped and stripped.endswith("]"):
            idx = stripped.find("[")
            array_suffix = stripped[idx:]
            base = stripped[:idx].rstrip()
            snippet = "typedef {} {}{};\n".format(base, name, array_suffix)
        else:
            snippet = "typedef {} {};\n".format(stripped, name)
        try:
            parsed = self._parser.parse(snippet)
            if parsed is None:
                printerr("Type parse produced None for '{}'".format(type_str))
                return None
            data_type = parsed
            if hasattr(parsed, "getDataType"):
                try:
                    inner = parsed.getDataType()
                    if inner is not None:
                        data_type = inner
                except Exception:
                    pass
            return data_type
        except Exception as exc:  # pragma: no cover - defensive guard
            printerr("Type parse failed for '{}': {}".format(type_str, exc))
            return None


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

    try:
        if var.getSource() == SourceType.USER_DEFINED:
            score += 5
    except Exception:
        pass

    try:
        name = var.getName() or ""
        if name and not (
            name.startswith("local_") or name.startswith("stack") or name.startswith("param")
        ):
            score += 2
    except Exception:
        pass

    try:
        storage = var.getVariableStorage()
        if storage is not None and storage.isRegisterStorage():
            score += 1  # Slight preference for stack slots.
    except Exception:
        pass
    return score


def _choose_variable(candidates, target_dt, used):
    available = [var for var in candidates if var not in used]
    if not available:
        return None
    best = None
    best_score = None
    for var in available:
        score = _variable_score(var, target_dt)
        if best is None or score < best_score:
            best = var
            best_score = score
    if best is None:
        return None
    if best_score is None:
        return best
    if best_score > 8:
        return None
    return best


def resolve_path(candidate):
    if candidate is None:
        return None
    if os.path.isabs(candidate):
        return candidate
    return os.path.abspath(os.path.join(os.getcwd(), candidate))


def load_json(path):
    if not os.path.exists(path):
        raise RuntimeError("annotation JSON not found at {}".format(path))
    with open(path, "r") as handle:
        return json.load(handle)


def find_function(entry, fm):
    entrypoint = entry.get("entrypoint")
    if entrypoint:
        try:
            offset = int(entrypoint, 16)
            func = fm.getFunctionContaining(toAddr(offset))
            if func is not None:
                return func
        except Exception:
            pass
    name = entry.get("name")
    if not name:
        return None
    for func in fm.getFunctions(True):
        if func.getName() == name:
            return func
    return None


def apply_parameters(func, specs, resolver):
    if not specs:
        return [], []
    changes = []
    warnings = []
    params = list(func.getParameters())
    if len(params) != len(specs):
        warnings.append(
            "Parameter count mismatch for {}: current={}, spec={}".format(
                func.getName(), len(params), len(specs)
            )
        )
    count = min(len(params), len(specs))
    for idx in range(count):
        param = params[idx]
        spec = specs[idx]
        desired_name = spec.get("name")
        desired_type = spec.get("type")
        dt = resolver.parse(desired_type) if desired_type else None
        try:
            if desired_name and param.getName() != desired_name:
                param.setName(desired_name, SourceType.USER_DEFINED)
                changes.append("param{} name -> {}".format(idx, desired_name))
        except Exception as exc:
            warnings.append("Failed to rename param{} for {}: {}".format(idx, func.getName(), exc))
        if dt is not None:
            try:
                param.setDataType(dt, SourceType.USER_DEFINED)
                changes.append("param{} type -> {}".format(idx, dt.getDisplayName()))
            except Exception as exc:
                warnings.append(
                    "Failed to set type for param{} in {}: {}".format(idx, func.getName(), exc)
                )
    return changes, warnings


def apply_locals(func, specs, resolver):
    if not specs:
        return [], []
    locals_vars = list(func.getLocalVariables())
    if not locals_vars:
        return [], [
            "No local variables present in {}".format(func.getName())
        ]
    changes = []
    warnings = []
    used = set()
    for spec in specs:
        name = spec.get("name")
        type_str = spec.get("type")
        dt = resolver.parse(type_str) if type_str else None
        candidate = _choose_variable(locals_vars, dt, used)
        if candidate is None:
            warnings.append(
                "Unable to match local '{}' ({}) in {}".format(
                    name or "<unnamed>", type_str or "<type>", func.getName()
                )
            )
            continue
        used.add(candidate)
        if name:
            try:
                if candidate.getName() != name:
                    candidate.setName(name, SourceType.USER_DEFINED)
                    changes.append("local {} -> name {}".format(candidate, name))
            except Exception as exc:
                warnings.append(
                    "Failed to rename local in {} to {}: {}".format(func.getName(), name, exc)
                )
        if dt is not None:
            try:
                candidate.setDataType(dt, SourceType.USER_DEFINED)
                changes.append("local {} -> type {}".format(candidate, dt.getDisplayName()))
            except Exception as exc:
                warnings.append(
                    "Failed to set type for local {} in {}: {}".format(candidate, func.getName(), exc)
                )
    return changes, warnings


def main():
    args = getScriptArgs()
    json_path = JSON_DEFAULT
    apply_params = True
    apply_locals_flag = True
    for arg in args:
        if arg.startswith("json="):
            json_path = arg.split("=", 1)[1]
        elif arg.startswith("apply_params="):
            apply_params = arg.split("=", 1)[1].lower() == "true"
        elif arg.startswith("apply_locals="):
            apply_locals_flag = arg.split("=", 1)[1].lower() == "true"

    json_path = resolve_path(json_path)
    data = load_json(json_path)
    entries = data.get("functions", [])
    if not entries:
        printerr("No function entries found in {}".format(json_path))
        return

    fm = currentProgram.getFunctionManager()
    dtm = currentProgram.getDataTypeManager()
    resolver = TypeResolver(dtm)

    applied = 0
    skipped = 0
    warnings_total = 0

    txn = currentProgram.startTransaction("Apply annotations from JSON")
    try:
        for entry in entries:
            if entry.get("status") == "mapped_missing":
                skipped += 1
                continue
            func = find_function(entry, fm)
            if func is None:
                printerr("Function {} not found; skipping".format(entry.get("name")))
                skipped += 1
                continue
            entry_warnings = []
            if apply_params:
                changes, warnings = apply_parameters(func, entry.get("parameters", []), resolver)
                if changes:
                    for change in changes:
                        print("{}: {}".format(func.getName(), change))
                entry_warnings.extend(warnings)
            if apply_locals_flag:
                changes, warnings = apply_locals(func, entry.get("locals", []), resolver)
                if changes:
                    for change in changes:
                        print("{}: {}".format(func.getName(), change))
                entry_warnings.extend(warnings)
            if entry_warnings:
                warnings_total += len(entry_warnings)
                for msg in entry_warnings:
                    printerr(msg)
            applied += 1
    finally:
        currentProgram.endTransaction(txn, True)

    print(
        "Annotation apply complete: processed={}, skipped={}, warnings={}".format(
            applied, skipped, warnings_total
        )
    )


if __name__ == "__main__":
    main()
