# Produce a JSON report describing functions that are not mapped to xzre symbols.
# Usage (headless):
#   -postScript ExportUnmappedFunctionSummaries.py [map=<path>] [locals=<path>] [out=<path>]
# Any relative paths are resolved against the current working directory when the script runs.
# @category xzre

import json
import os
import re

from ghidra.app.decompiler import DecompInterface
MAP_DEFAULT = os.path.join("xzre", "xzre.lds.in")
LOCALS_DEFAULT = os.path.join("ghidra_scripts", "generated", "xzre_locals.json")
OUTPUT_DEFAULT = os.path.join("reports", "unmapped_functions.json")

DEFSYM_PATTERN = re.compile(r"\bDEFSYM2?\(\s*([A-Za-z0-9_]+)")


def resolve_path(candidate):
    if candidate is None:
        return None
    if os.path.isabs(candidate):
        return candidate
    return os.path.abspath(os.path.join(os.getcwd(), candidate))


def load_known_names(map_path, locals_path):
    names = set()
    map_names = set()
    locals_meta = {}
    if map_path and os.path.exists(map_path):
        with open(map_path, "r") as handle:
            for line in handle:
                if "DEFSYM" not in line:
                    continue
                match = DEFSYM_PATTERN.search(line)
                if match:
                    symbol = match.group(1).strip()
                    names.add(symbol)
                    map_names.add(symbol)
    if locals_path and os.path.exists(locals_path):
        try:
            with open(locals_path, "r") as handle:
                data = json.load(handle)
                if isinstance(data, dict):
                    for func_name, meta in data.items():
                        names.add(func_name)
                        locals_meta[func_name] = meta
        except Exception as exc:  # pragma: no cover - defensive
            printerr("Failed to load locals mapping {}: {}".format(locals_path, exc))
    return names, map_names, locals_meta


def describe_storage(var):
    storage = var.getVariableStorage()
    if storage is None:
        return "<none>"
    try:
        if storage.hasStackStorage():
            return "stack@{}".format(storage.getStackOffset())
        if storage.isRegisterStorage():
            return "reg:{}".format(storage.getRegister())
        if storage.isMemoryStorage():
            return "mem:{}".format(storage.getMinAddress())
    except Exception:
        pass
    return str(storage)


def display_type(data_type):
    try:
        return data_type.getDisplayName()
    except Exception:
        return str(data_type)


def collect_decompilation(ifc, func, monitor):
    try:
        result = ifc.decompileFunction(func, 60, monitor)
        if result is None or not result.decompileCompleted():
            return None
        decomp = result.getDecompiledFunction()
        if decomp is None:
            return None
        text = decomp.getC()
        if text is None:
            return None
        return text
    except Exception as exc:  # pragma: no cover - defensive
        printerr("Failed to decompile {}: {}".format(func.getName(), exc))
        return None


def gather_function_info(func, ifc, monitor):
    monitor.checkCanceled()
    thunk_target_name = None
    if func.isThunk():
        try:
            thunk_target = func.getThunkedFunction(True)
            if thunk_target is not None:
                thunk_target_name = thunk_target.getName()
        except Exception:
            thunk_target_name = None

    info = {
        "name": func.getName(),
        "entrypoint": "0x{:X}".format(func.getEntryPoint().getOffset()),
        "address": str(func.getEntryPoint()),
        "call_convention": func.getCallingConventionName(),
        "has_custom_storage": func.hasCustomVariableStorage(),
        "is_thunk": func.isThunk(),
        "prototype": func.getSignature().getPrototypeString(True),
        "return_type": display_type(func.getReturnType()),
        "parameters": [],
        "tags": [],
    }
    if thunk_target_name:
        info["thunk_target"] = thunk_target_name

    params = func.getParameters()
    for param in params:
        info["parameters"].append(
            {
                "name": param.getName(),
                "type": display_type(param.getDataType()),
                "source": str(param.getSource()),
                "storage": describe_storage(param),
                "length": param.getLength(),
                "has_assigned_storage": param.hasAssignedStorage(),
            }
        )

    if func.isExternal():
        info["tags"].append("external")
    if func.getSignature().hasVarArgs():
        info["tags"].append("varargs")

    called = []
    try:
        for target in func.getCalledFunctions(monitor):
            called.append(target.getName())
    except Exception:
        pass
    if called:
        info["callees"] = sorted(set(called))

    if ifc is not None:
        decomp = collect_decompilation(ifc, func, monitor)
        if decomp:
            info["decompilation"] = decomp

    comment = func.getComment()
    if comment:
        info["comment"] = comment
    eol_comment = func.getRepeatableComment()
    if eol_comment:
        info["repeatable_comment"] = eol_comment

    description = infer_description(info)
    if description:
        info["description"] = description

    return info


def infer_description(info):
    if info.get("thunk_target"):
        return "Thunk wrapper around {}".format(info["thunk_target"])
    if info.get("is_thunk"):
        return "Thunk with unresolved target"
    decomp = info.get("decompilation") or ""
    if "halt_baddata" in decomp:
        return "External import stub that aborts via halt_baddata"
    callees = info.get("callees")
    if callees:
        preview = ", ".join(callees[:5])
        if len(callees) > 5:
            preview += ", ..."
        return "Calls: {}".format(preview)
    return None


def ensure_parent_dir(path):
    directory = os.path.dirname(path)
    if not directory:
        return
    if not os.path.exists(directory):
        os.makedirs(directory)


def main():
    args = getScriptArgs()
    map_path = MAP_DEFAULT
    locals_path = LOCALS_DEFAULT
    out_path = OUTPUT_DEFAULT

    for arg in args:
        if arg.startswith("map="):
            map_path = arg.split("=", 1)[1]
        elif arg.startswith("locals="):
            locals_path = arg.split("=", 1)[1]
        elif arg.startswith("out="):
            out_path = arg.split("=", 1)[1]

    map_path = resolve_path(map_path)
    locals_path = resolve_path(locals_path)
    out_path = resolve_path(out_path)

    known_names, _map_names, locals_meta = load_known_names(map_path, locals_path)
    if not known_names:
        printerr("Warning: no known xzre names loaded; report may include all functions.")

    fm = currentProgram.getFunctionManager()
    functions = list(fm.getFunctions(True))
    monitor.initialize(len(functions))

    ifc = DecompInterface()
    decompiler = None
    try:
        ifc.toggleCCode(True)
        if ifc.openProgram(currentProgram):
            decompiler = ifc
        else:
            printerr("Decompiler failed to open program; skipping decompilation output.")

        unmapped_entries = []
        for idx, func in enumerate(functions):
            monitor.checkCanceled()
            monitor.setProgress(idx)
            name = func.getName()
            if name in known_names:
                continue
            # Skip compiler-generated thunk wrappers that just forward to mapped functions
            if func.isThunk():
                thunked = func.getThunkedFunction(True)
                if thunked and thunked.getName() in known_names:
                    continue
            info = gather_function_info(func, decompiler, monitor)
            unmapped_entries.append(info)

        program_function_names = {func.getName() for func in functions}
        missing_mapped_entries = []
        for func_name, meta in sorted(locals_meta.items()):
            if func_name in program_function_names:
                continue
            entry = {
                "name": func_name,
                "status": "mapped_missing",
                "description": "Function mapped from xzre sources but not present in current program",
            }
            source = meta.get("source")
            if source:
                entry["source_file"] = source
            locals_list = meta.get("locals")
            if locals_list:
                entry["locals"] = locals_list
            missing_mapped_entries.append(entry)

        reported_entries = sorted(unmapped_entries, key=lambda item: item.get("entrypoint", "")) + missing_mapped_entries

        ensure_parent_dir(out_path)
        with open(out_path, "w") as handle:
            json.dump(
                {
                    "program": currentProgram.getName(),
                    "total_functions": len(functions),
                    "known_function_count": len(known_names),
                    "unmapped_count": len(unmapped_entries),
                    "missing_mapped_count": len(missing_mapped_entries),
                    "functions": reported_entries,
                },
                handle,
                indent=2,
                sort_keys=False,
            )

        print(
            "Wrote {} entries ({} unmapped, {} mapped-missing) to {}".format(
                len(reported_entries),
                len(unmapped_entries),
                len(missing_mapped_entries),
                out_path,
            )
        )
    finally:
        if ifc is not None:
            ifc.dispose()


if __name__ == "__main__":
    main()
