# Dumps local variable information for selected functions from the active
# program so that source-to-Ghidra mappings can be analyzed offline.
# @category xzre

import json
import os

from ghidra.app.decompiler import DecompInterface  # type: ignore
from ghidra.program.model.pcode import PcodeOp  # type: ignore
from ghidra.util.task import ConsoleTaskMonitor  # type: ignore


def _parse_args(raw_args):
    functions = []
    output_path = None
    for arg in raw_args:
        if arg.startswith("functions="):
            value = arg.split("=", 1)[1]
            functions = [item.strip() for item in value.split(",") if item.strip()]
        elif arg.startswith("output="):
            output_path = os.path.abspath(arg.split("=", 1)[1])
    if not functions:
        raise RuntimeError("functions=func1,func2 argument is required")
    if not output_path:
        raise RuntimeError("output=/path/to/file.json argument is required")
    return functions, output_path


def _find_function(function_manager, name):
    for func in function_manager.getFunctions(True):
        if func.getName() == name:
            return func
    return None


def _datatype_display(dt):
    if dt is None:
        return None
    try:
        return dt.getDisplayName()
    except Exception:
        try:
            return dt.getName()
        except Exception:
            return None


def _datatype_size(dt):
    if dt is None:
        return None
    try:
        return dt.getLength()
    except Exception:
        return None


def _storage_dict(storage):
    if storage is None:
        return {
            "repr": None,
            "is_stack": False,
            "is_register": False,
        }
    repr_value = None
    try:
        repr_value = str(storage)
    except Exception:
        pass
    is_stack = False
    is_register = False
    try:
        is_stack = storage.isStackStorage()
    except Exception:
        is_stack = False
    try:
        is_register = storage.isRegisterStorage()
    except Exception:
        is_register = False
    return {
        "repr": repr_value,
        "is_stack": is_stack,
        "is_register": is_register,
    }


def _collect_high_variable_uses(high_var):
    uses = set()
    if high_var is None:
        return []
    try:
        instances = high_var.getInstances()
    except Exception:
        instances = []
    for instance in instances:
        addr = None
        try:
            addr = instance.getPCAddress()
        except Exception:
            addr = None
        if addr is not None:
            try:
                uses.add(addr.toString())
            except Exception:
                continue
    return sorted(uses)


def _collect_high_variable_usage(high_var, function_manager):
    call_sites = set()
    is_returned = False
    if high_var is None:
        return [], is_returned
    try:
        instances = high_var.getInstances()
    except Exception:
        instances = []
    for instance in instances:
        try:
            descendants = instance.getDescendants()
        except Exception:
            descendants = []
        for op in descendants:
            try:
                opcode = op.getOpcode()
            except Exception:
                continue
            if opcode in (PcodeOp.CALL, PcodeOp.CALLIND):
                callee_name = None
                if opcode == PcodeOp.CALL:
                    try:
                        target = op.getInput(0)
                        if target is not None:
                            addr = target.getAddress()
                            callee = function_manager.getFunctionAt(addr)
                            if callee is not None:
                                callee_name = callee.getName()
                    except Exception:
                        callee_name = None
                for idx in range(1, op.getNumInputs()):
                    try:
                        inp = op.getInput(idx)
                    except Exception:
                        continue
                    if inp is None:
                        continue
                    try:
                        if inp.getHigh() == high_var:
                            call_sites.add((callee_name, idx - 1))
                    except Exception:
                        continue
            elif opcode == PcodeOp.RETURN:
                for idx in range(op.getNumInputs()):
                    try:
                        inp = op.getInput(idx)
                    except Exception:
                        continue
                    if inp is None:
                        continue
                    try:
                        if inp.getHigh() == high_var:
                            is_returned = True
                            break
                    except Exception:
                        continue
    ordered = [
        {"callee": item[0], "arg_index": item[1]}
        for item in sorted(call_sites, key=lambda v: (v[0] or "", v[1]))
    ]
    return ordered, is_returned


def _collect_locals_from_high(func, interface, monitor):
    result = []
    try:
        decomp_results = interface.decompileFunction(func, 120, monitor)
    except Exception as exc:
        printerr("Decompilation failed for {}: {}".format(func.getName(), exc))
        return None

    if decomp_results is None or not decomp_results.decompileCompleted():
        msg = "Decompilation did not complete for {}".format(func.getName())
        printerr(msg)
        return None

    high_func = decomp_results.getHighFunction()
    if high_func is None:
        printerr("HighFunction not available for {}".format(func.getName()))
        return None

    try:
        function_manager = func.getProgram().getFunctionManager()
    except Exception:
        function_manager = None

    try:
        symbol_map = high_func.getLocalSymbolMap()
        symbols = list(symbol_map.getSymbols())
    except Exception:
        symbols = []

    for symbol in symbols:
        try:
            if symbol.isParameter():
                continue
        except Exception:
            pass
        storage = None
        try:
            storage = symbol.getStorage()
        except Exception:
            storage = None
        data_type = None
        try:
            data_type = symbol.getDataType()
        except Exception:
            data_type = None
        try:
            source_type = str(symbol.getSymbolType())
        except Exception:
            source_type = None
        entry = {
            "name": symbol.getName(),
            "data_type": _datatype_display(data_type),
            "data_size": _datatype_size(data_type),
            "storage": _storage_dict(storage),
            "source_type": source_type,
            "use_addresses": _collect_high_variable_uses(symbol.getHighVariable()),
            "call_sites": [],
            "is_returned": False,
        }
        if function_manager is not None:
            try:
                call_sites, returned = _collect_high_variable_usage(symbol.getHighVariable(), function_manager)
                entry["call_sites"] = call_sites
                entry["is_returned"] = returned
            except Exception:
                pass
        result.append(entry)
    return result


def _collect_locals_from_function(func):
    result = []
    try:
        locals_iter = func.getLocalVariables()
    except Exception:
        locals_iter = []
    for var in locals_iter:
        storage = None
        try:
            storage = var.getVariableStorage()
        except Exception:
            storage = None
        entry = {
            "name": var.getName(),
            "data_type": _datatype_display(var.getDataType()),
            "data_size": _datatype_size(var.getDataType()),
            "storage": _storage_dict(storage),
            "source_type": str(var.getSource()),
            "use_addresses": [],
            "call_sites": [],
            "is_returned": False,
        }
        result.append(entry)
    return result


def main():
    program = currentProgram  # type: ignore  # noqa: F821 - provided by Ghidra
    function_manager = program.getFunctionManager()
    monitor = ConsoleTaskMonitor()
    functions, output_path = _parse_args(getScriptArgs())

    interface = DecompInterface()
    try:
        interface.openProgram(program)
    except Exception as exc:
        raise RuntimeError("Failed to open program for decompilation: {}".format(exc))

    report = {
        "program": program.getName(),
        "functions": [],
        "errors": [],
    }

    for name in functions:
        func = _find_function(function_manager, name)
        if func is None:
            message = "Function '{}' not found".format(name)
            printerr(message)
            report["errors"].append(message)
            continue

        locals_info = _collect_locals_from_high(func, interface, monitor)
        if locals_info is None:
            locals_info = _collect_locals_from_function(func)

        report["functions"].append(
            {
                "name": name,
                "entry_point": func.getEntryPoint().toString(),
                "locals": locals_info,
            }
        )

    interface.dispose()

    out_dir = os.path.dirname(output_path)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir)

    with open(output_path, "w") as outfile:
        json.dump(report, outfile, indent=2)
        outfile.write("\n")

    print("Dumped local variable data for {} functions to {}".format(len(report["functions"]), output_path))


if __name__ == "__main__":
    main()
