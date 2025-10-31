"""
Utility script to dump stack locals for a named function.
@category xzre
"""

from ghidra.program.model.listing import Function


def _find_function(fm, name):
    func_iter = fm.getFunctions(True)
    for func in func_iter:
        if func.getName() == name:
            return func
    return None


def _format_storage(var):
    storage = var.getVariableStorage()
    if storage is None:
        return "None"
    try:
        if storage.hasStackStorage():
            return "stack@{}".format(storage.getStackOffset())
        if storage.isRegisterStorage():
            reg = storage.getRegister()
            return "reg:{}".format(reg)
        if storage.isMemoryStorage():
            return "mem:{}".format(storage.getMinAddress())
    except Exception:
        pass
    return str(storage)


def main():
    args = dict(arg.split("=", 1) for arg in getScriptArgs() if "=" in arg)
    target_name = args.get("function")
    if not target_name:
        printerr("usage: -postScript DumpFunctionLocals.py function=<name>")
        return

    fm = currentProgram.getFunctionManager()
    func = _find_function(fm, target_name)
    if func is None:
        printerr("Function {} not found".format(target_name))
        return

    println("Locals for {}: entry={} frameSize={}".format(func.getName(), func.getEntryPoint(), func.getStackFrame().getFrameSize()))
    for var in func.getStackFrame().getLocals():
        dt = var.getDataType()
        dt_name = dt.getName() if dt else "<none>"
        try:
            display = dt.getDisplayName()
        except Exception:
            display = dt_name
        storage_str = _format_storage(var)
        try:
            first_use = var.getFirstUseOffset()
        except Exception:
            first_use = None
        println(
            "  {} :: {} [{} | {} | {}] len={} src={} firstUse={} valid={}".format(
                var.getName(),
                storage_str,
                dt_name,
                display,
                var.getDataType().__class__.__name__,
                var.getLength(),
                var.getSource(),
                first_use,
                var.isValid(),
            )
        )


if __name__ == "__main__":
    main()
