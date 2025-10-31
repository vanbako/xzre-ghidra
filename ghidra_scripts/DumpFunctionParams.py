"""
Dump parameter metadata for a specified function.
@category xzre
"""


def main():
    args = dict(arg.split("=", 1) for arg in getScriptArgs() if "=" in arg)
    target = args.get("function")
    if not target:
        printerr("usage: -postScript DumpFunctionParams.py function=<name>")
        return
    fm = currentProgram.getFunctionManager()
    func = None
    for f in fm.getFunctions(True):
        if f.getName() == target:
            func = f
            break
    if func is None:
        printerr("Function {} not found".format(target))
        return
    println(
        "Params for {} (cc={} customStorage={}):".format(
            func.getName(), func.getCallingConventionName(), func.hasCustomVariableStorage()
        )
    )
    for param in func.getParameters():
        storage = describe(param)
        println(
            "  {} len={} src={} assigned={} valid={} firstUse={} unassignedStorage={}".format(
                param.getName(),
                param.getLength(),
                param.getSource(),
                param.hasAssignedStorage(),
                param.isValid(),
                safe_first_use(param),
                is_unassigned(param),
            )
        )
        println("    storage={}".format(storage))


def describe(var):
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


def safe_first_use(var):
    try:
        return var.getFirstUseOffset()
    except Exception:
        return None


def is_unassigned(var):
    storage = var.getVariableStorage()
    if storage is None:
        return True
    try:
        return storage.isUnassignedStorage()
    except Exception:
        return False


if __name__ == "__main__":
    main()
