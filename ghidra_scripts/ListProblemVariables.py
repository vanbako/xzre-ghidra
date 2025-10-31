"""
Enumerate locals/parameters that lack assigned storage or are flagged invalid.
@category xzre
"""


def main():
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        issues = []
        for var in func.getLocalVariables():
            if not var.isValid() or not var.hasAssignedStorage():
                issues.append(var)
        for var in func.getParameters():
            if not var.isValid() or not var.hasAssignedStorage():
                issues.append(var)
        if issues:
            println("Function {}: {} vars with issues".format(func.getName(), len(issues)))
            for var in issues:
                storage = describe(var)
                println(
                    "  [{}] {} len={} src={} assigned={} valid={} firstUse={}".format(
                        var.__class__.__name__,
                        var.getName(),
                        var.getLength(),
                        var.getSource(),
                        var.hasAssignedStorage(),
                        var.isValid(),
                        safe_first_use(var),
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
    return storage.toString()


def safe_first_use(var):
    try:
        return var.getFirstUseOffset()
    except Exception:
        return None


if __name__ == "__main__":
    main()
