"""
Lists stack locals whose storage is never referenced (firstUseOffset < 0).
@category xzre
"""


def main():
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        stack_frame = func.getStackFrame()
        if stack_frame is None:
            continue
        offenders = []
        for var in stack_frame.getLocals():
            try:
                first_use = var.getFirstUseOffset()
            except Exception:
                first_use = None
            if first_use is None or first_use < 0:
                offenders.append((var, first_use))
        if offenders:
            println("Function {}: {} locals without use".format(func.getName(), len(offenders)))
            for var, first_use in offenders:
                println(
                    "  {} @ {} len={} src={} firstUse={}".format(
                        var.getName(),
                        _describe_storage(var),
                        var.getLength(),
                        var.getSource(),
                        first_use,
                    )
                )
        invalids = [var for var in stack_frame.getLocals() if not var.isValid()]
        if invalids:
            println("Function {}: {} locals marked invalid".format(func.getName(), len(invalids)))
            for var in invalids:
                println(
                    "  {} @ {} len={} src={} firstUse={}".format(
                        var.getName(),
                        _describe_storage(var),
                        var.getLength(),
                        var.getSource(),
                        var.getFirstUseOffset(),
                    )
                )


def _describe_storage(var):
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


if __name__ == "__main__":
    main()
