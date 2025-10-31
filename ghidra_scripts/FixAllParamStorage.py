"""
Mark functions with user-defined parameter storage as using custom variable storage.
@category xzre
"""

from ghidra.program.model.listing import Function


def main():
    fm = currentProgram.getFunctionManager()
    updated = 0
    for func in fm.getFunctions(True):
        if func.hasCustomVariableStorage():
            continue
        params = func.getParameters()
        if not params:
            continue
        needs_custom = False
        for param in params:
            storage = param.getVariableStorage()
            if storage is None:
                continue
            try:
                is_user = param.getSource() == func.getSignatureSource()
                if (storage.isRegisterStorage() or storage.hasStackStorage()) and is_user:
                    if not param.hasAssignedStorage():
                        needs_custom = True
                        break
            except Exception:
                continue
        if needs_custom:
            func.setCustomVariableStorage(True)
            updated += 1
    println("Marked {} functions with custom variable storage".format(updated))


if __name__ == "__main__":
    main()
