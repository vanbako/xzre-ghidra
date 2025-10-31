# Applies function signatures from the imported xzre header to the current program.
# Relies on prototypes already loaded via ImportXzreTypes (or any header parse).
# @category xzre

from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.data import FunctionDefinitionDataType
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType


def is_function_definition(dt):
    cls_name = dt.__class__.__name__
    return isinstance(dt, FunctionDefinitionDataType) or cls_name.endswith(
        "FunctionDefinitionDB"
    )


def build_prototype_map(dtm):
    prototypes = {}
    for dt in dtm.getAllDataTypes():
        if not is_function_definition(dt):
            continue
        name = dt.getName()
        if name not in prototypes:
            prototypes[name] = dt
    return prototypes


def main():
    dtm = currentProgram.getDataTypeManager()
    prototypes = build_prototype_map(dtm)
    if not prototypes:
        printerr("No function prototypes found in the data type manager; run ImportXzreTypes first.")
        return

    func_manager = currentProgram.getFunctionManager()
    applied = 0
    skipped = 0
    missing = 0
    missing_funcs = []

    txn = currentProgram.startTransaction("Apply xzre function signatures")
    cc_updates = 0
    default_cc_name = None
    default_cc = currentProgram.getCompilerSpec().getDefaultCallingConvention()
    if default_cc is None:
        printerr(
            "Compiler spec {} does not expose a default calling convention; skipping calling convention fixup.".format(
                currentProgram.getCompilerSpec().getCompilerSpecID()
            )
        )
    else:
        default_cc_name = default_cc.getName()

    try:
        for func in func_manager.getFunctions(True):
            name = func.getName()
            prototype = prototypes.get(name)
            if prototype is None:
                missing += 1
                missing_funcs.append(name)
                continue

            current_sig = func.getSignature()
            desired_proto = prototype.getPrototypeString()
            if current_sig.getPrototypeString(True) == desired_proto:
                skipped += 1
                continue

            cmd = ApplyFunctionSignatureCmd(
                func.getEntryPoint(), prototype, SourceType.USER_DEFINED, True, True
            )
            if cmd.applyTo(currentProgram):
                applied += 1
                print(
                    "Applied signature to {} at {}: {}".format(
                        name, func.getEntryPoint(), desired_proto
                    )
                )
            else:
                printerr(
                    "Failed to apply signature to {} at {}".format(
                        name, func.getEntryPoint()
                    )
                )
        if default_cc_name:
            unknown_marker = Function.UNKNOWN_CALLING_CONVENTION_STRING
            for func in func_manager.getFunctions(True):
                cc_name = func.getCallingConventionName()
                if cc_name is None or cc_name == unknown_marker:
                    func.setCallingConvention(default_cc_name)
                    cc_updates += 1
    finally:
        currentProgram.endTransaction(txn, True)

    if missing_funcs:
        print("Missing prototypes for: {}".format(", ".join(sorted(missing_funcs))))

    print(
        "Signature application summary: applied={}, skipped={}, missing={}".format(
            applied, skipped, missing
        )
    )
    if default_cc_name:
        print(
            "Calling convention fixup: assigned '{}' to {} functions".format(
                default_cc_name, cc_updates
            )
        )


if __name__ == "__main__":
    main()
