# Updates all functions that still have an "unknown" calling convention to use
# the compiler's default (System V AMD64 for the x86_64 gcc spec).
# @category xzre

from ghidra.program.model.listing import Function


def main():
    comp_spec = currentProgram.getCompilerSpec()
    default_cc = comp_spec.getDefaultCallingConvention()
    if default_cc is None:
        raise RuntimeError("Default calling convention missing for {}".format(comp_spec.getCompilerSpecID()))
    default_name = default_cc.getName()

    fm = currentProgram.getFunctionManager()
    unknown_marker = Function.UNKNOWN_CALLING_CONVENTION_STRING
    updated = 0
    for func in fm.getFunctions(True):
        cc_name = func.getCallingConventionName()
        if cc_name is None or cc_name == unknown_marker:
            func.setCallingConvention(default_name)
            updated += 1
    print("Applied calling convention '{}' to {} functions".format(default_name, updated))


if __name__ == "__main__":
    main()
