# Identifies functions whose calling convention is still the Ghidra "unknown" placeholder.
# @category xzre

from ghidra.program.model.listing import Function


def main():
    fm = currentProgram.getFunctionManager()
    unknown_marker = Function.UNKNOWN_CALLING_CONVENTION_STRING
    count = 0
    for func in fm.getFunctions(True):
        cc_name = func.getCallingConventionName()
        if cc_name is None or cc_name == unknown_marker:
            entry = func.getEntryPoint()
            print("{} {} has unknown calling convention".format(entry, func.getName()))
            count += 1
    print("Total functions with unknown calling convention: {}".format(count))


if __name__ == "__main__":
    main()
