# Emits the prototype string for every analyzed function.
# Helps cross-check Ghidra signatures against source headers.
# Optional usage: -postScript ListFunctionSignatures.py output=/tmp/signatures.txt
# @category xzre


def main():
    args = getScriptArgs()
    output_file = None
    for arg in args:
        if arg.startswith("output="):
            output_file = arg.split("=", 1)[1]

    out = None
    try:
        if output_file:
            out = open(output_file, "w")

        def emit(line):
            if out:
                out.write(line + "\n")
            else:
                print(line)

        func_manager = currentProgram.getFunctionManager()
        for func in func_manager.getFunctions(True):
            entry = func.getEntryPoint()
            signature = func.getSignature().getPrototypeString(True)
            emit("{} {} {}".format(entry, func.getName(), signature))
    finally:
        if out:
            out.close()


if __name__ == "__main__":
    main()
