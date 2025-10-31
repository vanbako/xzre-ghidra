# Dumps every function name and entry point in the current program.
# @category xzre


def main():
    func_manager = currentProgram.getFunctionManager()
    for func in func_manager.getFunctions(True):
        entry = func.getEntryPoint()
        print("{} {}".format(entry, func.getName()))


if __name__ == "__main__":
    main()
