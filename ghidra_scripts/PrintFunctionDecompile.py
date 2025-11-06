# Dumps the decompiled C for specified functions.
# Usage: -postScript PrintFunctionDecompile.py funcName1 [funcName2 ...]
# @category xzre

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface


def decompile_function(func, decompiler, monitor):
    result = decompiler.decompileFunction(func, 30, monitor)
    if not result.decompileCompleted():
        printerr("Failed to decompile {}: {}".format(func.getName(), result.getErrorMessage()))
        return None
    return result.getDecompiledFunction().getC()


def main():
    targets = getScriptArgs()
    if not targets:
        printerr("Provide one or more function names to decompile.")
        return

    func_manager = currentProgram.getFunctionManager()
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()

    for target in targets:
        match = None
        for func in func_manager.getFunctions(True):
            if func.getName() == target:
                match = func
                break
        if match is None:
            printerr("Function not found: {}".format(target))
            continue
        entry = match.getEntryPoint()
        print("=== {} @ {} ===".format(match.getName(), entry))
        text = decompile_function(match, decompiler, monitor)
        if text:
            print(text)
        listing = currentProgram.getListing()
        print("--- instructions ---")
        instruction_iter = listing.getInstructions(match.getBody(), True)
        while instruction_iter.hasNext():
            inst = instruction_iter.next()
            print("{}\t{}".format(inst.getAddress(), inst))
        print("--- end ---")


if __name__ == "__main__":
    main()
