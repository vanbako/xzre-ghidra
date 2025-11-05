# Attempts to rename a specific high-level local symbol using the same path as
# ApplyMappedLocals.py to debug failures.
# @category xzre

from ghidra.app.decompiler import DecompInterface  # type: ignore
from ghidra.program.model.symbol import SourceType  # type: ignore
from ghidra.util.task import ConsoleTaskMonitor  # type: ignore


def main():
    args = dict(arg.split("=", 1) for arg in getScriptArgs() if "=" in arg)
    func_name = args.get("function")
    old_name = args.get("old")
    new_name = args.get("new")
    if not func_name or not old_name or not new_name:
        println("Usage: function=<name> old=<current> new=<desired>")
        return
    fm = currentProgram.getFunctionManager()
    target = None
    for func in fm.getFunctions(True):
        if func.getName() == func_name:
            target = func
            break
    if target is None:
        println("Function {} not found".format(func_name))
        return
    iface = DecompInterface()
    iface.openProgram(currentProgram)
    result = iface.decompileFunction(target, 60, ConsoleTaskMonitor())
    if result is None or not result.decompileCompleted():
        println("Decompilation failed for {}".format(func_name))
        return
    high_func = result.getHighFunction()
    if high_func is None:
        println("HighFunction missing for {}".format(func_name))
        return
    symbol_map = high_func.getLocalSymbolMap()
    symbol = None
    for sym in symbol_map.getSymbols():
        if sym.getName() == old_name:
            symbol = sym
            break
    if symbol is None:
        println("Symbol {} not found in {}".format(old_name, func_name))
        return
    println("Attempting rename {} -> {} in {}".format(old_name, new_name, func_name))
    try:
        symbol_map.renameSymbol(symbol, new_name, SourceType.USER_DEFINED)
        println("renameSymbol succeeded")
    except Exception as exc:
        println("renameSymbol failed: {}".format(exc))


if __name__ == "__main__":
    main()
