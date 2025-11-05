# Prints detailed information about the local high-level symbols for selected
# functions. Useful for debugging variable rename/application issues.
# @category xzre

from ghidra.app.decompiler import DecompInterface  # type: ignore
from ghidra.util.task import ConsoleTaskMonitor  # type: ignore


def main():
    target_names = []
    for arg in getScriptArgs():
        if arg.startswith("functions="):
            target_names.extend(arg.split("=", 1)[1].split(","))
    if not target_names:
        println("Specify functions=<name>[,<name>...]")
        return

    fm = currentProgram.getFunctionManager()
    iface = DecompInterface()
    iface.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()

    for name in target_names:
        func = None
        try:
            for candidate in fm.getFunctions(True):
                if candidate.getName() == name:
                    func = candidate
                    break
        except Exception:
            func = None
        if func is None:
            println("Function {} not found".format(name))
            continue
        println("Function {} @ {}".format(func.getName(), func.getEntryPoint()))
        try:
            result = iface.decompileFunction(func, 60, monitor)
        except Exception as exc:
            println("  Decompile failed: {}".format(exc))
            continue
        if result is None or not result.decompileCompleted():
            println("  Decompilation did not complete")
            continue
        high_func = result.getHighFunction()
        if high_func is None:
            println("  HighFunction missing")
            continue
        try:
            symbol_map = high_func.getLocalSymbolMap()
            symbols = list(symbol_map.getSymbols())
        except Exception as exc:
            println("  Failed to fetch symbol map: {}".format(exc))
            continue
        for sym in symbols:
            try:
                if sym.isParameter():
                    continue
            except Exception:
                pass
            try:
                storage = sym.getStorage()
            except Exception:
                storage = None
            try:
                storage_str = str(storage) if storage is not None else "<none>"
            except Exception:
                storage_str = "<error>"
            try:
                sym_type = sym.getSymbolType()
            except Exception:
                sym_type = None
            try:
                high_var = sym.getHighVariable()
                high_type = high_var.getClass().getSimpleName() if high_var is not None else "None"
            except Exception:
                high_var = None
                high_type = "<error>"
            try:
                source_type = sym.getSource()
            except Exception:
                source_type = None
            println(
                "  {} storage={} type={} high={} source={}".format(
                    sym.getName(), storage_str, sym_type, high_type, source_type
                )
            )


if __name__ == "__main__":
    main()
