# Dumps the function definition datatype for specified names.
# Usage: -postScript DumpFunctionDefinition.py name1 name2 ...
# @category xzre

from ghidra.program.model.data import FunctionDefinitionDataType


def main():
    names = getScriptArgs()
    if not names:
        printerr("Provide one or more function names to inspect.")
        return

    dtm = currentProgram.getDataTypeManager()
    data_types = list(dtm.getAllDataTypes())

    def is_function_def(dt):
        return isinstance(dt, FunctionDefinitionDataType) or dt.__class__.__name__.endswith(
            "FunctionDefinitionDB"
        )
    for target in names:
        matches = [
            dt
            for dt in data_types
            if is_function_def(dt)
            and dt.getName() == target
        ]
        if not matches:
            partial = [
                dt
                for dt in data_types
                if is_function_def(dt)
                and target in dt.getName()
            ]
            if partial:
                print(
                    "{}: no exact match; showing {} partial matches".format(
                        target, len(partial)
                    )
                )
                matches = partial
            else:
                print("{}: <no function definition found>".format(target))
                continue
        print("{}: {} definitions".format(target, len(matches)))
        for dt in matches:
            proto = dt.getPrototypeString(True)
            path = dt.getCategoryPath().getPath()
            print("  - {} -> {}".format(path, proto))


if __name__ == "__main__":
    main()
