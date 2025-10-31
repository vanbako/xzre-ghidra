# Lists all function definitions available in the current program's data type manager.
# @category xzre

from ghidra.program.model.data import FunctionDefinitionDataType


def main():
    dtm = currentProgram.getDataTypeManager()
    sample = 0
    for dt in dtm.getAllDataTypes():
        if sample < 10:
            print(
                "DT: {} ({}) [{}]".format(
                    dt.getName(), dt.getCategoryPath(), dt.__class__.__name__
                )
            )
            sample += 1
    print("---")
    total = 0
    for dt in dtm.getAllDataTypes():
        if isinstance(dt, FunctionDefinitionDataType) or dt.__class__.__name__.endswith(
            "FunctionDefinitionDB"
        ):
            total += 1
            print("{}".format(dt.getName()))
    print("FUNCTION_DEFINITION_COUNT={}".format(total))


if __name__ == "__main__":
    main()
