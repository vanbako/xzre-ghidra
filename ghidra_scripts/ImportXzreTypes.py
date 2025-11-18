# Imports the preprocessed xzre headers into the active program's data type manager.
# @category xzre

import os
import sys

from ghidra.app.util.cparser.C import CParserUtils
from ghidra.program.model.data import DataTypeManager
from java.lang import String
from jarray import array


def main():
    script_args = getScriptArgs()
    if not script_args:
        printerr("Expected header path argument; none provided.")
        return

    header_path = os.path.abspath(script_args[0])
    if not os.path.exists(header_path):
        printerr("Header file not found: {}".format(header_path))
        return

    include_paths = []
    for arg in script_args[1:]:
        if arg.startswith("include_paths="):
            include_paths.extend(
                [
                    p
                    for p in arg.split("=", 1)[1].split(os.pathsep)
                    if p and os.path.isdir(p)
                ]
            )

    filenames = array([header_path], String)
    include_paths_arr = array(include_paths, String)
    cpp_args = array([], String)
    open_dtms = array([], DataTypeManager)

    dtm = currentProgram.getDataTypeManager()
    txn = currentProgram.startTransaction("Import xzre types")
    success = False
    try:
        CParserUtils.parseHeaderFiles(
            open_dtms, filenames, include_paths_arr, cpp_args, dtm, monitor
        )
        success = True
        if include_paths:
            print(
                "Imported xzre data types from {} (include paths: {})".format(
                    header_path, ", ".join(include_paths)
                )
            )
        else:
            print("Imported xzre data types from {}".format(header_path))
    except Exception as exc:
        printerr("Failed to import xzre data types: {}".format(exc))
    finally:
        currentProgram.endTransaction(txn, success)


if __name__ == "__main__":
    main()
