# Apply structured documentation from metadata/type_docs.json to the program's data types.
# @category xzre

import json
import os

from ghidra.program.model.data import CategoryPath


def parse_args(raw_args):
    docs_path = None
    for arg in raw_args:
        if arg.startswith("docs="):
            docs_path = arg.split("=", 1)[1]
            break
    return os.path.expanduser(docs_path) if docs_path else None


def load_doc_map(path):
    if not path or not os.path.exists(path):
        printerr("Type doc metadata not found: {}".format(path))
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        printerr("Type doc metadata must be a JSON object.")
        return {}
    return {str(k): str(v) for k, v in data.items()}


def find_datatype(dtm, name):
    # Try the root category first.
    dt = dtm.getDataType(CategoryPath("/"), name)
    if dt:
        return dt
    # Next try a fully qualified lookup.
    dt = dtm.getDataType("/" + name)
    if dt:
        return dt
    # Fallback: linear scan for an exact name match.
    dt_iter = dtm.getAllDataTypes()
    while dt_iter.hasNext():
        candidate = dt_iter.next()
        if candidate.getName() == name:
            return candidate
    return None


def apply_docs(doc_map):
    if not doc_map:
        print("No type documentation provided; skipping ApplyTypeDocs.")
        return

    dtm = currentProgram.getDataTypeManager()
    txn = dtm.startTransaction("Apply type documentation")
    updated = 0
    missing = []
    try:
        for name, doc in doc_map.items():
            dt = find_datatype(dtm, name)
            if not dt:
                missing.append(name)
                continue
            current = dt.getDescription()
            if current == doc:
                continue
            try:
                dt.setDescription(doc)
                updated += 1
            except Exception as exc:
                printerr("Failed to annotate {}: {}".format(name, exc))
        dtm.endTransaction(txn, True)
    except Exception:
        dtm.endTransaction(txn, False)
        raise

    print("Type docs applied: {}".format(updated))
    if missing:
        printerr("Missing data types for docs: {}".format(", ".join(sorted(missing))))


def main():
    docs_file = parse_args(getScriptArgs())
    doc_map = load_doc_map(docs_file)
    apply_docs(doc_map)


if __name__ == "__main__":
    main()
